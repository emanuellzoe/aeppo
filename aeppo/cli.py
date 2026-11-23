import argparse
import fnmatch
import sys
from pathlib import Path

from aeppo import __version__, lockfiles, osv, rules_vulns
from aeppo.config import CONFIG_NAME, find_config, load_config
from aeppo.report import format_json, format_sarif, format_text
from aeppo.scanner import SEVERITY_ORDER, _supported, filter_findings, load_baseline, scan_path


_DEFAULT_MAX_FILE_SIZE = 1024 * 1024


def _sarif_uri(target, finding_path):
    """Make SARIF locations relative to the working directory (the repository root in CI)."""
    location = target if target.is_file() else target / finding_path
    resolved = location.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_uri()


def _settings(args):
    """Merge .aeppo.toml with command-line options; options given on the command line win."""
    config = {}
    config_path = None
    if not args.no_config:
        if args.config:
            config_path = args.config
        else:
            # One directory target: search from it. Files or several targets (pre-commit): from cwd.
            start = args.paths[0] if len(args.paths) == 1 and args.paths[0].is_dir() else Path.cwd()
            config_path = find_config(start)
        if config_path:
            config = load_config(config_path)
    baseline_path = args.baseline or config.get("baseline")
    return {
        "config_path": config_path,
        "exclude": config.get("exclude", []) + args.exclude,
        "disable": config.get("disable", []) + [rule_id.upper() for rule_id in args.disable],
        "min_severity": args.min_severity or config.get("min_severity", "low"),
        "max_file_size": args.max_file_size or config.get("max_file_size", _DEFAULT_MAX_FILE_SIZE),
        "baseline": load_baseline(baseline_path) if baseline_path else None,
        "osv": args.osv or config.get("osv", False),
    }


def _scan_targets(args, settings, errors):
    """Scan every target; return (finding, target) pairs so SARIF can resolve each location."""
    results = []
    for target in args.paths:
        if target.is_file():
            if any(fnmatch.fnmatch(target.as_posix(), pattern) for pattern in settings["exclude"]):
                continue
            if not _supported(target) and (args.skip_unsupported or (settings["osv"] and lockfiles.kind(target))):
                continue
        findings = scan_path(target, excludes=settings["exclude"], max_file_size=settings["max_file_size"], errors=errors)
        results.extend((finding, target) for finding in findings)
    return results


def _check_dependencies(args, settings, results, errors, details):
    """Add VULN001/MAL001 findings from OSV.dev to ``results``; return False if OSV failed."""
    targets = [target for target in args.paths if not (target.is_file() and any(fnmatch.fnmatch(target.as_posix(), pattern) for pattern in settings["exclude"]))]
    client = osv.Client(cache_dir=osv.default_cache_dir())
    try:
        findings, package_count, lockfile_count = rules_vulns.scan(targets, client, settings["exclude"], errors, details)
    except osv.OSVError as error:
        print("aeppo: error: could not check dependencies with OSV.dev: {}".format(error), file=sys.stderr)
        return False
    results.extend(findings)
    print("aeppo: checked {} package version(s) from {} lockfile(s) against OSV.dev".format(package_count, lockfile_count), file=sys.stderr)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aeppo", description="Statically scan source code for suspicious patterns.")
    parser.add_argument("--version", action="version", version="aeppo {}".format(__version__))
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan files or directories")
    scan_parser.add_argument("paths", nargs="+", type=Path, metavar="PATH", help="file or directory to scan; may be repeated")
    scan_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_parser.add_argument("--exclude", action="append", default=[], help="exclude a relative path glob; may be repeated")
    scan_parser.add_argument("--max-file-size", type=int, default=None, metavar="BYTES", help="skip files larger than this (default: 1048576)")
    scan_parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default=None, help="report only findings at or above this severity (default: low)")
    scan_parser.add_argument("--disable", action="append", default=[], metavar="RULE", help="turn off a rule ID; may be repeated")
    scan_parser.add_argument("--baseline", type=Path, metavar="FILE", help="ignore findings recorded in a JSON file written by --format json")
    scan_parser.add_argument("--output", type=Path, metavar="FILE", help="write the report to FILE instead of standard output")
    scan_parser.add_argument("--config", type=Path, metavar="FILE", help="read settings from FILE instead of searching for {}".format(CONFIG_NAME))
    scan_parser.add_argument("--no-config", action="store_true", help="ignore {} files".format(CONFIG_NAME))
    scan_parser.add_argument("--osv", action="store_true", help="look up lockfile dependency versions in OSV.dev for known vulnerabilities and malware (sends package names and versions)")
    scan_parser.add_argument("--skip-unsupported", action="store_true", help="skip file targets aeppo cannot scan instead of failing (used by pre-commit)")
    check_parser = subparsers.add_parser("check", help="vet a repository before trying it: clone it safely, scan it, check its dependencies, and give a verdict")
    check_parser.add_argument("target", metavar="REPO", help="https:// repository URL, owner/repo on GitHub, or a local directory")
    check_parser.add_argument("--ref", help="branch or tag to check instead of the default branch")
    check_parser.add_argument("--format", choices=["text", "json"], default="text")
    check_parser.add_argument("--no-osv", action="store_true", help="do not look up dependencies in OSV.dev (no network use besides the clone)")
    args = parser.parse_args(argv)
    if args.command == "check":
        from aeppo import check
        return check.run(args.target, ref=args.ref, use_osv=not args.no_osv, output_format=args.format)

    errors = []
    details = {}
    try:
        if args.max_file_size is not None and args.max_file_size <= 0:
            raise ValueError("--max-file-size must be greater than zero")
        settings = _settings(args)
        results = _scan_targets(args, settings, errors)
        osv_failed = settings["osv"] and not _check_dependencies(args, settings, results, errors, details)
        kept = filter_findings(
            [finding for finding, _target in results],
            min_severity=settings["min_severity"],
            baseline=settings["baseline"],
            disabled=settings["disable"],
        )
    except (OSError, ValueError) as error:
        print("aeppo: {}".format(error), file=sys.stderr)
        return 2
    for message in errors:
        print("aeppo: warning: skipped {}".format(message), file=sys.stderr)

    targets = {id(finding): target for finding, target in results}
    if args.format == "json":
        report = format_json(kept)
    elif args.format == "sarif":
        report = format_sarif(kept, uri_for=lambda finding: _sarif_uri(targets[id(finding)], finding.path))
    else:
        report = "\n".join([format_text(kept)] + rules_vulns.summary(kept, details))

    if args.output:
        try:
            args.output.write_text(report + "\n", encoding="utf-8")
        except OSError as error:
            print("aeppo: cannot write {}: {}".format(args.output, error.strerror or error), file=sys.stderr)
            return 2
        print("aeppo: wrote {} finding(s) to {}".format(len(kept), args.output), file=sys.stderr)
    else:
        print(report)
    if osv_failed:
        return 2
    return 1 if kept else 0


if __name__ == "__main__":
    sys.exit(main())
