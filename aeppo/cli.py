import argparse
import sys
from pathlib import Path

from aeppo import __version__
from aeppo.report import format_json, format_sarif, format_text
from aeppo.scanner import SEVERITY_ORDER, filter_findings, load_baseline, scan_path


def _sarif_uri(target, finding_path):
    """Make SARIF locations relative to the working directory (the repository root in CI)."""
    location = target if target.is_file() else target / finding_path
    resolved = location.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_uri()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aeppo", description="Statically scan source code for suspicious patterns.")
    parser.add_argument("--version", action="version", version="aeppo {}".format(__version__))
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a file or directory")
    scan_parser.add_argument("path", type=Path, help="file or directory to scan")
    scan_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_parser.add_argument("--exclude", action="append", default=[], help="exclude a relative path glob; may be repeated")
    scan_parser.add_argument("--max-file-size", type=int, default=1024 * 1024, metavar="BYTES", help="skip files larger than this (default: 1048576)")
    scan_parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low", help="report only findings at or above this severity (default: low)")
    scan_parser.add_argument("--baseline", type=Path, metavar="FILE", help="ignore findings recorded in a JSON file written by --format json")
    scan_parser.add_argument("--output", type=Path, metavar="FILE", help="write the report to FILE instead of standard output")
    args = parser.parse_args(argv)

    errors = []
    try:
        baseline = load_baseline(args.baseline) if args.baseline else None
        findings = scan_path(args.path, excludes=args.exclude, max_file_size=args.max_file_size, errors=errors)
    except (OSError, ValueError) as error:
        print("aeppo: {}".format(error), file=sys.stderr)
        return 2
    for message in errors:
        print("aeppo: warning: skipped {}".format(message), file=sys.stderr)

    findings = filter_findings(findings, min_severity=args.min_severity, baseline=baseline)

    if args.format == "json":
        report = format_json(findings)
    elif args.format == "sarif":
        report = format_sarif(findings, uri_for=lambda path: _sarif_uri(args.path, path))
    else:
        report = format_text(findings)

    if args.output:
        try:
            args.output.write_text(report + "\n", encoding="utf-8")
        except OSError as error:
            print("aeppo: cannot write {}: {}".format(args.output, error.strerror or error), file=sys.stderr)
            return 2
        print("aeppo: wrote {} finding(s) to {}".format(len(findings), args.output), file=sys.stderr)
    else:
        print(report)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
