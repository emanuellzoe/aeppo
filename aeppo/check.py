"""``aeppo check``: vet a repository before trying it.

The repository is cloned shallowly into a temporary directory with every git feature that could
run code or fetch more content turned off, scanned as text (static rules plus OSV.dev), and
deleted. Nothing from the repository is executed, and its own ``.aeppo.toml`` and
``aeppo: ignore`` comments are ignored, because an attacker controls both.

Findings are grouped by the moment they would run on the reader's machine, and the report ends
with a verdict: danger (strong evidence), review (findings that need a human), or no known
issues (never a guarantee).
"""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.parse
from pathlib import Path, PurePosixPath

from aeppo import osv, report_html, rules_autoexec, rules_vulns
from aeppo.findings import SEVERITY_ORDER
from aeppo.scanner import _candidate_files, scan_path


CLONE_TIMEOUT = 600
_SHORTHAND = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")

# Sections, in report order: (key, heading, affects the reader's machine).
SECTIONS = (
    ("open", "Opening the folder in VS Code, a dev container or a direnv shell", True),
    ("install", "Installing its dependencies (npm, pip, composer, bundle install)", True),
    ("build", "Building it (cargo build, Gradle, Maven, MSBuild, docker build, go generate)", True),
    ("run", "Running its code or scripts", True),
    ("tests", "Running its tests and examples (only when you run them yourself)", True),
    ("deps", "Its dependencies (known vulnerabilities and malware, from OSV.dev)", True),
    ("ci", "Its GitHub Actions workflows (a risk to the project, not to you)", False),
    ("secrets", "Credentials committed to the repository (a risk to the project, not to you)", False),
)
# Strong signs of malicious intent wherever they appear.
_STRONG_RULES = {"MAL001", "NET001", "SH002", "SH003", "PY006"}
# Sections that run without the reader deciding to run the project's code.
_AUTOMATIC = {"open", "install", "build"}
_INSTALL_NAMES = {"setup.py", "package.json", "composer.json", "Gemfile", "extconf.rb"}
_TEST_DIRECTORIES = {"test", "tests", "__tests__", "spec", "specs", "testdata", "testing", "fixtures", "examples", "example", "e2e", "benchmarks"}
_TEST_FILE = re.compile(r"(?:^test_.*\.py|_test\.(?:py|go|rb|exs?)|_spec\.rb|\.(?:test|spec)\.[cm]?[jt]sx?|Tests?\.(?:java|kt))$")


def is_test_path(path):
    path = PurePosixPath(path)
    return bool(_TEST_DIRECTORIES & {part.lower() for part in path.parts[:-1]}) or bool(_TEST_FILE.search(path.name))


class CheckError(Exception):
    pass


def normalize_url(target):
    """Return an https clone URL for ``target`` (a URL or ``owner/repo`` on GitHub)."""
    if _SHORTHAND.match(target) and not target.endswith((".", "..")):
        return "https://github.com/" + target
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise CheckError("expected an https:// repository URL or owner/repo, got {!r}".format(target))
    if parsed.query or parsed.fragment:
        raise CheckError("the repository URL must not have a query or fragment")
    path = parsed.path.rstrip("/")
    if parsed.hostname in {"github.com", "www.github.com"}:
        # Browser URLs such as https://github.com/owner/repo/tree/main point at the repository.
        parts = [part for part in path.split("/") if part]
        if len(parts) < 2:
            raise CheckError("expected https://github.com/OWNER/REPO, got {!r}".format(target))
        path = "/" + "/".join(parts[:2])
    return urllib.parse.urlunsplit(("https", parsed.netloc, path, "", ""))


def _git(arguments, timeout):
    environment = dict(os.environ)
    environment.update({
        "GIT_TERMINAL_PROMPT": "0",  # never ask for credentials
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
    })
    command = [
        "git",
        "-c", "core.hooksPath=/dev/null",  # no hooks from the user's templates either
        "-c", "core.symlinks=false",  # links are checked out as plain files, never followed
        "-c", "core.fsmonitor=false",
        "-c", "credential.helper=",  # do not offer stored credentials to the remote
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "filter.lfs.smudge=",
        "-c", "filter.lfs.process=",
        "-c", "filter.lfs.required=false",
        "-c", "submodule.recurse=false",
    ] + arguments
    try:
        return subprocess.run(command, env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise CheckError("git is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise CheckError("git {} timed out after {} seconds".format(arguments[0], timeout))


def clone(url, destination, ref=None):
    """Shallow-clone ``url`` into ``destination``; return the checked-out commit."""
    arguments = ["clone", "--quiet", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules"]
    if ref:
        if ref.startswith("-"):
            raise CheckError("invalid ref {!r}".format(ref))
        arguments += ["--branch", ref]
    result = _git(arguments + ["--", url, str(destination)], CLONE_TIMEOUT)
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        raise CheckError("git clone failed: {}".format(detail[-1] if detail else "exit code {}".format(result.returncode)))
    head = _git(["-C", str(destination), "rev-parse", "HEAD"], 60)
    return head.stdout.strip() if head.returncode == 0 else ""


def _remove_tree(path):
    def make_writable(function, failed, _error):
        try:
            os.chmod(failed, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            function(failed)
        except OSError:
            pass
    shutil.rmtree(path, onerror=make_writable)


def section(finding):
    """Return the section key for a finding."""
    rule_id = finding.rule_id
    path = PurePosixPath(finding.path)
    name = path.name
    if rule_id in {"VULN001", "MAL001"}:
        return "deps"
    # Files under test and example directories run only when the reader runs them, even when they
    # look like a manifest or a workflow (tests/fixtures/package.json, tests/x/.github/workflows).
    # Credentials there are usually fixtures (a secret scanner's tests are full of fake keys); they
    # stay masked and listed with the tests.
    if is_test_path(finding.path):
        return "tests"
    if rule_id.startswith("SEC"):
        return "secrets"
    if rule_id.startswith("GHA") or ".github" in path.parts or name in {"action.yml", "action.yaml"}:
        return "ci"
    kind = rules_autoexec.kind(Path(finding.path))
    if rule_id.startswith("AUTO") or kind in {"vscode_tasks", "devcontainer"} or name == ".envrc":
        return "open"
    if rule_id.startswith("DEP") or kind == "composer" or name in _INSTALL_NAMES or name.endswith(".gemspec") or name.startswith("requirements"):
        return "install"
    # In .go files, shell rules with the plain "Shell script" message come from //go:generate lines;
    # commands passed to exec.Command are reported as "Embedded shell command".
    if rule_id.startswith("BLD") or kind in {"build_rs", "gradle", "maven", "msbuild", "dockerfile"} or (kind == "go" and rule_id.startswith("SH") and finding.message.startswith("Shell script")):
        return "build"
    return "tests" if is_test_path(finding.path) else "run"


def verdict(findings):
    """Return (level, reasons): level is "danger", "review" or "clear"."""
    danger = []
    review = []
    for finding in findings:
        key = section(finding)
        affects_you = dict((item[0], item[2]) for item in SECTIONS)[key]
        if key == "tests":
            # Tests and examples run only on request, so even strong signs there call for a
            # human (they are often detection samples, as in a scanner's own test corpus).
            if finding.rule_id in _STRONG_RULES:
                review.append(finding)
            continue
        if finding.rule_id in _STRONG_RULES:
            danger.append(finding)
        elif key in _AUTOMATIC and finding.severity == "high":
            danger.append(finding)
        elif affects_you and key != "tests" and SEVERITY_ORDER.get(finding.severity, 1) >= SEVERITY_ORDER["medium"]:
            review.append(finding)
    if danger:
        return "danger", danger
    if review:
        return "review", review
    return "clear", []


_VERDICT_TEXT = {
    "danger": "DANGER. Strong signs of malicious or dangerous behaviour; do not install, build or open it until you have read these findings.",
    "review": "REVIEW. Findings that need a human to judge; read them before installing, building or opening it.",
    "clear": "NO KNOWN ISSUES found by aeppo's rules. This is not a guarantee that the repository is safe.",
}
_LIMIT = 10


def _line(finding):
    return "    {}:{}: [{}|{}] {}".format(finding.path, finding.line, finding.rule_id, finding.severity, finding.message)


def format_text(source, commit, findings, level, reasons, details, osv_status):
    lines = ["aeppo check {}{}".format(source, " (commit {})".format(commit[:12]) if commit else ""), ""]
    lines.append("Verdict: " + _VERDICT_TEXT[level])
    for finding in reasons[:_LIMIT]:
        lines.append(_line(finding))
    if len(reasons) > _LIMIT:
        lines.append("    ... and {} more".format(len(reasons) - _LIMIT))
    grouped = {key: [] for key, _heading, _affects in SECTIONS}
    for finding in findings:
        grouped[section(finding)].append(finding)
    for key, heading, _affects in SECTIONS:
        items = sorted(grouped[key], key=lambda item: (-SEVERITY_ORDER.get(item.severity, 1), item.path, item.line))
        lines.append("")
        if key == "deps" and osv_status:
            heading += " [{}]".format(osv_status)
        if not items:
            lines.append("{}: nothing found".format(heading))
            continue
        counts = ", ".join("{} {}".format(sum(1 for item in items if item.severity == severity), severity) for severity in ("high", "medium", "low") if any(item.severity == severity for item in items))
        lines.append("{}: {} finding(s) ({})".format(heading, len(items), counts))
        if key == "deps":
            lines.extend(line for line in rules_vulns.summary(items, details)[2:])
            continue
        for finding in items[:_LIMIT]:
            lines.append(_line(finding))
        if len(items) > _LIMIT:
            lines.append("    ... and {} more (use --format json for all)".format(len(items) - _LIMIT))
    lines.extend([
        "",
        "aeppo read the files as text and ran nothing from the repository. Its rules find known risky",
        "patterns; they can miss new or obfuscated malware, so treat a clean result as 'nothing known',",
        "not 'safe'. Install and run untrusted code in a disposable VM or container.",
    ])
    return "\n".join(lines)


def format_json(source, commit, findings, level, reasons):
    return json.dumps({
        "source": source,
        "commit": commit,
        "verdict": level,
        "reasons": [{"path": item.path, "line": item.line, "rule_id": item.rule_id} for item in reasons],
        "findings": [dict(item.__dict__, section=section(item)) for item in findings],
    }, indent=2)


EXIT_CODES = {"clear": 0, "review": 1, "danger": 3}


def run(target, ref=None, use_osv=True, output_format="text", out=None, err=None, client=None, max_file_size=1024 * 1024, output=None):
    """Check ``target`` (a URL, ``owner/repo``, or a local directory) and print a report.

    ``output_format`` is text, json or html; ``output`` is a path to write the report to instead
    of ``out``. Returns the exit code: 0 no known issues, 1 review, 3 danger, 2 error.
    """
    import sys
    out = out or sys.stdout
    err = err or sys.stderr
    workspace = None
    try:
        local = Path(target)
        if local.is_dir():
            root, source, commit = local, str(local.resolve()), ""
        else:
            url = normalize_url(target)
            workspace = Path(tempfile.mkdtemp(prefix="aeppo-check-"))
            root = workspace / "repo"
            print("aeppo: cloning {} (shallow, no hooks, submodules or LFS)".format(url), file=err)
            commit = clone(url, root, ref)
            source = url
        errors = []
        findings = scan_path(root, max_file_size=max_file_size, errors=errors, honor_suppressions=False)
        details = {}
        osv_status = "not checked (--no-osv)"
        if use_osv:
            try:
                found, package_count, lockfile_count = rules_vulns.scan([root], client or osv.Client(cache_dir=osv.default_cache_dir()), (), errors, details)
                findings.extend(finding for finding, _target in found)
                osv_status = "{} package version(s) from {} lockfile(s) checked".format(package_count, lockfile_count) if lockfile_count else "no lockfiles"
            except osv.OSVError as error:
                osv_status = "NOT CHECKED: {}".format(error)
                print("aeppo: warning: could not check dependencies with OSV.dev: {}".format(error), file=err)
        for message in errors:
            print("aeppo: warning: skipped {}".format(message), file=err)
        level, reasons = verdict(findings)
        if output_format == "json":
            report = format_json(source, commit, findings, level, reasons)
        elif output_format == "html":
            # Excerpts are read now, while the checked-out copy still exists.
            scanned = [path.relative_to(root).as_posix() for path in _candidate_files(root)]
            report = report_html.render(source, commit, findings, level, reasons, details, osv_status, SECTIONS, section,
                                        _VERDICT_TEXT[level], scanned, report_html.read_excerpts(root, findings)).rstrip("\n")
        else:
            report = format_text(source, commit, findings, level, reasons, details, osv_status)
        if output is not None:
            Path(output).write_text(report + "\n", encoding="utf-8")
            print("aeppo: wrote the {} report to {} (verdict: {})".format(output_format, output, level), file=err)
        else:
            print(report, file=out)
        return EXIT_CODES[level]
    except (CheckError, OSError) as error:
        print("aeppo: {}".format(error), file=err)
        return 2
    finally:
        if workspace is not None:
            _remove_tree(workspace)
