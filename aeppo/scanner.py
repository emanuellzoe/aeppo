"""File discovery, suppression, fingerprints and baselines; dispatches each file to its rules.

Rule logic lives in the ``rules_*`` modules. ``Finding``, ``RULES`` and ``SEVERITY_ORDER`` are
re-exported here for backward compatibility.
"""
import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Union

from aeppo import rules_actions, rules_autoexec, rules_code, rules_deps, rules_js, rules_python, rules_secrets, rules_shell
from aeppo.findings import RULES, SEVERITY_ORDER, Finding, Rule, make_finding as _finding  # noqa: F401
from aeppo.rules_js import _JS_EXTENSIONS


# Documentation is checked for leaked secrets only; code rules would misfire on prose and snippets.
_DOCUMENT_EXTENSIONS = {".md", ".markdown", ".mdx"}

_SUPPRESSION = re.compile(r"aeppo:\s*ignore(-next-line)?(?:\[([A-Za-z0-9_,\s]+)\])?")

_SOURCE_EXTENSIONS = {".py"} | _JS_EXTENSIONS
# ``.env`` as an extension covers names such as ``production.env``; ``.env`` and ``.env.*`` are
# matched by name in ``_supported``.
_CONFIG_EXTENSIONS = {".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".env"}
_MANIFEST_NAMES = {"requirements.txt", "package.json"}
_ENTERED_HIDDEN_DIRECTORIES = {".github", ".vscode", ".devcontainer"}
_IGNORED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules"}
_DEFAULT_MAX_FILE_SIZE = 1024 * 1024


def _supported(path):
    name = path.name
    return (
        path.suffix.lower() in _SOURCE_EXTENSIONS | _CONFIG_EXTENSIONS | _DOCUMENT_EXTENSIONS | rules_shell.SHELL_EXTENSIONS
        or name in _MANIFEST_NAMES
        or name == ".env"
        or name.startswith(".env.")
        or (not path.suffix and rules_shell.is_shell_script(path))
        or rules_autoexec.kind(path) is not None
        or rules_code.language(path) is not None
    )


def _fingerprint(rule_id, line_text):
    normalized = " ".join(line_text.split())
    return hashlib.sha256("{}\0{}".format(rule_id, normalized).encode("utf-8")).hexdigest()[:16]


def _suppressed_rules(line, next_line):
    """Return the rule IDs a suppression comment on ``line`` covers (``None`` means all)."""
    covered = set()
    for match in _SUPPRESSION.finditer(line):
        if bool(match.group(1)) != next_line:
            continue
        if not match.group(2):
            return None
        covered.update(part.strip().upper() for part in match.group(2).split(",") if part.strip())
    return covered


def _is_suppressed(lines, finding):
    index = finding.line - 1
    candidates = []
    if 0 <= index < len(lines):
        candidates.append(_suppressed_rules(lines[index], next_line=False))
    if 1 <= index <= len(lines):
        candidates.append(_suppressed_rules(lines[index - 1], next_line=True))
    return any(rules is None or finding.rule_id in rules for rules in candidates)


def _finalize(findings, lines):
    kept = []
    for finding in sorted(findings, key=lambda item: item.line):
        if _is_suppressed(lines, finding):
            continue
        text = lines[finding.line - 1] if 0 < finding.line <= len(lines) else ""
        finding.fingerprint = _fingerprint(finding.rule_id, text)
        kept.append(finding)
    return kept


def _candidate_files(target):
    """Return supported files in sorted order, pruning hidden and vendor directories before descending.

    Hidden directories entered: ``.github`` (only ``workflows/*.yml|yaml``), ``.vscode`` (only
    ``tasks.json``) and ``.devcontainer`` (only ``devcontainer.json`` files).
    """
    candidates = []
    for directory, subdirectories, files in os.walk(target):
        relative = Path(directory).relative_to(target).parts
        hidden_root = next((part for part in relative if part in _ENTERED_HIDDEN_DIRECTORIES), None)
        if hidden_root == ".github":
            subdirectories[:] = ["workflows"] if relative[-1] == ".github" and "workflows" in subdirectories else []
            if relative[-1] == "workflows":
                candidates.extend(Path(directory, name) for name in files if Path(name).suffix.lower() in {".yml", ".yaml"} and Path(directory, name).is_file())
            continue
        if hidden_root:
            # .vscode: tasks.json only. .devcontainer: devcontainer.json, including named sub-configs.
            subdirectories[:] = [] if hidden_root == ".vscode" else [name for name in subdirectories if not name.startswith(".")]
            candidates.extend(Path(directory, name) for name in files if rules_autoexec.kind(Path(directory, name)) in {"vscode_tasks", "devcontainer"} and Path(directory, name).is_file())
            continue
        subdirectories[:] = [name for name in subdirectories if name in _ENTERED_HIDDEN_DIRECTORIES or (not name.startswith(".") and name not in _IGNORED_DIRECTORIES)]
        for name in files:
            path = Path(directory, name)
            if _supported(path) and path.is_file():
                candidates.append(path)
    return sorted(candidates)


def scan_path(path: Union[str, Path], excludes: Optional[List[str]] = None, max_file_size: int = _DEFAULT_MAX_FILE_SIZE, errors: Optional[List[str]] = None) -> List[Finding]:
    """Scan supported source files and dependency manifests without executing them.

    When ``errors`` is a list, files that cannot be read are skipped and described there;
    otherwise the first read error is raised.
    """
    target = Path(path)
    if max_file_size <= 0:
        raise ValueError("max_file_size must be greater than zero")
    if target.is_file():
        if not _supported(target):
            raise ValueError("Unsupported file type: {}".format(target.suffix or target.name))
        if target.stat().st_size > max_file_size:
            return []
        return scan_file(target)
    if not target.is_dir():
        raise ValueError("Scan target must be an existing file or directory")

    excludes = excludes or []
    findings = []
    for source in _candidate_files(target):
        relative_name = source.relative_to(target).as_posix()
        if any(fnmatch.fnmatch(relative_name, pattern) for pattern in excludes):
            continue
        try:
            if source.stat().st_size > max_file_size:
                continue
            file_findings = scan_file(source)
        except OSError as error:
            if errors is None:
                raise
            errors.append("{}: {}".format(relative_name, error.strerror or error))
            continue
        for item in file_findings:
            item.path = relative_name
            findings.append(item)
    return findings


def scan_file(path: Union[str, Path]) -> List[Finding]:
    """Statically scan supported source files and dependency manifests."""
    file_path = Path(path)
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    display_path = str(file_path)
    suffix = file_path.suffix.lower()
    findings = rules_secrets.secret_findings(display_path, lines)
    if suffix in _DOCUMENT_EXTENSIONS:
        return _finalize(findings, lines)
    code_language = rules_code.language(file_path)
    if suffix in _SOURCE_EXTENSIONS or code_language:
        findings.extend(rules_secrets.bidi_findings(display_path, lines))
    if file_path.name == "requirements.txt":
        findings.extend(rules_deps.scan_requirements(display_path, lines))
    elif file_path.name == "package.json":
        findings.extend(rules_deps.scan_package_json(display_path, "\n".join(lines)))
    elif suffix == ".py":
        findings.extend(rules_python.scan(display_path, lines))
    elif suffix in _JS_EXTENSIONS:
        findings.extend(rules_js.scan(display_path, lines))
    elif rules_autoexec.kind(file_path):
        for line_number, rule_id, severity, message in rules_autoexec.scan(rules_autoexec.kind(file_path), lines):
            finding = _finding(display_path, line_number, rule_id, message)
            if severity:
                finding.severity = severity
            findings.append(finding)
    elif rules_actions.is_actions_file(file_path):
        for line_number, rule_id, severity in rules_actions.scan(lines):
            finding = _finding(display_path, line_number, rule_id)
            if severity:
                finding.severity = severity
            findings.append(finding)
    elif suffix in rules_shell.SHELL_EXTENSIONS or file_path.name in rules_shell.SHELL_NAMES or (not suffix and lines and rules_shell.has_shell_shebang(lines[0])):
        findings.extend(_finding(display_path, line_number, rule_id) for line_number, rule_id in rules_shell.scan(lines))
    if code_language:
        # build.rs lines already reported as build-script execution are not reported twice.
        build_lines = {finding.line for finding in findings if finding.rule_id in {"BLD001", "BLD002"}}
        for line_number, rule_id, severity, message in rules_code.scan(code_language, "\n".join(lines)):
            if line_number in build_lines:
                continue
            if message is None and rule_id.startswith("SH"):
                message = rules_code.shell_message(RULES[rule_id].message)
            finding = _finding(display_path, line_number, rule_id, message)
            if severity:
                finding.severity = severity
            findings.append(finding)
    return _finalize(findings, lines)


def filter_findings(findings: Iterable[Finding], min_severity: str = "low", baseline: Optional[Set[Tuple[str, str, str]]] = None, disabled: Optional[Iterable[str]] = None) -> List[Finding]:
    """Drop findings below ``min_severity``, from ``disabled`` rules, or already in ``baseline``."""
    if min_severity not in SEVERITY_ORDER:
        raise ValueError("min_severity must be one of: {}".format(", ".join(SEVERITY_ORDER)))
    threshold = SEVERITY_ORDER[min_severity]
    known = baseline or set()
    off = {rule_id.upper() for rule_id in disabled or ()}
    unknown = sorted(off - set(RULES))
    if unknown:
        raise ValueError("Unknown rule ID(s) to disable: {}".format(", ".join(unknown)))
    return [
        finding
        for finding in findings
        if SEVERITY_ORDER.get(finding.severity, 1) >= threshold
        and finding.rule_id not in off
        and (finding.path, finding.rule_id, finding.fingerprint) not in known
    ]


def load_baseline(path: Union[str, Path]) -> Set[Tuple[str, str, str]]:
    """Load a baseline written by ``aeppo scan --format json``."""
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not all(isinstance(entry, dict) and {"path", "rule_id", "fingerprint"} <= entry.keys() for entry in entries):
        raise ValueError("Baseline must be a JSON array written by 'aeppo scan --format json'")
    return {(entry["path"], entry["rule_id"], entry["fingerprint"]) for entry in entries}
