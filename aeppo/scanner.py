import fnmatch
import json
import re
from pathlib import Path
from typing import List, Optional, Union


class Finding:
    def __init__(self, path, line, rule_id, message, severity="medium", confidence="medium", category="code-risk", recommendation="Review this finding in context."):
        self.path = path
        self.line = line
        self.rule_id = rule_id
        self.message = message
        self.severity = severity
        self.confidence = confidence
        self.category = category
        self.recommendation = recommendation

    def __eq__(self, other):
        return isinstance(other, Finding) and self.__dict__ == other.__dict__

    def __repr__(self):
        return "Finding({!r}, {!r}, {!r}, {!r})".format(self.path, self.line, self.rule_id, self.message)


_PYTHON_RULES = (
    ("PY001", re.compile(r"\bos\.system\s*\("), "Use of os.system may execute a shell command with unsafe input.", "medium", "medium", "command-execution", "Prefer argument-list APIs and validate untrusted input."),
    ("PY002", re.compile(r"\b(?:eval|exec)\s*\("), "Dynamic code execution can run attacker-controlled input.", "high", "medium", "dynamic-code", "Avoid dynamic evaluation or strictly constrain and validate the input."),
)
_JAVASCRIPT_RULES = (
    ("JS001", re.compile(r"\beval\s*\("), "Use of eval may execute dynamically constructed JavaScript.", "high", "medium", "dynamic-code", "Avoid eval and use explicit parsing or dispatch."),
    ("JS002", re.compile(r"\b(?:child_process\.)?(?:exec|execSync)\s*\("), "Shell command execution may be unsafe when arguments include untrusted input.", "high", "medium", "command-execution", "Prefer execFile/spawn with an argument array and validate untrusted input."),
)
_SECRET_RULES = (
    ("SEC001", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Possible AWS access key ID found.", "high", "medium", "secret", "Revoke and rotate it if it is real; do not commit credentials."),
    ("SEC002", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "Possible GitHub token found.", "high", "medium", "secret", "Revoke and rotate it if it is real; do not commit credentials."),
    ("SEC003", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private key material header found.", "high", "high", "secret", "Protect the key and rotate it if it was exposed."),
)
_SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
_CONFIG_EXTENSIONS = {".yaml", ".yml", ".toml", ".json", ".ini", ".cfg"}
_CONFIG_NAMES = {".env", ".env.local", ".env.development", ".env.production"}
_MANIFEST_NAMES = {"requirements.txt", "package.json"}
_IGNORED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules"}
_DEFAULT_MAX_FILE_SIZE = 1024 * 1024


def _finding(path, line, rule):
    rule_id, _pattern, message, severity, confidence, category, recommendation = rule
    return Finding(path, line, rule_id, message, severity, confidence, category, recommendation)


def _secret_findings(path, lines):
    findings = []
    for line_number, line in enumerate(lines, start=1):
        for rule in _SECRET_RULES:
            if rule[1].search(line):
                findings.append(_finding(path, line_number, rule))
    return findings


def _supported(path):
    return path.suffix.lower() in _SOURCE_EXTENSIONS | _CONFIG_EXTENSIONS or path.name in _MANIFEST_NAMES | _CONFIG_NAMES


def scan_path(path: Union[str, Path], excludes: Optional[List[str]] = None, max_file_size: int = _DEFAULT_MAX_FILE_SIZE) -> List[Finding]:
    """Scan supported source files and dependency manifests without executing them."""
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
    candidates = sorted(item for item in target.rglob("*") if item.is_file() and _supported(item))
    for source in candidates:
        relative = source.relative_to(target)
        relative_name = relative.as_posix()
        if any(part.startswith(".") or part in _IGNORED_DIRECTORIES for part in relative.parts[:-1]):
            continue
        if any(fnmatch.fnmatch(relative_name, pattern) for pattern in excludes):
            continue
        if source.stat().st_size > max_file_size:
            continue
        for item in scan_file(source):
            findings.append(Finding(relative_name, item.line, item.rule_id, item.message, item.severity, item.confidence, item.category, item.recommendation))
    return findings


def scan_file(path: Union[str, Path]) -> List[Finding]:
    """Statically scan supported source files and dependency manifests."""
    file_path = Path(path)
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    display_path = str(file_path)
    findings = _secret_findings(display_path, lines)
    if file_path.name == "requirements.txt":
        findings.extend(_scan_requirements(display_path, lines))
        return findings
    if file_path.name == "package.json":
        findings.extend(_scan_package_json(display_path, "\n".join(lines)))
        return findings

    if file_path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
        rules = _JAVASCRIPT_RULES
    elif file_path.suffix.lower() == ".py":
        rules = _PYTHON_RULES
    else:
        rules = ()
    for line_number, line in enumerate(lines, start=1):
        for rule in rules:
            if rule[1].search(line):
                findings.append(_finding(display_path, line_number, rule))
    return findings


def _scan_requirements(path, lines):
    findings = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("http://", "https://", "git+")) or " @ " in line:
            findings.append(Finding(path, line_number, "DEP002", "Dependency uses a direct URL or VCS reference.", "medium", "high", "supply-chain", "Verify the source and pin it to an immutable commit or trusted artifact."))
        elif re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?$", line):
            findings.append(Finding(path, line_number, "DEP001", "Dependency has no version constraint.", "low", "high", "dependency-management", "Pin dependencies to reviewed versions and use a lockfile where possible."))
    return findings


def _scan_package_json(path, raw):
    try:
        package = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(package, dict):
        return []
    findings = []
    scripts = package.get("scripts", {})
    if isinstance(scripts, dict):
        for name in ("preinstall", "install", "postinstall"):
            if name in scripts:
                line = next((index for index, text in enumerate(raw.splitlines(), start=1) if '"' + name + '"' in text), 1)
                findings.append(Finding(path, line, "DEP003", "Package defines an {} lifecycle script that runs during installation.".format(name), "medium", "high", "dependency-install-script", "Inspect the script and its transitive commands before installing dependencies."))
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = package.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            if isinstance(version, str) and version.startswith(("git+", "http://", "https://", "file:")):
                findings.append(Finding(path, 1, "DEP002", "Dependency {} uses a direct URL, VCS, or local path reference.".format(name), "medium", "high", "supply-chain", "Verify the source and pin it to an immutable commit or trusted artifact."))
    return findings
