from pathlib import Path
from typing import Union, List
import re


class Finding:
    def __init__(self, path: str, line: int, rule_id: str, message: str):
        self.path = path
        self.line = line
        self.rule_id = rule_id
        self.message = message

    def __eq__(self, other):
        return isinstance(other, Finding) and self.__dict__ == other.__dict__

    def __repr__(self):
        return "Finding({!r}, {!r}, {!r}, {!r})".format(self.path, self.line, self.rule_id, self.message)


_RULES = (
    ("PY001", re.compile(r"\bos\.system\s*\("), "Use of os.system may execute a shell command with unsafe input."),
)

_SECRET_RULES = (
    ("SEC001", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Possible AWS access key ID found; treat it as sensitive and rotate if real."),
    ("SEC002", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "Possible GitHub token found; treat it as sensitive and revoke if real."),
    ("SEC003", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private key material header found; protect the key and rotate if exposed."),
)


def scan_path(path: Union[str, Path]) -> List[Finding]:
    """Scan a Python file or recursively scan Python files in a directory.

    Paths in findings are relative to the scanned directory when scanning a directory.
    """
    target = Path(path)
    if target.is_file():
        return scan_file(target)
    if not target.is_dir():
        raise ValueError("Scan target must be an existing file or directory")

    ignored_directories = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules"}
    findings = []
    for source in sorted(target.rglob("*.py")):
        relative = source.relative_to(target)
        if any(part.startswith(".") or part in ignored_directories for part in relative.parts[:-1]):
            continue
        for finding in scan_file(source):
            findings.append(Finding(relative.as_posix(), finding.line, finding.rule_id, finding.message))
    return findings


def scan_file(path: Union[str, Path]) -> List[Finding]:
    """Statically scan a Python source file for known risky patterns."""
    file_path = Path(path)
    findings = []

    for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        for rule_id, pattern, message in _RULES + _SECRET_RULES:
            if pattern.search(line):
                findings.append(Finding(str(file_path), line_number, rule_id, message))

    return findings
