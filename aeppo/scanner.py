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
    ("JS001", re.compile(r"\beval\s*\("), "Use of eval may execute dynamically constructed JavaScript."),
)

_SECRET_RULES = (
    ("SEC001", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Possible AWS access key ID found; treat it as sensitive and rotate if real."),
    ("SEC002", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "Possible GitHub token found; treat it as sensitive and revoke if real."),
    ("SEC003", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private key material header found; protect the key and rotate if exposed."),
)


def scan_path(path: Union[str, Path]) -> List[Finding]:
    """Scan a supported source file or recursively scan source files in a directory.

    Paths in findings are relative to the scanned directory when scanning a directory.
    """
    target = Path(path)
    if target.is_file():
        return scan_file(target)
    if not target.is_dir():
        raise ValueError("Scan target must be an existing file or directory")

    ignored_directories = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules"}
    findings = []
    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}
    for source in sorted(item for item in target.rglob("*") if item.is_file() and item.suffix.lower() in supported_extensions):
        relative = source.relative_to(target)
        if any(part.startswith(".") or part in ignored_directories for part in relative.parts[:-1]):
            continue
        for finding in scan_file(source):
            findings.append(Finding(relative.as_posix(), finding.line, finding.rule_id, finding.message))
    return findings


def scan_file(path: Union[str, Path]) -> List[Finding]:
    """Statically scan Python/JavaScript source for known risky patterns."""
    file_path = Path(path)
    findings = []

    source_rules = _RULES
    if file_path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
        source_rules = (("JS001", re.compile(r"\beval\s*\("), "Use of eval may execute dynamically constructed JavaScript."),)
    for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        rules = source_rules + _SECRET_RULES
        for rule_id, pattern, message in rules:
            if pattern.search(line):
                findings.append(Finding(str(file_path), line_number, rule_id, message))

    return findings
