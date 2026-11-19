"""Secret rules (SEC001-SEC008) and Trojan Source bidirectional controls (SRC001)."""
import re

from aeppo.findings import RULES, make_finding as _finding


_SECRET_PATTERNS = (
    ("SEC001", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SEC002", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("SEC003", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    # Provider formats are kept close to the issued shape (numeric Slack IDs, versioned
    # Anthropic prefixes, long OpenAI project keys) so short placeholders are not reported.
    ("SEC004", re.compile(r"\bxox[abposr]-[0-9]{8,}-[0-9A-Za-z-]{10,}")),
    ("SEC005", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}")),
    ("SEC006", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{48}\b")),
    ("SEC007", re.compile(r"\bsk-ant-(?:api|admin|oat|sid)[0-9]{2}-[A-Za-z0-9_-]{32,}")),
    ("SEC008", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])")),
)

# Trojan Source (CVE-2021-42574): embedding/override/isolate controls reorder how code is displayed.
_BIDI_CONTROL = re.compile("[\u202a-\u202e\u2066-\u2069]")


# Every secret pattern contains one of these literals; checking them first keeps the
# per-line cost to a single regex search for the vast majority of lines.
_SECRET_HINT = re.compile(r"AKIA|gh[pousr]_|-----BEGIN|xox|k_live_|sk-|AIza")


# Provider documentation uses placeholder credentials that contain the word EXAMPLE (AWS documents
# ``AKIA...EXAMPLE``). They are still reported, so nothing is hidden, but at low severity and
# confidence so ``--min-severity medium`` filters them out.
_EXAMPLE_MARKER = "EXAMPLE"


def _looks_like_placeholder(value):
    # ``EXAMPLE`` keys, or a tail made of one or two repeated characters (``ghp_xxxx...``, ``AAAA...``).
    return _EXAMPLE_MARKER in value or len(set(value[-16:])) <= 2


def secret_findings(path, lines):
    findings = []
    for line_number, line in enumerate(lines, start=1):
        if not _SECRET_HINT.search(line):
            continue
        for rule_id, pattern in _SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            finding = _finding(path, line_number, rule_id)
            if _looks_like_placeholder(match.group(0)):
                finding.message = "Placeholder or documented example credential found ({}).".format(RULES[rule_id].message.rstrip("."))
                finding.severity = "low"
                finding.confidence = "low"
            findings.append(finding)
    return findings


def bidi_findings(path, lines):
    # Only source files: translation and data files can legitimately carry these characters.
    if not _BIDI_CONTROL.search("\n".join(lines)):
        return []
    return [_finding(path, line_number, "SRC001") for line_number, line in enumerate(lines, start=1) if _BIDI_CONTROL.search(line)]
