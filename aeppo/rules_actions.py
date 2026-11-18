"""GitHub Actions workflow and action rules (GHA001-GHA004).

YAML is read line by line (aeppo has no runtime dependencies), tracking only what the rules need:
the workflow triggers and the extent of ``run:`` / ``script:`` blocks. Each check returns
``(line_number, rule_id, severity_override)`` triples.
"""
import re
from pathlib import Path


_YAML_SUFFIXES = {".yml", ".yaml"}
_ACTION_NAMES = {"action.yml", "action.yaml"}

# Contexts an outside contributor controls (issue/PR text, branch names, commit messages).
_UNTRUSTED_EXPRESSION = re.compile(
    r"\$\{\{[^}]*?\b(?:"
    r"github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|(?:comment|review|review_comment)\.body"
    r"|discussion\.(?:title|body)"
    r"|pages\b[^}]*?\.page_name"
    r"|commits\b[^}]*?\.(?:message|author\.(?:email|name))"
    r"|head_commit\.(?:message|author\.(?:email|name))"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.message)"
    r")"
    r"|github\.head_ref"
    r")\b[^}]*\}\}"
)
_SCRIPT_KEY = re.compile(r"^(\s*)(?:-\s+)?(run|script)\s*:\s*(.*)$")
_USES = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*[\"']?([^@\s\"'#]+)@([^\s\"'#]+)")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_CHECKOUT_PR_HEAD = re.compile(
    r"^\s*ref\s*:\s*.*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/)"
    r"|\bgh\s+pr\s+checkout\b"
    r"|\bgit\s+(?:fetch|checkout)\b[^\n]*(?:refs/)?pull/"
)
_WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\b")
_EXTERNAL_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")


def is_actions_file(path):
    path = Path(path)
    if path.name in _ACTION_NAMES:
        return True
    parts = path.parts
    return path.suffix.lower() in _YAML_SUFFIXES and len(parts) >= 3 and parts[-2] == "workflows" and parts[-3] == ".github"


def _code_lines(lines):
    """Yield (number, line) for lines that are not YAML comments."""
    for line_number, line in enumerate(lines, start=1):
        if not line.lstrip().startswith("#"):
            yield line_number, line


def scan(lines):
    hits = []
    code = list(_code_lines(lines))
    text = "\n".join(line for _number, line in code)
    pull_request_target = "pull_request_target" in text
    external_trigger = any(trigger in text for trigger in _EXTERNAL_TRIGGERS)

    block_column = None
    for line_number, line in code:
        stripped = line.strip()
        if block_column is not None:
            column = len(line) - len(line.lstrip())
            if stripped and column <= block_column:
                block_column = None
            else:
                if _UNTRUSTED_EXPRESSION.search(line):
                    hits.append((line_number, "GHA002", None))
                if pull_request_target and _CHECKOUT_PR_HEAD.search(line):
                    hits.append((line_number, "GHA001", None))
                continue

        key = _SCRIPT_KEY.match(line)
        if key:
            value = key.group(3)
            if value.startswith(("|", ">")):
                block_column = key.start(2)
            elif _UNTRUSTED_EXPRESSION.search(value):
                hits.append((line_number, "GHA002", None))
            if pull_request_target and _CHECKOUT_PR_HEAD.search(value):
                hits.append((line_number, "GHA001", None))
            continue

        if pull_request_target and _CHECKOUT_PR_HEAD.search(line):
            hits.append((line_number, "GHA001", None))

        uses = _USES.match(line)
        if uses:
            action, ref = uses.group(1), uses.group(2)
            if not action.startswith(("./", "docker://")) and not _FULL_SHA.match(ref):
                # Mutable refs on GitHub-owned actions are common and lower risk than third-party ones.
                severity = "low" if action.split("/", 1)[0] in {"actions", "github"} else None
                hits.append((line_number, "GHA003", severity))

        if _WRITE_ALL.match(line):
            hits.append((line_number, "GHA004", "high" if external_trigger else None))
    return hits
