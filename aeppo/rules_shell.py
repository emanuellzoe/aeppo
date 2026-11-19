"""Shell script rules (SH001-SH005).

Scripts are matched line by line; comment lines are skipped. Each check returns
``(line_number, rule_id)`` pairs and the scanner turns them into findings.
"""
import re
from pathlib import Path


SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh", ".ps1"}
# direnv runs .envrc automatically when you cd into the directory (after `direnv allow`).
SHELL_NAMES = {".envrc"}

_SHEBANG = re.compile(r"^#!\s*(?:/usr/bin/env\s+(?:-\S+\s+)*)?(?:/(?:usr/)?(?:local/)?bin/)?(?:ba|z|da|k)?sh\b")
# A shell reading stdin runs it (``| sh``, ``| bash -s -- --flag``), unless it gets ``-c``. Other
# interpreters only run stdin with no script argument or with ``-``; ``| python3 -m json.tool`` or
# ``| node script.js`` merely process the downloaded data.
_INTERPRETER = (
    r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?"
    r"(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)"
    r"|(?:python[0-9.]*|perl|ruby|node)(?=\s*(?:$|[;&|)]|-(?:\s|$))))"
)

_RULES = (
    # Download piped straight into an interpreter, or sourced via process substitution / eval.
    (
        "SH001",
        re.compile(
            r"\b(?:curl|wget)\b[^|;&\n]*\|\s*" + _INTERPRETER
            + r"|(?:\bsource|(?<![\w.])\.|\b(?:ba|z)?sh)\s+<\(\s*(?:curl|wget)\b"
            + r"|\beval\s+[\"']?\$\(\s*(?:curl|wget)\b"
            # PowerShell download cradles (case-insensitive): iwr ... | iex, iex (... DownloadString(...)).
            + r"|(?i:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b[^|\n]*\|\s*(?:iex|invoke-expression)\b)"
            + r"|(?i:\b(?:iex|invoke-expression)\b[^\n]*\b(?:downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod)\b)"
        ),
    ),
    # Reverse shells. A bare /dev/tcp is also used by wait-for-it style health checks, so it only
    # counts together with an interactive shell or a stdin/stdout redirect onto the socket.
    (
        "SH002",
        re.compile(
            r"\b(?:ba|z|da|k)?sh\s+-i\b[^\n]*/dev/(?:tcp|udp)/"
            r"|/dev/(?:tcp|udp)/[^\n]*\b(?:0>&1|0<&\d+|>&\s*/dev/(?:tcp|udp))"
            r"|\b(?:nc|ncat|netcat)\b[^\n;|]*\s-[ce]\s*\S*\b(?:ba|z|da|k)?sh\b"
            r"|\bsocat\b[^\n]*\bexec:[^\n]*\b(?:ba|z|da|k)?sh\b"
            r"|\bmkfifo\b[^\n]*\b(?:nc|ncat|netcat)\b"
        ),
    ),
    # Encoded payload decoded and executed.
    (
        "SH003",
        re.compile(
            r"\b(?:base64\s+(?:-d|-D|--decode)|xxd\s+-r|openssl\s+(?:enc\s+)?-?base64\s+-d)\b[^\n|]*\|\s*" + _INTERPRETER
            + r"|\beval\s+[\"']?\$\([^)\n]*\b(?:base64\s+(?:-d|-D|--decode)|xxd\s+-r)"
            # powershell -EncodedCommand <base64>
            + r"|(?i:\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,})"
        ),
    ),
    # Persistence: new SSH authorized key or cron entry.
    (
        "SH004",
        re.compile(
            r"(?:>>?|\btee\s+(?:-a\s+)?)\s*[\"']?(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/\s\"']+)/\.ssh/authorized_keys\b"
            r"|\|\s*crontab\s+-(?:\s|$)"
            r"|(?:>>?|\btee\s+(?:-a\s+)?)\s*[\"']?/etc/cron"
        ),
    ),
    # Shell startup file changes. Installers (nvm, rustup) do this legitimately, so it is a low
    # severity review signal.
    (
        "SH005",
        re.compile(r"(?:>>|\btee\s+-a)\s*[\"']?(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|bash_profile|profile|zshrc|zprofile|zshenv)\b"),
    ),
)

# Cheap substring gate per line (checked against the lowercased line): every rule needs one.
_HINTS = (
    "curl", "wget", "/dev/", "nc", "socat", "mkfifo", "base64", "xxd", "authorized_keys", "crontab", "cron", "rc", "profile", "zshenv",
    "iex", "invoke-", "iwr", "irm", "powershell", "pwsh",
)


def has_shell_shebang(first_line):
    return bool(_SHEBANG.match(first_line))


def is_shell_script(path):
    """True for .sh-style names, or an extensionless file whose first line is a shell shebang."""
    path = Path(path)
    if path.suffix.lower() in SHELL_EXTENSIONS or path.name in SHELL_NAMES:
        return True
    if path.suffix:
        return False
    try:
        with path.open("rb") as handle:
            head = handle.read(128)
    except OSError:
        return False
    return head.startswith(b"#!") and has_shell_shebang(head.split(b"\n", 1)[0].decode("utf-8", "replace"))


_PRINT_COMMAND = re.compile(r"^(?:echo|printf)\b")


def _mask_quoted_text(line):
    """Blank out quoted text, keeping ``$(...)`` inside double quotes because the shell runs it.

    ``echo "curl ... | sh"`` only prints install instructions; ``echo payload | sh`` (pipe outside
    the quotes) and ``echo "$(curl ...)"`` still run something and stay visible.
    """
    out = []
    quote = None
    depth = 0
    index = 0
    while index < len(line):
        char = line[index]
        if quote is None:
            if char in "'\"":
                quote = char
                out.append(" ")
            else:
                out.append(char)
        elif quote == "'":
            if char == "'":
                quote = None
            out.append(" ")
        else:  # inside double quotes
            if depth == 0 and char == "\\" and index + 1 < len(line):
                out.append("  ")
                index += 2
                continue
            if line.startswith("$(", index):
                depth += 1
                out.append("$(")
                index += 2
                continue
            if depth:
                depth += char == "("
                depth -= char == ")"
                out.append(char)
            elif char == '"':
                quote = None
                out.append(" ")
            else:
                out.append(" ")
        index += 1
    return "".join(out)


def check_command(text):
    """Return the shell rule IDs that match one command or line of shell text.

    Also used for commands embedded in other files (Dockerfile RUN, VS Code tasks, build scripts).
    """
    stripped = text.lstrip()
    lowered = text.lower()
    if not stripped or not any(hint in lowered for hint in _HINTS):
        return []
    # Printed instructions: only what runs outside the quoted text counts.
    if _PRINT_COMMAND.match(stripped):
        text = _mask_quoted_text(text)
    return [rule_id for rule_id, pattern in _RULES if pattern.search(text)]


def scan(lines):
    hits = []
    for line_number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue
        hits.extend((line_number, rule_id) for rule_id in check_command(line))
    return hits
