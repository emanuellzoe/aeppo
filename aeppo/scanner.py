import ast
import fnmatch
import hashlib
import json
import os
import re
from collections import namedtuple
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Union

from aeppo import rules_actions, rules_shell


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


class Finding:
    def __init__(self, path, line, rule_id, message, severity="medium", confidence="medium", category="code-risk", recommendation="Review this finding in context.", fingerprint=""):
        self.path = path
        self.line = line
        self.rule_id = rule_id
        self.message = message
        self.severity = severity
        self.confidence = confidence
        self.category = category
        self.recommendation = recommendation
        self.fingerprint = fingerprint

    def __eq__(self, other):
        return isinstance(other, Finding) and self.__dict__ == other.__dict__

    def __repr__(self):
        return "Finding({!r}, {!r}, {!r}, {!r})".format(self.path, self.line, self.rule_id, self.message)


Rule = namedtuple("Rule", "message severity confidence category recommendation")

_REVOKE = "Revoke and rotate it if it is real; do not commit credentials."

RULES = {
    "PY001": Rule("Use of os.system or os.popen may execute a shell command with unsafe input.", "medium", "medium", "command-execution", "Prefer argument-list APIs such as subprocess.run([...]) and validate untrusted input."),
    "PY002": Rule("Dynamic code execution can run attacker-controlled input.", "high", "medium", "dynamic-code", "Avoid dynamic evaluation or strictly constrain and validate the input."),
    "PY003": Rule("subprocess call runs its command through a shell.", "high", "medium", "command-execution", "Pass an argument list without shell=True, or quote untrusted values with shlex.quote."),
    "PY004": Rule("Unpickling can execute arbitrary code when the data is untrusted.", "high", "medium", "unsafe-deserialization", "Only unpickle trusted data; prefer JSON or another data-only format."),
    "PY005": Rule("yaml.load without a safe loader can construct arbitrary Python objects.", "high", "medium", "unsafe-deserialization", "Use yaml.safe_load or pass Loader=yaml.SafeLoader."),
    "PY006": Rule("Spawns an interactive shell, a common reverse-shell or backdoor pattern.", "high", "medium", "backdoor", "Confirm why the program needs an interactive shell and remove it if it is unexpected."),
    "JS001": Rule("Use of eval may execute dynamically constructed JavaScript.", "high", "medium", "dynamic-code", "Avoid eval and use explicit parsing or dispatch."),
    "JS002": Rule("Shell command execution may be unsafe when arguments include untrusted input.", "high", "medium", "command-execution", "Prefer execFile/spawn with an argument array and validate untrusted input."),
    "JS003": Rule("Function constructor or string-based timer evaluates code at runtime.", "high", "medium", "dynamic-code", "Pass a function instead of a code string and avoid new Function."),
    "SEC001": Rule("Possible AWS access key ID found.", "high", "medium", "secret", _REVOKE),
    "SEC002": Rule("Possible GitHub token found.", "high", "medium", "secret", _REVOKE),
    "SEC003": Rule("Private key material header found.", "high", "high", "secret", "Protect the key and rotate it if it was exposed."),
    "SEC004": Rule("Possible Slack token found.", "high", "medium", "secret", _REVOKE),
    "SEC005": Rule("Possible Stripe live secret or restricted key found.", "high", "high", "secret", _REVOKE),
    "SEC006": Rule("Possible OpenAI API key found.", "high", "medium", "secret", _REVOKE),
    "SEC007": Rule("Possible Anthropic API key found.", "high", "high", "secret", _REVOKE),
    "SEC008": Rule("Possible Google API key found.", "high", "medium", "secret", _REVOKE),
    "DEP001": Rule("Dependency has no version constraint.", "low", "high", "dependency-management", "Pin dependencies to reviewed versions and use a lockfile where possible."),
    "DEP002": Rule("Dependency uses a direct URL, VCS, or local path reference.", "medium", "high", "supply-chain", "Verify the source and pin it to an immutable commit or trusted artifact."),
    "DEP003": Rule("Package defines an install lifecycle script that runs during installation.", "medium", "high", "dependency-install-script", "Inspect the script and its transitive commands before installing dependencies."),
    "SH001": Rule("Shell script downloads remote content and runs it.", "high", "high", "supply-chain", "Download to a file, verify its checksum or signature, and review it before running."),
    "SH002": Rule("Shell script opens a reverse shell.", "high", "medium", "backdoor", "Remove it unless the script is an intended remote-access tool."),
    "SH003": Rule("Shell script decodes an encoded payload and runs it.", "high", "medium", "obfuscation", "Decode the payload and review it; ship readable scripts instead of encoded ones."),
    "SH004": Rule("Shell script installs persistence (SSH authorized key or cron entry).", "high", "medium", "backdoor", "Confirm the key or job is expected; installers should not add access or schedules silently."),
    "SH005": Rule("Shell script modifies a shell startup file.", "low", "low", "persistence", "Review what is appended; installers commonly add PATH entries, but this can also hide persistence."),
    "GHA001": Rule("pull_request_target workflow checks out or fetches code from the pull request.", "high", "high", "ci-security", "Do not run untrusted PR code with pull_request_target; use pull_request, or split the privileged step into a workflow_run job."),
    "GHA002": Rule("Untrusted GitHub context is expanded directly into a script.", "high", "high", "ci-security", "Pass the value through an environment variable (env: TITLE: ${{ ... }}) and quote \"$TITLE\" in the script."),
    "GHA003": Rule("Action is referenced by a mutable tag or branch instead of a full commit SHA.", "medium", "high", "supply-chain", "Pin the action to a full 40-character commit SHA and note the version in a comment."),
    "GHA004": Rule("Workflow grants write-all permissions.", "medium", "high", "ci-security", "Grant only the permissions each job needs, starting from contents: read."),
    "DEP004": Rule("Install script downloads remote content and pipes it into an interpreter.", "high", "high", "supply-chain", "Do not install until the downloaded script is reviewed; vendor it or pin it to a verified checksum."),
    "SRC001": Rule("Bidirectional Unicode control character can make code render differently from how it runs (Trojan Source).", "high", "medium", "obfuscation", "Remove the control character, or confirm it only appears inside an intended string literal."),
}

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

# Line-based fallback for Python files that do not parse (for example Python 2 sources).
_PYTHON_FALLBACK_PATTERNS = (
    ("PY001", re.compile(r"\bos\.(?:system|popen)\s*\(")),
    ("PY002", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(")),
)

# Calls such as ``pattern.exec(text)`` (RegExp) are method calls on unrelated objects, so a
# bare name must not be preceded by ``.``, ``$`` or a word character. ``.then(eval)`` passes
# eval itself as a callback, which runs whatever text the promise resolves to.
_JS_EVAL = re.compile(r"(?<![\w$.])eval\s*\(|[(,]\s*eval\s*[),]")
# ``require('child_process').exec(...)`` calls the module without binding it to a name first.
_JS_EXEC_TEMPLATE = r"(?:\b(?:{})|require\(\s*['\"](?:node:)?child_process['\"]\s*\))\s*\.(?:exec|execSync)\s*\("
# A bare ``exec(`` is only a shell call when it comes from child_process (``const { exec } =
# require('child_process')``). Files that never mention child_process often define their own
# ``exec`` helper (for example a contract or database call), so bare calls there are not reported.
_JS_BARE_EXEC = r"(?<![\w$.])(?:exec|execSync)\s*\("
# ``spawn('sh', ['-c', cmd])`` with a non-literal command: a variable or a template with ``${}``.
_JS_SHELL = re.compile(
    r"\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*['\"`](?:/(?:usr/)?bin/)?(?:ba|z|da|k)?sh['\"`]\s*,\s*\[\s*['\"]-[A-Za-z]*c[A-Za-z]*['\"]\s*,"
    r"\s*(?:[A-Za-z_$][\w$.]*\s*[\],+]|`[^`]*\$\{)"
)
_JS_EXEC_DEFINITION = re.compile(r"(?:\basync\s+|\bfunction\b\s*\*?\s*)(?:exec|execSync)\s*\(|^\s*(?:exec|execSync)\s*\([^)]*\)\s*\{")
_JS_CHILD_PROCESS_ALIAS = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?:node:)?child_process['"]\s*\)"""
    r"""|\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['"](?:node:)?child_process['"]"""
)
# ``Function(...)`` builds code with or without ``new``; type annotations (``x: Function``) have no call.
_JS_DYNAMIC = re.compile(r"(?<![\w$.])Function\s*\(|(?<![\w$])(?:(?:window|globalThis|self)\.)?(?:setTimeout|setInterval)\s*\(\s*['\"`]")
# Trojan Source (CVE-2021-42574): embedding/override/isolate controls reorder how code is displayed.
_BIDI_CONTROL = re.compile("[\u202a-\u202e\u2066-\u2069]")
_REMOTE_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|node|python3?|perl|ruby)\b"
    r"|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
)
_JS_COMMENT_PREFIXES = ("//", "/*", "*")
# A method named ``Function`` (for example a Babel visitor: ``Function(path) {``) is a definition,
# not a call to the Function constructor.
# Matches anywhere on the line so inline visitors (``{ Function(path) { ... } }``) are covered; a
# call to the constructor is never directly followed by a ``{`` body (or a TS return type and body).
_JS_FUNCTION_METHOD = re.compile(r"(?<![\w$.])(?:async\s+)?Function\s*\([^)]*\)\s*(?::\s*[\w$<>\[\], |.]+)?\s*\{")
# ES module and CommonJS variants (.mjs/.cjs) and their TypeScript counterparts (.mts/.cts).
_JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
# Documentation is checked for leaked secrets only; code rules would misfire on prose and snippets.
_DOCUMENT_EXTENSIONS = {".md", ".markdown", ".mdx"}

_SUPPRESSION = re.compile(r"aeppo:\s*ignore(-next-line)?(?:\[([A-Za-z0-9_,\s]+)\])?")

_SOURCE_EXTENSIONS = {".py"} | _JS_EXTENSIONS
# ``.env`` as an extension covers names such as ``production.env``; ``.env`` and ``.env.*`` are
# matched by name in ``_supported``.
_CONFIG_EXTENSIONS = {".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".env"}
_MANIFEST_NAMES = {"requirements.txt", "package.json"}
_IGNORED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules"}
_DEFAULT_MAX_FILE_SIZE = 1024 * 1024


def _finding(path, line, rule_id, message=None):
    rule = RULES[rule_id]
    return Finding(path, line, rule_id, message or rule.message, rule.severity, rule.confidence, rule.category, rule.recommendation)


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


def _secret_findings(path, lines):
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


def _bidi_findings(path, lines):
    # Only source files: translation and data files can legitimately carry these characters.
    if not _BIDI_CONTROL.search("\n".join(lines)):
        return []
    return [_finding(path, line_number, "SRC001") for line_number, line in enumerate(lines, start=1) if _BIDI_CONTROL.search(line)]


def _supported(path):
    name = path.name
    return (
        path.suffix.lower() in _SOURCE_EXTENSIONS | _CONFIG_EXTENSIONS | _DOCUMENT_EXTENSIONS | rules_shell.SHELL_EXTENSIONS
        or name in _MANIFEST_NAMES
        or name == ".env"
        or name.startswith(".env.")
        or (not path.suffix and rules_shell.is_shell_script(path))
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

    The one hidden directory entered is ``.github``, and inside it only ``workflows/*.yml|yaml``.
    """
    candidates = []
    for directory, subdirectories, files in os.walk(target):
        relative = Path(directory).relative_to(target).parts
        if ".github" in relative:
            subdirectories[:] = ["workflows"] if relative[-1] == ".github" and "workflows" in subdirectories else []
            if relative[-1] == "workflows":
                candidates.extend(Path(directory, name) for name in files if Path(name).suffix.lower() in {".yml", ".yaml"} and Path(directory, name).is_file())
            continue
        subdirectories[:] = [name for name in subdirectories if name == ".github" or (not name.startswith(".") and name not in _IGNORED_DIRECTORIES)]
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
    findings = _secret_findings(display_path, lines)
    if suffix in _DOCUMENT_EXTENSIONS:
        return _finalize(findings, lines)
    if suffix in _SOURCE_EXTENSIONS:
        findings.extend(_bidi_findings(display_path, lines))
    if file_path.name == "requirements.txt":
        findings.extend(_scan_requirements(display_path, lines))
    elif file_path.name == "package.json":
        findings.extend(_scan_package_json(display_path, "\n".join(lines)))
    elif suffix == ".py":
        findings.extend(_scan_python(display_path, lines))
    elif suffix in _JS_EXTENSIONS:
        findings.extend(_scan_javascript(display_path, lines))
    elif rules_actions.is_actions_file(file_path):
        for line_number, rule_id, severity in rules_actions.scan(lines):
            finding = _finding(display_path, line_number, rule_id)
            if severity:
                finding.severity = severity
            findings.append(finding)
    elif suffix in rules_shell.SHELL_EXTENSIONS or (not suffix and lines and rules_shell.has_shell_shebang(lines[0])):
        findings.extend(_finding(display_path, line_number, rule_id) for line_number, rule_id in rules_shell.scan(lines))
    return _finalize(findings, lines)


def filter_findings(findings: Iterable[Finding], min_severity: str = "low", baseline: Optional[Set[Tuple[str, str, str]]] = None) -> List[Finding]:
    """Drop findings below ``min_severity`` and findings already recorded in ``baseline``."""
    if min_severity not in SEVERITY_ORDER:
        raise ValueError("min_severity must be one of: {}".format(", ".join(SEVERITY_ORDER)))
    threshold = SEVERITY_ORDER[min_severity]
    known = baseline or set()
    return [
        finding
        for finding in findings
        if SEVERITY_ORDER.get(finding.severity, 1) >= threshold
        and (finding.path, finding.rule_id, finding.fingerprint) not in known
    ]


def load_baseline(path: Union[str, Path]) -> Set[Tuple[str, str, str]]:
    """Load a baseline written by ``aeppo scan --format json``."""
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not all(isinstance(entry, dict) and {"path", "rule_id", "fingerprint"} <= entry.keys() for entry in entries):
        raise ValueError("Baseline must be a JSON array written by 'aeppo scan --format json'")
    return {(entry["path"], entry["rule_id"], entry["fingerprint"]) for entry in entries}


_SUBPROCESS_FUNCTIONS = {"run", "call", "check_call", "check_output", "Popen"}
_SUBPROCESS_SHELL_FUNCTIONS = {"getoutput", "getstatusoutput"}
_PICKLE_MODULES = {"pickle", "_pickle", "cPickle", "dill"}
_UNSAFE_YAML_LOADERS = {"Loader", "FullLoader", "UnsafeLoader", "CLoader", "CFullLoader", "CUnsafeLoader"}
_TRACKED_MODULES = {"os", "subprocess", "yaml", "pty", "importlib"} | _PICKLE_MODULES
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}


# A Python rule can only fire if the file contains one of these call or import shapes, so
# files without them skip the (comparatively expensive) AST parse and walk entirely.
# ``name as`` covers ``from os import system as run`` where the call site no longer names it.
# Deserialization names (``loads`` and friends) are common (``json.loads``), so they only count
# when a tracked module is mentioned. Avoid leading lookbehinds here: they defeat re's fast scan.
_PYTHON_HINT = re.compile(r"\b(?:eval|exec|system|popen|getoutput|getstatusoutput)(?:\s*\(|\s+as\s)|\bshell\s*=\s*True")
_PYTHON_DESERIALIZE_HINT = re.compile(r"\b(?:loads?|load_all|unsafe_load(?:_all)?|Unpickler)(?:\s*\(|\s+as\s)")
_PYTHON_DESERIALIZE_MODULES = ("pickle", "dill", "yaml")


# Dynamic imports, getattr lookups, pty and shell argument lists can hide the call names above.
# Each is guarded by a plain substring test first, which is much cheaper than a regex scan.
_PYTHON_DYNAMIC_IMPORT_HINT = re.compile(r"(?:__import__|import_module)\s*\(\s*['\"](?:os|subprocess|yaml|pty|pickle|_pickle|cPickle|dill)['\"]")
_PYTHON_PTY_HINT = re.compile(r"\bpty\.spawn\b|\bfrom\s+pty\s+import\b|\bimport\s+pty\b")
_PYTHON_GETATTR_HINT = re.compile(r"\bgetattr\s*\([^,()]+,\s*['\"](?:system|popen|getoutput|getstatusoutput|run|call|check_call|check_output|Popen|loads?|unsafe_load)['\"]")
_PYTHON_SHELL_ARGV_HINT = re.compile(r"['\"](?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k)?sh|cmd(?:\.exe)?|pwsh|powershell(?:\.exe)?)['\"]\s*,\s*['\"][-/]")


def _python_may_match(source):
    if ("__import__" in source or "import_module" in source) and _PYTHON_DYNAMIC_IMPORT_HINT.search(source):
        return True
    if "pty" in source and _PYTHON_PTY_HINT.search(source):
        return True
    if "getattr" in source and _PYTHON_GETATTR_HINT.search(source):
        return True
    if ("sh'" in source or 'sh"' in source or "cmd" in source or "powershell" in source) and _PYTHON_SHELL_ARGV_HINT.search(source):
        return True
    if _PYTHON_HINT.search(source):
        return True
    return any(module in source for module in _PYTHON_DESERIALIZE_MODULES) and bool(_PYTHON_DESERIALIZE_HINT.search(source))


def _string_constant(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _module_of(node, modules, names):
    """Resolve an expression to a tracked module name, including ``__import__("os")``."""
    if isinstance(node, ast.Name):
        return modules.get(node.id)
    if not (isinstance(node, ast.Call) and node.args):
        return None
    imported = _string_constant(node.args[0])
    if imported not in _TRACKED_MODULES:
        return None
    func = node.func
    if isinstance(func, ast.Name) and (func.id == "__import__" or names.get(func.id) == ("importlib", "import_module")):
        return imported
    if isinstance(func, ast.Attribute) and func.attr == "import_module" and _module_of(func.value, modules, names) == "importlib":
        return imported
    return None


def _call_target(func, modules, names):
    if isinstance(func, ast.Attribute):
        module = _module_of(func.value, modules, names)
        if module:
            return module, func.attr
    if isinstance(func, ast.Name) and func.id in names:
        return names[func.id]
    # getattr(os, "system")(...) hides the attribute name from a plain attribute lookup.
    if isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "getattr" and len(func.args) >= 2:
        attribute = _string_constant(func.args[1])
        module = _module_of(func.args[0], modules, names)
        if module and attribute:
            return module, attribute
    return None


_SHELL_COMMAND_FLAG = re.compile(r"^(?:-[A-Za-z]*c[A-Za-z]*|/c|-Command)$", re.IGNORECASE)


def _is_shell(node):
    program = _string_constant(node)
    return program is not None and program.replace("\\", "/").rsplit("/", 1)[-1].lower() in _SHELLS


def _shell_invocation(call):
    """Classify a ``["sh", ...]`` argument list.

    ``"interactive"``: the shell is started with ``-i`` (reverse-shell shape).
    ``"dynamic"``: ``-c`` runs a command string that is not a literal, so it can carry injected input.
    Running a script file or a literal ``-c`` command is not reported.
    """
    if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)) or not call.args[0].elts:
        return None
    items = call.args[0].elts
    if not _is_shell(items[0]):
        return None
    if any(_string_constant(item) == "-i" for item in items[1:]):
        return "interactive"
    for index, item in enumerate(items[1:], start=1):
        flag = _string_constant(item)
        if flag and _SHELL_COMMAND_FLAG.match(flag):
            command = items[index + 1] if index + 1 < len(items) else None
            if command is not None and _string_constant(command) is None:
                return "dynamic"
            return None
    return None


def _is_true(node):
    return isinstance(node, ast.Constant) and node.value is True


def _uses_unsafe_yaml_loader(call):
    if any(keyword.arg is None for keyword in call.keywords):
        return False  # ``**kwargs`` may supply a safe loader; avoid guessing.
    loader = next((keyword.value for keyword in call.keywords if keyword.arg == "Loader"), None)
    if loader is None and len(call.args) > 1:
        loader = call.args[1]
    if loader is None:
        return True
    if isinstance(loader, ast.Attribute):
        return loader.attr in _UNSAFE_YAML_LOADERS
    if isinstance(loader, ast.Name):
        return loader.id in _UNSAFE_YAML_LOADERS
    return False


def _python_rule(call, modules, names):
    func = call.func
    if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
        return "PY002"
    target = _call_target(func, modules, names)
    if target is None:
        return None
    module, attribute = target
    if module == "os" and attribute in {"system", "popen"}:
        return "PY001"
    if module == "pty" and attribute == "spawn" and call.args:
        program = call.args[0]
        if isinstance(program, (ast.List, ast.Tuple)) and program.elts:
            program = program.elts[0]
        if _is_shell(program):
            return "PY006"
    if module == "subprocess":
        if attribute in _SUBPROCESS_SHELL_FUNCTIONS:
            return "PY003"
        if attribute in _SUBPROCESS_FUNCTIONS:
            invocation = _shell_invocation(call)
            if invocation == "interactive":
                return "PY006"
            if invocation == "dynamic" or any(keyword.arg == "shell" and _is_true(keyword.value) for keyword in call.keywords):
                return "PY003"
    if module in _PICKLE_MODULES and attribute in {"load", "loads", "Unpickler"}:
        return "PY004"
    if module == "yaml":
        if attribute in {"unsafe_load", "unsafe_load_all"}:
            return "PY005"
        if attribute in {"load", "load_all"} and _uses_unsafe_yaml_loader(call):
            return "PY005"
    return None


def _scan_python(path, lines):
    """Match real calls via the AST so comments, strings and unrelated methods are ignored."""
    source = "\n".join(lines)
    if not _python_may_match(source):
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [
            _finding(path, line_number, rule_id)
            for line_number, line in enumerate(lines, start=1)
            for rule_id, pattern in _PYTHON_FALLBACK_PATTERNS
            if pattern.search(line)
        ]
    # One walk collects both imports and calls; calls are resolved once all aliases are known.
    modules = {name: name for name in _TRACKED_MODULES}
    names = {}
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append(node)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _TRACKED_MODULES and alias.asname:
                    modules[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in _TRACKED_MODULES:
            for alias in node.names:
                names[alias.asname or alias.name] = (node.module, alias.name)
    hits = set()
    for call in calls:
        rule_id = _python_rule(call, modules, names)
        if rule_id:
            hits.add((call.lineno, rule_id))
    return [_finding(path, line_number, rule_id) for line_number, rule_id in sorted(hits)]


def _scan_javascript(path, lines):
    source = "\n".join(lines)
    has_eval, has_exec = "eval" in source, "exec" in source
    has_dynamic = "Function" in source or "setTimeout" in source or "setInterval" in source
    has_shell = "spawn" in source or "execFile" in source
    if not (has_eval or has_exec or has_dynamic or has_shell):
        return []
    exec_pattern = None
    if has_exec:
        aliases = {"child_process"}
        uses_child_process = "child_process" in source
        if uses_child_process:
            for required, imported in _JS_CHILD_PROCESS_ALIAS.findall(source):
                aliases.add(required or imported)
        pattern = _JS_EXEC_TEMPLATE.format("|".join(re.escape(alias) for alias in sorted(aliases)))
        if uses_child_process:
            pattern += "|" + _JS_BARE_EXEC
        exec_pattern = re.compile(pattern)
    findings = []
    for line_number, line in enumerate(lines, start=1):
        # Substring checks are far cheaper than regex searches and skip almost every line.
        line_eval = has_eval and "eval" in line
        line_exec = has_exec and "exec" in line
        line_dynamic = has_dynamic and ("Function" in line or "set" in line)
        line_shell = has_shell and "sh" in line
        if not (line_eval or line_exec or line_dynamic or line_shell) or line.lstrip().startswith(_JS_COMMENT_PREFIXES):
            continue
        if line_eval and _JS_EVAL.search(line):
            findings.append(_finding(path, line_number, "JS001"))
        exec_call = line_exec and exec_pattern.search(line) and not _JS_EXEC_DEFINITION.search(line)
        if exec_call or (line_shell and _JS_SHELL.search(line)):
            findings.append(_finding(path, line_number, "JS002"))
        if line_dynamic and _JS_DYNAMIC.search(line) and not _JS_FUNCTION_METHOD.search(line):
            findings.append(_finding(path, line_number, "JS003"))
    return findings


def _scan_requirements(path, lines):
    findings = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("http://", "https://", "git+")) or " @ " in line:
            findings.append(_finding(path, line_number, "DEP002", "Dependency uses a direct URL or VCS reference."))
        elif re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?$", line):
            findings.append(_finding(path, line_number, "DEP001"))
    return findings


def _scan_package_json(path, raw):
    try:
        package = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(package, dict):
        return []
    raw_lines = raw.splitlines()
    findings = []
    scripts = package.get("scripts", {})
    if isinstance(scripts, dict):
        # ``prepare`` also runs when the package is installed from a git URL.
        for name in ("preinstall", "install", "postinstall", "prepare"):
            if name not in scripts:
                continue
            line = next((index for index, text in enumerate(raw_lines, start=1) if '"' + name + '"' in text), 1)
            if name != "prepare":
                findings.append(_finding(path, line, "DEP003", "Package defines an {} lifecycle script that runs during installation.".format(name)))
            command = scripts[name]
            if isinstance(command, str) and _REMOTE_PIPE.search(command):
                findings.append(_finding(path, line, "DEP004", "The {} script downloads remote content and pipes it into an interpreter.".format(name)))
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = package.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            if isinstance(version, str) and version.startswith(("git+", "http://", "https://", "file:")):
                key, value = json.dumps(name), json.dumps(version)
                line = next((index for index, text in enumerate(raw_lines, start=1) if key in text and value in text), 1)
                findings.append(_finding(path, line, "DEP002", "Dependency {} uses a direct URL, VCS, or local path reference.".format(name)))
    return findings
