"""Python rules (PY001-PY006), matched on the AST with import, alias, ``__import__`` and
``getattr`` resolution. Files that do not parse fall back to line patterns."""
import ast
import re

from aeppo.findings import make_finding as _finding


# Line-based fallback for Python files that do not parse (for example Python 2 sources).
_PYTHON_FALLBACK_PATTERNS = (
    ("PY001", re.compile(r"\bos\.(?:system|popen)\s*\(")),
    ("PY002", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(")),
)


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


def scan(path, lines):
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
