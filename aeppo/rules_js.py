"""JavaScript and TypeScript rules (JS001-JS003), matched per line after substring prefilters."""
import re

from aeppo.findings import make_finding as _finding


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
_JS_COMMENT_PREFIXES = ("//", "/*", "*")
# A method named ``Function`` (for example a Babel visitor: ``Function(path) {``) is a definition,
# not a call to the Function constructor.
# Matches anywhere on the line so inline visitors (``{ Function(path) { ... } }``) are covered; a
# call to the constructor is never directly followed by a ``{`` body (or a TS return type and body).
_JS_FUNCTION_METHOD = re.compile(r"(?<![\w$.])(?:async\s+)?Function\s*\([^)]*\)\s*(?::\s*[\w$<>\[\], |.]+)?\s*\{")
# ES module and CommonJS variants (.mjs/.cjs) and their TypeScript counterparts (.mts/.cts).
_JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}


def scan(path, lines):
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
