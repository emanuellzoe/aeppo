"""Code rules for Go, Rust, Java/Kotlin, PHP and Ruby.

They look for the same things the Python and JavaScript rules do: a shell started with a command
built at runtime, code evaluated from a string, unsafe deserialization, and a network connection
handed to a shell (reverse shell). Matching runs on ``lexer.lex`` output, so comments and string
contents never match, and a shell command given as a plain string literal is checked with the
shell rules (SH001-SH004) instead of being reported just for existing.

Checks return ``(line_number, rule_id, severity_override, message_override)`` tuples.
"""
import posixpath
import re
from pathlib import Path

from aeppo import lexer, rules_shell


_EXTENSIONS = {
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".php": "php",
    ".phtml": "php",
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
}
# Bundler and Rake evaluate these as Ruby.
_NAMES = {"Gemfile": "ruby", "Rakefile": "ruby"}

# Substrings a file needs before it is worth lexing.
_HINTS = {
    "go": ("exec.Command", "net.Dial"),
    "rust": ("Command::new",),
    "java": ("Runtime", "ProcessBuilder", "ObjectInputStream"),
    "php": ("eval", "exec", "system", "passthru", "popen", "proc_open", "unserialize", "create_function", "assert", "preg_replace", "`"),
    "ruby": ("eval", "system", "exec", "spawn", "popen", "Open3", "Marshal", "`", "%x"),
}

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_COMMAND_FLAG = re.compile(r"^(?:-[a-zA-Z]*c|/[cC]|-(?:command|Command|EncodedCommand|enc|e))$")
_INTERACTIVE_FLAGS = {"-i", "-l", "-il", "-li", "--login", "-s"}

_SHELL_MESSAGE_PREFIX = "Shell script "


def language(path):
    path = Path(path)
    return _NAMES.get(path.name) or _EXTENSIONS.get(path.suffix.lower())


def scan(file_language, text):
    if not any(hint in text for hint in _HINTS[file_language]):
        return []
    source = lexer.lex(file_language, text)
    return _CHECKS[file_language](source)


# --- shared helpers -------------------------------------------------------------------------


def _is_shell(value):
    return value is not None and posixpath.basename(value.replace("\\", "/")).lower() in _SHELLS


def _classify(source, spans):
    """Classify an argv-style call: ``("command", text)`` for a shell with a literal command,
    ``("dynamic", None)`` for a shell with a runtime command, ``("interactive", None)`` for a bare
    shell, or None when the program is not a shell."""
    if not spans:
        return None
    values = [source.literal(start, end) for start, end in spans]
    if not _is_shell(values[0]):
        return None
    rest = values[1:]
    for index, value in enumerate(rest):
        if value is not None and _COMMAND_FLAG.match(value):
            if index + 1 >= len(rest):
                return ("dynamic", None)
            command = rest[index + 1]
            if command is None:
                return ("dynamic", None)
            return ("command", command)
    if all(value is not None and value in _INTERACTIVE_FLAGS for value in rest):
        return ("interactive", None)
    return None


def _classify_string(value):
    """Classify a single command string (``system("...")``)."""
    words = value.split()
    if words and _is_shell(words[0]) and all(word in _INTERACTIVE_FLAGS for word in words[1:]):
        return ("interactive", None)
    return ("command", value)


def _shell_hits(line, command):
    """Shell rules on a literal command string embedded in code."""
    hits = []
    for rule_id in rules_shell.check_command(command):
        hits.append((line, rule_id, None, None))
    return hits


def _unwrap(source, spans, wrappers):
    """``new String[]{"sh", "-c", x}`` / ``List.of(...)`` / ``[...]``: return the inner spans."""
    if len(spans) != 1:
        return spans
    start, end = spans[0]
    head = source.masked[start:end].lstrip()
    offset = start + (len(source.masked[start:end]) - len(head))
    for wrapper in wrappers:
        match = wrapper.match(head)
        if match:
            inner, _close = lexer.call_arguments(source, offset + match.end() - 1)
            return inner
    return spans


def _report(hits, line, classification, rule_id, severity=None, message=None):
    kind, command = classification
    if kind == "command":
        hits.extend(_shell_hits(line, command))
    elif kind == "dynamic":
        hits.append((line, rule_id, severity, message))
    return kind == "interactive"


def _network_shell(hits, interactive_lines, has_network, language_name):
    if has_network:
        for line in interactive_lines:
            hits.append((line, "NET001", None, "{} program connects to the network and starts an interactive shell (reverse-shell pattern).".format(language_name)))


# --- Go -------------------------------------------------------------------------------------

_GO_COMMAND = re.compile(r"\bexec\.Command(Context)?\s*\(")
_GO_DIAL = re.compile(r"\b(\w+)\s*,\s*\w+\s*:?=\s*net\.Dial\w*\s*\(")
_GO_NETWORK = re.compile(r"\bnet\.Dial\w*\s*\(")


def _go(source):
    hits, interactive = [], []
    masked = source.masked
    for match in _GO_COMMAND.finditer(masked):
        spans, _close = lexer.call_arguments(source, match.end() - 1)
        if match.group(1):
            spans = spans[1:]
        classification = _classify(source, spans)
        if classification is None:
            continue
        line = source.line_of(match.start())
        if _report(hits, line, classification, "GO001"):
            interactive.append(line)
    _network_shell(hits, interactive, bool(_GO_NETWORK.search(masked)), "Go")
    # cmd.Stdin = conn, with conn from net.Dial: the process talks to the remote end. One finding
    # is enough, and none when the interactive shell above was already reported.
    if interactive and _GO_NETWORK.search(masked):
        return hits
    for dial in _GO_DIAL.finditer(masked):
        wiring = re.compile(r"\.Std(?:in|out|err)\s*=\s*" + re.escape(dial.group(1)) + r"\b").search(masked)
        if wiring:
            hits.append((source.line_of(wiring.start()), "NET001", None, "Go program connects a process's standard streams to a network connection (reverse-shell pattern)."))
            break
    return hits


# --- Rust -----------------------------------------------------------------------------------

_RUST_COMMAND = re.compile(r"\bCommand::new\s*\(")
_RUST_CHAIN = re.compile(r"\s*\.\s*(\w+)\s*(?:::\s*<[^>]*>\s*)?\(")
_RUST_ARRAY = (re.compile(r"&?\s*\["), re.compile(r"vec!\s*\["))
_RUST_NETWORK = re.compile(r"\bTcpStream::connect\b|\bUdpSocket::bind\b")


def _rust(source):
    hits, interactive = [], []
    masked = source.masked
    for match in _RUST_COMMAND.finditer(masked):
        spans, close = lexer.call_arguments(source, match.end() - 1)
        if close is None or len(spans) != 1:
            continue
        argv = list(spans)
        position = close + 1
        while True:
            chain = _RUST_CHAIN.match(masked, position)
            if not chain:
                break
            arguments, close = lexer.call_arguments(source, chain.end() - 1)
            if close is None:
                break
            if chain.group(1) == "arg":
                argv.extend(arguments)
            elif chain.group(1) == "args":
                argv.extend(_unwrap(source, arguments, _RUST_ARRAY))
            position = close + 1
        classification = _classify(source, argv)
        if classification is None:
            continue
        line = source.line_of(match.start())
        if _report(hits, line, classification, "RS001"):
            interactive.append(line)
    _network_shell(hits, interactive, bool(_RUST_NETWORK.search(masked)), "Rust")
    return hits


# --- Java / Kotlin --------------------------------------------------------------------------

_JAVA_RUNTIME_EXEC = re.compile(r"\bgetRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|(?<![\w.])(\w+)\s*\.\s*exec\s*\(")
_JAVA_RUNTIME_VARIABLE = re.compile(r"\b(\w+)\s*(?::\s*Runtime\s*)?=\s*Runtime\s*\.\s*getRuntime\s*\(\s*\)")
_JAVA_PROCESS_BUILDER = re.compile(r"\bProcessBuilder\s*\(|\.\s*command\s*\(")
_JAVA_ARRAY = (
    re.compile(r"new\s+String\s*\[\s*\]\s*\{"),
    re.compile(r"(?:List\s*\.\s*of|Arrays\s*\.\s*asList|arrayOf|listOf|mutableListOf)\s*\("),
)
_JAVA_OBJECT_STREAM = re.compile(r"\bObjectInputStream\b")
_JAVA_READ_OBJECT = re.compile(r"\.\s*readObject\s*\(\s*\)")
_JAVA_NETWORK = re.compile(r"\bnew\s+Socket\s*\(|(?<![\w.])Socket\s*\(\s*[\"\w]")


def _java(source):
    hits, interactive = [], []
    masked = source.masked
    runtime_names = {match.group(1) for match in _JAVA_RUNTIME_VARIABLE.finditer(masked)}
    for match in _JAVA_RUNTIME_EXEC.finditer(masked):
        if match.group(1) is not None and match.group(1) not in runtime_names:
            continue
        spans, _close = lexer.call_arguments(source, match.end() - 1)
        if not spans:
            continue
        line = source.line_of(match.start())
        first = source.literal(*spans[0])
        if len(spans) == 1 and first is not None:
            classification = _classify_string(first)
            if classification[0] == "interactive":
                interactive.append(line)
            else:
                hits.extend(_shell_hits(line, first))
            continue
        classification = _classify(source, _unwrap(source, spans[:1], _JAVA_ARRAY))
        if classification is None:
            # exec(String) with a runtime value is split on spaces, not run by a shell, but the
            # program name and its arguments still come from that value.
            if len(spans) == 1 and not _JAVA_ARRAY[0].match(masked[spans[0][0]:spans[0][1]].lstrip()):
                hits.append((line, "JV002", None, None))
            continue
        if _report(hits, line, classification, "JV001"):
            interactive.append(line)
    if "ProcessBuilder" in masked:
        for match in _JAVA_PROCESS_BUILDER.finditer(masked):
            spans, _close = lexer.call_arguments(source, match.end() - 1)
            classification = _classify(source, _unwrap(source, spans, _JAVA_ARRAY))
            if classification is None:
                continue
            line = source.line_of(match.start())
            if _report(hits, line, classification, "JV001"):
                interactive.append(line)
    if _JAVA_OBJECT_STREAM.search(masked):
        hits.extend((source.line_of(match.start()), "JV003", None, None) for match in _JAVA_READ_OBJECT.finditer(masked))
    _network_shell(hits, interactive, bool(_JAVA_NETWORK.search(masked)), "Java")
    return hits


# --- PHP ------------------------------------------------------------------------------------

# Function calls only: ``$pdo->exec(...)``, ``Foo::system(...)`` and definitions are not shell calls.
_PHP_NOT_FUNCTION = r"(?<![\w$>:\\])(?<!function )(?<!function  )"
_PHP_SHELL_CALL = re.compile(_PHP_NOT_FUNCTION + r"(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(", re.IGNORECASE)
_PHP_EVAL = re.compile(_PHP_NOT_FUNCTION + r"(eval|create_function|assert|preg_replace)\s*\(", re.IGNORECASE)
_PHP_UNSERIALIZE = re.compile(_PHP_NOT_FUNCTION + r"unserialize\s*\(", re.IGNORECASE)
_PHP_USER_INPUT = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input")
_PHP_ESCAPED = re.compile(r"\bescapeshell(?:arg|cmd)\s*\(", re.IGNORECASE)
_PHP_DECODE = re.compile(r"\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin)\s*\(", re.IGNORECASE)
_PHP_NETWORK = re.compile(r"\b(?:fsockopen|pfsockopen|stream_socket_client|socket_connect)\s*\(", re.IGNORECASE)
_PHP_EVAL_MODIFIER = re.compile(r"^(.).*\1[a-zA-Z]*e[a-zA-Z]*$", re.DOTALL)


def _taint(arguments_text, user_input, escaped=None):
    if user_input.search(arguments_text):
        return "high"
    if escaped is not None and escaped.search(arguments_text):
        return "low"
    return None


def _php(source):
    hits, interactive = [], []
    masked, code = source.masked, source.code
    for match in _PHP_SHELL_CALL.finditer(masked):
        spans, close = lexer.call_arguments(source, match.end() - 1)
        if not spans or close is None:
            continue
        line = source.line_of(match.start())
        first = source.literal(*spans[0])
        if first is not None:
            if _classify_string(first)[0] == "interactive":
                interactive.append(line)
            else:
                hits.extend(_shell_hits(line, first))
            continue
        arguments_text = code[spans[0][0]:spans[0][1]]
        hits.append((line, "PHP002", _taint(arguments_text, _PHP_USER_INPUT, _PHP_ESCAPED), None))
    for token in source.strings:
        if token.kind != "shell":
            continue
        line = source.line_of(token.start)
        value = lexer.literal_value("php", token.text)
        if value is None:
            hits.append((line, "PHP002", _taint(token.text, _PHP_USER_INPUT, _PHP_ESCAPED), "PHP backtick operator runs a shell command built at runtime."))
        else:
            hits.extend(_shell_hits(line, value))
    for match in _PHP_EVAL.finditer(masked):
        name = match.group(1).lower()
        spans, close = lexer.call_arguments(source, match.end() - 1)
        if not spans or close is None:
            continue
        arguments_text = code[spans[0][0]:close]
        line = source.line_of(match.start())
        obfuscated = bool(_PHP_DECODE.search(arguments_text))
        message = "PHP evaluates decoded or decompressed data as code (common in web shells)." if obfuscated else None
        severity = None
        if name == "preg_replace":
            pattern = source.literal(*spans[0])
            if pattern is None or not _PHP_EVAL_MODIFIER.match(pattern):
                continue
            message = "preg_replace with the /e modifier evaluates the replacement as PHP code."
        elif name == "assert":
            # assert() only evaluates strings (PHP < 8); an expression such as assert($a > 0) is fine.
            if not (obfuscated or _PHP_USER_INPUT.search(arguments_text) or source.literal(*spans[0]) is not None):
                continue
        if _PHP_USER_INPUT.search(arguments_text):
            message = message or "PHP evaluates request data as code."
        elif name == "eval" and not obfuscated and source.literal(*spans[0]) is not None:
            severity = "low"
        hits.append((line, "PHP001", severity, message))
    for match in _PHP_UNSERIALIZE.finditer(masked):
        spans, close = lexer.call_arguments(source, match.end() - 1)
        if not spans or close is None:
            continue
        arguments_text = code[spans[0][0]:close]
        if "allowed_classes" in arguments_text or source.literal(*spans[0]) is not None:
            continue
        hits.append((source.line_of(match.start()), "PHP003", "high" if _PHP_USER_INPUT.search(arguments_text) else None, None))
    _network_shell(hits, interactive, bool(_PHP_NETWORK.search(masked)), "PHP")
    return hits


# --- Ruby -----------------------------------------------------------------------------------

# Kernel methods called without a receiver, or on Kernel / Process / IO / Open3.
_RUBY_RECEIVER = r"(?:(?<![\w.:@$])|(?<=Kernel\.)|(?<=Process\.)|(?<=IO\.)|(?<=Open3\.))"
_RUBY_SHELL_CALL = re.compile(_RUBY_RECEIVER + r"(system|exec|spawn|popen|popen2|popen2e|popen3|capture2|capture2e|capture3|pipeline_r|pipeline_w|pipeline)\b(?:\(|[ \t]+(?=[\"'`%\w@$:\[(]))")
_RUBY_EVAL = re.compile(r"(?:(?<![\w.:@$])|(?<=Kernel\.)|(?<=binding\.))(eval)\b(?:\(|[ \t]+(?=[\"'%\w@$(]))")
_RUBY_MARSHAL = re.compile(r"\bMarshal\s*\.\s*(?:load|restore)\b")
_RUBY_USER_INPUT = re.compile(r"\bparams\s*\[|\brequest\s*\.\s*(?:params|body|query_string)\b|\bcookies\s*\[")
_RUBY_NETWORK = re.compile(r"\bTCPSocket\s*\.\s*(?:new|open)\b|\bSocket\s*\.\s*tcp\b")
# Paren-less arguments end at a trailing modifier, a block, or the end of an enclosing block.
_RUBY_ARGUMENT_END = re.compile(r"\s(?:if|unless|while|until|do|and|or|rescue)\b|\s*[{};]")
_RUBY_OPTION = re.compile(r"\s*(?:\w+:\s|:\w+\s*=>|\[\s*:\w+|\w+\s*=>)")
_RUBY_DEFINITION = re.compile(r"\bdef\s+(?:self\.)?$")


def _ruby_arguments(source, match):
    """Argument spans for ``name(...)`` or a paren-less ``name arg, arg`` up to the end of line."""
    masked = source.masked
    if masked[match.end() - 1] == "(":
        spans, close = lexer.call_arguments(source, match.end() - 1)
        return spans, close
    start = match.end()
    end = masked.find("\n", start)
    end = len(masked) if end < 0 else end
    # Stop at a trailing modifier or block: ``system "x" if ok``, ``spawn "x" do``.
    tail = _RUBY_ARGUMENT_END.search(masked, start, end)
    if tail:
        end = tail.start()
    spans, argument_start, depth = [], start, 0
    for index in range(start, end):
        char = masked[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            spans.append((argument_start, index))
            argument_start = index + 1
    if masked[argument_start:end].strip():
        spans.append((argument_start, end))
    return spans, end


def _ruby(source):
    hits, interactive = [], []
    masked, code = source.masked, source.code
    for match in _RUBY_SHELL_CALL.finditer(masked):
        line_start = masked.rfind("\n", 0, match.start()) + 1
        if _RUBY_DEFINITION.search(masked[line_start:match.start()]):
            continue
        spans, close = _ruby_arguments(source, match)
        # An environment hash may come first (system({"A" => "1"}, "cmd")) and options last
        # (exec("cmd", in: s, out: s), chdir: dir, :err => :out); neither is part of the command.
        if spans and masked[spans[0][0]:spans[0][1]].lstrip().startswith("{"):
            spans = spans[1:]
        while spans and _RUBY_OPTION.match(masked[spans[-1][0]:spans[-1][1]]):
            spans = spans[:-1]
        if not spans:
            continue
        line = source.line_of(match.start())
        if len(spans) == 1:
            first = source.literal(*spans[0])
            if first is not None:
                if _classify_string(first)[0] == "interactive":
                    interactive.append(line)
                else:
                    hits.extend(_shell_hits(line, first))
                continue
            arguments_text = code[spans[0][0]:spans[0][1]]
            # A splat (*args) or an array is the argv form, which runs no shell.
            if arguments_text.strip().startswith((":", "[", "*")):
                continue
            hits.append((line, "RB002", _taint(arguments_text, _RUBY_USER_INPUT), None))
            continue
        classification = _classify(source, spans)
        if classification is None:
            # argv form (program, arg, arg): no shell involved.
            continue
        if _report(hits, line, classification, "RB002"):
            interactive.append(line)
    for token in source.strings:
        if token.kind != "shell":
            continue
        line = source.line_of(token.start)
        value = lexer.literal_value("ruby", token.text)
        if value is None:
            hits.append((line, "RB002", _taint(token.text, _RUBY_USER_INPUT), "Ruby backticks or %x run a shell command built at runtime."))
        else:
            hits.extend(_shell_hits(line, value))
    for match in _RUBY_EVAL.finditer(masked):
        line_start = masked.rfind("\n", 0, match.start()) + 1
        if _RUBY_DEFINITION.search(masked[line_start:match.start()]):
            continue
        spans, _close = _ruby_arguments(source, match)
        if not spans:
            continue
        arguments_text = code[spans[0][0]:spans[0][1]]
        hits.append((source.line_of(match.start()), "RB001", None, "Ruby evaluates request data as code." if _RUBY_USER_INPUT.search(arguments_text) else None))
    hits.extend((source.line_of(match.start()), "RB003", None, None) for match in _RUBY_MARSHAL.finditer(masked))
    _network_shell(hits, interactive, bool(_RUBY_NETWORK.search(masked)), "Ruby")
    return hits


_CHECKS = {"go": _go, "rust": _rust, "java": _java, "php": _php, "ruby": _ruby}


def shell_message(rule_message):
    """Shell rule messages say "Shell script ..."; inside code the shell command is embedded."""
    if rule_message.startswith(_SHELL_MESSAGE_PREFIX):
        return "Embedded shell command " + rule_message[len(_SHELL_MESSAGE_PREFIX):]
    return rule_message
