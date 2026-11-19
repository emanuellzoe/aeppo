"""A small lexer for Go, Rust, Java/Kotlin, PHP and Ruby source.

It does not parse anything; it only finds comments and string literals so pattern rules can tell
code from text. ``lex`` returns a ``Source`` with two views of the text, both the same length as
the input so offsets and line numbers line up:

* ``code``: comments blanked out, string literals kept;
* ``masked``: comments and the inside of string literals blanked out, delimiters kept.

Rules search ``masked`` for call shapes (so ``"exec.Command("`` inside a string or a comment never
matches) and read arguments back from ``code``. Each language's tokens are one combined regular
expression, so the work happens in the regex engine rather than in a per-character Python loop.
"""
import bisect
import re


# Shared token shapes.
# Interpolation with up to two levels of nested braces: "#{x ? "#{y}" : z}".
_RUBY_INTERPOLATION = r"#\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}"
_LINE_COMMENT = r"//[^\n]*"
_BLOCK_COMMENT = r"/\*.*?(?:\*/|\Z)"
_DOUBLE = r'"(?:\\.|[^"\\\n])*"'
_CHAR = r"'(?:\\.|[^'\\\n])*'"

_TOKENS = {
    "go": (
        ("comment", _LINE_COMMENT + "|" + _BLOCK_COMMENT),
        ("string", _DOUBLE + "|" + _CHAR + r"|`[^`]*`"),
    ),
    "rust": (
        ("comment", _LINE_COMMENT + "|" + _BLOCK_COMMENT),
        # Raw strings r#"..."#, byte strings, and char literals ('a', '\n'); a lifetime ('a) has no
        # closing quote right after one character, so it stays code.
        ("string", r'b?r(?P<hashes>#*)".*?"(?P=hashes)|b?"(?:\\.|[^"\\])*"|b?\'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]+\}|.)|[^\\\'\n])\''),
    ),
    "java": (
        ("comment", _LINE_COMMENT + "|" + _BLOCK_COMMENT),
        # Text blocks and Kotlin raw strings, then strings with Kotlin ${...} templates.
        ("string", r'""".*?"""|"(?:\\.|\$\{(?:[^{}\n]|\{[^{}\n]*\})*\}|\$(?!\{)|[^"\\\n$])*"|' + _CHAR),
    ),
    "php": (
        # Everything outside <?php ... ?> is HTML; it is blanked like a comment. A '#' comment
        # is not an attribute (#[...]).
        ("comment", r"\?>.*?(?:<\?(?:php\b|=)?|\Z)|" + _LINE_COMMENT + r"|#(?!\[)[^\n]*|" + _BLOCK_COMMENT),
        ("heredoc", r"<<<[ \t]*(?P<hq>[\"']?)(?P<hid>[A-Za-z_]\w*)(?P=hq)(?=\n(?P<body>.*?)(?P<hend>^[ \t]*(?P=hid)\b))"),
        ("string", r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\""),
        ("shell", r"`(?:\\.|[^`\\])*`"),
    ),
    "ruby": (
        ("comment", r"^=begin\b.*?(?:^=end\b[^\n]*|\Z)|^__END__\n.*\Z|#[^\n]*"),
        # The heredoc token is only the <<~ID marker; its body (from the next line to the
        # terminator) is captured by the lookahead and blanked separately, so the rest of the
        # marker's line (``run(<<~SH, x)``) is still read as code.
        ("heredoc", r"<<[~-]?(?P<hq>[\"'`]?)(?P<hid>[A-Z_][A-Z0-9_]*)(?P=hq)(?=[^\n]*\n(?P<body>.*?)(?P<hend>^[ \t]*(?P=hid)$))"),
        # Regex literals: a '/' where an operand is expected and not followed by a space.
        ("regex", r"(?:(?<=[(,=~!&|{\[;?:])|(?<=^)|(?<=[(,=~!&|{\[;?:\s]\s)|(?<=\w\s))/(?![\s=])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+/[imxounse]*"),
        ("string", r"'(?:\\.|[^'\\])*'|\"(?:\\.|" + _RUBY_INTERPOLATION + r"|#(?!\{)|[^\"\\#])*\""
                   r"|%[qQwWiI](?:\((?:\\.|[^)\\])*\)|\[(?:\\.|[^\]\\])*\]|\{(?:\\.|[^}\\])*\}|<(?:\\.|[^>\\])*>|\|(?:\\.|[^|\\])*\|)"),
        ("shell", r"`(?:\\.|" + _RUBY_INTERPOLATION + r"|#(?!\{)|[^`\\#])*`|%x(?:\((?:\\.|[^)\\])*\)|\[(?:\\.|[^\]\\])*\]|\{(?:\\.|[^}\\])*\}|\|(?:\\.|[^|\\])*\|)"),
    ),
}

_KINDS = ("comment", "heredoc", "regex", "string", "shell")

_PATTERNS = {
    language: re.compile("|".join("(?P<{}>{})".format(kind, pattern) for kind, pattern in tokens), re.DOTALL | re.MULTILINE)
    for language, tokens in _TOKENS.items()
}

_BLANK = re.compile(r"[^\n]")
_LITERAL_BODY = re.compile(r'^(?:[br]{0,2}#*)?("""|["\'`])(.*)\1#*$', re.DOTALL)
_PERCENT_BODY = re.compile(r"^%[qQwWiIx](.)(.*).$", re.DOTALL)
_INTERPOLATION = {
    "ruby": re.compile(r"#\{"),
    "java": re.compile(r"\$[{A-Za-z_]"),  # Kotlin string templates
    "php": re.compile(r"\$[{A-Za-z_]|\{\$"),
}


class Token:
    __slots__ = ("start", "end", "kind", "text", "body")

    def __init__(self, start, end, kind, text, body=None):
        self.start, self.end, self.kind, self.text, self.body = start, end, kind, text, body


class Source:
    def __init__(self, language, text, code, masked, tokens):
        self.language = language
        self.text = text
        self.code = code
        self.masked = masked
        self.strings = [token for token in tokens if token.kind != "comment"]
        self._by_start = {token.start: token for token in self.strings}
        self._newlines = [index for index, char in enumerate(text) if char == "\n"]

    def line_of(self, offset):
        return bisect.bisect_right(self._newlines, offset - 1) + 1

    def literal(self, start, end):
        """The value of a plain string literal spanning exactly ``[start, end)`` (ignoring
        surrounding whitespace), or None for anything else, including interpolated strings."""
        while start < end and self.code[start].isspace():
            start += 1
        while end > start and self.code[end - 1].isspace():
            end -= 1
        token = self._by_start.get(start)
        if token is None or token.end != end or token.kind not in {"string", "heredoc"}:
            return None
        return literal_value(self.language, token.text, token.body)


def literal_value(language, text, heredoc_body=None):
    """Inner text of a string token, or None when it is interpolated."""
    if heredoc_body is not None:
        body = heredoc_body
        single_quoted = "'" in text
    else:
        match = _PERCENT_BODY.match(text) if text.startswith("%") else _LITERAL_BODY.match(text)
        if not match:
            return None
        body = match.group(2)
        single_quoted = text.lstrip("br#").startswith("'") or text[:2] in {"%q", "%w", "%i"}
    interpolation = _INTERPOLATION.get(language)
    if interpolation and not single_quoted and interpolation.search(body):
        return None
    return body


def lex(language, text):
    pattern = _PATTERNS[language]
    code, masked, tokens = [], [], []
    position = 0
    if language == "php":
        # Leading HTML before the first PHP tag.
        first = text.find("<?")
        if first < 0:
            blank = _BLANK.sub(" ", text)
            return Source(language, text, blank, blank, [])
        if first:
            blank = _BLANK.sub(" ", text[:first])
            code.append(blank)
            masked.append(blank)
            position = first
    heredoc_end = None  # (line_end, body_end) while finishing a heredoc marker's line
    while True:
        limit = heredoc_end[0] if heredoc_end else len(text)
        match = pattern.search(text, position, limit)
        if match is None:
            code.append(text[position:limit])
            masked.append(text[position:limit])
            if not heredoc_end:
                break
            body = text[limit:heredoc_end[1]]
            code.append(body)
            masked.append(_BLANK.sub(" ", body))
            position, heredoc_end = heredoc_end[1], None
            continue
        start, end = match.span()
        between = text[position:start]
        code.append(between)
        masked.append(between)
        token_text = match.group(0)
        kind = next(kind for kind in _KINDS if kind in match.re.groupindex and match.group(kind) is not None)
        if kind == "heredoc":
            tokens.append(Token(start, end, kind, token_text, match.group("body")))
            code.append(token_text)
            masked.append(token_text)
            line_end = text.find("\n", end)
            if heredoc_end is None and line_end >= 0:
                heredoc_end = (line_end, match.end("hend"))
            position = end
            continue
        tokens.append(Token(start, end, kind, token_text))
        if kind == "comment":
            blank = _BLANK.sub(" ", token_text)
            code.append(blank)
            masked.append(blank)
        else:
            code.append(token_text)
            inner = _BLANK.sub(" ", token_text[1:-1]) if len(token_text) >= 2 else ""
            masked.append(token_text[:1] + inner + token_text[-1:] if len(token_text) >= 2 else token_text)
        position = end
    return Source(language, text, "".join(code), "".join(masked), tokens)


_OPEN = "([{"
_CLOSE = ")]}"


def call_arguments(source, open_index):
    """Split the call whose ``(`` (or ``[``/``{``) is at ``open_index`` into argument spans.

    Returns ``(spans, close_index)``; spans are ``(start, end)`` offsets into the text. Brackets
    inside strings and comments are already blanked in ``masked``, so they do not count.
    """
    masked = source.masked
    depth = 0
    spans = []
    argument_start = open_index + 1
    index = open_index
    limit = min(len(masked), open_index + 20000)
    while index < limit:
        char = masked[index]
        if char in _OPEN:
            depth += 1
        elif char in _CLOSE:
            depth -= 1
            if depth == 0:
                if masked[argument_start:index].strip():
                    spans.append((argument_start, index))
                return spans, index
        elif char == "," and depth == 1:
            spans.append((argument_start, index))
            argument_start = index + 1
        index += 1
    return spans, None
