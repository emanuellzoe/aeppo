"""Project configuration from ``.aeppo.toml``.

Supported top-level keys::

    exclude = ["tests/fixtures/**"]   # relative path globs, added to --exclude
    disable = ["GHA003"]              # rule IDs to turn off
    min-severity = "medium"           # low | medium | high
    max-file-size = 1048576           # bytes
    baseline = "aeppo-baseline.json"  # relative to the config file
    osv = true                        # look up lockfile dependencies in OSV.dev (like --osv)

Python 3.11+ parses the file with ``tomllib``. Older versions use a small parser for the subset
above (strings, integers, booleans, arrays), so aeppo keeps no runtime dependencies. Unknown keys
and unknown rule IDs are errors, so a typo cannot silently turn a setting off.
"""
import re
from pathlib import Path

from aeppo.scanner import RULES, SEVERITY_ORDER


CONFIG_NAME = ".aeppo.toml"

_KEYS = {
    "exclude": "a list of path globs",
    "disable": "a list of rule IDs",
    "min-severity": "one of low, medium, high",
    "max-file-size": "a positive integer",
    "baseline": "a path string",
    "osv": "true or false",
}


def find_config(start):
    """Return the nearest ``.aeppo.toml`` from ``start`` upward, stopping at a repository root."""
    directory = Path(start).resolve()
    if not directory.is_dir():
        directory = directory.parent
    for candidate in (directory, *directory.parents):
        config = candidate / CONFIG_NAME
        if config.is_file():
            return config
        if (candidate / ".git").exists():
            return None
    return None


def load_config(path):
    """Read and validate a config file; return a dict with normalised values."""
    path = Path(path)
    raw = _parse(path.read_text(encoding="utf-8"))
    unknown = sorted(set(raw) - set(_KEYS))
    if unknown:
        raise ValueError("{}: unknown key(s) {}; expected {}".format(path, ", ".join(unknown), ", ".join(sorted(_KEYS))))
    config = {}
    for key in ("exclude", "disable"):
        if key in raw:
            value = raw[key]
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError("{}: {} must be {}".format(path, key, _KEYS[key]))
            config[key] = value
    if "disable" in config:
        config["disable"] = [rule_id.upper() for rule_id in config["disable"]]
        unknown_rules = sorted(set(config["disable"]) - set(RULES))
        if unknown_rules:
            raise ValueError("{}: unknown rule ID(s) in disable: {}".format(path, ", ".join(unknown_rules)))
    if "min-severity" in raw:
        if raw["min-severity"] not in SEVERITY_ORDER:
            raise ValueError("{}: min-severity must be {}".format(path, _KEYS["min-severity"]))
        config["min_severity"] = raw["min-severity"]
    if "max-file-size" in raw:
        value = raw["max-file-size"]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("{}: max-file-size must be {}".format(path, _KEYS["max-file-size"]))
        config["max_file_size"] = value
    if "osv" in raw:
        if not isinstance(raw["osv"], bool):
            raise ValueError("{}: osv must be {}".format(path, _KEYS["osv"]))
        config["osv"] = raw["osv"]
    if "baseline" in raw:
        if not isinstance(raw["baseline"], str) or not raw["baseline"]:
            raise ValueError("{}: baseline must be {}".format(path, _KEYS["baseline"]))
        config["baseline"] = (path.parent / raw["baseline"]).resolve()
    return config


def _parse(text):
    try:
        import tomllib
    except ImportError:
        return parse_minimal_toml(text)
    return tomllib.loads(text)


_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_SCALAR = re.compile(r"[+-]?\d[\d_]*\b|true\b|false\b")
_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f"}


def parse_minimal_toml(text):
    """Parse top-level ``key = value`` pairs (strings, integers, booleans, arrays)."""
    result = {}
    position = _skip(text, 0)
    while position < len(text):
        if text[position] == "[":
            raise ValueError("line {}: tables are not supported; use top-level keys".format(_line_of(text, position)))
        key = _BARE_KEY.match(text, position)
        if not key:
            raise ValueError("line {}: expected a key".format(_line_of(text, position)))
        position = _skip(text, key.end(), newlines=False)
        if position >= len(text) or text[position] != "=":
            raise ValueError("line {}: expected '=' after {}".format(_line_of(text, position), key.group()))
        value, position = _value(text, _skip(text, position + 1, newlines=False))
        rest = _skip(text, position, newlines=False)
        if rest < len(text) and text[rest] not in "\r\n":
            raise ValueError("line {}: unexpected text after the value".format(_line_of(text, rest)))
        if key.group() in result:
            raise ValueError("line {}: duplicate key {}".format(_line_of(text, key.start()), key.group()))
        result[key.group()] = value
        position = _skip(text, rest)
    return result


def _skip(text, position, newlines=True):
    while position < len(text):
        char = text[position]
        if char in " \t" or (newlines and char in "\r\n"):
            position += 1
        elif char == "#":
            while position < len(text) and text[position] != "\n":
                position += 1
        else:
            break
    return position


def _value(text, position):
    if position >= len(text):
        raise ValueError("line {}: missing value".format(_line_of(text, position)))
    char = text[position]
    if char == '"':
        out = []
        position += 1
        while position < len(text) and text[position] != '"':
            if text[position] in "\r\n":
                break
            if text[position] == "\\":
                escape = text[position + 1 : position + 2]
                if escape not in _ESCAPES:
                    raise ValueError("line {}: unsupported escape \\{}".format(_line_of(text, position), escape))
                out.append(_ESCAPES[escape])
                position += 2
            else:
                out.append(text[position])
                position += 1
        if position >= len(text) or text[position] != '"':
            raise ValueError("line {}: unterminated string".format(_line_of(text, position)))
        return "".join(out), position + 1
    if char == "'":
        end = text.find("'", position + 1)
        if end == -1 or "\n" in text[position:end]:
            raise ValueError("line {}: unterminated string".format(_line_of(text, position)))
        return text[position + 1 : end], end + 1
    if char == "[":
        items = []
        position = _skip(text, position + 1)
        while True:
            if position >= len(text):
                raise ValueError("unterminated array")
            if text[position] == "]":
                return items, position + 1
            item, position = _value(text, position)
            items.append(item)
            position = _skip(text, position)
            if position < len(text) and text[position] == ",":
                position = _skip(text, position + 1)
            elif position < len(text) and text[position] != "]":
                raise ValueError("line {}: expected ',' or ']' in array".format(_line_of(text, position)))
    scalar = _SCALAR.match(text, position)
    if not scalar:
        raise ValueError("line {}: unsupported value".format(_line_of(text, position)))
    token = scalar.group()
    if token in ("true", "false"):
        return token == "true", scalar.end()
    return int(token.replace("_", "")), scalar.end()


def _line_of(text, position):
    return text.count("\n", 0, position) + 1
