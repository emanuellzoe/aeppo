"""Content a reviewer cannot read: committed executables (BIN001), encoded blobs (OBF001),
minified or packed source (OBF002) and lookalike letters in identifiers (SRC002).

Binaries are recognized by their header bytes only; nothing is loaded or run.
"""
import re
import struct


BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".elf"}
HEADER_BYTES = 4096

_MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}


def might_be_binary(path):
    """Return True when ``path`` is worth reading a header from (no suffix, a binary suffix, or ``.so.1``)."""
    suffix = path.suffix.lower()
    return not suffix or suffix in BINARY_SUFFIXES or ".so." in path.name or suffix[1:].isdigit()


def executable_format(header):
    """Return "ELF", "Mach-O" or "PE" when ``header`` starts an executable or shared library, else None."""
    if header.startswith(b"\x7fELF"):
        return "ELF"
    if header[:4] in _MACHO_MAGICS:
        return "Mach-O"
    if header.startswith(b"\xca\xfe\xba\xbe") and len(header) >= 8:
        # Universal Mach-O binaries and Java class files share this magic; a universal binary
        # counts its architectures (a handful), a class file stores its version (45 or more).
        return "Mach-O" if struct.unpack(">I", header[4:8])[0] < 20 else None
    if header.startswith(b"MZ") and len(header) >= 64:
        offset = struct.unpack("<I", header[60:64])[0]
        if offset + 4 <= len(header) and header[offset:offset + 4] == b"PE\0\0":
            return "PE"
    return None


# Base64 runs of 400+ characters mixing cases and digits, or hex runs of 400+ digits. Images and
# fonts in data: URIs and inline source maps are ordinary and skipped.
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{400,}")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){150,}")
_BENIGN_PREFIX = re.compile(r"(?:data:(?:image|font|audio|video)/[\w.+-]+|data:application/(?:font|x-font)[\w.+-]*|sourceMappingURL=data:[\w/+.-]+)(?:;[\w=-]+)*;base64,$")
_DECODE = re.compile(r"\b(?:b64decode|b32decode|a85decode|unhexlify|fromhex|decodebytes|atob|zlib\.decompress|marshal\.loads)\b|Buffer\.from\([^)]*['\"](?:base64|hex)['\"]|base64\s+(?:-d|--decode)|\bxxd\s+-r|String\.fromCharCode")
_EXECUTE = re.compile(r"\b(?:exec|eval|compile|Function|execSync|spawn|system|popen)\s*\(|\|\s*(?:ba|z)?sh\b|\bsh\s+-c\b")


def _is_base64_blob(text):
    return any(char.isupper() for char in text) and any(char.islower() for char in text) and any(char.isdigit() for char in text)


def _blob_lines(lines):
    found = []
    for line_number, line in enumerate(lines, start=1):
        if len(line) < 300:
            continue
        for match in _BASE64_RUN.finditer(line):
            if _is_base64_blob(match.group(0)) and not _BENIGN_PREFIX.search(line[max(0, match.start() - 80):match.start()]):
                found.append(line_number)
                break
        else:
            if _HEX_RUN.search(line) or _HEX_ESCAPES.search(line):
                found.append(line_number)
    return found


def blob_findings(lines):
    """Return [(line, rule_id, severity, message)]: one OBF001 per file, at the first blob."""
    blobs = _blob_lines(lines)
    if not blobs:
        return []
    text = "\n".join(lines)
    count = "" if len(blobs) == 1 else " ({} lines with blobs)".format(len(blobs))
    if _DECODE.search(text) and _EXECUTE.search(text):
        return [(blobs[0], "OBF001", "high", "Large encoded blob in a file that decodes data and runs code; it may be a hidden payload{}.".format(count))]
    return [(blobs[0], "OBF001", None, "Large encoded blob (base64 or hex) in source code{}; decode it to see what it contains.".format(count))]


_PACKED_LENGTH = {"js": 5000, "other": 2000}
# Minified code is dense with statement punctuation; a long line that is one string or a data
# table (Unicode ranges, word lists) is not.
_CODE_PUNCTUATION = re.compile(r"[;(){}]")
_MIN_PUNCTUATION_RATIO = 1 / 50


def packed_findings(lines, language, skip_lines=()):
    """Return [(line, rule_id, severity, message)]: one OBF002 at the first very long line."""
    limit = _PACKED_LENGTH["js" if language == "js" else "other"]
    for line_number, line in enumerate(lines, start=1):
        if len(line) >= limit and line_number not in skip_lines and len(_CODE_PUNCTUATION.findall(line)) >= len(line) * _MIN_PUNCTUATION_RATIO:
            severity = "low" if language == "js" else None
            message = "Source line is {} characters long; minified or packed code hides what it does.".format(len(line))
            return [(line_number, "OBF002", severity, message)]
    return []


# Cyrillic and Greek letters drawn like Latin ones. A word that mixes them with ASCII letters
# (``p\u0430ypal`` written with a Cyrillic ``\u0430``) looks like one name and is another.
_CONFUSABLES = set("аеорсухіјѕԁһӏԛԝАВЕЅІЈКМНОРСТХУԌονΑΒΕΖΗΙΚΜΝΟΡΤΥΧϲϳ")
_WORD = re.compile(r"[^\W\d_](?:\w)*")
_LATIN = re.compile(r"[A-Za-z]")


def homoglyph_findings(lines):
    """Return [(line, rule_id, severity, message)] for words mixing ASCII letters with lookalikes."""
    found = []
    for line_number, line in enumerate(lines, start=1):
        if line.isascii():
            continue
        for match in _WORD.finditer(line):
            word = match.group(0)
            lookalikes = [char for char in word if char in _CONFUSABLES]
            if lookalikes and _LATIN.search(word):
                message = "'{}' mixes Latin letters with lookalike {} (U+{:04X}); it is a different name from the one it appears to be.".format(
                    word.encode("ascii", "replace").decode("ascii"), "Cyrillic" if "Ѐ" <= lookalikes[0] <= "ԯ" else "Greek", ord(lookalikes[0]))
                found.append((line_number, "SRC002", None, message))
                break
    return found
