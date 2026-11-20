"""Read exact dependency versions from lockfiles, without running a package manager.

Each parser returns ``Package`` tuples (OSV ecosystem, name, version, line). Only packages that
resolve from the public registry of their ecosystem are returned: workspace members, local paths,
git checkouts and URLs are skipped, because their names say nothing about a registry release.
"""
import json
import re
from collections import namedtuple


Package = namedtuple("Package", "ecosystem name version line")

_EXACT_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+.~][0-9A-Za-z.+~-]*)?$")
_REQUIREMENTS_NAME = re.compile(r"^(?:.*[-_.])?requirements(?:[-_.].*)?\.txt$", re.IGNORECASE)


def kind(path):
    """Return the lockfile format of ``path``, or ``None``."""
    name = path.name
    if name in _PARSERS:
        return name
    if _REQUIREMENTS_NAME.match(name) or (path.parent.name == "requirements" and path.suffix == ".txt"):
        return "requirements.txt"
    return None


def parse(kind_name, text):
    try:
        return [package for package in _PARSERS[kind_name](text) if _EXACT_VERSION.match(package.version)]
    except (ValueError, TypeError, AttributeError, KeyError):
        # A malformed lockfile is not a scan error; it simply yields no packages.
        return []


def _line_finder(text):
    """Return a function mapping a substring to the 1-based line of its first occurrence."""
    def line_of(needle, default=1):
        index = text.find(needle)
        return text.count("\n", 0, index) + 1 if index >= 0 else default
    return line_of


def _npm_lock(text):
    data = json.loads(text)
    line_of = _line_finder(text)
    packages = []
    entries = data.get("packages")
    if isinstance(entries, dict):
        # lockfileVersion 2 and 3: keys are install paths such as node_modules/a/node_modules/@s/b.
        for key, entry in entries.items():
            if "node_modules/" not in key or not isinstance(entry, dict) or entry.get("link"):
                continue
            version = entry.get("version")
            resolved = entry.get("resolved", "")
            if not isinstance(version, str) or (isinstance(resolved, str) and resolved.startswith(("file:", "git", "http://", "https://")) and "/-/" not in resolved):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
            packages.append(_npm_package(name, version, line_of(json.dumps(key) + ":")))
        return packages
    # lockfileVersion 1: nested "dependencies" objects.
    def walk(dependencies):
        for name, entry in dependencies.items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str):
                line = line_of(json.dumps(name) + ":")
                if version.startswith("npm:"):
                    name, _, version = version[4:].rpartition("@")
                packages.append(_npm_package(name, version, line))
            if isinstance(entry.get("dependencies"), dict):
                walk(entry["dependencies"])
    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])
    return packages


def _npm_package(name, version, line):
    return Package("npm", name, version, line)


def _split_npm_spec(spec):
    """Split ``@scope/name@range`` into name and range."""
    at = spec.find("@", 1)
    return (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")


def _yarn_lock(text):
    packages = []
    header = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        if not line[0].isspace():
            header = (line_number, line.rstrip(":").strip()) if line.rstrip().endswith(":") else None
            continue
        if header is None:
            continue
        match = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if not match:
            continue
        header_line, specs = header
        header = None
        first = specs.split(",")[0].strip().strip('"')
        if first.startswith("__metadata"):
            continue
        name, spec_range = _split_npm_spec(first)
        # Yarn Berry protocols other than npm (workspace:, link:, portal:, file:, patch:) are local.
        if ":" in spec_range and not spec_range.startswith("npm:"):
            continue
        if spec_range.startswith("npm:") and "@" in spec_range[5:]:
            name = _split_npm_spec(spec_range[4:])[0]
        packages.append(_npm_package(name, match.group(1), header_line))
    return packages


def _pnpm_lock(text):
    packages = []
    in_packages = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line and not line[0].isspace():
            in_packages = line.rstrip() == "packages:"
            continue
        if not in_packages:
            continue
        match = re.match(r"^  (['\"]?)(/?[^\s'\"]+)\1:\s*$", line)
        if not match:
            continue
        key = match.group(2).lstrip("/")
        key = re.sub(r"\(.*$", "", key)
        at = key.find("@", 1)
        if at > 0 and key[:at].count("/") == (1 if key.startswith("@") else 0):
            # pnpm 6 and 9: name@version, optionally followed by (peer@version).
            name, version = key[:at], key[at + 1:]
        else:
            # pnpm 5: /name/version_peer@version
            name, _, version = key.rpartition("/")
            version = version.split("_", 1)[0]
        if name and ":" not in version:
            packages.append(_npm_package(name, version, line_number))
    return packages


def _python_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(text):
    packages = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;,\\]+)\s*(?:[;\\].*)?$", line)
        if match and "*" not in match.group(2):
            packages.append(Package("PyPI", _python_name(match.group(1)), match.group(2), line_number))
    return packages


def _toml_packages(text):
    """Yield (line, fields) for each ``[[package]]`` table; values are raw TOML right-hand sides."""
    current = None
    table = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("["):
            if stripped == "[[package]]":
                if current is not None:
                    yield current
                current, table = (line_number, {}), ""
            elif current is not None and stripped.startswith("[package.") and not stripped.startswith("[["):
                table = stripped.strip("[]")[len("package."):] + "."
            else:
                if current is not None:
                    yield current
                current = None
            continue
        if current is None:
            continue
        match = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$", stripped)
        if match:
            current[1].setdefault(table + match.group(1), match.group(2).strip())
    if current is not None:
        yield current


def _toml_string(value):
    match = re.match(r'^"((?:[^"\\]|\\.)*)"|^\'([^\']*)\'', value or "")
    if not match:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def _poetry_lock(text):
    packages = []
    seen = set()
    for line, fields in _toml_packages(text):
        name, version = _toml_string(fields.get("name")), _toml_string(fields.get("version"))
        source_type = _toml_string(fields.get("source.type"))
        if not name or not version or source_type in {"git", "directory", "file", "url"}:
            continue
        key = (name, version)
        if key not in seen:
            seen.add(key)
            packages.append(Package("PyPI", _python_name(name), version, line))
    return packages


def _uv_lock(text):
    packages = []
    for line, fields in _toml_packages(text):
        name, version = _toml_string(fields.get("name")), _toml_string(fields.get("version"))
        source = fields.get("source", "")
        if name and version and re.match(r"^\{\s*registry\s*=", source):
            packages.append(Package("PyPI", _python_name(name), version, line))
    return packages


def _cargo_lock(text):
    packages = []
    for line, fields in _toml_packages(text):
        name, version = _toml_string(fields.get("name")), _toml_string(fields.get("version"))
        source = _toml_string(fields.get("source")) or ""
        if name and version and source.startswith(("registry+", "sparse+")):
            packages.append(Package("crates.io", name, version, line))
    return packages


def _go_mod(text):
    """Read ``require`` directives from go.mod (go.sum also lists versions that are not selected)."""
    required = []
    replaced = {}
    block = None
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = None
                continue
            directive, rest = block, line
        else:
            match = re.match(r"^(require|replace)\s*(\(?)\s*(.*)$", line)
            if not match:
                continue
            if match.group(2):
                block = match.group(1)
                continue
            directive, rest = match.group(1), match.group(3)
        if directive == "require":
            parts = rest.split()
            if len(parts) >= 2:
                required.append((parts[0], parts[1], line_number))
        elif "=>" in rest:
            left, right = (part.split() for part in rest.split("=>", 1))
            if left:
                replaced[left[0]] = right
    packages = []
    for module, version, line_number in required:
        if module in replaced:
            target = replaced[module]
            if len(target) < 2:
                continue  # replaced by a local directory
            module, version = target[0], target[1]
        packages.append(Package("Go", module, version[1:] if version.startswith("v") else version, line_number))
    return packages


def _composer_lock(text):
    data = json.loads(text)
    line_of = _line_finder(text)
    packages = []
    for section in ("packages", "packages-dev"):
        for entry in data.get(section) or []:
            if not isinstance(entry, dict):
                continue
            name, version = entry.get("name"), entry.get("version")
            if isinstance(name, str) and isinstance(version, str) and not version.startswith("dev-"):
                packages.append(Package("Packagist", name, version[1:] if version[:1] in "vV" else version, line_of('"name": ' + json.dumps(name))))
    return packages


_GEM_PLATFORM = re.compile(r"-(?:x86|x64|arm|aarch64|universal|java|mswin|mingw|darwin|linux|freebsd)[\w.-]*$")


def _gemfile_lock(text):
    packages = []
    section = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line and not line[0].isspace():
            section = line.strip()
            continue
        if section != "GEM":
            continue
        match = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$", line)
        if match:
            packages.append(Package("RubyGems", match.group(1), _GEM_PLATFORM.sub("", match.group(2)), line_number))
    return packages


_PARSERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "requirements.txt": _requirements,
    "poetry.lock": _poetry_lock,
    "uv.lock": _uv_lock,
    "Cargo.lock": _cargo_lock,
    "go.mod": _go_mod,
    "composer.lock": _composer_lock,
    "Gemfile.lock": _gemfile_lock,
}
