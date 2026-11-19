"""Entry points that run automatically when a repository is opened, built or installed.

Backdoors in a cloned repository rarely sit in application code; they sit where a tool runs code
without being asked: a VS Code task on folder open, a dev container's host-side command, a Rust
build script (rust-analyzer runs it on open), a Gradle build (IDE import evaluates it), Composer
install hooks, Dockerfile RUN steps, or direnv's .envrc (handled as a shell script).

No language parser is needed: each check reads the config or build file line by line and reuses
the shell rules (SH001-SH004) for commands embedded in it. Checks return
``(line_number, rule_id, severity_override, message_override)`` tuples.
"""
import json
import re
from pathlib import Path

from aeppo import rules_shell


_DEVCONTAINER_NAMES = {"devcontainer.json", ".devcontainer.json"}
_GRADLE_NAMES = {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "init.gradle", "init.gradle.kts"}
_MSBUILD_SUFFIXES = {".csproj", ".vbproj", ".fsproj", ".props", ".targets"}
# Composer events that run during `composer install` / `update` / `create-project`.
_COMPOSER_EVENTS = (
    "pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd",
    "pre-autoload-dump", "post-autoload-dump", "post-root-package-install", "post-create-project-cmd",
)

_FOLDER_OPEN = re.compile(r'"runOn"\s*:\s*"folderOpen"')
_INITIALIZE_COMMAND = re.compile(r'"initializeCommand"\s*:')
_RUST_NETWORK = re.compile(r"\b(?:reqwest|ureq|attohttpc|isahc|hyper|minreq|curl)::|\bTcpStream::connect\b|\bUdpSocket::bind\b")
_RUST_SHELL = re.compile(r'\bCommand::new\(\s*"(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|curl|wget)"')
_GRADLE_EXEC = re.compile(r"\bcommandLine\b|\bexec\s*\{|\.execute\s*\(\s*\)|\bProcessBuilder\s*\(|\bRuntime\.getRuntime\(\)\.exec\b")
_GRADLE_NETWORK = re.compile(r"""\b(?:new\s+)?URL\s*\(\s*["'][^"']+["']\s*\)\s*\.\s*(?:text\b|readText\s*\(|openStream\s*\(|readBytes\s*\()""")
_MAVEN_SHELL = re.compile(r"<executable>\s*(?:sh|bash|zsh|cmd|powershell|pwsh|curl|wget)(?:\.exe)?\s*</executable>")
_MSBUILD_EXEC = re.compile(r"""<Exec\b[^>]*\bCommand\s*=\s*(["'])(.*?)\1""", re.DOTALL)
_MSBUILD_DOWNLOAD = re.compile(r"<DownloadFile\b")
_GO_GENERATE = re.compile(r"^\s*//go:generate\s+(.*)$")
_DOCKER_RUN = re.compile(r"^\s*RUN\b(.*)$", re.IGNORECASE)


def kind(path):
    """Return the entry-point kind handled here, or None."""
    path = Path(path)
    name = path.name
    lower = name.lower()
    suffix = path.suffix.lower()
    if name == "tasks.json" and path.parent.name == ".vscode":
        return "vscode_tasks"
    if name in _DEVCONTAINER_NAMES:
        return "devcontainer"
    if lower in {"dockerfile", "containerfile"} or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
        return "dockerfile"
    if name == "build.rs":
        return "build_rs"
    if name == "composer.json":
        return "composer"
    if name in _GRADLE_NAMES:
        return "gradle"
    if name == "pom.xml":
        return "maven"
    if suffix in _MSBUILD_SUFFIXES:
        return "msbuild"
    if suffix == ".go":
        return "go"
    return None


def scan(file_kind, lines):
    return _SCANNERS[file_kind](lines)


def _shell_lines(lines, skip_prefixes=("//", "#")):
    """Shell rules on every non-comment line of a config/build file."""
    hits = []
    for line_number, line in enumerate(lines, start=1):
        if line.lstrip().startswith(skip_prefixes):
            continue
        hits.extend((line_number, rule_id, None, None) for rule_id in rules_shell.check_command(line))
    return hits


def _vscode_tasks(lines):
    hits = _shell_lines(lines)
    hits.extend((number, "AUTO001", None, None) for number, line in enumerate(lines, start=1) if _FOLDER_OPEN.search(line) and not line.lstrip().startswith("//"))
    return hits


def _devcontainer(lines):
    hits = _shell_lines(lines)
    hits.extend((number, "AUTO002", None, None) for number, line in enumerate(lines, start=1) if _INITIALIZE_COMMAND.search(line) and not line.lstrip().startswith("//"))
    return hits


def _dockerfile(lines):
    """Shell rules on each RUN instruction, with backslash continuations joined."""
    hits = []
    index = 0
    while index < len(lines):
        match = _DOCKER_RUN.match(lines[index])
        if not match:
            index += 1
            continue
        start = index
        parts = [match.group(1)]
        while lines[index].rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            parts.append(lines[index])
        command = " ".join(part.rstrip().rstrip("\\") for part in parts)
        hits.extend((start + 1, rule_id, None, None) for rule_id in rules_shell.check_command(command))
        index += 1
    return hits


def _build_rs(lines):
    hits = _shell_lines(lines, skip_prefixes=("//",))
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("//"):
            continue
        if _RUST_NETWORK.search(line):
            hits.append((number, "BLD002", None, "Rust build script (build.rs) uses a network client; it runs on every build and when an IDE opens the project."))
        if _RUST_SHELL.search(line):
            hits.append((number, "BLD001", "medium", "Rust build script (build.rs) starts a shell or download tool; it runs on every build and when an IDE opens the project."))
    return hits


def _gradle(lines):
    hits = _shell_lines(lines, skip_prefixes=("//", "*", "/*"))
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith(("//", "*", "/*")):
            continue
        if _GRADLE_NETWORK.search(line):
            hits.append((number, "BLD002", None, "Gradle build script downloads content while it is evaluated, which also happens on IDE import."))
        if _GRADLE_EXEC.search(line):
            hits.append((number, "BLD001", "low", "Gradle build script runs an external command; check whether it runs at configuration time (on IDE import) or only in a task."))
    return hits


def _maven(lines):
    hits = _shell_lines(lines, skip_prefixes=("<!--",))
    if any("exec-maven-plugin" in line for line in lines):
        hits.extend((number, "BLD001", "medium", "Maven exec-maven-plugin runs a shell or download tool during the build.") for number, line in enumerate(lines, start=1) if _MAVEN_SHELL.search(line))
    return hits


def _msbuild(lines):
    text = "\n".join(lines)
    hits = []
    for match in _MSBUILD_EXEC.finditer(text):
        number = text.count("\n", 0, match.start()) + 1
        command = match.group(2).replace("&quot;", '"').replace("&amp;", "&").replace("&gt;", ">").replace("&lt;", "<")
        hits.extend((number, rule_id, None, None) for rule_id in rules_shell.check_command(command))
    hits.extend((number, "BLD002", "medium", "MSBuild DownloadFile task fetches content during the build.") for number, line in enumerate(lines, start=1) if _MSBUILD_DOWNLOAD.search(line))
    return hits


def _composer(lines):
    try:
        package = json.loads("\n".join(lines))
    except ValueError:
        return []
    scripts = package.get("scripts") if isinstance(package, dict) else None
    if not isinstance(scripts, dict):
        return []
    hits = []
    for event in _COMPOSER_EVENTS:
        if event not in scripts:
            continue
        number = next((index for index, line in enumerate(lines, start=1) if '"{}"'.format(event) in line), 1)
        # Composer hooks are routine in frameworks (for example Laravel's post-autoload-dump), so the
        # plain review signal is low; a remote download piped into an interpreter is not.
        hits.append((number, "DEP003", "low", "Composer {} script runs automatically during install or update.".format(event)))
        commands = scripts[event] if isinstance(scripts[event], list) else [scripts[event]]
        if any(isinstance(command, str) and "SH001" in rules_shell.check_command(command) for command in commands):
            hits.append((number, "DEP004", None, "Composer {} script downloads remote content and pipes it into an interpreter.".format(event)))
    return hits


def _go(lines):
    hits = []
    for number, line in enumerate(lines, start=1):
        match = _GO_GENERATE.match(line)
        if match:
            hits.extend((number, rule_id, None, None) for rule_id in rules_shell.check_command(match.group(1)))
    return hits


_SCANNERS = {
    "vscode_tasks": _vscode_tasks,
    "devcontainer": _devcontainer,
    "dockerfile": _dockerfile,
    "build_rs": _build_rs,
    "composer": _composer,
    "gradle": _gradle,
    "maven": _maven,
    "msbuild": _msbuild,
    "go": _go,
}
