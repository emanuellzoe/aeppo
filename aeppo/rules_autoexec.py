"""Entry points that run automatically when a repository is opened, built or installed.

Backdoors in a cloned repository rarely sit in application code; they sit where a tool runs code
without being asked: a VS Code task on folder open, a dev container's host-side command, a Rust
build script (rust-analyzer runs it on open), a Gradle build (IDE import evaluates it), Composer
install hooks, Dockerfile RUN steps, direnv's .envrc (handled as a shell script), or the config
files that make a tool run a program from the repository: yarnPath and .npmrc, an in-tree Python
build backend, .pth files, Cargo wrappers, build tool wrappers, VS Code settings, and Makefiles.

No language parser is needed: each check reads the config or build file line by line and reuses
the shell rules (SH001-SH004) for commands embedded in it. Checks return
``(line_number, rule_id, severity_override, message_override)`` tuples.
"""
import json
import re
from pathlib import Path

from aeppo import rules_shell


_DEVCONTAINER_NAMES = {"devcontainer.json", ".devcontainer.json"}
_MAKEFILE_NAMES = {"Makefile", "makefile", "GNUmakefile", "justfile", "Justfile", ".justfile"}
_WRAPPER_PROPERTIES = {"gradle-wrapper.properties", "maven-wrapper.properties"}
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
    if name == "settings.json" and path.parent.name == ".vscode":
        return "vscode_settings"
    if name in {".yarnrc.yml", ".yarnrc"}:
        return "yarnrc"
    if name == ".npmrc":
        return "npmrc"
    if name == "pyproject.toml":
        return "pyproject"
    if suffix == ".pth":
        return "pth"
    if name in {"config.toml", "config"} and path.parent.name == ".cargo":
        return "cargo_config"
    if name in _WRAPPER_PROPERTIES:
        return "build_wrapper"
    if name in _MAKEFILE_NAMES or suffix == ".mk":
        return "makefile"
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


def scan(file_kind, lines, path=None):
    """Check ``lines`` of a file of ``file_kind``; ``path`` (the file on disk) lets VS Code settings
    tell a program committed to the repository from one installed on the machine."""
    if file_kind == "vscode_settings":
        return _vscode_settings(lines, path)
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


# --- config files that make a tool run a program -----------------------------------------------

def _value(text):
    """The first quoted string in ``text``, or the bare remainder (YAML, .npmrc, TOML)."""
    match = re.search(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'', text)
    if match:
        return match.group(1) if match.group(1) is not None else match.group(2)
    return text.strip().rstrip(",").strip()


def _in_repository(value):
    """True for a relative path such as ``./tools/x.js`` or ``bin/x`` (not a bare command name)."""
    value = value.replace("${workspaceFolder}/", "./").replace("${workspaceRoot}/", "./")
    return bool(value) and not value.startswith(("/", "~", "$", "%")) and not re.match(r"^[A-Za-z]:[\\/]", value) and ("/" in value or "\\" in value)


# Yarn ships its own release and official plugins into .yarn/; anything else runs repository code.
_YARN_RELEASE = re.compile(r"^\.yarn/releases/yarn-[\w.+-]+\.c?js$")
_YARN_OFFICIAL_PLUGIN = re.compile(r"^\.yarn/plugins/@yarnpkg/plugin-[\w-]+\.c?js$")


def _yarnrc(lines):
    hits = []
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = re.match(r'^(?:yarnPath|"?yarn-path"?)\s*:?\s*(.+)$', stripped)
        if match:
            target = _value(match.group(1))
            if _YARN_RELEASE.match(target[2:] if target.startswith("./") else target):
                hits.append((number, "DEP005", "low", "yarnPath runs the committed Yarn release {} on every yarn command; check that it matches the official release.".format(target)))
            else:
                hits.append((number, "DEP005", None, "yarnPath makes every yarn command run {} from the repository instead of Yarn.".format(target)))
            continue
        match = re.match(r"^-?\s*path\s*:\s*(.+)$", stripped)
        if match:
            target = _value(match.group(1))
            if not _YARN_OFFICIAL_PLUGIN.match(target[2:] if target.startswith("./") else target):
                hits.append((number, "DEP005", "medium", "Yarn plugin {} from the repository is loaded by every yarn command.".format(target)))
    return hits


_NODE_PRELOAD = re.compile(r"(?:^|\s)(?:--require|-r|--import|--loader|--experimental-loader)(?:\s|=)")


def _npmrc(lines):
    hits = []
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith((";", "#")) or "=" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split("=", 1))
        value = _value(value)
        if key == "node-options" and _NODE_PRELOAD.search(" " + value):
            hits.append((number, "DEP005", None, ".npmrc node-options preloads code ({}) into every npm script and node process npm starts.".format(value)))
        elif key == "onload-script":
            hits.append((number, "DEP005", None, ".npmrc onload-script runs {} every time npm starts.".format(value)))
        elif key in {"script-shell", "git"} and value:
            hits.append((number, "DEP005", None if _in_repository(value) else "low", ".npmrc {} makes npm run {} instead of the usual program.".format(key, value)))
    return hits


def _pyproject(lines):
    hits = []
    in_build_system = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("["):
            in_build_system = stripped.startswith("[build-system]")
            continue
        if in_build_system and re.match(r"^backend-path\s*=", stripped):
            hits.append((number, "DEP006", None, None))
    return hits


def _pth(lines):
    # site.py executes .pth lines that start with "import"; other lines only extend sys.path.
    return [(number, "DEP007", None, None) for number, line in enumerate(lines, start=1) if re.match(r"^import[\s\t]", line)]


_CARGO_WRAPPERS = {"rustc-wrapper", "rustc-workspace-wrapper", "rustc", "rustdoc"}


def _cargo_config(lines):
    hits = []
    for number, line in enumerate(lines, start=1):
        match = re.match(r'^\s*"?([\w-]+)"?\s*=\s*(.+)$', line)
        if not match or line.lstrip().startswith("#"):
            continue
        key, value = match.group(1), _value(match.group(2).split(" #", 1)[0])
        if not value or value.startswith("["):
            value = _value(match.group(2).strip("[] "))
        local = _in_repository(value)
        if key in _CARGO_WRAPPERS:
            # Named tools such as sccache are common; a program committed to the repository is not.
            hits.append((number, "BLD003", "high" if local else "low", "Cargo runs {} {} on every build and when rust-analyzer opens the project.".format(key, value)))
        elif key == "linker" and local:
            hits.append((number, "BLD003", "high", "Cargo uses the program {} from the repository as the linker on every build.".format(value)))
        elif key == "runner" and local:
            hits.append((number, "BLD003", "medium", "cargo run and cargo test start the program {} from the repository.".format(value)))
        hits.extend((number, rule_id, None, None) for rule_id in rules_shell.check_command(value))
    return hits


_OFFICIAL_DISTRIBUTIONS = re.compile(r"^https://(?:services\.gradle\.org/distributions/|downloads\.gradle(?:-dn)?\.org/|repo\.maven\.apache\.org/maven2/|repo1\.maven\.org/maven2/)")


def _build_wrapper(lines):
    hits = []
    for number, line in enumerate(lines, start=1):
        match = re.match(r"^\s*(distributionUrl|wrapperUrl)\s*[=:]\s*(\S+)", line)
        if match:
            url = match.group(2).replace("\\:", ":").replace("\\=", "=")
            if not _OFFICIAL_DISTRIBUTIONS.match(url):
                hits.append((number, "BLD004", None, "Build tool wrapper downloads {} from {}; the wrapper runs it on every build and IDE import.".format(match.group(1), url)))
    return hits


def _makefile(lines):
    return _shell_lines(lines, skip_prefixes=("#",))


_VSCODE_PROGRAM_KEY = re.compile(r'^\s*"([\w.-]*(?:[Pp]ath|[Ee]xecutable|[Rr]untime|[Ss]erver[Pp]ath|[Ii]nterpreter[\w]*|alternateTools[\w.]*)|terminal\.integrated\.[\w.]*)"\s*:\s*(.+)$')
_VSCODE_ENV = re.compile(r'"(LD_PRELOAD|DYLD_INSERT_LIBRARIES|NODE_OPTIONS|PYTHONSTARTUP|BASH_ENV|ENV|PROMPT_COMMAND|PERL5OPT|RUBYOPT)"\s*:')


def _vscode_settings(lines, path):
    workspace = Path(path).parent.parent if path else None
    hits = []
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("//"):
            continue
        env = _VSCODE_ENV.search(line)
        if env:
            hits.append((number, "AUTO003", None, "VS Code settings set {} for its terminals and tasks, which can load code from the repository.".format(env.group(1))))
            continue
        match = _VSCODE_PROGRAM_KEY.match(line)
        if not match:
            continue
        value = _value(match.group(2))
        if not _in_repository(value):
            continue
        relative = value.replace("${workspaceFolder}/", "").replace("${workspaceRoot}/", "")
        # A virtualenv interpreter that is not committed is created locally; flag committed programs.
        if workspace is not None and (workspace / relative).is_file():
            hits.append((number, "AUTO003", None, "VS Code setting {} runs {}, a file committed to the repository, when the folder opens.".format(match.group(1), value)))
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
    "yarnrc": _yarnrc,
    "npmrc": _npmrc,
    "pyproject": _pyproject,
    "pth": _pth,
    "cargo_config": _cargo_config,
    "build_wrapper": _build_wrapper,
    "makefile": _makefile,
}
