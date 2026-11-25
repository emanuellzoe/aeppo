"""Finding objects and the rule registry shared by every rule module."""
from collections import namedtuple


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
    "AUTO001": Rule("VS Code task runs automatically when the folder is opened (runOn: folderOpen).", "medium", "high", "auto-exec", "Check the task's command before trusting the workspace; automatic tasks run as soon as the folder opens."),
    "AUTO002": Rule("Dev container initializeCommand runs on the host machine, outside the container.", "medium", "high", "auto-exec", "Review the command before opening the folder in a dev container; it runs with your local user's access."),
    "BLD001": Rule("Build script runs an external command.", "medium", "medium", "build-exec", "Check what the command does and when it runs; build scripts also run on IDE import or project open."),
    "BLD002": Rule("Build script downloads content from the network.", "high", "medium", "build-exec", "Builds should not fetch and use remote content implicitly; vendor it or pin it to a checksum."),
    "AUTO003": Rule("VS Code workspace setting runs a program from the repository or changes the terminal environment.", "medium", "medium", "auto-exec", "Check the program or variable before trusting the workspace; VS Code and its extensions start these tools when the folder opens."),
    "BLD003": Rule("Cargo config runs a wrapper or runner program on build.", "medium", "medium", "build-exec", "Check the program; cargo and rust-analyzer run rustc wrappers on every build, including when an IDE opens the project."),
    "BLD004": Rule("Build tool wrapper downloads its distribution from an unofficial URL.", "high", "medium", "supply-chain", "Point the wrapper at the official distribution (services.gradle.org, repo.maven.apache.org) and set its SHA-256 checksum."),
    "DEP005": Rule("Package manager config runs code from the repository on every command.", "high", "medium", "dependency-install-script", "Check the file it points at before running yarn or npm in this folder; it runs with your user's access."),
    "DEP006": Rule("Python build backend is loaded from the repository (backend-path); it runs on pip install.", "medium", "high", "dependency-install-script", "Read the in-tree backend before running pip install on this project."),
    "DEP007": Rule(".pth file runs Python code on every interpreter start once installed.", "high", "medium", "persistence", "Remove the import line unless it is expected; .pth files are a known way to hide code that runs whenever Python starts."),
    "GHA004": Rule("Workflow grants write-all permissions.", "medium", "high", "ci-security", "Grant only the permissions each job needs, starting from contents: read."),
    "DEP004": Rule("Install script downloads remote content and pipes it into an interpreter.", "high", "high", "supply-chain", "Do not install until the downloaded script is reviewed; vendor it or pin it to a verified checksum."),
    "GO001": Rule("exec.Command runs a shell with a command built at runtime.", "high", "medium", "command-execution", "Pass the program and its arguments separately (exec.Command(\"git\", \"log\", ref)) instead of sh -c with a built string."),
    "RS001": Rule("std::process::Command runs a shell with a command built at runtime.", "high", "medium", "command-execution", "Run the program directly with .arg() for each argument instead of sh -c with a formatted string."),
    "JV001": Rule("Process API runs a shell with a command built at runtime.", "high", "medium", "command-execution", "Pass the program and each argument as separate strings to ProcessBuilder, without sh -c."),
    "JV002": Rule("Runtime.exec runs a command string built at runtime.", "medium", "medium", "command-execution", "Use ProcessBuilder with a fixed program and separate, validated arguments."),
    "JV003": Rule("ObjectInputStream.readObject deserializes data that can execute code through gadget classes.", "medium", "medium", "unsafe-deserialization", "Do not deserialize untrusted data; use a data format such as JSON, or an ObjectInputFilter allow-list."),
    "PHP001": Rule("PHP evaluates code at runtime (eval, create_function, assert or preg_replace /e).", "high", "medium", "dynamic-code", "Remove the dynamic evaluation; web shells often hide behind eval of decoded data."),
    "PHP002": Rule("PHP runs a shell command built at runtime.", "medium", "medium", "command-execution", "Avoid the shell; if it is required, pass every value through escapeshellarg and never use request data directly."),
    "PHP003": Rule("unserialize on data that may be attacker controlled can instantiate arbitrary objects.", "low", "medium", "unsafe-deserialization", "Use json_decode, or pass ['allowed_classes' => false] to unserialize."),
    "RB001": Rule("Ruby evaluates a string as code at runtime.", "high", "medium", "dynamic-code", "Avoid eval; use explicit dispatch (public_send with an allow-list) or a parser."),
    "RB002": Rule("Ruby runs a shell command built at runtime.", "medium", "medium", "command-execution", "Use the argv form (system(\"git\", \"log\", ref)) so no shell parses the values."),
    "RB003": Rule("Marshal.load deserializes data that can execute code.", "medium", "medium", "unsafe-deserialization", "Only load Marshal data you produced yourself; use JSON for anything that crosses a trust boundary."),
    "NET001": Rule("Program connects to the network and hands the connection to a shell (reverse-shell pattern).", "high", "medium", "backdoor", "Remove it unless the program is an intended remote-access tool."),
    "VULN001": Rule("Dependency version has a known vulnerability.", "medium", "high", "vulnerable-dependency", "Upgrade to a fixed version and regenerate the lockfile."),
    "MAL001": Rule("Dependency version is listed as a malicious package.", "high", "high", "malware", "Do not install it; if it was installed, treat the machine and its credentials as compromised."),
    "SRC001": Rule("Bidirectional Unicode control character can make code render differently from how it runs (Trojan Source).", "high", "medium", "obfuscation", "Remove the control character, or confirm it only appears inside an intended string literal."),
}


def make_finding(path, line, rule_id, message=None):
    rule = RULES[rule_id]
    return Finding(path, line, rule_id, message or rule.message, rule.severity, rule.confidence, rule.category, rule.recommendation)
