# aeppo

`aeppo` is a local static scanner that flags selected risky code patterns and potentially exposed credentials in Python, JavaScript, TypeScript, Go, Rust, Java, Kotlin, PHP and Ruby source files, shell scripts, CI workflows and build files. With `--osv` it also looks up the exact dependency versions in lockfiles in [OSV.dev](https://osv.dev/) to report known vulnerabilities and malicious packages. It does not execute scanned code.

## Project status

Early prototype. It scans selected Python, JavaScript, TypeScript, configuration, and dependency-manifest files. Python rules match real calls using the standard-library `ast` module; Go, Rust, Java/Kotlin, PHP and Ruby rules run on a small lexer that separates code from comments and strings; JavaScript, TypeScript, secret, and dependency rules are pattern-based. Findings do not prove that code is malicious or that a credential is valid; false positives and false negatives are possible.

## Requirements

- Python 3.9 or later
- No runtime dependencies

## Installation

Install from [PyPI](https://pypi.org/project/aeppo/):

```bash
python3 -m pip install aeppo
# or, as an isolated command-line tool:
pipx install aeppo
```

Or clone the public repository and install locally:

```bash
git clone https://github.com/emanuellzoe/aeppo.git
cd aeppo
python3 -m pip install .
```

This installs the `aeppo` command using the package metadata in `pyproject.toml`. Check the installed version with `aeppo --version`.

Or run directly from a checkout without installing:

```bash
python3 -m aeppo scan PATH
```

## Usage

```bash
aeppo scan PATH
aeppo scan PATH --format json
aeppo scan PATH --format sarif --output aeppo.sarif
aeppo scan PATH --min-severity medium
aeppo scan PATH --baseline aeppo-baseline.json
aeppo scan PATH --exclude '**/generated/**' --max-file-size 524288
aeppo scan PATH --disable GHA003 --disable SH005
aeppo scan app.py scripts/deploy.sh   # several files or directories at once
aeppo scan PATH --osv                 # also check lockfile dependencies in OSV.dev
aeppo check owner/repo                # vet a GitHub repository before trying it (see below)
```

aeppo scans `.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`, `.go`, `.rs`, `.java`, `.kt`, `.kts`, `.php`, `.phtml`, `.rb`, `.rake`, `.gemspec`, `Gemfile`, `Rakefile`, shell scripts (`.sh`, `.bash`, `.zsh`, `.ksh`, `.ps1`, `.envrc`, and extensionless files with a shell shebang), files that run automatically when a repository is opened, built or installed (`.vscode/tasks.json`, `devcontainer.json`, `Dockerfile`/`Containerfile`, `build.rs`, `composer.json`, Gradle and Maven builds, MSBuild project files, `//go:generate` in `.go` files), GitHub Actions workflows (`.github/workflows/*.yml`) and `action.yml` files, Markdown (`.md`, `.markdown`, `.mdx`; secret rules only), `.yaml`, `.yml`, `.toml`, `.json`, `.ini`, `.cfg`, `.env` and any `.env.*` file (such as `.env.local` or `.env.staging`), `requirements.txt`, and `package.json`. It skips hidden directories and common generated/vendor directories without descending into them. `--exclude` accepts a relative path glob and may be repeated. Files larger than 1 MiB are skipped by default; override the limit with `--max-file-size BYTES`. A file that cannot be read is skipped with a warning on standard error instead of stopping the scan.

| Option | Effect |
|---|---|
| `--format text\|json\|sarif` | Output format (default `text`) |
| `--output FILE` | Write the report to `FILE` instead of standard output |
| `--min-severity low\|medium\|high` | Report only findings at or above this severity (default `low`) |
| `--baseline FILE` | Ignore findings already recorded in a JSON report (see below) |
| `--disable RULE` | Turn off a rule ID; may be repeated. Unknown IDs are an error |
| `--config FILE` / `--no-config` | Use a specific settings file, or ignore `.aeppo.toml` (see below) |
| `--osv` | Look up lockfile dependency versions in OSV.dev (see [below](#known-vulnerable-and-malicious-dependencies)) |
| `--skip-unsupported` | Skip file arguments aeppo cannot scan instead of failing (used by the pre-commit hook) |

Text output includes the path, line number, rule ID, severity, confidence, category, explanation, and recommendation. JSON output is an array of findings with `path`, `line`, `rule_id`, `message`, `severity`, `confidence`, `category`, `recommendation`, and `fingerprint` fields. SARIF output follows SARIF 2.1.0 and can be uploaded to GitHub code scanning.

Exit codes:

- `0`: scan completed with no findings (after severity, suppression, and baseline filtering)
- `1`: scan completed and findings were reported
- `2`: target could not be scanned, arguments were invalid, the config/baseline/output file could not be used, or `--osv` could not reach OSV.dev (the report of the other rules is still printed)

## Configuration file

Put project settings in `.aeppo.toml` so every run (CLI, pre-commit, GitHub Action) uses the same ones:

```toml
exclude = ["tests/fixtures/**", "vendor/**"]   # relative path globs
disable = ["SH005"]                            # rule IDs to turn off
min-severity = "medium"                        # low | medium | high
max-file-size = 1048576                        # bytes
baseline = "aeppo-baseline.json"               # relative to this file
osv = true                                     # same as --osv
```

aeppo looks for `.aeppo.toml` starting from the scanned directory and moving up to the repository root (the first directory containing `.git`). When several paths or individual files are given, as pre-commit does, the search starts from the current directory. Use `--config FILE` to choose a file or `--no-config` to ignore it.

- Command-line options win: `--min-severity`, `--max-file-size`, and `--baseline` replace the file's values, while `--exclude` and `--disable` add to them.
- Exclude globs are matched against paths relative to the scanned directory, or against the path as given for file arguments. Keep the file at the repository root and scan from there.
- Unknown keys, unknown rule IDs, and invalid values are errors (exit code 2), so a typo cannot silently turn a setting off.
- Python 3.11+ reads the file with `tomllib`. Python 3.9 and 3.10 use a built-in parser for top-level keys with strings, integers, booleans, and arrays, so aeppo still has no runtime dependencies.

## pre-commit

Scan staged files before every commit with [pre-commit](https://pre-commit.com/). Add this to `.pre-commit-config.yaml` (pin `rev` to a release commit SHA):

```yaml
repos:
  - repo: https://github.com/emanuellzoe/aeppo
    rev: f40a369bad4e4cb534fdb2089f27834b540a0012  # v0.9.0
    hooks:
      - id: aeppo
```

The hook passes the staged files to `aeppo scan --skip-unsupported`, so files aeppo does not understand are skipped. It reads the repository's `.aeppo.toml`, and a finding blocks the commit until it is fixed, suppressed with `aeppo: ignore[RULE]`, or recorded in a baseline.

## Suppressing reviewed findings

After reviewing a finding, silence it with a comment on the same line or on the line above:

```python
subprocess.run(command, shell=True)  # aeppo: ignore[PY003]

# aeppo: ignore-next-line[SEC001]
EXAMPLE_KEY = "..."
```

`aeppo: ignore` without a rule list covers every rule on that line. Prefer listing rule IDs so new kinds of findings on the same line are still reported. The comment works in any scanned file that allows comments (`#`, `//`, and so on).

## Baselines

To adopt aeppo in an existing repository without fixing every historical finding first, record the current findings and pass them back on later runs:

```bash
aeppo scan . --format json --output aeppo-baseline.json
aeppo scan . --baseline aeppo-baseline.json
```

Findings are matched by path, rule ID, and a fingerprint of the whitespace-normalized source line, so they stay matched when surrounding lines move. Editing the flagged line or adding a new finding makes it reported again. Review the baseline file before committing it, because it records where secrets were found (but not the secret values).

## Checking a repository before trying it

Stars, forks and contributors do not make a repository safe to clone and run. `aeppo check` looks at a repository the way a backdoor would use it: what runs when you open it, install it, build it or run it.

```bash
aeppo check owner/repo                              # GitHub shorthand
aeppo check https://github.com/owner/repo           # any https:// git URL (GitLab, Codeberg, ...)
aeppo check https://github.com/owner/repo --ref v2.0
aeppo check ./already-cloned-repo                   # a local directory, scanned in place
aeppo check owner/repo --format json
aeppo check owner/repo --format html --output report.html   # visual report, open it in a browser
aeppo check owner/repo --no-osv                     # no network use besides the clone
```

1. **Safe clone.** The repository is cloned with `--depth 1` into a temporary directory that is deleted afterwards. Hooks, submodules, Git LFS, symbolic links (checked out as plain files), stored credentials, and every transport except `https` are turned off.
2. **Scan.** All static rules run, and lockfile dependencies are looked up in OSV.dev (as with `--osv`). The repository's own `.aeppo.toml` and `aeppo: ignore` comments are ignored, because whoever wrote the repository controls them.
3. **Report.** Findings are grouped by the moment they would run on your machine: opening the folder (VS Code tasks, dev containers, `.envrc`), installing dependencies (`package.json` scripts, `setup.py`, Composer hooks), building (`build.rs`, Gradle, Maven, MSBuild, Dockerfile, `go generate`), running its code, running its tests and examples, and its dependencies. GitHub Actions findings and committed credentials are listed separately because they put the project at risk, not you.
4. **Verdict.**

| Verdict | When | Exit code |
|---|---|---|
| `DANGER` | A strong sign of malicious behaviour anywhere (`MAL001`, `NET001`, `SH002`, `SH003`, `PY006`), or a high-severity finding in something that runs on open, install or build | `3` |
| `REVIEW` | A medium- or high-severity finding in its code, install, build, open or dependency sections | `1` |
| `NO KNOWN ISSUES` | Nothing above. Findings in tests and examples, CI workflows and committed credentials are listed but do not change the verdict | `0` |

Exit code `2` means the check could not run (invalid URL, clone failed, git missing). If OSV.dev cannot be reached, the dependency section says `NOT CHECKED` and the verdict covers the other sections only.

### Visual report

`--format html` writes a single self-contained page: the verdict banner, a card per section coloured by its worst finding, a table of vulnerable dependencies with the upgrade that fixes them, and a tree of every scanned file (red: high, yellow: medium or low, green: scanned with nothing found). Each file with findings shows the lines around them, with the flagged lines highlighted and the explanation and recommendation underneath.

The page is safe to open even when the repository is hostile: every value from the repository is HTML-escaped, the page contains no JavaScript, and its Content-Security-Policy allows nothing but its own stylesheet. Lines flagged as committed credentials are replaced with a placeholder, so the report can be shared.

`NO KNOWN ISSUES` is not a guarantee. aeppo finds known risky patterns in text; new or obfuscated malware, a malicious dependency that no database lists yet, or harm done at run time can all be missed. Install and run code you do not trust in a disposable VM or container.

## Known-vulnerable and malicious dependencies

`aeppo scan PATH --osv` reads the exact versions pinned in lockfiles and looks them up in [OSV.dev](https://osv.dev/), which aggregates the GitHub Advisory Database, PyPA, RustSec, the Go vulnerability database, RubySec and the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) feed.

| Ecosystem | Files read |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5 to v9) |
| PyPI | `poetry.lock`, `uv.lock`, `requirements*.txt` and `requirements/*.txt` (only `name==version` pins) |
| crates.io | `Cargo.lock` |
| Go | `go.mod` `require` directives, after `replace` (`go.sum` also lists versions that are not used) |
| Packagist | `composer.lock` |
| RubyGems | `Gemfile.lock` (`GEM` section) |

| ID | Detection | Severity |
|---|---|---|
| `VULN001` | A pinned version is affected by a published advisory. The message names the advisory and CVE, and the recommendation names the first fixed version | From the advisory: GitHub severity or the CVSS v3 score (critical and high are reported as `high`); `medium` when the advisory gives none; `low` for informational RustSec notices such as `unmaintained` |
| `MAL001` | A pinned version is listed as malicious (`MAL-` advisories) | Always `high` |

- **What is sent:** only the ecosystem, package name and version of each locked dependency, to `api.osv.dev`. Nothing else leaves the machine. Without `--osv` (or `osv = true`) aeppo makes no network requests. Packages from workspaces, local paths, git and URL sources are not sent, but private registry packages listed in a lockfile are; do not use `--osv` if their names are confidential.
- **Cache:** full advisory records are cached in `~/.cache/aeppo/osv` (`$XDG_CACHE_HOME` or `$AEPPO_CACHE_DIR` override it) and refetched when OSV reports a newer revision. Every scan still asks OSV which advisories apply, so newly published ones are reported the next time you scan.
- **Summary:** text output ends with one line per affected package version: the number of advisories by severity, the lockfile locations, and the single upgrade that fixes every advisory with a listed fix (for example `tar 6.2.1 (npm): 12 advisories (1 critical, 8 high, 3 medium) -> upgrade to 7.5.21 or later`). Malicious packages are listed first. When a version has several advisories, each finding's recommendation also names that upgrade.
- **Findings** point at the lockfile line of the package and work with `--min-severity`, `--disable`, baselines and SARIF like other rules. Their fingerprint is the package, version and advisory, so upgrading the package clears the finding from a baseline match. Lockfiles cannot carry suppression comments; use a baseline or `--disable` instead.
- Lockfiles are read up to 64 MiB regardless of `--max-file-size`; `node_modules` and hidden directories are skipped.
- A version range in `package.json`, `pyproject.toml` or an unpinned `requirements.txt` line is not checked, because the installed version is not known. Commit a lockfile to have it checked.
- An advisory matching a version does not mean the vulnerable code is reachable from the project; review the advisory before treating it as exploitable.

## GitHub Action

Add aeppo to a workflow after checking out the repository:

```yaml
name: Security scan
on:
  pull_request:
permissions:
  contents: read
jobs:
  aeppo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: emanuellzoe/aeppo@f40a369bad4e4cb534fdb2089f27834b540a0012 # v0.9.0
        with:
          path: .
          format: json
          exclude: |
            **/generated/**
          max-file-size: "1048576"
          min-severity: low
          fail-on-findings: "true"
```

Both actions are pinned to full commit SHAs; verify the source and update the pins deliberately when upgrading. Release commits are listed on the [releases page](https://github.com/emanuellzoe/aeppo/releases). The action runs the scanner on the GitHub runner, does not execute scanned code, and requires only repository read permission. Findings fail the job by default; set `fail-on-findings: "false"` to report findings without failing the job.

| Input | Default | Description |
|---|---|---|
| `path` | `.` | File or directory to scan |
| `format` | `text` | `text`, `json`, or `sarif` |
| `exclude` | | Newline-separated relative path globs |
| `max-file-size` | `1048576` | Skip larger files (bytes) |
| `min-severity` | `low` | `low`, `medium`, or `high` |
| `baseline` | | JSON baseline written by `aeppo scan --format json` |
| `output-file` | | Write the report to this file instead of the log |
| `fail-on-findings` | `true` | Fail the job when findings are reported |
| `osv` | `false` | `"true"` checks lockfile dependencies in OSV.dev (`VULN001`, `MAL001`); needs network access from the runner |
| `python-version` | `3.12` | Python used to run aeppo |

### Uploading results to GitHub code scanning

Write SARIF to a file and upload it so findings appear as code scanning alerts and pull-request annotations. Uploading needs `security-events: write`; `if: always()` uploads even when findings fail the scan step.

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  aeppo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: emanuellzoe/aeppo@f40a369bad4e4cb534fdb2089f27834b540a0012 # v0.9.0
        with:
          format: sarif
          output-file: aeppo.sarif
      - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
        if: always()
        with:
          sarif_file: aeppo.sarif
```

SARIF locations are written relative to the working directory, which is the repository root on GitHub runners.

## Current rules

| ID | Detection | Notes |
|---|---|---|
| `PY001` | `os.system(...)` or `os.popen(...)` call, including aliases, `__import__("os")`, `importlib.import_module("os")`, and `getattr(os, "system")` | Matched on the syntax tree; comments and strings are ignored |
| `PY002` | Call to the built-in `eval(...)` or `exec(...)` | Method calls such as `model.eval()` are not reported |
| `PY003` | `subprocess` call with `shell=True`, `getoutput`/`getstatusoutput`, or a shell argument list such as `["sh", "-c", command]` whose command is not a literal | Running a script file or a literal `-c` command is not reported |
| `PY004` | `pickle`/`dill` `load`, `loads`, or `Unpickler` | Unsafe only when the data is untrusted |
| `PY005` | `yaml.load`/`load_all` without a safe loader, or `yaml.unsafe_load` | `SafeLoader`/`CSafeLoader` and `yaml.safe_load` are not reported |
| `PY006` | Interactive shell: `subprocess` with `["/bin/sh", "-i"]`, or `pty.spawn` of a shell | Common reverse-shell and backdoor shape |
| `JS001` | `eval(` call, or `eval` passed as a callback such as `.then(eval)` | Method calls named `eval` are not reported |
| `JS002` | `exec(`/`execSync(` called bare, on `child_process`, on a `child_process` alias, or on `require('child_process')`; `spawn`/`execFile` of a shell with `-c` and a non-literal command | A bare `exec(` is reported only in files that mention `child_process`, so local helpers named `exec` are not reported. `RegExp.prototype.exec` and method definitions named `exec` are not reported either |
| `JS003` | `Function(...)` with or without `new`, or `setTimeout`/`setInterval` with a string argument | Type annotations such as `cb: Function` and methods named `Function` (Babel visitors) are not reported |
| `SRC001` | Bidirectional Unicode control characters in Python, JavaScript, TypeScript, Go, Rust, Java/Kotlin, PHP or Ruby source ([Trojan Source](https://trojansource.codes/)) | Data files such as translations are not checked; suppress intended uses inside string literals |
| `SEC001` | AWS access key ID pattern beginning with `AKIA` | Does not validate the key or determine whether it is active |
| `SEC002` | GitHub token patterns beginning with `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` | Does not validate the token |
| `SEC003` | Common PEM private-key headers | Detects a header, not whether the complete key is valid |
| `SEC004` | Slack token (`xoxb-`, `xoxp-`, ... followed by numeric IDs) | Does not validate the token |
| `SEC005` | Stripe live secret or restricted key (`sk_live_`, `rk_live_`) | Test-mode keys are not reported |
| `SEC006` | OpenAI API key (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, or legacy `sk-` keys) | Short placeholders are not reported |
| `SEC007` | Anthropic API key (`sk-ant-api03-` and similar versioned prefixes) | Does not validate the key |
| `SEC008` | Google API key beginning with `AIza` | Does not validate the key |
| `DEP001` | Unconstrained requirement in `requirements.txt` | Dependency hygiene signal; not a vulnerability verdict |
| `DEP002` | Direct URL, VCS, or local dependency reference | Verify the source and pin to an immutable revision |
| `DEP003` | npm install lifecycle script in `package.json` | Review commands before installing dependencies |
| `DEP004` | Install or `prepare` script that downloads content and pipes it into a shell or interpreter (`curl ... \| sh`, `bash <(curl ...)`) | Reported in addition to `DEP003` |

Python files that cannot be parsed (for example Python 2 sources) fall back to line-based patterns for `PY001` and `PY002`.

### Shell scripts

| ID | Detection | Notes |
|---|---|---|
| `SH001` | Download piped into an interpreter (`curl ... \| sh`, `\| bash -s`, `\| python3`), `source <(curl ...)`, `eval "$(curl ...)"` | `\| python3 -m json.tool`, `\| jq`, `\| node script.js` and `sh -c` only process data and are not reported |
| `SH002` | Reverse shells: `bash -i >& /dev/tcp/...`, `nc -e /bin/sh`, `socat ... exec:sh`, `mkfifo` + `nc` | A plain `/dev/tcp` health check (wait-for-it) is not reported |
| `SH003` | Encoded payload decoded and run (`base64 -d \| sh`, `eval "$(... base64 -d)"`, `xxd -r \| sh`) | Decoding to a file is not reported |
| `SH004` | Persistence: appending to `authorized_keys`, installing a cron entry (`\| crontab -`, writes to `/etc/cron*`) | `crontab -l` is not reported |
| `SH005` | Appending to a shell startup file (`~/.bashrc`, `~/.zshrc`, `~/.profile`) | Low severity: installers do this legitimately |

### GitHub Actions

| ID | Detection | Notes |
|---|---|---|
| `GHA001` | `pull_request_target` workflow that checks out or fetches the pull request's code (`ref: ${{ github.event.pull_request.head.sha }}`, `gh pr checkout`) | The "pwn request" pattern; checking out `github.sha` is not reported |
| `GHA002` | Untrusted context (issue/PR title or body, comment body, `github.head_ref`, commit messages) expanded inside `run:` or `script:` | Passing the value through `env:` is the fix and is not reported |
| `GHA003` | Action referenced by a tag or branch instead of a full commit SHA | `low` for `actions/*` and `github/*`, `medium` for third-party actions; local `./` actions are not reported |
| `GHA004` | `permissions: write-all` | `high` when the workflow also runs on `pull_request_target`, `workflow_run` or `issue_comment` |

### Auto-run entry points

A backdoor in a cloned repository usually sits where a tool runs code without being asked, not in application code. These files are read without a language parser. Commands embedded in them are checked with the shell rules (`SH001`–`SH004`), so `curl … | sh` in a Dockerfile `RUN` step, a VS Code task, a `//go:generate` line or an MSBuild `<Exec>` is reported too.

| ID | Detection | Notes |
|---|---|---|
| `AUTO001` | `.vscode/tasks.json` task with `"runOn": "folderOpen"` | Runs as soon as the folder opens in VS Code (once automatic tasks are allowed) |
| `AUTO002` | `devcontainer.json` `initializeCommand` | Runs on the **host** before the container starts; in-container commands such as `postCreateCommand` are not reported |
| `BLD001` | Build script starts a shell or download tool: `build.rs` `Command::new("sh"/"curl"…)` (medium), Gradle `commandLine`/`exec {}`/`.execute()` (low), `exec-maven-plugin` running a shell (medium) | `build.rs` runs on every build and when rust-analyzer opens the project; Gradle runs on IDE import. `Command::new("git")` is not reported |
| `BLD002` | Build script uses the network: `build.rs` with `reqwest`/`ureq`/`TcpStream` (high), Gradle `URL(...).readText()` (high), MSBuild `<DownloadFile>` (medium) | |
| `DEP003` / `DEP004` | Composer install hooks (`post-install-cmd`, `post-autoload-dump`, …); `DEP004` when one pipes a download into an interpreter | Composer hooks are routine in frameworks, so `DEP003` is low for Composer |

`SH001` also covers PowerShell download cradles (`iwr … | iex`, `IEX (… DownloadString(…))`), and `SH003` covers `powershell -EncodedCommand`. `.envrc` is scanned as a shell script because direnv runs it on `cd`.

### Go, Rust, Java/Kotlin, PHP and Ruby

These rules run on a lexer that blanks out comments and string contents, so call shapes inside comments, documentation strings, PHP's surrounding HTML, Ruby regex literals and heredocs do not match. A shell started with a **plain string literal** as its command is not reported for that alone; the literal is checked with the shell rules instead, so `exec.Command("sh", "-c", "curl … | sh")` reports `SH001` while `exec.Command("sh", "-c", "make test")` stays quiet. The argv form (`exec.Command("git", "log", ref)`, `system("git", "log", ref)`) runs no shell and is not reported.

| ID | Detection | Notes |
|---|---|---|
| `GO001` | `exec.Command`/`CommandContext` running `sh`/`bash`/`cmd`/`powershell` with `-c`//`/C` and a command built at runtime | |
| `RS001` | `std::process::Command::new("sh")` with `.arg("-c")`/`.args([...])` and a runtime command, across a multi-line builder chain | In `build.rs` the line is reported as `BLD001` instead |
| `JV001` | `ProcessBuilder(...)`, `.command(...)` or `Runtime.exec(new String[]{...})` running a shell with `-c` and a runtime command; `List.of`, `Arrays.asList`, Kotlin `arrayOf`/`listOf` are unwrapped | |
| `JV002` | `Runtime.getRuntime().exec(cmd)` (or a `Runtime` variable) with a runtime command string | medium: the string is split on spaces, not run by a shell |
| `JV003` | `ObjectInputStream` + `.readObject()` | medium; legitimate in RPC code, dangerous on untrusted input |
| `PHP001` | `eval`, `create_function`, `assert` of a string, `preg_replace` with `/e` | low for `eval` of a plain literal; the message calls out `eval(base64_decode(…))`-style web shells and request data |
| `PHP002` | `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, `pcntl_exec`, backticks with a runtime command | high with `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`, low when wrapped in `escapeshellarg`; `$pdo->exec()` and `Foo::system()` are not calls to these functions |
| `PHP003` | `unserialize` of a non-literal | low by default (common for internal caches), high with request data; not reported with `allowed_classes` |
| `RB001` | `eval` of a non-literal (with or without parentheses) | `obj.eval` and method definitions are ignored |
| `RB002` | `system`, `exec`, `spawn`, `IO.popen`, `Open3.*` with a single runtime string, or a shell with `-c`; interpolated backticks and `%x()` | high with `params[...]`; splats and argv forms are not reported |
| `RB003` | `Marshal.load` / `Marshal.restore` | medium |
| `NET001` | Network connection (`net.Dial`, `TcpStream::connect`, `new Socket`, `fsockopen`, `TCPSocket.new`) in the same file as an interactive shell (`/bin/sh`, `sh -i`), or a Go process whose `Stdin`/`Stdout` is the dialed connection | Reverse-shell pattern |

During directory traversal, aeppo enters `.github/workflows`, `.vscode` (only `tasks.json`) and `.devcontainer`, but skips other hidden directories, `.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, and `node_modules`.

## Security limitations

- Scanning is static and limited to the source and configuration formats listed above; target code and dependency scripts are not executed.
- Python rules follow import aliases, `__import__`, `importlib.import_module`, and `getattr` with literal names within a single file only. Calls reached through variables, wrappers, or names built at runtime are not detected.
- Names assembled at runtime, such as `globalThis['ev' + 'al']`, are out of reach for pattern-based rules. aeppo is a review aid, not a reliable detector of deliberately obfuscated backdoors.
- JavaScript, TypeScript, and secret rules are regular expressions and can miss obfuscated variants or produce false positives.
- Values that look like placeholders are still reported, but at `low` severity and confidence. This covers values containing `EXAMPLE` (such as the AWS documentation key) and values whose tail repeats one or two characters (`ghp_xxxx...`). Use `--min-severity medium` to hide them. Other well-formed dummy values are reported normally; suppress or baseline them after review.
- `SEC003` matches the private-key header line only, so headers quoted in documentation or in detection rules are reported too.
- Go, Rust, Java/Kotlin, PHP and Ruby rules are lexer-based patterns, not type-aware analysis: a shell program or flag held in a variable (`exec.Command(shell, flag, cmd)`), wrapper functions, and aliased imports are not followed, and taint is only approximated (request data on the same call). C, C++, C#, Swift and other languages are checked for secrets and auto-run entry points only.
- Secret rules also run on these source files, so test fixtures (for example in secret scanners' own `_test.go` files) can report secret findings; exclude them in `.aeppo.toml` if that is noise.
- Do not post findings containing secrets in public issues. If a real secret is detected, treat it as exposed and revoke or rotate it with the relevant provider.
- Do not treat a sandbox as an absolute guarantee if dynamic analysis is added in the future.
- `DEP` rules flag review signals only. Known vulnerabilities and malware are reported only with `--osv`, only for versions pinned in a lockfile, and only when OSV.dev lists them; a new malicious package can be in use before any database lists it.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Contributions adding rules should include positive and negative tests with dummy values, never real credentials. Split dummy secrets and risky call strings in test sources (for example `"AKIA" + "..."`) so aeppo's own scan of this repository stays clean.

## Contributing, security and changes

- [CONTRIBUTING.md](CONTRIBUTING.md): development setup, module layout, and how to add a rule with corpus samples.
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately.
- [CHANGELOG.md](CHANGELOG.md): what changed in each release.

## License

aeppo is distributed under the MIT License. See `LICENSE` for the full text.
