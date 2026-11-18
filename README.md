# aeppo

`aeppo` is a local static scanner that flags selected risky code patterns and potentially exposed credentials in Python, JavaScript, and TypeScript source files. It does not execute scanned code.

## Project status

Early prototype. It scans selected Python, JavaScript, TypeScript, configuration, and dependency-manifest files. Python rules match real calls using the standard-library `ast` module; JavaScript, TypeScript, secret, and dependency rules are pattern-based. Findings do not prove that code is malicious or that a credential is valid; false positives and false negatives are possible.

## Requirements

- Python 3.9 or later
- No runtime dependencies

## Installation

Clone the public repository and install locally:

```bash
git clone https://github.com/emanuellzoe/aeppo.git
cd aeppo
python3 -m pip install .
```

This installs the `aeppo` command using the package metadata in `pyproject.toml`. Check the installed version with `aeppo --version`.

Or run directly from a checkout without installing:

```bash
python3 -m aeppo.cli scan PATH
```

## Usage

```bash
aeppo scan PATH
aeppo scan PATH --format json
aeppo scan PATH --format sarif --output aeppo.sarif
aeppo scan PATH --min-severity medium
aeppo scan PATH --baseline aeppo-baseline.json
aeppo scan PATH --exclude '**/generated/**' --max-file-size 524288
```

aeppo scans `.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`, shell scripts (`.sh`, `.bash`, `.zsh`, `.ksh`, and extensionless files with a shell shebang), GitHub Actions workflows (`.github/workflows/*.yml`) and `action.yml` files, Markdown (`.md`, `.markdown`, `.mdx`; secret rules only), `.yaml`, `.yml`, `.toml`, `.json`, `.ini`, `.cfg`, `.env` and any `.env.*` file (such as `.env.local` or `.env.staging`), `requirements.txt`, and `package.json`. It skips hidden directories and common generated/vendor directories without descending into them. `--exclude` accepts a relative path glob and may be repeated. Files larger than 1 MiB are skipped by default; override the limit with `--max-file-size BYTES`. A file that cannot be read is skipped with a warning on standard error instead of stopping the scan.

| Option | Effect |
|---|---|
| `--format text\|json\|sarif` | Output format (default `text`) |
| `--output FILE` | Write the report to `FILE` instead of standard output |
| `--min-severity low\|medium\|high` | Report only findings at or above this severity (default `low`) |
| `--baseline FILE` | Ignore findings already recorded in a JSON report (see below) |

Text output includes the path, line number, rule ID, severity, confidence, category, explanation, and recommendation. JSON output is an array of findings with `path`, `line`, `rule_id`, `message`, `severity`, `confidence`, `category`, `recommendation`, and `fingerprint` fields. SARIF output follows SARIF 2.1.0 and can be uploaded to GitHub code scanning.

Exit codes:

- `0`: scan completed with no findings (after severity, suppression, and baseline filtering)
- `1`: scan completed and findings were reported
- `2`: target could not be scanned, arguments were invalid, or the baseline/output file could not be used

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
      - uses: emanuellzoe/aeppo@d41323bd6f36265d42c6b08c551e1483410fc963 # v0.3.2
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
      - uses: emanuellzoe/aeppo@d41323bd6f36265d42c6b08c551e1483410fc963 # v0.3.2
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
| `SRC001` | Bidirectional Unicode control characters in Python, JavaScript, or TypeScript source ([Trojan Source](https://trojansource.codes/)) | Data files such as translations are not checked; suppress intended uses inside string literals |
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

During directory traversal, aeppo enters `.github/workflows` but skips other hidden directories, `.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, and `node_modules`.

## Security limitations

- Scanning is static and limited to the source and configuration formats listed above; target code and dependency scripts are not executed.
- Python rules follow import aliases, `__import__`, `importlib.import_module`, and `getattr` with literal names within a single file only. Calls reached through variables, wrappers, or names built at runtime are not detected.
- Names assembled at runtime, such as `globalThis['ev' + 'al']`, are out of reach for pattern-based rules. aeppo is a review aid, not a reliable detector of deliberately obfuscated backdoors.
- JavaScript, TypeScript, and secret rules are regular expressions and can miss obfuscated variants or produce false positives.
- Values that look like placeholders are still reported, but at `low` severity and confidence. This covers values containing `EXAMPLE` (such as the AWS documentation key) and values whose tail repeats one or two characters (`ghp_xxxx...`). Use `--min-severity medium` to hide them. Other well-formed dummy values are reported normally; suppress or baseline them after review.
- `SEC003` matches the private-key header line only, so headers quoted in documentation or in detection rules are reported too.
- Go, Rust, Java, and other languages are not scanned for code patterns; only their supported configuration and Markdown files are checked.
- Do not post findings containing secrets in public issues. If a real secret is detected, treat it as exposed and revoke or rotate it with the relevant provider.
- Do not treat a sandbox as an absolute guarantee if dynamic analysis is added in the future.
- Dependency rules flag review signals only. aeppo does not query vulnerability databases or determine whether a package version is known vulnerable.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Contributions adding rules should include positive and negative tests with dummy values, never real credentials. Split dummy secrets and risky call strings in test sources (for example `"AKIA" + "..."`) so aeppo's own scan of this repository stays clean.

## License

aeppo is distributed under the MIT License. See `LICENSE` for the full text.
