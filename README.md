# aeppo

`aeppo` is a local static scanner that flags selected risky code patterns and potentially exposed credentials in Python, JavaScript, and TypeScript source files. It does not execute scanned code.

## Project status

Early prototype. It scans selected Python, JavaScript, TypeScript, configuration, and dependency-manifest files using pattern-based rules. Findings do not prove that code is malicious or that a credential is valid; false positives and false negatives are possible.

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

This installs the `aeppo` command using the package metadata in `setup.py`.

Or run directly from a checkout without installing:

```bash
python3 -m aeppo.cli scan PATH
```

## Usage

```bash
aeppo scan PATH
aeppo scan PATH --format json
aeppo scan PATH --exclude '**/generated/**' --max-file-size 524288
```

aeppo scans `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.yaml`, `.yml`, `.toml`, `.json`, `.ini`, `.cfg`, `.env`, `.env.local`, `.env.development`, `.env.production`, `requirements.txt`, and `package.json`. It skips hidden directories and common generated/vendor directories. `--exclude` accepts a relative path glob and may be repeated. Files larger than 1 MiB are skipped by default; override the limit with `--max-file-size BYTES`.

Text output includes the path, line number, rule ID, severity, confidence, category, explanation, and recommendation. JSON output is an array of findings with `path`, `line`, `rule_id`, `message`, `severity`, `confidence`, `category`, and `recommendation` fields.

Exit codes:

- `0`: scan completed with no findings
- `1`: scan completed and findings were reported
- `2`: target could not be scanned or arguments were invalid

## Current rules

| ID | Detection | Notes |
|---|---|---|
| `PY001` | `os.system(` call pattern in Python | Static heuristic; review the usage context |
| `PY002` | `eval(` or `exec(` call pattern in Python | Static heuristic; review the usage context |
| `JS001` | `eval(` call pattern in JavaScript/TypeScript | Static heuristic; review the usage context |
| `JS002` | `exec(` or `execSync(` call pattern in JavaScript/TypeScript | Static heuristic; review the usage context |
| `SEC001` | AWS access key ID pattern beginning with `AKIA` | Does not validate the key or determine whether it is active |
| `SEC002` | GitHub token patterns beginning with `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` | Does not validate the token |
| `SEC003` | Common PEM private-key headers | Detects a header, not whether the complete key is valid |
| `DEP001` | Unconstrained requirement in `requirements.txt` | Dependency hygiene signal; not a vulnerability verdict |
| `DEP002` | Direct URL, VCS, or local dependency reference | Verify the source and pin to an immutable revision |
| `DEP003` | npm install lifecycle script in `package.json` | Review commands before installing dependencies |

During directory traversal, aeppo skips hidden directories, `.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, and `node_modules`.

## Security limitations

- Scanning is static and limited to the source and configuration formats listed above; target code and dependency scripts are not executed.
- Simple regular-expression rules can miss obfuscated variants or produce false positives.
- Do not post findings containing secrets in public issues. If a real secret is detected, treat it as exposed and revoke or rotate it with the relevant provider.
- Do not treat a sandbox as an absolute guarantee if dynamic analysis is added in the future.
- Dependency rules flag review signals only. aeppo does not query vulnerability databases or determine whether a package version is known vulnerable.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Contributions adding rules should include positive and negative tests with dummy values, never real credentials.

## License

aeppo is distributed under the MIT License. See `LICENSE` for the full text.
