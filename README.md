# aeppo

`aeppo` is a local static scanner that flags selected risky code patterns and potentially exposed credentials in Python, JavaScript, and TypeScript source files. It does not execute scanned code.

## Project status

Early prototype. It scans `.py`, `.js`, `.jsx`, `.ts`, and `.tsx` files and currently uses a small set of pattern-based rules. Findings do not prove that code is malicious or that a credential is valid; false positives and false negatives are possible.

## Requirements

- Python 3.9 or later
- No external dependencies

## Usage

From the repository root:

```bash
python3 -m aeppo.cli scan PATH
```

Examples:

```bash
python3 -m aeppo.cli scan ./some-repository
python3 -m aeppo.cli scan ./some-repository --format json
```

Text output includes the path, line number, rule ID, and explanation. JSON output is an array of findings with `path`, `line`, `rule_id`, and `message` fields.

Exit codes:

- `0`: scan completed with no findings
- `1`: scan completed and findings were reported
- `2`: target could not be scanned or arguments were invalid

## Current rules

| ID | Detection | Notes |
|---|---|---|
| `PY001` | `os.system(` call pattern in Python | Static heuristic; review the usage context |
| `JS001` | `eval(` call pattern in JavaScript/TypeScript | Static heuristic; review the usage context |
| `SEC001` | AWS access key ID pattern beginning with `AKIA` | Does not validate the key or determine whether it is active |
| `SEC002` | GitHub token patterns beginning with `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` | Does not validate the token |
| `SEC003` | Common PEM private-key headers | Detects a header, not whether the complete key is valid |

During directory traversal, aeppo skips hidden directories, `.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, and `node_modules`.

## Security limitations

- Scanning is static and limited to the Python, JavaScript, and TypeScript extensions listed above; target code is not executed.
- Simple regular-expression rules can miss obfuscated variants or produce false positives.
- Do not post findings containing secrets in public issues. If a real secret is detected, treat it as exposed and revoke or rotate it with the relevant provider.
- Do not treat a sandbox as an absolute guarantee if dynamic analysis is added in the future.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Contributions adding rules should include positive and negative tests with dummy values, never real credentials.
