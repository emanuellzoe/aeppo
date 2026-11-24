# Changelog

All notable changes to aeppo. Versions follow [Semantic Versioning](https://semver.org/); while the version is below 1.0, a minor release can add rules that report new findings on code that was clean before.

## Unreleased

## 0.10.0 (2026-11-24)

- `aeppo check --format html` writes a visual report: verdict banner, section cards, a vulnerable-dependency table, a colour-coded tree of the scanned files, and code excerpts with the flagged lines highlighted. The page has no JavaScript and a strict Content-Security-Policy, escapes everything from the repository, and masks lines flagged as credentials. `--output FILE` writes any `check` report to a file.

## 0.9.0 (2026-11-23)

- `aeppo check REPO` vets a repository before you try it: a hardened shallow clone into a temporary directory (no hooks, submodules, LFS, symlinks, stored credentials or non-https transports), all static rules plus OSV.dev, findings grouped by when they would run (open, install, build, run, tests, dependencies), and a verdict (`DANGER`, `REVIEW`, `NO KNOWN ISSUES`; exit codes 3, 1, 0). The repository's `.aeppo.toml` and suppression comments are ignored.
- `--osv` text output ends with a per-package summary that names the one upgrade fixing every advisory with a fix (for example `tar 6.2.1 -> 7.5.21`), and recommendations of packages with several advisories name that upgrade too.
- `python -m aeppo` works (previously `python -m aeppo.cli`, which still works).

## 0.8.0 (2026-11-23)

- `--osv` (or `osv = true` in `.aeppo.toml`, or the Action's `osv` input) looks up exact versions from `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, pinned `requirements*.txt`, `Cargo.lock`, `go.mod`, `composer.lock` and `Gemfile.lock` in OSV.dev: `VULN001` for known vulnerabilities (with the first fixed version) and `MAL001` for packages listed as malicious. Off by default; without it aeppo makes no network requests.
- Split `aeppo/scanner.py` into rule modules (`findings`, `rules_python`, `rules_js`, `rules_secrets`, `rules_deps`). Findings, fingerprints and the public API (`aeppo.scanner.scan_path`, `scan_file`, `filter_findings`, `load_baseline`, `RULES`, `Finding`) are unchanged.
- Added `SECURITY.md`, `CONTRIBUTING.md` and this changelog.
- Added a PyPI publishing workflow (trusted publishing, no stored token).

## 0.7.0 (2026-11-19)

- Code rules for Go, Rust, Java/Kotlin, PHP and Ruby on a shared lexer that blanks comments and string contents: `GO001`, `RS001`, `JV001`–`JV003`, `PHP001`–`PHP003`, `RB001`–`RB003`, and `NET001` for reverse shells.
- Shell commands passed to these APIs as plain literals are checked with the shell rules (`SH001`–`SH004`) instead of being reported for existing.
- `SRC001` (Trojan Source) also checks these languages.

## 0.6.0 (2026-11-19)

- Auto-run entry points: `AUTO001` (VS Code `runOn: folderOpen`), `AUTO002` (dev container `initializeCommand`), `BLD001`/`BLD002` (`build.rs`, Gradle, Maven, MSBuild), Composer install hooks.
- Shell rules now also run on Dockerfile `RUN`, MSBuild `<Exec>`, `//go:generate`, `.envrc` and PowerShell (`iwr | iex`, `-EncodedCommand`).

## 0.5.1 (2026-11-19)

- Fixed: install instructions printed with `echo`/`printf` (`echo "curl … | sh"`) are no longer reported.

## 0.5.0 (2026-11-18)

- `.aeppo.toml` configuration (exclude, disable, min-severity, max-file-size, baseline), discovered by walking up to the repository root.
- pre-commit hook (`id: aeppo`).

## 0.4.0 (2026-11-18)

- Shell script rules `SH001`–`SH005` (download piped into an interpreter, reverse shells, encoded payloads, persistence, startup files).
- GitHub Actions rules `GHA001`–`GHA004` (pull_request_target checkout, script injection, unpinned actions, write-all).

## 0.3.3 (2026-11-18)

- Detection corpus with expected findings, and a scan-speed benchmark in CI.

## 0.3.2 (2026-11-18)

- Fixed: a bare `exec()` in JavaScript is only reported when the file uses `child_process`.

## 0.3.1 (2026-11-18)

- Scan `.mjs`/`.cjs`/`.mts`/`.cts` and Markdown (secrets only); placeholder credentials and Babel `Function(path)` visitors are no longer reported at normal severity.

## 0.3.0 (2026-11-18)

- Indirect Python calls (`__import__`, `importlib`, `getattr`), interactive shells (`PY006`), Trojan Source (`SRC001`), remote install scripts in `package.json` (`DEP004`).
- SARIF output, baselines, inline suppression, `--min-severity`, `--disable`.

## 0.2.0 (2026-11-18)

- First release: Python, JavaScript and TypeScript rules, secret patterns, dependency manifests, JSON and text output, and a composite GitHub Action.
