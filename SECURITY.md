# Security policy

## Supported versions

Only the latest release receives fixes. Pin the GitHub Action and pre-commit hook to a full commit SHA and update it when a new release is published.

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/emanuellzoe/aeppo/security/advisories/new). Do not open a public issue.

Useful reports include the aeppo version, the command or Action inputs, and a minimal file that reproduces the problem. If a sample needs to look malicious, keep it inert: harmless commands such as `echo hi`, URLs on the reserved `.invalid` domain, and documentation addresses such as `192.0.2.1`.

You can expect an acknowledgement within a week. Fixes are released as a new version, with credit in the release notes unless you prefer otherwise.

## What counts as a vulnerability

aeppo reads files as text and never executes, imports or installs the code it scans. Issues in scope include:

- aeppo executing, importing or evaluating anything from a scanned repository;
- a crafted file that makes aeppo write outside its output, read files outside the scan target, or hang (for example catastrophic regex backtracking);
- the GitHub Action exposing secrets, or running with more permissions than documented;
- `aeppo check` running hooks, filters or other code from the cloned repository, following its symbolic links, fetching submodules or LFS objects, offering stored credentials, or leaving the clone behind;
- a repository's `.aeppo.toml` or suppression comments changing the result of `aeppo check`;
- `--osv` sending anything other than package ecosystems, names and versions, or making network requests without `--osv`;
- findings or reports that leak more of a detected secret than the matched line.

A missed detection (false negative) or a false positive is not a vulnerability; please open a normal issue for those, with an inert sample if possible.

## Secrets in findings

Findings include the matched file and line. Do not post findings that contain real secrets in public issues; treat any detected secret as exposed and rotate it with its provider.
