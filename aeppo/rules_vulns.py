"""Known-vulnerable and malicious dependency versions from lockfiles (VULN001, MAL001), via OSV.dev."""
import fnmatch
import hashlib
import os
from pathlib import Path

from aeppo import lockfiles, osv
from aeppo.findings import make_finding


# Lockfiles of large projects are often several megabytes; they are parsed, not pattern-scanned.
MAX_LOCKFILE_SIZE = 64 * 1024 * 1024
_SKIPPED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules"}
_ID_PREFERENCE = ("GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "CVE-")


def lockfile_paths(target, excludes=()):
    """Return (path, display path, lockfile kind) for each lockfile under ``target``."""
    target = Path(target)
    if target.is_file():
        kind = lockfiles.kind(target)
        return [(target, str(target), kind)] if kind else []
    found = []
    for directory, subdirectories, files in os.walk(target):
        subdirectories[:] = sorted(name for name in subdirectories if not name.startswith(".") and name not in _SKIPPED_DIRECTORIES)
        for name in sorted(files):
            path = Path(directory, name)
            kind = lockfiles.kind(path)
            if not kind:
                continue
            relative = path.relative_to(target).as_posix()
            if any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
                continue
            found.append((path, relative, kind))
    return found


def collect(targets, excludes=(), errors=None):
    """Parse every lockfile; return a list of (display path, target, Package)."""
    entries = []
    for target in targets:
        for path, display, kind in lockfile_paths(target, excludes):
            try:
                if path.stat().st_size > MAX_LOCKFILE_SIZE:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                if errors is None:
                    raise
                errors.append("{}: {}".format(display, error.strerror or error))
                continue
            entries.extend((display, target, package) for package in lockfiles.parse(kind, text))
    return entries


def _groups(records):
    """Merge records that describe the same issue (GHSA, PYSEC and CVE aliases of each other)."""
    groups = []
    for record in records:
        names = {record["id"], *[alias for alias in record.get("aliases") or [] if isinstance(alias, str)]}
        merged = [group for group in groups if group[0] & names]
        for group in merged:
            groups.remove(group)
            names |= group[0]
        groups.append((names, [record] + [item for group in merged for item in group[1]]))
    return groups


def _primary(ids):
    for prefix in ("MAL-",) + _ID_PREFERENCE:
        matching = sorted(value for value in ids if value.startswith(prefix))
        if matching:
            return matching[0]
    return sorted(ids)[0]


def _fingerprint(rule_id, package, advisory):
    text = "\0".join((rule_id, package.ecosystem, package.name, package.version, advisory))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def findings_for(entries, results):
    """Turn OSV results into findings, one per advisory group per lockfile entry."""
    findings = []
    for display, target, package in entries:
        records = [record for record in results.get((package.ecosystem, package.name, package.version), []) if not record.get("withdrawn")]
        for ids, group in _groups(records):
            advisory = _primary(ids)
            link = "https://osv.dev/vulnerability/" + advisory
            summary = next((record.get("summary") for record in group if record.get("summary")), "")
            label = "{} {} ({})".format(package.name, package.version, package.ecosystem)
            if any(record["id"].startswith("MAL-") for record in group):
                finding = make_finding(display, package.line, "MAL001", "{} is listed as a malicious package [{}]{}".format(label, advisory, ": " + summary if summary else "."))
                finding.recommendation = "Do not install it. Remove it from the lockfile; if it was installed, treat that machine and its credentials as compromised. " + link
            else:
                aliases = sorted(value for value in ids if value.startswith("CVE-"))[:2]
                reference = ", ".join([advisory] + [alias for alias in aliases if alias != advisory])
                fixed = sorted({value for record in group for value in osv.fixed_versions(record, package.ecosystem, package.name, package.version)}, key=osv.version_key)
                labels = [osv.severity_label(record) for record in group]
                labels = [value for value in labels if value]
                severity = max(labels, key=osv._RANK.get) if labels else None
                note = next((osv.informational(record) for record in group if osv.informational(record)), None)
                if note:
                    message = "{} has an informational advisory ({}) [{}]".format(label, note, reference)
                else:
                    message = "{} has a known {}vulnerability [{}]".format(label, severity + " " if severity else "", reference)
                message += ": " + summary if summary else "."
                if fixed:
                    message += "" if message.endswith(".") else "."
                    message += " Fixed in {}.".format(fixed[0])
                finding = make_finding(display, package.line, "VULN001", message)
                finding.severity = "low" if note else {"critical": "high", None: "medium"}.get(severity, severity)
                if fixed:
                    finding.recommendation = "Upgrade {} to {} or later and regenerate the lockfile. {}".format(package.name, fixed[0], link)
                else:
                    finding.recommendation = "No fixed version is listed; check the advisory for mitigations or replace the package. " + link
            finding.fingerprint = _fingerprint(finding.rule_id, package, advisory)
            findings.append((finding, target))
    return findings


def scan(targets, client, excludes=(), errors=None):
    """Query OSV once for every lockfile package; return (findings with targets, package count, lockfile count)."""
    entries = collect(targets, excludes, errors)
    packages = {(package.ecosystem, package.name, package.version) for _display, _target, package in entries}
    if not packages:
        return [], 0, 0
    results = client.query(packages)
    lockfile_count = len({(id(target), display) for display, target, _package in entries})
    return findings_for(entries, results), len(packages), lockfile_count
