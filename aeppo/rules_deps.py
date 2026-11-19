"""Dependency manifest rules for requirements.txt and package.json (DEP001-DEP004)."""
import json
import re

from aeppo.findings import make_finding as _finding


_REMOTE_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|node|python3?|perl|ruby)\b"
    r"|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
)


def scan_requirements(path, lines):
    findings = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("http://", "https://", "git+")) or " @ " in line:
            findings.append(_finding(path, line_number, "DEP002", "Dependency uses a direct URL or VCS reference."))
        elif re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?$", line):
            findings.append(_finding(path, line_number, "DEP001"))
    return findings


def scan_package_json(path, raw):
    try:
        package = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(package, dict):
        return []
    raw_lines = raw.splitlines()
    findings = []
    scripts = package.get("scripts", {})
    if isinstance(scripts, dict):
        # ``prepare`` also runs when the package is installed from a git URL.
        for name in ("preinstall", "install", "postinstall", "prepare"):
            if name not in scripts:
                continue
            line = next((index for index, text in enumerate(raw_lines, start=1) if '"' + name + '"' in text), 1)
            if name != "prepare":
                findings.append(_finding(path, line, "DEP003", "Package defines an {} lifecycle script that runs during installation.".format(name)))
            command = scripts[name]
            if isinstance(command, str) and _REMOTE_PIPE.search(command):
                findings.append(_finding(path, line, "DEP004", "The {} script downloads remote content and pipes it into an interpreter.".format(name)))
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = package.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            if isinstance(version, str) and version.startswith(("git+", "http://", "https://", "file:")):
                key, value = json.dumps(name), json.dumps(version)
                line = next((index for index, text in enumerate(raw_lines, start=1) if key in text and value in text), 1)
                findings.append(_finding(path, line, "DEP002", "Dependency {} uses a direct URL, VCS, or local path reference.".format(name)))
    return findings
