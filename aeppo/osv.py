"""Minimal OSV.dev client (https://google.github.io/osv.dev/api/), standard library only.

Only package names, versions and ecosystems are sent. ``querybatch`` returns advisory IDs with
their last-modified time; full records are fetched once and cached on disk until OSV reports a
newer ``modified`` time, so repeated scans cost one batch request per 1000 packages.
"""
import json
import math
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aeppo import __version__


API = "https://api.osv.dev/v1"
_BATCH_SIZE = 1000
_MAX_PAGES = 20
_TIMEOUT = 30
_ATTEMPTS = 3
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class OSVError(Exception):
    pass


def default_cache_dir():
    if os.environ.get("AEPPO_CACHE_DIR"):
        return Path(os.environ["AEPPO_CACHE_DIR"])
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "aeppo" / "osv"


def _http_fetch(method, url, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "aeppo/{} (+https://github.com/emanuellzoe/aeppo)".format(__version__),
    })
    for attempt in range(_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            # Retry rate limiting and server errors; anything else is a real answer.
            if error.code not in (429, 500, 502, 503, 504) or attempt == _ATTEMPTS - 1:
                raise OSVError("{} {} returned HTTP {}".format(method, url, error.code))
        except (urllib.error.URLError, OSError) as error:
            if attempt == _ATTEMPTS - 1:
                raise OSVError("{} {} failed: {}".format(method, url, getattr(error, "reason", error)))
        except ValueError as error:
            raise OSVError("{} {} returned invalid JSON: {}".format(method, url, error))
        time.sleep(2 ** attempt)
    raise OSVError("{} {} failed".format(method, url))


class Client:
    """Query OSV. ``fetch(method, url, body)`` is injectable so tests never touch the network."""

    def __init__(self, fetch=None, cache_dir=None, workers=8):
        self.fetch = fetch or _http_fetch
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.workers = workers

    def query(self, packages):
        """Map each (ecosystem, name, version) to the list of full OSV records that affect it."""
        keys = sorted(set(packages))
        ids = {key: {} for key in keys}
        for start in range(0, len(keys), _BATCH_SIZE):
            chunk = keys[start:start + _BATCH_SIZE]
            pending = [(key, None) for key in chunk]
            for _page in range(_MAX_PAGES):
                if not pending:
                    break
                queries = []
                for (ecosystem, name, version), token in pending:
                    query = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
                    if token:
                        query["page_token"] = token
                    queries.append(query)
                response = self.fetch("POST", API + "/querybatch", {"queries": queries})
                results = response.get("results") if isinstance(response, dict) else None
                if not isinstance(results, list) or len(results) != len(pending):
                    raise OSVError("unexpected querybatch response")
                next_pending = []
                for (key, _token), result in zip(pending, results):
                    result = result if isinstance(result, dict) else {}
                    for vuln in result.get("vulns") or []:
                        if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                            ids[key][vuln["id"]] = vuln.get("modified")
                    if result.get("next_page_token"):
                        next_pending.append((key, result["next_page_token"]))
                pending = next_pending
        wanted = {}
        for found in ids.values():
            wanted.update(found)
        records = self._records(wanted)
        return {key: [records[vuln_id] for vuln_id in sorted(found) if vuln_id in records] for key, found in ids.items()}

    def _records(self, wanted):
        records = {}
        missing = []
        for vuln_id, modified in wanted.items():
            if not _SAFE_ID.match(vuln_id):
                continue
            cached = self._cached(vuln_id, modified)
            if cached is not None:
                records[vuln_id] = cached
            else:
                missing.append(vuln_id)
        if missing:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                for vuln_id, record in zip(missing, pool.map(self._fetch_record, missing)):
                    records[vuln_id] = record
                    self._store(vuln_id, record)
        return records

    def _fetch_record(self, vuln_id):
        record = self.fetch("GET", API + "/vulns/" + vuln_id, None)
        if not isinstance(record, dict) or record.get("id") != vuln_id:
            raise OSVError("unexpected record for {}".format(vuln_id))
        return record

    def _cache_path(self, vuln_id):
        return self.cache_dir / (vuln_id.replace(":", "_") + ".json")

    def _cached(self, vuln_id, modified):
        if not self.cache_dir or not modified:
            return None
        try:
            record = json.loads(self._cache_path(vuln_id).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return record if isinstance(record, dict) and record.get("modified") == modified else None

    def _store(self, vuln_id, record):
        if not self.cache_dir:
            return
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=str(self.cache_dir), suffix=".tmp")
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(record, stream)
            os.replace(temporary, str(self._cache_path(vuln_id)))
        except OSError:
            pass  # The cache is an optimisation; a read-only home directory must not fail the scan.


# CVSS v3.x base score (https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations).
_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value):
    integer = int(round(value * 100000))
    return integer / 100000.0 if integer % 10000 == 0 else (math.floor(integer / 10000) + 1) / 10.0


def cvss3_score(vector):
    """Return the CVSS v3 base score of ``vector``, or ``None`` if it is not a valid v3 vector."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3."):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope_changed = metrics["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        values = {name: table[metrics[name]] for name, table in _CVSS3.items()}
    except KeyError:
        return None
    impact_base = 1 - (1 - values["C"]) * (1 - values["I"]) * (1 - values["A"])
    if scope_changed:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
    else:
        impact = 6.42 * impact_base
    exploitability = 8.22 * values["AV"] * values["AC"] * privileges * values["UI"]
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    return _roundup(min(1.08 * total if scope_changed else total, 10))


_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_label(record):
    """Return critical/high/medium/low for an OSV record, or ``None`` when it gives no severity."""
    labels = []
    sources = [record.get("database_specific")]
    for affected in record.get("affected") or []:
        if isinstance(affected, dict):
            sources.extend([affected.get("database_specific"), affected.get("ecosystem_specific")])
    for source in sources:
        if isinstance(source, dict) and isinstance(source.get("severity"), str):
            label = _LABELS.get(source["severity"].upper())
            if label:
                labels.append(label)
    for entry in record.get("severity") or []:
        score = cvss3_score(entry.get("score")) if isinstance(entry, dict) else None
        if score is not None:
            labels.append("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else None)
    labels = [label for label in labels if label]
    return max(labels, key=_RANK.get) if labels else None


def informational(record):
    """RustSec marks advisories such as ``unmaintained`` or ``unsound`` as informational."""
    for affected in record.get("affected") or []:
        details = affected.get("database_specific") if isinstance(affected, dict) else None
        if isinstance(details, dict) and isinstance(details.get("informational"), str):
            return details["informational"]
    return None


def version_key(version):
    """Loose ordering key that works across ecosystems: numbers compare numerically, and a
    pre-release suffix (1.0.0rc1, 1.0.0-beta) sorts before the release."""
    parts = []
    for token in re.findall(r"\d+|[A-Za-z]+", version):
        parts.append((2, int(token), "") if token.isdigit() else (0, 0, token.lower()))
    parts.append((1, 0, ""))
    return parts


def _same_package(affected, ecosystem, name):
    package = affected.get("package") if isinstance(affected, dict) else None
    if not isinstance(package, dict):
        return False
    other = package.get("name", "")
    if ecosystem == "PyPI":
        other = re.sub(r"[-_.]+", "-", other).lower()
    return package.get("ecosystem", "").split(":", 1)[0] == ecosystem and other == name


def fixed_versions(record, ecosystem, name, version):
    """Return fixed versions newer than ``version`` for this package, smallest first."""
    fixed = set()
    for affected in record.get("affected") or []:
        if not _same_package(affected, ecosystem, name):
            continue
        for range_ in affected.get("ranges") or []:
            # GIT ranges hold commit hashes, which are not versions a lockfile can name.
            if not isinstance(range_, dict) or range_.get("type") == "GIT":
                continue
            for event in range_.get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    current = version_key(version)
    newer = [value for value in fixed if version_key(value) > current]
    return sorted(newer, key=version_key)
