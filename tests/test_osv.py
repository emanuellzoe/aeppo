"""Lockfile parsing and OSV.dev lookups (VULN001, MAL001). No test touches the network."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aeppo import lockfiles, osv, rules_vulns
from aeppo.cli import main


def parsed(kind, text):
    return [(package.ecosystem, package.name, package.version, package.line) for package in lockfiles.parse(kind, text)]


class LockfileParserTests(unittest.TestCase):
    def test_package_lock_v3(self):
        text = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
                "node_modules/a/node_modules/@scope/b": {"version": "2.0.0"},
                "node_modules/alias": {"name": "real-name", "version": "1.2.3"},
                "node_modules/local": {"link": True},
                "packages/local": {"version": "0.1.0"},
                "node_modules/from-git": {"version": "1.0.0", "resolved": "git+ssh://git@example.invalid/x.git#abc"},
            },
        }, indent=2)
        self.assertEqual(
            [(name, version) for _ecosystem, name, version, _line in parsed("package-lock.json", text)],
            [("lodash", "4.17.15"), ("@scope/b", "2.0.0"), ("real-name", "1.2.3")],
        )
        self.assertEqual(parsed("package-lock.json", text)[0][3], text.splitlines().index('    "node_modules/lodash": {') + 1)

    def test_package_lock_v1(self):
        text = json.dumps({"lockfileVersion": 1, "dependencies": {"minimist": {"version": "0.0.8", "dependencies": {"x": {"version": "1.0.0"}}}, "aliased": {"version": "npm:real@2.0.0"}}}, indent=2)
        self.assertEqual([(name, version) for _e, name, version, _l in parsed("package-lock.json", text)], [("minimist", "0.0.8"), ("x", "1.0.0"), ("real", "2.0.0")])

    def test_yarn_classic_and_berry(self):
        classic = '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.2"\n  resolved "https://registry.yarnpkg.com/x"\n\nlodash@^4.17.0:\n  version "4.17.15"\n'
        self.assertEqual(parsed("yarn.lock", classic), [("npm", "@babel/core", "7.1.2", 3), ("npm", "lodash", "4.17.15", 7)])
        berry = '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.15\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n\n"alias@npm:real@^1.0.0":\n  version: 1.0.1\n'
        self.assertEqual(parsed("yarn.lock", berry), [("npm", "lodash", "4.17.15", 4), ("npm", "real", "1.0.1", 10)])

    def test_pnpm_versions(self):
        v5 = "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.15:\n    resolution: {integrity: x}\n  /@scope/pkg/1.0.0_react@18.0.0:\n    dev: false\n"
        self.assertEqual(parsed("pnpm-lock.yaml", v5), [("npm", "lodash", "4.17.15", 5), ("npm", "@scope/pkg", "1.0.0", 7)])
        v9 = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        version: 4.17.15\n\npackages:\n\n  lodash@4.17.15:\n    resolution: {integrity: x}\n\n  '@scope/pkg@1.0.0(react@18.0.0)':\n    resolution: {integrity: y}\n\nsnapshots:\n\n  lodash@4.17.15: {}\n"
        self.assertEqual(parsed("pnpm-lock.yaml", v9), [("npm", "lodash", "4.17.15", 11), ("npm", "@scope/pkg", "1.0.0", 14)])

    def test_requirements_only_exact_pins(self):
        text = "Django==3.2.0\nrequests>=2.0\nPyYAML[extra] == 5.3 ; python_version > '3'\nflask\n# pinned==1.0\nzope.interface===5.0.0 \\\n    --hash=sha256:abc\nwild==1.*\n"
        self.assertEqual(parsed("requirements.txt", text), [("PyPI", "django", "3.2.0", 1), ("PyPI", "pyyaml", "5.3", 3), ("PyPI", "zope-interface", "5.0.0", 6)])
        self.assertEqual(lockfiles.kind(Path("requirements-dev.txt")), "requirements.txt")
        self.assertEqual(lockfiles.kind(Path("requirements/base.txt")), "requirements.txt")
        self.assertIsNone(lockfiles.kind(Path("notes.txt")))

    def test_poetry_and_uv(self):
        poetry = '[[package]]\nname = "Jinja2"\nversion = "2.10"\n\n[package.dependencies]\nname = "ignored"\n\n[[package]]\nname = "local-lib"\nversion = "0.1.0"\n\n[package.source]\ntype = "directory"\nurl = "../lib"\n\n[metadata]\nlock-version = "2.0"\n'
        self.assertEqual(parsed("poetry.lock", poetry), [("PyPI", "jinja2", "2.10", 1)])
        uv = '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "urllib3"\nversion = "1.26.4"\nsource = { registry = "https://pypi.org/simple" }\n'
        self.assertEqual(parsed("uv.lock", uv), [("PyPI", "urllib3", "1.26.4", 6)])

    def test_cargo_go_composer_gemfile(self):
        cargo = '[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "forked"\nversion = "1.0.0"\nsource = "git+https://example.invalid/forked#abc"\n'
        self.assertEqual(parsed("Cargo.lock", cargo), [("crates.io", "time", "0.1.43", 5)])
        go = "module example.invalid/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n\tgithub.com/c/d v0.0.0-20200101000000-abcdefabcdef\n\tgithub.com/e/f v1.0.0\n)\n\nreplace github.com/e/f => ../f\nreplace github.com/a/b v1.2.3 => github.com/a/b v1.2.4\n"
        self.assertEqual(parsed("go.mod", go), [("Go", "golang.org/x/text", "0.3.0", 5), ("Go", "github.com/a/b", "1.2.4", 8), ("Go", "github.com/c/d", "0.0.0-20200101000000-abcdefabcdef", 9)])
        composer = json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": "v7.4.0"}, {"name": "acme/dev", "version": "dev-main"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}, indent=4)
        self.assertEqual([(n, v) for _e, n, v, _l in parsed("composer.lock", composer)], [("guzzlehttp/guzzle", "7.4.0"), ("phpunit/phpunit", "9.5.0")])
        gemfile = "GIT\n  remote: https://example.invalid/x.git\n  specs:\n    forked (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.3-x86_64-linux)\n      racc (~> 1.4)\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n"
        self.assertEqual(parsed("Gemfile.lock", gemfile), [("RubyGems", "nokogiri", "1.13.3", 9), ("RubyGems", "rack", "2.2.3", 11)])

    def test_malformed_lockfiles_yield_nothing(self):
        for kind in ("package-lock.json", "composer.lock", "yarn.lock", "Cargo.lock", "go.mod"):
            self.assertEqual(lockfiles.parse(kind, "{not valid"), [])


class SeverityTests(unittest.TestCase):
    def test_cvss3_scores(self):
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(osv.cvss3_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"), 0.0)
        self.assertIsNone(osv.cvss3_score("CVSS:4.0/AV:N/AC:L"))
        self.assertIsNone(osv.cvss3_score("CVSS:3.1/AV:N"))

    def test_severity_label_prefers_highest_source(self):
        self.assertEqual(osv.severity_label({"database_specific": {"severity": "MODERATE"}}), "medium")
        self.assertEqual(osv.severity_label({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}), "critical")
        self.assertIsNone(osv.severity_label({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}))

    def test_version_ordering(self):
        self.assertLess(osv.version_key("1.0.0rc1"), osv.version_key("1.0.0"))
        self.assertLess(osv.version_key("1.9.0"), osv.version_key("1.10.0"))
        record = {"affected": [{"package": {"ecosystem": "PyPI", "name": "Django"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.24"}, {"introduced": "3.0"}, {"fixed": "3.1.12"}, {"introduced": "3.2"}, {"fixed": "3.2.4"}]},
            {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abcdef"}]},
        ]}]}
        self.assertEqual(osv.fixed_versions(record, "PyPI", "django", "3.2.0"), ["3.2.4"])


def record(vuln_id, package, ecosystem="npm", **extra):
    base = {"id": vuln_id, "modified": "2026-01-01T00:00:00Z", "summary": "Example issue in " + package,
            "affected": [{"package": {"ecosystem": ecosystem, "name": package}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}
    base.update(extra)
    return base


class FakeOSV:
    def __init__(self, vulns, records):
        self.vulns = vulns  # (ecosystem, name, version) -> list of ids
        self.records = records
        self.calls = []

    def __call__(self, method, url, body):
        self.calls.append((method, url))
        if method == "POST":
            results = []
            for query in body["queries"]:
                key = (query["package"]["ecosystem"], query["package"]["name"], query["version"])
                results.append({"vulns": [{"id": vuln_id, "modified": self.records[vuln_id]["modified"]} for vuln_id in self.vulns.get(key, [])]})
            return {"results": results}
        return self.records[url.rsplit("/", 1)[1]]


class ClientTests(unittest.TestCase):
    def test_query_and_cache(self):
        fake = FakeOSV({("npm", "lodash", "4.17.15"): ["GHSA-aaaa-bbbb-cccc"]}, {"GHSA-aaaa-bbbb-cccc": record("GHSA-aaaa-bbbb-cccc", "lodash")})
        with tempfile.TemporaryDirectory() as cache:
            client = osv.Client(fetch=fake, cache_dir=cache)
            result = client.query([("npm", "lodash", "4.17.15"), ("npm", "left-pad", "1.3.0")])
            self.assertEqual([item["id"] for item in result[("npm", "lodash", "4.17.15")]], ["GHSA-aaaa-bbbb-cccc"])
            self.assertEqual(result[("npm", "left-pad", "1.3.0")], [])
            self.assertEqual([method for method, _url in fake.calls], ["POST", "GET"])
            fake.calls.clear()
            client.query([("npm", "lodash", "4.17.15")])
            self.assertEqual([method for method, _url in fake.calls], ["POST"])
            # A newer modified time invalidates the cached record.
            fake.records["GHSA-aaaa-bbbb-cccc"]["modified"] = "2026-02-01T00:00:00Z"
            fake.calls.clear()
            client.query([("npm", "lodash", "4.17.15")])
            self.assertEqual([method for method, _url in fake.calls], ["POST", "GET"])

    def test_pagination(self):
        pages = []

        def fetch(method, url, body):
            if method == "GET":
                return record(url.rsplit("/", 1)[1], "big")
            query = body["queries"][0]
            pages.append(query.get("page_token"))
            if "page_token" not in query:
                return {"results": [{"vulns": [{"id": "GHSA-1111-1111-1111", "modified": "x"}], "next_page_token": "next"}]}
            return {"results": [{"vulns": [{"id": "GHSA-2222-2222-2222", "modified": "x"}]}]}

        result = osv.Client(fetch=fetch).query([("npm", "big", "1.0.0")])
        self.assertEqual(pages, [None, "next"])
        self.assertEqual(len(result[("npm", "big", "1.0.0")]), 2)

    def test_unexpected_response_is_an_error(self):
        with self.assertRaises(osv.OSVError):
            osv.Client(fetch=lambda method, url, body: {"results": []}).query([("npm", "x", "1.0.0")])


class FindingTests(unittest.TestCase):
    def findings(self, records):
        package = lockfiles.Package("PyPI", "django", "3.2.0", 4)
        return [finding for finding, _target in rules_vulns.findings_for([("requirements.txt", ".", package)], {("PyPI", "django", "3.2.0"): records})]

    def test_aliases_are_merged_and_highest_severity_wins(self):
        ghsa = record("GHSA-xxxx-yyyy-zzzz", "Django", "PyPI", aliases=["CVE-2021-0001", "PYSEC-2021-1"], database_specific={"severity": "HIGH"})
        pysec = record("PYSEC-2021-1", "django", "PyPI", aliases=["CVE-2021-0001", "GHSA-xxxx-yyyy-zzzz"], summary="")
        (finding,) = self.findings([ghsa, pysec])
        self.assertEqual((finding.rule_id, finding.severity, finding.line), ("VULN001", "high", 4))
        self.assertIn("[GHSA-xxxx-yyyy-zzzz, CVE-2021-0001]", finding.message)
        self.assertIn("Fixed in 9.9.9.", finding.message)
        self.assertIn("https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz", finding.recommendation)
        self.assertEqual(len(finding.fingerprint), 16)

    def test_malware_withdrawn_unknown_severity_and_informational(self):
        malware = record("MAL-2026-0001", "django", "PyPI", aliases=["GHSA-mmmm-mmmm-mmmm"])
        (finding,) = self.findings([malware, record("GHSA-mmmm-mmmm-mmmm", "django", "PyPI")])
        self.assertEqual((finding.rule_id, finding.severity), ("MAL001", "high"))
        self.assertEqual(self.findings([record("GHSA-wwww-wwww-wwww", "django", "PyPI", withdrawn="2026-01-02")]), [])
        (unknown,) = self.findings([record("PYSEC-2026-9", "django", "PyPI")])
        self.assertEqual(unknown.severity, "medium")
        unmaintained = record("RUSTSEC-2026-0001", "django", "PyPI")
        unmaintained["affected"][0]["database_specific"] = {"informational": "unmaintained"}
        (info,) = self.findings([unmaintained])
        self.assertEqual(info.severity, "low")
        self.assertIn("informational advisory (unmaintained)", info.message)


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "app").mkdir()
        (self.root / "app" / "Cargo.lock").write_text('[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        (self.root / "app" / "node_modules").mkdir()
        (self.root / "app" / "node_modules" / "yarn.lock").write_text('x@^1:\n  version "1.0.0"\n')
        self.fake = FakeOSV({("crates.io", "time", "0.1.43"): ["RUSTSEC-2020-0071"]}, {"RUSTSEC-2020-0071": record("RUSTSEC-2020-0071", "time", "crates.io", severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}])})
        environment = mock.patch.dict(os.environ, {"AEPPO_CACHE_DIR": str(self.root / "cache")})
        environment.start()
        self.addCleanup(environment.stop)
        self.addCleanup(self.directory.cleanup)

    def test_no_network_without_flag(self):
        with mock.patch("aeppo.osv._http_fetch", side_effect=AssertionError("network used")):
            code, stdout, _stderr = self.run_cli("scan", str(self.root / "app"), "--no-config")
        self.assertEqual((code, stdout.strip()), (0, "No findings."))

    def test_osv_findings_in_json(self):
        with mock.patch("aeppo.osv._http_fetch", self.fake):
            code, stdout, stderr = self.run_cli("scan", str(self.root / "app"), "--no-config", "--osv", "--format", "json")
        self.assertEqual(code, 1)
        (finding,) = json.loads(stdout)
        self.assertEqual((finding["path"], finding["line"], finding["rule_id"], finding["severity"]), ("Cargo.lock", 1, "VULN001", "medium"))
        self.assertIn("checked 1 package version(s) from 1 lockfile(s)", stderr)
        # The lockfile inside node_modules was not read.
        self.assertEqual([url for method, url in self.fake.calls if method == "POST"], [osv.API + "/querybatch"])

    def test_lockfile_as_file_target_baseline_and_disable(self):
        lockfile = str(self.root / "app" / "Cargo.lock")
        with mock.patch("aeppo.osv._http_fetch", self.fake):
            code, stdout, _stderr = self.run_cli("scan", lockfile, "--no-config", "--osv", "--format", "json")
            self.assertEqual(code, 1)
            baseline = self.root / "baseline.json"
            baseline.write_text(stdout)
            self.assertEqual(self.run_cli("scan", lockfile, "--no-config", "--osv", "--baseline", str(baseline))[0], 0)
            self.assertEqual(self.run_cli("scan", lockfile, "--no-config", "--osv", "--disable", "VULN001")[0], 0)

    def test_osv_failure_exits_2_and_still_reports(self):
        with mock.patch("aeppo.osv._http_fetch", side_effect=osv.OSVError("offline")):
            code, stdout, stderr = self.run_cli("scan", str(self.root / "app"), "--no-config", "--osv")
        self.assertEqual(code, 2)
        self.assertIn("No findings.", stdout)
        self.assertIn("could not check dependencies with OSV.dev: offline", stderr)

    def test_config_enables_osv(self):
        (self.root / "app" / ".aeppo.toml").write_text("osv = true\n")
        with mock.patch("aeppo.osv._http_fetch", self.fake):
            code, _stdout, _stderr = self.run_cli("scan", str(self.root / "app"))
        self.assertEqual(code, 1)
        (self.root / "app" / ".aeppo.toml").write_text('osv = "yes"\n')
        self.assertEqual(self.run_cli("scan", str(self.root / "app"))[0], 2)


if __name__ == "__main__":
    unittest.main()
