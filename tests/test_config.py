import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.cli import main
from aeppo.config import find_config, load_config, parse_minimal_toml


SYSTEM_CALL = "os." + "system(command)\n"


def run(argv):
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class MinimalTomlTests(unittest.TestCase):
    SAMPLE = (
        "# aeppo settings\n"
        'exclude = ["tests/**", \'docs/*.md\']  # trailing comment\n'
        "disable = [\n"
        '  "GHA003",\n'
        '  "SH005",  # installers\n'
        "]\n"
        'min-severity = "medium"\n'
        "max-file-size = 2_000_000\n"
        'baseline = "base\\\\line.json"\n'
    )

    def test_parses_the_supported_subset(self):
        self.assertEqual(
            parse_minimal_toml(self.SAMPLE),
            {
                "exclude": ["tests/**", "docs/*.md"],
                "disable": ["GHA003", "SH005"],
                "min-severity": "medium",
                "max-file-size": 2000000,
                "baseline": "base\\line.json",
            },
        )

    def test_matches_tomllib_when_available(self):
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        self.assertEqual(parse_minimal_toml(self.SAMPLE), tomllib.loads(self.SAMPLE))

    def test_rejects_unsupported_syntax(self):
        for text in ("[tool.aeppo]\nexclude = []\n", "exclude = [\"a\"\n", 'min-severity = "high" extra\n', "x = 1\nx = 2\n", 'a = "open\n'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_minimal_toml(text)


class LoadConfigTests(unittest.TestCase):
    def write(self, directory, text):
        path = Path(directory) / ".aeppo.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_valid_config_is_normalised(self):
        with TemporaryDirectory() as directory:
            path = self.write(directory, 'disable = ["gha003"]\nmin-severity = "high"\nbaseline = "b.json"\n')
            config = load_config(path)
        self.assertEqual(config["disable"], ["GHA003"])
        self.assertEqual(config["min_severity"], "high")
        self.assertEqual(config["baseline"].name, "b.json")
        self.assertTrue(config["baseline"].is_absolute())

    def test_typos_are_errors(self):
        cases = ['exlude = ["x"]\n', 'disable = ["PY999"]\n', 'min-severity = "critical"\n', "max-file-size = 0\n", 'exclude = "not-a-list"\n']
        for text in cases:
            with self.subTest(text=text), TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    load_config(self.write(directory, text))

    def test_find_config_walks_up_and_stops_at_repository_root(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "repo" / ".git").mkdir(parents=True)
            (root / "repo" / "src" / "pkg").mkdir(parents=True)
            self.write(root / "repo", "exclude = []\n")
            self.write(root, "exclude = []\n")  # outside the repository: must not be used

            self.assertEqual(find_config(root / "repo" / "src" / "pkg"), (root / "repo" / ".aeppo.toml").resolve())
            (root / "repo" / ".aeppo.toml").unlink()
            self.assertIsNone(find_config(root / "repo" / "src"))


class CliConfigTests(unittest.TestCase):
    def make_repo(self, directory, config):
        root = Path(directory)
        (root / ".git").mkdir()
        (root / "fixtures").mkdir()
        (root / "app.py").write_text("import os\n" + SYSTEM_CALL)
        (root / "fixtures" / "sample.py").write_text("import os\n" + SYSTEM_CALL)
        (root / "requirements.txt").write_text("demo-package\n")
        if config is not None:
            (root / ".aeppo.toml").write_text(config)
        return root

    def test_config_excludes_disables_and_filters(self):
        with TemporaryDirectory() as directory:
            root = self.make_repo(directory, 'exclude = ["fixtures/**"]\nmin-severity = "medium"\n')
            code, out, _err = run(["scan", str(root), "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual([(f["path"], f["rule_id"]) for f in json.loads(out)], [("app.py", "PY001")])

    def test_command_line_overrides_and_extends_config(self):
        with TemporaryDirectory() as directory:
            root = self.make_repo(directory, 'min-severity = "high"\n')
            code, out, _err = run(["scan", str(root), "--format", "json", "--min-severity", "low", "--disable", "PY001"])
        self.assertEqual(code, 1)
        self.assertEqual([f["rule_id"] for f in json.loads(out)], ["DEP001"])

    def test_disabling_every_reported_rule_returns_zero(self):
        with TemporaryDirectory() as directory:
            root = self.make_repo(directory, 'disable = ["PY001", "DEP001"]\n')
            code, out, _err = run(["scan", str(root)])
        self.assertEqual((code, out.strip()), (0, "No findings."))

    def test_no_config_and_explicit_config(self):
        with TemporaryDirectory() as directory:
            root = self.make_repo(directory, 'disable = ["PY001", "DEP001"]\n')
            other = Path(directory) / "other.toml"
            other.write_text('disable = ["DEP001"]\n')
            ignored, _out, _err = run(["scan", str(root), "--no-config"])
            code, out, _err = run(["scan", str(root), "--config", str(other), "--format", "json"])
        self.assertEqual(ignored, 1)
        self.assertEqual(sorted({f["rule_id"] for f in json.loads(out)}), ["PY001"])

    def test_invalid_config_returns_two(self):
        with TemporaryDirectory() as directory:
            root = self.make_repo(directory, 'disable = ["NOPE1"]\n')
            code, _out, err = run(["scan", str(root)])
        self.assertEqual(code, 2)
        self.assertIn("NOPE1", err)

    def test_unknown_disable_flag_returns_two(self):
        with TemporaryDirectory() as directory:
            root = self.make_repo(directory, None)
            code, _out, err = run(["scan", str(root), "--disable", "NOPE1"])
        self.assertEqual(code, 2)
        self.assertIn("NOPE1", err)


class PreCommitStyleTests(unittest.TestCase):
    def test_multiple_file_targets_with_skip_unsupported(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("import os\n" + SYSTEM_CALL)
            (root / "b.js").write_text("require('child_process').ex" + "ec(cmd)\n")
            (root / "logo.svg").write_text("<svg/>\n")
            (root / "notes.txt").write_text("plain text\n")
            files = [str(root / name) for name in ("a.py", "b.js", "logo.svg", "notes.txt")]

            code, out, _err = run(["scan", "--skip-unsupported", "--format", "json", "--no-config", *files])
            strict, _out, err = run(["scan", "--no-config", *files])

        self.assertEqual(code, 1)
        self.assertEqual(sorted(f["rule_id"] for f in json.loads(out)), ["JS002", "PY001"])
        self.assertEqual(strict, 2)
        self.assertIn("Unsupported file type", err)

    def test_config_excludes_apply_to_file_targets(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "corpus").mkdir()
            sample = root / "corpus" / "sample.py"
            sample.write_text("import os\n" + SYSTEM_CALL)
            config = root / "cfg.toml"
            config.write_text('exclude = ["*/corpus/*"]\n')

            code, out, _err = run(["scan", "--config", str(config), str(sample)])
        self.assertEqual((code, out.strip()), (0, "No findings."))

    def test_sarif_locations_for_several_directory_targets(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("one", "two"):
                (root / name).mkdir()
                (root / name / "app.py").write_text("import os\n" + SYSTEM_CALL)

            code, out, _err = run(["scan", "--no-config", "--format", "sarif", str(root / "one"), str(root / "two")])

        uris = sorted(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in json.loads(out)["runs"][0]["results"])
        self.assertEqual(code, 1)
        self.assertEqual(len(uris), 2)
        self.assertTrue(uris[0].endswith("one/app.py") and uris[1].endswith("two/app.py"))

    def test_hook_definition_points_at_the_cli(self):
        hooks = (Path(__file__).resolve().parents[1] / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        self.assertIn("- id: aeppo", hooks)
        self.assertIn("entry: aeppo scan --skip-unsupported", hooks)
        self.assertIn("language: python", hooks)


if __name__ == "__main__":
    unittest.main()
