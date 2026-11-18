import unittest
import json
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stderr, redirect_stdout

from aeppo import __version__
from aeppo.cli import main


class CliTests(unittest.TestCase):
    def test_scan_command_emits_machine_readable_json(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            call = "os." + "system" + "(user_input)"
            (root / "bad.py").write_text("import os\n" + call + "\n")
            output = StringIO()

            with redirect_stdout(output):
                result = main(["scan", str(root), "--format", "json"])

        self.assertEqual(result, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload[0]["path"], "bad.py")
        self.assertEqual(payload[0]["rule_id"], "PY001")
        self.assertEqual(payload[0]["severity"], "medium")
        self.assertEqual(payload[0]["category"], "command-execution")

    def test_scan_command_accepts_exclude_and_max_file_size(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            call = "os." + "system" + "(user_input)"
            (root / "skip.py").write_text(call)
            (root / "keep.py").write_text(call)
            output = StringIO()

            with redirect_stdout(output):
                result = main(["scan", str(root), "--exclude", "skip.py", "--max-file-size", "100"])

        self.assertEqual(result, 1)
        self.assertIn("keep.py", output.getvalue())
        self.assertNotIn("skip.py", output.getvalue())

    def test_scan_command_reports_findings_and_returns_one(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            call = "os." + "system" + "(user_input)"
            (root / "bad.py").write_text("import os\n" + call + "\n")
            output = StringIO()

            with redirect_stdout(output):
                result = main(["scan", str(root)])

        self.assertEqual(result, 1)
        self.assertIn("bad.py:2: [PY001|medium]", output.getvalue())
        self.assertIn("confidence=medium", output.getvalue())
        self.assertIn("Recommendation:", output.getvalue())

    def test_scan_command_emits_sarif_with_rules_and_fingerprints(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.py").write_text("import os\n" + "os." + "system(user_input)\n")
            output = StringIO()

            with redirect_stdout(output):
                result = main(["scan", str(root), "--format", "sarif"])

        self.assertEqual(result, 1)
        sarif = json.loads(output.getvalue())
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
        self.assertIn("PY001", rule_ids)
        finding = run["results"][0]
        self.assertEqual(finding["ruleId"], "PY001")
        self.assertEqual(rule_ids[finding["ruleIndex"]], "PY001")
        self.assertEqual(finding["level"], "warning")
        location = finding["locations"][0]["physicalLocation"]
        self.assertTrue(location["artifactLocation"]["uri"].endswith("bad.py"))
        self.assertEqual(location["region"]["startLine"], 2)
        self.assertTrue(finding["partialFingerprints"]["aeppo/v1"])

    def test_scan_command_writes_report_to_output_file(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "src"
            root.mkdir()
            (root / "bad.py").write_text("ex" + "ec(code)\n")
            report = Path(directory) / "report.json"
            output = StringIO()

            with redirect_stdout(output), redirect_stderr(StringIO()) as notice:
                result = main(["scan", str(root), "--format", "json", "--output", str(report)])
            self.assertIn("wrote 1 finding(s)", notice.getvalue())

            payload = json.loads(report.read_text())

        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(payload[0]["rule_id"], "PY002")

    def test_min_severity_and_baseline_control_exit_code(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "src"
            root.mkdir()
            (root / "requirements.txt").write_text("demo-package\n")
            (root / "bad.py").write_text("ex" + "ec(code)\n")
            baseline = Path(directory) / "baseline.json"

            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                low_only = main(["scan", str(root), "--exclude", "*.py", "--min-severity", "medium"])
                main(["scan", str(root), "--format", "json", "--output", str(baseline)])
                with_baseline = main(["scan", str(root), "--baseline", str(baseline)])

        self.assertEqual(low_only, 0)
        self.assertEqual(with_baseline, 0)

    def test_invalid_baseline_returns_two(self):
        with TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            baseline.write_text("not json")

            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as errors:
                result = main(["scan", directory, "--baseline", str(baseline)])

        self.assertEqual(result, 2)
        self.assertIn("aeppo:", errors.getvalue())

    def test_version_flag(self):
        output = StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as exit_info:
            main(["--version"])

        self.assertEqual(exit_info.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), "aeppo " + __version__)

    def test_scan_command_returns_zero_for_clean_directory(self):
        with TemporaryDirectory() as directory:
            (Path(directory) / "safe.py").write_text("print('safe')\n")
            output = StringIO()

            with redirect_stdout(output):
                result = main(["scan", directory])

        self.assertEqual(result, 0)
        self.assertIn("No findings.", output.getvalue())


if __name__ == "__main__":
    unittest.main()
