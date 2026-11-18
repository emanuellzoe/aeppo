import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTION_ENTRY = PROJECT_ROOT / "scripts" / "action_entry.py"


class ActionEntryTests(unittest.TestCase):
    def run_action(self, scan_path, **overrides):
        environment = os.environ.copy()
        environment.update(
            {
                "AEPPO_ACTION_PATH": str(PROJECT_ROOT),
                "AEPPO_SCAN_PATH": str(scan_path),
                "AEPPO_FORMAT": "json",
                "AEPPO_EXCLUDES": "",
                "AEPPO_MAX_FILE_SIZE": "1048576",
                "AEPPO_FAIL_ON_FINDINGS": "true",
            }
        )
        environment.update(overrides)
        return subprocess.run(
            [sys.executable, str(ACTION_ENTRY)],
            cwd=PROJECT_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_fails_with_json_findings_by_default(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "unsafe.py"
            call = "os." + "system(user_input)"
            source.write_text(call + "\n")

            result = self.run_action(directory)

        self.assertEqual(result.returncode, 1, result.stderr)
        findings = json.loads(result.stdout)
        self.assertEqual(findings[0]["rule_id"], "PY001")

    def test_can_exclude_findings_without_hiding_the_output(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "unsafe.py"
            call = "os." + "system(user_input)"
            source.write_text(call + "\n")

            result = self.run_action(
                directory,
                AEPPO_FAIL_ON_FINDINGS="false",
                AEPPO_EXCLUDES="unsafe.py",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])

    def test_min_severity_input_filters_low_findings(self):
        with TemporaryDirectory() as directory:
            (Path(directory) / "requirements.txt").write_text("demo-package\n")

            result = self.run_action(directory, AEPPO_MIN_SEVERITY="medium")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])

    def test_writes_sarif_to_output_file(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "unsafe.py"
            source.write_text("os." + "system(user_input)\n")
            report = Path(directory) / "aeppo.sarif"

            result = self.run_action(directory, AEPPO_FORMAT="sarif", AEPPO_OUTPUT_FILE=str(report), AEPPO_EXCLUDES="*.sarif")
            sarif = json.loads(report.read_text())

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "PY001")


if __name__ == "__main__":
    unittest.main()
