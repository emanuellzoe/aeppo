import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.scanner import scan_file, scan_path


class ScanFileTests(unittest.TestCase):
    def test_scans_python_files_recursively_and_skips_hidden_and_venv_dirs(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / ".git").mkdir()
            (root / ".venv").mkdir()
            call = "os." + "system" + "(user_input)"
            (root / "src" / "app.py").write_text("import os\n" + call + "\n")
            (root / ".git" / "ignored.py").write_text(call + "\n")
            (root / ".venv" / "ignored.py").write_text(call + "\n")

            findings = scan_path(root)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "src/app.py")
        self.assertEqual(findings[0].line, 2)

    def test_reports_suspicious_shell_execution_with_location(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text("print('safe')\nimport os\n" + "os." + "system(user_input)\n")

            findings = scan_file(source)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 3)
        self.assertEqual(findings[0].rule_id, "PY001")
        self.assertIn("shell command", findings[0].message.lower())

    def test_does_not_flag_unrelated_source(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text("print('hello')\n")

            findings = scan_file(source)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
