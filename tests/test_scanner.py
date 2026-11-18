import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.scanner import scan_file, scan_path


class ScanFileTests(unittest.TestCase):
    def test_scans_javascript_and_typescript_for_eval(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            eval_call = "ev" + "al(userInput)"
            (root / "src" / "app.js").write_text(eval_call + "\n")
            (root / "src" / "app.ts").write_text("const result = " + eval_call + ";\n")

            findings = scan_path(root)

        self.assertEqual(len(findings), 2)
        self.assertEqual([finding.path for finding in findings], ["src/app.js", "src/app.ts"])
        self.assertEqual([finding.rule_id for finding in findings], ["JS001", "JS001"])
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].category, "dynamic-code")

    def test_excludes_matching_files_and_skips_files_over_size_limit(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            call = "os." + "system(x)"
            (root / "ignored.py").write_text(call)
            (root / "large.py").write_text(call + " " * 100)
            (root / "keep.py").write_text(call)

            findings = scan_path(root, excludes=["ignored.py"], max_file_size=20)

        self.assertEqual([finding.path for finding in findings], ["keep.py"])

    def test_detects_unpinned_requirements_and_package_install_scripts(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo-package\n")
            (root / "package.json").write_text('{"scripts":{"preinstall":"node setup.js"}}')

            findings = scan_path(root)

        self.assertEqual({finding.rule_id for finding in findings}, {"DEP001", "DEP003"})
        self.assertTrue(all(finding.severity and finding.confidence and finding.recommendation for finding in findings))

    def test_detects_direct_dependency_references(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo-package @ https://example.invalid/demo.whl\n")
            (root / "package.json").write_text('{"dependencies":{"demo-package":"git+https://example.invalid/demo.git"}}')

            findings = scan_path(root)

        self.assertEqual(len(findings), 2)
        self.assertEqual({finding.rule_id for finding in findings}, {"DEP002"})

    def test_ignores_invalid_package_json_without_crashing(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text("[]")

            findings = scan_path(root)

        self.assertEqual(findings, [])

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

    def test_flags_python_dynamic_code_and_javascript_shell_execution(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            py_call = "ev" + "al(user_input)"
            js_call = "child_process." + "ex" + "ec(command)"
            (root / "dynamic.py").write_text(py_call + "\n")
            (root / "command.js").write_text(js_call + "\n")

            findings = scan_path(root)

        self.assertEqual({finding.rule_id for finding in findings}, {"PY002", "JS002"})

    def test_does_not_flag_unrelated_source(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text("print('hello')\n")

            findings = scan_file(source)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
