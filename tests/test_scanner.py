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

    def test_python_ignores_comments_strings_and_method_calls(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text(
                "# never call os." + "system() here\n"
                "PATTERN = 'find -ex" + "ec(rm)'\n"
                "model.ev" + "al()\n"
                "ssh.ex" + "ec(command)\n"
                "doc = \"os." + "system(x)\"\n"
            )

            findings = scan_file(source)

        self.assertEqual(findings, [])

    def test_python_reports_multiline_call_at_its_first_line(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text("import os\nos." + "system(\n    command,\n)\n")

            findings = scan_file(source)

        self.assertEqual([(finding.line, finding.rule_id) for finding in findings], [(2, "PY001")])

    def test_python_falls_back_to_patterns_when_file_does_not_parse(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "legacy.py"
            source.write_text("print 'legacy'\nex" + "ec(code)\n")

            findings = scan_file(source)

        self.assertEqual([(finding.line, finding.rule_id) for finding in findings], [(2, "PY002")])

    def test_javascript_ignores_regexp_exec_method_calls_and_comments(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "parse.ts"
            source.write_text(
                "const match = /a(b)/.ex" + "ec(text)\n"
                "const other = PATTERN.ex" + "ec(line)\n"
                "// avoid ev" + "al(input)\n"
                " * child_process.ex" + "ec(cmd) in docs\n"
            )

            findings = scan_file(source)

        self.assertEqual(findings, [])

    def test_javascript_still_flags_destructured_exec(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "run.js"
            source.write_text("const { ex" + "ecSync } = require('child_process')\nex" + "ecSync(command)\n")

            findings = scan_file(source)

        self.assertEqual([(finding.line, finding.rule_id) for finding in findings], [(2, "JS002")])

    def test_package_json_direct_dependency_reports_its_line(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "package.json"
            source.write_text('{\n  "dependencies": {\n    "left": "^1.0.0",\n    "demo": "git+https://example.invalid/demo.git"\n  }\n}\n')

            findings = scan_file(source)

        self.assertEqual([(finding.line, finding.rule_id) for finding in findings], [(4, "DEP002")])

    def test_does_not_flag_unrelated_source(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text("print('hello')\n")

            findings = scan_file(source)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
