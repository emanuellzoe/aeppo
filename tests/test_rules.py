import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.scanner import filter_findings, load_baseline, scan_file, scan_path


def scan_source(name, text):
    with TemporaryDirectory() as directory:
        source = Path(directory) / name
        source.write_text(text)
        return [(finding.line, finding.rule_id) for finding in scan_file(source)]


class PythonRuleTests(unittest.TestCase):
    def test_flags_subprocess_with_shell_true_but_not_argument_lists(self):
        found = scan_source(
            "run.py",
            "import subprocess\n"
            "subprocess.run(command, shell=True)\n"
            "subprocess.run(['ls', path])\n"
            "subprocess.run(command, shell=False)\n"
            "subprocess.getoutput(command)\n",
        )
        self.assertEqual(found, [(2, "PY003"), (5, "PY003")])

    def test_resolves_import_aliases_and_from_imports(self):
        found = scan_source(
            "alias.py",
            "import os as o\n"
            "from os import popen\n"
            "from subprocess import Popen as P\n"
            "o.system(command)\n"
            "popen(command)\n"
            "P(command, shell=True)\n",
        )
        self.assertEqual(found, [(4, "PY001"), (5, "PY001"), (6, "PY003")])

    def test_renamed_from_imports_are_not_skipped_by_the_fast_prefilter(self):
        found = scan_source(
            "renamed.py",
            "from os import system as run_shell\n"
            "from pickle import loads as decode\n"
            "run_shell(command)\n"
            "decode(blob)\n",
        )
        self.assertEqual(found, [(3, "PY001"), (4, "PY004")])

    def test_flags_unpickling(self):
        found = scan_source("load.py", "import pickle\nimport dill\npickle.loads(blob)\ndill.load(handle)\n")
        self.assertEqual(found, [(3, "PY004"), (4, "PY004")])

    def test_flags_yaml_load_only_without_a_safe_loader(self):
        found = scan_source(
            "config.py",
            "import yaml\n"
            "yaml.load(text)\n"
            "yaml.load(text, Loader=yaml.SafeLoader)\n"
            "yaml.load(text, yaml.CSafeLoader)\n"
            "yaml.load(text, Loader=yaml.FullLoader)\n"
            "yaml.safe_load(text)\n"
            "yaml.unsafe_load(text)\n"
            "yaml.load(text, **options)\n",
        )
        self.assertEqual(found, [(2, "PY005"), (5, "PY005"), (7, "PY005")])

    def test_ignores_same_names_on_unrelated_objects(self):
        found = scan_source("other.py", "client.run(command, shell=True)\ncache.loads(blob)\nparser.load(text)\n")
        self.assertEqual(found, [])


class JavaScriptRuleTests(unittest.TestCase):
    def test_flags_child_process_aliases(self):
        found = scan_source(
            "run.js",
            "const cp = require('node:child_process')\n"
            "import * as proc from 'child_process'\n"
            "cp.exec(command)\n"
            "proc.execSync(command)\n"
            "other.exec(command)\n",
        )
        self.assertEqual(found, [(3, "JS002"), (4, "JS002")])

    def test_ignores_code_inside_multiline_template_literals(self):
        # A test that embeds Python source: exec() and eval() there are text, not calls.
        found = scan_source(
            "fuzz.test.ts",
            "import { exec } from 'child_process'\n"
            "const label = 'a ` backtick in a plain string'\n"
            "const snippet = `\n"
            "exec(code, namespace)\n"
            "eval(expr)\n"
            "`\n"
            "exec(command)\n"
            "const run = new Function(`\n"
            "  return ${body}; eval(x)\n"
            "`)\n",
        )
        self.assertEqual(found, [(7, "JS002"), (8, "JS003"), (9, "JS001")])

    def test_ignores_exec_method_definitions(self):
        found = scan_source(
            "client.ts",
            "class Client {\n"
            "  async exec(command: string) {\n"
            "  exec(command) {\n"
            "}\n"
            "function exec(command) {}\n",
        )
        self.assertEqual(found, [])

    def test_flags_function_constructor_and_string_timers(self):
        found = scan_source(
            "dynamic.js",
            "const run = new Function('a', body)\n"
            "setTimeout('tick()', 10)\n"
            "window.setInterval(`poll()`, 50)\n"
            "setTimeout(() => tick(), 10)\n",
        )
        self.assertEqual(found, [(1, "JS003"), (2, "JS003"), (3, "JS003")])


class SecretRuleTests(unittest.TestCase):
    def test_detects_additional_provider_key_formats(self):
        values = [
            ("SEC004", "xox" + "b-" + "123456789012-123456789012-abcdefghijkl"),
            ("SEC005", "sk_" + "live_" + "a1" * 12),
            ("SEC006", "sk-" + "proj-" + "A1b2" * 12),
            ("SEC007", "sk-" + "ant-" + "api03-" + "x" * 40),
            ("SEC008", "AI" + "za" + "B" * 35),
        ]
        text = "".join("KEY_{}={}\n".format(index, value) for index, (_rule, value) in enumerate(values))

        found = scan_source(".env.staging", text)

        self.assertEqual(found, [(index, rule) for index, (rule, _value) in enumerate(values, start=1)])

    def test_anthropic_key_is_not_reported_as_openai(self):
        found = scan_source("keys.py", 'KEY = "' + "sk-" + "ant-" + "api03-" + "x" * 48 + '"\n')
        self.assertEqual(found, [(1, "SEC007")])

    def test_short_placeholders_are_not_reported(self):
        text = "".join(
            'V{} = "{}"\n'.format(index, value)
            for index, value in enumerate(["xox" + "b-fake-token", "sk-" + "ant-oat-LEAKED-PROFILE-B", "sk-" + "proj-AbCdEf1234567890GhIjKl"])
        )
        self.assertEqual(scan_source("fixtures.py", text), [])


class SuppressionTests(unittest.TestCase):
    def test_inline_and_next_line_suppression(self):
        call = "os." + "system(command)"
        found = scan_source(
            "suppressed.py",
            "import os\n"
            + call + "  # aeppo: ignore\n"
            + call + "  # aeppo: ignore[PY001]\n"
            + call + "  # aeppo: ignore[PY002]\n"
            "# aeppo: ignore-next-line\n"
            + call + "\n"
            "# aeppo: ignore\n"
            + call + "\n",
        )
        self.assertEqual(found, [(4, "PY001"), (8, "PY001")])

    def test_suppression_works_in_javascript_and_env_files(self):
        self.assertEqual(scan_source("a.js", "ev" + "al(x) // aeppo: ignore[JS001]\n"), [])
        self.assertEqual(scan_source(".env", "# aeppo: ignore-next-line[SEC001]\nKEY=" + "AKIA" + "IOSFODNN7EXAMPLE\n"), [])


class FilterAndBaselineTests(unittest.TestCase):
    def test_min_severity_drops_lower_findings(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo-package\n")
            (root / "run.py").write_text("ex" + "ec(code)\n")

            findings = scan_path(root)

        self.assertEqual({finding.rule_id for finding in filter_findings(findings, min_severity="medium")}, {"PY002"})
        self.assertEqual(len(filter_findings(findings)), 2)
        with self.assertRaises(ValueError):
            filter_findings(findings, min_severity="critical")

    def test_baseline_survives_line_shifts_but_not_new_findings(self):
        call = "os." + "system(command)\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text(call)
            baseline_file = root / "baseline.json"
            import json

            baseline_file.write_text(json.dumps([finding.__dict__ for finding in scan_path(root)]))
            source.write_text("import os\n\n" + call + "os." + "system(other)\n")

            findings = filter_findings(scan_path(root), baseline=load_baseline(baseline_file))

        self.assertEqual([(finding.line, finding.rule_id) for finding in findings], [(4, "PY001")])

    def test_rejects_malformed_baseline(self):
        with TemporaryDirectory() as directory:
            baseline_file = Path(directory) / "baseline.json"
            baseline_file.write_text('{"not": "a list"}')
            with self.assertRaises(ValueError):
                load_baseline(baseline_file)


@unittest.skipIf(os.name == "nt" or getattr(os, "geteuid", lambda: 1)() == 0, "requires POSIX permissions as a non-root user")
class UnreadableFileTests(unittest.TestCase):
    def test_skips_unreadable_files_when_collecting_errors(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            locked = root / "locked.py"
            locked.write_text("print('x')\n")
            (root / "open.py").write_text("ex" + "ec(code)\n")
            locked.chmod(0)
            try:
                errors = []
                findings = scan_path(root, errors=errors)
                with self.assertRaises(OSError):
                    scan_path(root)
            finally:
                locked.chmod(0o600)

        self.assertEqual([finding.path for finding in findings], ["open.py"])
        self.assertEqual(len(errors), 1)
        self.assertIn("locked.py", errors[0])


if __name__ == "__main__":
    unittest.main()
