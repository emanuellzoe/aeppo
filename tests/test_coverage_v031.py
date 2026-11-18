"""Coverage gaps found by scanning public security repositories as text (nothing was executed)."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.scanner import filter_findings, scan_file, scan_path


EXAMPLE_AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
REALISTIC_AWS_KEY = "AKIA" + "Z7Q4M2X9" + "B3K8L5P1"


def scan_source(name, text):
    with TemporaryDirectory() as directory:
        source = Path(directory) / name
        source.write_text(text, encoding="utf-8")
        return scan_file(source)


class ModuleExtensionTests(unittest.TestCase):
    def test_mjs_cjs_mts_cts_files_are_scanned(self):
        call = "execS" + "ync(`git clone ${url}`)\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a.mjs", "b.cjs", "c.mts", "d.cts"):
                (root / name).write_text(call)

            findings = scan_path(root)

        self.assertEqual([(finding.path, finding.rule_id) for finding in findings], [("a.mjs", "JS002"), ("b.cjs", "JS002"), ("c.mts", "JS002"), ("d.cts", "JS002")])


class FunctionMethodTests(unittest.TestCase):
    def test_method_named_function_is_not_reported(self):
        found = scan_source(
            "visitor.ts",
            "const visitor = {\n"
            "  Function(path) {\n"
            "    async Function(innerPath) {\n"
            "  },\n"
            "}\n",
        )
        self.assertEqual(found, [])

    def test_function_constructor_call_is_still_reported(self):
        found = scan_source("a.mjs", "const value = Number(Function(`return (${expr})`)())\n")
        self.assertEqual([(finding.line, finding.rule_id) for finding in found], [(1, "JS003")])


class ExampleCredentialTests(unittest.TestCase):
    def test_documented_example_key_is_reported_at_low_severity(self):
        found = scan_source(".env", "AWS_ACCESS_KEY_ID=" + EXAMPLE_AWS_KEY + "\n")

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].rule_id, "SEC001")
        self.assertEqual((found[0].severity, found[0].confidence), ("low", "low"))
        self.assertIn("example", found[0].message.lower())
        self.assertEqual(filter_findings(found, min_severity="medium"), [])

    def test_repeated_character_placeholders_are_low_severity(self):
        text = "TOKEN=" + "ghp_" + "x" * 36 + "\nKEY=" + "AKIA" + "X" * 16 + "\n"
        found = scan_source(".env", text)

        self.assertEqual([(finding.rule_id, finding.severity) for finding in found], [("SEC002", "low"), ("SEC001", "low")])
        self.assertIn("placeholder", found[0].message.lower())

    def test_pem_header_severity_is_unchanged(self):
        found = scan_source("key.py", 'KEY = """-----BEGIN ' + 'RSA PRIVATE KEY-----"""\n')
        self.assertEqual([(finding.rule_id, finding.severity) for finding in found], [("SEC003", "high")])

    def test_realistic_key_keeps_high_severity(self):
        found = scan_source(".env", "AWS_ACCESS_KEY_ID=" + REALISTIC_AWS_KEY + "\n")

        self.assertEqual([(finding.rule_id, finding.severity) for finding in found], [("SEC001", "high")])


class MarkdownTests(unittest.TestCase):
    def test_markdown_is_checked_for_secrets_only(self):
        found = scan_source(
            "README.md",
            "# Setup\n"
            "Export `AWS_ACCESS_KEY_ID=" + REALISTIC_AWS_KEY + "` before running.\n"
            "```js\n"
            "ev" + "al(userInput)\n"
            "require('child_process').ex" + "ec(cmd)\n"
            "```\n",
        )
        self.assertEqual([(finding.line, finding.rule_id) for finding in found], [(2, "SEC001")])

    def test_mdx_and_markdown_extensions_are_scanned(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "guide.mdx").write_text("token: " + REALISTIC_AWS_KEY + "\n")
            (root / "notes.markdown").write_text("nothing here\n")

            findings = scan_path(root)

        self.assertEqual([(finding.path, finding.rule_id) for finding in findings], [("guide.mdx", "SEC001")])


if __name__ == "__main__":
    unittest.main()
