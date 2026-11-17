import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.scanner import scan_path


class ScannerSecretTests(unittest.TestCase):
    def test_detects_github_personal_access_token_pattern(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "config.py"
            token = "ghp_" + "A" * 36
            source.write_text('TOKEN = "' + token + '"\n')

            findings = scan_path(directory)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC002")
        self.assertEqual(findings[0].line, 1)
        self.assertIn("GitHub token", findings[0].message)

    def test_detects_private_key_header(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "key.py"
            header = "-----BEGIN " + "RSA PRIVATE KEY-----"
            source.write_text('KEY = "' + header + '"\n')

            findings = scan_path(directory)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC003")

    def test_detects_aws_access_key_pattern(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "config.py"
            key = "AKIA" + "IOSFODNN7EXAMPLE"
            source.write_text('AWS_KEY = "' + key + '"\n')

            findings = scan_path(directory)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC001")
        self.assertEqual(findings[0].line, 1)
        self.assertIn("AWS access key", findings[0].message)

    def test_does_not_flag_short_or_unrelated_values(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "config.py"
            source.write_text('key = "hello world"\n')

            findings = scan_path(directory)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
