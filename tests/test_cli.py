import unittest
import json
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout

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

    def test_scan_command_reports_findings_and_returns_one(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            call = "os." + "system" + "(user_input)"
            (root / "bad.py").write_text("import os\n" + call + "\n")
            output = StringIO()

            with redirect_stdout(output):
                result = main(["scan", str(root)])

        self.assertEqual(result, 1)
        self.assertIn("bad.py:2: [PY001]", output.getvalue())

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
