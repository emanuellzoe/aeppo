"""Detection corpus: inert samples that must, or must not, be reported.

Static samples live in tests/corpus and are only read as text; nothing in the corpus is ever run
or imported. Secrets and bidirectional control characters are generated here instead of being
committed, so the repository carries no credential-shaped strings and no hidden characters.
Expectations, with the reason for each sample, are in tests/corpus/expected.json.
"""
import json
import shutil
import unittest
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory

from aeppo.scanner import scan_path


CORPUS = Path(__file__).resolve().parent / "corpus"
MANIFEST = CORPUS / "expected.json"
NOT_SAMPLES = {"expected.json", "README.md"}

RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
LEFT_TO_RIGHT_ISOLATE = chr(0x2066)
POP_DIRECTIONAL_ISOLATE = chr(0x2069)

# Split so neither this file nor the repository contains a credential-shaped literal.
GENERATED = {
    "generated/secrets/realistic_aws.env": "AWS_ACCESS_KEY_ID=" + "AKIA" + "Z7Q4M2X9" + "B3K8L5P1" + "\n",
    "generated/secrets/example_aws.env": "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7" + "EXAMPLE" + "\n",
    "generated/secrets/placeholder_github.md": "Run `tool --token " + "ghp_" + "x" * 36 + "`\n",
    "generated/secrets/leak_in_readme.md": "# Setup\nexport AWS_ACCESS_KEY_ID=" + "AKIA" + "Q8W3E5R7" + "T2Y4U6I9" + "\n",
    "generated/secrets/stripe_live.py": 'STRIPE_KEY = "' + "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + '"\n',
    "generated/secrets/anthropic.ts": "const key = '" + "sk-" + "ant-" + "api03-" + "Zq8" * 14 + "'\n",
    "generated/secrets/private_key.py": 'KEY = """-----BEGIN ' + 'RSA PRIVATE KEY-----"""\n',
    "generated/trojan_source.js": "const ok = 1\nconst isAdmin = false; /*"
    + RIGHT_TO_LEFT_OVERRIDE
    + " } "
    + LEFT_TO_RIGHT_ISOLATE
    + "if (isAdmin)"
    + POP_DIRECTIONAL_ISOLATE
    + " */\n",
    "generated/negative/bidi_in_translations.json": '{"greeting": "' + LEFT_TO_RIGHT_ISOLATE + "hello" + POP_DIRECTIONAL_ISOLATE + '"}\n',
}


def load_manifest():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {path: entry for path, entry in manifest.items() if not path.startswith("_")}


def scan_corpus():
    with TemporaryDirectory() as directory:
        root = Path(directory) / "corpus"
        shutil.copytree(CORPUS, root)
        for relative, text in GENERATED.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        samples = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and path.name not in NOT_SAMPLES)
        findings = scan_path(root, excludes=sorted(NOT_SAMPLES))
    reported = defaultdict(list)
    for finding in findings:
        reported[finding.path].append("{}:{}:{}".format(finding.line, finding.rule_id, finding.severity))
    return samples, reported


class DetectionCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest()
        cls.samples, cls.reported = scan_corpus()

    def test_every_sample_has_an_expectation(self):
        self.assertEqual(sorted(self.manifest), self.samples, "add new corpus files to tests/corpus/expected.json (and remove deleted ones)")

    def test_every_expectation_has_a_reason(self):
        missing = [path for path, entry in self.manifest.items() if not entry.get("why")]
        self.assertEqual(missing, [])

    def test_samples_report_exactly_the_expected_findings(self):
        for path, entry in sorted(self.manifest.items()):
            with self.subTest(sample=path, why=entry["why"]):
                self.assertEqual(sorted(self.reported.get(path, [])), sorted(entry["expect"]))

    def test_known_misses_are_still_missed(self):
        # A known miss that starts being detected is good news: update expected.json.
        for path, entry in self.manifest.items():
            if entry.get("known_miss"):
                with self.subTest(sample=path):
                    self.assertEqual(self.reported.get(path, []), [], "detected now; move it out of known_miss")

    def test_nothing_is_reported_outside_the_manifest(self):
        self.assertEqual(sorted(set(self.reported) - set(self.manifest)), [])


def summary():
    manifest = load_manifest()
    _samples, reported = scan_corpus()
    positives = [path for path, entry in manifest.items() if entry["expect"]]
    negatives = [path for path, entry in manifest.items() if not entry["expect"] and not entry.get("known_miss")]
    detected = sum(1 for path in positives if sorted(reported.get(path, [])) == sorted(manifest[path]["expect"]))
    quiet = sum(1 for path in negatives if not reported.get(path))
    known = sum(1 for entry in manifest.values() if entry.get("known_miss"))
    return "positives detected {}/{} | negatives quiet {}/{} | known misses {}".format(detected, len(positives), quiet, len(negatives), known)


if __name__ == "__main__":
    print(summary())
    unittest.main()
