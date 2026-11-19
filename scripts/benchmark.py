"""Scan-speed benchmark on a generated repository.

The generated files are benign but deliberately pass aeppo's cheap prefilters (subprocess calls,
getattr, json.loads, exec-named methods, long lines), so they exercise the expensive paths: AST
parsing, per-line regexes, and secret hints. Nothing generated is executed.

Usage: python scripts/benchmark.py [--files N] [--budget SECONDS] [--max-ratio RATIO]

Absolute times vary a lot between machines and CI runners, so the benchmark also reports the scan
time divided by the time it takes to simply read every file in the same run. That ratio is far
more stable, and --max-ratio fails the run when it is exceeded, so CI catches large slowdowns.
"""
import argparse
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aeppo.scanner import scan_path  # noqa: E402


PYTHON_BODY = '''import json
import subprocess
import yaml


class Worker:
    def run(self, payload):
        data = json.loads(payload)
        handler = getattr(self, "handle_" + data["kind"], None)
        result = subprocess.run(["git", "status", "--short"], capture_output=True, text=True)
        config = yaml.safe_load(data.get("config", "{}"))
        return handler, result.stdout, config

    def handle_ping(self, value):
        # eval and exec are mentioned in comments only: eval(x) exec(y)
        return {"pong": value, "note": "os.system is not called here"}
'''

TYPESCRIPT_BODY = '''import { readFile } from 'node:fs/promises'

const PATTERN = /^(\\w+)=(.*)$/
export async function parse(path: string): Promise<Record<string, string>> {
  const text = await readFile(path, 'utf8')
  const out: Record<string, string> = {}
  for (const line of text.split('\\n')) {
    const match = PATTERN.exec(line)
    if (match) out[match[1]] = match[2]
  }
  return out
}
export const visitor = { Function(path: unknown) { return path } }
export const longLine = "%s"
'''

SHELL_BODY = '''#!/usr/bin/env bash
set -euo pipefail
# Benign: downloads go to files, /dev/tcp is a health check, nothing is piped into a shell.
curl -fsSL -o "$TMP/tool.tar.gz" "https://example.invalid/tool.tar.gz"
(echo -n > /dev/tcp/$HOST/$PORT) >/dev/null 2>&1 || echo "waiting for $HOST"
curl -fsS "http://127.0.0.1:$PORT/stats" | python3 -m json.tool
crontab -l || true
base64 -d payload.b64 > payload.bin
'''

WORKFLOW_BODY = '''name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Test
        env:
          TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "PR ${{ github.event.pull_request.number }}: $TITLE"
          make test
'''

AUTOEXEC_FILES = {
    "Dockerfile": "FROM python:3.12-slim\nRUN apt-get update \\\n    && apt-get install -y curl\nRUN curl -fsSL -o /tmp/t.tgz https://example.invalid/t.tgz\n" * 3,
    "build.rs": 'use std::process::Command;\nfn main() {\n    let rev = Command::new("git").args(["rev-parse", "HEAD"]).output().unwrap();\n    println!("cargo:rustc-env=REV={:?}", rev.stdout);\n}\n',
    ".vscode/tasks.json": '{\n  "version": "2.0.0",\n  "tasks": [{ "label": "build", "type": "shell", "command": "npm run build" }]\n}\n',
    "setup.ps1": "$ErrorActionPreference = 'Stop'\nInvoke-WebRequest -Uri https://example.invalid/t.zip -OutFile t.zip\nExpand-Archive t.zip -DestinationPath tools\n",
    "build.gradle.kts": 'plugins { kotlin("jvm") version "2.0.0" }\ndependencies { implementation("org.slf4j:slf4j-api:2.0.13") }\n',
}

# Benign files that pass the code-rule hints, so the lexer and argument parsing run.
CODE_FILES = {
    "tool.go": 'package main\n\nimport "os/exec"\n\n// exec.Command("sh", "-c", x) in a comment\nfunc rev() ([]byte, error) {\n\treturn exec.Command("git", "rev-parse", "HEAD").Output()\n}\n' * 20,
    "tool.rs": 'use std::process::Command;\nfn rev() { let _ = Command::new("git").args(["rev-parse", "HEAD"]).output(); let s: &\'static str = "x"; }\n' * 20,
    "Tool.java": 'class Tool {\n  void run(String f) throws Exception {\n    new ProcessBuilder("git", "log", f).start(); // Runtime.getRuntime().exec(x)\n  }\n}\n' * 20,
    "tool.php": '<html><p>Don\'t</p></html>\n<?php\n$pdo->exec($sql);\n$rows = json_decode($body, true);\n?>\n' * 20,
    "tool.rb": 'def rev(ref)\n  system("git", "log", ref) # system("rm #{ref}")\n  out = `git rev-parse HEAD`\n  ref.gsub(/[`"]/, "")\nend\n' * 20,
}

MARKDOWN_BODY = "# Notes\n\nSet `sk-test` style keys in your environment, never in docs.\n\n" + "Lorem ipsum dolor sit amet. " * 40 + "\n"


def build(root, files):
    long_line = "x" * 2000
    for index in range(files):
        folder = root / "pkg{}".format(index // 50)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "worker_{}.py".format(index)).write_text(PYTHON_BODY * 8, encoding="utf-8")
        (folder / "parse_{}.ts".format(index)).write_text((TYPESCRIPT_BODY % long_line) * 4, encoding="utf-8")
        if index % 4 == 0:
            (folder / "README_{}.md".format(index)).write_text(MARKDOWN_BODY, encoding="utf-8")
            (folder / "setup_{}.sh".format(index)).write_text(SHELL_BODY * 4, encoding="utf-8")
            (folder / "run_{}".format(index)).write_text(SHELL_BODY, encoding="utf-8")
        if index % 50 == 0:
            for relative, body in list(AUTOEXEC_FILES.items()) + list(CODE_FILES.items()):
                target = folder / "project" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8")
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    for index in range(max(1, files // 30)):
        (workflows / "ci_{}.yml".format(index)).write_text(WORKFLOW_BODY * 3, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--files", type=int, default=1500, help="Python/TypeScript file pairs to generate (default: 1500)")
    parser.add_argument("--budget", type=float, default=None, help="fail when the scan takes longer than this many seconds")
    parser.add_argument("--max-ratio", type=float, default=None, help="fail when scan time / plain read time exceeds this")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        build(root, args.files)
        paths = sorted(path for path in root.rglob("*") if path.is_file())
        megabytes = sum(path.stat().st_size for path in paths) / 1_000_000
        # Fastest of several plain reads: a short timing is noisy, and the minimum is the most stable.
        read_times = []
        for _attempt in range(5):
            start = time.perf_counter()
            for path in paths:
                path.read_text(encoding="utf-8", errors="replace").splitlines()
            read_times.append(time.perf_counter() - start)
        read_time = min(read_times)
        start = time.perf_counter()
        findings = scan_path(root)
        elapsed = time.perf_counter() - start

    ratio = elapsed / read_time
    print("aeppo benchmark: {} files, {:.1f} MB, scan {:.2f}s ({:.0f} files/s), read {:.2f}s, ratio {:.1f}x, {} findings".format(len(paths), megabytes, elapsed, len(paths) / elapsed, read_time, ratio, len(findings)))
    if findings:
        print("FAIL: unexpected findings in benign benchmark files:", [(f.path, f.line, f.rule_id) for f in findings[:5]])
        return 1
    if args.budget is not None and elapsed > args.budget:
        print("FAIL: scan took {:.2f}s, budget is {:.2f}s".format(elapsed, args.budget))
        return 1
    if args.max_ratio is not None and ratio > args.max_ratio:
        print("FAIL: scan/read ratio {:.1f}x exceeds {:.1f}x".format(ratio, args.max_ratio))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
