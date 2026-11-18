import argparse
import json
import sys
from pathlib import Path

from aeppo.scanner import scan_path


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aeppo", description="Statically scan source code for suspicious patterns.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a file or directory")
    scan_parser.add_argument("path", type=Path, help="file or directory to scan")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")
    scan_parser.add_argument("--exclude", action="append", default=[], help="exclude a relative path glob; may be repeated")
    scan_parser.add_argument("--max-file-size", type=int, default=1024 * 1024, metavar="BYTES", help="skip files larger than this (default: 1048576)")
    args = parser.parse_args(argv)

    try:
        findings = scan_path(args.path, excludes=args.exclude, max_file_size=args.max_file_size)
    except (OSError, ValueError) as error:
        print("aeppo: {}".format(error), file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps([finding.__dict__ for finding in findings], indent=2))
    else:
        for finding in findings:
            print("{}:{}: [{}|{}] {} ({}, confidence={})".format(finding.path, finding.line, finding.rule_id, finding.severity, finding.message, finding.category, finding.confidence))
            print("  Recommendation: {}".format(finding.recommendation))
        if not findings:
            print("No findings.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
