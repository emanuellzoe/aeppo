import os
import sys
from pathlib import Path


def main():
    action_path = Path(os.environ["AEPPO_ACTION_PATH"])
    sys.path.insert(0, str(action_path))
    from aeppo.cli import main as scanner_main

    arguments = [
        "scan",
        os.environ.get("AEPPO_SCAN_PATH", "."),
        "--format",
        os.environ.get("AEPPO_FORMAT", "text"),
        "--max-file-size",
        os.environ.get("AEPPO_MAX_FILE_SIZE", "1048576"),
        "--min-severity",
        os.environ.get("AEPPO_MIN_SEVERITY", "") or "low",
    ]
    baseline = os.environ.get("AEPPO_BASELINE", "").strip()
    if baseline:
        arguments.extend(["--baseline", baseline])
    output_file = os.environ.get("AEPPO_OUTPUT_FILE", "").strip()
    if output_file:
        arguments.extend(["--output", output_file])
    if os.environ.get("AEPPO_OSV", "false").strip().lower() == "true":
        arguments.append("--osv")
    for pattern in os.environ.get("AEPPO_EXCLUDES", "").splitlines():
        pattern = pattern.strip()
        if pattern:
            arguments.extend(["--exclude", pattern])

    result = scanner_main(arguments)
    if result == 1 and os.environ.get("AEPPO_FAIL_ON_FINDINGS", "true").lower() == "false":
        return 0
    return result


if __name__ == "__main__":
    sys.exit(main())
