#!/usr/bin/env python3
"""
Decide whether a JSON feed file changed in a way worth committing.

`generated_at` moves on every run, so a plain `git diff` always reports a
change. This compares the working-tree file against the committed version with
that field excluded, and leaves the file itself untouched - the published feed
must keep its real generation timestamp so consumers can judge freshness.

Exit codes:
    0 - materially changed (or new file): commit it
    1 - no material change: caller should discard the working-tree copy
    2 - error
"""

import json
import subprocess
import sys
from pathlib import Path

VOLATILE_KEYS = ("generated_at",)


def strip_volatile(data: dict) -> dict:
    """Return a copy of the top-level object without run-dependent fields."""
    return {k: v for k, v in data.items() if k not in VOLATILE_KEYS}


def committed_version(path: str) -> dict | None:
    """Load the HEAD version of a file, or None if it is not tracked yet."""
    result = subprocess.run(
        ["git", "show", f"HEAD:{path}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "feeds/apttrail_threat_feed.json"

    file = Path(path)
    if not file.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    try:
        current = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return 2

    previous = committed_version(path)
    if previous is None:
        print(f"{path}: new or untracked, treating as changed")
        return 0

    if strip_volatile(current) == strip_volatile(previous):
        print(f"{path}: only generated_at changed, no material update")
        return 1

    print(f"{path}: material change detected")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
