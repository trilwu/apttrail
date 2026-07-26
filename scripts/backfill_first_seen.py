#!/usr/bin/env python3
"""
Recover pre-2026 first_seen dates from Maltrail's discarded history.

Maltrail reset its repository on 2026-01-03 with an "Initial commit (fresh
repo)". Everything published before that is unreachable from ``master``, so
``git blame`` dates every older indicator to the reset - which is why the feed
reported that all 167,000 indicators appeared in January 2026.

The old history survives in the repository's pull-request refs: a PR opened
before the reset still has the pre-reset history as its ancestry. Fetching one
such ref restores a decade of dates.

Algorithm: one ``git log -p`` pass over the trails directory, recording the
oldest commit that *added* each line. That is a single history walk; blaming
each file separately meant one deep walk per file and ran for hours.

Run it against a full clone. On a blob-filtered clone every patch is a network
round-trip and the walk takes about ten hours instead of minutes.

Usage:
    python scripts/backfill_first_seen.py <maltrail-repo> [--pr 19300] [--out FILE]

The output is a JSON map of indicator value to unix timestamp, intended to be
compressed and vendored so collection stays fast and offline.
"""

import argparse
import gzip
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

TRAILS_DIR = "trails/static/malware"
DEFAULT_PR = 19300  # head 2025-02-19, 117,351 commits reaching back to 2014
LEGACY_REF = "refs/apttrail/legacy"


def warn_if_partial_clone(repo: Path) -> None:
    """
    Refuse to run quietly against a partial clone.

    A ``--filter=blob:none`` clone fetches blobs on demand, and this script
    reads a patch for every commit. Measured against such a clone it managed
    372 commits in two minutes - roughly ten hours for the full history, all of
    it network round-trips. A full clone turns the same work into local reads.
    """
    result = subprocess.run(
        ["git", "config", "--get-all", "remote.origin.promisor"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if "true" in result.stdout:
        print(
            "WARNING: this looks like a partial (blob-filtered) clone.\n"
            "         Every commit's patch will be fetched over the network and the\n"
            "         run will take hours. Use a full clone of the legacy ref instead.",
            file=sys.stderr,
        )


def fetch_legacy(repo: Path, pull_request: int) -> str:
    """Fetch a pre-reset pull-request ref and return its name."""
    print(f"fetching refs/pull/{pull_request}/head (this is a separate history, expect a large download)")
    subprocess.run(
        ["git", "fetch", "--quiet", "origin", f"refs/pull/{pull_request}/head:{LEGACY_REF}"],
        cwd=repo,
        check=True,
    )
    head = subprocess.run(
        ["git", "log", "-1", "--format=%ad %H", "--date=short", LEGACY_REF],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    print(f"legacy head: {head}")
    return LEGACY_REF


def walk_history(repo: Path, ref: str) -> dict[str, int]:
    """
    Record the first commit that added each indicator line.

    Returns:
        Mapping of indicator value to the unix timestamp of that commit
    """
    # Deliberately not --reverse: that makes git buffer the entire commit list
    # before emitting anything, which stalls for many minutes on a 117,000
    # commit history. Walking newest-first streams immediately, and letting
    # each older commit overwrite the entry leaves the oldest one standing.
    process = subprocess.Popen(
        [
            "git",
            "log",
            "--format=@%at",
            "-p",
            "--no-renames",
            "--no-color",
            "--unified=0",
            ref,
            "--",
            TRAILS_DIR,
        ],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
        bufsize=1024 * 1024,
    )

    first_seen: dict[str, int] = {}
    timestamp: int | None = None
    started = time.time()
    commits = 0

    assert process.stdout is not None
    for line in process.stdout:
        line = line.rstrip("\n")

        if line.startswith("@") and line[1:].isdigit():
            timestamp = int(line[1:])
            commits += 1
            if commits % 20000 == 0:
                print(
                    f"  {commits:,} commits, {len(first_seen):,} indicators, {time.time() - started:.0f}s", flush=True
                )
            continue

        # --unified=0 means every '+' line is an actual addition. Skip the
        # '+++' file header.
        if not line.startswith("+") or line.startswith("+++"):
            continue

        value = line[1:].strip()
        if not value or value.startswith("#") or timestamp is None:
            continue

        # Walking newest-first, so the last write for a value comes from the
        # oldest commit that added it - which is the first_seen we want.
        first_seen[value] = timestamp

    process.wait()
    print(f"walked {commits:,} commits in {time.time() - started:.0f}s")
    return first_seen


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", type=Path, help="Path to a Maltrail clone")
    parser.add_argument("--pr", type=int, default=DEFAULT_PR, help=f"Pre-reset PR ref to fetch (default: {DEFAULT_PR})")
    parser.add_argument("--ref", default=None, help="Use an already-fetched ref instead of fetching")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("src/apttrail/data/legacy_first_seen.json.gz"),
        help="Output file (gzipped JSON)",
    )
    args = parser.parse_args(argv[1:])

    if not (args.repo / ".git").exists():
        print(f"not a git repository: {args.repo}", file=sys.stderr)
        return 2

    warn_if_partial_clone(args.repo)
    ref = args.ref or fetch_legacy(args.repo, args.pr)
    first_seen = walk_history(args.repo, ref)

    if not first_seen:
        print("no indicators recovered - is the ref really pre-reset?", file=sys.stderr)
        return 1

    years = Counter(datetime.fromtimestamp(ts, tz=timezone.utc).year for ts in first_seen.values())
    print(f"{len(first_seen):,} indicators dated")
    print("by year:", dict(sorted(years.items())))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.out, "wt", encoding="utf-8", newline="\n") as f:
        json.dump(first_seen, f, separators=(",", ":"), sort_keys=True)

    print(f"wrote {args.out} ({args.out.stat().st_size / 1024 / 1024:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
