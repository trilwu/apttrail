#!/usr/bin/env python3
"""Print markdown release-note statistics for a generated JSON feed."""

import json
import sys
from pathlib import Path

DEFAULT_FEED = "release-feeds/apttrail_threat_feed.json"


def main(argv: list[str]) -> int:
    feed_path = Path(argv[1] if len(argv) > 1 else DEFAULT_FEED)

    try:
        data = json.loads(feed_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error reading {feed_path}: {e}", file=sys.stderr)
        return 1

    total = 0
    types: dict[str, int] = {}
    for group in data["apt_groups"].values():
        total += group["statistics"]["total"]
        for itype, count in group["statistics"]["by_type"].items():
            types[itype] = types.get(itype, 0) + count

    print(f"- **Generated at:** {data.get('generated_at', 'unknown')}")
    print(f"- **APT Groups:** {data['total_apt_groups']}")
    print(f"- **Total Indicators:** {total:,}")
    print()
    print("### Indicators by Type:")
    for itype, count in sorted(types.items()):
        print(f"- {itype}: {count:,}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
