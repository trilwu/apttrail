#!/usr/bin/env python3
import json
import sys
import subprocess
from pathlib import Path

# Check if there are actual changes in the feeds (check staged changes)
result = subprocess.run(
    ['git', 'diff', '--staged', '--stat', 'feeds/'],
    capture_output=True,
    text=True
)

if not result.stdout.strip():
    print("No changes detected in feeds")
    sys.exit(0)

# Parse git diff to get actual changes (check staged changes)
diff_result = subprocess.run(
    ['git', 'diff', '--staged', '--numstat', 'feeds/apttrail_threat_feed.json'],
    capture_output=True,
    text=True
)

# Get list of changed APT groups
changed_groups = set()
if diff_result.stdout.strip():
    diff_lines = subprocess.run(
        ['git', 'diff', '--staged', 'feeds/apttrail_threat_feed.json'],
        capture_output=True,
        text=True
    )

    for line in diff_lines.stdout.split('\n'):
        # Look for APT group names in the diff (lines with + or - and apt_groups)
        if (line.startswith('+') or line.startswith('-')) and '"apt_groups"' not in line:
            # Extract APT group names from changed sections
            import re
            matches = re.findall(r'"([A-Z0-9_]+)":\s*{', line)
            changed_groups.update(matches)

# Load current data
with open('feeds/apttrail_threat_feed.json') as f:
    data = json.load(f)

# Generate concise summary of changes
print(f"Update APT threat feeds")
print()

if changed_groups:
    print(f"Changed groups: {', '.join(sorted(changed_groups)[:10])}")
    if len(changed_groups) > 10:
        print(f"... and {len(changed_groups) - 10} more")
else:
    # If we can't detect specific groups, show general update
    print(f"Updated {data['total_apt_groups']} APT groups")

print()
print(f"Total indicators: {sum(g['statistics']['total'] for g in data['apt_groups'].values()):,}")
