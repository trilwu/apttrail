#!/usr/bin/env python3
"""
Generate a meaningful commit message for APT feed updates.

Analyzes git diff to determine what actually changed and creates
a descriptive commit message.
"""

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


def get_changed_files():
    """Get list of changed feed files."""
    result = subprocess.run(["git", "diff", "--cached", "--name-only"], capture_output=True, text=True, check=True)
    return [f for f in result.stdout.strip().split("\n") if f.startswith("feeds/")]


def analyze_json_changes(filepath):
    """Analyze changes in JSON feed file."""
    try:
        # Get old version
        old_result = subprocess.run(["git", "show", f"HEAD:{filepath}"], capture_output=True, text=True)

        if old_result.returncode != 0:
            # New file
            return {"new_file": True}

        old_data = json.loads(old_result.stdout)
        new_data = json.loads(Path(filepath).read_text())

        # Compare APT groups
        old_groups = set(old_data.get("apt_groups", {}).keys())
        new_groups = set(new_data.get("apt_groups", {}).keys())

        added_groups = new_groups - old_groups
        removed_groups = old_groups - new_groups

        # Compare indicators per group
        indicator_changes = defaultdict(lambda: {"added": 0, "removed": 0})

        for group in old_groups & new_groups:
            old_indicators = old_data["apt_groups"][group].get("indicators", {})
            new_indicators = new_data["apt_groups"][group].get("indicators", {})

            for ioc_type in set(list(old_indicators.keys()) + list(new_indicators.keys())):
                old_set = set(old_indicators.get(ioc_type, []))
                new_set = set(new_indicators.get(ioc_type, []))

                added = len(new_set - old_set)
                removed = len(old_set - new_set)

                if added > 0 or removed > 0:
                    indicator_changes[group]["added"] += added
                    indicator_changes[group]["removed"] += removed

        return {
            "added_groups": list(added_groups),
            "removed_groups": list(removed_groups),
            "indicator_changes": dict(indicator_changes),
        }

    except Exception as e:
        print(f"Error analyzing {filepath}: {e}", file=sys.stderr)
        return {}


def generate_commit_message():
    """Generate a meaningful commit message based on changes."""
    changed_files = get_changed_files()

    if not changed_files:
        print("No changes to commit")
        return None

    # Analyze JSON feed for detailed changes
    json_file = next((f for f in changed_files if f.endswith(".json") and "stix" not in f and "misp" not in f), None)

    if not json_file:
        return "Update APT threat feeds"

    changes = analyze_json_changes(json_file)

    if not changes or changes.get("new_file"):
        return "Update APT threat feeds"

    # Build commit message
    parts = []

    # New APT groups
    if changes.get("added_groups"):
        groups = ", ".join(changes["added_groups"][:3])
        if len(changes["added_groups"]) > 3:
            groups += f" (+{len(changes['added_groups']) - 3} more)"
        parts.append(f"New APT groups: {groups}")

    # Removed APT groups
    if changes.get("removed_groups"):
        groups = ", ".join(changes["removed_groups"][:3])
        parts.append(f"Removed: {groups}")

    # Indicator changes
    indicator_changes = changes.get("indicator_changes", {})
    if indicator_changes:
        # Get top 3 groups with most changes
        top_changes = sorted(indicator_changes.items(), key=lambda x: x[1]["added"] + x[1]["removed"], reverse=True)[:3]

        for group, stats in top_changes:
            if stats["added"] > 0:
                parts.append(f"{group}: +{stats['added']} IOCs")
            if stats["removed"] > 0:
                parts.append(f"{group}: -{stats['removed']} IOCs")

    if not parts:
        return "Update APT threat feeds"

    # Combine into message
    title = "Update APT threat feeds"
    body = "\n".join(f"- {part}" for part in parts)

    return f"{title}\n\n{body}"


if __name__ == "__main__":
    message = generate_commit_message()
    if message:
        print(message)
    else:
        sys.exit(1)
