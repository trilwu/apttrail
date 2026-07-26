"""
Append-only changelog of indicator additions and removals.

The git history of the feed files is a poor record of IOC change: answering
"when did this domain appear?" would mean diffing multi-megabyte JSON blobs.
This module emits one small JSON line per change instead, rotated monthly, so
the record stays queryable with grep/jq and costs a few KB per day.

Note that `first_seen` (collected from Maltrail's own git history) already
answers when an indicator entered upstream. This changelog answers what
`first_seen` cannot: when an indicator left the feed.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from apttrail.models import APTGroup

# group -> indicator type -> set of indicator values
IndicatorIndex = dict[str, dict[str, set[str]]]


def load_previous_feed(path: Path | str) -> IndicatorIndex | None:
    """
    Load a previously exported JSON feed into a comparable index.

    Handles both export shapes: a plain list of indicator values, and the
    timestamp-grouped shape used when first_seen collection is enabled.

    Args:
        path: Path to a previously exported apttrail_threat_feed.json

    Returns:
        Nested index of group -> type -> values, or None if the file is
        missing or unreadable. None means "no baseline", which callers must
        treat as "emit nothing" rather than "everything is new".
    """
    file = Path(path)
    if not file.exists():
        return None

    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    groups = data.get("apt_groups")
    if not isinstance(groups, dict):
        return None

    index: IndicatorIndex = {}
    for group_name, group in groups.items():
        indicators = group.get("indicators", {})
        index[group_name] = {indicator_type: _extract_values(entries) for indicator_type, entries in indicators.items()}

    return index


def _extract_values(entries: Any) -> set[str]:
    """Pull indicator values out of either export shape."""
    values: set[str] = set()

    if not isinstance(entries, list):
        return values

    for entry in entries:
        if isinstance(entry, str):
            values.add(entry)
        elif isinstance(entry, dict):
            values.update(v for v in entry.get("indicators", []) if isinstance(v, str))

    return values


def index_current(apt_groups: dict[str, APTGroup]) -> IndicatorIndex:
    """Build the same index shape from freshly collected groups."""
    return {
        name: {itype.value: {ind.value for ind in indicators} for itype, indicators in group.indicators.items()}
        for name, group in apt_groups.items()
    }


def diff_indicators(previous: IndicatorIndex, current: IndicatorIndex) -> list[dict[str, str]]:
    """
    Compare two indicator indexes.

    Args:
        previous: Baseline index
        current: Newly collected index

    Returns:
        Change events sorted deterministically by (group, type, action, value)
        so repeated runs over identical input produce identical output.
    """
    events: list[dict[str, str]] = []

    for group in sorted(set(previous) | set(current)):
        prev_types = previous.get(group, {})
        curr_types = current.get(group, {})

        for indicator_type in sorted(set(prev_types) | set(curr_types)):
            prev_values = prev_types.get(indicator_type, set())
            curr_values = curr_types.get(indicator_type, set())

            for value in sorted(curr_values - prev_values):
                events.append({"group": group, "type": indicator_type, "action": "added", "value": value})
            for value in sorted(prev_values - curr_values):
                events.append({"group": group, "type": indicator_type, "action": "removed", "value": value})

    return events


def append_changes(changes_dir: Path | str, events: list[dict[str, str]], timestamp: datetime) -> Path | None:
    """
    Append change events to the monthly log.

    Args:
        changes_dir: Directory holding the monthly JSONL files
        events: Change events to record
        timestamp: Observation time stamped onto every event

    Returns:
        Path of the file written, or None if there was nothing to record.
    """
    if not events:
        return None

    directory = Path(changes_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{timestamp.strftime('%Y-%m')}.jsonl"

    ts = timestamp.isoformat()
    with open(target, "a", encoding="utf-8", newline="\n") as f:
        for event in events:
            f.write(json.dumps({"ts": ts, **event}, ensure_ascii=False, sort_keys=True) + "\n")

    return target
