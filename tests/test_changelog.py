import json
from datetime import datetime

from apttrail.changelog import (
    append_changes,
    diff_indicators,
    index_current,
    load_previous_feed,
)
from apttrail.models import APTGroup, APTGroupMetadata, Indicator, IndicatorType

TS = datetime(2026, 7, 26, 4, 0, 0)


def write_feed(path, indicators):
    """Write a minimal exported feed with the given group -> type -> entries."""
    path.write_text(
        json.dumps({"apt_groups": {name: {"indicators": types} for name, types in indicators.items()}}),
        encoding="utf-8",
    )
    return path


def test_load_previous_feed_reads_flat_shape(tmp_path):
    feed = write_feed(tmp_path / "feed.json", {"APT28": {"domain": ["a.com", "b.com"]}})

    assert load_previous_feed(feed) == {"APT28": {"domain": {"a.com", "b.com"}}}


def test_load_previous_feed_reads_timestamp_grouped_shape(tmp_path):
    # Shape produced when first_seen collection is enabled.
    feed = write_feed(
        tmp_path / "feed.json",
        {"APT28": {"domain": [{"first_seen": "2026-01-01T00:00:00+00:00", "indicators": ["a.com", "b.com"]}]}},
    )

    assert load_previous_feed(feed) == {"APT28": {"domain": {"a.com", "b.com"}}}


def test_load_previous_feed_returns_none_when_missing(tmp_path):
    # None means "no baseline" - callers must not treat it as "all new".
    assert load_previous_feed(tmp_path / "absent.json") is None


def test_diff_detects_additions_and_removals():
    previous = {"APT28": {"domain": {"keep.com", "gone.com"}}}
    current = {"APT28": {"domain": {"keep.com", "new.com"}}}

    events = diff_indicators(previous, current)

    assert events == [
        {"group": "APT28", "type": "domain", "action": "added", "value": "new.com"},
        {"group": "APT28", "type": "domain", "action": "removed", "value": "gone.com"},
    ]


def test_diff_handles_new_and_removed_groups():
    previous = {"OLDGROUP": {"ipv4": {"1.1.1.1"}}}
    current = {"NEWGROUP": {"ipv4": {"2.2.2.2"}}}

    events = diff_indicators(previous, current)

    assert {"group": "NEWGROUP", "type": "ipv4", "action": "added", "value": "2.2.2.2"} in events
    assert {"group": "OLDGROUP", "type": "ipv4", "action": "removed", "value": "1.1.1.1"} in events


def test_diff_is_empty_for_identical_input():
    index = {"APT28": {"domain": {"a.com"}}}

    assert diff_indicators(index, dict(index)) == []


def test_index_current_matches_loaded_shape():
    metadata = APTGroupMetadata(filename="apt_x.txt")
    group = APTGroup(name="X", metadata=metadata)
    group.add_indicator(Indicator(value="a.com", indicator_type=IndicatorType.DOMAIN))

    assert index_current({"X": group}) == {"X": {"domain": {"a.com"}}}


def test_append_changes_writes_monthly_jsonl(tmp_path):
    events = [{"group": "APT28", "type": "domain", "action": "added", "value": "new.com"}]

    written = append_changes(tmp_path, events, TS)

    assert written.name == "2026-07.jsonl"
    record = json.loads(written.read_text(encoding="utf-8").strip())
    assert record == {
        "ts": "2026-07-26T04:00:00",
        "group": "APT28",
        "type": "domain",
        "action": "added",
        "value": "new.com",
    }


def test_append_changes_appends_rather_than_overwrites(tmp_path):
    append_changes(tmp_path, [{"group": "A", "type": "domain", "action": "added", "value": "1.com"}], TS)
    append_changes(tmp_path, [{"group": "B", "type": "domain", "action": "added", "value": "2.com"}], TS)

    lines = (tmp_path / "2026-07.jsonl").read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2


def test_append_changes_writes_nothing_when_no_events(tmp_path):
    assert append_changes(tmp_path, [], TS) is None
    assert list(tmp_path.iterdir()) == []
