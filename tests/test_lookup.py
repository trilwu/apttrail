"""Per-indicator lookup index tests.

The index answers the question the rest of the feed cannot: given one indicator
from an alert, what do we know about it, without downloading everything.
"""

import hashlib
import json
from datetime import datetime

import pytest

from apttrail.exporters.lookup import LookupExporter, canonical, shard_for
from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType


def group(name, values, **metadata_kwargs):
    apt = APTGroup(name=name, metadata=APTGroupMetadata(filename=f"apt_{name.lower()}.txt", **metadata_kwargs))
    for value, indicator_type, first_seen in values:
        apt.add_indicator(Indicator(value=value, indicator_type=indicator_type, first_seen=first_seen))
    return apt


@pytest.fixture
def feed():
    return {
        "SOFACY": group(
            "SOFACY",
            [
                ("shared.example", IndicatorType.DOMAIN, datetime(2020, 5, 1)),
                ("fancy.example", IndicatorType.DOMAIN, datetime(2019, 1, 2)),
                ("1.2.3.4:8080", IndicatorType.IPV4, None),
            ],
            attack_id="G0007",
            attack_name="APT28",
        ),
        # The same domain attributed to a second actor, seen earlier there.
        "OTHER": group("OTHER", [("shared.example", IndicatorType.DOMAIN, datetime(2018, 3, 4))]),
    }


@pytest.fixture
def written(tmp_path, feed):
    LookupExporter(tmp_path).export(feed, FeedMetadata())
    return tmp_path


def entry_for(path, value):
    payload = json.loads((path / "by-indicator" / f"{shard_for(value)}.json").read_text("utf-8"))
    return payload[value]


class TestSharding:
    def test_shard_is_the_first_byte_of_sha256(self):
        assert shard_for("evil.example") == hashlib.sha256(b"evil.example").hexdigest()[:2]

    def test_a_client_can_compute_the_path_offline(self, written):
        # This is the whole point: no server-side query needed.
        value = "fancy.example"
        expected = written / "by-indicator" / f"{hashlib.sha256(value.encode()).hexdigest()[:2]}.json"

        assert expected.exists()
        assert value in json.loads(expected.read_text("utf-8"))

    def test_index_documents_the_scheme(self, written):
        index = json.loads((written / "by-indicator" / "index.json").read_text("utf-8"))

        assert index["indicators"] == 3
        assert "sha256" in index["scheme"]
        assert index["shards"]


class TestEntries:
    def test_entry_carries_type_group_and_attribution(self, written):
        entry = entry_for(written, "fancy.example")

        assert entry["type"] == "domain"
        assert entry["groups"] == ["SOFACY"]
        assert entry["attack_ids"] == ["G0007"]
        assert entry["first_seen"] == "2019-01-02"

    def test_indicator_shared_by_two_actors_lists_both(self, written):
        entry = entry_for(written, "shared.example")

        assert sorted(entry["groups"]) == ["OTHER", "SOFACY"]

    def test_earliest_first_seen_wins_across_groups(self, written):
        entry = entry_for(written, "shared.example")

        # SOFACY saw it in 2020, OTHER in 2018.
        assert entry["first_seen"] == "2018-03-04"

    def test_unmapped_group_contributes_no_attack_id(self, written):
        entry = entry_for(written, "shared.example")

        assert entry["attack_ids"] == ["G0007"]

    def test_missing_first_seen_is_omitted_not_null(self, written):
        entry = entry_for(written, "1.2.3.4")

        assert "first_seen" not in entry
        assert entry["type"] == "ipv4"


class TestCanonicalKeys:
    """A responder pastes what their alert showed, not what upstream stored."""

    def test_a_bare_address_finds_an_indicator_recorded_with_a_port(self, written):
        # Upstream holds "1.2.3.4:8080". Keying on that verbatim meant a lookup
        # for the address landed on the wrong shard and returned nothing,
        # which reads exactly like "not a known indicator".
        entry = entry_for(written, "1.2.3.4")

        assert entry["type"] == "ipv4"
        assert entry["seen_as"] == ["1.2.3.4:8080"]

    def test_the_port_form_is_not_a_separate_key(self, written):
        payload = json.loads(
            (written / "by-indicator" / f"{shard_for(canonical('1.2.3.4:8080', IndicatorType.IPV4))}.json").read_text(
                "utf-8"
            )
        )

        assert "1.2.3.4:8080" not in payload

    def test_case_is_folded(self):
        assert canonical("Evil.EXAMPLE") == "evil.example"

    def test_only_ipv4_loses_its_port(self):
        # An IPv6 address is mostly colons and a URL's colon is its scheme.
        assert canonical("2001:db8::1", IndicatorType.IPV6) == "2001:db8::1"
        assert canonical("http://evil.example/x", IndicatorType.URL) == "http://evil.example/x"

    def test_the_rule_is_published_for_clients(self, written):
        index = json.loads((written / "by-indicator" / "index.json").read_text("utf-8"))

        assert "lowercase" in index["canonical"]
        assert ":port" in index["canonical"]


def test_returns_the_indicator_count(tmp_path, feed):
    assert LookupExporter(tmp_path).export(feed, FeedMetadata()) == 3


def test_shards_are_evenly_spread(tmp_path):
    # Hash sharding must not degenerate when values share prefixes.
    values = [(f"host{i}.example", IndicatorType.DOMAIN, None) for i in range(2000)]
    LookupExporter(tmp_path).export({"G": group("G", values)}, FeedMetadata())

    shards = [p for p in (tmp_path / "by-indicator").iterdir() if p.name != "index.json"]
    sizes = [len(json.loads(p.read_text("utf-8"))) for p in shards]

    assert len(shards) > 200
    assert max(sizes) < 40  # 2000/256 is ~8; a bad scheme would pile up
