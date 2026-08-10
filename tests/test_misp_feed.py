"""MISP feed exporter tests.

The README previously told people to add a single event JSON as a "MISP Feed".
That fails: a feed is manifest.json plus one file per event. These tests pin the
layout MISP actually reads.
"""

import json

import pytest

from apttrail.exporters.misp_feed import MISPFeedExporter
from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType


def group(name, values, **metadata_kwargs):
    apt = APTGroup(name=name, metadata=APTGroupMetadata(filename=f"apt_{name.lower()}.txt", **metadata_kwargs))
    for value, indicator_type in values:
        apt.add_indicator(Indicator(value=value, indicator_type=indicator_type))
    return apt


@pytest.fixture
def feed():
    return {
        "SOFACY": group(
            "SOFACY",
            [("fancy.example", IndicatorType.DOMAIN), ("1.2.3.4:8080", IndicatorType.IPV4)],
            attack_id="G0007",
            attack_name="APT28",
            attack_url="https://attack.mitre.org/groups/G0007/",
        ),
        "UNMAPPED": group("UNMAPPED", [("lonely.example", IndicatorType.DOMAIN)]),
        "EMPTY": group("EMPTY", []),
    }


@pytest.fixture
def written(tmp_path, feed):
    MISPFeedExporter(tmp_path).export(feed, FeedMetadata())
    return tmp_path


def manifest(path):
    return json.loads((path / "manifest.json").read_text("utf-8"))


class TestLayout:
    def test_manifest_and_one_file_per_event_exist(self, written):
        entries = manifest(written)

        assert len(entries) == 2  # EMPTY contributes nothing
        for event_uuid in entries:
            assert (written / f"{event_uuid}.json").exists()

    def test_hashes_csv_is_written(self, written):
        rows = (written / "hashes.csv").read_text("utf-8").strip().splitlines()

        # One row per attribute value across both events.
        assert len(rows) == 3
        assert all(len(row.split(",")) == 2 for row in rows)

    def test_manifest_entry_carries_what_misp_reads(self, written):
        entry = next(iter(manifest(written).values()))

        assert set(entry) >= {"Orgc", "Tag", "info", "date", "analysis", "threat_level_id", "timestamp"}
        assert entry["Orgc"]["name"] == "APTtrail"

    def test_event_file_is_a_wrapped_misp_event(self, written):
        event_uuid = next(iter(manifest(written)))
        payload = json.loads((written / f"{event_uuid}.json").read_text("utf-8"))

        assert set(payload) == {"Event"}
        event = payload["Event"]
        assert event["uuid"] == event_uuid
        assert event["published"] is True
        assert event["Orgc"]["name"] == "APTtrail"


class TestPerActorEvents:
    def event_for(self, path, name_fragment):
        for event_uuid, entry in manifest(path).items():
            if name_fragment in entry["info"]:
                return json.loads((path / f"{event_uuid}.json").read_text("utf-8"))["Event"]
        raise AssertionError(f"no event mentioning {name_fragment}")

    def test_one_event_per_group_not_one_giant_event(self, written):
        # The previous exporter emitted a single event with 155,210 attributes.
        infos = sorted(entry["info"] for entry in manifest(written).values())

        assert infos == [
            "APTtrail: APT28 (G0007) - Maltrail group SOFACY",
            "APTtrail: UNMAPPED",
        ]

    def test_mapped_group_gets_the_galaxy_tag(self, written):
        event = self.event_for(written, "G0007")
        tags = [tag["name"] for tag in event["Tag"]]

        assert 'misp-galaxy:mitre-intrusion-set="APT28 - G0007"' in tags
        assert "apt:sofacy" in tags
        assert "tlp:clear" in tags

    def test_unmapped_group_has_no_galaxy_tag(self, written):
        event = self.event_for(written, "UNMAPPED")
        tags = [tag["name"] for tag in event["Tag"]]

        assert not any(tag.startswith("misp-galaxy:") for tag in tags)

    def test_attributes_are_typed_and_flagged_for_ids(self, written):
        event = self.event_for(written, "G0007")
        by_value = {attribute["value"]: attribute for attribute in event["Attribute"]}

        assert by_value["fancy.example"]["type"] == "domain"
        assert by_value["1.2.3.4:8080"]["type"] == "ip-dst"
        assert all(attribute["to_ids"] for attribute in event["Attribute"])
        assert all(attribute["category"] for attribute in event["Attribute"])


class TestStability:
    def test_uuids_are_stable_across_runs(self, tmp_path, feed):
        first = tmp_path / "a"
        second = tmp_path / "b"

        MISPFeedExporter(first).export(feed, FeedMetadata())
        MISPFeedExporter(second).export(feed, FeedMetadata())

        # Re-fetching must update events in place, not duplicate them.
        assert sorted(manifest(first)) == sorted(manifest(second))

    def test_attribute_uuids_are_stable(self, tmp_path, feed):
        first = tmp_path / "a"
        second = tmp_path / "b"
        MISPFeedExporter(first).export(feed, FeedMetadata())
        MISPFeedExporter(second).export(feed, FeedMetadata())

        event_uuid = next(iter(manifest(first)))
        left = json.loads((first / f"{event_uuid}.json").read_text("utf-8"))["Event"]["Attribute"]
        right = json.loads((second / f"{event_uuid}.json").read_text("utf-8"))["Event"]["Attribute"]

        assert [a["uuid"] for a in left] == [a["uuid"] for a in right]


def test_returns_the_event_count(tmp_path, feed):
    assert MISPFeedExporter(tmp_path).export(feed, FeedMetadata()) == 2


class TestDirectoryPage:
    """
    MISP appends /manifest.json, so the bare feed URL returning 404 broke
    nothing in the software - and blocked the pull request for a week, because
    the first thing MISP's maintainer did was open the URL.
    """

    def test_the_feed_directory_serves_something(self, tmp_path, sample_apt_group, sample_metadata):
        MISPFeedExporter(tmp_path).export({"TEST": sample_apt_group}, sample_metadata)

        assert (tmp_path / "index.html").exists()

    def test_it_explains_what_the_url_is_for(self, tmp_path, sample_apt_group, sample_metadata):
        MISPFeedExporter(tmp_path).export({"TEST": sample_apt_group}, sample_metadata)
        page = (tmp_path / "index.html").read_text("utf-8")

        assert "MISP feed directory" in page
        assert "Add Feed" in page
        assert 'href="manifest.json"' in page
        assert 'href="hashes.csv"' in page

    def test_it_does_not_disturb_the_feed_itself(self, tmp_path, sample_apt_group, sample_metadata):
        events = MISPFeedExporter(tmp_path).export({"TEST": sample_apt_group}, sample_metadata)
        manifest = json.loads((tmp_path / "manifest.json").read_text("utf-8"))

        # index.html is inert: the manifest still lists exactly the events.
        assert len(manifest) == events
        assert "index.html" not in manifest
