import json

import pytest

from apttrail.exporters.slices import SliceExporter
from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType


def group(name, values, **metadata_kwargs):
    apt = APTGroup(name=name, metadata=APTGroupMetadata(filename=f"apt_{name.lower()}.txt", **metadata_kwargs))
    for value, indicator_type in values:
        apt.add_indicator(Indicator(value=value, indicator_type=indicator_type))
    return apt


@pytest.fixture
def feed():
    return {
        "APT28": group(
            "APT28",
            [
                ("fancy.example", IndicatorType.DOMAIN),
                ("bear.example", IndicatorType.DOMAIN),
                ("1.2.3.4:8080", IndicatorType.IPV4),
            ],
            attack_id="G0007",
            attack_name="APT28",
            attack_url="https://attack.mitre.org/groups/G0007/",
            aliases=["Fancy Bear"],
        ),
        "UNMAPPED": group("UNMAPPED", [("lonely.example", IndicatorType.DOMAIN)]),
        "EMPTY": group("EMPTY", []),
    }


@pytest.fixture
def written(tmp_path, feed):
    SliceExporter(tmp_path).export(feed, FeedMetadata())
    return tmp_path


class TestByType:
    def test_flat_domain_list_merges_every_group(self, written):
        lines = self._values(written / "by-type" / "domain.txt")

        assert lines == ["bear.example", "fancy.example", "lonely.example"]

    def test_ip_list_drops_the_port(self, written):
        # A blocklist consumer wants the address, not host:port.
        assert self._values(written / "by-type" / "ipv4.txt") == ["1.2.3.4"]

    def test_banner_is_commented_so_the_file_stays_greppable(self, written):
        text = (written / "by-type" / "domain.txt").read_text("utf-8")

        assert text.startswith("#")
        assert "github.com/trilwu/apttrail" in text

    def test_absent_types_produce_no_file(self, written):
        assert not (written / "by-type" / "sha256.txt").exists()

    @staticmethod
    def _values(path):
        return [line for line in path.read_text("utf-8").splitlines() if not line.startswith("#")]


class TestByGroup:
    def test_mapped_group_is_named_by_attack_id(self, written):
        # An ATT&CK-driven workflow can construct the path directly.
        assert (written / "by-group" / "G0007.json").exists()
        assert (written / "by-group" / "G0007-domain.txt").exists()

    def test_unmapped_group_falls_back_to_the_maltrail_name(self, written):
        assert (written / "by-group" / "UNMAPPED.json").exists()

    def test_group_file_carries_attribution_and_indicators(self, written):
        payload = json.loads((written / "by-group" / "G0007.json").read_text("utf-8"))

        assert payload["attack_id"] == "G0007"
        assert payload["attack_url"] == "https://attack.mitre.org/groups/G0007/"
        assert payload["aliases"] == ["Fancy Bear"]
        assert payload["indicators"]["domain"] == ["bear.example", "fancy.example"]
        assert payload["counts"]["domain"] == 2

    def test_group_without_indicators_is_skipped(self, written):
        assert not (written / "by-group" / "EMPTY.json").exists()

    def test_group_without_domains_gets_no_domain_list(self, tmp_path):
        only_ips = {"IPONLY": group("IPONLY", [("9.9.9.9", IndicatorType.IPV4)])}

        SliceExporter(tmp_path).export(only_ips, FeedMetadata())

        assert (tmp_path / "by-group" / "IPONLY.json").exists()
        assert not (tmp_path / "by-group" / "IPONLY-domain.txt").exists()


class TestIndex:
    def test_index_reports_attack_coverage(self, written):
        payload = json.loads((written / "index.json").read_text("utf-8"))

        assert payload["totals"]["groups"] == 2  # EMPTY is excluded
        assert payload["totals"]["groups_mapped_to_attack"] == 1
        assert payload["totals"]["indicators"] == 4

    def test_index_lets_a_client_find_a_group_without_downloading_it(self, written):
        payload = json.loads((written / "index.json").read_text("utf-8"))

        entry = next(e for e in payload["groups"] if e["group"] == "APT28")
        assert entry["slug"] == "G0007"
        assert entry["attack_name"] == "APT28"
        assert entry["counts"] == {"domain": 2, "ipv4": 1}


def test_export_is_idempotent(tmp_path, feed):
    exporter = SliceExporter(tmp_path)
    exporter.export(feed, FeedMetadata(generated_at=FeedMetadata().generated_at))
    first = (tmp_path / "by-type" / "domain.txt").read_text("utf-8")

    exporter.export(feed, FeedMetadata(generated_at=FeedMetadata().generated_at))

    assert (tmp_path / "by-type" / "domain.txt").read_text("utf-8").count("bear.example") == 1
    assert first.count("bear.example") == 1
