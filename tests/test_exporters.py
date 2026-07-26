import json

from apttrail.exporters import CSVExporter, JSONExporter, STIXExporter, SuricataExporter, YARAExporter


def test_json_export(tmp_path, sample_apt_group, sample_metadata):
    output_file = tmp_path / "feed.json"
    exporter = JSONExporter(output_file)

    exporter.export({"TEST": sample_apt_group}, sample_metadata)

    assert output_file.exists()
    data = json.loads(output_file.read_text("utf-8"))
    assert data["source"] == "Maltrail APT Indicators"
    assert "TEST" in data["apt_groups"]
    assert len(data["apt_groups"]["TEST"]["indicators"]["ipv4"]) == 1


def test_csv_compact_export(tmp_path, sample_apt_group, sample_metadata):
    output_file = tmp_path / "feed.csv"
    exporter = CSVExporter(output_file, compact=True)

    exporter.export({"TEST": sample_apt_group}, sample_metadata)

    assert output_file.exists()
    lines = output_file.read_text("utf-8").splitlines()
    assert len(lines) >= 3  # Header + 2 indicators


def test_stix_export(tmp_path, sample_apt_group, sample_metadata):
    output_file = tmp_path / "feed_stix.json"
    exporter = STIXExporter(output_file)

    exporter.export({"TEST": sample_apt_group}, sample_metadata)

    assert output_file.exists()
    data = json.loads(output_file.read_text("utf-8"))
    assert data["type"] == "bundle"
    assert len(data["objects"]) > 0


def test_suricata_export(tmp_path, sample_apt_group, sample_metadata):
    output_file = tmp_path / "feed.rules"
    exporter = SuricataExporter(output_file)

    exporter.export({"TEST": sample_apt_group}, sample_metadata)

    assert output_file.exists()
    content = output_file.read_text("utf-8")
    # Rule-level behaviour is pinned in test_suricata.py; this is a smoke test.
    assert "alert ip $HOME_NET any -> 1.2.3.4 any" in content
    assert 'msg:"APTtrail TEST - traffic to 1.2.3.4"' in content


def test_yara_export(tmp_path, sample_apt_group, sample_metadata):
    output_file = tmp_path / "feed.yar"
    exporter = YARAExporter(output_file)

    exporter.export({"TEST": sample_apt_group}, sample_metadata)

    assert output_file.exists()
    content = output_file.read_text("utf-8")
    assert "rule APT_TEST" in content
    assert '"1.2.3.4"' in content
    assert "$domain0" in content  # Check domain is also there


class TestYaraHonesty:
    """The feed has no file hashes, so the rules must not imply otherwise."""

    def build(self, tmp_path, values):
        from apttrail.exporters import YARAExporter
        from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator

        apt = APTGroup(name="T", metadata=APTGroupMetadata(filename="apt_t.txt"))
        for value, indicator_type in values:
            apt.add_indicator(Indicator(value=value, indicator_type=indicator_type))

        out = tmp_path / "feed.yar"
        YARAExporter(out).export({"T": apt}, FeedMetadata())
        return out.read_text("utf-8")

    def test_hashless_feed_says_so_and_skips_the_hash_import(self, tmp_path):
        from apttrail.models import IndicatorType

        content = self.build(tmp_path, [("evil.com", IndicatorType.DOMAIN)])

        assert "match indicator STRINGS" in content
        assert 'import "hash"' not in content
        assert 'import "pe"' not in content  # was imported but never used

    def test_hash_import_appears_only_when_needed(self, tmp_path):
        from apttrail.models import IndicatorType

        content = self.build(tmp_path, [("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.MD5)])

        assert 'import "hash"' in content
        assert "match indicator STRINGS" not in content

    def test_sha1_gets_a_condition(self, tmp_path):
        from apttrail.models import IndicatorType

        content = self.build(tmp_path, [("da39a3ee5e6b4b0d3255bfef95601890afd80709", IndicatorType.SHA1)])

        assert "hash.sha1(0, filesize)" in content

    def test_indicators_are_not_truncated(self, tmp_path):
        from apttrail.models import IndicatorType

        values = [(f"h{i}.example", IndicatorType.DOMAIN) for i in range(150)]
        content = self.build(tmp_path, values)

        assert content.count("$domain") == 150  # previously capped at 100

    def test_quote_in_a_value_is_escaped(self, tmp_path):
        from apttrail.models import IndicatorType

        content = self.build(tmp_path, [('ev"il.example', IndicatorType.DOMAIN)])

        assert '\\"' in content
