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
