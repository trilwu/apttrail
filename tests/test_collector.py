import json
from datetime import datetime
from pathlib import Path

from apttrail.collector import APTThreatFeedCollector
from apttrail.models import CollectorConfig, FeedExportConfig, IndicatorType

SECOND_COMMIT_DATE = "2026-04-01T10:00:00+00:00"


def collect(config):
    collector = APTThreatFeedCollector(config)
    collector.collect_indicators()
    return collector


def test_collect_parses_groups_from_filenames(collector_config):
    collector = collect(collector_config)

    assert set(collector.apt_groups) == {"DEMO", "OTHER"}


def test_collect_classifies_every_indicator_type(collector_config):
    collector = collect(collector_config)
    demo = collector.apt_groups["DEMO"]

    assert demo.indicator_counts == {"domain": 1, "ipv4": 1, "url": 1, "md5": 1}


def test_collect_extracts_aliases_and_references(collector_config):
    collector = collect(collector_config)
    metadata = collector.apt_groups["DEMO"].metadata

    assert metadata.aliases == ["demo-group", "demoapt"]
    assert metadata.references == ["https://example.com/report"]


def test_indicators_carry_the_report_they_were_filed_under(collector_config, maltrail_repo):
    # Upstream groups indicators under the write-up they came from. That
    # association is the only per-indicator provenance the feed can offer.
    trail = maltrail_repo / "trails" / "static" / "malware" / "apt_sourced.txt"
    trail.write_text(
        "# Reference: https://vendor.test/report-a\nalpha.com\n\n# Reference: https://vendor.test/report-b\nbeta.com\n",
        encoding="utf-8",
    )

    collector = collect(collector_config)

    by_value = {i.value: i for i in collector.apt_groups["SOURCED"].indicators[IndicatorType.DOMAIN]}
    assert by_value["alpha.com"].references == ["https://vendor.test/report-a"]
    assert by_value["beta.com"].references == ["https://vendor.test/report-b"]


def test_last_modified_is_the_real_commit_time(collector_config):
    # A wall-clock fallback here was what produced ~4,000 no-op feed commits.
    collector = collect(collector_config)

    last_modified = collector.apt_groups["DEMO"].metadata.last_modified
    assert last_modified == datetime.fromisoformat("2026-03-01T10:00:00+00:00")


def test_last_modified_is_none_when_file_has_no_history(collector_config, maltrail_repo):
    untracked = maltrail_repo / "trails" / "static" / "malware" / "apt_untracked.txt"
    untracked.write_text("ghost.com\n", encoding="utf-8")

    collector = collect(collector_config)

    assert collector.apt_groups["UNTRACKED"].metadata.last_modified is None


def test_repo_key_returns_none_outside_repository(collector_config):
    collector = APTThreatFeedCollector(collector_config)

    assert collector._repo_key(Path("/somewhere/else/apt_x.txt")) is None


def test_missing_apt_directory_is_reported_not_raised(tmp_path):
    config = CollectorConfig(
        maltrail_path=str(tmp_path / "nothing-here"),
        auto_update=False,
        export_config=FeedExportConfig(output_dir=str(tmp_path / "out")),
    )

    collector = collect(config)

    assert collector.apt_groups == {}


def test_update_repository_is_skipped_when_auto_update_off(collector_config):
    assert APTThreatFeedCollector(collector_config).update_repository() is True


class TestTimestamps:
    def config_with_timestamps(self, collector_config):
        return collector_config.model_copy(
            update={"export_config": collector_config.export_config.model_copy(update={"collect_timestamps": True})}
        )

    def test_first_seen_comes_from_upstream_blame(self, collector_config):
        collector = collect(self.config_with_timestamps(collector_config))

        indicators = collector.apt_groups["DEMO"].indicators[IndicatorType.DOMAIN]
        assert {i.first_seen.isoformat() for i in indicators} == {"2026-03-01T10:00:00+00:00"}

    def test_cached_run_still_reports_first_seen(self, collector_config):
        config = self.config_with_timestamps(collector_config)
        collect(config)

        # Second run: nothing upstream moved, so no file is re-blamed and the
        # timestamps must come back out of the cache.
        collector = collect(config)

        indicators = collector.apt_groups["DEMO"].indicators[IndicatorType.DOMAIN]
        assert all(i.first_seen is not None for i in indicators)

    def test_changed_file_is_reblamed(self, collector_config, maltrail_repo, git_commit):
        config = self.config_with_timestamps(collector_config)
        collect(config)

        demo = maltrail_repo / "trails" / "static" / "malware" / "apt_demo.txt"
        demo.write_text(demo.read_text(encoding="utf-8") + "fresh.com\n", encoding="utf-8")
        git_commit(maltrail_repo, "add fresh")

        collector = collect(config)

        by_value = {i.value: i for i in collector.apt_groups["DEMO"].indicators[IndicatorType.DOMAIN]}
        assert by_value["fresh.com"].first_seen == datetime.fromisoformat(SECOND_COMMIT_DATE)


class TestExport:
    def test_writes_every_requested_format(self, collector_config):
        config = collector_config.model_copy(
            update={
                "export_config": collector_config.export_config.model_copy(
                    update={"formats": ["json", "csv", "stix", "suricata", "yara", "misp", "sigma"]}
                )
            }
        )
        collector = collect(config)
        collector.export_feeds()

        out = Path(config.export_config.output_dir)
        written = {p.name for p in out.iterdir() if p.is_file()}
        assert written == {
            "apttrail_threat_feed.json",
            "apttrail_threat_feed.csv",
            "apttrail_threat_feed_metadata.csv",  # side-car written by the CSV exporter
            "apttrail_threat_feed_stix.json",
            "apttrail_threat_feed.rules",
            "apttrail_threat_feed.yar",
            "apttrail_threat_feed_misp.json",
            "apttrail_threat_feed.yaml",
        }

    def test_json_carries_real_generated_at(self, collector_config):
        collector = collect(collector_config)
        collector.export_feeds()

        data = json.loads(
            (Path(collector_config.export_config.output_dir) / "apttrail_threat_feed.json").read_text("utf-8")
        )
        assert data["generated_at"].startswith("20")
        assert data["generated_at"] != "2024-01-01T00:00:00"


class TestChangelog:
    def test_baseline_run_records_nothing(self, collector_config):
        collector = collect(collector_config)
        collector.export_feeds()

        assert not (Path(collector_config.export_config.output_dir) / "changes").exists()

    def test_second_run_records_additions_and_removals(self, collector_config, maltrail_repo):
        collector = collect(collector_config)
        collector.export_feeds()

        demo = maltrail_repo / "trails" / "static" / "malware" / "apt_demo.txt"
        demo.write_text(demo.read_text(encoding="utf-8").replace("keep.com", "swapped.com"), encoding="utf-8")

        collector = collect(collector_config)
        collector.export_feeds()

        log = next((Path(collector_config.export_config.output_dir) / "changes").iterdir())
        events = [json.loads(line) for line in log.read_text("utf-8").splitlines()]
        actions = {(e["action"], e["value"]) for e in events}
        assert ("added", "swapped.com") in actions
        assert ("removed", "keep.com") in actions

    def test_can_be_disabled(self, collector_config, maltrail_repo):
        config = collector_config.model_copy(
            update={"export_config": collector_config.export_config.model_copy(update={"write_changelog": False})}
        )
        collector = collect(config)
        collector.export_feeds()

        demo = maltrail_repo / "trails" / "static" / "malware" / "apt_demo.txt"
        demo.write_text("changed.com\n", encoding="utf-8")
        collector = collect(config)
        collector.export_feeds()

        assert not (Path(config.export_config.output_dir) / "changes").exists()
