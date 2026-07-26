import argparse
from pathlib import Path

import pytest

from apttrail import cli

ALL_FORMATS = ["json", "csv", "stix", "suricata", "yara", "misp", "sigma"]


def namespace(**overrides):
    """Build an args namespace with every format flag off by default."""
    args = {f"{fmt}_only": False for fmt in ALL_FORMATS}
    args.update(overrides)
    return argparse.Namespace(**args)


def test_no_flag_exports_every_format():
    assert cli.get_export_formats(namespace()) == ALL_FORMATS


@pytest.mark.parametrize("fmt", ALL_FORMATS)
def test_single_flag_selects_only_that_format(fmt):
    assert cli.get_export_formats(namespace(**{f"{fmt}_only": True})) == [fmt]


def test_flags_combine():
    args = namespace(json_only=True, sigma_only=True)

    assert cli.get_export_formats(args) == ["json", "sigma"]


def run_cli(monkeypatch, *argv):
    monkeypatch.setattr("sys.argv", ["apttrail", *argv])
    return cli.main()


def test_main_collects_and_exports(monkeypatch, maltrail_repo, tmp_path):
    out = tmp_path / "out"

    code = run_cli(
        monkeypatch,
        "--maltrail-path",
        str(maltrail_repo),
        "--no-update",
        "--output-dir",
        str(out),
        "--json-only",
    )

    assert code == 0
    assert (out / "apttrail_threat_feed.json").exists()


def test_main_honours_collect_timestamps(monkeypatch, maltrail_repo, tmp_path):
    out = tmp_path / "out"

    code = run_cli(
        monkeypatch,
        "--maltrail-path",
        str(maltrail_repo),
        "--no-update",
        "--output-dir",
        str(out),
        "--cache-dir",
        str(tmp_path / "cache"),
        "--json-only",
        "--collect-timestamps",
    )

    assert code == 0
    assert "first_seen" in (out / "apttrail_threat_feed.json").read_text("utf-8")


def test_deprecated_no_timestamps_still_wins(monkeypatch, maltrail_repo, tmp_path):
    out = tmp_path / "out"

    run_cli(
        monkeypatch,
        "--maltrail-path",
        str(maltrail_repo),
        "--no-update",
        "--output-dir",
        str(out),
        "--cache-dir",
        str(tmp_path / "cache"),
        "--json-only",
        "--collect-timestamps",
        "--no-timestamps",
    )

    assert "first_seen" not in (out / "apttrail_threat_feed.json").read_text("utf-8")


def test_force_refresh_invalidates_cache(monkeypatch, maltrail_repo, tmp_path):
    cache_dir = tmp_path / "cache"
    args = [
        "--maltrail-path",
        str(maltrail_repo),
        "--no-update",
        "--output-dir",
        str(tmp_path / "out"),
        "--cache-dir",
        str(cache_dir),
        "--json-only",
        "--collect-timestamps",
    ]
    run_cli(monkeypatch, *args)

    assert run_cli(monkeypatch, *args, "--force-refresh") == 0


def test_main_reports_failed_repository_update(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "apttrail.collector.APTThreatFeedCollector.update_repository",
        lambda _self: False,
    )

    code = run_cli(monkeypatch, "--maltrail-path", str(tmp_path / "nope"), "--output-dir", str(tmp_path / "out"))

    assert code == 1


def test_main_returns_error_code_on_exception(monkeypatch, tmp_path):
    def boom(_self):
        raise RuntimeError("collection exploded")

    monkeypatch.setattr("apttrail.collector.APTThreatFeedCollector.collect_indicators", boom)

    code = run_cli(monkeypatch, "--maltrail-path", str(tmp_path), "--no-update", "--output-dir", str(tmp_path / "out"))

    assert code == 1


def test_output_dir_defaults_to_feeds(monkeypatch):
    monkeypatch.setattr("sys.argv", ["apttrail"])

    assert Path(cli.parse_args().output_dir) == Path("feeds")
