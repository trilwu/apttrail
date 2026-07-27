import json
import re
from datetime import datetime, timezone

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

        assert payload["maltrail_groups"] == ["APT28"]
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


class TestProvenance:
    """Every indicator should be traceable to the report that published it."""

    @pytest.fixture
    def sourced(self, tmp_path):
        apt = APTGroup(name="APT28", metadata=APTGroupMetadata(filename="apt_apt28.txt"))
        apt.add_indicator(
            Indicator(
                value="fresh.example",
                indicator_type=IndicatorType.DOMAIN,
                first_seen=datetime(2026, 3, 21, tzinfo=timezone.utc),
                first_seen_precision="exact",
                references=["https://vendor.test/march-report"],
            )
        )
        apt.add_indicator(
            Indicator(
                value="9.9.9.9",
                indicator_type=IndicatorType.IPV4,
                first_seen=datetime(2026, 1, 3, tzinfo=timezone.utc),
                first_seen_precision="at-or-before",
            )
        )
        SliceExporter(tmp_path).export({"APT28": apt}, FeedMetadata())
        return tmp_path

    def payload(self, sourced):
        return json.loads((sourced / "by-group" / "APT28.json").read_text("utf-8"))

    def test_json_timeline_records_the_source_of_each_batch(self, sourced):
        newest = self.payload(sourced)["timeline"][0]

        assert newest["first_seen"] == "2026-03-21"
        assert newest["references"] == ["https://vendor.test/march-report"]
        assert newest["indicators"] == {"domain": ["fresh.example"]}
        assert newest["counts"] == {"domain": 1}

    def test_json_timeline_is_newest_first(self, sourced):
        assert [b["first_seen"] for b in self.payload(sourced)["timeline"]] == ["2026-03-21", "2026-01-03"]

    def test_only_dates_that_are_a_floor_are_flagged(self, sourced):
        precision = self.payload(sourced)["first_seen_precision"]

        assert precision["ipv4"] == {"9.9.9.9": "at-or-before"}
        assert precision["domain"] == {}

    def test_the_page_puts_the_report_link_beside_its_indicator(self, sourced):
        page = (sourced / "by-group" / "APT28.html").read_text("utf-8")

        assert 'href="https://vendor.test/march-report"' in page
        assert page.index("march-report") < page.index("fresh.example")


class TestIndex:
    def test_index_reports_attack_coverage(self, written):
        payload = json.loads((written / "index.json").read_text("utf-8"))

        assert payload["totals"]["slices"] == 2  # EMPTY is excluded
        assert payload["totals"]["maltrail_groups"] == 2
        assert payload["totals"]["maltrail_groups_mapped_to_attack"] == 1
        assert payload["totals"]["attack_groups"] == 1
        assert payload["totals"]["indicators"] == 4

    def test_index_lets_a_client_find_a_group_without_downloading_it(self, written):
        payload = json.loads((written / "index.json").read_text("utf-8"))

        entry = next(e for e in payload["groups"] if e["slug"] == "G0007")
        assert entry["maltrail_groups"] == ["APT28"]
        assert entry["attack_name"] == "APT28"
        assert entry["counts"] == {"domain": 2, "ipv4": 1}


class TestLandingPage:
    """Most arrivals hold a vendor name, not an ATT&CK id."""

    @pytest.fixture
    def page(self, written):
        return (written / "index.html").read_text("utf-8")

    def test_an_alias_that_is_not_printed_is_still_searchable(self, tmp_path):
        # APT28 has 24 aliases; printing them all would drown the table, but a
        # reader holding "Fancy Bear" must still find the row.
        many = [f"alias-{i}" for i in range(12)] + ["fancy bear"]
        apt = group("SOFACY", [("a.example", IndicatorType.DOMAIN)], attack_name="APT28", aliases=many)
        SliceExporter(tmp_path).export({"SOFACY": apt}, FeedMetadata())

        page = (tmp_path / "index.html").read_text("utf-8")
        row = page.split("<tbody id=grouplist>")[1]
        key = row.split('data-k="')[1].split('"')[0]
        printed = row.split("<div class=aka>")[1].split("</div>")[0]

        assert "fancy bear" in key
        assert "fancy bear" not in printed  # it sorts past the six shown
        assert "+7" in printed  # and the reader is told how many are hidden

    def test_the_maltrail_name_is_shown_beside_the_attack_name(self, page):
        # by-group files are keyed on one and headed by the other.
        assert "APT28" in page
        assert "Fancy Bear" in page

    def test_nothing_is_fetched_from_another_origin(self, page):
        assert "<link rel=stylesheet" not in page
        assert "<script src" not in page
        assert "googleapis" not in page
        for href in re.findall(r'<link[^>]*href="([^"]+)"', page):
            assert href.startswith(("data:", "https://trilwu.github.io/")), href

    def test_it_carries_a_link_preview(self, page):
        assert 'property="og:title"' in page
        assert "rel=canonical" in page

    def test_it_uses_the_same_design_tokens_as_the_actor_pages(self, page, written):
        actor = (written / "by-group" / "G0007.html").read_text("utf-8")

        assert "--accent" in page and "--accent" in actor
        assert "class=stats" in page and "class=stats" in actor

    def test_the_filter_is_hidden_until_script_reveals_it(self, page):
        assert "id=tools hidden" in page


class TestActivityPage:
    """Every other view is keyed on an actor, which needs a name to start from."""

    @pytest.fixture
    def site(self, tmp_path):
        apt = APTGroup(
            name="APT28",
            metadata=APTGroupMetadata(filename="apt_sofacy.txt", attack_id="G0007", attack_name="APT28"),
        )
        apt.add_indicator(
            Indicator(
                value="fresh.example",
                indicator_type=IndicatorType.DOMAIN,
                first_seen=datetime(2026, 7, 20, tzinfo=timezone.utc),
                references=["https://vendor.test/july"],
            )
        )
        apt.add_indicator(
            Indicator(
                value="old.example",
                indicator_type=IndicatorType.DOMAIN,
                first_seen=datetime(2019, 1, 2, tzinfo=timezone.utc),
                references=["https://vendor.test/2019"],
            )
        )
        quiet = APTGroup(name="QUIET", metadata=APTGroupMetadata(filename="apt_quiet.txt"))
        quiet.add_indicator(Indicator(value="undated.example", indicator_type=IndicatorType.DOMAIN))

        SliceExporter(tmp_path).export({"APT28": apt, "QUIET": quiet}, FeedMetadata())
        return tmp_path

    def test_newest_batch_leads(self, site):
        # Scoped to the feed itself: the header states the window oldest-first.
        body = (site / "activity.html").read_text("utf-8").split("<main class=solo>")[1]

        assert body.index("2026-07-20") < body.index("2019-01-02")

    def test_each_entry_names_its_group_and_source(self, site):
        page = (site / "activity.html").read_text("utf-8")

        assert "APT28" in page
        assert "vendor.test" in page

    def test_undated_indicators_are_not_activity(self, site):
        # An undated indicator says nothing about when anything happened;
        # including it would make a quiet week look busy.
        page = (site / "activity.html").read_text("utf-8")

        assert "QUIET" not in page

    def test_entries_deep_link_to_the_batch_on_the_actor_page(self, site):
        page = (site / "activity.html").read_text("utf-8")
        anchor = re.search(r'href="by-group/G0007\.html#(b-[^"]+)"', page).group(1)

        assert f'<li id="{anchor}"' in (site / "by-group" / "G0007.html").read_text("utf-8")

    def test_the_anchor_survives_a_newer_batch_landing_above_it(self, site, tmp_path):
        # Positional ids would renumber and break every citation.
        before = re.findall(r'id="(b-2019-01-02[^"]*)"', (site / "by-group" / "G0007.html").read_text("utf-8"))

        apt = APTGroup(
            name="APT28",
            metadata=APTGroupMetadata(filename="apt_sofacy.txt", attack_id="G0007", attack_name="APT28"),
        )
        for value, when, ref in [
            ("old.example", datetime(2019, 1, 2, tzinfo=timezone.utc), "https://vendor.test/2019"),
            ("newer.example", datetime(2026, 7, 26, tzinfo=timezone.utc), "https://vendor.test/newest"),
        ]:
            apt.add_indicator(
                Indicator(value=value, indicator_type=IndicatorType.DOMAIN, first_seen=when, references=[ref])
            )
        later = tmp_path / "later"
        SliceExporter(later).export({"APT28": apt}, FeedMetadata())

        after = re.findall(r'id="(b-2019-01-02[^"]*)"', (later / "by-group" / "G0007.html").read_text("utf-8"))
        assert before == after

    def test_machine_readable_twin(self, site):
        payload = json.loads((site / "activity.json").read_text("utf-8"))

        assert payload["batches"][0]["date"] == "2026-07-20"
        assert payload["batches"][0]["references"] == ["https://vendor.test/july"]
        assert payload["window"] == {"from": "2019-01-02", "to": "2026-07-20"}


class TestLinks:
    """Text that looks clickable and is not reads as a broken page."""

    def test_the_group_name_and_id_both_open_the_profile(self, written):
        page = (written / "index.html").read_text("utf-8")

        assert '<td class=gid><a href="by-group/G0007.html">G0007</a></td>' in page
        assert '<a class=who href="by-group/G0007.html">APT28</a>' in page

    def test_an_unmapped_group_still_has_a_clickable_cell(self, written):
        page = (written / "index.html").read_text("utf-8")

        assert '<a href="by-group/UNMAPPED.html">&mdash;</a>' in page

    def test_the_actor_page_links_the_upstream_trail_file(self, written):
        page = (written / "by-group" / "G0007.html").read_text("utf-8")

        assert "Upstream trail" in page
        assert "maltrail/blob/master/trails/static/malware/apt_apt28.txt" in page


def test_export_is_idempotent(tmp_path, feed):
    exporter = SliceExporter(tmp_path)
    exporter.export(feed, FeedMetadata(generated_at=FeedMetadata().generated_at))
    first = (tmp_path / "by-type" / "domain.txt").read_text("utf-8")

    exporter.export(feed, FeedMetadata(generated_at=FeedMetadata().generated_at))

    assert (tmp_path / "by-type" / "domain.txt").read_text("utf-8").count("bear.example") == 1
    assert first.count("bear.example") == 1


class TestMergingByAttackId:
    """Maltrail splits actors that ATT&CK treats as one intrusion set.

    22 ATT&CK ids are affected in the live feed; G0040 covers DONOT, PATCHWORK
    and HANGOVER. Without merging, the last group written won and a request for
    Patchwork returned 984 of its 2,225 indicators.
    """

    @pytest.fixture
    def collided(self, tmp_path):
        attack = {
            "attack_id": "G0040",
            "attack_name": "Patchwork",
            "attack_url": "https://attack.mitre.org/groups/G0040/",
        }
        feed = {
            "DONOT": group("DONOT", [("donot.example", IndicatorType.DOMAIN)], aliases=["apt-c-35"], **attack),
            "PATCHWORK": group(
                "PATCHWORK",
                [("patchwork.example", IndicatorType.DOMAIN), ("9.9.9.9", IndicatorType.IPV4)],
                aliases=["dropping elephant"],
                **attack,
            ),
            "HANGOVER": group("HANGOVER", [("hangover.example", IndicatorType.DOMAIN)], **attack),
        }
        SliceExporter(tmp_path).export(feed, FeedMetadata())
        return tmp_path

    def test_one_file_per_attack_id(self, collided):
        files = sorted(p.name for p in (collided / "by-group").iterdir())

        assert files == [
            "G0040-domain.txt",
            "G0040-navigator.json",
            "G0040.html",
            "G0040.json",
        ]

    def test_indicators_from_every_member_are_present(self, collided):
        payload = json.loads((collided / "by-group" / "G0040.json").read_text("utf-8"))

        assert payload["indicators"]["domain"] == [
            "donot.example",
            "hangover.example",
            "patchwork.example",
        ]
        assert payload["counts"] == {"domain": 3, "ipv4": 1}

    def test_source_groups_are_recorded(self, collided):
        payload = json.loads((collided / "by-group" / "G0040.json").read_text("utf-8"))

        assert payload["maltrail_groups"] == ["DONOT", "HANGOVER", "PATCHWORK"]

    def test_aliases_are_unioned(self, collided):
        payload = json.loads((collided / "by-group" / "G0040.json").read_text("utf-8"))

        assert payload["aliases"] == ["apt-c-35", "dropping elephant"]

    def test_flat_list_covers_every_member(self, collided):
        lines = [
            line
            for line in (collided / "by-group" / "G0040-domain.txt").read_text("utf-8").splitlines()
            if not line.startswith("#")
        ]

        assert lines == ["donot.example", "hangover.example", "patchwork.example"]

    def test_index_counts_the_merged_group_once(self, collided):
        payload = json.loads((collided / "index.json").read_text("utf-8"))

        assert payload["totals"]["slices"] == 1
        assert payload["totals"]["maltrail_groups"] == 3
        assert payload["totals"]["attack_groups"] == 1
        assert payload["totals"]["indicators"] == 4
