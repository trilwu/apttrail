"""Actor profile page tests."""

from datetime import datetime, timezone

import pytest

from apttrail.exporters.group_pages import MAX_REFERENCES, MAX_ROWS, build_timeline, render
from apttrail.profiles import ActorProfile, Software, Technique


def ioc(date=None, precision="exact", references=()):
    """One merged-entry indicator record, as the slice exporter builds it."""
    return {
        "first_seen": date,
        "precision": precision if date else None,
        "references": list(references),
    }


def entry(**overrides):
    base = {
        "maltrail_groups": ["SOFACY"],
        "attack_id": "G0007",
        "attack_name": "APT28",
        "attack_url": "https://attack.mitre.org/groups/G0007/",
        "aliases": ["fancy bear", "sofacy"],
        "references": ["https://example.test/report"],
        "last_modified": None,
        "first_seen_range": {"earliest": "2019-01-02", "latest": "2026-03-21"},
        "indicators": {
            "domain": {
                "old.example": ioc(
                    datetime(2019, 1, 2, tzinfo=timezone.utc),
                    references=["https://vendor.test/2019-write-up"],
                ),
                "new.example": ioc(
                    datetime(2026, 3, 21, tzinfo=timezone.utc),
                    references=["https://vendor.test/2026-write-up"],
                ),
                "undated.example": ioc(),
            },
            "ipv4": {"1.2.3.4": ioc(datetime(2020, 6, 6, tzinfo=timezone.utc))},
        },
    }
    base.update(overrides)
    return base


@pytest.fixture
def profile():
    return ActorProfile(
        name="APT28",
        description="A threat group attributed to Russia's GRU.",
        country="RU",
        sponsor="Russian Federation",
        sectors=["Government", "Military"],
        victims=["Georgia", "France"],
        activity=["Espionage"],
        techniques=[Technique(id="T1218.011", name="Rundll32")],
        software=[Software(id="S0002", name="Mimikatz")],
        references=["https://attack.mitre.org/groups/G0007/"],
    )


@pytest.fixture
def page(profile):
    return render("G0007", entry(), profile, "2026-07-27T00:00:00+00:00")


class TestProfileContent:
    def test_shows_who_the_group_is(self, page):
        assert "APT28" in page
        assert "attributed to Russia&#x27;s GRU" in page

    def test_shows_origin_and_sponsor(self, page):
        assert "Suspected origin" in page
        assert "RU" in page and "Russian Federation" in page

    def test_shows_targeting(self, page):
        assert "Targeted sectors" in page
        assert "Government" in page and "Military" in page
        assert "Suspected victims" in page and "Georgia" in page

    def test_shows_activity_type(self, page):
        assert "Espionage" in page

    def test_links_the_attack_group_page(self, page):
        assert 'href="https://attack.mitre.org/groups/G0007/"' in page


class TestTechniques:
    def test_lists_techniques_with_links(self, page):
        assert "T1218.011" in page
        assert "Rundll32" in page
        # Sub-techniques nest under the parent on attack.mitre.org.
        assert "https://attack.mitre.org/techniques/T1218/011/" in page

    def test_lists_software(self, page):
        assert "Mimikatz" in page


class TestTimeline:
    def test_indicators_carry_their_first_seen_date(self, page):
        assert "2019-01-02" in page
        assert "old.example" in page

    def test_newest_batch_comes_first(self, page):
        assert page.index("new.example") < page.index("old.example")

    def test_undated_indicator_is_still_listed(self, page):
        assert "undated.example" in page
        assert "date unknown" in page

    def test_undated_batch_sorts_last(self, page):
        assert page.index("old.example") < page.index("undated.example")

    def test_counts_name_the_types_in_each_batch(self, page):
        assert "1 domain" in page
        assert "1 ipv4" in page

    def test_a_mixed_batch_labels_the_type_of_each_row(self, profile):
        mixed = {
            "domain": {"a.example": ioc(datetime(2026, 3, 21, tzinfo=timezone.utc))},
            "ipv4": {"9.9.9.9": ioc(datetime(2026, 3, 21, tzinfo=timezone.utc))},
        }

        page = render("G0007", entry(indicators=mixed), profile, "now")

        assert "<td class=kind>ipv4</td>" in page

    def test_a_single_type_batch_does_not_repeat_the_type_on_every_row(self, page):
        # The heading already says "1 domain"; a column of identical labels is
        # width spent on nothing.
        assert "<td class=kind>domain</td>" not in page

    def test_type_totals_and_full_lists_are_still_reachable(self, page):
        assert "domain 3" in page
        assert "ipv4 1" in page
        assert 'href="G0007.json"' in page
        assert 'href="G0007-domain.txt"' in page

    def test_large_group_is_truncated_with_a_link_to_the_full_list(self, profile):
        many = {f"host{i:05d}.example": ioc(datetime(2026, 1, 1, tzinfo=timezone.utc)) for i in range(MAX_ROWS + 50)}
        page = render("G0007", entry(indicators={"domain": many}), profile, "now")

        assert f"Showing the {MAX_ROWS:,} most recent of {MAX_ROWS + 50:,}" in page
        assert f"and {50:,} more in this batch" in page
        assert 'href="G0007.json"' in page

    def test_an_at_or_before_date_is_not_presented_as_a_sighting(self, profile):
        # Upstream reset its history in January 2026; blame cannot see past it,
        # so those dates are a floor. Rendering them as plain dates would claim
        # a decade of infrastructure all appeared on one day.
        floored = {"domain": {"old.example": ioc(datetime(2026, 1, 3, tzinfo=timezone.utc), "at-or-before")}}

        page = render("G0007", entry(indicators=floored), profile, "now")

        assert "or earlier" in page
        assert "may be older" in page


class TestPerIndicatorSource:
    """The report an indicator was filed under is what explains why it is here."""

    def test_each_batch_links_the_report_it_came_from(self, page):
        assert 'href="https://vendor.test/2026-write-up"' in page
        assert 'href="https://vendor.test/2019-write-up"' in page

    def test_the_link_sits_with_its_own_indicators(self, page):
        # The 2026 report must appear between the two batches, not collected
        # with everything else at the bottom of the page.
        assert page.index("2026-write-up") < page.index("old.example")

    def test_link_labels_drop_the_scheme(self, page):
        assert ">vendor.test/2026-write-up<" in page

    def test_indicators_from_different_reports_are_separate_batches(self):
        same_day = {
            "domain": {
                "a.example": ioc(datetime(2026, 3, 21, tzinfo=timezone.utc), references=["https://one.test/a"]),
                "b.example": ioc(datetime(2026, 3, 21, tzinfo=timezone.utc), references=["https://two.test/b"]),
            }
        }

        batches = build_timeline(entry(indicators=same_day))

        assert [b["references"] for b in batches] == [["https://two.test/b"], ["https://one.test/a"]]

    def test_a_batch_with_no_reference_says_so_rather_than_leaving_a_gap(self, page):
        assert "No upstream reference for this batch" in page


class TestReferences:
    def test_merges_maltrail_and_attack_references(self, page):
        assert "https://example.test/report" in page
        assert "https://attack.mitre.org/groups/G0007/" in page

    def test_a_long_reference_list_is_capped(self, profile):
        # One group carries 1,607 of these; the timeline is where provenance
        # lives now, so the tail belongs in the JSON.
        many = [f"https://vendor.test/report-{i:04d}" for i in range(MAX_REFERENCES + 12)]

        page = render("G0007", entry(references=many), profile, "now")

        assert "https://vendor.test/report-0000" in page
        assert "https://vendor.test/report-0051" not in page
        # 12 upstream references plus the one ATT&CK contributes.
        assert "13 more" in page


class TestWithoutAProfile:
    """Two thirds of Maltrail's groups are not tracked by ATT&CK."""

    @pytest.fixture
    def bare(self):
        return render(
            "UNMAPPED",
            entry(attack_id=None, attack_name=None, maltrail_groups=["UNMAPPED"]),
            None,
            "now",
        )

    def test_page_still_renders(self, bare):
        assert "UNMAPPED" in bare
        assert "old.example" in bare

    def test_says_there_is_no_description_rather_than_leaving_a_gap(self, bare):
        assert "No published description" in bare

    def test_omits_technique_and_software_sections(self, bare):
        assert "Techniques" not in bare
        assert "Software" not in bare


def test_escapes_untrusted_values():
    hostile = entry(indicators={"domain": {"<script>alert(1)</script>.example": ioc()}})

    page = render("X", hostile, None, "now")

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_escapes_untrusted_reference_urls():
    # The URLs come from upstream comment lines and land in an href.
    hostile = entry(
        indicators={"domain": {"a.example": ioc(references=['https://x.test/"><script>alert(1)</script>'])}}
    )

    page = render("X", hostile, None, "now")

    assert "<script>alert(1)</script>" not in page
    assert "&quot;&gt;&lt;script&gt;" in page
