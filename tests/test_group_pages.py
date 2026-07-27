"""Actor profile page tests."""

import re
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
        assert "<tr><td>domain</td><td class=n>3</td>" in page
        assert "<tr><td>ipv4</td><td class=n>1</td>" in page
        assert 'href="G0007.json"' in page
        assert 'href="G0007-domain.txt"' in page

    def test_large_group_is_truncated_with_a_link_to_the_full_list(self, profile):
        many = {f"host{i:05d}.example": ioc(datetime(2026, 1, 1, tzinfo=timezone.utc)) for i in range(MAX_ROWS + 50)}
        page = render("G0007", entry(indicators={"domain": many}), profile, "now")

        assert f"Showing the {MAX_ROWS:,} most recent of {MAX_ROWS + 50:,}" in page
        assert f"{50:,} more in this batch" in page
        assert 'href="G0007.json"' in page

    def test_an_at_or_before_date_is_not_presented_as_a_sighting(self, profile):
        # Upstream reset its history in January 2026; blame cannot see past it,
        # so those dates are a floor. Rendering them as plain dates would claim
        # a decade of infrastructure all appeared on one day.
        floored = {"domain": {"old.example": ioc(datetime(2026, 1, 3, tzinfo=timezone.utc), "at-or-before")}}

        page = render("G0007", entry(indicators=floored), profile, "now")

        assert "or earlier" in page
        assert "may be older" in page


class TestTriageHeader:
    """The numbers a responder needs before deciding to read any further."""

    def test_counts_indicators_and_distinct_reports(self, page):
        assert "Indicators" in page and "Source reports" in page
        assert ">2</dd>" in page  # two distinct reports across the batches

    def test_shows_how_old_the_newest_indicator_is(self, page):
        # "2026-03-21" alone does not answer "is this actor current?".
        assert "Newest indicator" in page
        assert "this year" in page
        # And each batch carries its own age, so a 2019 entry reads as stale.
        assert "7 yrs ago" in page

    def test_activity_span_is_year_to_year(self, page):
        assert "2019&ndash;2026" in page

    def test_year_histogram_marks_recent_activity(self, page):
        assert "class=spark" in page
        assert 'title="2019: 1 indicators"' in page

    def test_a_single_year_group_gets_no_histogram(self, profile):
        one_year = {"domain": {"a.example": ioc(datetime(2026, 1, 1, tzinfo=timezone.utc))}}

        page = render("G0007", entry(indicators=one_year), profile, "2026-07-27")

        assert "<span" not in page.split("spark-axis")[0].split("class=spark")[-1]


class TestPrincipalSources:
    """A flat list of references says nothing about which one carries weight."""

    def test_ranks_reports_by_how_many_indicators_they_brought(self, profile):
        weighted = {
            "domain": {
                "a.example": ioc(datetime(2026, 3, 1, tzinfo=timezone.utc), references=["https://big.test/r"]),
                "b.example": ioc(datetime(2026, 3, 1, tzinfo=timezone.utc), references=["https://big.test/r"]),
                "c.example": ioc(datetime(2025, 1, 1, tzinfo=timezone.utc), references=["https://small.test/r"]),
            }
        }

        page = render("G0007", entry(indicators=weighted), profile, "2026-07-27")
        panel = page.split("id=reporting")[1].split("</ul>")[0]

        assert panel.index("big.test") < panel.index("small.test")

    def test_omitted_when_nothing_is_sourced(self, profile):
        bare = {"domain": {"a.example": ioc(datetime(2026, 1, 1, tzinfo=timezone.utc))}}

        page = render("G0007", entry(indicators=bare), profile, "2026-07-27")

        assert "Principal sources" not in page


class TestInteractionContract:
    """
    The script reads structure out of the page. These are the hooks it needs.

    Both defects here shipped: the defang rule turned "http://x" into
    "hxxphttp://x", and the batch date stopped being a <time> element when it
    became a link, which silently emptied the age filter and left the CSV
    export with no dates.
    """

    def test_defang_does_not_repeat_the_scheme(self, page):
        assert "'hxxp$1:'" in page
        assert "/^http(s?):/i" in page
        assert "/^(https?):/i" not in page

    def test_the_batch_date_is_machine_readable(self, page):
        # The age filter and the CSV export both read this attribute.
        assert '<time datetime="2026-03-21">' in page

    def test_every_row_carries_its_type_for_the_chips(self, page):
        assert '<tr data-t="domain">' in page
        assert '<tr data-t="ipv4">' in page

    def test_type_chips_cover_the_types_present(self, page):
        assert "data-type=all" in page
        assert 'data-type="domain"' in page
        assert 'data-type="ipv4"' in page

    def test_the_age_cutoff_is_relative_to_the_newest_indicator(self, profile):
        # Cutting against today would empty the page for a dormant actor.
        dormant = {"domain": {"a.example": ioc(datetime(2019, 5, 1, tzinfo=timezone.utc))}}
        dormant["domain"]["b.example"] = ioc(datetime(2012, 5, 1, tzinfo=timezone.utc))

        page = render("G0007", entry(indicators=dormant), profile, "2026-07-27")

        assert 'data-recent="2017-01-01"' in page
        assert "since 2017" in page

    def test_no_age_toggle_when_everything_is_recent(self, profile):
        recent = {"domain": {"a.example": ioc(datetime(2026, 5, 1, tzinfo=timezone.utc))}}

        page = render("G0007", entry(indicators=recent), profile, "2026-07-27")

        assert "id=recent" not in page

    def test_an_empty_filter_result_is_explained(self, page):
        assert "id=empty" in page
        assert "No indicator matches" in page


class TestNoExternalDependencies:
    """SOC networks block third-party origins and these pages get saved to disk."""

    def test_nothing_is_fetched_from_another_origin(self, page):
        # <link> itself is fine - canonical is metadata and the favicon is a
        # data URI. What must not exist is a request to somewhere else.
        assert "@import" not in page.split("<style>")[1]
        assert "<link rel=stylesheet" not in page
        assert "<script src" not in page
        assert "<img" not in page
        for href in re.findall(r"<link[^>]*href=\"([^\"]+)\"", page):
            assert href.startswith(("data:", "https://trilwu.github.io/")), href

    def test_it_carries_a_link_preview(self, page):
        # Pasted into Slack or a ticket, the site should not render as a bare URL.
        assert 'property="og:title"' in page
        assert 'property="og:description"' in page
        assert 'content="summary"' in page
        assert "rel=canonical" in page

    def test_the_preview_summarises_the_actor_not_a_truncated_sentence(self, page):
        summary = re.search(r'name=description content="([^"]+)"', page).group(1)

        assert summary.startswith("4 indicators attributed to APT28 (G0007)")
        assert "source reports" in summary

    def test_the_favicon_is_self_contained(self, page):
        assert 'rel=icon href="data:image/svg+xml,' in page

    def test_the_page_is_readable_without_script(self, page):
        without_script = page.split("<script>")[0]

        assert "old.example" in without_script
        assert "vendor.test" in without_script

    def test_script_only_conveniences_start_hidden(self, page):
        # The filter box is useless without script, so script reveals it.
        assert "class=tools id=tools hidden" in page


class TestPerIndicatorSource:
    """The report an indicator was filed under is what explains why it is here."""

    def test_each_batch_links_the_report_it_came_from(self, page):
        assert 'href="https://vendor.test/2026-write-up"' in page
        assert 'href="https://vendor.test/2019-write-up"' in page

    def test_the_link_sits_with_its_own_indicators(self, page):
        # The 2026 report must appear between the two batches, not collected
        # with everything else at the bottom of the page.
        assert page.index("2026-write-up") < page.index("old.example")

    def test_link_labels_split_host_from_path(self, page):
        # The host is what an analyst recognises; the path is context.
        assert ">vendor.test</span>" in page
        assert ">/2026-write-up</span>" in page

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
        assert "no upstream reference for this batch" in page


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
