"""Actor profile page tests."""

from datetime import datetime, timezone

import pytest

from apttrail.exporters.group_pages import MAX_ROWS, render
from apttrail.profiles import ActorProfile, Software, Technique


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
                "old.example": datetime(2019, 1, 2, tzinfo=timezone.utc),
                "new.example": datetime(2026, 3, 21, tzinfo=timezone.utc),
                "undated.example": None,
            },
            "ipv4": {"1.2.3.4": datetime(2020, 6, 6, tzinfo=timezone.utc)},
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


class TestIndicatorTables:
    def test_indicators_carry_their_first_seen_date(self, page):
        assert "2019-01-02" in page
        assert "old.example" in page

    def test_newest_indicator_comes_first(self, page):
        assert page.index("new.example") < page.index("old.example")

    def test_undated_indicator_is_still_listed(self, page):
        assert "undated.example" in page

    def test_each_indicator_type_gets_a_section(self, page):
        assert "domain <span class=sub>(3)</span>" in page
        assert "ipv4 <span class=sub>(1)</span>" in page

    def test_large_group_is_truncated_with_a_link_to_the_full_list(self, profile):
        many = {f"host{i:05d}.example": datetime(2026, 1, 1, tzinfo=timezone.utc) for i in range(MAX_ROWS + 50)}
        page = render("G0007", entry(indicators={"domain": many}), profile, "now")

        assert f"Showing the {MAX_ROWS} most recent of {MAX_ROWS + 50:,}" in page
        assert 'href="G0007.json"' in page
        assert 'href="G0007-domain.txt"' in page


class TestReferences:
    def test_merges_maltrail_and_attack_references(self, page):
        assert "https://example.test/report" in page
        assert "https://attack.mitre.org/groups/G0007/" in page


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
    hostile = entry(indicators={"domain": {"<script>alert(1)</script>.example": None}})

    page = render("X", hostile, None, "now")

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
