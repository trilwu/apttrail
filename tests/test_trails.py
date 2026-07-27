"""Reading Maltrail trail files, references included."""

import pytest

from apttrail.trails import read_trail

TRAIL = """# Copyright (c) 2014-2026 Maltrail developers
# Aliases: fancy bear, sofacy
# MITRE: https://attack.mitre.org/groups/G0007/

# Reference: https://vendor.test/first-report
# Reference: https://vendor.test/first-report-appendix

first.example
1.2.3.4

# Reference: https://vendor.test/second-report
second.example
first.example
"""


@pytest.fixture
def trail(tmp_path):
    path = tmp_path / "apt_demo.txt"
    path.write_text(TRAIL, encoding="utf-8")
    return read_trail(path)


class TestReferenceBlocks:
    def test_an_indicator_carries_the_report_above_it(self, trail):
        assert trail.indicators["1.2.3.4"] == [
            "https://vendor.test/first-report",
            "https://vendor.test/first-report-appendix",
        ]

    def test_a_later_block_replaces_the_earlier_one(self, trail):
        assert trail.indicators["second.example"] == ["https://vendor.test/second-report"]

    def test_a_value_listed_twice_keeps_both_sources(self, trail):
        # The same domain is cited by two reports; dropping one would lose the
        # evidence that the actor reused it.
        assert trail.indicators["first.example"] == [
            "https://vendor.test/first-report",
            "https://vendor.test/first-report-appendix",
            "https://vendor.test/second-report",
        ]

    def test_indicators_before_any_reference_have_none(self, tmp_path):
        path = tmp_path / "apt_bare.txt"
        path.write_text("orphan.example\n# Reference: https://vendor.test/x\nlater.example\n", encoding="utf-8")

        trail = read_trail(path)

        assert trail.indicators == {
            "orphan.example": [],
            "later.example": ["https://vendor.test/x"],
        }


class TestHeader:
    def test_aliases_are_split(self, trail):
        assert trail.aliases == ["fancy bear", "sofacy"]

    def test_every_reference_is_listed_once_for_the_group(self, trail):
        assert trail.references == [
            "https://vendor.test/first-report",
            "https://vendor.test/first-report-appendix",
            "https://vendor.test/second-report",
        ]

    def test_a_non_web_reference_never_becomes_a_link(self, tmp_path):
        # These lines are free text upstream; a javascript: URL reaching an
        # href would be an XSS hole fed by a third-party repository.
        path = tmp_path / "apt_x.txt"
        path.write_text("# Reference: javascript:alert(1)\nx.example\n", encoding="utf-8")

        trail = read_trail(path)

        assert trail.references == []
        assert trail.indicators["x.example"] == []

    def test_a_mitre_comment_is_not_mistaken_for_an_alias(self, trail):
        assert "https://attack.mitre.org/groups/G0007/" not in trail.aliases
