"""Sigma exporter tests.

The important guarantee here is that the output parses. The previous exporter
produced a single rule containing 141,148 values plus an empty selection block,
and the first per-group version emitted an unquoted description containing
"Aliases: " - a colon-space, which is not legal in a plain YAML scalar.
"""

import pytest
import yaml

from apttrail.exporters.sigma import SigmaExporter
from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType


def group(name, values, **metadata_kwargs):
    apt = APTGroup(name=name, metadata=APTGroupMetadata(filename=f"apt_{name.lower()}.txt", **metadata_kwargs))
    for value, indicator_type in values:
        apt.add_indicator(Indicator(value=value, indicator_type=indicator_type))
    return apt


@pytest.fixture
def feed():
    return {
        "SOFACY": group(
            "SOFACY",
            [("fancy.example", IndicatorType.DOMAIN), ("1.2.3.4", IndicatorType.IPV4)],
            aliases=["Fancy Bear", "apt28", "pawn storm"],
            attack_id="G0007",
            attack_name="APT28",
            attack_url="https://attack.mitre.org/groups/G0007/",
        ),
        "UNMAPPED": group("UNMAPPED", [("lonely.example", IndicatorType.DOMAIN)]),
        "HASHONLY": group("HASHONLY", [("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.MD5)]),
        "IPONLY": group("IPONLY", [("9.9.9.9", IndicatorType.IPV4)]),
    }


@pytest.fixture
def rules(tmp_path, feed):
    out = tmp_path / "feed.yaml"
    SigmaExporter(out).export(feed, FeedMetadata())
    text = out.read_text("utf-8")
    return text, [doc for doc in yaml.safe_load_all(text) if doc]


def test_output_is_valid_multi_document_yaml(rules):
    _, docs = rules

    # SOFACY, UNMAPPED, HASHONLY; IPONLY has nothing Sigma can express.
    assert len(docs) == 3


def test_one_rule_per_group(rules):
    _, docs = rules
    titles = sorted(doc["title"] for doc in docs)

    assert titles == ["APTtrail G0007 APT28", "APTtrail HASHONLY", "APTtrail UNMAPPED"]


def test_description_with_colon_space_is_quoted(rules):
    _, docs = rules
    doc = next(d for d in docs if d["title"] == "APTtrail G0007 APT28")

    # "Aliases: " round-trips only because the scalar is quoted.
    assert "Aliases: Fancy Bear, apt28, pawn storm" in doc["description"]


def test_no_empty_selection_blocks(rules):
    _, docs = rules

    for doc in docs:
        for key, block in doc["detection"].items():
            if key == "condition":
                continue
            for values in block.values():
                assert values, f"{doc['title']} has an empty {key}"


def test_condition_names_only_present_selections(rules):
    _, docs = rules

    for doc in docs:
        detection = doc["detection"]
        for name in detection["condition"].split(" or "):
            assert name in detection


def test_attack_group_id_becomes_a_sigma_tag(rules):
    _, docs = rules
    doc = next(d for d in docs if d["title"] == "APTtrail G0007 APT28")

    assert "attack.g0007" in doc["tags"]


def test_unmapped_group_has_no_group_tag(rules):
    _, docs = rules
    doc = next(d for d in docs if d["title"] == "APTtrail UNMAPPED")

    assert doc["tags"] == ["attack.command_and_control"]


def test_attack_url_is_referenced_first(rules):
    _, docs = rules
    doc = next(d for d in docs if d["title"] == "APTtrail G0007 APT28")

    assert doc["references"][0] == "https://attack.mitre.org/groups/G0007/"


def test_header_flags_oversized_rules(tmp_path):
    huge = {"BIG": group("BIG", [(f"h{i}.example", IndicatorType.DOMAIN) for i in range(5001)])}
    out = tmp_path / "feed.yaml"

    SigmaExporter(out).export(huge, FeedMetadata())

    text = out.read_text("utf-8")
    assert "Large rules" in text
    assert "BIG: 5,001 values" in text
    # Flagged, not truncated.
    docs = [d for d in yaml.safe_load_all(text) if d]
    assert len(docs[0]["detection"]["selection_domains"]["DestinationHostname"]) == 5001


def test_returns_false_when_nothing_to_export(tmp_path):
    only_ips = {"IPONLY": group("IPONLY", [("9.9.9.9", IndicatorType.IPV4)])}

    assert SigmaExporter(tmp_path / "feed.yaml").export(only_ips, FeedMetadata()) is False


def test_quote_in_an_indicator_does_not_break_parsing(tmp_path):
    odd = {"ODD": group("ODD", [("o'brien.example", IndicatorType.DOMAIN)], aliases=["it's complicated"])}
    out = tmp_path / "feed.yaml"

    SigmaExporter(out).export(odd, FeedMetadata())

    docs = [d for d in yaml.safe_load_all(out.read_text("utf-8")) if d]
    assert docs[0]["detection"]["selection_domains"]["DestinationHostname"] == ["o'brien.example"]
    assert "it's complicated" in docs[0]["description"]
