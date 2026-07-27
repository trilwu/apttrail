"""Regression tests for the Suricata exporter.

Every test here pins a rule defect that shipped to users at some point.
"""

import re

import pytest

from apttrail.exporters.suricata import SuricataExporter, escape_content
from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType

RULE_LINE = re.compile(r"^alert\s+\S+\s+.*\(.*sid:\d+;.*\)$")


def build_group(name="DEMO", values=(), **metadata_kwargs):
    metadata = APTGroupMetadata(filename=f"apt_{name.lower()}.txt", **metadata_kwargs)
    group = APTGroup(name=name, metadata=metadata)
    for value, indicator_type in values:
        group.add_indicator(Indicator(value=value, indicator_type=indicator_type))
    return {name: group}


def render(tmp_path, groups, **kwargs):
    out = tmp_path / "feed.rules"
    SuricataExporter(out, **kwargs).export(groups, FeedMetadata())
    return out.read_text("utf-8")


def rule_lines(content):
    return [line for line in content.splitlines() if line.startswith("alert ")]


class TestEscaping:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ('say"hi', 'say\\"hi'),
            ("a;b", "a\\;b"),
            ("back\\slash", "back\\\\slash"),
            ("plain/path.php", "plain/path.php"),
        ],
    )
    def test_special_characters_are_escaped(self, raw, expected):
        assert escape_content(raw) == expected

    def test_non_ascii_becomes_hex_block(self):
        assert escape_content("café") == "caf|c3 a9|"

    def test_live_indicator_with_quote_does_not_break_the_rule(self, tmp_path):
        # This exact value is in the published feed and used to emit an
        # unbalanced content string, corrupting every rule after it.
        nasty = '/YKYD69Q_705BA84C/"PhoenixTechnologiesLTD"-INTEL-6222004/player_16.php'
        content = render(tmp_path, build_group(values=[(nasty, IndicatorType.URL_PATH)]))

        line = rule_lines(content)[0]
        assert '\\"PhoenixTechnologiesLTD\\"' in line
        assert line.count('"') % 2 == 0


class TestDomainRules:
    def test_match_is_anchored_at_both_ends(self, tmp_path):
        content = render(tmp_path, build_group(values=[("evil.com", IndicatorType.DOMAIN)]))

        line = rule_lines(content)[0]
        assert "dns.query;" in line
        assert "startswith" in line and "endswith" in line

    def test_dataset_mode_emits_one_rule_per_buffer(self, tmp_path):
        groups = build_group(values=[(f"host{i}.evil.com", IndicatorType.DOMAIN) for i in range(50)])

        content = render(tmp_path, groups, use_datasets=True)

        lines = rule_lines(content)
        assert len(lines) == 2  # dns.query + tls.sni
        assert any("dns.query; dataset:isset," in line for line in lines)
        assert any("tls.sni; dataset:isset," in line for line in lines)

    def test_dataset_file_holds_base64_values(self, tmp_path):
        import base64

        render(tmp_path, build_group(values=[("evil.com", IndicatorType.DOMAIN)]), use_datasets=True)

        listfile = tmp_path / "suricata-datasets" / "apttrail-demo-domains.lst"
        assert listfile.read_text("utf-8").strip() == base64.b64encode(b"evil.com").decode()


class TestUrlRules:
    def test_pathless_url_does_not_match_every_request(self, tmp_path):
        # 97% of URL indicators have no path. Emitting http.uri content:"/"
        # for them alerted on all HTTP traffic.
        content = render(tmp_path, build_group(values=[("http://128.199.73.43", IndicatorType.URL)]))

        line = rule_lines(content)[0]
        assert 'content:"/"' not in line
        assert "http.host;" in line
        assert "http.uri;" not in line

    def test_url_with_real_path_matches_host_and_path(self, tmp_path):
        content = render(tmp_path, build_group(values=[("http://evil.com/gate.php", IndicatorType.URL)]))

        line = rule_lines(content)[0]
        assert 'http.host; content:"evil.com"' in line
        assert 'http.uri; content:"/gate.php"' in line

    def test_schemeless_url_is_handled(self, tmp_path):
        content = render(tmp_path, build_group(values=[("evil.com/shell.php", IndicatorType.URL)]))

        line = rule_lines(content)[0]
        assert 'http.host; content:"evil.com"' in line
        assert 'http.uri; content:"/shell.php"' in line


class TestHashRules:
    def test_no_hash_rule_when_group_has_no_hashes(self, tmp_path):
        content = render(tmp_path, build_group(values=[("evil.com", IndicatorType.DOMAIN)]))

        assert "filemd5" not in content

    def test_hash_rule_references_a_list_file_and_is_not_negated(self, tmp_path):
        digest = "d41d8cd98f00b204e9800998ecf8427e"
        content = render(tmp_path, build_group(values=[(digest, IndicatorType.MD5)]))

        line = next(line for line in rule_lines(content) if "filemd5" in line)
        assert "filemd5:!" not in line  # the old rule negated the match
        assert f"filemd5:apttrail-demo-{IndicatorType.MD5.value}.lst;" in line
        listfile = tmp_path / "suricata-datasets" / "apttrail-demo-md5.lst"
        assert listfile.read_text("utf-8").strip() == digest

    def test_sha256_uses_the_matching_keyword(self, tmp_path):
        digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        content = render(tmp_path, build_group(values=[(digest, IndicatorType.SHA256)]))

        assert "filesha256:" in content
        assert "filemd5:" not in content


class TestRuleHygiene:
    @pytest.fixture
    def mixed_feed(self, tmp_path):
        groups = build_group(
            values=[
                ("evil.com", IndicatorType.DOMAIN),
                ("1.2.3.4:8080", IndicatorType.IPV4),
                ("http://evil.com/gate.php", IndicatorType.URL),
                ("/beacon.php", IndicatorType.URL_PATH),
                ("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.MD5),
            ]
        )
        return render(tmp_path, groups)

    def test_every_rule_is_structurally_complete(self, mixed_feed):
        lines = rule_lines(mixed_feed)
        assert lines
        for line in lines:
            assert RULE_LINE.match(line), line

    def test_sids_are_unique(self, mixed_feed):
        sids = re.findall(r"sid:(\d+);", mixed_feed)
        assert len(sids) == len(set(sids))

    def test_ip_port_is_stripped_from_the_address(self, mixed_feed):
        line = next(line for line in rule_lines(mixed_feed) if "1.2.3.4" in line)
        assert "-> 1.2.3.4 any" in line
        assert "1.2.3.4:8080" not in line

    def test_header_tells_the_analyst_how_to_validate(self, mixed_feed):
        assert "suricata -T" in mixed_feed


class TestAttribution:
    def test_attack_id_lands_in_rule_metadata(self, tmp_path):
        groups = build_group(
            name="APT28",
            values=[("evil.com", IndicatorType.DOMAIN)],
            attack_id="G0007",
            attack_url="https://attack.mitre.org/groups/G0007/",
        )

        content = render(tmp_path, groups)

        assert "mitre_group_id G0007" in content
        assert "# MITRE ATT&CK: G0007" in content

    def test_metadata_omits_attack_id_when_unmapped(self, tmp_path):
        content = render(tmp_path, build_group(values=[("evil.com", IndicatorType.DOMAIN)]))

        assert "mitre_group_id" not in content
        assert "metadata:apt_group DEMO;" in content


class TestSuricataParserConstraints:
    """Constraints learned from running `suricata -T` in CI, not from docs."""

    def test_msg_semicolon_is_escaped(self, tmp_path):
        # Suricata: bad option value formatting (possible missing semicolon)
        # for keyword msg -- an unescaped ; ends the option early.
        content = render(tmp_path, build_group(values=[("/semi;colon.php", IndicatorType.URL_PATH)]))

        line = rule_lines(content)[0]
        assert "msg:" in line
        assert r"- HTTP request to /semi\;colon.php" in line

    def test_msg_quote_is_escaped(self, tmp_path):
        content = render(tmp_path, build_group(values=[('/a/"q"/b.php', IndicatorType.URL_PATH)]))

        line = rule_lines(content)[0]
        assert '\\"q\\"' in line
        assert line.count('"') % 2 == 0

    def test_http_host_does_not_carry_nocase(self, tmp_path):
        # Suricata 7 rejects nocase on http.host; the buffer is already
        # normalised to lowercase.
        content = render(tmp_path, build_group(values=[("http://evil.com/x.php", IndicatorType.URL)]))

        line = rule_lines(content)[0]
        assert "http.host;" in line
        assert "nocase" not in line.split("http.host;")[1].split("http.uri;")[0]

    def test_dns_query_keeps_nocase(self, tmp_path):
        # dns.query accepts nocase and anchoring together; only http.host does not.
        content = render(tmp_path, build_group(values=[("evil.com", IndicatorType.DOMAIN)]))

        assert "dns.query;" in rule_lines(content)[0]
        assert "nocase" in rule_lines(content)[0]


class TestAlertVolume:
    """
    An implant beaconing every 30s is ~2,900 identical alerts per host per day.
    Suppressing that is worth a lot - but only where suppression cannot also
    hide a second, different indicator.
    """

    def rules(self, tmp_path, values, datasets=True):
        apt = APTGroup(name="APT28", metadata=APTGroupMetadata(filename="apt_apt28.txt"))
        for value, kind in values:
            apt.add_indicator(Indicator(value=value, indicator_type=kind))
        out = tmp_path / "feed.rules"
        SuricataExporter(out, use_datasets=datasets).export({"APT28": apt}, FeedMetadata())
        return out.read_text("utf-8")

    def rule_for(self, text, proto):
        return next(line for line in text.splitlines() if line.startswith(f"alert {proto} "))

    def test_ip_rule_collapses_beaconing_without_hiding_a_second_c2(self, tmp_path):
        # by_both keys on the src/dst pair: beaconing to one address collapses,
        # a different address in the same dataset still alerts on its own.
        text = self.rules(tmp_path, [("1.2.3.4", IndicatorType.IPV4), ("5.6.7.8", IndicatorType.IPV4)])

        rule = self.rule_for(text, "ip")
        assert "threshold:type limit, track by_both, count 1, seconds 3600" in rule

    def test_http_rule_is_per_host_so_the_source_alone_is_enough(self, tmp_path):
        text = self.rules(tmp_path, [("http://evil.example/a", IndicatorType.URL)])

        assert "track by_src" in self.rule_for(text, "http")

    def test_dns_dataset_rule_is_left_unthresholded_on_purpose(self, tmp_path):
        # One rule covers the whole group's domain set and a query's
        # destination is the resolver, so no track= key can tell one malicious
        # domain from the next. Suppressing would drop indicators.
        text = self.rules(tmp_path, [("a.example", IndicatorType.DOMAIN), ("b.example", IndicatorType.DOMAIN)])

        assert "threshold:" not in self.rule_for(text, "dns")
        assert "threshold:" not in self.rule_for(text, "tls")

    def test_a_one_domain_rule_can_be_thresholded_because_it_hides_nothing(self, tmp_path):
        text = self.rules(tmp_path, [("a.example", IndicatorType.DOMAIN)], datasets=False)

        assert "track by_src" in self.rule_for(text, "dns")

    def test_every_rule_still_has_something_for_the_prefilter(self, tmp_path):
        # A rule with only pcre: and no content/dataset gives the multi-pattern
        # matcher nothing to prefilter on, so it runs against every packet.
        text = self.rules(
            tmp_path,
            [
                ("a.example", IndicatorType.DOMAIN),
                ("1.2.3.4", IndicatorType.IPV4),
                ("http://evil.example/x", IndicatorType.URL),
            ],
        )

        for line in text.splitlines():
            if line.startswith("alert "):
                assert "dataset:" in line or "content:" in line, line
                assert "pcre:" not in line, line
