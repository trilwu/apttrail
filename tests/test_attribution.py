import json

import pytest

from apttrail.attribution import AttackGroup, AttackGroupIndex, load_index, normalize


@pytest.fixture
def index():
    return AttackGroupIndex(
        [
            AttackGroup(id="G0007", name="APT28", aliases=["APT28", "Fancy Bear", "Sofacy"]),
            AttackGroup(id="G0016", name="APT29", aliases=["APT29", "Cozy Bear", "NOBELIUM"]),
            AttackGroup(id="G0040", name="Patchwork", aliases=["Patchwork", "DoNot Team", "Dropping Elephant"]),
        ]
    )


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("APT-C-36", "apt_c_36"),
        ("Fancy Bear", "fancybear"),
        ("APT 28", "apt28"),
    ],
)
def test_normalize_collapses_punctuation_and_case(left, right):
    assert normalize(left) == normalize(right)


class TestResolve:
    def test_matches_the_canonical_name(self, index):
        assert index.resolve("APT28").id == "G0007"

    def test_matches_an_alias_regardless_of_punctuation(self, index):
        assert index.resolve("fancy-bear").id == "G0007"
        assert index.resolve("COZY BEAR").id == "G0016"

    def test_tries_candidates_in_order(self, index):
        # Maltrail passes the group name first, then its aliases.
        assert index.resolve("UNKNOWNNAME", "Sofacy").id == "G0007"

    def test_bare_number_falls_back_to_apt_prefix(self, index):
        # Maltrail derives names from filenames, so apt_28.txt becomes "28".
        assert index.resolve("28").id == "G0007"

    def test_returns_none_for_untracked_actor(self, index):
        assert index.resolve("1877TEAM") is None

    def test_ignores_empty_candidates(self, index):
        assert index.resolve("", "APT29").id == "G0016"

    def test_url_points_at_the_attack_page(self, index):
        assert index.resolve("APT28").url == "https://attack.mitre.org/groups/G0007/"


class TestVendoredData:
    def test_ships_with_the_package(self):
        index = load_index()
        assert len(index) > 150

    def test_resolves_well_known_groups(self):
        index = load_index()
        assert index.resolve("APT28").id == "G0007"
        assert index.resolve("Lazarus Group").id == "G0032"

    @pytest.mark.parametrize(
        ("maltrail_name", "maltrail_aliases", "expected"),
        [
            ("DEATHSTALKER", [], "G0120"),
            ("GHOSTEMPEROR", ["entryshell", "sparrowdoor"], "G1045"),
            ("UNC4210", ["kopiluwak", "quietcanary"], "G0010"),
            ("DONOT", ["apt-c-35", "donot"], "G0040"),
        ],
    )
    def test_threat_actor_synonyms_are_folded_in(self, maltrail_name, maltrail_aliases, expected):
        # None of these names appear in the ATT&CK cluster under the name
        # Maltrail uses. They resolve because the refresh script folds
        # threat-actor synonyms into the ATT&CK group they identify.
        index = load_index()

        assert index.resolve(maltrail_name, *maltrail_aliases).id == expected

    def test_data_file_is_deterministic_and_sorted(self):
        from apttrail.attribution import DATA_FILE

        payload = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        ids = [g["id"] for g in payload["groups"]]
        assert ids == sorted(ids)
        for group in payload["groups"]:
            assert group["aliases"] == sorted(group["aliases"])


class TestDegradedMode:
    def test_missing_data_file_yields_an_empty_index(self, tmp_path):
        # A packaging mistake must not break collection outright.
        index = load_index(tmp_path / "absent.json")
        assert len(index) == 0
        assert index.resolve("APT28") is None

    def test_corrupt_data_file_yields_an_empty_index(self, tmp_path):
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")

        assert len(load_index(broken)) == 0


class TestGenericSuffixes:
    """ATT&CK writes "Gamaredon Group"; the Maltrail file is apt_gamaredon.txt."""

    def test_a_bare_name_resolves_past_a_trailing_generic_word(self):
        index = AttackGroupIndex([AttackGroup(id="G0047", name="Gamaredon Group", aliases=["Primitive Bear"])])

        assert index.resolve("GAMAREDON").id == "G0047"
        assert index.resolve("Gamaredon Group").id == "G0047"

    def test_only_that_closed_set_of_words_is_stripped(self):
        # Dropping any last word would make "Fancy Bear" resolve from "Fancy".
        index = AttackGroupIndex([AttackGroup(id="G0007", name="Fancy Bear")])

        assert index.resolve("Fancy") is None
        assert index.resolve("Fancy Bear").id == "G0007"

    def test_a_single_word_name_is_left_alone(self):
        index = AttackGroupIndex([AttackGroup(id="G0001", name="Group")])

        assert index.resolve("Group").id == "G0001"
