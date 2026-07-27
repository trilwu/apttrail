"""
Map Maltrail APT group names onto MITRE ATT&CK groups.

This is the part of APTtrail that other free feeds do not provide. IOC feeds
and actor-to-technique mappings normally live in separate places, joined by
hand through alias tables; here each indicator arrives already carrying the
ATT&CK group id of the actor it belongs to.

The alias table is vendored from the MISP galaxy mitre-intrusion-set cluster
(see ``data/attack_groups.json``) so collection stays offline and
deterministic. Refresh it with ``scripts/refresh_attack_groups.py``.
"""

import json
import re
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

DATA_FILE = Path(__file__).parent / "data" / "attack_groups.json"
ATTACK_URL = "https://attack.mitre.org/groups/{group_id}/"

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

#: Generic words ATT&CK appends to an actor's name but Maltrail's filename does
#: not. Kept to a closed set: stripping *any* trailing word would make
#: "Sandworm Team" and "Sandworm" indistinguishable from anything else starting
#: with Sandworm.
GENERIC_SUFFIXES = frozenset({"group", "team", "gang", "crew"})


def normalize(name: str) -> str:
    """
    Reduce a group name to a comparable key.

    Maltrail, ATT&CK and vendor reporting disagree on punctuation and spacing
    for the same actor: "APT-C-36", "APT_C_36" and "apt c 36" are one group.
    """
    return _NON_ALNUM.sub("", name.lower())


class AttackGroup(BaseModel):
    """A MITRE ATT&CK intrusion set."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="ATT&CK group id, e.g. G0007")
    name: str = Field(..., description="ATT&CK group name, e.g. APT28")
    aliases: list[str] = Field(default_factory=list, description="Known synonyms")

    @property
    def url(self) -> str:
        """Canonical ATT&CK page for the group."""
        return ATTACK_URL.format(group_id=self.id)


class AttackGroupIndex:
    """Alias-to-group lookup over the vendored ATT&CK data."""

    def __init__(self, groups: list[AttackGroup]) -> None:
        self.groups = groups
        self._by_alias: dict[str, AttackGroup] = {}

        for group in groups:
            for alias in [group.name, *group.aliases]:
                for key in self._keys_for(alias):
                    # Lower G-ids win ties so the mapping is stable regardless
                    # of input ordering.
                    existing = self._by_alias.get(key)
                    if existing is None or group.id < existing.id:
                        self._by_alias[key] = group

    @staticmethod
    def _keys_for(alias: str) -> list[str]:
        """
        Lookup keys for one ATT&CK alias.

        ATT&CK writes "Gamaredon Group" and "Gorgon Group" where Maltrail files
        say GAMAREDON and GORGON, so the bare name resolved to nothing at all.
        Indexing the name without its trailing generic word fixes that. Only
        that closed set of words is stripped - dropping any last word would
        collapse "Lazarus Group" and "Lazarus" onto whatever else began with
        Lazarus.
        """
        keys = [normalize(alias)]
        words = alias.split()
        if len(words) > 1 and words[-1].lower() in GENERIC_SUFFIXES:
            stripped = normalize(" ".join(words[:-1]))
            if stripped:
                keys.append(stripped)
        return keys

    def __len__(self) -> int:
        return len(self.groups)

    def resolve(self, *names: str) -> AttackGroup | None:
        """
        Find the ATT&CK group matching any of the given names.

        Args:
            names: Candidate names, most authoritative first (typically the
                Maltrail group name followed by its aliases)

        Returns:
            The matching group, or None when the actor is not tracked by ATT&CK
        """
        for name in names:
            if not name:
                continue

            match = self._by_alias.get(normalize(name))
            if match:
                return match

            # Maltrail names some groups by bare number ("28" from apt_28.txt).
            digits = normalize(name)
            if digits.isdigit():
                match = self._by_alias.get(f"apt{digits}")
                if match:
                    return match

        return None


@lru_cache(maxsize=1)
def load_index(path: Path | None = None) -> AttackGroupIndex:
    """
    Load the vendored ATT&CK group index.

    Args:
        path: Override for the data file, mainly for tests

    Returns:
        An index; empty if the data file is missing or unreadable, so a
        packaging mistake degrades attribution rather than breaking collection.
    """
    data_file = Path(path) if path else DATA_FILE

    try:
        payload = json.loads(data_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return AttackGroupIndex([])

    return AttackGroupIndex([AttackGroup(**entry) for entry in payload.get("groups", [])])
