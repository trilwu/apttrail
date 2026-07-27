"""
Actor profiles: who a group is, not just what it touched.

The feed answers "which indicators belong to this actor". A responder landing
on a group also wants the things a vendor actor page carries: a description,
where the group is believed to operate from, who it targets, and which ATT&CK
techniques it uses.

All of that is open data in the MISP galaxy, stitched together by
``scripts/refresh_attack_profiles.py`` and vendored here so page generation
stays offline and reproducible.
"""

import gzip
import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

DATA_FILE = Path(__file__).parent / "data" / "attack_profiles.json.gz"
TECHNIQUE_URL = "https://attack.mitre.org/techniques/{path}/"
SOFTWARE_URL = "https://attack.mitre.org/software/{software_id}/"


class Technique(BaseModel):
    """An ATT&CK technique a group is known to use."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Technique id, e.g. T1566 or T1218.011")
    name: str = Field(..., description="Technique name")

    @property
    def url(self) -> str:
        """ATT&CK page for the technique; sub-techniques nest under the parent."""
        return TECHNIQUE_URL.format(path=self.id.replace(".", "/"))


class Software(BaseModel):
    """Malware or tooling attributed to a group."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default="", description="ATT&CK software id, when known")
    name: str = Field(..., description="Software name")

    @property
    def url(self) -> str | None:
        """
        ATT&CK page for the software.

        None where the galaxy carried a name but no id, which happens for
        tooling ATT&CK has not catalogued; the caller renders plain text rather
        than a link that would 404.
        """
        return SOFTWARE_URL.format(software_id=self.id) if self.id.startswith("S") else None


class ActorProfile(BaseModel):
    """Everything known about an actor beyond its indicators."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="ATT&CK group name")
    description: str = Field(default="", description="Prose description")
    country: str | None = Field(default=None, description="ISO country code of suspected origin")
    sponsor: str | None = Field(default=None, description="Suspected state sponsor")
    sectors: list[str] = Field(default_factory=list, description="Targeted sectors")
    victims: list[str] = Field(default_factory=list, description="Suspected victim countries")
    activity: list[str] = Field(default_factory=list, description="Types of incident, e.g. Espionage")
    techniques: list[Technique] = Field(default_factory=list, description="ATT&CK techniques used")
    software: list[Software] = Field(default_factory=list, description="Malware and tools used")
    references: list[str] = Field(default_factory=list, description="Further reading")


class ProfileIndex:
    """Lookup of ATT&CK group id to profile."""

    def __init__(self, profiles: dict[str, ActorProfile]) -> None:
        self._profiles = profiles

    def __len__(self) -> int:
        return len(self._profiles)

    def get(self, attack_id: str | None) -> ActorProfile | None:
        """
        Profile for an ATT&CK group id.

        Args:
            attack_id: e.g. "G0007"; None for groups ATT&CK does not track

        Returns:
            The profile, or None when the group is unmapped or unknown
        """
        if not attack_id:
            return None
        return self._profiles.get(attack_id)


@lru_cache(maxsize=1)
def load_profiles(path: Path | None = None) -> ProfileIndex:
    """
    Load the vendored profiles.

    Args:
        path: Override for the data file, mainly for tests

    Returns:
        An index; empty when the file is missing or unreadable, so pages fall
        back to indicators-only rather than failing to build.
    """
    data_file = Path(path) if path else DATA_FILE

    try:
        with gzip.open(data_file, "rt", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError, EOFError):
        return ProfileIndex({})

    profiles: dict[str, ActorProfile] = {}
    for group_id, payload in raw.items():
        profiles[group_id] = ActorProfile(
            name=payload.get("name", group_id),
            description=payload.get("description", ""),
            country=payload.get("country"),
            sponsor=payload.get("sponsor"),
            sectors=payload.get("sectors") or [],
            victims=payload.get("victims") or [],
            activity=payload.get("activity") or [],
            # The generator stores these as [id, name] pairs to keep the file small.
            techniques=[Technique(id=t[0], name=t[1]) for t in payload.get("techniques") or []],
            software=[Software(id=s[0], name=s[1]) for s in payload.get("software") or []],
            references=payload.get("references") or [],
        )

    return ProfileIndex(profiles)
