#!/usr/bin/env python3
"""
Build the actor profile data that backs the per-group pages.

Security vendors publish an actor page: who they are, where they are believed
to operate from, who they target, what techniques they use, and what to read
next. All of that is already published as open data across the MISP galaxy;
this stitches it into one file per ATT&CK group.

Sources, all from https://github.com/MISP/misp-galaxy:

- ``mitre-intrusion-set``  description, references, and ``uses`` relations
- ``mitre-attack-pattern`` technique ids and names, to resolve those relations
- ``mitre-malware`` / ``mitre-tool``  named software the group is known to use
- ``threat-actor``  country, suspected sponsor, targeted sectors and victims,
  which ATT&CK itself does not record

Output is gzipped and vendored so page generation stays offline.

Usage:
    python scripts/refresh_attack_profiles.py
"""

import gzip
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

GALAXY = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{name}.json"
OUTPUT = Path(__file__).resolve().parents[1] / "src" / "apttrail" / "data" / "attack_profiles.json.gz"

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
# ATT&CK descriptions are littered with markdown links back to attack.mitre.org.
_MD_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
_CITATION = re.compile(r"\(Citation:[^)]*\)")


def normalize(name: str) -> str:
    """Must match apttrail.attribution.normalize."""
    return _NON_ALNUM.sub("", name.lower())


def fetch(cluster: str) -> dict[str, Any]:
    url = GALAXY.format(name=cluster)
    print(f"fetching {cluster}")
    with urllib.request.urlopen(url, timeout=180) as response:  # noqa: S310 - fixed https URL
        return json.load(response)


def clean_description(text: str) -> str:
    """
    Strip ATT&CK markup down to readable prose.

    Descriptions carry markdown links and inline "(Citation: ...)" markers that
    are noise on a rendered page; the references list covers the sources.
    """
    text = _MD_LINK.sub(r"\1", text)
    text = _CITATION.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def as_list(value: Any) -> list[str]:
    """Galaxy fields are sometimes a scalar and sometimes a list."""
    if value is None:
        return []
    return sorted(set(value)) if isinstance(value, list) else [value]


def index_by_uuid(cluster: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["uuid"]: entry for entry in cluster["values"]}


def short_name(value: str) -> str:
    """MISP cluster values look like "Rundll32 - T1218.011"."""
    return value.rsplit(" - ", 1)[0].strip()


def build(
    intrusion_sets: dict[str, Any],
    patterns: dict[str, Any],
    malware: dict[str, Any],
    tools: dict[str, Any],
    threat_actors: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    by_pattern = index_by_uuid(patterns)
    by_software = {**index_by_uuid(malware), **index_by_uuid(tools)}

    # threat-actor holds the geopolitical detail ATT&CK omits.
    actor_by_alias: dict[str, dict[str, Any]] = {}
    for entry in threat_actors["values"]:
        meta = entry.get("meta", {})
        for alias in {entry["value"], *(meta.get("synonyms") or [])}:
            actor_by_alias.setdefault(normalize(alias), entry)

    profiles: dict[str, dict[str, Any]] = {}

    for cluster in intrusion_sets["values"]:
        meta = cluster.get("meta", {})
        group_id = meta.get("external_id")
        if not group_id or not group_id.startswith("G"):
            continue

        name = short_name(cluster["value"])
        related = cluster.get("related") or []

        techniques = []
        software = []
        for relation in related:
            if relation.get("type") != "uses":
                continue
            target = relation.get("dest-uuid")

            if target in by_pattern:
                pattern = by_pattern[target]
                techniques.append({"id": pattern["meta"].get("external_id", ""), "name": short_name(pattern["value"])})
            elif target in by_software:
                item = by_software[target]
                software.append({"id": item["meta"].get("external_id", ""), "name": short_name(item["value"])})

        actor = actor_by_alias.get(normalize(name))
        for alias in meta.get("synonyms") or []:
            if actor:
                break
            actor = actor_by_alias.get(normalize(alias))
        actor_meta = actor.get("meta", {}) if actor else {}

        profiles[group_id] = {
            "name": name,
            "description": clean_description(cluster.get("description", "")),
            "country": actor_meta.get("country"),
            "sponsor": actor_meta.get("cfr-suspected-state-sponsor"),
            "sectors": sorted(set(actor_meta.get("cfr-target-category") or [])),
            "victims": sorted(set(actor_meta.get("cfr-suspected-victims") or [])),
            "activity": as_list(actor_meta.get("cfr-type-of-incident")),
            "techniques": sorted(
                {(t["id"], t["name"]) for t in techniques if t["id"]},
            ),
            "software": sorted({(s["id"], s["name"]) for s in software if s["name"]}),
            "references": sorted(set(meta.get("refs") or []))[:25],
        }

    return profiles


def main() -> int:
    profiles = build(
        fetch("mitre-intrusion-set"),
        fetch("mitre-attack-pattern"),
        fetch("mitre-malware"),
        fetch("mitre-tool"),
        fetch("threat-actor"),
    )

    described = sum(1 for p in profiles.values() if p["description"])
    located = sum(1 for p in profiles.values() if p["country"])
    with_ttp = sum(1 for p in profiles.values() if p["techniques"])
    sectors = sum(1 for p in profiles.values() if p["sectors"])

    print(f"{len(profiles)} groups")
    print(f"  description: {described}")
    print(f"  country:     {located}")
    print(f"  sectors:     {sectors}")
    print(f"  techniques:  {with_ttp}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(OUTPUT, "wb", mtime=0) as raw:
        raw.write(json.dumps(profiles, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8"))

    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
