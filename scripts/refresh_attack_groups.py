#!/usr/bin/env python3
"""
Regenerate src/apttrail/data/attack_groups.json from the MISP galaxy.

Two clusters are combined:

- ``mitre-intrusion-set`` supplies the authoritative ATT&CK group ids and their
  official aliases.
- ``threat-actor`` supplies far richer vendor naming. Where one of its clusters
  unambiguously identifies a single ATT&CK group, its synonyms are folded into
  that group. This is what lets APTtrail resolve names like DEATHSTALKER,
  GHOSTEMPEROR or UNC4210, which ATT&CK lists under other names.

Usage:
    python scripts/refresh_attack_groups.py
"""

import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

GALAXY = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{name}.json"
OUTPUT = Path(__file__).resolve().parents[1] / "src" / "apttrail" / "data" / "attack_groups.json"

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize(name: str) -> str:
    """Must match apttrail.attribution.normalize."""
    return _NON_ALNUM.sub("", name.lower())


def fetch(cluster: str) -> dict:
    url = GALAXY.format(name=cluster)
    print(f"fetching {url}")
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - fixed https URL
        return json.load(response)


def base_groups(intrusion_sets: dict) -> list[dict]:
    """Extract ATT&CK groups and their official aliases."""
    groups = []
    for cluster in intrusion_sets["values"]:
        meta = cluster.get("meta", {})
        external_id = meta.get("external_id")
        if not external_id or not external_id.startswith("G"):
            continue

        # cluster["value"] is formatted "APT28 - G0007"
        name = cluster["value"].rsplit(" - ", 1)[0].strip()
        groups.append(
            {
                "id": external_id,
                "name": name,
                "aliases": sorted({name, *(meta.get("synonyms") or [])}),
            }
        )

    groups.sort(key=lambda g: g["id"])
    return groups


def expand_with_threat_actors(groups: list[dict], threat_actors: dict) -> int:
    """
    Fold threat-actor synonyms into the ATT&CK groups they identify.

    A cluster is only used when it resolves to exactly one ATT&CK group;
    ambiguous clusters are skipped rather than guessed at.
    """
    by_alias: dict[str, str] = {}
    for group in groups:
        for alias in group["aliases"]:
            by_alias.setdefault(normalize(alias), group["id"])

    additions: dict[str, set[str]] = defaultdict(set)
    for cluster in threat_actors["values"]:
        names = {cluster["value"], *(cluster.get("meta", {}).get("synonyms") or [])}
        matched = {by_alias[normalize(n)] for n in names if normalize(n) in by_alias}

        if len(matched) == 1:
            additions[matched.pop()].update(names)

    added = 0
    for group in groups:
        new_aliases = additions.get(group["id"], set())
        merged = sorted({*group["aliases"], *new_aliases})
        added += len(merged) - len(group["aliases"])
        group["aliases"] = merged

    return added


def main() -> int:
    intrusion_sets = fetch("mitre-intrusion-set")
    threat_actors = fetch("threat-actor")

    groups = base_groups(intrusion_sets)
    added = expand_with_threat_actors(groups, threat_actors)

    payload = {
        "source": "https://github.com/MISP/misp-galaxy (mitre-intrusion-set + threat-actor)",
        "galaxy_version": intrusion_sets.get("version"),
        "groups": groups,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    total_aliases = sum(len(g["aliases"]) for g in groups)
    print(f"{len(groups)} groups, {total_aliases} aliases (+{added} from threat-actor) -> {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
