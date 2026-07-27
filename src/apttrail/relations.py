"""
How APT groups relate to one another.

Four kinds of evidence, deliberately kept apart rather than blended into one
"relatedness" number, because they are not equally strong and a reader deserves
to know which one they are looking at:

- **infrastructure** — the same domain or address attributed to both groups.
  The strongest signal here and, in this corpus, a rare one: 268 of 154,910
  values touch more than one group. That rarity is what makes it worth showing.
  It also reproduces relationships the field already accepts - Lazarus Group
  and APT38 share 56 indicators - which is the only external check available.
- **reporting** — the same write-up cites both groups. Corroborating rather
  than conclusive: a survey paper naming twelve actors links none of them.
- **software** — shared named malware or tooling, weighted by how rare the tool
  is. Mimikatz appears under 28 groups and should count for almost nothing;
  a bespoke implant should count for a lot.
- **technique** — overlap in published ATT&CK techniques, as Jaccard rather
  than a raw count. T1566.001 is attributed to 54 of 95 profiled groups, so
  counting shared techniques without normalising says everyone is related to
  everyone.

Nothing here asserts that two groups *are* the same actor or cooperate. It says
what the sources have in common, and names which source.
"""

from collections import Counter, defaultdict
from itertools import combinations
from typing import Any

from apttrail.profiles import ProfileIndex

#: An indicator or report touching this many groups is shared infrastructure or
#: a survey, not a link between any particular pair of them.
MAX_SHARED_OWNERS = 8

#: Technique overlap below this is the common core every actor shares. The
#: highest overlap in the corpus is 0.44, so this keeps a handful of genuinely
#: close pairs rather than a threshold picked to look tidy.
MIN_TECHNIQUE_JACCARD = 0.40

#: A tool attributed to this many profiled groups is commodity - Mimikatz,
#: Cobalt Strike, PsExec, certutil - and two groups both using one says nothing
#: about either. Dropped outright rather than down-weighted: leaving them in
#: produced edges whose entire evidence was "shares ipconfig, Net".
COMMODITY_TOOL_GROUPS = 8

#: Weakest software overlap worth reporting, over what is left.
MIN_SOFTWARE_WEIGHT = 0.30

#: Evidence ordered by how much it actually supports a claim of a relationship.
TIERS = {"infrastructure": 0, "reporting": 1, "software": 2, "technique": 3}


def _pairs(owners: dict[str, set[str]]) -> Counter[tuple[str, str]]:
    """Count how many things each pair of groups has in common."""
    counted: Counter[tuple[str, str]] = Counter()
    for group_set in owners.values():
        if 1 < len(group_set) < MAX_SHARED_OWNERS:
            for pair in combinations(sorted(group_set), 2):
                counted[pair] += 1
    return counted


def build_relations(entries: dict[str, dict[str, Any]], profiles: ProfileIndex) -> dict[str, list[dict[str, Any]]]:
    """
    Work out which groups relate to which, and on what evidence.

    Args:
        entries: Merged group entries, keyed by slug
        profiles: Vendored actor profiles, for techniques and software

    Returns:
        Slug to its relations, each carrying the kind of evidence, a weight,
        and a sentence naming what is actually shared
    """
    edges: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)

    # Shared infrastructure.
    owners: dict[str, set[str]] = defaultdict(set)
    for slug, entry in entries.items():
        for values in entry["indicators"].values():
            for value in values:
                owners[value].add(slug)
    for pair, count in _pairs(owners).items():
        edges[pair]["infrastructure"] = {
            "weight": float(count),
            "detail": f"{count:,} shared indicator{'s' if count != 1 else ''}",
        }

    # Shared reporting.
    cited: dict[str, set[str]] = defaultdict(set)
    for slug, entry in entries.items():
        for url in entry.get("references") or []:
            cited[url].add(slug)
    for pair, count in _pairs(cited).items():
        edges[pair]["reporting"] = {
            "weight": float(count),
            "detail": f"{count:,} report{'s' if count != 1 else ''} cite both",
        }

    # Shared tooling and techniques, for the groups ATT&CK profiles.
    software: dict[str, set[str]] = {}
    techniques: dict[str, set[str]] = {}
    for slug, entry in entries.items():
        profile = profiles.get(entry.get("attack_id"))
        if profile:
            software[slug] = {item.name for item in profile.software}
            techniques[slug] = {item.id for item in profile.techniques}

    tool_frequency = Counter(name for names in software.values() for name in names)
    commodity = {name for name, count in tool_frequency.items() if count >= COMMODITY_TOOL_GROUPS}
    for a, b in combinations(sorted(software), 2):
        common = (software[a] & software[b]) - commodity
        if not common:
            continue
        # Of what is left, a rarer tool counts for more.
        weight = sum(1 / tool_frequency[name] for name in common)
        if weight >= MIN_SOFTWARE_WEIGHT:
            named = sorted(common, key=lambda n: tool_frequency[n])[:3]
            edges[(a, b)]["software"] = {
                "weight": round(weight, 3),
                "detail": "shares "
                + ", ".join(named)
                + (f" and {len(common) - len(named)} more" if len(common) > 3 else ""),
            }

    for a, b in combinations(sorted(techniques), 2):
        union = techniques[a] | techniques[b]
        if not union:
            continue
        overlap = len(techniques[a] & techniques[b]) / len(union)
        if overlap >= MIN_TECHNIQUE_JACCARD:
            edges[(a, b)]["technique"] = {
                "weight": round(overlap, 3),
                "detail": f"{round(overlap * 100)}% of published techniques in common",
            }

    relations: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for (a, b), kinds in edges.items():
        for other, slug in ((b, a), (a, b)):
            relations[slug].append(
                {
                    "slug": other,
                    "evidence": [
                        {"kind": kind, **body} for kind, body in sorted(kinds.items(), key=lambda kv: TIERS[kv[0]])
                    ],
                }
            )

    for slug in relations:
        relations[slug].sort(key=lambda r: (TIERS[r["evidence"][0]["kind"]], -r["evidence"][0]["weight"]))

    return dict(relations)


def to_graph(
    entries: dict[str, dict[str, Any]],
    relations: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """
    Flatten the relations into a node and edge list.

    Args:
        entries: Merged group entries, for node labels and sizes
        relations: Output of :func:`build_relations`

    Returns:
        A graph payload; only groups with at least one relation are included,
        because 220 unconnected dots is not a picture of anything
    """
    seen: set[tuple[str, str]] = set()
    links: list[dict[str, Any]] = []
    for slug, related in relations.items():
        for item in related:
            pair = (slug, item["slug"]) if slug < item["slug"] else (item["slug"], slug)
            if pair in seen:
                continue
            seen.add(pair)
            links.append({"source": pair[0], "target": pair[1], "evidence": item["evidence"]})

    connected = {slug for link in links for slug in (link["source"], link["target"])}
    nodes = []
    for slug in sorted(connected):
        entry = entries[slug]
        nodes.append(
            {
                "slug": slug,
                "attack_id": entry.get("attack_id"),
                "label": entry.get("attack_name") or ", ".join(entry["maltrail_groups"]),
                "indicators": sum(len(values) for values in entry["indicators"].values()),
            }
        )

    return {"nodes": nodes, "links": links}
