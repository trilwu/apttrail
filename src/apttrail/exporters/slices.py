"""
Analyst-facing slices of the feed.

The single 7MB JSON is the wrong shape for most day-to-day work. A responder
chasing one actor wants that actor's indicators; someone filling a blocklist
wants a flat list of domains. Both are one HTTP GET away here, with no parsing:

    by-type/domain.txt          every domain, one per line
    by-type/ipv4.txt            every IPv4 address, no ports
    by-group/G0007.json         one ATT&CK group, full detail
    by-group/G0007-domain.txt   one ATT&CK group, flat list
    index.json                  what exists, with counts

File names use exactly the type tokens that appear in the JSON feed, so a
client can build any path mechanically.

Files are named by ATT&CK group id where the actor is mapped, falling back to
the Maltrail name, so a lookup from an ATT&CK-driven workflow lands directly on
the right file.
"""

import json
from pathlib import Path
from typing import Any

from apttrail.models import APTGroup, FeedMetadata, IndicatorType

#: Types that make sense as flat, directly consumable lists.
FLAT_TYPES = (
    IndicatorType.DOMAIN,
    IndicatorType.IPV4,
    IndicatorType.IPV6,
    IndicatorType.URL,
    IndicatorType.URL_PATH,
    IndicatorType.MD5,
    IndicatorType.SHA1,
    IndicatorType.SHA256,
)

BANNER = "# APTtrail - {title}\n# {count} indicators | {url}\n# Generated {generated}\n"
PROJECT_URL = "https://github.com/trilwu/apttrail"


class SliceExporter:
    """Writes per-type and per-group slices under an output directory."""

    def __init__(self, output_dir: Path | str) -> None:
        """
        Args:
            output_dir: Directory to populate; created if absent
        """
        self.output_dir = Path(output_dir)

    def export(self, apt_groups: dict[str, APTGroup], metadata: FeedMetadata) -> dict[str, int]:
        """
        Write every slice.

        Args:
            apt_groups: Collected APT groups
            metadata: Feed metadata, used for the generation banner

        Returns:
            Counts of files written, keyed by slice kind
        """
        by_type_dir = self.output_dir / "by-type"
        by_group_dir = self.output_dir / "by-group"
        by_type_dir.mkdir(parents=True, exist_ok=True)
        by_group_dir.mkdir(parents=True, exist_ok=True)

        generated = metadata.generated_at.isoformat()
        written = {"by_type": 0, "by_group": 0}

        for indicator_type in FLAT_TYPES:
            values = self._collect_type(apt_groups, indicator_type)
            if not values:
                continue

            self._write_list(
                by_type_dir / f"{indicator_type.value}.txt",
                title=f"all {indicator_type.value} indicators",
                values=values,
                generated=generated,
            )
            written["by_type"] += 1

        index: list[dict[str, Any]] = []
        for slug, entry in sorted(self._merge_by_slug(apt_groups).items()):
            self._write_group(by_group_dir, slug, entry, generated)
            index.append(self._index_entry(slug, entry))
            written["by_group"] += 1

        self._write_index(index, metadata, written)
        return written

    @staticmethod
    def _slug(group: APTGroup, name: str) -> str:
        """Prefer the ATT&CK id so ATT&CK-driven lookups resolve directly."""
        return group.metadata.attack_id or name

    def _merge_by_slug(self, apt_groups: dict[str, APTGroup]) -> dict[str, dict[str, Any]]:
        """
        Combine Maltrail groups that resolve to the same ATT&CK intrusion set.

        Maltrail tracks DONOT, PATCHWORK and HANGOVER separately; ATT&CK calls
        all three G0040. Writing them to the same slug without merging meant the
        last one won, so a request for Patchwork's infrastructure returned 984
        of its 2,225 indicators. 22 ATT&CK ids are affected.

        Args:
            apt_groups: Collected groups, keyed by Maltrail name

        Returns:
            Merged entries keyed by slug, skipping groups with no indicators
        """
        merged: dict[str, dict[str, Any]] = {}

        for name in sorted(apt_groups):
            group = apt_groups[name]
            if not group.total_indicators:
                continue

            metadata = group.metadata
            slug = self._slug(group, name)
            entry = merged.setdefault(
                slug,
                {
                    "maltrail_groups": [],
                    "attack_id": metadata.attack_id,
                    "attack_name": metadata.attack_name,
                    "attack_url": metadata.attack_url,
                    "aliases": set(),
                    "references": set(),
                    "last_modified": None,
                    "indicators": {},
                },
            )

            entry["maltrail_groups"].append(name)
            entry["aliases"].update(metadata.aliases)
            entry["references"].update(metadata.references)
            if metadata.last_modified and (
                entry["last_modified"] is None or metadata.last_modified > entry["last_modified"]
            ):
                entry["last_modified"] = metadata.last_modified

            for indicator_type, indicators in group.indicators.items():
                bucket = entry["indicators"].setdefault(indicator_type.value, set())
                bucket.update(i.value for i in indicators)

        return merged

    @staticmethod
    def _collect_type(apt_groups: dict[str, APTGroup], indicator_type: IndicatorType) -> list[str]:
        values: set[str] = set()
        for group in apt_groups.values():
            for indicator in group.indicators.get(indicator_type, set()):
                # Ports belong to the observation, not to the address; a
                # blocklist consumer wants the bare address.
                values.add(indicator.value.split(":")[0] if indicator_type is IndicatorType.IPV4 else indicator.value)
        return sorted(values)

    def _write_list(self, path: Path, title: str, values: list[str], generated: str) -> None:
        banner = BANNER.format(title=title, count=len(values), url=PROJECT_URL, generated=generated)
        path.write_text(banner + "\n".join(values) + "\n", encoding="utf-8", newline="\n")

    def _write_group(self, directory: Path, slug: str, entry: dict[str, Any], generated: str) -> None:
        last_modified = entry["last_modified"]
        payload = {
            "slug": slug,
            "maltrail_groups": sorted(entry["maltrail_groups"]),
            "attack_id": entry["attack_id"],
            "attack_name": entry["attack_name"],
            "attack_url": entry["attack_url"],
            "aliases": sorted(entry["aliases"]),
            "references": sorted(entry["references"]),
            "last_modified": last_modified.isoformat() if last_modified else None,
            "generated_at": generated,
            "counts": self._counts(entry),
            "indicators": {
                indicator_type: sorted(values) for indicator_type, values in sorted(entry["indicators"].items())
            },
        }
        (directory / f"{slug}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        # Flat domain list per group: the single most requested shape for
        # hunting one actor in DNS logs.
        domains = sorted(entry["indicators"].get(IndicatorType.DOMAIN.value, set()))
        if domains:
            label = f"{entry['attack_id']} {entry['attack_name']}" if entry["attack_id"] else slug
            self._write_list(directory / f"{slug}-domain.txt", f"{label} domains", domains, generated)

    @staticmethod
    def _counts(entry: dict[str, Any]) -> dict[str, int]:
        return {indicator_type: len(values) for indicator_type, values in sorted(entry["indicators"].items())}

    def _index_entry(self, slug: str, entry: dict[str, Any]) -> dict[str, Any]:
        counts = self._counts(entry)
        return {
            "slug": slug,
            "maltrail_groups": sorted(entry["maltrail_groups"]),
            "attack_id": entry["attack_id"],
            "attack_name": entry["attack_name"],
            "aliases": sorted(entry["aliases"]),
            "total": sum(counts.values()),
            "counts": counts,
        }

    def _write_index(self, index: list[dict[str, Any]], metadata: FeedMetadata, written: dict[str, int]) -> None:
        # Two different counts, and conflating them is misleading: several
        # Maltrail groups can share one ATT&CK id, so the number of mapped
        # source groups exceeds the number of distinct intrusion sets.
        attack_ids = {entry["attack_id"] for entry in index if entry["attack_id"]}
        mapped_sources = sum(len(entry["maltrail_groups"]) for entry in index if entry["attack_id"])
        source_groups = sum(len(entry["maltrail_groups"]) for entry in index)

        payload = {
            "generated_at": metadata.generated_at.isoformat(),
            "project": PROJECT_URL,
            "totals": {
                "slices": len(index),
                "maltrail_groups": source_groups,
                "maltrail_groups_mapped_to_attack": mapped_sources,
                "attack_groups": len(attack_ids),
                "indicators": sum(entry["total"] for entry in index),
                "by_type_files": written["by_type"],
            },
            "groups": index,
        }
        (self.output_dir / "index.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self._write_html_index(payload)

    def _write_html_index(self, payload: dict[str, Any]) -> None:
        """
        Write a browsable landing page.

        Served over GitHub Pages this is the first thing a responder sees, so
        it answers the only two questions that matter on arrival: what is here,
        and what is the URL for the actor I care about.
        """
        totals = payload["totals"]
        groups = sorted(payload["groups"], key=lambda g: -g["total"])

        rows = "\n".join(
            "<tr>"
            f"<td>{self._esc(g['attack_id'] or '')}</td>"
            f"<td>{self._esc(g['attack_name'] or ', '.join(g['maltrail_groups']))}</td>"
            f"<td class=n>{g['total']:,}</td>"
            f"<td><a href=\"by-group/{self._esc(g['slug'])}.json\">json</a>"
            + (
                f" · <a href=\"by-group/{self._esc(g['slug'])}-domain.txt\">domains</a>"
                if g["counts"].get("domain")
                else ""
            )
            + "</td></tr>"
            for g in groups
        )

        lists = "\n".join(
            f'<li><a href="by-type/{t.value}.txt">{t.value}.txt</a></li>'
            for t in FLAT_TYPES
            if (self.output_dir / "by-type" / f"{t.value}.txt").exists()
        )

        html = f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>APTtrail - APT indicators with ATT&amp;CK attribution</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.55 ui-sans-serif, system-ui, sans-serif; max-width: 60rem;
        margin: 2rem auto; padding: 0 1rem; }}
 h1 {{ margin-bottom: .2rem; }}
 .sub {{ opacity: .75; margin-top: 0; }}
 code, pre {{ font-family: ui-monospace, monospace; font-size: .9em; }}
 pre {{ background: #8881; padding: .8rem; overflow-x: auto; border-radius: 6px; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: .5rem; }}
 th, td {{ text-align: left; padding: .3rem .6rem; border-bottom: 1px solid #8883; }}
 td.n, th.n {{ text-align: right; font-variant-numeric: tabular-nums; }}
 ul {{ columns: 2; }}
</style>
<h1>APTtrail</h1>
<p class=sub>{totals["indicators"]:,} indicators &middot;
{totals["maltrail_groups"]} APT groups &middot;
{totals["maltrail_groups_mapped_to_attack"]} mapped onto {totals["attack_groups"]} MITRE ATT&amp;CK intrusion sets &middot;
generated {self._esc(payload["generated_at"])}</p>

<p>Every indicator carries the group it belongs to. Plain files, stable URLs,
no API key. <a href="{PROJECT_URL}">Source and docs</a>.</p>

<pre>curl -sL {PROJECT_URL.replace("github.com", "trilwu.github.io").replace("/trilwu/apttrail", "/apttrail")}/by-group/G0007-domain.txt</pre>

<h2>Full lists</h2>
<ul>
{lists}
<li><a href="index.json">index.json</a></li>
</ul>

<h2>By group</h2>
<table>
<tr><th>ATT&amp;CK</th><th>Group</th><th class=n>IOCs</th><th>Files</th></tr>
{rows}
</table>
</html>
"""
        (self.output_dir / "index.html").write_text(html, encoding="utf-8", newline="\n")

    @staticmethod
    def _esc(value: str) -> str:
        """Minimal HTML escaping for values that come from upstream data."""
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
