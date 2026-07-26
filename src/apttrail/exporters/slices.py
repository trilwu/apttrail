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
        for name in sorted(apt_groups):
            group = apt_groups[name]
            if not group.total_indicators:
                continue

            slug = self._slug(group, name)
            self._write_group(by_group_dir, slug, name, group, generated)
            index.append(self._index_entry(slug, name, group))
            written["by_group"] += 1

        self._write_index(index, metadata, written)
        return written

    @staticmethod
    def _slug(group: APTGroup, name: str) -> str:
        """Prefer the ATT&CK id so ATT&CK-driven lookups resolve directly."""
        return group.metadata.attack_id or name

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

    def _write_group(self, directory: Path, slug: str, name: str, group: APTGroup, generated: str) -> None:
        metadata = group.metadata
        payload = {
            "group": name,
            "attack_id": metadata.attack_id,
            "attack_name": metadata.attack_name,
            "attack_url": metadata.attack_url,
            "aliases": sorted(metadata.aliases),
            "references": sorted(metadata.references),
            "last_modified": metadata.last_modified.isoformat() if metadata.last_modified else None,
            "generated_at": generated,
            "counts": group.indicator_counts,
            "indicators": {
                indicator_type.value: sorted(i.value for i in indicators)
                for indicator_type, indicators in sorted(group.indicators.items(), key=lambda kv: kv[0].value)
            },
        }
        (directory / f"{slug}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        # Flat domain list per group: the single most requested shape for
        # hunting one actor in DNS logs.
        domains = sorted(i.value for i in group.indicators.get(IndicatorType.DOMAIN, set()))
        if domains:
            label = f"{metadata.attack_id} {metadata.attack_name}" if metadata.attack_id else name
            self._write_list(directory / f"{slug}-domain.txt", f"{label} domains", domains, generated)

    @staticmethod
    def _index_entry(slug: str, name: str, group: APTGroup) -> dict[str, Any]:
        return {
            "slug": slug,
            "group": name,
            "attack_id": group.metadata.attack_id,
            "attack_name": group.metadata.attack_name,
            "aliases": sorted(group.metadata.aliases),
            "total": group.total_indicators,
            "counts": group.indicator_counts,
        }

    def _write_index(self, index: list[dict[str, Any]], metadata: FeedMetadata, written: dict[str, int]) -> None:
        attributed = sum(1 for entry in index if entry["attack_id"])
        payload = {
            "generated_at": metadata.generated_at.isoformat(),
            "project": PROJECT_URL,
            "totals": {
                "groups": len(index),
                "groups_mapped_to_attack": attributed,
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
