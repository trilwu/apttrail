"""
Per-indicator lookup index.

Everything else in the feed is keyed by actor. That is the wrong shape for the
most common question a responder actually has: *an alert fired on this domain -
what do you know about it?* Answering that previously meant downloading the
whole feed and grepping.

The index shards indicators by the first byte of ``sha256(value)`` into 256
files, so a client fetches roughly 1/256th of the data to answer one lookup and
can compute the path offline:

    shard = sha256("evil.example").hexdigest()[:2]
    GET /by-indicator/<shard>.json

Sharding on a hash rather than on, say, the first letter keeps the shards
evenly sized regardless of how indicator values cluster.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from apttrail.models import APTGroup, FeedMetadata, IndicatorType

SHARD_COUNT_HEX = 2  # 256 shards


def shard_for(value: str) -> str:
    """
    Return the shard name holding an indicator.

    Args:
        value: Indicator value, exactly as it appears in the feed

    Returns:
        Two lowercase hex characters
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:SHARD_COUNT_HEX]


class LookupExporter:
    """Writes the sharded per-indicator index."""

    def __init__(self, output_dir: Path | str) -> None:
        """
        Args:
            output_dir: Directory to populate; created if absent
        """
        self.output_dir = Path(output_dir)

    def export(self, apt_groups: dict[str, APTGroup], metadata: FeedMetadata) -> int:
        """
        Write the index.

        Args:
            apt_groups: Collected APT groups
            metadata: Feed metadata, recorded in the shard index

        Returns:
            Number of distinct indicators indexed
        """
        entries = self._collect(apt_groups)

        shards: dict[str, dict[str, Any]] = {}
        for value, entry in entries.items():
            shards.setdefault(shard_for(value), {})[value] = entry

        directory = self.output_dir / "by-indicator"
        directory.mkdir(parents=True, exist_ok=True)

        for shard, payload in shards.items():
            (directory / f"{shard}.json").write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
                newline="\n",
            )

        (directory / "index.json").write_text(
            json.dumps(
                {
                    "generated_at": metadata.generated_at.isoformat(),
                    "indicators": len(entries),
                    "shards": sorted(shards),
                    "scheme": "sha256(value) hex, first 2 characters",
                    "example": "curl $SITE/by-indicator/$(printf %s evil.example | sha256sum | cut -c1-2).json",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        return len(entries)

    @staticmethod
    def _collect(apt_groups: dict[str, APTGroup]) -> dict[str, dict[str, Any]]:
        """
        Build one entry per distinct indicator value.

        An indicator can belong to more than one group, so groups and ATT&CK
        ids accumulate rather than overwrite, and the earliest first_seen wins.
        """
        entries: dict[str, dict[str, Any]] = {}

        for name in sorted(apt_groups):
            group = apt_groups[name]
            attack_id = group.metadata.attack_id

            for indicator_type, indicators in group.indicators.items():
                if indicator_type is IndicatorType.UNKNOWN:
                    continue

                for indicator in indicators:
                    entry = entries.setdefault(
                        indicator.value,
                        {
                            "type": indicator_type.value,
                            "groups": [],
                            "attack_ids": [],
                            "first_seen": None,
                            "first_seen_precision": None,
                            "references": [],
                        },
                    )

                    if name not in entry["groups"]:
                        entry["groups"].append(name)
                    if attack_id and attack_id not in entry["attack_ids"]:
                        entry["attack_ids"].append(attack_id)
                    # The report that published this indicator. Without it the
                    # lookup answers who and when but not why, which is the
                    # question that decides whether a hit is worth escalating.
                    for url in indicator.references:
                        if url not in entry["references"]:
                            entry["references"].append(url)

                    if indicator.first_seen:
                        seen = indicator.first_seen.date().isoformat()
                        if entry["first_seen"] is None or seen < entry["first_seen"]:
                            entry["first_seen"] = seen
                            entry["first_seen_precision"] = indicator.first_seen_precision

        # Drop the key entirely when unknown rather than carrying a null.
        for entry in entries.values():
            if entry["first_seen"] is None:
                del entry["first_seen"]
            if not entry["first_seen_precision"]:
                del entry["first_seen_precision"]
            if not entry["references"]:
                del entry["references"]

        return entries
