"""
JSON exporter for APTtrail.

Exports threat indicators to JSON format with full metadata.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata


class JSONExporter(BaseExporter):
    """
    Exports indicators to JSON format.

    Produces a structured JSON file with APT group metadata,
    indicators grouped by type, and optional timestamps.
    """

    def __init__(self, output_path: Path | str) -> None:
        """Initialize the JSON exporter."""
        super().__init__(output_path)

    def export(
        self,
        apt_groups: dict[str, APTGroup],
        metadata: FeedMetadata,
        commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to JSON format.

        Args:
            apt_groups: Dictionary of APT groups with indicators
            metadata: Feed metadata
            commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        output = self._build_output(apt_groups, metadata, commit_references)
        content = json.dumps(output, indent=2, ensure_ascii=False, sort_keys=True, default=str)
        return self._write_if_changed(content)

    def _build_output(
        self,
        apt_groups: dict[str, APTGroup],
        metadata: FeedMetadata,
        commit_references: dict[str, list[str]] | None,
    ) -> dict[str, Any]:
        """Build the output dictionary structure."""
        output: dict[str, Any] = {
            "source": metadata.source,
            "generated_at": metadata.generated_at.isoformat(),
            "total_apt_groups": len(apt_groups),
            "apt_groups": {},
        }

        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            output["apt_groups"][apt_name] = self._serialize_apt_group(apt_group, commit_references)

        return output

    def _serialize_apt_group(
        self,
        apt_group: APTGroup,
        commit_references: dict[str, list[str]] | None,
    ) -> dict[str, Any]:
        """Serialize a single APT group."""
        indicators_data = self._serialize_indicators_with_timestamps(apt_group, commit_references)

        return {
            "metadata": {
                "filename": apt_group.metadata.filename,
                "aliases": sorted(apt_group.metadata.aliases),
                "references": sorted(apt_group.metadata.references),
                "last_modified": (
                    apt_group.metadata.last_modified.isoformat() if apt_group.metadata.last_modified else None
                ),
                "attack_id": apt_group.metadata.attack_id,
                "attack_name": apt_group.metadata.attack_name,
                "attack_url": apt_group.metadata.attack_url,
            },
            "indicators": indicators_data,
            "statistics": {
                "total": apt_group.total_indicators,
                "by_type": apt_group.indicator_counts,
            },
        }

    def _serialize_indicators_with_timestamps(
        self,
        apt_group: APTGroup,
        commit_references: dict[str, list[str]] | None,
    ) -> dict[str, Any]:
        """Serialize indicators with timestamp grouping."""
        result: dict[str, Any] = {}

        for indicator_type in sorted(apt_group.indicators.keys(), key=lambda x: x.value):
            indicators = apt_group.indicators[indicator_type]

            # The grouped shape carries dates and source reports; the flat list
            # carries neither, so use it only when there is nothing to lose.
            has_context = any(ind.first_seen or ind.references for ind in indicators)

            if has_context:
                result[indicator_type.value] = self._group_by_timestamp(indicators, commit_references)
            else:
                result[indicator_type.value] = sorted(ind.value for ind in indicators)

        return result

    def _group_by_timestamp(
        self,
        indicators: set[Any],
        commit_references: dict[str, list[str]] | None,
    ) -> list[dict[str, Any]]:
        """
        Group indicators by first_seen date, commit and source report.

        The report an indicator was filed under upstream is part of the key:
        two domains dated the same day but published by different write-ups are
        separate findings, and merging them would leave the reader unable to
        tell which reference belongs to which value.
        """
        grouped: dict[tuple[str, str, str, tuple[str, ...]], list[str]] = defaultdict(list)

        for indicator in indicators:
            first_seen = indicator.first_seen.isoformat() if indicator.first_seen else "unknown"
            commit = indicator.commit_hash or ""
            precision = indicator.first_seen_precision or ""
            key = (first_seen, commit, precision, tuple(indicator.references))
            grouped[key].append(indicator.value)

        result = []
        for (first_seen, commit, precision, sources), values in sorted(grouped.items()):
            entry: dict[str, Any] = {
                "first_seen": first_seen,
                "indicators": sorted(values),
            }
            # "at-or-before" means upstream history does not reach further back;
            # the indicator may well be older.
            if precision:
                entry["first_seen_precision"] = precision

            references = list(sources)
            for url in (commit_references or {}).get(commit, []):
                if url not in references:
                    references.append(url)
            if references:
                entry["references"] = references

            result.append(entry)

        return result
