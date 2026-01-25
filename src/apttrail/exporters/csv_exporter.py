"""
CSV exporter for APTtrail.

Exports threat indicators to CSV format for easy ingestion.
"""

import csv
import io
from pathlib import Path

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata


class CSVExporter(BaseExporter):
    """
    Exports indicators to CSV format.

    Produces a compact CSV with one indicator per row,
    and optionally a separate metadata CSV file.
    """

    def __init__(self, output_path: Path | str, compact: bool = True) -> None:
        """
        Initialize the CSV exporter.

        Args:
            output_path: Path for the output file
            compact: If True, creates compact format without duplicating metadata
        """
        super().__init__(output_path)
        self.compact = compact

    def export(
        self,
        apt_groups: dict[str, APTGroup],
        _metadata: FeedMetadata,
        _commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to CSV format.

        Args:
            apt_groups: Dictionary of APT groups with indicators
            metadata: Feed metadata
            commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        if self.compact:
            return self._export_compact(apt_groups)
        return self._export_full(apt_groups)

    def _export_compact(self, apt_groups: dict[str, APTGroup]) -> bool:
        """Export in compact format with separate metadata file."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        # Check if we have timestamps
        has_timestamps = any(
            any(ind.first_seen for indicators in group.indicators.values() for ind in indicators)
            for group in apt_groups.values()
        )

        # Write header
        if has_timestamps:
            writer.writerow(["apt_group", "indicator_type", "indicator", "first_seen"])
        else:
            writer.writerow(["apt_group", "indicator_type", "indicator"])

        # Write data rows
        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            for indicator_type in sorted(apt_group.indicators.keys(), key=lambda x: x.value):
                for indicator in sorted(apt_group.indicators[indicator_type], key=lambda x: x.value):
                    if has_timestamps:
                        first_seen = indicator.first_seen.isoformat() if indicator.first_seen else "unknown"
                        writer.writerow(
                            [
                                apt_name,
                                indicator_type.value,
                                indicator.value,
                                first_seen,
                            ]
                        )
                    else:
                        writer.writerow([apt_name, indicator_type.value, indicator.value])

        result = self._write_if_changed(buffer.getvalue())

        # Also export metadata file
        self._export_metadata(apt_groups)

        return result

    def _export_full(self, apt_groups: dict[str, APTGroup]) -> bool:
        """Export in full format with metadata per row."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["apt_group", "indicator_type", "indicator", "aliases", "references"])

        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            aliases = ", ".join(sorted(apt_group.metadata.aliases))
            references = " | ".join(sorted(apt_group.metadata.references))

            for indicator_type in sorted(apt_group.indicators.keys(), key=lambda x: x.value):
                for indicator in sorted(apt_group.indicators[indicator_type], key=lambda x: x.value):
                    writer.writerow(
                        [
                            apt_name,
                            indicator_type.value,
                            indicator.value,
                            aliases,
                            references,
                        ]
                    )

        return self._write_if_changed(buffer.getvalue())

    def _export_metadata(self, apt_groups: dict[str, APTGroup]) -> None:
        """Export metadata to a separate CSV file."""
        metadata_path = self.output_path.with_name(self.output_path.stem + "_metadata.csv")

        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["apt_group", "aliases", "references"])

        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            aliases = ", ".join(sorted(apt_group.metadata.aliases))
            references = " | ".join(sorted(apt_group.metadata.references))
            writer.writerow([apt_name, aliases, references])

        content = buffer.getvalue()

        if metadata_path.exists():
            existing = metadata_path.read_text(encoding="utf-8")
            if existing == content:
                print(f"Metadata unchanged: {metadata_path}")
                return

        metadata_path.write_text(content, encoding="utf-8")
        print(f"Metadata exported to {metadata_path}")
