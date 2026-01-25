"""
Base exporter interface for APTtrail.

Defines the abstract base class that all exporters must implement.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from apttrail.models import APTGroup, FeedMetadata


class BaseExporter(ABC):
    """
    Abstract base class for feed exporters.

    All exporters must implement the export() method to produce
    output in their specific format.

    Attributes:
        output_path: Path to the output file
    """

    def __init__(self, output_path: Path | str) -> None:
        """
        Initialize the exporter.

        Args:
            output_path: Path for the output file
        """
        self.output_path = Path(output_path)

    @abstractmethod
    def export(
        self,
        apt_groups: dict[str, APTGroup],
        metadata: FeedMetadata,
        commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to the target format.

        Args:
            apt_groups: Dictionary of APT groups with indicators
            metadata: Feed metadata
            commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded, False otherwise
        """
        pass

    def _ensure_directory(self) -> None:
        """Ensure the output directory exists."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def _write_if_changed(self, content: str) -> bool:
        """
        Write content to file only if it changed.

        Args:
            content: Content to write

        Returns:
            True if file was written, False if unchanged
        """
        self._ensure_directory()

        if self.output_path.exists():
            existing = self.output_path.read_text(encoding="utf-8")
            if existing == content:
                print(f"Output unchanged: {self.output_path}")
                return False

        self.output_path.write_text(content, encoding="utf-8")
        print(f"Exported to {self.output_path}")
        return True

    @staticmethod
    def _serialize_indicators(apt_group: APTGroup) -> dict[str, Any]:
        """
        Serialize indicators for export.

        Args:
            apt_group: APT group to serialize

        Returns:
            Dictionary with serialized indicator data
        """
        return {
            indicator_type.value: [ind.value for ind in indicators]
            for indicator_type, indicators in apt_group.indicators.items()
        }
