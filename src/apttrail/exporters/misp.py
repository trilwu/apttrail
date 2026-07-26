"""
MISP exporter for APTtrail.

Exports threat indicators to MISP core format.
"""

import json
import uuid
from pathlib import Path
from typing import Any

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType


class MISPExporter(BaseExporter):
    """
    Exports indicators to MISP format.

    Produces MISP events containing attributes for indicators.
    """

    def __init__(self, output_path: Path | str) -> None:
        """Initialize the MISP exporter."""
        super().__init__(output_path)

    def export(
        self,
        apt_groups: dict[str, APTGroup],
        metadata: FeedMetadata,
        _commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to MISP format.

        Args:
            apt_groups: Dictionary of APT groups with indicators
            metadata: Feed metadata
            commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        misp_event = self._build_event(apt_groups, metadata)
        content = json.dumps(misp_event, indent=2, ensure_ascii=False, sort_keys=True)
        return self._write_if_changed(content)

    def _build_event(
        self,
        apt_groups: dict[str, APTGroup],
        metadata: FeedMetadata,
    ) -> dict[str, Any]:
        """Build the MISP event structure."""
        # Create a single large event or multiple events?
        # A single event for the feed is typical for a daily/hourly dump.

        event_uuid = str(uuid.uuid4())
        attributes: list[dict[str, Any]] = []

        event: dict[str, Any] = {
            "Event": {
                "uuid": event_uuid,
                "info": f"APTtrail Feed - {metadata.generated_at.date()}",
                "date": str(metadata.generated_at.date()),
                "timestamp": str(int(metadata.generated_at.timestamp())),
                "analysis": "2",  # Completed
                "threat_level_id": "2",  # Medium
                "published": True,
                "Attribute": attributes,
                "Tag": [
                    {"name": "tlp:white", "colour": "#ffffff"},
                    {"name": "source:apttrail", "colour": "#0088cc"},
                ],
            }
        }

        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            self._add_group_attributes(attributes, apt_name, apt_group)

        return event

    def _add_group_attributes(
        self,
        attributes: list[dict[str, Any]],
        apt_name: str,
        apt_group: APTGroup,
    ) -> None:
        """Add attributes for an APT group."""
        tags = [{"name": f"apt:{apt_name.lower()}", "colour": "#ff0000"}]

        # The galaxy tag is what makes a MISP event pivot to the actor cluster.
        if apt_group.metadata.attack_id:
            tags.append(
                {
                    "name": f'misp-galaxy:mitre-intrusion-set="{apt_group.metadata.attack_name}'
                    f' - {apt_group.metadata.attack_id}"',
                    "colour": "#0088cc",
                }
            )

        for indicator_type, indicators in apt_group.indicators.items():
            misp_type = self._map_to_misp_type(indicator_type)
            if not misp_type:
                continue

            for indicator in indicators:
                attr = {
                    "type": misp_type,
                    "value": indicator.value,
                    "to_ids": True,
                    "timestamp": str(int(self._get_timestamp(indicator).timestamp())),
                    "comment": f"APT {apt_name} Indicator",
                    "Tag": tags,
                }
                attributes.append(attr)

    def _map_to_misp_type(self, indicator_type: IndicatorType) -> str | None:
        """Map internal type to MISP attribute type."""
        mapping = {
            IndicatorType.IPV4: "ip-dst",
            IndicatorType.IPV6: "ip-dst",  # MISP uses same type, auto-detects? or ip-dst|port
            IndicatorType.DOMAIN: "domain",
            IndicatorType.URL: "url",
            IndicatorType.URL_PATH: "uri",
            IndicatorType.MD5: "md5",
            IndicatorType.SHA1: "sha1",
            IndicatorType.SHA256: "sha256",
            IndicatorType.FILE_PATH: "filename",
        }
        return mapping.get(indicator_type)

    def _get_timestamp(self, indicator: Any) -> Any:
        """Get timestamp for indicator, defaulting to now."""
        from datetime import datetime

        return indicator.first_seen if indicator.first_seen else datetime.now()
