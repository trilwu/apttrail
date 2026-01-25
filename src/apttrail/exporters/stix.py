"""
STIX 2.1 exporter for APTtrail.

Exports threat indicators to STIX 2.1 bundle format.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType


class STIXExporter(BaseExporter):
    """
    Exports indicators to STIX 2.1 format.

    Produces a STIX bundle with threat actors, indicators,
    and relationships between them.
    """

    FIXED_TIMESTAMP = "2024-01-01T00:00:00.000Z"

    def __init__(self, output_path: Path | str) -> None:
        """Initialize the STIX exporter."""
        super().__init__(output_path)

    def export(
        self,
        apt_groups: dict[str, APTGroup],
        _metadata: FeedMetadata,
        _commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to STIX 2.1 format.

        Args:
            apt_groups: Dictionary of APT groups with indicators
            metadata: Feed metadata
            commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        bundle = self._build_bundle(apt_groups)
        content = json.dumps(bundle, indent=2, ensure_ascii=False, sort_keys=True)
        return self._write_if_changed(content)

    def _build_bundle(self, apt_groups: dict[str, APTGroup]) -> dict[str, Any]:
        """Build the STIX bundle."""
        bundle_id = hashlib.md5(b"apttrail-bundle").hexdigest()

        bundle: dict[str, Any] = {
            "type": "bundle",
            "id": self._format_uuid(bundle_id),
            "objects": [],
        }

        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            threat_actor = self._create_threat_actor(apt_name, apt_group)
            bundle["objects"].append(threat_actor)

            # Create indicators and relationships
            for indicator_type in sorted(apt_group.indicators.keys(), key=lambda x: x.value):
                for indicator in sorted(apt_group.indicators[indicator_type], key=lambda x: x.value):
                    indicator_obj = self._create_indicator(apt_name, indicator_type, indicator.value)
                    if indicator_obj:
                        bundle["objects"].append(indicator_obj)

                        relationship = self._create_relationship(
                            indicator_obj["id"], threat_actor["id"], apt_name, indicator.value
                        )
                        bundle["objects"].append(relationship)

        return bundle

    def _format_uuid(self, hex_hash: str) -> str:
        """Format a hex hash as a UUID-like string."""
        return f"bundle--{hex_hash[:8]}-{hex_hash[8:12]}-{hex_hash[12:16]}-{hex_hash[16:20]}-{hex_hash[20:32]}"

    def _create_threat_actor(self, apt_name: str, apt_group: APTGroup) -> dict[str, Any]:
        """Create a STIX threat actor object."""
        actor_hash = hashlib.md5(apt_name.encode()).hexdigest()

        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{actor_hash[:8]}-{actor_hash[8:12]}-{actor_hash[12:16]}-{actor_hash[16:20]}-{actor_hash[20:32]}",
            "created": self.FIXED_TIMESTAMP,
            "modified": self.FIXED_TIMESTAMP,
            "name": f"APT {apt_name}",
            "threat_actor_types": ["nation-state", "hacktivist", "criminal"],
            "aliases": sorted(apt_group.metadata.aliases),
            "external_references": [{"url": ref} for ref in sorted(apt_group.metadata.references)],
        }

    def _create_indicator(self, apt_name: str, indicator_type: IndicatorType, value: str) -> dict[str, Any] | None:
        """Create a STIX indicator object."""
        pattern = self._get_stix_pattern(indicator_type, value)
        if not pattern:
            return None

        ind_hash = hashlib.md5(value.encode()).hexdigest()

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ind_hash[:8]}-{ind_hash[8:12]}-{ind_hash[12:16]}-{ind_hash[16:20]}-{ind_hash[20:32]}",
            "created": self.FIXED_TIMESTAMP,
            "modified": self.FIXED_TIMESTAMP,
            "name": f"{apt_name} - {indicator_type.value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": self.FIXED_TIMESTAMP,
            "labels": ["malicious-activity"],
            "description": f"Indicator associated with APT {apt_name}",
        }

    def _get_stix_pattern(self, indicator_type: IndicatorType, value: str) -> str | None:
        """Get STIX pattern for an indicator type."""
        patterns = {
            IndicatorType.IPV4: f"[network-traffic:dst_ref.value = '{value}']",
            IndicatorType.IPV6: f"[network-traffic:dst_ref.value = '{value}']",
            IndicatorType.DOMAIN: f"[domain-name:value = '{value}']",
            IndicatorType.URL: f"[url:value = '{value}']",
            IndicatorType.MD5: f"[file:hashes.MD5 = '{value}']",
            IndicatorType.SHA1: f"[file:hashes.SHA1 = '{value}']",
            IndicatorType.SHA256: f"[file:hashes.SHA256 = '{value}']",
            IndicatorType.FILE_PATH: f"[file:name = '{value}']",
        }
        return patterns.get(indicator_type)

    def _create_relationship(
        self, indicator_id: str, threat_actor_id: str, apt_name: str, value: str
    ) -> dict[str, Any]:
        """Create a STIX relationship object."""
        rel_hash = hashlib.md5(f"{apt_name}{value}".encode()).hexdigest()

        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{rel_hash[:8]}-{rel_hash[8:12]}-{rel_hash[12:16]}-{rel_hash[16:20]}-{rel_hash[20:32]}",
            "created": self.FIXED_TIMESTAMP,
            "modified": self.FIXED_TIMESTAMP,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": threat_actor_id,
        }
