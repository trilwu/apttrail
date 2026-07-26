"""
STIX 2.1 exporter for APTtrail.

Emits ``intrusion-set`` objects rather than ``threat-actor``: an intrusion set
is the STIX concept that MITRE ATT&CK groups map to, so a bundle built this way
merges cleanly with ATT&CK data in OpenCTI or any other STIX consumer.

Object ids are UUIDv5 over a fixed namespace, which keeps them stable across
runs (a consumer re-ingesting the feed updates objects instead of duplicating
them) while remaining valid UUIDs. The previous exporter used a raw MD5 digest,
which is not a well-formed UUID at all.
"""

import json
import uuid
from pathlib import Path
from typing import Any

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType

# Stable namespace so ids are reproducible run to run.
APTTRAIL_NAMESPACE = uuid.UUID("8f1f2b9e-0d2c-5a3e-9c47-2f0d3a5b6c71")


class STIXExporter(BaseExporter):
    """Exports indicators to a STIX 2.1 bundle."""

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
            _metadata: Feed metadata
            _commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        bundle = self._build_bundle(apt_groups)
        content = json.dumps(bundle, indent=2, ensure_ascii=False, sort_keys=True)
        return self._write_if_changed(content)

    @staticmethod
    def stix_id(object_type: str, key: str) -> str:
        """Build a deterministic, spec-valid STIX id."""
        return f"{object_type}--{uuid.uuid5(APTTRAIL_NAMESPACE, f'{object_type}:{key}')}"

    def _build_bundle(self, apt_groups: dict[str, APTGroup]) -> dict[str, Any]:
        bundle: dict[str, Any] = {
            "type": "bundle",
            "id": self.stix_id("bundle", "apttrail"),
            "objects": [],
        }

        for apt_name in sorted(apt_groups):
            apt_group = apt_groups[apt_name]
            intrusion_set = self._create_intrusion_set(apt_name, apt_group)
            bundle["objects"].append(intrusion_set)

            for indicator_type in sorted(apt_group.indicators, key=lambda t: t.value):
                for indicator in sorted(apt_group.indicators[indicator_type], key=lambda i: i.value):
                    indicator_obj = self._create_indicator(apt_name, indicator_type, indicator.value)
                    if not indicator_obj:
                        continue

                    bundle["objects"].append(indicator_obj)
                    bundle["objects"].append(
                        self._create_relationship(indicator_obj["id"], intrusion_set["id"], apt_name, indicator.value)
                    )

        return bundle

    def _create_intrusion_set(self, apt_name: str, apt_group: APTGroup) -> dict[str, Any]:
        """Create a STIX intrusion-set, linked to ATT&CK when the group is mapped."""
        metadata = apt_group.metadata

        external_references: list[dict[str, Any]] = []
        if metadata.attack_id:
            external_references.append(
                {
                    "source_name": "mitre-attack",
                    "external_id": metadata.attack_id,
                    "url": metadata.attack_url,
                }
            )
        external_references.extend({"source_name": "apttrail", "url": ref} for ref in sorted(metadata.references))

        return {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": self.stix_id("intrusion-set", metadata.attack_id or apt_name),
            "created": self.FIXED_TIMESTAMP,
            "modified": self.FIXED_TIMESTAMP,
            "name": metadata.attack_name or f"APT {apt_name}",
            "aliases": sorted({*metadata.aliases, apt_name}),
            "external_references": external_references,
        }

    def _create_indicator(self, apt_name: str, indicator_type: IndicatorType, value: str) -> dict[str, Any] | None:
        pattern = self._get_stix_pattern(indicator_type, value)
        if not pattern:
            return None

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": self.stix_id("indicator", value),
            "created": self.FIXED_TIMESTAMP,
            "modified": self.FIXED_TIMESTAMP,
            "name": f"{apt_name} - {indicator_type.value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": self.FIXED_TIMESTAMP,
            "labels": ["malicious-activity"],
            "description": f"Indicator associated with APT {apt_name}",
        }

    @staticmethod
    def _escape(value: str) -> str:
        """Escape a value for a STIX pattern string literal."""
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _get_stix_pattern(self, indicator_type: IndicatorType, value: str) -> str | None:
        """Build the STIX pattern for an indicator."""
        escaped = self._escape(value)

        if indicator_type is IndicatorType.IPV4:
            # Ports are recorded separately; the address alone is the observable.
            return f"[ipv4-addr:value = '{self._escape(value.split(':')[0])}']"

        patterns = {
            IndicatorType.IPV6: f"[ipv6-addr:value = '{escaped}']",
            IndicatorType.DOMAIN: f"[domain-name:value = '{escaped}']",
            IndicatorType.URL: f"[url:value = '{escaped}']",
            # A bare request path is an HTTP request property, not a filename.
            IndicatorType.URL_PATH: (f"[network-traffic:extensions.'http-request-ext'.request_value = '{escaped}']"),
            IndicatorType.MD5: f"[file:hashes.MD5 = '{escaped}']",
            IndicatorType.SHA1: f"[file:hashes.'SHA-1' = '{escaped}']",
            IndicatorType.SHA256: f"[file:hashes.'SHA-256' = '{escaped}']",
            IndicatorType.FILE_PATH: f"[file:name = '{escaped}']",
        }
        return patterns.get(indicator_type)

    def _create_relationship(
        self, indicator_id: str, intrusion_set_id: str, apt_name: str, value: str
    ) -> dict[str, Any]:
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": self.stix_id("relationship", f"{apt_name}:{value}"),
            "created": self.FIXED_TIMESTAMP,
            "modified": self.FIXED_TIMESTAMP,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": intrusion_set_id,
        }
