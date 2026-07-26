"""
Sigma rules exporter for APTtrail.

Exports threat indicators to Sigma rule format (YAML).
"""

from pathlib import Path

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType


class SigmaExporter(BaseExporter):
    """
    Exports indicators to Sigma rules.

    Produces a Sigma rule file detecting APT indicators.
    """

    def __init__(self, output_path: Path | str) -> None:
        """Initialize the Sigma exporter."""
        super().__init__(output_path)

    def export(
        self,
        apt_groups: dict[str, APTGroup],
        metadata: FeedMetadata,
        _commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to Sigma format.

        Args:
            apt_groups: Dictionary of APT groups with indicators
            metadata: Feed metadata
            commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        # Collect all indicators
        domains: list[str] = []
        hashes: list[str] = []

        for group in apt_groups.values():
            if IndicatorType.DOMAIN in group.indicators:
                domains.extend(i.value for i in group.indicators[IndicatorType.DOMAIN])

            for hash_type in [IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256]:
                if hash_type in group.indicators:
                    hashes.extend(i.value for i in group.indicators[hash_type])

        if not domains and not hashes:
            return False

        # Generate YAML content
        content = self._generate_yaml(domains, hashes, metadata)
        return self._write_if_changed(content)

    def _generate_yaml(self, domains: list[str], hashes: list[str], metadata: FeedMetadata) -> str:
        """Generate Sigma YAML content."""
        date_str = metadata.generated_at.strftime("%Y/%m/%d")

        # Helper for yaml list
        def to_yaml_list(items: list[str]) -> str:
            return "\n".join(f"      - '{item}'" for item in sorted(set(items)))

        yaml = f"""title: APTtrail Threat Indicators
id: apttrail-feed-detection
status: experimental
description: Detects activity from APT groups tracked by APTtrail/Maltrail
author: APTtrail
date: {date_str}
references:
    - https://github.com/trilwu/apttrail
logsource:
    category: network_connection
    product: windows
detection:
    selection_domains:
        DestinationHostname:
{to_yaml_list(domains)}
    selection_hashes:
        Hashes:
{to_yaml_list(hashes)}
    condition: selection_domains or selection_hashes
falsepositives:
    - Unknown
level: high
tags:
    - attack.command_and_control
"""
        return yaml
