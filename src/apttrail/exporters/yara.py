"""
YARA rules exporter for APTtrail.

Exports threat indicators to YARA rules format.
"""

import io
import re
from pathlib import Path

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType


class YARAExporter(BaseExporter):
    """
    Exports indicators to YARA rules format.

    Produces YARA rules for file scanning with domain, IP, and hash indicators.
    """

    def __init__(self, output_path: Path | str) -> None:
        """Initialize the YARA exporter."""
        super().__init__(output_path)

    def export(
        self,
        apt_groups: dict[str, APTGroup],
        _metadata: FeedMetadata,
        _commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to YARA rules format.

        Args:
            apt_groups: Dictionary of APT groups with indicators
            metadata: Feed metadata
            commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        content = self._generate_rules(apt_groups)
        return self._write_if_changed(content)

    def _generate_rules(self, apt_groups: dict[str, APTGroup]) -> str:
        """Generate all YARA rules."""
        buffer = io.StringIO()

        # Write header
        buffer.write("/*\n")
        buffer.write("   Maltrail APT Threat Feed - YARA Rules\n")
        buffer.write("   Source: https://github.com/stamparm/maltrail\n")
        buffer.write("   \n")
        buffer.write("   IMPORTANT: These are automatically generated rules for threat detection\n")
        buffer.write("   Review and test before deploying to production\n")
        buffer.write("*/\n\n")

        # Import required modules
        buffer.write('import "hash"\n')
        buffer.write('import "pe"\n\n')

        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            self._write_apt_rules(buffer, apt_name, apt_group)

        return buffer.getvalue()

    def _write_apt_rules(
        self,
        buffer: io.StringIO,
        apt_name: str,
        apt_group: APTGroup,
    ) -> None:
        """Write YARA rules for a single APT group."""
        # Sanitize name for YARA identifier
        safe_name = self._sanitize_name(apt_name)

        # Collect all string indicators
        domains = []
        ips = []
        hashes = {"md5": [], "sha1": [], "sha256": []}

        if IndicatorType.DOMAIN in apt_group.indicators:
            domains = sorted(ind.value for ind in apt_group.indicators[IndicatorType.DOMAIN])

        if IndicatorType.IPV4 in apt_group.indicators:
            ips = sorted(ind.value for ind in apt_group.indicators[IndicatorType.IPV4])

        for hash_type, indicator_type in [
            ("md5", IndicatorType.MD5),
            ("sha1", IndicatorType.SHA1),
            ("sha256", IndicatorType.SHA256),
        ]:
            if indicator_type in apt_group.indicators:
                hashes[hash_type] = sorted(ind.value for ind in apt_group.indicators[indicator_type])

        # Skip if no usable indicators
        if not domains and not ips and not any(hashes.values()):
            return

        # Write the rule
        buffer.write(f"rule APT_{safe_name} {{\n")
        buffer.write("    meta:\n")
        buffer.write(f'        description = "Indicators associated with APT {apt_name}"\n')
        buffer.write('        author = "APTtrail"\n')
        buffer.write('        date = "auto-generated"\n')

        if apt_group.metadata.aliases:
            aliases = ", ".join(apt_group.metadata.aliases[:3])
            buffer.write(f'        aliases = "{aliases}"\n')

        buffer.write("\n")

        # Write strings section
        if domains or ips:
            buffer.write("    strings:\n")
            string_count = 0

            # Add domains (limit to avoid rule explosion)
            for domain in domains[:100]:
                buffer.write(f'        $domain{string_count} = "{domain}" nocase\n')
                string_count += 1

            # Add IPs
            for ip in ips[:50]:
                ip_clean = ip.split(":")[0]
                buffer.write(f'        $ip{string_count} = "{ip_clean}"\n')
                string_count += 1

            buffer.write("\n")

        # Write condition section
        buffer.write("    condition:\n")
        conditions = []

        if domains or ips:
            conditions.append("any of them")

        # Add hash conditions
        if hashes["md5"]:
            md5_list = " or ".join(f'hash.md5(0, filesize) == "{h}"' for h in hashes["md5"][:20])
            if md5_list:
                conditions.append(f"({md5_list})")

        if hashes["sha256"]:
            sha256_list = " or ".join(f'hash.sha256(0, filesize) == "{h}"' for h in hashes["sha256"][:20])
            if sha256_list:
                conditions.append(f"({sha256_list})")

        if conditions:
            buffer.write(f"        {' or '.join(conditions)}\n")
        else:
            buffer.write("        false\n")

        buffer.write("}\n\n")

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a name for use as a YARA identifier."""
        # Replace invalid characters with underscores
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        # Ensure it doesn't start with a number
        if sanitized and sanitized[0].isdigit():
            sanitized = "_" + sanitized
        return sanitized
