"""
YARA rules exporter for APTtrail.

Exports threat indicators to YARA rules format.
"""

import io
import re
from pathlib import Path

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType


def _escape_yara(value: str) -> str:
    """Escape a value for a YARA text string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


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

        has_hashes = any(
            apt_group.indicators.get(indicator_type)
            for apt_group in apt_groups.values()
            for indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256)
        )

        buffer.write("/*\n")
        buffer.write("   APTtrail - YARA rules\n")
        buffer.write("   Source: https://github.com/stamparm/maltrail\n")
        buffer.write("   Docs:   https://github.com/trilwu/apttrail\n")
        buffer.write("\n")
        if not has_hashes:
            # Be explicit rather than let someone assume these are hash rules.
            buffer.write("   NOTE: the Maltrail APT trails carry no file hashes, so these rules\n")
            buffer.write("   match indicator STRINGS - domains and IPs - inside files and memory.\n")
            buffer.write("   That is a weaker signal than hash matching and will also hit benign\n")
            buffer.write("   files that merely mention a domain, such as logs, PCAPs and this\n")
            buffer.write("   feed itself. Scope your scans accordingly.\n")
            buffer.write("\n")
        buffer.write("   Review and test before deploying to production.\n")
        buffer.write("*/\n\n")

        # `hash` is only needed where hash conditions are emitted; `pe` was
        # imported but never used.
        if has_hashes:
            buffer.write('import "hash"\n\n')

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
        hashes: dict[str, list[str]] = {"md5": [], "sha1": [], "sha256": []}

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

            for domain in domains:
                buffer.write(f'        $domain{string_count} = "{_escape_yara(domain)}" nocase\n')
                string_count += 1

            for ip in ips:
                ip_clean = ip.split(":")[0]
                buffer.write(f'        $ip{string_count} = "{_escape_yara(ip_clean)}"\n')
                string_count += 1

            buffer.write("\n")

        # Write condition section
        buffer.write("    condition:\n")
        conditions = []

        if domains or ips:
            conditions.append("any of them")

        # sha1 was previously collected but never given a condition, so those
        # hashes were silently dropped from the rule.
        for hash_type, function in (("md5", "hash.md5"), ("sha1", "hash.sha1"), ("sha256", "hash.sha256")):
            digests = hashes[hash_type]
            if digests:
                clause = " or ".join(f'{function}(0, filesize) == "{digest}"' for digest in digests)
                conditions.append(f"({clause})")

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
