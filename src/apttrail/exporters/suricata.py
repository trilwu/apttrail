"""
Suricata rules exporter for APTtrail.

Exports threat indicators to Suricata/Snort rules format.
"""

import io
import urllib.parse
from pathlib import Path

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType


class SuricataExporter(BaseExporter):
    """
    Exports indicators to Suricata rules format.

    Produces optimized detection rules for DNS, IP, HTTP, and file hash indicators.
    """

    STARTING_SID = 9000000

    def __init__(
        self,
        output_path: Path | str,
        optimized: bool = True,
        use_datasets: bool = False,
    ) -> None:
        """
        Initialize the Suricata exporter.

        Args:
            output_path: Path for the output file
            optimized: Generate optimized single rules per indicator
            use_datasets: Use PCRE and IP lists for rule grouping
        """
        super().__init__(output_path)
        self.optimized = optimized
        self.use_datasets = use_datasets

    def export(
        self,
        apt_groups: dict[str, APTGroup],
        _metadata: FeedMetadata,
        _commit_references: dict[str, list[str]] | None = None,
    ) -> bool:
        """
        Export indicators to Suricata rules format.

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
        """Generate all Suricata rules."""
        buffer = io.StringIO()
        sid_counter = self.STARTING_SID

        # Write header
        buffer.write("# Maltrail APT Threat Feed - Suricata Rules\n")
        buffer.write("# Source: https://github.com/stamparm/maltrail\n")
        buffer.write("#\n")
        buffer.write("# IMPORTANT: These are automatically generated rules for threat detection\n")
        buffer.write("# Review and test before deploying to production\n")
        if self.use_datasets:
            buffer.write("# Optimized: Using PCRE alternation and IP lists (~99% rule reduction)\n")
        buffer.write("#\n\n")

        for apt_name in sorted(apt_groups.keys()):
            apt_group = apt_groups[apt_name]
            sid_counter = self._write_apt_rules(buffer, apt_name, apt_group, sid_counter)

        return buffer.getvalue()

    def _write_apt_rules(
        self,
        buffer: io.StringIO,
        apt_name: str,
        apt_group: APTGroup,
        sid_counter: int,
    ) -> int:
        """Write rules for a single APT group."""
        aliases = ", ".join(apt_group.metadata.aliases)

        buffer.write("# ==================================================\n")
        buffer.write(f"# APT Group: {apt_name}\n")
        if aliases:
            buffer.write(f"# Aliases: {aliases}\n")
        buffer.write("# ==================================================\n\n")

        # Domain rules
        if IndicatorType.DOMAIN in apt_group.indicators:
            sid_counter = self._write_domain_rules(
                buffer, apt_name, apt_group.indicators[IndicatorType.DOMAIN], sid_counter
            )

        # IP rules
        if IndicatorType.IPV4 in apt_group.indicators:
            sid_counter = self._write_ip_rules(buffer, apt_name, apt_group.indicators[IndicatorType.IPV4], sid_counter)

        # URL rules
        if IndicatorType.URL in apt_group.indicators:
            sid_counter = self._write_url_rules(buffer, apt_name, apt_group.indicators[IndicatorType.URL], sid_counter)

        # Hash rules
        for hash_type in [IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256]:
            if hash_type in apt_group.indicators:
                sid_counter = self._write_hash_rules(
                    buffer, apt_name, hash_type, apt_group.indicators[hash_type], sid_counter
                )

        return sid_counter

    def _write_domain_rules(
        self,
        buffer: io.StringIO,
        apt_name: str,
        indicators: set,
        sid_counter: int,
    ) -> int:
        """Write domain detection rules."""
        domains = sorted(ind.value for ind in indicators)
        buffer.write(f"# {apt_name} - Domain Indicators ({len(domains)} domains)\n")

        if self.use_datasets:
            # PCRE alternation for all domains
            domains_escaped = "|".join(d.replace(".", "\\.") for d in domains)
            rule = (
                f'alert dns any any -> any any (msg:"APT {apt_name} - Malicious Domain Activity"; '
                f'dns.query; pcre:"/^({domains_escaped})$/i"; classtype:trojan-activity; '
                f"sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n"
            )
            buffer.write(rule)
            sid_counter += 1
        else:
            for domain in domains:
                rule = (
                    f'alert dns any any -> any any (msg:"APT {apt_name} - Malicious Domain {domain}"; '
                    f'dns.query; content:"{domain}"; classtype:trojan-activity; '
                    f"sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n"
                )
                buffer.write(rule)
                sid_counter += 1

        buffer.write("\n")
        return sid_counter

    def _write_ip_rules(
        self,
        buffer: io.StringIO,
        apt_name: str,
        indicators: set,
        sid_counter: int,
    ) -> int:
        """Write IP address detection rules."""
        ips = sorted(ind.value.split(":")[0] for ind in indicators)
        buffer.write(f"# {apt_name} - IPv4 Indicators ({len(ips)} IPs)\n")

        if self.use_datasets:
            ips_bracketed = "[" + ",".join(ips) + "]"
            rule = (
                f'alert ip any any -> {ips_bracketed} any (msg:"APT {apt_name} - Traffic to Malicious IPs"; '
                f"threshold:type limit, track by_src, count 1, seconds 3600; classtype:trojan-activity; "
                f"sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n"
            )
            buffer.write(rule)
            sid_counter += 1
        else:
            for ip in ips:
                rule = (
                    f'alert ip any any <> {ip} any (msg:"APT {apt_name} - Traffic to/from Malicious IP {ip}"; '
                    f"classtype:trojan-activity; threshold:type limit, track by_src, count 1, seconds 3600; "
                    f"sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n"
                )
                buffer.write(rule)
                sid_counter += 1

        buffer.write("\n")
        return sid_counter

    def _write_url_rules(
        self,
        buffer: io.StringIO,
        apt_name: str,
        indicators: set,
        sid_counter: int,
    ) -> int:
        """Write URL detection rules."""
        buffer.write(f"# {apt_name} - URL Indicators\n")

        for indicator in sorted(indicators, key=lambda x: x.value):
            try:
                parsed = urllib.parse.urlparse(indicator.value)
                if parsed.netloc:
                    path = parsed.path or "/"
                    rule = (
                        f"alert http $HOME_NET any -> $EXTERNAL_NET any "
                        f'(msg:"APT {apt_name} - HTTP Request to Malicious URL"; '
                        f'flow:established,to_server; http.uri; content:"{path}"; '
                        f'http.host; content:"{parsed.netloc}"; classtype:trojan-activity; '
                        f"sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n"
                    )
                    buffer.write(rule)
                    sid_counter += 1
            except Exception:
                pass

        buffer.write("\n")
        return sid_counter

    def _write_hash_rules(
        self,
        buffer: io.StringIO,
        apt_name: str,
        hash_type: IndicatorType,
        indicators: set,
        sid_counter: int,
    ) -> int:
        """Write file hash detection rules."""
        buffer.write(f"# {apt_name} - {hash_type.value.upper()} File Hash Indicators\n")

        for indicator in sorted(indicators, key=lambda x: x.value):
            rule = (
                f"alert http $HOME_NET any -> $EXTERNAL_NET any "
                f'(msg:"APT {apt_name} - Download of File with Known {hash_type.value.upper()} Hash"; '
                f"flow:established,to_server; filestore; filemd5:!{indicator.value}; "
                f"classtype:trojan-activity; sid:{sid_counter}; rev:1; metadata:apt_group {apt_name};)\n"
            )
            buffer.write(rule)
            sid_counter += 1

        buffer.write("\n")
        return sid_counter
