"""
Suricata rules exporter for APTtrail.

Correctness notes, because the previous generation of this exporter shipped
rules that were actively harmful:

- ``content`` values must escape ``\\``, ``"`` and ``;``. One live indicator
  contains a double quote, which silently corrupted the rule file.
- Domain matches must be anchored. An unanchored ``content:"evil.com"`` on
  ``dns.query`` also fires on ``notevil.com.attacker.net``.
- 97% of URL indicators in the live feed carry no path, so emitting
  ``http.uri; content:"/"`` for them matched every HTTP request on the wire.
- ``filemd5`` takes the *filename* of a hash list, not an inline hash, and the
  previous ``filemd5:!<hash>`` also negated the match. Hash rules now reference
  a sidecar list and are emitted only when hashes exist.
"""

import base64
import io
import urllib.parse
from collections.abc import Iterable
from pathlib import Path

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, Indicator, IndicatorType

# Printable ASCII is safe inside a content: string once the three special
# characters are escaped.
_SAFE_MIN, _SAFE_MAX = 0x20, 0x7E
_MUST_ESCAPE = {"\\": "\\\\", '"': '\\"', ";": "\\;"}


def escape_content(value: str) -> str:
    """
    Escape a value for use inside a Suricata ``content:"..."``.

    Bytes outside printable ASCII become ``|hex|`` blocks, which is how
    Suricata expresses binary content.

    Args:
        value: Raw indicator value

    Returns:
        A string safe to interpolate into a content keyword
    """
    out: list[str] = []
    pending_hex: list[str] = []

    def flush() -> None:
        if pending_hex:
            out.append("|" + " ".join(pending_hex) + "|")
            pending_hex.clear()

    for char in value:
        if char in _MUST_ESCAPE:
            flush()
            out.append(_MUST_ESCAPE[char])
        elif _SAFE_MIN <= ord(char) <= _SAFE_MAX:
            flush()
            out.append(char)
        else:
            pending_hex.extend(f"{byte:02x}" for byte in char.encode("utf-8"))

    flush()
    return "".join(out)


class SuricataExporter(BaseExporter):
    """
    Exports indicators to Suricata rules.

    Two modes:

    - per-indicator rules (default): one rule per IOC, precise but large.
    - dataset mode: one rule per group and indicator type, backed by sidecar
      ``.lst`` files. Preferred for the full feed, whose domain set alone is
      over 150,000 entries.
    """

    #: Local rule range, chosen to sit clear of Emerging Threats (2000000+).
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
            output_path: Path for the output rule file
            optimized: Retained for CLI compatibility; rules are always emitted
                in their most selective form
            use_datasets: Emit dataset-backed rules plus sidecar .lst files
        """
        super().__init__(output_path)
        self.optimized = optimized
        self.use_datasets = use_datasets
        self.dataset_dir = Path(output_path).parent / "suricata-datasets"
        self._sid = self.STARTING_SID

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
            _metadata: Feed metadata
            _commit_references: Optional commit hash to references mapping

        Returns:
            True if export succeeded
        """
        self._sid = self.STARTING_SID
        content = self._generate_rules(apt_groups)
        return self._write_if_changed(content)

    def next_sid(self) -> int:
        """Allocate the next signature id."""
        sid = self._sid
        self._sid += 1
        return sid

    def _generate_rules(self, apt_groups: dict[str, APTGroup]) -> str:
        buffer = io.StringIO()
        buffer.write("# APTtrail - Suricata rules\n")
        buffer.write("# Source: https://github.com/stamparm/maltrail\n")
        buffer.write("# Docs:   https://github.com/trilwu/apttrail\n")
        buffer.write("#\n")
        buffer.write(f"# SID range: {self.STARTING_SID}+ (local range, clear of Emerging Threats)\n")
        if self.use_datasets:
            buffer.write("# Dataset mode: place suricata-datasets/*.lst alongside this rule file\n")
            buffer.write("# or under your default-rule-path.\n")
        buffer.write("# Validate before deploying:  suricata -T -S apttrail_threat_feed.rules\n")
        buffer.write("#\n\n")

        for apt_name in sorted(apt_groups):
            self._write_apt_rules(buffer, apt_name, apt_groups[apt_name])

        return buffer.getvalue()

    def _write_apt_rules(self, buffer: io.StringIO, apt_name: str, group: APTGroup) -> None:
        indicators = group.indicators
        emitting = (
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.URL,
            IndicatorType.URL_PATH,
            IndicatorType.MD5,
            IndicatorType.SHA1,
            IndicatorType.SHA256,
        )
        if not any(indicators.get(t) for t in emitting):
            return

        buffer.write(f"# {'=' * 60}\n")
        buffer.write(f"# APT Group: {apt_name}\n")
        if group.metadata.aliases:
            buffer.write(f"# Aliases: {', '.join(group.metadata.aliases)}\n")
        if group.metadata.attack_id:
            buffer.write(f"# MITRE ATT&CK: {group.metadata.attack_id} - {group.metadata.attack_url}\n")
        buffer.write(f"# {'=' * 60}\n")

        self._write_domain_rules(buffer, apt_name, group, indicators.get(IndicatorType.DOMAIN, set()))
        self._write_ip_rules(buffer, apt_name, group, indicators.get(IndicatorType.IPV4, set()))
        self._write_url_rules(buffer, apt_name, group, indicators.get(IndicatorType.URL, set()))
        self._write_uri_path_rules(buffer, apt_name, group, indicators.get(IndicatorType.URL_PATH, set()))
        self._write_hash_rules(buffer, apt_name, group, indicators)
        buffer.write("\n")

    def _metadata_for(self, group: APTGroup, apt_name: str) -> str:
        """Build the metadata keyword, carrying ATT&CK attribution when known."""
        parts = [f"apt_group {apt_name}"]
        if group.metadata.attack_id:
            parts.append(f"mitre_group_id {group.metadata.attack_id}")
        return ", ".join(parts)

    def _write_dataset(self, name: str, values: Iterable[str], data_type: str) -> str:
        """
        Write a dataset sidecar file and return its filename.

        String datasets hold base64-encoded values, one per line; ip and raw
        datasets hold the values verbatim.
        """
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{name}.lst"

        lines = [
            base64.b64encode(value.encode("utf-8")).decode("ascii") if data_type == "string" else value
            for value in sorted(values)
        ]

        (self.dataset_dir / filename).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        return filename

    @staticmethod
    def _slug(apt_name: str) -> str:
        return "".join(c if c.isalnum() else "-" for c in apt_name.lower()).strip("-")

    def _write_domain_rules(
        self, buffer: io.StringIO, apt_name: str, group: APTGroup, indicators: set[Indicator]
    ) -> None:
        if not indicators:
            return

        domains = sorted(i.value for i in indicators)
        meta = self._metadata_for(group, apt_name)
        buffer.write(f"# {apt_name} - {len(domains)} domain(s)\n")

        if self.use_datasets:
            name = f"apttrail-{self._slug(apt_name)}-domains"
            dataset = self._write_dataset(name, domains, "string")
            buffer.write(
                f'alert dns any any -> any any (msg:"APTtrail {apt_name} - DNS query for known malicious domain"; '
                f"dns.query; dataset:isset,{name},type string,load {dataset}; "
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )
            buffer.write(
                f'alert tls any any -> any any (msg:"APTtrail {apt_name} - TLS SNI for known malicious domain"; '
                f"tls.sni; dataset:isset,{name},type string,load {dataset}; "
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )
            return

        for domain in domains:
            # startswith+endswith pins the whole buffer, so neither
            # notevil.com nor evil.com.attacker.net matches evil.com.
            buffer.write(
                f'alert dns any any -> any any (msg:"APTtrail {apt_name} - DNS query for {domain}"; '
                f'dns.query; content:"{escape_content(domain)}"; nocase; startswith; endswith; '
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )

    def _write_ip_rules(self, buffer: io.StringIO, apt_name: str, group: APTGroup, indicators: set[Indicator]) -> None:
        if not indicators:
            return

        # Nearly every IP indicator carries the observed C2 port. The port is
        # not matched on, so the rule still fires if the actor moves ports.
        addresses = sorted({i.value.split(":")[0] for i in indicators})
        meta = self._metadata_for(group, apt_name)
        buffer.write(f"# {apt_name} - {len(addresses)} IPv4 address(es)\n")

        if self.use_datasets:
            name = f"apttrail-{self._slug(apt_name)}-ips"
            dataset = self._write_dataset(name, addresses, "ip")
            buffer.write(
                f'alert ip $HOME_NET any -> any any (msg:"APTtrail {apt_name} - traffic to known malicious IP"; '
                f"ip.dst; dataset:isset,{name},type ip,load {dataset}; "
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )
            return

        for address in addresses:
            buffer.write(
                f'alert ip $HOME_NET any -> {address} any (msg:"APTtrail {apt_name} - traffic to {address}"; '
                f"threshold:type limit, track by_src, count 1, seconds 3600; "
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )

    def _write_url_rules(self, buffer: io.StringIO, apt_name: str, group: APTGroup, indicators: set[Indicator]) -> None:
        if not indicators:
            return

        meta = self._metadata_for(group, apt_name)
        body = io.StringIO()
        written = 0

        for indicator in sorted(indicators, key=lambda i: i.value):
            host, path = self._split_url(indicator.value)
            if not host:
                continue

            clauses = [f'http.host; content:"{escape_content(host)}"; nocase; startswith; endswith']
            # A path of "/" carries no signal: matching it alerts on every
            # request to any host. Fall back to host-only detection.
            if path and path != "/":
                clauses.append(f'http.uri; content:"{escape_content(path)}"; startswith')
                described = f"{host}{path}"
            else:
                described = host

            body.write(
                f"alert http $HOME_NET any -> $EXTERNAL_NET any "
                f'(msg:"APTtrail {apt_name} - HTTP request to {described}"; '
                f"flow:established,to_server; {'; '.join(clauses)}; "
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )
            written += 1

        if written:
            buffer.write(f"# {apt_name} - {written} URL(s)\n")
            buffer.write(body.getvalue())

    @staticmethod
    def _split_url(value: str) -> tuple[str, str]:
        """Split an indicator into (host, path), tolerating a missing scheme."""
        candidate = value if "://" in value else f"http://{value}"
        try:
            parsed = urllib.parse.urlparse(candidate)
            host = parsed.hostname or ""
        except ValueError:
            return "", ""

        return host, parsed.path or ""

    def _write_uri_path_rules(
        self, buffer: io.StringIO, apt_name: str, group: APTGroup, indicators: set[Indicator]
    ) -> None:
        if not indicators:
            return

        paths = sorted(i.value for i in indicators if i.value != "/")
        if not paths:
            return

        meta = self._metadata_for(group, apt_name)
        buffer.write(f"# {apt_name} - {len(paths)} URI path(s)\n")

        if self.use_datasets:
            name = f"apttrail-{self._slug(apt_name)}-uripaths"
            dataset = self._write_dataset(name, paths, "string")
            buffer.write(
                f"alert http $HOME_NET any -> $EXTERNAL_NET any "
                f'(msg:"APTtrail {apt_name} - HTTP request to known malicious URI path"; '
                f"flow:established,to_server; http.uri; dataset:isset,{name},type string,load {dataset}; "
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )
            return

        for path in paths:
            buffer.write(
                f"alert http $HOME_NET any -> $EXTERNAL_NET any "
                f'(msg:"APTtrail {apt_name} - HTTP request to {path}"; '
                f'flow:established,to_server; http.uri; content:"{escape_content(path)}"; startswith; '
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )

    def _write_hash_rules(
        self,
        buffer: io.StringIO,
        apt_name: str,
        group: APTGroup,
        indicators: dict[IndicatorType, set[Indicator]],
    ) -> None:
        """
        Emit file-hash rules.

        Suricata's filemd5/filesha1/filesha256 keywords take the *filename* of
        a newline-separated hash list, so each rule ships with a sidecar file.
        Nothing is emitted when the group has no hashes, which is currently
        every group in the Maltrail feed.
        """
        meta = self._metadata_for(group, apt_name)

        for indicator_type, keyword in (
            (IndicatorType.MD5, "filemd5"),
            (IndicatorType.SHA1, "filesha1"),
            (IndicatorType.SHA256, "filesha256"),
        ):
            hashes = sorted(i.value for i in indicators.get(indicator_type, set()))
            if not hashes:
                continue

            listfile = self._write_dataset(f"apttrail-{self._slug(apt_name)}-{indicator_type.value}", hashes, "raw")
            buffer.write(f"# {apt_name} - {len(hashes)} {indicator_type.value.upper()} hash(es)\n")
            buffer.write(
                f"alert http any any -> any any "
                f'(msg:"APTtrail {apt_name} - download of file with known {indicator_type.value.upper()} hash"; '
                f"flow:established,to_client; {keyword}:{listfile}; "
                f"classtype:trojan-activity; sid:{self.next_sid()}; rev:1; metadata:{meta};)\n"
            )
