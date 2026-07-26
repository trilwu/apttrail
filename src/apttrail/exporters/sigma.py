"""
Sigma rules exporter for APTtrail.

Emits one rule per APT group rather than a single rule containing every
indicator. The previous version produced one rule with 141,148 values in a
single ``DestinationHostname`` list, which no SIEM backend will compile into a
usable query, and an empty ``selection_hashes`` block because the feed carries
no hashes.

Per-group rules mean a detection engineer can load the actors they care about
and skip the handful of groups with tens of thousands of domains. Each rule is
tagged with its ATT&CK group id, which is how Sigma expresses attribution.

For the very large groups, the right shape is a lookup table rather than an
inline list: point your SIEM at ``by-type/domain.txt`` and correlate against it.
The file header says so.
"""

from pathlib import Path

from apttrail.exporters.base import BaseExporter
from apttrail.models import APTGroup, FeedMetadata, IndicatorType

#: Rules above this many values are still emitted, but flagged in the header so
#: nobody is surprised by their size.
LARGE_RULE_THRESHOLD = 5000

HASH_TYPES = (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256)


class SigmaExporter(BaseExporter):
    """Exports indicators to Sigma rules, one per APT group."""

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
            _commit_references: Optional commit hash to references mapping

        Returns:
            True if any rule was written
        """
        rules: list[str] = []
        large: list[tuple[str, int]] = []

        for name in sorted(apt_groups):
            group = apt_groups[name]
            domains = sorted(i.value for i in group.indicators.get(IndicatorType.DOMAIN, set()))
            hashes = sorted(
                i.value for indicator_type in HASH_TYPES for i in group.indicators.get(indicator_type, set())
            )

            if not domains and not hashes:
                continue

            if len(domains) + len(hashes) > LARGE_RULE_THRESHOLD:
                large.append((name, len(domains) + len(hashes)))

            rules.append(self._rule(name, group, domains, hashes, metadata))

        if not rules:
            return False

        return self._write_if_changed(self._header(len(rules), large) + "\n".join(rules))

    def _header(self, rule_count: int, large: list[tuple[str, int]]) -> str:
        lines = [
            "# APTtrail - Sigma rules",
            f"# {rule_count} rules, one per APT group. Multi-document YAML: split on '---'.",
            "# Docs: https://github.com/trilwu/apttrail",
            "#",
            "# Each rule inlines one group's indicators. For the largest groups a lookup",
            "# table is the better shape - point your SIEM at",
            "# https://trilwu.github.io/apttrail/by-type/domain.txt and correlate.",
        ]
        if large:
            lines.append("#")
            lines.append("# Large rules (consider the lookup-table approach instead):")
            lines.extend(f"#   {name}: {count:,} values" for name, count in sorted(large, key=lambda x: -x[1]))
        lines.append("#\n")
        return "\n".join(lines)

    def _rule(
        self,
        name: str,
        group: APTGroup,
        domains: list[str],
        hashes: list[str],
        metadata: FeedMetadata,
    ) -> str:
        attack_id = group.metadata.attack_id
        title = f"APTtrail {attack_id} {group.metadata.attack_name}" if attack_id else f"APTtrail {name}"

        selections: list[str] = []
        conditions: list[str] = []

        # Only emit a selection that has values; an empty list is not valid Sigma.
        if domains:
            selections.append("    selection_domains:\n        DestinationHostname:\n" + self._values(domains))
            conditions.append("selection_domains")
        if hashes:
            selections.append("    selection_hashes:\n        Hashes:\n" + self._values(hashes))
            conditions.append("selection_hashes")

        tags = ["attack.command_and_control"]
        if attack_id:
            # Sigma spells ATT&CK group ids in lowercase.
            tags.append(f"attack.{attack_id.lower()}")

        references = ["https://github.com/trilwu/apttrail"]
        if group.metadata.attack_url:
            references.insert(0, group.metadata.attack_url)

        aliases = ", ".join(sorted(group.metadata.aliases)) or "none recorded"
        description = f"Network indicators attributed to {name} by Maltrail. Aliases: {aliases}"

        return (
            "---\n"
            f"title: {self._scalar(title)}\n"
            f"id: {self._rule_id(attack_id or name)}\n"
            "status: experimental\n"
            f"description: {self._scalar(description)}\n"
            "author: APTtrail\n"
            f"date: {metadata.generated_at.strftime('%Y/%m/%d')}\n"
            "references:\n" + "".join(f"    - {ref}\n" for ref in references) + "logsource:\n"
            "    category: network_connection\n"
            "detection:\n"
            + "".join(f"{block}\n" for block in selections)
            + f"    condition: {' or '.join(conditions)}\n"
            "falsepositives:\n"
            "    - Sinkholed or re-registered domains\n"
            "    - Shared hosting reused by benign sites\n"
            "level: high\n"
            "tags:\n" + "".join(f"    - {tag}\n" for tag in tags)
        )

    @staticmethod
    def _scalar(value: str) -> str:
        """Quote a YAML scalar. Plain scalars cannot contain \": \", and alias
        lists and titles routinely do."""
        return "'{}'".format(value.replace("'", "''"))

    @staticmethod
    def _rule_id(key: str) -> str:
        """Stable, readable rule id."""
        return f"apttrail-{key.lower().replace(' ', '-')}"

    @staticmethod
    def _values(items: list[str]) -> str:
        # Quote every value: bare YAML scalars break on leading dashes,
        # colons and other characters that appear in indicator data.
        return "".join("            - '{}'\n".format(item.replace("'", "''")) for item in items)
