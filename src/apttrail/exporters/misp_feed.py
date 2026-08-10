"""
MISP feed exporter.

A MISP *feed* is not a single event file. It is a directory containing
``manifest.json``, one ``<event-uuid>.json`` per event, and optionally
``hashes.csv`` for fast correlation. Pointing MISP at a lone event JSON, as this
project's documentation previously suggested, simply fails.

One event per APT group is also the granularity MISP users want: events are the
unit you tag, pivot on and correlate against, so a per-actor event lets an
analyst pivot from one hit to that actor's whole infrastructure. The previous
exporter produced a single event holding 155,210 attributes, which no MISP
instance will render usefully and which throws away the attribution entirely.

Event UUIDs are UUIDv5 over a fixed namespace so that re-fetching the feed
updates events in place instead of duplicating them on every pull.
"""

import csv
import hashlib
import io
import json
import uuid
from pathlib import Path
from typing import Any

from apttrail.models import APTGroup, FeedMetadata, IndicatorType

#: Stable namespace, distinct from the STIX one so ids never collide.
APTTRAIL_MISP_NAMESPACE = uuid.UUID("2b1a6f4c-9d3e-5f80-a7c1-4e6b8d902f31")

ORG_NAME = "APTtrail"
ORG_UUID = str(uuid.uuid5(APTTRAIL_MISP_NAMESPACE, "org:apttrail"))

#: MISP attribute type per indicator type. Types with no sensible mapping are
#: skipped rather than forced into a wrong one.
MISP_TYPES = {
    IndicatorType.IPV4: "ip-dst",
    IndicatorType.IPV6: "ip-dst",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.URL_PATH: "uri",
    IndicatorType.MD5: "md5",
    IndicatorType.SHA1: "sha1",
    IndicatorType.SHA256: "sha256",
    IndicatorType.FILE_PATH: "filename",
}

THREAT_LEVEL_MEDIUM = "2"
ANALYSIS_COMPLETED = "2"


SITE_URL = "https://trilwu.github.io/apttrail"
PROJECT_URL = "https://github.com/trilwu/apttrail"


class MISPFeedExporter:
    """Writes a MISP-compatible feed directory."""

    def __init__(self, output_dir: Path | str) -> None:
        """
        Args:
            output_dir: Directory to populate; created if absent
        """
        self.output_dir = Path(output_dir)

    def export(self, apt_groups: dict[str, APTGroup], metadata: FeedMetadata) -> int:
        """
        Write the feed.

        Args:
            apt_groups: Collected APT groups
            metadata: Feed metadata, used for event dates and timestamps

        Returns:
            Number of events written
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        manifest: dict[str, Any] = {}
        hash_rows: list[tuple[str, str]] = []
        date = metadata.generated_at.date().isoformat()
        timestamp = str(int(metadata.generated_at.timestamp()))

        for name in sorted(apt_groups):
            group = apt_groups[name]
            attributes = self._attributes(name, group, timestamp)
            if not attributes:
                continue

            event_uuid = str(uuid.uuid5(APTTRAIL_MISP_NAMESPACE, f"event:{name}"))
            info = self._info(name, group)
            tags = self._tags(name, group)

            event = {
                "Event": {
                    "uuid": event_uuid,
                    "info": info,
                    "date": date,
                    "timestamp": timestamp,
                    "published": True,
                    "analysis": ANALYSIS_COMPLETED,
                    "threat_level_id": THREAT_LEVEL_MEDIUM,
                    "Orgc": {"name": ORG_NAME, "uuid": ORG_UUID},
                    "Tag": tags,
                    "Attribute": attributes,
                }
            }

            (self.output_dir / f"{event_uuid}.json").write_text(
                json.dumps(event, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )

            manifest[event_uuid] = {
                "Orgc": {"name": ORG_NAME, "uuid": ORG_UUID},
                "Tag": tags,
                "info": info,
                "date": date,
                "analysis": ANALYSIS_COMPLETED,
                "threat_level_id": THREAT_LEVEL_MEDIUM,
                "timestamp": timestamp,
            }

            hash_rows.extend(
                (hashlib.md5(attribute["value"].encode("utf-8")).hexdigest(), event_uuid)  # noqa: S324 - MISP format
                for attribute in attributes
            )

        (self.output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self._write_hashes(hash_rows)
        self._write_directory_page(len(manifest), metadata)

        return len(manifest)

    def _write_directory_page(self, events: int, metadata: FeedMetadata) -> None:
        """
        Give the feed directory itself something to serve.

        MISP never requests this URL - it appends ``/manifest.json`` (Feed.php)
        - so the bare path returning 404 was harmless to the software and
        actively harmful to the review: the first thing a maintainer does with
        a feed URL is open it, and MISP's own lead reported the 404 on the
        pull request. Static hosting serves index.html for a directory, so this
        is all it takes to make the URL explain itself.
        """
        generated = metadata.generated_at.isoformat()
        (self.output_dir / "index.html").write_text(
            f"""<!doctype html>
<html lang=en>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>APTtrail MISP feed</title>
<style>
 body {{ font: 15px/1.6 ui-sans-serif, system-ui, sans-serif; max-width: 44rem;
        margin: 3rem auto; padding: 0 1.2rem; }}
 code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .88em; }}
 pre {{ background: #8881; padding: .8rem; border-radius: 4px; overflow-x: auto; }}
 .muted {{ opacity: .75; }}
</style>
<h1>APTtrail MISP feed</h1>
<p>This is a <strong>MISP feed directory</strong>, not a web page. Add the URL
below in MISP under <em>Sync Actions &rarr; Feeds &rarr; Add Feed</em>, with
input source <code>Network</code> and format <code>MISP Feed</code>:</p>
<pre>{SITE_URL}/misp-feed</pre>
<p>MISP appends <code>/manifest.json</code> itself. The parts, if you want to
look directly:</p>
<ul>
  <li><a href="manifest.json">manifest.json</a> &mdash; {events:,} events, one per APT group</li>
  <li><a href="hashes.csv">hashes.csv</a> &mdash; for correlation without pulling events</li>
  <li><code>&lt;event-uuid&gt;.json</code> &mdash; one file per event, listed in the manifest</li>
</ul>
<p class=muted>Event and attribute UUIDs are deterministic, so re-fetching
updates events in place rather than duplicating them. Generated {generated},
rebuilt hourly.</p>
<p><a href="{SITE_URL}/">APTtrail</a> &middot;
<a href="{PROJECT_URL}">source</a></p>
</html>
""",
            encoding="utf-8",
            newline="\n",
        )

    @staticmethod
    def _info(name: str, group: APTGroup) -> str:
        """Event title, as it appears in the MISP event list."""
        metadata = group.metadata
        if metadata.attack_id:
            return f"APTtrail: {metadata.attack_name} ({metadata.attack_id}) - Maltrail group {name}"
        return f"APTtrail: {name}"

    @staticmethod
    def _tags(name: str, group: APTGroup) -> list[dict[str, str]]:
        tags = [
            {"name": "tlp:clear", "colour": "#ffffff"},
            {"name": "source:apttrail", "colour": "#0088cc"},
            {"name": f"apt:{name.lower()}", "colour": "#ff0000"},
        ]
        if group.metadata.attack_id:
            # The galaxy tag is what makes the event pivot to the actor cluster.
            tags.append(
                {
                    "name": f'misp-galaxy:mitre-intrusion-set="{group.metadata.attack_name}'
                    f' - {group.metadata.attack_id}"',
                    "colour": "#0088cc",
                }
            )
        return tags

    @staticmethod
    def _attributes(name: str, group: APTGroup, timestamp: str) -> list[dict[str, Any]]:
        attributes: list[dict[str, Any]] = []

        for indicator_type, indicators in sorted(group.indicators.items(), key=lambda kv: kv[0].value):
            misp_type = MISP_TYPES.get(indicator_type)
            if not misp_type:
                continue

            for indicator in sorted(indicators, key=lambda i: i.value):
                attribute_timestamp = str(int(indicator.first_seen.timestamp())) if indicator.first_seen else timestamp
                attributes.append(
                    {
                        "uuid": str(uuid.uuid5(APTTRAIL_MISP_NAMESPACE, f"attr:{name}:{indicator.value}")),
                        "type": misp_type,
                        "category": "Network activity" if misp_type != "filename" else "Payload delivery",
                        "value": indicator.value,
                        "to_ids": True,
                        "timestamp": attribute_timestamp,
                    }
                )

        return attributes

    def _write_hashes(self, rows: list[tuple[str, str]]) -> None:
        """
        Write hashes.csv, which MISP uses to correlate without pulling events.
        """
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerows(sorted(set(rows)))
        (self.output_dir / "hashes.csv").write_text(buffer.getvalue(), encoding="utf-8", newline="\n")
