"""
Render one of each page type from synthetic data, for the browser tests.

The JavaScript on these pages reads structure out of the HTML - a row's
``data-t``, a batch's ``<time>``, the ``#empty`` element. That coupling is
invisible to the Python tests and to a type checker, and it has broken twice:
a defang rule that emitted ``hxxphttp://``, and a ``<time>`` element dropped in
a refactor that silently emptied the age filter and the CSV date column.

This produces the fixtures ``tests/js/pages.test.mjs`` drives. Synthetic input
rather than a Maltrail clone, so it runs in a second and pins exactly the cases
that matter: a URL to defang, two types for the chips, dates far enough apart
to exercise the age cut, and a hidden alias to search for.

Usage:
    python scripts/render_fixture_pages.py build/fixtures
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apttrail.exporters.lookup import LookupExporter
from apttrail.exporters.slices import SliceExporter
from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType

NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)


def indicator(value: str, kind: IndicatorType, days_ago: int, report: str) -> Indicator:
    return Indicator(
        value=value,
        indicator_type=kind,
        first_seen=NOW - timedelta(days=days_ago),
        first_seen_precision="exact",
        references=[report],
    )


def build() -> dict[str, APTGroup]:
    apt28 = APTGroup(
        name="SOFACY",
        metadata=APTGroupMetadata(
            filename="apt_sofacy.txt",
            attack_id="G0007",
            attack_name="APT28",
            attack_url="https://attack.mitre.org/groups/G0007/",
            # The alias the index filter must find even though the row prints
            # only the first six.
            aliases=[f"alias-{i}" for i in range(9)] + ["fancy bear"],
            last_modified=NOW - timedelta(days=3),
        ),
    )
    recent = "https://vendor.test/2026-report"
    old = "https://vendor.test/2019-report"
    apt28.add_indicator(indicator("http://84.38.134.56", IndicatorType.URL, 5, recent))
    apt28.add_indicator(indicator("https://evil.example/payload", IndicatorType.URL, 5, recent))
    apt28.add_indicator(indicator("fresh.example", IndicatorType.DOMAIN, 5, recent))
    apt28.add_indicator(indicator("second.example", IndicatorType.DOMAIN, 30, recent))
    apt28.add_indicator(indicator("9.9.9.9", IndicatorType.IPV4, 30, recent))
    # Far enough back that the "since <year>" cut has something to remove.
    apt28.add_indicator(indicator("ancient.example", IndicatorType.DOMAIN, 2800, old))
    apt28.add_indicator(
        Indicator(value="undated.example", indicator_type=IndicatorType.DOMAIN, references=[]),
    )

    quiet = APTGroup(name="QUIET", metadata=APTGroupMetadata(filename="apt_quiet.txt"))
    quiet.add_indicator(indicator("quiet.example", IndicatorType.DOMAIN, 900, old))
    # Shares an indicator and a report with APT28, so the relationship graph
    # has something to draw and the "related groups" panel has a row.
    quiet.add_indicator(indicator("second.example", IndicatorType.DOMAIN, 30, recent))

    return {"SOFACY": apt28, "QUIET": quiet}


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "build/fixtures")
    out.mkdir(parents=True, exist_ok=True)

    feed = build()
    meta = FeedMetadata(generated_at=NOW)
    SliceExporter(out).export(feed, meta)
    # search.html is useless without the shards it queries.
    LookupExporter(out).export(feed, meta)

    written = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    print(f"Wrote {len(written)} files to {out}")
    for name in written:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
