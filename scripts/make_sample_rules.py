#!/usr/bin/env python3
"""
Generate a Suricata rule file exercising every rule shape APTtrail emits.

Used by CI to run the real ``suricata -T`` parser over our output without
cloning Maltrail. The fixture deliberately includes the awkward values found
in the live feed: an indicator containing a double quote, a URL with no path,
an IP carrying a port, and a non-ASCII domain.

Usage:
    python scripts/make_sample_rules.py <output-dir> [--datasets]
"""

import sys
from pathlib import Path

from apttrail.exporters.suricata import SuricataExporter
from apttrail.models import APTGroup, APTGroupMetadata, FeedMetadata, Indicator, IndicatorType

SAMPLES = [
    ("evil.example", IndicatorType.DOMAIN),
    ("xn--n3h.example", IndicatorType.DOMAIN),
    ("café.example", IndicatorType.DOMAIN),
    ("1.2.3.4:8080", IndicatorType.IPV4),
    ("5.6.7.8", IndicatorType.IPV4),
    ("http://evil.example", IndicatorType.URL),
    ("http://evil.example/gate.php", IndicatorType.URL),
    ("evil.example/schemeless.php", IndicatorType.URL),
    ("/beacon.php", IndicatorType.URL_PATH),
    ('/a/"quoted"/b.php', IndicatorType.URL_PATH),
    ("/semi;colon.php", IndicatorType.URL_PATH),
    ("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.MD5),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IndicatorType.SHA1),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IndicatorType.SHA256),
]


def build_groups() -> dict[str, APTGroup]:
    mapped = APTGroup(
        name="APT28",
        metadata=APTGroupMetadata(
            filename="apt_28.txt",
            aliases=["Fancy Bear"],
            attack_id="G0007",
            attack_name="APT28",
            attack_url="https://attack.mitre.org/groups/G0007/",
        ),
    )
    unmapped = APTGroup(name="UNMAPPED", metadata=APTGroupMetadata(filename="apt_unmapped.txt"))

    for value, indicator_type in SAMPLES:
        mapped.add_indicator(Indicator(value=value, indicator_type=indicator_type))
    unmapped.add_indicator(Indicator(value="other.example", indicator_type=IndicatorType.DOMAIN))

    return {"APT28": mapped, "UNMAPPED": unmapped}


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    out_dir = Path(argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    use_datasets = "--datasets" in argv

    rules = out_dir / "apttrail_sample.rules"
    SuricataExporter(rules, use_datasets=use_datasets).export(build_groups(), FeedMetadata())

    # suricata resolves dataset `load` paths against the rule directory.
    dataset_dir = out_dir / "suricata-datasets"
    if dataset_dir.is_dir():
        for listfile in dataset_dir.glob("*.lst"):
            (out_dir / listfile.name).write_bytes(listfile.read_bytes())

    print(f"wrote {rules} (datasets={use_datasets})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
