"""
CLI module for APTtrail.

Handles command-line argument parsing and application entry point.
"""

import argparse
import sys

from apttrail.collector import APTThreatFeedCollector
from apttrail.models import CollectorConfig, FeedExportConfig


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Maltrail APT Threat Feed Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Collect and export to all formats
  %(prog)s --json-only        # Export only to JSON format
  %(prog)s --no-update        # Skip repository update
  %(prog)s --output-dir feeds # Export to custom directory
        """,
    )

    parser.add_argument(
        "--maltrail-path",
        default="data/maltrail",
        help="Path to Maltrail repository (default: data/maltrail)",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="Skip repository update",
    )
    parser.add_argument(
        "--collect-timestamps",
        action="store_true",
        help="Collect per-indicator first_seen data via git blame (slow)",
    )
    parser.add_argument(
        "--no-timestamps",
        action="store_true",
        help="Deprecated: timestamp collection is off unless --collect-timestamps is given",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Directory for the timestamp cache (default: ~/.apttrail)",
    )
    parser.add_argument(
        "--no-changelog",
        action="store_true",
        help="Skip appending IOC additions/removals to feeds/changes/YYYY-MM.jsonl",
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force refresh timestamps (ignore cache)",
    )

    # Export format flags
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Export only JSON format",
    )
    parser.add_argument(
        "--csv-only",
        action="store_true",
        help="Export only CSV format",
    )
    parser.add_argument(
        "--stix-only",
        action="store_true",
        help="Export only STIX format",
    )
    parser.add_argument(
        "--suricata-only",
        action="store_true",
        help="Export only Suricata rules format",
    )
    parser.add_argument(
        "--yara-only",
        action="store_true",
        help="Export only YARA rules format",
    )
    parser.add_argument(
        "--misp-only",
        action="store_true",
        help="Export only MISP format",
    )
    parser.add_argument(
        "--sigma-only",
        action="store_true",
        help="Export only Sigma rules format",
    )
    parser.add_argument(
        "--misp-feed-only",
        action="store_true",
        help="Export only the MISP feed directory (manifest.json + per-group events)",
    )
    parser.add_argument(
        "--slices-only",
        action="store_true",
        help="Export only the per-type and per-group slices",
    )

    # Optimization flags
    parser.add_argument(
        "--suricata-dataset",
        action="store_true",
        help="Emit dataset-backed Suricata rules plus sidecar .lst files",
    )

    parser.add_argument(
        "--output-dir",
        default="feeds",  # Changed default from '.' to 'feeds' to match repo structure better? Or keep '.'?
        # Original default was '.', but example said 'feeds'
        # Let's keep '.' as default but typical usage might be 'feeds'
        help="Output directory for feed files (default: feeds)",
    )

    # Actually, original code defaulted to '.' but often used with --output-dir feeds
    # I will set default to 'feeds' as it's cleaner than polluting root
    parser.set_defaults(output_dir="feeds")

    return parser.parse_args()


def get_export_formats(args: argparse.Namespace) -> list[str]:
    """Determine export formats based on arguments."""
    formats = []

    if args.json_only:
        formats.append("json")
    if args.csv_only:
        formats.append("csv")
    if args.stix_only:
        formats.append("stix")
    if args.suricata_only:
        formats.append("suricata")
    if args.yara_only:
        formats.append("yara")
    if args.misp_only:
        formats.append("misp")
    if args.sigma_only:
        formats.append("sigma")
    if args.slices_only:
        formats.append("slices")
    if args.misp_feed_only:
        formats.append("misp-feed")

    # If no specific format requested, export all
    if not formats:
        formats = ["json", "csv", "stix", "suricata", "yara", "misp", "sigma", "slices", "misp-feed"]

    return formats


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    args = parse_args()

    try:
        # Create configuration
        export_config = FeedExportConfig(
            output_dir=args.output_dir,
            formats=get_export_formats(args),
            optimized=True,  # Always optimized by default now? Original code had default True
            collect_timestamps=args.collect_timestamps and not args.no_timestamps,
            write_changelog=not args.no_changelog,
            use_datasets=args.suricata_dataset,
        )

        config = CollectorConfig(
            maltrail_path=args.maltrail_path,
            auto_update=not args.no_update,
            cache_dir=args.cache_dir,
            export_config=export_config,
        )

        # Initialize and run collector
        collector = APTThreatFeedCollector(config)

        # Handle force refresh
        if args.force_refresh and collector.cache:
            print("Force refresh requested, invalidating cache...")
            collector.cache.invalidate()

        # Update repo
        if not collector.update_repository():
            print("Failed to update repository")
            return 1

        # Collect
        collector.collect_indicators()

        # Export
        collector.export_feeds()

        if collector.cache:
            collector.cache.close()

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
