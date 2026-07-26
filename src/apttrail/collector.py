"""
Main collector module for APTtrail.

Orchestrates the collection, processing, and export of APT threat indicators.
"""

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from apttrail.attribution import load_index
from apttrail.changelog import append_changes, diff_indicators, index_current, load_previous_feed
from apttrail.classifiers.indicator import classify_indicator
from apttrail.exporters import (
    CSVExporter,
    JSONExporter,
    SliceExporter,
    STIXExporter,
    SuricataExporter,
    YARAExporter,
)
from apttrail.models import (
    APTGroup,
    APTGroupMetadata,
    CollectorConfig,
    FeedMetadata,
    Indicator,
    IndicatorType,
)
from apttrail.utils.cache import TimestampCache
from apttrail.utils.git import GitOperations
from apttrail.utils.parallel import ParallelProcessor


class APTThreatFeedCollector:
    """
    Collector for APT threat indicators.

    Handles the lifecycle of:
    1. Updating the source repository
    2. Parsing APT files
    3. Collecting metadata and timestamps
    4. Exporting to various formats
    """

    def __init__(self, config: CollectorConfig) -> None:
        """
        Initialize the collector.

        Args:
            config: Collector configuration
        """
        self.config = config
        self.maltrail_path = Path(config.maltrail_path)
        self.apt_files_path = self.maltrail_path / "trails" / "static" / "malware"
        self.git_ops = GitOperations(self.maltrail_path)
        cache_dir = Path(config.cache_dir) if config.cache_dir else None
        self.cache = TimestampCache(cache_dir) if config.export_config.collect_timestamps else None

        # State
        self.apt_groups: dict[str, APTGroup] = {}
        self.commit_references: dict[str, list[str]] = {}
        self.file_last_modified: dict[str, datetime] = {}

    def update_repository(self) -> bool:
        """
        Update the Maltrail repository.

        Returns:
            True if successful, False otherwise
        """
        if not self.config.auto_update:
            return True

        return self.git_ops.update_or_clone()

    def collect_indicators(self) -> None:
        """
        Collect all APT indicators from the repository.
        """
        if not self.apt_files_path.exists():
            print(f"Error: APT files path not found: {self.apt_files_path}")
            return

        apt_files = sorted(self.apt_files_path.glob("apt_*.txt"))
        print(f"Found {len(apt_files)} APT indicator files")

        # One history walk for every file, instead of one `git log` per file.
        self.file_last_modified = self.git_ops.get_last_commit_times(self.apt_files_path)
        print(f"Resolved commit times for {len(self.file_last_modified)} files")

        if self.config.export_config.collect_timestamps:
            print("Timestamp collection enabled (using git blame)")

        # In Phase 3 we will enable parallel processing fully
        # For now we use sequential processing or simple parallel if stable
        # Using parallel processor for file parsing
        processor = ParallelProcessor()
        results = processor.process_files(apt_files, self._parse_apt_file, show_progress=True)

        for _, apt_group in results:
            if apt_group:
                self.apt_groups[apt_group.name] = apt_group
                print(f"  {apt_group.name}: {apt_group.total_indicators} indicators collected")

        # Collect commit references if needed
        if self.config.export_config.collect_timestamps:
            self._collect_commit_references()

    def _parse_apt_file(self, filepath: Path) -> APTGroup:
        """
        Parse a single APT indicator file.

        Args:
            filepath: Path to the APT file

        Returns:
            APTGroup object with parsed indicators
        """
        apt_name = filepath.stem.replace("apt_", "").upper()

        # Get metadata
        last_modified = self._get_last_modified(filepath)
        aliases = []
        references = []

        # Get timestamps if requested. Re-blame only files whose own last
        # commit time moved; the previous HEAD-based check re-blamed all 340
        # files on every upstream push, which is most hours.
        timestamps: dict[str, dict[str, Any]] = {}
        if self.config.export_config.collect_timestamps and self.cache:
            file_key = self._repo_key(filepath)
            fingerprint = last_modified.isoformat() if last_modified else None

            if file_key is None or fingerprint is None or self.cache.get_file_state(file_key) != fingerprint:
                timestamps = self.git_ops.get_file_timestamps_bulk(filepath)
                if file_key and fingerprint and timestamps:
                    self.cache.set_file_state(file_key, fingerprint)

        indicators_by_type: dict[IndicatorType, set[Indicator]] = defaultdict(set)

        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if line.startswith("#"):
                    if "Reference:" in line:
                        ref = line.split("Reference:", 1)[1].strip()
                        if ref.startswith(("http://", "https://")):
                            references.append(ref)
                    elif "Aliases:" in line or "Alias:" in line:
                        alias_str = line.split(":", 1)[1].strip()
                        aliases.extend([a.strip() for a in alias_str.split(",")])
                    continue

                # Classify indicator
                indicator_type = classify_indicator(line)
                if indicator_type != IndicatorType.UNKNOWN:
                    # Enrich with timestamp info if available
                    ts_info = timestamps.get(line, {})
                    first_seen = ts_info.get("first_seen")
                    commit = ts_info.get("commit")

                    # Try cache if no timestamp from git
                    if not first_seen and self.cache:
                        cached = self.cache.get(line)
                        if cached:
                            first_seen = cached.get("first_seen")
                            commit = cached.get("commit")

                    indicator = Indicator(
                        value=line, indicator_type=indicator_type, first_seen=first_seen, commit_hash=commit
                    )

                    # Update cache if we have timestamp info
                    if self.cache and (first_seen or commit):
                        self.cache.set(line, first_seen, commit)

                    indicators_by_type[indicator_type].add(indicator)

        attack_group = load_index().resolve(apt_name, *aliases)

        metadata = APTGroupMetadata(
            filename=filepath.name,
            aliases=aliases,
            references=references,
            last_modified=last_modified,
            attack_id=attack_group.id if attack_group else None,
            attack_name=attack_group.name if attack_group else None,
            attack_url=attack_group.url if attack_group else None,
        )

        return APTGroup(name=apt_name, metadata=metadata, indicators=indicators_by_type)

    def _record_changes(self, output_dir: Path, generated_at: datetime) -> None:
        """
        Append indicator additions and removals to the monthly changelog.

        Skipped when no previous export exists: a first run would otherwise
        record every indicator as newly added.

        Args:
            output_dir: Directory holding the exported feeds
            generated_at: Timestamp to stamp onto the change events
        """
        previous = load_previous_feed(output_dir / "apttrail_threat_feed.json")
        if previous is None:
            print("  Changelog: no previous feed, skipping baseline run")
            return

        events = diff_indicators(previous, index_current(self.apt_groups))
        written = append_changes(output_dir / "changes", events, generated_at)

        if written:
            added = sum(1 for e in events if e["action"] == "added")
            removed = len(events) - added
            print(f"  Changelog: +{added} / -{removed} written to {written.name}")
        else:
            print("  Changelog: no indicator changes")

    def _get_last_modified(self, filepath: Path) -> datetime | None:
        """
        Look up a file's last commit time from the prefetched history.

        Args:
            filepath: Path to the APT file

        Returns:
            Last commit datetime, or None if the file has no history. Callers
            must not substitute the current time: doing so makes the exported
            feed change on every run even when no indicator changed.
        """
        key = self._repo_key(filepath)
        return self.file_last_modified.get(key) if key else None

    def _repo_key(self, filepath: Path) -> str | None:
        """Repo-relative POSIX path used as the key for cached file state."""
        try:
            return filepath.relative_to(self.maltrail_path).as_posix()
        except ValueError:
            return None

    def _collect_commit_references(self) -> None:
        """Extract reference URLs from commit messages."""
        print("Extracting reference URLs from commit messages...")
        all_commits = set()

        for group in self.apt_groups.values():
            for indicators in group.indicators.values():
                for ind in indicators:
                    if ind.commit_hash:
                        all_commits.add(ind.commit_hash)

        if all_commits:
            self.commit_references = self.git_ops.get_commit_references(all_commits)
            print(f"  Found references in {len(self.commit_references)} commits")

        # Update cache metadata
        if self.cache:
            current_commit = self.git_ops.get_current_commit()
            if current_commit:
                self.cache.set_maltrail_commit(current_commit)

            stats = self.cache.get_stats()
            print(f"  Cache: {stats['total_indicators']} indicators, {stats['db_size_mb']:.2f} MB")

    def export_feeds(self) -> None:
        """Export collected indicators to configured formats."""
        export_config = self.config.export_config
        output_dir = Path(export_config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        metadata = FeedMetadata(
            total_apt_groups=len(self.apt_groups),
            total_indicators=sum(g.total_indicators for g in self.apt_groups.values()),
            maltrail_commit=self.git_ops.get_current_commit(),
        )

        formats = export_config.formats
        print(f"\nExporting threat feeds to {output_dir}...")

        # Must run before the JSON export overwrites the previous snapshot.
        if export_config.write_changelog:
            self._record_changes(output_dir, metadata.generated_at)

        if "json" in formats:
            JSONExporter(output_dir / "apttrail_threat_feed.json").export(
                self.apt_groups, metadata, self.commit_references
            )

        if "csv" in formats:
            # Always compact for this exporter logic based on original,
            # or configurable? Original had compact=True default.
            CSVExporter(output_dir / "apttrail_threat_feed.csv", compact=True).export(
                self.apt_groups, metadata, self.commit_references
            )

        if "stix" in formats:
            STIXExporter(output_dir / "apttrail_threat_feed_stix.json").export(
                self.apt_groups, metadata, self.commit_references
            )

        if "suricata" in formats:
            SuricataExporter(
                output_dir / "apttrail_threat_feed.rules",
                optimized=export_config.optimized,
                use_datasets=export_config.use_datasets,
            ).export(self.apt_groups, metadata, self.commit_references)

        if "yara" in formats:
            YARAExporter(output_dir / "apttrail_threat_feed.yar").export(
                self.apt_groups, metadata, self.commit_references
            )

        if "misp" in formats:
            from apttrail.exporters.misp import MISPExporter

            MISPExporter(output_dir / "apttrail_threat_feed_misp.json").export(
                self.apt_groups, metadata, self.commit_references
            )

        if "sigma" in formats:
            from apttrail.exporters.sigma import SigmaExporter

            SigmaExporter(output_dir / "apttrail_threat_feed.yaml").export(
                self.apt_groups, metadata, self.commit_references
            )

        if "misp-feed" in formats:
            from apttrail.exporters import MISPFeedExporter

            events = MISPFeedExporter(output_dir / "misp-feed").export(self.apt_groups, metadata)
            print(f"  MISP feed: {events} events")

        if "slices" in formats:
            counts = SliceExporter(output_dir).export(self.apt_groups, metadata)
            print(f"  Slices: {counts['by_type']} by-type, {counts['by_group']} by-group")

        print("All feeds exported successfully.")
