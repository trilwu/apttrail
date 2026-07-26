"""
Pydantic models for APTtrail data structures.

These models provide type safety, validation, and serialization
for threat intelligence data.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IndicatorType(str, Enum):
    """Enumeration of supported indicator types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    URL_PATH = "url_path"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE_PATH = "file_path"
    UNKNOWN = "unknown"


class Indicator(BaseModel):
    """
    Represents a single threat indicator (IOC).

    Attributes:
        value: The indicator value (IP, domain, hash, etc.)
        indicator_type: Classification of the indicator
        first_seen: When the indicator was first observed
        commit_hash: Git commit that added this indicator
        references: Source URLs for this indicator
    """

    model_config = ConfigDict(frozen=True)

    value: str = Field(..., min_length=1, description="The indicator value")
    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    first_seen: datetime | None = Field(default=None, description="First observation time")
    commit_hash: str | None = Field(default=None, description="Git commit hash")
    references: list[str] = Field(default_factory=list, description="Source URLs")

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        """Ensure indicator value is stripped and non-empty."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("Indicator value cannot be empty")
        return stripped

    def __hash__(self) -> int:
        return hash((self.value, self.indicator_type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Indicator):
            return False
        return self.value == other.value and self.indicator_type == other.indicator_type


class APTGroupMetadata(BaseModel):
    """
    Metadata about an APT group.

    Attributes:
        filename: Original source filename
        aliases: Alternative names for the group
        references: External reference URLs
        last_modified: Last modification time
    """

    model_config = ConfigDict(frozen=True)

    filename: str = Field(..., description="Original source filename")
    aliases: list[str] = Field(default_factory=list, description="Alternative names")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    last_modified: datetime | None = Field(default=None, description="Last modification time")
    attack_id: str | None = Field(default=None, description="MITRE ATT&CK group id, e.g. G0007")
    attack_name: str | None = Field(default=None, description="MITRE ATT&CK group name, e.g. APT28")
    attack_url: str | None = Field(default=None, description="MITRE ATT&CK group page URL")


class APTGroup(BaseModel):
    """
    Represents an APT (Advanced Persistent Threat) group with its indicators.

    Attributes:
        name: The APT group name/identifier
        metadata: Additional metadata about the group
        indicators: Dictionary of indicators grouped by type
    """

    model_config = ConfigDict(frozen=False)

    name: str = Field(..., min_length=1, description="APT group name")
    metadata: APTGroupMetadata = Field(..., description="Group metadata")
    indicators: dict[IndicatorType, set[Indicator]] = Field(default_factory=dict, description="Indicators by type")

    @property
    def total_indicators(self) -> int:
        """Get total count of all indicators."""
        return sum(len(indicators) for indicators in self.indicators.values())

    @property
    def indicator_counts(self) -> dict[str, int]:
        """Get counts by indicator type."""
        return {k.value: len(v) for k, v in self.indicators.items()}

    def add_indicator(self, indicator: Indicator) -> None:
        """Add an indicator to the appropriate type bucket."""
        if indicator.indicator_type not in self.indicators:
            self.indicators[indicator.indicator_type] = set()
        self.indicators[indicator.indicator_type].add(indicator)


class FeedMetadata(BaseModel):
    """
    Metadata about the generated threat feed.

    Attributes:
        source: Data source description
        generated_at: Feed generation timestamp
        total_apt_groups: Number of APT groups included
        total_indicators: Total indicator count
        maltrail_commit: Maltrail repository commit hash
    """

    model_config = ConfigDict(frozen=True)

    source: str = Field(default="Maltrail APT Indicators", description="Data source")
    generated_at: datetime = Field(default_factory=datetime.now, description="Generation time")
    total_apt_groups: int = Field(default=0, ge=0, description="Number of APT groups")
    total_indicators: int = Field(default=0, ge=0, description="Total indicators")
    maltrail_commit: str | None = Field(default=None, description="Source commit hash")


class FeedExportConfig(BaseModel):
    """
    Configuration for feed export operations.

    Attributes:
        output_dir: Directory for output files
        formats: List of formats to export
        optimized: Whether to use optimized output
        collect_timestamps: Whether to collect git timestamps
    """

    model_config = ConfigDict(frozen=True)

    output_dir: str = Field(default=".", description="Output directory")
    formats: list[str] = Field(
        default_factory=lambda: ["json", "csv", "suricata", "yara", "stix", "slices"],
        description="Export formats",
    )
    optimized: bool = Field(default=True, description="Use optimized output")
    collect_timestamps: bool = Field(default=False, description="Collect git timestamps")
    write_changelog: bool = Field(default=True, description="Append IOC additions/removals to feeds/changes")
    use_datasets: bool = Field(default=False, description="Use Suricata datasets")


class CollectorConfig(BaseModel):
    """
    Configuration for the APT collector.

    Attributes:
        maltrail_path: Path to Maltrail repository
        auto_update: Whether to auto-update the repository
        export_config: Export configuration
    """

    model_config = ConfigDict(frozen=True)

    maltrail_path: str = Field(default="data/maltrail", description="Maltrail repo path")
    auto_update: bool = Field(default=True, description="Auto-update repository")
    cache_dir: str | None = Field(default=None, description="Timestamp cache directory (default: ~/.apttrail)")
    export_config: FeedExportConfig = Field(default_factory=FeedExportConfig, description="Export settings")


# Type aliases for convenience
IndicatorDict = dict[IndicatorType, set[Indicator]]
APTGroupDict = dict[str, APTGroup]
TimestampInfo = dict[str, Any]
