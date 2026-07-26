"""
First-seen dates recovered from Maltrail's discarded history.

Maltrail reset its repository on 2026-01-03 ("Initial commit (fresh repo)").
``git blame`` cannot see past a root commit, so every indicator that already
existed dates to the reset - which is why the feed once claimed all 167,000
indicators first appeared in January 2026.

The old history survives in pre-reset pull-request refs. ``scripts/
backfill_first_seen.py`` walks it once and writes the map vendored here, so
collection stays offline and fast. Roughly two thirds of the live feed gets a
real date this way, spanning 2015 to 2025.

Anything absent from the map either arrived after the legacy cutoff, in which
case blame against the current history dates it exactly, or sits in the gap
between the cutoff and the reset, where the honest answer is "at or before".
"""

import gzip
import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).parent / "data" / "legacy_first_seen.json.gz"


class LegacyFirstSeen:
    """Lookup of indicator value to recovered first-seen time."""

    def __init__(self, timestamps: dict[str, int]) -> None:
        self._timestamps = timestamps

    def __len__(self) -> int:
        return len(self._timestamps)

    def get(self, value: str) -> datetime | None:
        """
        Recovered first-seen time for an indicator.

        Args:
            value: Indicator value, exactly as it appears upstream

        Returns:
            UTC datetime, or None when the value is not in the recovered map
        """
        timestamp = self._timestamps.get(value)
        if timestamp is None:
            return None
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def earliest(self, value: str, observed: datetime | None) -> tuple[datetime | None, str | None]:
        """
        Combine a recovered date with one observed in the current history.

        Args:
            value: Indicator value
            observed: Date from blaming the current repository, if any

        Returns:
            (first_seen, precision) where precision is "exact" when the date
            comes from a real addition, and None when nothing is known.
            Callers keep their own "at-or-before" marking for dates that fall
            on a history boundary.
        """
        recovered = self.get(value)

        if recovered and observed:
            return (recovered, "exact") if recovered <= observed else (observed, "exact")
        if recovered:
            return recovered, "exact"
        return observed, None


@lru_cache(maxsize=1)
def load_legacy(path: Path | None = None) -> LegacyFirstSeen:
    """
    Load the vendored map.

    Args:
        path: Override for the data file, mainly for tests

    Returns:
        A lookup; empty when the file is absent or unreadable, so a missing
        map degrades dating rather than breaking collection.
    """
    data_file = Path(path) if path else DATA_FILE

    try:
        with gzip.open(data_file, "rt", encoding="utf-8") as f:
            return LegacyFirstSeen(json.load(f))
    except (OSError, json.JSONDecodeError, EOFError):
        return LegacyFirstSeen({})
