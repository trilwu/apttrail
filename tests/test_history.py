"""Recovered first-seen history tests.

Maltrail reset its repository on 2026-01-03, so blame against the current
history dates every older indicator to the reset. These tests cover the map
recovered from the discarded history and how it combines with blame.
"""

import gzip
import json
from datetime import datetime, timezone

import pytest

from apttrail.history import LegacyFirstSeen, load_legacy

JAN_2019 = datetime(2019, 1, 2, tzinfo=timezone.utc)
JAN_2026 = datetime(2026, 1, 2, tzinfo=timezone.utc)


@pytest.fixture
def legacy():
    return LegacyFirstSeen({"old.example": int(JAN_2019.timestamp())})


class TestLookup:
    def test_known_value_returns_utc(self, legacy):
        assert legacy.get("old.example") == JAN_2019

    def test_unknown_value_returns_none(self, legacy):
        assert legacy.get("new.example") is None


class TestEarliest:
    def test_recovered_date_beats_the_reset_boundary(self, legacy):
        # This is the whole point: blame says 2026, history says 2019.
        assert legacy.earliest("old.example", JAN_2026) == (JAN_2019, "exact")

    def test_observed_date_wins_when_it_is_older(self, legacy):
        older = datetime(2017, 5, 5, tzinfo=timezone.utc)

        assert legacy.earliest("old.example", older) == (older, "exact")

    def test_recovered_date_used_when_nothing_was_observed(self, legacy):
        assert legacy.earliest("old.example", None) == (JAN_2019, "exact")

    def test_unknown_value_passes_the_observation_through_unclaimed(self, legacy):
        # No recovered date means we cannot upgrade the precision.
        assert legacy.earliest("new.example", JAN_2026) == (JAN_2026, None)

    def test_nothing_known_at_all(self, legacy):
        assert legacy.earliest("new.example", None) == (None, None)


class TestVendoredMap:
    def test_ships_with_the_package(self):
        assert len(load_legacy()) > 50_000

    def test_dates_predate_the_upstream_reset(self):
        recovered = load_legacy()
        reset = datetime(2026, 1, 3, tzinfo=timezone.utc)

        sample = [recovered.get(v) for v in list(recovered._timestamps)[:200]]
        assert all(date < reset for date in sample if date)


class TestDegradedMode:
    def test_missing_file_yields_an_empty_map(self, tmp_path):
        # A packaging slip must cost dating accuracy, not collection.
        recovered = load_legacy(tmp_path / "absent.json.gz")

        assert len(recovered) == 0
        assert recovered.earliest("anything", JAN_2026) == (JAN_2026, None)

    def test_corrupt_file_yields_an_empty_map(self, tmp_path):
        broken = tmp_path / "broken.json.gz"
        broken.write_bytes(b"not gzip")

        assert len(load_legacy(broken)) == 0

    def test_truncated_gzip_yields_an_empty_map(self, tmp_path):
        truncated = tmp_path / "truncated.json.gz"
        payload = gzip.compress(json.dumps({"a.example": 1}).encode())
        truncated.write_bytes(payload[: len(payload) // 2])

        assert len(load_legacy(truncated)) == 0
