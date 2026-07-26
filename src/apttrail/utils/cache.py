"""
Timestamp cache for APTtrail.

Provides persistent caching of indicator timestamps to avoid
repeated git blame operations.
"""

import hashlib
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any


class TimestampCache:
    """
    SQLite-based cache for indicator timestamps.

    Stores first_seen timestamps and commit hashes to avoid
    redundant git operations on subsequent runs.

    A single connection is shared across the collector's worker threads and
    guarded by a lock. Opening a connection per indicator, as an earlier
    version did, dominated the runtime at ~125k indicators.
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        """
        Initialize the cache.

        Args:
            cache_dir: Directory for cache file (default: .apttrail/)
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".apttrail"

        cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = cache_dir / "cache.db"
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def __enter__(self) -> "TimestampCache":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Commit pending writes and close the connection."""
        with self._lock:
            self._conn.commit()
            self._conn.close()

    def commit(self) -> None:
        """Flush pending writes to disk."""
        with self._lock:
            self._conn.commit()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._lock:
            conn = self._conn
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS indicator_timestamps (
                    indicator_hash TEXT PRIMARY KEY,
                    indicator_value TEXT NOT NULL,
                    first_seen TEXT,
                    commit_hash TEXT,
                    last_checked TEXT NOT NULL
                )
            """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_last_checked
                ON indicator_timestamps(last_checked)
            """
            )
            conn.commit()

    def _hash_indicator(self, value: str) -> str:
        """Generate a hash for an indicator value."""
        return hashlib.sha256(value.encode()).hexdigest()

    def get(self, indicator_value: str) -> dict[str, Any] | None:
        """
        Get cached timestamp for an indicator.

        Args:
            indicator_value: The indicator value

        Returns:
            Dict with first_seen and commit_hash, or None if not cached
        """
        indicator_hash = self._hash_indicator(indicator_value)

        with self._lock:
            cursor = self._conn.execute(
                """
                SELECT first_seen, commit_hash
                FROM indicator_timestamps
                WHERE indicator_hash = ?
                """,
                (indicator_hash,),
            )
            row = cursor.fetchone()

            if row:
                first_seen_str, commit_hash = row
                return {
                    "first_seen": datetime.fromisoformat(first_seen_str) if first_seen_str else None,
                    "commit": commit_hash,
                }

            return None

    def set(self, indicator_value: str, first_seen: datetime | None, commit_hash: str | None) -> None:
        """
        Cache timestamp for an indicator.

        Args:
            indicator_value: The indicator value
            first_seen: When the indicator was first seen
            commit_hash: Git commit hash
        """
        indicator_hash = self._hash_indicator(indicator_value)
        now = datetime.now().isoformat()

        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO indicator_timestamps
                (indicator_hash, indicator_value, first_seen, commit_hash, last_checked)
                VALUES (?, ?, ?, ?, ?)
                """,
                (indicator_hash, indicator_value, first_seen.isoformat() if first_seen else None, commit_hash, now),
            )

    def get_file_state(self, file_key: str) -> str | None:
        """
        Get the fingerprint recorded for a source file.

        Used to decide whether a file needs re-blaming. Keying on the file's
        own last commit time, rather than on the repository HEAD, means an
        upstream push that touches three files does not invalidate all 340.

        Args:
            file_key: Repo-relative path of the source file

        Returns:
            The stored fingerprint, or None if the file was never processed
        """
        with self._lock:
            cursor = self._conn.execute("SELECT value FROM cache_metadata WHERE key = ?", (f"file:{file_key}",))
            row = cursor.fetchone()
            return row[0] if row else None

    def set_file_state(self, file_key: str, fingerprint: str) -> None:
        """
        Record the fingerprint of a processed source file.

        Args:
            file_key: Repo-relative path of the source file
            fingerprint: Value identifying the file's current version
        """
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache_metadata (key, value) VALUES (?, ?)",
                (f"file:{file_key}", fingerprint),
            )

    def get_maltrail_commit(self) -> str | None:
        """Get the cached Maltrail commit hash."""
        with self._lock:
            cursor = self._conn.execute("SELECT value FROM cache_metadata WHERE key = 'maltrail_commit'")
            row = cursor.fetchone()
            return row[0] if row else None

    def set_maltrail_commit(self, commit_hash: str) -> None:
        """Set the Maltrail commit hash."""
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO cache_metadata (key, value)
                VALUES ('maltrail_commit', ?)
                """,
                (commit_hash,),
            )
            self._conn.commit()

    def invalidate(self) -> None:
        """Clear all cached timestamps."""
        with self._lock:
            self._conn.execute("DELETE FROM indicator_timestamps")
            self._conn.execute("DELETE FROM cache_metadata")
            self._conn.commit()

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            self._conn.commit()
            cursor = self._conn.execute("SELECT COUNT(*) FROM indicator_timestamps")
            count = cursor.fetchone()[0]

            cursor = self._conn.execute("SELECT MIN(last_checked), MAX(last_checked) FROM indicator_timestamps")
            min_check, max_check = cursor.fetchone()

            return {
                "total_indicators": count,
                "oldest_check": min_check,
                "newest_check": max_check,
                "db_size_mb": self.db_path.stat().st_size / (1024 * 1024) if self.db_path.exists() else 0,
            }
