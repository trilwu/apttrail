"""
Timestamp cache for APTtrail.

Provides persistent caching of indicator timestamps to avoid
repeated git blame operations.
"""

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


class TimestampCache:
    """
    SQLite-based cache for indicator timestamps.
    
    Stores first_seen timestamps and commit hashes to avoid
    redundant git operations on subsequent runs.
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
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS indicator_timestamps (
                    indicator_hash TEXT PRIMARY KEY,
                    indicator_value TEXT NOT NULL,
                    first_seen TEXT,
                    commit_hash TEXT,
                    last_checked TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_last_checked 
                ON indicator_timestamps(last_checked)
            """)

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
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT first_seen, commit_hash 
                FROM indicator_timestamps 
                WHERE indicator_hash = ?
                """,
                (indicator_hash,)
            )
            row = cursor.fetchone()
            
            if row:
                first_seen_str, commit_hash = row
                return {
                    "first_seen": datetime.fromisoformat(first_seen_str) if first_seen_str else None,
                    "commit": commit_hash
                }
            
            return None

    def set(
        self,
        indicator_value: str,
        first_seen: datetime | None,
        commit_hash: str | None
    ) -> None:
        """
        Cache timestamp for an indicator.
        
        Args:
            indicator_value: The indicator value
            first_seen: When the indicator was first seen
            commit_hash: Git commit hash
        """
        indicator_hash = self._hash_indicator(indicator_value)
        now = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO indicator_timestamps 
                (indicator_hash, indicator_value, first_seen, commit_hash, last_checked)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    indicator_hash,
                    indicator_value,
                    first_seen.isoformat() if first_seen else None,
                    commit_hash,
                    now
                )
            )

    def get_maltrail_commit(self) -> str | None:
        """Get the cached Maltrail commit hash."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT value FROM cache_metadata WHERE key = 'maltrail_commit'"
            )
            row = cursor.fetchone()
            return row[0] if row else None

    def set_maltrail_commit(self, commit_hash: str) -> None:
        """Set the Maltrail commit hash."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cache_metadata (key, value)
                VALUES ('maltrail_commit', ?)
                """,
                (commit_hash,)
            )

    def invalidate(self) -> None:
        """Clear all cached timestamps."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM indicator_timestamps")
            conn.execute("DELETE FROM cache_metadata")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM indicator_timestamps")
            count = cursor.fetchone()[0]
            
            cursor = conn.execute(
                "SELECT MIN(last_checked), MAX(last_checked) FROM indicator_timestamps"
            )
            min_check, max_check = cursor.fetchone()
            
            return {
                "total_indicators": count,
                "oldest_check": min_check,
                "newest_check": max_check,
                "db_size_mb": self.db_path.stat().st_size / (1024 * 1024) if self.db_path.exists() else 0
            }
