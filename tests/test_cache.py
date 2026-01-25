"""
Test timestamp cache functionality.
"""

import pytest
from datetime import datetime
from pathlib import Path
from apttrail.utils.cache import TimestampCache


def test_cache_init(tmp_path):
    """Test cache initialization."""
    cache = TimestampCache(cache_dir=tmp_path)
    assert cache.db_path.exists()


def test_cache_set_get(tmp_path):
    """Test setting and getting cached timestamps."""
    cache = TimestampCache(cache_dir=tmp_path)
    
    now = datetime.now()
    cache.set("1.2.3.4", now, "abc123")
    
    result = cache.get("1.2.3.4")
    assert result is not None
    assert result["commit"] == "abc123"
    assert result["first_seen"].replace(microsecond=0) == now.replace(microsecond=0)


def test_cache_miss(tmp_path):
    """Test cache miss returns None."""
    cache = TimestampCache(cache_dir=tmp_path)
    result = cache.get("nonexistent")
    assert result is None


def test_cache_maltrail_commit(tmp_path):
    """Test Maltrail commit tracking."""
    cache = TimestampCache(cache_dir=tmp_path)
    
    cache.set_maltrail_commit("commit123")
    assert cache.get_maltrail_commit() == "commit123"


def test_cache_invalidate(tmp_path):
    """Test cache invalidation."""
    cache = TimestampCache(cache_dir=tmp_path)
    
    cache.set("1.2.3.4", datetime.now(), "abc123")
    cache.set_maltrail_commit("commit123")
    
    cache.invalidate()
    
    assert cache.get("1.2.3.4") is None
    assert cache.get_maltrail_commit() is None


def test_cache_stats(tmp_path):
    """Test cache statistics."""
    cache = TimestampCache(cache_dir=tmp_path)
    
    cache.set("1.2.3.4", datetime.now(), "abc123")
    cache.set("evil.com", datetime.now(), "def456")
    
    stats = cache.get_stats()
    assert stats["total_indicators"] == 2
    assert stats["db_size_mb"] > 0
