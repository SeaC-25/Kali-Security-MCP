"""
Tests for ResultCache (kali_mcp/core/cache.py)

Covers:
- CacheEntry: expiry, touch
- ResultCache: get/set, LRU eviction, TTL expiry, stats
- Key generation
"""

import time
from unittest.mock import patch

import pytest

from kali_mcp.core.cache import CacheEntry, ResultCache


# ===================== CacheEntry Tests =====================

class TestCacheEntry:
    def test_not_expired_when_zero(self):
        entry = CacheEntry(key="k", value="v", expires_at=0)
        assert entry.is_expired() is False

    def test_expired(self):
        entry = CacheEntry(key="k", value="v", expires_at=time.time() - 10)
        assert entry.is_expired() is True

    def test_not_expired(self):
        entry = CacheEntry(key="k", value="v", expires_at=time.time() + 300)
        assert entry.is_expired() is False

    def test_touch(self):
        entry = CacheEntry(key="k", value="v")
        old_count = entry.access_count
        entry.touch()
        assert entry.access_count == old_count + 1


# ===================== ResultCache Tests =====================

@pytest.fixture
def cache():
    return ResultCache(max_size=5, default_ttl=60)


class TestCacheGetSet:
    def test_set_and_get(self, cache):
        cache.set("nmap", "10.0.0.1", {"ports": [80]})
        hit, value = cache.get("nmap", "10.0.0.1")
        assert hit is True
        assert value == {"ports": [80]}

    def test_miss(self, cache):
        hit, value = cache.get("nmap", "10.0.0.1")
        assert hit is False
        assert value is None

    def test_different_params_different_keys(self, cache):
        cache.set("nmap", "10.0.0.1", "result1", params={"ports": "80"})
        cache.set("nmap", "10.0.0.1", "result2", params={"ports": "443"})
        _, v1 = cache.get("nmap", "10.0.0.1", params={"ports": "80"})
        _, v2 = cache.get("nmap", "10.0.0.1", params={"ports": "443"})
        assert v1 == "result1"
        assert v2 == "result2"

    def test_overwrite_existing(self, cache):
        cache.set("nmap", "t", "old")
        cache.set("nmap", "t", "new")
        _, value = cache.get("nmap", "t")
        assert value == "new"


class TestCacheExpiry:
    def test_expired_entry_returns_miss(self, cache):
        cache.set("nmap", "t", "val", ttl=1)
        # Simulate time passing
        key = cache._generate_key("nmap", "t", {})
        cache._cache[key].expires_at = time.time() - 1
        hit, _ = cache.get("nmap", "t")
        assert hit is False

    def test_cleanup_expired(self, cache):
        cache.set("nmap", "t1", "val1", ttl=1)
        cache.set("nmap", "t2", "val2", ttl=1)
        # Force expire
        for entry in cache._cache.values():
            entry.expires_at = time.time() - 1
        removed = cache.cleanup_expired()
        assert removed == 2
        assert len(cache._cache) == 0


class TestCacheLRU:
    def test_eviction_when_full(self, cache):
        for i in range(6):  # max_size is 5
            cache.set("tool", f"target{i}", f"val{i}")
        assert len(cache._cache) == 5
        # First entry should have been evicted
        hit, _ = cache.get("tool", "target0")
        assert hit is False

    def test_access_prevents_eviction(self, cache):
        for i in range(5):
            cache.set("tool", f"t{i}", f"v{i}")
        # Access t0 to move it to end
        cache.get("tool", "t0")
        # Add one more to trigger eviction - t1 should be evicted, not t0
        cache.set("tool", "t5", "v5")
        hit0, _ = cache.get("tool", "t0")
        assert hit0 is True
        hit1, _ = cache.get("tool", "t1")
        assert hit1 is False


class TestCacheStats:
    def test_initial_stats(self, cache):
        stats = cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["size"] == 0

    def test_hit_miss_counting(self, cache):
        cache.set("nmap", "t", "v")
        cache.get("nmap", "t")        # hit
        cache.get("nmap", "other")     # miss
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == "50.0%"

    def test_eviction_counting(self, cache):
        for i in range(6):  # triggers 1 eviction
            cache.set("tool", f"t{i}", f"v{i}")
        stats = cache.get_stats()
        assert stats["evictions"] == 1


class TestCacheKeyGeneration:
    def test_deterministic(self, cache):
        k1 = cache._generate_key("nmap", "10.0.0.1", {"a": 1, "b": 2})
        k2 = cache._generate_key("nmap", "10.0.0.1", {"b": 2, "a": 1})
        assert k1 == k2  # sorted params

    def test_different_tools_different_keys(self, cache):
        k1 = cache._generate_key("nmap", "t", {})
        k2 = cache._generate_key("gobuster", "t", {})
        assert k1 != k2


class TestCacheClear:
    def test_clear(self, cache):
        cache.set("nmap", "t", "v")
        cache.clear()
        assert len(cache._cache) == 0

    def test_invalidate(self, cache):
        cache.set("nmap", "t1", "v1")
        cache.set("nmap", "t2", "v2")
        removed = cache.invalidate()
        assert removed == 2
        assert len(cache._cache) == 0
