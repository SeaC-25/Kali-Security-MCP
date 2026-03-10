"""
Tests for result_cache module (kali_mcp/core/result_cache.py)

Covers:
- CachedResult: creation, is_expired, increment_hit
- ResultCache: init, _generate_key, get, set, invalidate, get_stats,
  _save_cache, _load_cache, TOOL_TTL
- ScanDeduplicator: init, should_skip, _params_equivalent, _scan_covered,
  record_scan, get_previous_result, get_merged_results
- IncrementalScanner: init, get_new_targets, mark_scanned,
  add_discovered_assets, get_new_assets
- SmartScanOptimizer: init, get_optimization_report, suggest_optimizations
"""

import json
import time
import os
import tempfile
import pytest

from kali_mcp.core.result_cache import (
    CachedResult,
    ResultCache,
    ScanDeduplicator,
    IncrementalScanner,
    SmartScanOptimizer,
)


# ===================== CachedResult Tests =====================

class TestCachedResult:
    def test_creation(self):
        cr = CachedResult(
            tool_name="nmap_scan",
            target="10.0.0.1",
            params_hash="abc123",
            result={"ports": [80, 443]},
            timestamp=time.time(),
            execution_time=5.0,
        )
        assert cr.tool_name == "nmap_scan"
        assert cr.target == "10.0.0.1"
        assert cr.hit_count == 0

    def test_is_expired_false(self):
        cr = CachedResult("t", "x", "h", {}, time.time(), 1.0)
        assert cr.is_expired(3600) is False

    def test_is_expired_true(self):
        cr = CachedResult("t", "x", "h", {}, time.time() - 7200, 1.0)
        assert cr.is_expired(3600) is True

    def test_increment_hit(self):
        cr = CachedResult("t", "x", "h", {}, time.time(), 1.0)
        assert cr.hit_count == 0
        cr.increment_hit()
        assert cr.hit_count == 1
        cr.increment_hit()
        assert cr.hit_count == 2


# ===================== ResultCache Tests =====================

class TestResultCacheInit:
    def test_defaults(self):
        cache = ResultCache()
        assert cache.persist_path is None
        assert cache.stats["hits"] == 0
        assert cache.stats["misses"] == 0

    def test_tool_ttl_exists(self):
        cache = ResultCache()
        assert "nmap_scan" in cache.TOOL_TTL
        assert cache.TOOL_TTL["hydra_attack"] == 0  # no-cache tool
        assert cache.TOOL_TTL["default"] == 1800


class TestResultCacheGenerateKey:
    def test_deterministic(self):
        cache = ResultCache()
        k1 = cache._generate_key("nmap", "10.0.0.1", {"ports": "80"})
        k2 = cache._generate_key("nmap", "10.0.0.1", {"ports": "80"})
        assert k1 == k2

    def test_different_params_different_key(self):
        cache = ResultCache()
        k1 = cache._generate_key("nmap", "10.0.0.1", {"ports": "80"})
        k2 = cache._generate_key("nmap", "10.0.0.1", {"ports": "443"})
        assert k1 != k2

    def test_none_params(self):
        cache = ResultCache()
        k1 = cache._generate_key("nmap", "10.0.0.1", None)
        k2 = cache._generate_key("nmap", "10.0.0.1", {})
        assert k1 == k2


class TestResultCacheGetSet:
    def test_set_and_get(self):
        cache = ResultCache()
        cache.set("nmap_scan", "10.0.0.1", {"ports": "80"}, {"open": [80]}, 2.0)
        result = cache.get("nmap_scan", "10.0.0.1", {"ports": "80"})
        assert result is not None
        assert result.result == {"open": [80]}
        assert result.hit_count == 1

    def test_miss(self):
        cache = ResultCache()
        result = cache.get("nmap_scan", "10.0.0.1")
        assert result is None
        assert cache.stats["misses"] == 1

    def test_no_cache_tool_skip_set(self):
        cache = ResultCache()
        cache.set("hydra_attack", "10.0.0.1", {}, "result", 1.0)
        result = cache.get("hydra_attack", "10.0.0.1", {})
        assert result is None

    def test_expired_eviction(self):
        cache = ResultCache()
        key = cache._generate_key("nuclei_scan", "t", {})
        cache._cache[key] = CachedResult(
            "nuclei_scan", "t", "h", "old", time.time() - 3600, 1.0
        )
        result = cache.get("nuclei_scan", "t", {})
        assert result is None
        assert cache.stats["evictions"] == 1

    def test_hit_increments_stats(self):
        cache = ResultCache()
        cache.set("nmap_scan", "t", {}, "r", 1.0)
        cache.get("nmap_scan", "t", {})
        cache.get("nmap_scan", "t", {})
        assert cache.stats["hits"] == 2


class TestResultCacheInvalidate:
    def test_invalidate_by_tool(self):
        cache = ResultCache()
        cache.set("nmap_scan", "t1", {}, "r1", 1.0)
        cache.set("nmap_scan", "t2", {}, "r2", 1.0)
        cache.set("gobuster_scan", "t1", {}, "r3", 1.0)
        cache.invalidate(tool_name="nmap_scan")
        assert cache.get("nmap_scan", "t1", {}) is None
        assert cache.get("nmap_scan", "t2", {}) is None
        assert cache.get("gobuster_scan", "t1", {}) is not None

    def test_invalidate_by_target(self):
        cache = ResultCache()
        cache.set("nmap_scan", "t1", {}, "r1", 1.0)
        cache.set("nmap_scan", "t2", {}, "r2", 1.0)
        cache.invalidate(target="t1")
        assert cache.get("nmap_scan", "t1", {}) is None
        assert cache.get("nmap_scan", "t2", {}) is not None

    def test_invalidate_all(self):
        cache = ResultCache()
        cache.set("nmap_scan", "t1", {}, "r1", 1.0)
        cache.set("gobuster_scan", "t2", {}, "r2", 1.0)
        cache.invalidate()
        assert len(cache._cache) == 0


class TestResultCacheStats:
    def test_empty_stats(self):
        cache = ResultCache()
        stats = cache.get_stats()
        assert stats["cache_size"] == 0
        assert stats["hit_rate"] == "0.0%"
        assert stats["time_saved_estimate"] == 0

    def test_stats_with_data(self):
        cache = ResultCache()
        cache.set("nmap_scan", "t", {}, "r", 5.0)
        cache.get("nmap_scan", "t", {})  # hit
        cache.get("nmap_scan", "x", {})  # miss
        stats = cache.get_stats()
        assert stats["cache_size"] == 1
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert "50.0%" in stats["hit_rate"]


class TestResultCachePersistence:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "cache.json")
            cache1 = ResultCache(persist_path=path)
            cache1.set("nmap_scan", "t1", {}, {"ports": [80]}, 2.0)

            # Load into a new cache
            cache2 = ResultCache(persist_path=path)
            result = cache2.get("nmap_scan", "t1", {})
            assert result is not None

    def test_load_nonexistent(self):
        cache = ResultCache(persist_path="/tmp/nonexistent_kali_cache_xyz.json")
        # Should not crash
        assert len(cache._cache) == 0


# ===================== ScanDeduplicator Tests =====================

class TestScanDeduplicator:
    def test_init(self):
        dedup = ScanDeduplicator()
        assert dedup.executed_scans == {}
        assert dedup.scan_results == {}

    def test_no_skip_first_scan(self):
        dedup = ScanDeduplicator()
        skip, reason = dedup.should_skip("nmap_scan", "10.0.0.1", {"ports": "80"})
        assert skip is False
        assert reason is None

    def test_skip_identical_scan(self):
        dedup = ScanDeduplicator()
        dedup.record_scan("nmap_scan", "10.0.0.1", {"ports": "80"}, "result")
        skip, reason = dedup.should_skip("nmap_scan", "10.0.0.1", {"ports": "80"})
        assert skip is True
        assert "nmap_scan" in reason

    def test_no_skip_different_params(self):
        dedup = ScanDeduplicator()
        dedup.record_scan("gobuster_scan", "t", {"wordlist": "/usr/share/wordlists/dirb/common.txt"}, "r")
        # Different wordlist without equivalence match
        skip, _ = dedup.should_skip("gobuster_scan", "t", {"wordlist": "/other/list.txt"})
        # The equivalence check for gobuster checks "big"/"large" in old vs "common" in new
        # Here old has "common" and new has "/other/list.txt", so not equivalent
        # but the base check old_params == new_params also fails, so...
        # Actually, for gobuster_scan it uses PARAM_EQUIVALENCE rules
        # old has "common", new has "/other/list.txt" - the lambda triggers for "common" in new
        # but "common" is NOT in new, so lambda returns old == new which is False
        # So the params are not equivalent, skip should be False
        assert skip is False

    def test_nmap_full_port_covers_masscan(self):
        dedup = ScanDeduplicator()
        dedup.record_scan("nmap_scan", "t", {"ports": "1-65535"}, "result")
        skip, reason = dedup.should_skip("masscan_fast_scan", "t", {})
        assert skip is True
        assert "nmap_scan" in reason

    def test_dir_scan_big_covers_common(self):
        dedup = ScanDeduplicator()
        dedup.record_scan("gobuster_scan", "t", {"wordlist": "/big/list.txt"}, "r")
        skip, reason = dedup.should_skip("ffuf_scan", "t", {"wordlist": "/common.txt"})
        assert skip is True

    def test_record_and_get_previous(self):
        dedup = ScanDeduplicator()
        dedup.record_scan("nmap_scan", "t", {}, {"ports": [80]})
        result = dedup.get_previous_result("nmap_scan", "t")
        assert result == {"ports": [80]}

    def test_get_previous_none(self):
        dedup = ScanDeduplicator()
        assert dedup.get_previous_result("nmap_scan", "t") is None

    def test_get_merged_results(self):
        dedup = ScanDeduplicator()
        dedup.record_scan("nmap_scan", "t", {}, "nmap_result")
        dedup.record_scan("masscan_fast_scan", "t", {}, "masscan_result")
        merged = dedup.get_merged_results("t", "port_scan")
        assert "nmap_scan" in merged
        assert "masscan_fast_scan" in merged

    def test_get_merged_unknown_type(self):
        dedup = ScanDeduplicator()
        assert dedup.get_merged_results("t", "unknown_type") == {}

    def test_params_equivalent_nmap_full_port(self):
        dedup = ScanDeduplicator()
        dedup.record_scan("nmap_scan", "t", {"ports": "1-65535", "scan_type": "-sV"}, "r")
        skip, _ = dedup.should_skip("nmap_scan", "t", {"ports": "80", "scan_type": "-sV"})
        assert skip is True


# ===================== IncrementalScanner Tests =====================

class TestIncrementalScanner:
    def test_init(self):
        scanner = IncrementalScanner()
        assert len(scanner.scanned_targets) == 0

    def test_get_new_targets_all_new(self):
        scanner = IncrementalScanner()
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        new = scanner.get_new_targets(targets, "port_scan")
        assert new == targets

    def test_get_new_targets_after_marking(self):
        scanner = IncrementalScanner()
        scanner.mark_scanned(["10.0.0.1", "10.0.0.2"], "port_scan")
        new = scanner.get_new_targets(["10.0.0.1", "10.0.0.2", "10.0.0.3"], "port_scan")
        assert new == ["10.0.0.3"]

    def test_different_scan_types_independent(self):
        scanner = IncrementalScanner()
        scanner.mark_scanned(["10.0.0.1"], "port_scan")
        new = scanner.get_new_targets(["10.0.0.1"], "vuln_scan")
        assert new == ["10.0.0.1"]

    def test_add_discovered_assets(self):
        scanner = IncrementalScanner()
        scanner.add_discovered_assets("subdomains", ["a.example.com", "b.example.com"])
        scanner.add_discovered_assets("subdomains", ["b.example.com", "c.example.com"])
        # b.example.com should not be duplicated
        assert len(scanner.discovered_assets["subdomains"]) == 3

    def test_get_new_assets(self):
        scanner = IncrementalScanner()
        scanner.add_discovered_assets("hosts", ["10.0.0.1", "10.0.0.2"])
        new = scanner.get_new_assets("hosts", known_assets=["10.0.0.1"])
        assert new == ["10.0.0.2"]

    def test_get_new_assets_none_known(self):
        scanner = IncrementalScanner()
        scanner.add_discovered_assets("hosts", ["10.0.0.1"])
        new = scanner.get_new_assets("hosts")
        assert new == ["10.0.0.1"]

    def test_get_new_assets_empty_type(self):
        scanner = IncrementalScanner()
        new = scanner.get_new_assets("nonexistent_type")
        assert new == []


# ===================== SmartScanOptimizer Tests =====================

class TestSmartScanOptimizer:
    def test_init(self):
        opt = SmartScanOptimizer()
        assert opt.cache is not None
        assert opt.deduplicator is not None
        assert opt.incremental is not None
        assert opt.optimization_stats["scans_skipped"] == 0

    def test_get_optimization_report(self):
        opt = SmartScanOptimizer()
        report = opt.get_optimization_report()
        assert "cache_stats" in report
        assert "scans_skipped" in report
        assert "total_time_saved_seconds" in report
        assert "total_time_saved_minutes" in report

    def test_suggest_optimizations_no_skip(self):
        opt = SmartScanOptimizer()
        planned = [
            {"tool": "nmap_scan", "target": "t1", "params": {}},
            {"tool": "gobuster_scan", "target": "t1", "params": {}},
        ]
        result = opt.suggest_optimizations(planned)
        assert len(result) == 2
        assert all(s["status"] == "execute" for s in result)

    def test_suggest_optimizations_with_skip(self):
        opt = SmartScanOptimizer()
        # Record a scan first
        opt.deduplicator.record_scan("nmap_scan", "t1", {}, "result")
        planned = [
            {"tool": "nmap_scan", "target": "t1", "params": {}},
            {"tool": "gobuster_scan", "target": "t1", "params": {}},
        ]
        result = opt.suggest_optimizations(planned)
        assert result[0]["status"] == "skip"
        assert result[1]["status"] == "execute"

    def test_init_with_cache_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "cache.json")
            opt = SmartScanOptimizer(cache_path=path)
            assert opt.cache.persist_path == path
