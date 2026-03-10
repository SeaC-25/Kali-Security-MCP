"""
Tests for HighSpeedExecutor (kali_mcp/core/high_speed_executor.py)

Covers:
- TaskPriority enum: all members and values
- TaskStatus enum: all members and values
- Task dataclass: creation, defaults, ordering, mutable isolation
- ExecutionStats dataclass: creation, defaults
- LRUCache: get/set, TTL expiry, LRU eviction, thread safety, stats, clear
- AdaptiveRateLimiter: init, acquire, report_success/error/timeout, get_stats
- TaskScheduler: submit, get_next, complete, get_status, get_stats, concurrency
- HighSpeedExecutor: init, register_tool, submit_task, submit_batch,
    execute_parallel, execute_async, execute_batch_async, worker lifecycle,
    _execute_task, get_task_status, get_stats, shutdown, cache/rate integration
- FastExecutorFactory: create with presets, get_tool_config
- FAST_SCAN_PRESETS: structure and keys
- Global convenience functions: get_executor, quick_execute,
    quick_execute_async, parallel_execute, parallel_execute_async,
    get_execution_stats (all patched to avoid real singletons)
"""

import asyncio
import hashlib
import json
import time
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from datetime import datetime, timedelta
from queue import PriorityQueue
from unittest.mock import patch, MagicMock, PropertyMock, call

import pytest

from kali_mcp.core.high_speed_executor import (
    TaskPriority,
    TaskStatus,
    Task,
    ExecutionStats,
    LRUCache,
    AdaptiveRateLimiter,
    TaskScheduler,
    HighSpeedExecutor,
    FastExecutorFactory,
    FAST_SCAN_PRESETS,
    get_executor,
    quick_execute,
    quick_execute_async,
    parallel_execute,
    parallel_execute_async,
    get_execution_stats,
)


# ===================== TaskPriority Enum =====================

class TestTaskPriority:
    def test_critical_value(self):
        assert TaskPriority.CRITICAL.value == 1

    def test_high_value(self):
        assert TaskPriority.HIGH.value == 2

    def test_normal_value(self):
        assert TaskPriority.NORMAL.value == 3

    def test_low_value(self):
        assert TaskPriority.LOW.value == 4

    def test_background_value(self):
        assert TaskPriority.BACKGROUND.value == 5

    def test_all_members_present(self):
        members = set(TaskPriority.__members__.keys())
        assert members == {"CRITICAL", "HIGH", "NORMAL", "LOW", "BACKGROUND"}

    def test_member_count(self):
        assert len(TaskPriority) == 5

    def test_ordering_by_value(self):
        ordered = sorted(TaskPriority, key=lambda x: x.value)
        assert ordered == [
            TaskPriority.CRITICAL,
            TaskPriority.HIGH,
            TaskPriority.NORMAL,
            TaskPriority.LOW,
            TaskPriority.BACKGROUND,
        ]

    def test_from_value(self):
        assert TaskPriority(1) is TaskPriority.CRITICAL
        assert TaskPriority(5) is TaskPriority.BACKGROUND

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            TaskPriority(99)


# ===================== TaskStatus Enum =====================

class TestTaskStatus:
    def test_pending_value(self):
        assert TaskStatus.PENDING.value == "pending"

    def test_queued_value(self):
        assert TaskStatus.QUEUED.value == "queued"

    def test_running_value(self):
        assert TaskStatus.RUNNING.value == "running"

    def test_completed_value(self):
        assert TaskStatus.COMPLETED.value == "completed"

    def test_failed_value(self):
        assert TaskStatus.FAILED.value == "failed"

    def test_cancelled_value(self):
        assert TaskStatus.CANCELLED.value == "cancelled"

    def test_timeout_value(self):
        assert TaskStatus.TIMEOUT.value == "timeout"

    def test_all_members_present(self):
        members = set(TaskStatus.__members__.keys())
        assert members == {"PENDING", "QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "TIMEOUT"}

    def test_member_count(self):
        assert len(TaskStatus) == 7

    def test_from_value(self):
        assert TaskStatus("pending") is TaskStatus.PENDING
        assert TaskStatus("timeout") is TaskStatus.TIMEOUT


# ===================== Task Dataclass =====================

class TestTask:
    def test_basic_creation(self):
        t = Task(priority=3, task_id="t1", tool_name="nmap", parameters={"target": "x"})
        assert t.priority == 3
        assert t.task_id == "t1"
        assert t.tool_name == "nmap"
        assert t.parameters == {"target": "x"}

    def test_defaults(self):
        t = Task(priority=1, task_id="t1", tool_name="scan", parameters={})
        assert t.callback is None
        assert t.timeout == 60
        assert t.retry_count == 3
        assert t.status == TaskStatus.PENDING
        assert t.result is None
        assert t.error is None
        assert t.execution_time == 0.0
        assert isinstance(t.created_at, datetime)

    def test_ordering_by_priority(self):
        t1 = Task(priority=1, task_id="a", tool_name="t", parameters={})
        t2 = Task(priority=3, task_id="b", tool_name="t", parameters={})
        t3 = Task(priority=2, task_id="c", tool_name="t", parameters={})
        sorted_tasks = sorted([t2, t3, t1])
        assert [t.priority for t in sorted_tasks] == [1, 2, 3]

    def test_ordering_ignores_non_compare_fields(self):
        t1 = Task(priority=1, task_id="zzz", tool_name="aaa", parameters={})
        t2 = Task(priority=1, task_id="aaa", tool_name="zzz", parameters={})
        # Same priority should be equal for ordering
        assert (t1 <= t2) and (t2 <= t1)

    def test_compare_only_on_priority(self):
        t_low = Task(priority=5, task_id="t", tool_name="t", parameters={})
        t_high = Task(priority=1, task_id="t", tool_name="t", parameters={})
        assert t_high < t_low

    def test_mutable_defaults_isolation(self):
        """Parameters dict should be independent per instance."""
        t1 = Task(priority=1, task_id="t1", tool_name="t", parameters={"a": 1})
        t2 = Task(priority=1, task_id="t2", tool_name="t", parameters={"b": 2})
        t1.parameters["c"] = 3
        assert "c" not in t2.parameters

    def test_custom_timeout(self):
        t = Task(priority=1, task_id="t", tool_name="t", parameters={}, timeout=120)
        assert t.timeout == 120

    def test_custom_retry_count(self):
        t = Task(priority=1, task_id="t", tool_name="t", parameters={}, retry_count=5)
        assert t.retry_count == 5

    def test_status_mutable(self):
        t = Task(priority=1, task_id="t", tool_name="t", parameters={})
        t.status = TaskStatus.RUNNING
        assert t.status == TaskStatus.RUNNING

    def test_priority_queue_compatibility(self):
        """Tasks can be placed in PriorityQueue and retrieved in order."""
        q = PriorityQueue()
        t3 = Task(priority=3, task_id="t3", tool_name="t", parameters={})
        t1 = Task(priority=1, task_id="t1", tool_name="t", parameters={})
        t2 = Task(priority=2, task_id="t2", tool_name="t", parameters={})
        q.put(t3)
        q.put(t1)
        q.put(t2)
        assert q.get().priority == 1
        assert q.get().priority == 2
        assert q.get().priority == 3


# ===================== ExecutionStats Dataclass =====================

class TestExecutionStats:
    def test_all_defaults_zero(self):
        s = ExecutionStats()
        assert s.total_tasks == 0
        assert s.completed_tasks == 0
        assert s.failed_tasks == 0
        assert s.timeout_tasks == 0
        assert s.total_execution_time == 0.0
        assert s.average_execution_time == 0.0
        assert s.cache_hits == 0
        assert s.cache_misses == 0
        assert s.connection_reuse_count == 0

    def test_custom_values(self):
        s = ExecutionStats(total_tasks=10, completed_tasks=8, failed_tasks=2)
        assert s.total_tasks == 10
        assert s.completed_tasks == 8
        assert s.failed_tasks == 2

    def test_mutation(self):
        s = ExecutionStats()
        s.total_tasks += 1
        s.cache_hits += 5
        assert s.total_tasks == 1
        assert s.cache_hits == 5


# ===================== LRUCache =====================

@pytest.fixture
def lru_cache():
    return LRUCache(max_size=5, default_ttl=300)


class TestLRUCache:
    def test_init_defaults(self):
        c = LRUCache()
        assert c.max_size == 1000
        assert c.default_ttl == 300
        assert len(c.cache) == 0
        assert len(c.ttl_map) == 0

    def test_init_custom(self):
        c = LRUCache(max_size=10, default_ttl=60)
        assert c.max_size == 10
        assert c.default_ttl == 60

    def test_set_and_get(self, lru_cache):
        lru_cache.set("nmap", {"target": "10.0.0.1"}, {"ports": [80]})
        hit, val = lru_cache.get("nmap", {"target": "10.0.0.1"})
        assert hit is True
        assert val == {"ports": [80]}

    def test_miss(self, lru_cache):
        hit, val = lru_cache.get("nmap", {"target": "10.0.0.1"})
        assert hit is False
        assert val is None

    def test_different_params_different_keys(self, lru_cache):
        lru_cache.set("nmap", {"target": "A"}, "result_a")
        lru_cache.set("nmap", {"target": "B"}, "result_b")
        _, val_a = lru_cache.get("nmap", {"target": "A"})
        _, val_b = lru_cache.get("nmap", {"target": "B"})
        assert val_a == "result_a"
        assert val_b == "result_b"

    def test_different_tools_different_keys(self, lru_cache):
        lru_cache.set("nmap", {"target": "x"}, "nmap_result")
        lru_cache.set("gobuster", {"target": "x"}, "gobuster_result")
        _, val_n = lru_cache.get("nmap", {"target": "x"})
        _, val_g = lru_cache.get("gobuster", {"target": "x"})
        assert val_n == "nmap_result"
        assert val_g == "gobuster_result"

    def test_overwrite_existing_key(self, lru_cache):
        lru_cache.set("nmap", {"target": "x"}, "old")
        lru_cache.set("nmap", {"target": "x"}, "new")
        hit, val = lru_cache.get("nmap", {"target": "x"})
        assert hit is True
        assert val == "new"

    def test_ttl_expiry(self, lru_cache):
        lru_cache.set("tool", {"a": 1}, "value", ttl=1)
        hit, _ = lru_cache.get("tool", {"a": 1})
        assert hit is True

        # Simulate expiry by manipulating ttl_map
        key = lru_cache._generate_key("tool", {"a": 1})
        lru_cache.ttl_map[key] = datetime.now() - timedelta(seconds=10)
        hit, val = lru_cache.get("tool", {"a": 1})
        assert hit is False
        assert val is None
        # Entry should be cleaned up
        assert key not in lru_cache.cache
        assert key not in lru_cache.ttl_map

    def test_lru_eviction_oldest_removed(self):
        c = LRUCache(max_size=3, default_ttl=300)
        c.set("t", {"k": 1}, "v1")
        c.set("t", {"k": 2}, "v2")
        c.set("t", {"k": 3}, "v3")
        # Cache is full, adding one more should evict oldest (k=1)
        c.set("t", {"k": 4}, "v4")
        hit1, _ = c.get("t", {"k": 1})
        assert hit1 is False
        hit4, val4 = c.get("t", {"k": 4})
        assert hit4 is True
        assert val4 == "v4"

    def test_lru_access_prevents_eviction(self):
        c = LRUCache(max_size=3, default_ttl=300)
        c.set("t", {"k": 1}, "v1")
        c.set("t", {"k": 2}, "v2")
        c.set("t", {"k": 3}, "v3")
        # Access k=1 to make it recently used
        c.get("t", {"k": 1})
        # Adding k=4 should evict k=2 (now oldest)
        c.set("t", {"k": 4}, "v4")
        hit1, _ = c.get("t", {"k": 1})
        assert hit1 is True
        hit2, _ = c.get("t", {"k": 2})
        assert hit2 is False

    def test_clear(self, lru_cache):
        lru_cache.set("t", {"a": 1}, "v")
        lru_cache.set("t", {"a": 2}, "v")
        lru_cache.clear()
        assert len(lru_cache.cache) == 0
        assert len(lru_cache.ttl_map) == 0

    def test_stats_empty(self, lru_cache):
        s = lru_cache.stats()
        assert s["size"] == 0
        assert s["max_size"] == 5
        assert s["utilization"] == 0.0

    def test_stats_with_entries(self, lru_cache):
        lru_cache.set("t", {"a": 1}, "v1")
        lru_cache.set("t", {"a": 2}, "v2")
        s = lru_cache.stats()
        assert s["size"] == 2
        assert s["utilization"] == pytest.approx(40.0)

    def test_generate_key_deterministic(self, lru_cache):
        key1 = lru_cache._generate_key("tool", {"b": 2, "a": 1})
        key2 = lru_cache._generate_key("tool", {"a": 1, "b": 2})
        assert key1 == key2  # sort_keys=True makes order irrelevant

    def test_generate_key_is_md5_hex(self, lru_cache):
        key = lru_cache._generate_key("nmap", {"target": "x"})
        assert len(key) == 32
        int(key, 16)  # valid hex

    def test_custom_ttl_per_set(self, lru_cache):
        lru_cache.set("t", {"a": 1}, "v", ttl=600)
        key = lru_cache._generate_key("t", {"a": 1})
        # TTL should be roughly now + 600s
        expected_min = datetime.now() + timedelta(seconds=598)
        expected_max = datetime.now() + timedelta(seconds=602)
        assert expected_min <= lru_cache.ttl_map[key] <= expected_max

    def test_default_ttl_used_when_none(self):
        c = LRUCache(max_size=5, default_ttl=100)
        c.set("t", {"a": 1}, "v", ttl=None)
        key = c._generate_key("t", {"a": 1})
        expected_min = datetime.now() + timedelta(seconds=98)
        expected_max = datetime.now() + timedelta(seconds=102)
        assert expected_min <= c.ttl_map[key] <= expected_max

    def test_eviction_cleans_ttl_map(self):
        c = LRUCache(max_size=2, default_ttl=300)
        c.set("t", {"k": 1}, "v1")
        c.set("t", {"k": 2}, "v2")
        old_key = c._generate_key("t", {"k": 1})
        # Evict oldest by adding new entry
        c.set("t", {"k": 3}, "v3")
        assert old_key not in c.ttl_map

    def test_set_zero_ttl_means_default(self):
        """ttl=0 is falsy, so it uses default_ttl."""
        c = LRUCache(max_size=5, default_ttl=100)
        c.set("t", {"a": 1}, "v", ttl=0)
        key = c._generate_key("t", {"a": 1})
        # Should use default_ttl=100
        expected_min = datetime.now() + timedelta(seconds=98)
        expected_max = datetime.now() + timedelta(seconds=102)
        assert expected_min <= c.ttl_map[key] <= expected_max

    def test_get_without_ttl_entry(self, lru_cache):
        """If a key is in cache but not in ttl_map, it should still return."""
        key = lru_cache._generate_key("t", {"a": 1})
        lru_cache.cache[key] = "raw_value"
        # No ttl_map entry -- the TTL check is only if key in self.ttl_map
        hit, val = lru_cache.get("t", {"a": 1})
        assert hit is True
        assert val == "raw_value"


# ===================== AdaptiveRateLimiter =====================

class TestAdaptiveRateLimiter:
    def test_init_defaults(self):
        r = AdaptiveRateLimiter()
        assert r.current_rate == 10.0
        assert r.min_rate == 1.0
        assert r.max_rate == 100.0
        assert r.adjustment_factor == 0.1
        assert r.success_count == 0
        assert r.error_count == 0
        assert r.timeout_count == 0

    def test_init_custom(self):
        r = AdaptiveRateLimiter(initial_rate=50, min_rate=5, max_rate=200, adjustment_factor=0.2)
        assert r.current_rate == 50.0
        assert r.min_rate == 5.0
        assert r.max_rate == 200.0
        assert r.adjustment_factor == 0.2

    def test_report_success_increases_rate(self):
        r = AdaptiveRateLimiter(initial_rate=10.0, adjustment_factor=0.1, max_rate=100.0)
        r.report_success()
        assert r.current_rate == pytest.approx(11.0)
        assert r.success_count == 1

    def test_report_success_capped_at_max(self):
        r = AdaptiveRateLimiter(initial_rate=99.5, adjustment_factor=0.1, max_rate=100.0)
        r.report_success()
        assert r.current_rate == 100.0  # capped

    def test_report_error_decreases_rate(self):
        r = AdaptiveRateLimiter(initial_rate=10.0, adjustment_factor=0.1, min_rate=1.0)
        r.report_error()
        # factor * 2 = 0.2 reduction => 10 * 0.8 = 8.0
        assert r.current_rate == pytest.approx(8.0)
        assert r.error_count == 1

    def test_report_error_floored_at_min(self):
        r = AdaptiveRateLimiter(initial_rate=1.5, adjustment_factor=0.5, min_rate=1.0)
        r.report_error()
        # 1.5 * (1 - 0.5*2) = 1.5 * 0 = 0 => clamped to 1.0
        assert r.current_rate == 1.0

    def test_report_timeout_decreases_rate_more(self):
        r = AdaptiveRateLimiter(initial_rate=10.0, adjustment_factor=0.1, min_rate=1.0)
        r.report_timeout()
        # factor * 3 = 0.3 reduction => 10 * 0.7 = 7.0
        assert r.current_rate == pytest.approx(7.0)
        assert r.timeout_count == 1

    def test_report_timeout_floored_at_min(self):
        r = AdaptiveRateLimiter(initial_rate=2.0, adjustment_factor=0.5, min_rate=1.0)
        r.report_timeout()
        # 2.0 * (1 - 0.5*3) = 2.0 * -0.5 = -1.0 => clamped to 1.0
        assert r.current_rate == 1.0

    def test_get_stats_initial(self):
        r = AdaptiveRateLimiter(initial_rate=10.0)
        s = r.get_stats()
        assert s["current_rate"] == 10.0
        assert s["success_count"] == 0
        assert s["error_count"] == 0
        assert s["timeout_count"] == 0
        assert s["success_rate"] == 0  # total=0 -> 0

    def test_get_stats_with_counts(self):
        r = AdaptiveRateLimiter(initial_rate=10.0, adjustment_factor=0.0)
        r.report_success()
        r.report_success()
        r.report_error()
        s = r.get_stats()
        assert s["success_count"] == 2
        assert s["error_count"] == 1
        assert s["timeout_count"] == 0
        # success_rate = 2/3 * 100
        assert s["success_rate"] == pytest.approx(200.0 / 3.0)

    def test_acquire_no_wait_first_call(self):
        r = AdaptiveRateLimiter(initial_rate=1000.0)
        r.last_request_time = 0.0  # ensure first call is fast
        start = time.time()
        r.acquire()
        elapsed = time.time() - start
        assert elapsed < 0.1  # should be nearly instant

    def test_multiple_successes_incremental_increase(self):
        r = AdaptiveRateLimiter(initial_rate=10.0, adjustment_factor=0.1, max_rate=100.0)
        for _ in range(5):
            r.report_success()
        # 10 * 1.1^5
        expected = 10.0 * (1.1 ** 5)
        assert r.current_rate == pytest.approx(expected)


# ===================== TaskScheduler =====================

@pytest.fixture
def scheduler():
    return TaskScheduler(max_concurrent=3)


class TestTaskScheduler:
    def test_init(self):
        s = TaskScheduler(max_concurrent=10)
        assert s.max_concurrent == 10
        assert s.task_counter == 0

    def test_submit_returns_task_id(self, scheduler):
        t = Task(priority=3, task_id="", tool_name="t", parameters={})
        tid = scheduler.submit(t)
        assert tid.startswith("task_")
        assert t.status == TaskStatus.QUEUED

    def test_submit_preserves_existing_id(self, scheduler):
        t = Task(priority=3, task_id="my_id", tool_name="t", parameters={})
        tid = scheduler.submit(t)
        assert tid == "my_id"

    def test_submit_auto_generates_id_when_empty(self, scheduler):
        t = Task(priority=3, task_id="", tool_name="t", parameters={})
        tid = scheduler.submit(t)
        assert tid != ""
        assert "task_" in tid

    def test_get_next_returns_highest_priority(self, scheduler):
        t_low = Task(priority=5, task_id="low", tool_name="t", parameters={})
        t_high = Task(priority=1, task_id="high", tool_name="t", parameters={})
        t_mid = Task(priority=3, task_id="mid", tool_name="t", parameters={})
        scheduler.submit(t_low)
        scheduler.submit(t_high)
        scheduler.submit(t_mid)
        next_task = scheduler.get_next()
        assert next_task.task_id == "high"
        assert next_task.status == TaskStatus.RUNNING

    def test_get_next_returns_none_when_empty(self, scheduler):
        assert scheduler.get_next() is None

    def test_get_next_returns_none_when_at_max_concurrent(self, scheduler):
        # Fill up to max_concurrent=3
        for i in range(3):
            t = Task(priority=3, task_id=f"t{i}", tool_name="t", parameters={})
            scheduler.submit(t)
            scheduler.get_next()
        # Now submit one more but get_next should return None
        t = Task(priority=1, task_id="extra", tool_name="t", parameters={})
        scheduler.submit(t)
        assert scheduler.get_next() is None

    def test_complete_moves_to_completed(self, scheduler):
        t = Task(priority=3, task_id="t1", tool_name="t", parameters={})
        scheduler.submit(t)
        scheduler.get_next()
        scheduler.complete("t1", result="done")
        assert "t1" not in scheduler.running_tasks
        assert "t1" in scheduler.completed_tasks
        assert scheduler.completed_tasks["t1"].status == TaskStatus.COMPLETED
        assert scheduler.completed_tasks["t1"].result == "done"

    def test_complete_with_error_marks_failed(self, scheduler):
        t = Task(priority=3, task_id="t1", tool_name="t", parameters={})
        scheduler.submit(t)
        scheduler.get_next()
        scheduler.complete("t1", error="something broke")
        assert scheduler.completed_tasks["t1"].status == TaskStatus.FAILED
        assert scheduler.completed_tasks["t1"].error == "something broke"

    def test_complete_nonexistent_task_does_nothing(self, scheduler):
        scheduler.complete("nonexistent")
        assert "nonexistent" not in scheduler.completed_tasks

    def test_get_status_running(self, scheduler):
        t = Task(priority=3, task_id="t1", tool_name="t", parameters={})
        scheduler.submit(t)
        scheduler.get_next()
        result = scheduler.get_status("t1")
        assert result is not None
        assert result.status == TaskStatus.RUNNING

    def test_get_status_completed(self, scheduler):
        t = Task(priority=3, task_id="t1", tool_name="t", parameters={})
        scheduler.submit(t)
        scheduler.get_next()
        scheduler.complete("t1", result="ok")
        result = scheduler.get_status("t1")
        assert result.status == TaskStatus.COMPLETED

    def test_get_status_unknown(self, scheduler):
        assert scheduler.get_status("nope") is None

    def test_get_stats(self, scheduler):
        t = Task(priority=3, task_id="t1", tool_name="t", parameters={})
        scheduler.submit(t)
        s = scheduler.get_stats()
        assert s["queued"] == 1
        assert s["running"] == 0
        assert s["completed"] == 0
        assert s["max_concurrent"] == 3

    def test_get_stats_after_running(self, scheduler):
        t = Task(priority=3, task_id="t1", tool_name="t", parameters={})
        scheduler.submit(t)
        scheduler.get_next()
        s = scheduler.get_stats()
        assert s["queued"] == 0
        assert s["running"] == 1

    def test_task_counter_increments(self, scheduler):
        for i in range(5):
            t = Task(priority=3, task_id="", tool_name="t", parameters={})
            scheduler.submit(t)
        assert scheduler.task_counter == 5

    def test_completing_frees_concurrency_slot(self, scheduler):
        """Completing a task should allow get_next to return another."""
        for i in range(3):
            t = Task(priority=3, task_id=f"t{i}", tool_name="t", parameters={})
            scheduler.submit(t)
            scheduler.get_next()
        # All 3 slots occupied
        extra = Task(priority=1, task_id="extra", tool_name="t", parameters={})
        scheduler.submit(extra)
        assert scheduler.get_next() is None
        # Complete one
        scheduler.complete("t0", result="ok")
        got = scheduler.get_next()
        assert got is not None
        assert got.task_id == "extra"


# ===================== HighSpeedExecutor =====================

@pytest.fixture
def hse():
    """Create a HighSpeedExecutor with mocked executors to avoid real pools."""
    with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
         patch.object(ProcessPoolExecutor, '__init__', return_value=None):
        executor = HighSpeedExecutor(
            max_workers=10,
            max_process_workers=2,
            cache_size=100,
            cache_ttl=60,
            enable_rate_limiting=False,
        )
        # Manually ensure thread_executor has a mock submit
        executor.thread_executor = MagicMock(spec=ThreadPoolExecutor)
        executor.process_executor = MagicMock(spec=ProcessPoolExecutor)
        return executor


class TestHighSpeedExecutorInit:
    def test_attributes(self, hse):
        assert hse.max_workers == 10
        assert hse.max_process_workers == 2
        assert isinstance(hse.cache, LRUCache)
        assert isinstance(hse.scheduler, TaskScheduler)
        assert hse.rate_limiter is None  # enable_rate_limiting=False
        assert isinstance(hse.stats, ExecutionStats)
        assert hse.running is False
        assert hse.worker_thread is None
        assert hse.tool_executors == {}

    def test_rate_limiter_enabled(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = HighSpeedExecutor(enable_rate_limiting=True)
            ex.thread_executor = MagicMock()
            ex.process_executor = MagicMock()
            assert isinstance(ex.rate_limiter, AdaptiveRateLimiter)


class TestHighSpeedExecutorRegisterTool:
    def test_register_tool(self, hse):
        fn = lambda: None
        hse.register_tool("my_tool", fn)
        assert "my_tool" in hse.tool_executors
        assert hse.tool_executors["my_tool"] is fn

    def test_register_multiple_tools(self, hse):
        hse.register_tool("a", lambda: 1)
        hse.register_tool("b", lambda: 2)
        assert len(hse.tool_executors) == 2

    def test_overwrite_tool(self, hse):
        fn1 = lambda: 1
        fn2 = lambda: 2
        hse.register_tool("t", fn1)
        hse.register_tool("t", fn2)
        assert hse.tool_executors["t"] is fn2


class TestHighSpeedExecutorSubmitTask:
    def test_submit_task_basic(self, hse):
        tid = hse.submit_task("nmap", {"target": "x"}, use_cache=False)
        assert isinstance(tid, str)
        assert hse.stats.total_tasks == 1

    def test_submit_task_cache_hit(self, hse):
        hse.cache.set("nmap", {"target": "x"}, {"cached": True})
        tid = hse.submit_task("nmap", {"target": "x"}, use_cache=True)
        assert tid.startswith("cached_")
        assert hse.stats.cache_hits == 1
        assert hse.stats.total_tasks == 0  # task not actually submitted

    def test_submit_task_cache_miss(self, hse):
        tid = hse.submit_task("nmap", {"target": "x"}, use_cache=True)
        assert not tid.startswith("cached_")
        assert hse.stats.cache_misses == 1
        assert hse.stats.total_tasks == 1

    def test_submit_task_cache_hit_calls_callback(self, hse):
        callback = MagicMock()
        hse.cache.set("nmap", {"target": "x"}, {"result": "cached"})
        hse.submit_task("nmap", {"target": "x"}, use_cache=True, callback=callback)
        callback.assert_called_once_with({"result": "cached"})

    def test_submit_task_no_cache(self, hse):
        tid = hse.submit_task("nmap", {"target": "x"}, use_cache=False)
        assert hse.stats.cache_hits == 0
        assert hse.stats.cache_misses == 0

    def test_submit_task_priority(self, hse):
        hse.submit_task("nmap", {}, priority=TaskPriority.CRITICAL, use_cache=False)
        task = hse.scheduler.get_next()
        assert task.priority == 1

    def test_submit_task_default_priority_is_normal(self, hse):
        hse.submit_task("nmap", {}, use_cache=False)
        task = hse.scheduler.get_next()
        assert task.priority == TaskPriority.NORMAL.value


class TestHighSpeedExecutorSubmitBatch:
    def test_submit_batch(self, hse):
        tasks = [
            {"tool": "nmap", "params": {"target": "a"}},
            {"tool": "gobuster", "params": {"url": "b"}},
        ]
        ids = hse.submit_batch(tasks, priority=TaskPriority.HIGH)
        assert len(ids) == 2
        assert hse.stats.total_tasks == 2

    def test_submit_batch_uses_defaults(self, hse):
        tasks = [{"tool": "nmap"}]
        ids = hse.submit_batch(tasks)
        assert len(ids) == 1

    def test_submit_batch_empty(self, hse):
        ids = hse.submit_batch([])
        assert ids == []


class TestHighSpeedExecutorExecuteParallel:
    def test_execute_parallel_known_tools(self, hse):
        def mock_tool(target=""):
            return {"result": target}

        hse.register_tool("scanner", mock_tool)
        future_mock = MagicMock()
        future_mock.result.return_value = {"result": "x"}
        hse.thread_executor.submit.return_value = future_mock

        results = hse.execute_parallel([("scanner", {"target": "x"})], timeout=10)
        assert len(results) == 1
        assert results[0]["success"] is True
        assert results[0]["tool"] == "scanner"

    def test_execute_parallel_unknown_tool_skipped(self, hse):
        results = hse.execute_parallel([("unknown_tool", {"target": "x"})], timeout=10)
        assert len(results) == 0

    def test_execute_parallel_exception_handled(self, hse):
        hse.register_tool("bad_tool", lambda: None)
        future_mock = MagicMock()
        future_mock.result.side_effect = RuntimeError("boom")
        hse.thread_executor.submit.return_value = future_mock

        results = hse.execute_parallel([("bad_tool", {})], timeout=10)
        assert len(results) == 1
        assert results[0]["success"] is False
        assert "boom" in results[0]["error"]

    def test_execute_parallel_caches_success(self, hse):
        hse.register_tool("tool", lambda: "ok")
        future_mock = MagicMock()
        future_mock.result.return_value = "result_value"
        hse.thread_executor.submit.return_value = future_mock

        hse.execute_parallel([("tool", {"p": 1})], timeout=10)
        hit, val = hse.cache.get("tool", {"p": 1})
        assert hit is True
        assert val == "result_value"


class TestHighSpeedExecutorExecuteAsync:
    @pytest.mark.asyncio
    async def test_execute_async_unknown_tool(self, hse):
        with pytest.raises(ValueError, match="Unknown tool"):
            await hse.execute_async("nonexistent", {})

    @pytest.mark.asyncio
    async def test_execute_async_cache_hit(self, hse):
        hse.cache.set("tool", {"a": 1}, "cached_value")
        result = await hse.execute_async("tool", {"a": 1})
        assert result == "cached_value"

    @pytest.mark.asyncio
    async def test_execute_async_success(self, hse):
        def mock_fn(target=""):
            return {"found": True}

        hse.register_tool("scan", mock_fn)

        async def fake_run_in_executor(executor, func):
            return func()

        loop = asyncio.get_event_loop()
        with patch.object(loop, 'run_in_executor', side_effect=fake_run_in_executor):
            result = await hse.execute_async("scan", {"target": "x"}, timeout=5)
            assert result == {"found": True}
            assert hse.stats.completed_tasks == 1


class TestHighSpeedExecutorExecuteTask:
    def test_execute_task_unknown_tool(self, hse):
        t = Task(priority=3, task_id="t1", tool_name="unknown", parameters={})
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        completed = hse.scheduler.get_status("t1")
        assert completed.status == TaskStatus.FAILED
        assert "Unknown tool" in completed.error

    def test_execute_task_success(self, hse):
        call_count = {"n": 0}
        def mock_fn(**kwargs):
            call_count["n"] += 1
            return {"ok": True}

        hse.register_tool("tool", mock_fn)
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={"a": 1})
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        completed = hse.scheduler.get_status("t1")
        assert completed.status == TaskStatus.COMPLETED
        assert completed.result == {"ok": True}
        assert hse.stats.completed_tasks == 1
        assert call_count["n"] == 1

    def test_execute_task_caches_result(self, hse):
        hse.register_tool("tool", lambda **kwargs: "val")
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={"x": 1})
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        hit, val = hse.cache.get("tool", {"x": 1})
        assert hit is True
        assert val == "val"

    def test_execute_task_calls_callback(self, hse):
        cb = MagicMock()
        hse.register_tool("tool", lambda: "res")
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={}, callback=cb)
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        cb.assert_called_once_with("res")

    def test_execute_task_callback_error_logged(self, hse):
        cb = MagicMock(side_effect=RuntimeError("cb fail"))
        hse.register_tool("tool", lambda: "res")
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={}, callback=cb)
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        # Should not raise; callback errors are caught
        hse._execute_task(t)
        completed = hse.scheduler.get_status("t1")
        assert completed.status == TaskStatus.COMPLETED

    def test_execute_task_failure_retries(self, hse):
        call_count = {"n": 0}
        def failing_fn():
            call_count["n"] += 1
            raise RuntimeError("fail")

        hse.register_tool("tool", failing_fn)
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={}, retry_count=2)
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        # Should have resubmitted with retry_count decremented
        assert t.retry_count == 1
        assert hse.stats.failed_tasks == 1

    def test_execute_task_failure_no_retries_left(self, hse):
        hse.register_tool("tool", MagicMock(side_effect=RuntimeError("fail")))
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={}, retry_count=0)
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        completed = hse.scheduler.get_status("t1")
        assert completed.status == TaskStatus.FAILED
        assert "fail" in completed.error

    def test_execute_task_with_rate_limiter(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = HighSpeedExecutor(enable_rate_limiting=True)
            ex.thread_executor = MagicMock()
            ex.process_executor = MagicMock()

            ex.register_tool("tool", lambda: "ok")
            ex.rate_limiter = MagicMock()

            t = Task(priority=3, task_id="t1", tool_name="tool", parameters={})
            ex.scheduler.submit(t)
            ex.scheduler.get_next()
            ex._execute_task(t)

            ex.rate_limiter.acquire.assert_called_once()
            ex.rate_limiter.report_success.assert_called_once()

    def test_execute_task_failure_reports_error_to_rate_limiter(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = HighSpeedExecutor(enable_rate_limiting=True)
            ex.thread_executor = MagicMock()
            ex.process_executor = MagicMock()

            ex.register_tool("tool", MagicMock(side_effect=RuntimeError("x")))
            ex.rate_limiter = MagicMock()

            t = Task(priority=3, task_id="t1", tool_name="tool", parameters={}, retry_count=0)
            ex.scheduler.submit(t)
            ex.scheduler.get_next()
            ex._execute_task(t)

            ex.rate_limiter.report_error.assert_called_once()

    def test_execute_task_records_execution_time(self, hse):
        def slow_fn():
            time.sleep(0.05)
            return "done"

        hse.register_tool("tool", slow_fn)
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={})
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        assert t.execution_time > 0.0


class TestHighSpeedExecutorGetTaskStatus:
    def test_get_task_status_existing(self, hse):
        hse.register_tool("tool", lambda **kw: "res")
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={"a": 1}, retry_count=0)
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        status = hse.get_task_status("t1")
        assert status is not None
        assert status["task_id"] == "t1"
        assert status["tool"] == "tool"
        assert status["status"] == "completed"
        assert status["result"] == "res"
        assert status["error"] is None

    def test_get_task_status_nonexistent(self, hse):
        assert hse.get_task_status("nope") is None


class TestHighSpeedExecutorGetStats:
    def test_get_stats_initial(self, hse):
        s = hse.get_stats()
        assert s["execution"]["total"] == 0
        assert s["execution"]["completed"] == 0
        assert s["execution"]["failed"] == 0
        assert s["execution"]["timeout"] == 0
        assert s["cache"]["hits"] == 0
        assert s["cache"]["misses"] == 0
        assert s["cache"]["hit_rate"] == 0
        assert "scheduler" in s
        assert s["rate_limiter"] is None

    def test_get_stats_average_time(self, hse):
        hse.stats.completed_tasks = 2
        hse.stats.total_execution_time = 10.0
        s = hse.get_stats()
        assert s["execution"]["average_time"] == 5.0

    def test_get_stats_cache_hit_rate(self, hse):
        hse.stats.cache_hits = 3
        hse.stats.cache_misses = 7
        s = hse.get_stats()
        assert s["cache"]["hit_rate"] == 30.0

    def test_get_stats_with_rate_limiter(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = HighSpeedExecutor(enable_rate_limiting=True)
            ex.thread_executor = MagicMock()
            ex.process_executor = MagicMock()
            s = ex.get_stats()
            assert s["rate_limiter"] is not None
            assert "current_rate" in s["rate_limiter"]


class TestHighSpeedExecutorWorkerLifecycle:
    def test_start_worker(self, hse):
        hse.start_worker()
        assert hse.running is True
        assert hse.worker_thread is not None
        assert hse.worker_thread.daemon is True
        hse.stop_worker()

    def test_start_worker_idempotent(self, hse):
        hse.start_worker()
        first_thread = hse.worker_thread
        hse.start_worker()
        assert hse.worker_thread is first_thread
        hse.stop_worker()

    def test_stop_worker(self, hse):
        hse.start_worker()
        hse.stop_worker()
        assert hse.running is False

    def test_stop_worker_when_not_started(self, hse):
        hse.stop_worker()  # should not raise
        assert hse.running is False


class TestHighSpeedExecutorShutdown:
    def test_shutdown_stops_worker(self, hse):
        hse.start_worker()
        hse.shutdown()
        assert hse.running is False
        hse.thread_executor.shutdown.assert_called_once_with(wait=False)
        hse.process_executor.shutdown.assert_called_once_with(wait=False)

    def test_shutdown_without_worker(self, hse):
        hse.shutdown()
        hse.thread_executor.shutdown.assert_called_once()
        hse.process_executor.shutdown.assert_called_once()


# ===================== FAST_SCAN_PRESETS =====================

class TestFastScanPresets:
    def test_all_presets_present(self):
        assert "ctf_speed" in FAST_SCAN_PRESETS
        assert "awd_extreme" in FAST_SCAN_PRESETS
        assert "pentest_balanced" in FAST_SCAN_PRESETS
        assert "stealth_slow" in FAST_SCAN_PRESETS

    def test_preset_count(self):
        assert len(FAST_SCAN_PRESETS) == 4

    def test_ctf_speed_config(self):
        c = FAST_SCAN_PRESETS["ctf_speed"]
        assert c["max_workers"] == 100
        assert c["cache_ttl"] == 60
        assert c["timeout"] == 30
        assert c["rate_limit"] is False
        assert "nmap_scan" in c["tools"]

    def test_awd_extreme_config(self):
        c = FAST_SCAN_PRESETS["awd_extreme"]
        assert c["max_workers"] == 200
        assert c["timeout"] == 15
        assert c["rate_limit"] is False

    def test_pentest_balanced_config(self):
        c = FAST_SCAN_PRESETS["pentest_balanced"]
        assert c["max_workers"] == 50
        assert c["cache_ttl"] == 300
        assert c["rate_limit"] is True

    def test_stealth_slow_config(self):
        c = FAST_SCAN_PRESETS["stealth_slow"]
        assert c["max_workers"] == 10
        assert c["cache_ttl"] == 600
        assert c["rate_limit"] is True

    def test_each_preset_has_required_keys(self):
        required = {"max_workers", "cache_ttl", "timeout", "rate_limit", "tools"}
        for name, config in FAST_SCAN_PRESETS.items():
            assert required.issubset(config.keys()), f"Preset {name} missing keys"

    def test_tools_values_are_dicts(self):
        for name, config in FAST_SCAN_PRESETS.items():
            for tool_name, tool_config in config["tools"].items():
                assert isinstance(tool_config, dict), f"{name}.tools.{tool_name} not dict"


# ===================== FastExecutorFactory =====================

class TestFastExecutorFactory:
    def test_create_default_preset(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = FastExecutorFactory.create()
            assert isinstance(ex, HighSpeedExecutor)
            assert ex.max_workers == 50  # pentest_balanced

    def test_create_ctf_speed(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = FastExecutorFactory.create("ctf_speed")
            assert ex.max_workers == 100

    def test_create_awd_extreme(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = FastExecutorFactory.create("awd_extreme")
            assert ex.max_workers == 200

    def test_create_stealth_slow(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = FastExecutorFactory.create("stealth_slow")
            assert ex.max_workers == 10

    def test_create_unknown_preset_uses_default(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = FastExecutorFactory.create("nonexistent_preset")
            assert ex.max_workers == 50  # falls back to pentest_balanced

    def test_create_rate_limiting_disabled_for_ctf(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = FastExecutorFactory.create("ctf_speed")
            assert ex.rate_limiter is None

    def test_create_rate_limiting_enabled_for_pentest(self):
        with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
             patch.object(ProcessPoolExecutor, '__init__', return_value=None):
            ex = FastExecutorFactory.create("pentest_balanced")
            assert isinstance(ex.rate_limiter, AdaptiveRateLimiter)

    def test_get_tool_config_existing(self):
        config = FastExecutorFactory.get_tool_config("ctf_speed", "nmap_scan")
        assert config["timing"] == "-T5"

    def test_get_tool_config_nonexistent_tool(self):
        config = FastExecutorFactory.get_tool_config("ctf_speed", "no_such_tool")
        assert config == {}

    def test_get_tool_config_nonexistent_preset(self):
        config = FastExecutorFactory.get_tool_config("no_such_preset", "nmap_scan")
        assert config == {}


# ===================== Global Convenience Functions =====================

class TestGetExecutor:
    def test_get_executor_creates_singleton(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance
        try:
            mod._executor_instance = None
            with patch.object(ThreadPoolExecutor, '__init__', return_value=None), \
                 patch.object(ProcessPoolExecutor, '__init__', return_value=None), \
                 patch.object(HighSpeedExecutor, 'start_worker'):
                ex = get_executor("pentest_balanced")
                assert isinstance(ex, HighSpeedExecutor)
                ex.start_worker.assert_called_once()
                # Second call returns same instance
                ex2 = get_executor()
                assert ex2 is ex
        finally:
            mod._executor_instance = original

    def test_get_executor_reuses_existing(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance
        try:
            sentinel = MagicMock()
            mod._executor_instance = sentinel
            result = get_executor()
            assert result is sentinel
        finally:
            mod._executor_instance = original


class TestQuickExecute:
    def test_quick_execute_completed(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance

        mock_ex = MagicMock()
        mock_ex.submit_task.return_value = "tid_1"
        # First call: running, second call: completed
        mock_ex.get_task_status.side_effect = [
            {"status": "running"},
            {"status": "completed", "result": "success_data"},
        ]
        try:
            mod._executor_instance = mock_ex
            with patch('kali_mcp.core.high_speed_executor.time.sleep'):
                result = quick_execute("tool", {"p": 1}, timeout=30)
            assert result == "success_data"
        finally:
            mod._executor_instance = original

    def test_quick_execute_failed(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance

        mock_ex = MagicMock()
        mock_ex.submit_task.return_value = "tid_1"
        mock_ex.get_task_status.return_value = {"status": "failed", "error": "broken"}
        try:
            mod._executor_instance = mock_ex
            with patch('kali_mcp.core.high_speed_executor.time.sleep'):
                with pytest.raises(Exception, match="broken"):
                    quick_execute("tool", {})
        finally:
            mod._executor_instance = original


class TestQuickExecuteAsync:
    @pytest.mark.asyncio
    async def test_quick_execute_async(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance

        mock_ex = MagicMock()

        async def mock_execute_async(tool, params, timeout):
            return {"async": True}

        mock_ex.execute_async = mock_execute_async
        try:
            mod._executor_instance = mock_ex
            result = await quick_execute_async("tool", {"a": 1}, timeout=10)
            assert result == {"async": True}
        finally:
            mod._executor_instance = original


class TestParallelExecute:
    def test_parallel_execute(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance

        mock_ex = MagicMock()
        mock_ex.execute_parallel.return_value = [{"success": True}]
        try:
            mod._executor_instance = mock_ex
            result = parallel_execute([("tool", {})], timeout=60)
            assert result == [{"success": True}]
            mock_ex.execute_parallel.assert_called_once_with([("tool", {})], 60)
        finally:
            mod._executor_instance = original


class TestParallelExecuteAsync:
    @pytest.mark.asyncio
    async def test_parallel_execute_async(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance

        mock_ex = MagicMock()

        async def mock_batch(tasks, max_conc, timeout):
            return [{"success": True}]

        mock_ex.execute_batch_async = mock_batch
        try:
            mod._executor_instance = mock_ex
            result = await parallel_execute_async([("tool", {})], max_concurrent=5, timeout=30)
            assert result == [{"success": True}]
        finally:
            mod._executor_instance = original


class TestGetExecutionStats:
    def test_get_execution_stats(self):
        import kali_mcp.core.high_speed_executor as mod
        original = mod._executor_instance

        mock_ex = MagicMock()
        mock_ex.get_stats.return_value = {"execution": {"total": 42}}
        try:
            mod._executor_instance = mock_ex
            result = get_execution_stats()
            assert result == {"execution": {"total": 42}}
        finally:
            mod._executor_instance = original


# ===================== Integration-Style Unit Tests =====================

class TestHighSpeedExecutorIntegration:
    """Test combinations of components working together within HSE."""

    def test_submit_and_execute_full_cycle(self, hse):
        """Submit a task, execute it, verify completion."""
        results = []
        def my_tool(target=""):
            return f"scanned:{target}"

        hse.register_tool("scanner", my_tool)
        tid = hse.submit_task("scanner", {"target": "10.0.0.1"}, use_cache=False)

        task = hse.scheduler.get_next()
        assert task is not None
        hse._execute_task(task)

        status = hse.get_task_status(tid)
        assert status["status"] == "completed"
        assert status["result"] == "scanned:10.0.0.1"

    def test_task_priority_ordering_in_scheduler(self, hse):
        """Higher priority tasks should come out first."""
        hse.submit_task("t", {"a": 1}, priority=TaskPriority.LOW, use_cache=False)
        hse.submit_task("t", {"a": 2}, priority=TaskPriority.CRITICAL, use_cache=False)
        hse.submit_task("t", {"a": 3}, priority=TaskPriority.NORMAL, use_cache=False)

        t1 = hse.scheduler.get_next()
        t2 = hse.scheduler.get_next()
        t3 = hse.scheduler.get_next()
        assert t1.priority == TaskPriority.CRITICAL.value
        assert t2.priority == TaskPriority.NORMAL.value
        assert t3.priority == TaskPriority.LOW.value

    def test_cache_integration_second_call_cached(self, hse):
        hse.register_tool("tool", lambda x=0: x * 2)
        # First submit: cache miss
        tid1 = hse.submit_task("tool", {"x": 5}, use_cache=True)
        task = hse.scheduler.get_next()
        hse._execute_task(task)
        # result cached
        hit, val = hse.cache.get("tool", {"x": 5})
        assert hit is True
        assert val == 10
        # Second submit: should hit cache
        tid2 = hse.submit_task("tool", {"x": 5}, use_cache=True)
        assert tid2.startswith("cached_")
        assert hse.stats.cache_hits == 1

    def test_stats_accumulate_through_execution(self, hse):
        hse.register_tool("ok_tool", lambda: "ok")
        hse.register_tool("bad_tool", MagicMock(side_effect=RuntimeError("fail")))

        # Execute good task
        t1 = Task(priority=3, task_id="good", tool_name="ok_tool", parameters={})
        hse.scheduler.submit(t1)
        hse.scheduler.get_next()
        hse._execute_task(t1)

        # Execute bad task (no retries)
        t2 = Task(priority=3, task_id="bad", tool_name="bad_tool", parameters={}, retry_count=0)
        hse.scheduler.submit(t2)
        hse.scheduler.get_next()
        hse._execute_task(t2)

        assert hse.stats.completed_tasks == 1
        assert hse.stats.failed_tasks == 1

    def test_worker_processes_submitted_tasks(self, hse):
        """Start worker, submit a task, verify it's processed."""
        call_tracker = {"called": False}
        def my_tool():
            call_tracker["called"] = True
            return "done"

        hse.register_tool("tool", my_tool)
        hse.start_worker()
        try:
            tid = hse.submit_task("tool", {}, use_cache=False)
            # Wait for worker to process
            deadline = time.time() + 2
            while time.time() < deadline:
                status = hse.get_task_status(tid)
                if status and status["status"] in ("completed", "failed"):
                    break
                time.sleep(0.05)
            status = hse.get_task_status(tid)
            assert status is not None
            assert status["status"] == "completed"
            assert call_tracker["called"] is True
        finally:
            hse.stop_worker()


# ===================== Edge Cases =====================

class TestEdgeCases:
    def test_lru_cache_single_capacity(self):
        c = LRUCache(max_size=1, default_ttl=300)
        c.set("t", {"k": 1}, "v1")
        c.set("t", {"k": 2}, "v2")
        hit1, _ = c.get("t", {"k": 1})
        assert hit1 is False
        hit2, val2 = c.get("t", {"k": 2})
        assert hit2 is True
        assert val2 == "v2"

    def test_empty_params_cache_key(self):
        c = LRUCache(max_size=5, default_ttl=300)
        c.set("tool", {}, "value")
        hit, val = c.get("tool", {})
        assert hit is True
        assert val == "value"

    def test_scheduler_submit_many_tasks(self):
        s = TaskScheduler(max_concurrent=100)
        for i in range(50):
            t = Task(priority=i % 5 + 1, task_id=f"t{i}", tool_name="t", parameters={})
            s.submit(t)
        assert s.task_counter == 50
        stats = s.get_stats()
        assert stats["queued"] == 50

    def test_task_with_none_callback(self, hse):
        hse.register_tool("tool", lambda: "ok")
        t = Task(priority=3, task_id="t1", tool_name="tool", parameters={}, callback=None)
        hse.scheduler.submit(t)
        hse.scheduler.get_next()
        hse._execute_task(t)
        # No exception should be raised
        assert hse.scheduler.get_status("t1").status == TaskStatus.COMPLETED

    def test_execution_stats_average_with_zero_completed(self, hse):
        s = hse.get_stats()
        assert s["execution"]["average_time"] == 0.0

    def test_rate_limiter_multiple_reports_interleaved(self):
        r = AdaptiveRateLimiter(initial_rate=10.0, adjustment_factor=0.1, min_rate=1.0, max_rate=100.0)
        r.report_success()
        r.report_error()
        r.report_timeout()
        # 10 * 1.1 = 11 -> 11 * 0.8 = 8.8 -> 8.8 * 0.7 = 6.16
        assert r.current_rate == pytest.approx(6.16)
        assert r.success_count == 1
        assert r.error_count == 1
        assert r.timeout_count == 1

    def test_cache_stats_full_utilization(self):
        c = LRUCache(max_size=3, default_ttl=300)
        c.set("t", {"k": 1}, "v1")
        c.set("t", {"k": 2}, "v2")
        c.set("t", {"k": 3}, "v3")
        s = c.stats()
        assert s["utilization"] == pytest.approx(100.0)

    def test_submit_batch_with_mixed_cache(self, hse):
        """Batch with some cached and some new tasks."""
        hse.cache.set("cached_tool", {"p": 1}, "cached_result")
        tasks = [
            {"tool": "cached_tool", "params": {"p": 1}, "use_cache": True},
            {"tool": "new_tool", "params": {"p": 2}, "use_cache": True},
        ]
        ids = hse.submit_batch(tasks)
        assert len(ids) == 2
        assert ids[0].startswith("cached_")
        assert not ids[1].startswith("cached_")


# ===================== __all__ Export Tests =====================

class TestModuleExports:
    def test_all_exports(self):
        import kali_mcp.core.high_speed_executor as mod
        expected = [
            "TaskPriority", "TaskStatus", "Task", "ExecutionStats",
            "LRUCache", "AdaptiveRateLimiter", "TaskScheduler",
            "HighSpeedExecutor", "FastExecutorFactory", "FAST_SCAN_PRESETS",
            "get_executor", "quick_execute", "quick_execute_async",
            "parallel_execute", "parallel_execute_async", "get_execution_stats",
        ]
        for name in expected:
            assert name in mod.__all__, f"{name} missing from __all__"
            assert hasattr(mod, name), f"{name} not defined in module"

    def test_all_length(self):
        import kali_mcp.core.high_speed_executor as mod
        assert len(mod.__all__) == 16
