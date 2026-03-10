"""
Comprehensive tests for EventBus (kali_mcp/core/event_bus.py)

Covers:
- Event and Subscription dataclasses
- Pattern matching: exact, wildcard "*", prefix "tool.*", non-match, edge cases
- subscribe(): handler registration, default subscriber_name, priority sorting
- unsubscribe(): removal, idempotent on missing pattern/name
- emit(): event creation, handler dispatch, stats tracking, error handling
- Priority ordering across same-pattern and cross-pattern subscriptions
- Event history: append, trim at max_history=500, recent events
- get_stats(): structure and value correctness
- get_recent_events(): filtering by pattern, limit, format
- get_events_for_target(): target substring matching, limit
- Thread safety under concurrent subscribe/emit
- NOTE: Timeout tests are intentionally excluded (would be slow).
"""

import time
import threading
from unittest.mock import MagicMock, patch

import pytest

from kali_mcp.core.event_bus import EventBus, Event, Subscription, HANDLER_TIMEOUT


# ──────────────────────────────────────────────────────────────
# Dataclass construction
# ──────────────────────────────────────────────────────────────

class TestEventDataclass:
    """Verify Event dataclass field defaults and construction."""

    def test_event_required_fields(self):
        e = Event(event_type="tool.result", data={"key": "val"})
        assert e.event_type == "tool.result"
        assert e.data == {"key": "val"}

    def test_event_timestamp_auto(self):
        before = time.time()
        e = Event(event_type="x", data={})
        after = time.time()
        assert before <= e.timestamp <= after

    def test_event_source_default_empty(self):
        e = Event(event_type="x", data={})
        assert e.source == ""

    def test_event_source_explicit(self):
        e = Event(event_type="x", data={}, source="scanner")
        assert e.source == "scanner"


class TestSubscriptionDataclass:
    """Verify Subscription dataclass fields and defaults."""

    def test_subscription_fields(self):
        fn = lambda event: None
        s = Subscription(handler=fn, subscriber_name="sub1", event_pattern="tool.*")
        assert s.handler is fn
        assert s.subscriber_name == "sub1"
        assert s.event_pattern == "tool.*"
        assert s.priority == 0  # default

    def test_subscription_priority_explicit(self):
        s = Subscription(handler=lambda e: None, subscriber_name="s",
                         event_pattern="*", priority=99)
        assert s.priority == 99


# ──────────────────────────────────────────────────────────────
# _pattern_matches (static, tested in isolation)
# ──────────────────────────────────────────────────────────────

class TestPatternMatches:
    """Thoroughly test the static _pattern_matches method."""

    # --- wildcard "*" ---
    def test_wildcard_matches_anything(self):
        assert EventBus._pattern_matches("*", "tool.result") is True
        assert EventBus._pattern_matches("*", "anything.at.all") is True
        assert EventBus._pattern_matches("*", "") is True

    # --- exact match ---
    def test_exact_match_identical(self):
        assert EventBus._pattern_matches("tool.result", "tool.result") is True

    def test_exact_match_different(self):
        assert EventBus._pattern_matches("tool.result", "tool.error") is False

    def test_exact_match_substring_not_enough(self):
        assert EventBus._pattern_matches("tool", "tool.result") is False

    # --- prefix "xxx.*" ---
    def test_prefix_matches_child(self):
        assert EventBus._pattern_matches("tool.*", "tool.result") is True
        assert EventBus._pattern_matches("tool.*", "tool.error") is True

    def test_prefix_does_not_match_different_prefix(self):
        assert EventBus._pattern_matches("tool.*", "vuln.candidate") is False

    def test_prefix_does_not_match_bare_prefix(self):
        """'tool.*' should NOT match 'tool' (no dot-separated child)."""
        assert EventBus._pattern_matches("tool.*", "tool") is False

    def test_prefix_does_not_match_partial_prefix(self):
        """'tool.*' should not match 'toolbox.scan' because prefix is 'tool' + '.'."""
        assert EventBus._pattern_matches("tool.*", "toolbox.scan") is False

    def test_prefix_deeper_nesting(self):
        """'tool.*' should match 'tool.scan.deep' since it starts with 'tool.'."""
        assert EventBus._pattern_matches("tool.*", "tool.scan.deep") is True

    # --- negative / edge cases ---
    def test_non_wildcard_non_exact_fails(self):
        assert EventBus._pattern_matches("tool.res", "tool.result") is False

    def test_empty_pattern_vs_empty_event(self):
        assert EventBus._pattern_matches("", "") is True  # exact match

    def test_empty_pattern_vs_nonempty_event(self):
        assert EventBus._pattern_matches("", "tool.result") is False


# ──────────────────────────────────────────────────────────────
# subscribe()
# ──────────────────────────────────────────────────────────────

class TestSubscribe:
    """Test subscribe behaviour: registration, naming, priority sorting."""

    def test_subscribe_adds_to_subscriptions(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("tool.result", handler, "my_sub")
        stats = event_bus.get_stats()
        assert stats["subscriber_count"] == 1

    def test_subscribe_default_name_uses_handler_name(self, event_bus):
        def my_custom_handler(event):
            pass
        event_bus.subscribe("tool.result", my_custom_handler)
        # Internal check: the subscription should carry the function name
        subs = event_bus._subscriptions["tool.result"]
        assert len(subs) == 1
        assert subs[0].subscriber_name == "my_custom_handler"

    def test_subscribe_explicit_name_overrides(self, event_bus):
        event_bus.subscribe("tool.result", lambda e: None, subscriber_name="override")
        subs = event_bus._subscriptions["tool.result"]
        assert subs[0].subscriber_name == "override"

    def test_subscribe_multiple_same_pattern(self, event_bus):
        event_bus.subscribe("x", MagicMock(), "s1")
        event_bus.subscribe("x", MagicMock(), "s2")
        event_bus.subscribe("x", MagicMock(), "s3")
        assert len(event_bus._subscriptions["x"]) == 3

    def test_subscribe_sorts_by_priority_descending(self, event_bus):
        event_bus.subscribe("x", MagicMock(), "low", priority=1)
        event_bus.subscribe("x", MagicMock(), "high", priority=10)
        event_bus.subscribe("x", MagicMock(), "mid", priority=5)
        names = [s.subscriber_name for s in event_bus._subscriptions["x"]]
        assert names == ["high", "mid", "low"]

    def test_subscribe_to_different_patterns(self, event_bus):
        event_bus.subscribe("a", MagicMock(), "s1")
        event_bus.subscribe("b", MagicMock(), "s2")
        stats = event_bus.get_stats()
        assert stats["subscriber_count"] == 2


# ──────────────────────────────────────────────────────────────
# unsubscribe()
# ──────────────────────────────────────────────────────────────

class TestUnsubscribe:
    """Test unsubscribe removes correct handlers."""

    def test_unsubscribe_removes_handler(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("ev", handler, "doomed")
        event_bus.unsubscribe("ev", "doomed")
        event_bus.emit("ev", {})
        handler.assert_not_called()

    def test_unsubscribe_leaves_other_handlers(self, event_bus):
        h1 = MagicMock()
        h2 = MagicMock()
        event_bus.subscribe("ev", h1, "keep")
        event_bus.subscribe("ev", h2, "remove")
        event_bus.unsubscribe("ev", "remove")
        event_bus.emit("ev", {})
        h1.assert_called_once()
        h2.assert_not_called()

    def test_unsubscribe_nonexistent_pattern_no_crash(self, event_bus):
        event_bus.unsubscribe("nonexistent.pattern", "nobody")  # should not raise

    def test_unsubscribe_wrong_name_no_effect(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("ev", handler, "real_name")
        event_bus.unsubscribe("ev", "wrong_name")
        event_bus.emit("ev", {})
        handler.assert_called_once()

    def test_unsubscribe_then_resubscribe(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("ev", handler, "sub")
        event_bus.unsubscribe("ev", "sub")
        event_bus.subscribe("ev", handler, "sub")
        event_bus.emit("ev", {})
        handler.assert_called_once()

    def test_unsubscribe_reduces_subscriber_count(self, event_bus):
        event_bus.subscribe("ev", MagicMock(), "s1")
        event_bus.subscribe("ev", MagicMock(), "s2")
        event_bus.unsubscribe("ev", "s1")
        assert event_bus.get_stats()["subscriber_count"] == 1


# ──────────────────────────────────────────────────────────────
# emit() — basic dispatch
# ──────────────────────────────────────────────────────────────

class TestEmit:
    """Test core emit behaviour: event creation, dispatch, stats."""

    def test_emit_calls_handler_with_event(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("tool.result", handler, "sub")
        event_bus.emit("tool.result", {"tool": "nmap", "target": "10.0.0.1"}, source="exec")

        handler.assert_called_once()
        event = handler.call_args[0][0]
        assert isinstance(event, Event)
        assert event.event_type == "tool.result"
        assert event.data["tool"] == "nmap"
        assert event.source == "exec"

    def test_emit_multiple_handlers(self, event_bus):
        h1 = MagicMock()
        h2 = MagicMock()
        event_bus.subscribe("tool.result", h1, "sub1")
        event_bus.subscribe("tool.result", h2, "sub2")
        event_bus.emit("tool.result", {"x": 1})
        h1.assert_called_once()
        h2.assert_called_once()

    def test_emit_no_subscribers_no_crash(self, event_bus):
        event_bus.emit("orphan.event", {"data": "nothing"})

    def test_emit_source_default_empty(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("ev", handler, "sub")
        event_bus.emit("ev", {})
        event = handler.call_args[0][0]
        assert event.source == ""

    def test_emit_wildcard_subscriber_receives_all(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("*", handler, "catch_all")
        event_bus.emit("tool.result", {})
        event_bus.emit("vuln.candidate", {})
        event_bus.emit("custom.event", {})
        assert handler.call_count == 3

    def test_emit_prefix_subscriber(self, event_bus):
        handler = MagicMock()
        event_bus.subscribe("tool.*", handler, "tool_watcher")
        event_bus.emit("tool.result", {})
        event_bus.emit("tool.error", {})
        event_bus.emit("vuln.candidate", {})
        assert handler.call_count == 2


# ──────────────────────────────────────────────────────────────
# emit() — priority ordering
# ──────────────────────────────────────────────────────────────

class TestPriorityOrdering:
    """Test that handlers execute in descending priority order."""

    def test_same_pattern_priority_order(self, event_bus):
        order = []
        event_bus.subscribe("ev", lambda e: order.append("low"), "low", priority=1)
        event_bus.subscribe("ev", lambda e: order.append("high"), "high", priority=10)
        event_bus.subscribe("ev", lambda e: order.append("mid"), "mid", priority=5)
        event_bus.emit("ev", {})
        assert order == ["high", "mid", "low"]

    def test_cross_pattern_priority_order(self, event_bus):
        """Wildcard and exact subscriptions are merged and sorted by priority."""
        order = []
        event_bus.subscribe("*", lambda e: order.append("wildcard_p3"), "wc", priority=3)
        event_bus.subscribe("tool.result", lambda e: order.append("exact_p10"), "ex", priority=10)
        event_bus.subscribe("tool.*", lambda e: order.append("prefix_p5"), "pf", priority=5)
        event_bus.emit("tool.result", {})
        assert order == ["exact_p10", "prefix_p5", "wildcard_p3"]

    def test_equal_priority_stable(self, event_bus):
        """Handlers with equal priority all get called (order is stable but unspecified)."""
        names = []
        event_bus.subscribe("ev", lambda e: names.append("a"), "a", priority=5)
        event_bus.subscribe("ev", lambda e: names.append("b"), "b", priority=5)
        event_bus.emit("ev", {})
        assert set(names) == {"a", "b"}
        assert len(names) == 2


# ──────────────────────────────────────────────────────────────
# emit() — error handling
# ──────────────────────────────────────────────────────────────

class TestEmitErrorHandling:
    """Test handler errors are caught, logged, and tracked in stats."""

    def test_handler_exception_does_not_crash_bus(self, event_bus):
        def bad(event):
            raise ValueError("boom")
        event_bus.subscribe("ev", bad, "bad_sub")
        event_bus.emit("ev", {})  # should not raise

    def test_handler_exception_increments_errors(self, event_bus):
        def bad(event):
            raise RuntimeError("fail")
        event_bus.subscribe("ev", bad, "bad_sub")
        event_bus.emit("ev", {})
        stats = event_bus.get_stats()
        assert stats["total_errors"] == 1
        assert stats["by_type"]["ev"]["errors"] == 1

    def test_handler_exception_does_not_block_others(self, event_bus):
        order = []

        def bad(event):
            raise RuntimeError("fail")

        def good(event):
            order.append("good")

        # bad runs first (higher priority), good should still run
        event_bus.subscribe("ev", bad, "bad", priority=10)
        event_bus.subscribe("ev", good, "good", priority=1)
        event_bus.emit("ev", {})
        assert order == ["good"]

    def test_multiple_errors_tracked(self, event_bus):
        def bad1(event):
            raise ValueError("v")

        def bad2(event):
            raise TypeError("t")

        event_bus.subscribe("ev", bad1, "b1")
        event_bus.subscribe("ev", bad2, "b2")
        event_bus.emit("ev", {})
        stats = event_bus.get_stats()
        assert stats["total_errors"] == 2


# ──────────────────────────────────────────────────────────────
# Stats tracking
# ──────────────────────────────────────────────────────────────

class TestGetStats:
    """Test get_stats() structure and correctness."""

    def test_initial_stats_all_zero(self, event_bus):
        stats = event_bus.get_stats()
        assert stats["total_events"] == 0
        assert stats["total_handled"] == 0
        assert stats["total_errors"] == 0
        assert stats["total_timeouts"] == 0
        assert stats["subscriber_count"] == 0
        assert stats["history_size"] == 0

    def test_stats_keys_present(self, event_bus):
        stats = event_bus.get_stats()
        for key in ("total_events", "total_handled", "total_errors",
                     "total_timeouts", "by_type", "subscriber_count", "history_size"):
            assert key in stats

    def test_stats_emitted_count(self, event_bus):
        event_bus.emit("a", {})
        event_bus.emit("b", {})
        event_bus.emit("a", {})
        stats = event_bus.get_stats()
        assert stats["total_events"] == 3
        assert stats["by_type"]["a"]["emitted"] == 2
        assert stats["by_type"]["b"]["emitted"] == 1

    def test_stats_handled_count(self, event_bus):
        h = MagicMock()
        event_bus.subscribe("a", h, "s")
        event_bus.emit("a", {})
        event_bus.emit("a", {})
        stats = event_bus.get_stats()
        assert stats["total_handled"] == 2

    def test_stats_subscriber_count_multi_pattern(self, event_bus):
        event_bus.subscribe("a", MagicMock(), "s1")
        event_bus.subscribe("b", MagicMock(), "s2")
        event_bus.subscribe("a", MagicMock(), "s3")
        assert event_bus.get_stats()["subscriber_count"] == 3

    def test_stats_by_type_isolation(self, event_bus):
        """Stats for different event types are independent."""
        event_bus.subscribe("a", MagicMock(), "sa")
        event_bus.subscribe("b", lambda e: (_ for _ in ()).throw(ValueError), "sb")
        event_bus.emit("a", {})
        event_bus.emit("b", {})
        stats = event_bus.get_stats()
        assert stats["by_type"]["a"]["handled"] == 1
        assert stats["by_type"]["a"]["errors"] == 0
        assert stats["by_type"]["b"]["errors"] == 1


# ──────────────────────────────────────────────────────────────
# Event history
# ──────────────────────────────────────────────────────────────

class TestEventHistory:
    """Test event history storage and trimming."""

    def test_events_stored(self, event_bus):
        event_bus.emit("e1", {"k": 1})
        event_bus.emit("e2", {"k": 2})
        assert event_bus.get_stats()["history_size"] == 2

    def test_history_capped_at_500(self, event_bus):
        for i in range(600):
            event_bus.emit("bulk", {"i": i})
        assert event_bus.get_stats()["history_size"] == 500

    def test_history_keeps_most_recent(self, event_bus):
        for i in range(550):
            event_bus.emit("bulk", {"i": i})
        # After 550 emits and trimming to 500, the oldest retained is i=50
        oldest = event_bus._event_history[0]
        assert oldest.data["i"] == 50

    def test_history_order_preserved(self, event_bus):
        event_bus.emit("first", {})
        event_bus.emit("second", {})
        event_bus.emit("third", {})
        types = [e.event_type for e in event_bus._event_history]
        assert types == ["first", "second", "third"]


# ──────────────────────────────────────────────────────────────
# get_recent_events()
# ──────────────────────────────────────────────────────────────

class TestGetRecentEvents:
    """Test get_recent_events() formatting, filtering, and limits."""

    def test_format_keys(self, event_bus):
        event_bus.emit("tool.result", {"tool_name": "nmap"}, source="exec")
        recent = event_bus.get_recent_events(limit=10)
        assert len(recent) == 1
        item = recent[0]
        for key in ("event_type", "source", "timestamp", "data_keys", "data_preview"):
            assert key in item
        assert item["event_type"] == "tool.result"
        assert item["source"] == "exec"
        assert "tool_name" in item["data_keys"]

    def test_limit(self, event_bus):
        for i in range(10):
            event_bus.emit("ev", {"i": i})
        recent = event_bus.get_recent_events(limit=3)
        assert len(recent) == 3
        # Should be the last 3 events
        assert recent[0]["data_preview"]["i"] == "7"
        assert recent[2]["data_preview"]["i"] == "9"

    def test_filter_by_exact_type(self, event_bus):
        event_bus.emit("tool.result", {})
        event_bus.emit("vuln.candidate", {})
        event_bus.emit("tool.error", {})
        recent = event_bus.get_recent_events(event_type="tool.result")
        assert len(recent) == 1
        assert recent[0]["event_type"] == "tool.result"

    def test_filter_by_prefix_wildcard(self, event_bus):
        event_bus.emit("tool.result", {})
        event_bus.emit("tool.error", {})
        event_bus.emit("vuln.candidate", {})
        recent = event_bus.get_recent_events(event_type="tool.*")
        assert len(recent) == 2
        event_types = {r["event_type"] for r in recent}
        assert event_types == {"tool.result", "tool.error"}

    def test_filter_by_global_wildcard(self, event_bus):
        event_bus.emit("a", {})
        event_bus.emit("b", {})
        recent = event_bus.get_recent_events(event_type="*")
        assert len(recent) == 2

    def test_filter_no_match(self, event_bus):
        event_bus.emit("tool.result", {})
        recent = event_bus.get_recent_events(event_type="vuln.*")
        assert len(recent) == 0

    def test_no_filter_returns_all(self, event_bus):
        event_bus.emit("a", {})
        event_bus.emit("b", {})
        event_bus.emit("c", {})
        recent = event_bus.get_recent_events()
        assert len(recent) == 3

    def test_data_preview_truncates_long_values(self, event_bus):
        event_bus.emit("ev", {"long_key": "x" * 500})
        recent = event_bus.get_recent_events(limit=1)
        preview = recent[0]["data_preview"]["long_key"]
        assert len(preview) <= 200

    def test_data_preview_max_5_keys(self, event_bus):
        data = {f"key_{i}": i for i in range(10)}
        event_bus.emit("ev", data)
        recent = event_bus.get_recent_events(limit=1)
        assert len(recent[0]["data_preview"]) <= 5

    def test_default_limit_is_20(self, event_bus):
        for i in range(30):
            event_bus.emit("ev", {"i": i})
        recent = event_bus.get_recent_events()
        assert len(recent) == 20


# ──────────────────────────────────────────────────────────────
# get_events_for_target()
# ──────────────────────────────────────────────────────────────

class TestGetEventsForTarget:
    """Test target-based event filtering."""

    def test_matches_exact_target(self, event_bus):
        event_bus.emit("tool.result", {"target": "192.168.1.100"})
        event_bus.emit("tool.result", {"target": "10.0.0.1"})
        results = event_bus.get_events_for_target("192.168.1.100")
        assert len(results) == 1
        assert results[0].data["target"] == "192.168.1.100"

    def test_matches_substring(self, event_bus):
        event_bus.emit("ev", {"target": "http://example.com/path"})
        results = event_bus.get_events_for_target("example.com")
        assert len(results) == 1

    def test_no_match(self, event_bus):
        event_bus.emit("ev", {"target": "192.168.1.1"})
        results = event_bus.get_events_for_target("10.0.0.1")
        assert len(results) == 0

    def test_missing_target_key(self, event_bus):
        event_bus.emit("ev", {"other_key": "value"})
        results = event_bus.get_events_for_target("anything")
        assert len(results) == 0

    def test_limit(self, event_bus):
        for i in range(10):
            event_bus.emit("ev", {"target": "host"})
        results = event_bus.get_events_for_target("host", limit=3)
        assert len(results) == 3

    def test_returns_event_objects(self, event_bus):
        event_bus.emit("ev", {"target": "host"})
        results = event_bus.get_events_for_target("host")
        assert isinstance(results[0], Event)

    def test_limit_returns_most_recent(self, event_bus):
        for i in range(10):
            event_bus.emit("ev", {"target": "host", "seq": i})
        results = event_bus.get_events_for_target("host", limit=3)
        seqs = [r.data["seq"] for r in results]
        assert seqs == [7, 8, 9]


# ──────────────────────────────────────────────────────────────
# Full integration: subscribe + emit + stats + history
# ──────────────────────────────────────────────────────────────

class TestIntegration:
    """End-to-end scenarios combining multiple features."""

    def test_full_lifecycle(self, event_bus):
        """Subscribe, emit, check stats, check history, unsubscribe, re-emit."""
        received = []
        event_bus.subscribe("tool.result", lambda e: received.append(e), "watcher")

        event_bus.emit("tool.result", {"tool": "nmap"}, source="exec")
        assert len(received) == 1

        stats = event_bus.get_stats()
        assert stats["total_events"] == 1
        assert stats["total_handled"] == 1
        assert stats["history_size"] == 1

        recent = event_bus.get_recent_events()
        assert len(recent) == 1
        assert recent[0]["event_type"] == "tool.result"

        event_bus.unsubscribe("tool.result", "watcher")
        event_bus.emit("tool.result", {"tool": "gobuster"})
        assert len(received) == 1  # handler was removed
        assert event_bus.get_stats()["total_events"] == 2
        assert event_bus.get_stats()["history_size"] == 2

    def test_mixed_patterns_and_errors(self, event_bus):
        """Wildcard + exact + error handler all interact correctly."""
        log = []
        event_bus.subscribe("*", lambda e: log.append(("wildcard", e.event_type)), "wc", priority=1)
        event_bus.subscribe("tool.result", lambda e: log.append(("exact", e.event_type)), "ex", priority=5)

        def failing(event):
            raise RuntimeError("oops")
        event_bus.subscribe("tool.*", failing, "fail", priority=3)

        event_bus.emit("tool.result", {})
        # exact(p5) runs first, then fail(p3) raises (caught), then wildcard(p1) runs
        assert log == [("exact", "tool.result"), ("wildcard", "tool.result")]

        stats = event_bus.get_stats()
        assert stats["total_handled"] == 2
        assert stats["total_errors"] == 1

    def test_emit_without_subscribers_still_tracks_stats(self, event_bus):
        event_bus.emit("orphan", {"x": 1})
        stats = event_bus.get_stats()
        assert stats["total_events"] == 1
        assert stats["total_handled"] == 0
        assert stats["history_size"] == 1


# ──────────────────────────────────────────────────────────────
# Thread safety
# ──────────────────────────────────────────────────────────────

class TestThreadSafety:
    """Verify concurrent subscribe/emit operations don't crash or corrupt."""

    def test_concurrent_subscribe_and_emit(self, event_bus):
        errors = []

        def subscribe_worker():
            try:
                for i in range(50):
                    event_bus.subscribe(f"thread.{i}", MagicMock(), f"sub_{i}")
            except Exception as e:
                errors.append(e)

        def emit_worker():
            try:
                for i in range(50):
                    event_bus.emit("thread.event", {"i": i})
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=subscribe_worker),
            threading.Thread(target=emit_worker),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Thread safety errors: {errors}"

    def test_concurrent_emit_stats_consistency(self, event_bus):
        """Emit from multiple threads — total_events should match total emits."""
        n_threads = 4
        n_per_thread = 25
        errors = []

        def emitter():
            try:
                for _ in range(n_per_thread):
                    event_bus.emit("concurrent", {})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=emitter) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0
        stats = event_bus.get_stats()
        assert stats["total_events"] == n_threads * n_per_thread


# ──────────────────────────────────────────────────────────────
# HANDLER_TIMEOUT constant sanity check
# ──────────────────────────────────────────────────────────────

class TestHandlerTimeoutConstant:
    """Verify the module-level constant is accessible and sensible."""

    def test_handler_timeout_value(self):
        assert HANDLER_TIMEOUT == 5.0
