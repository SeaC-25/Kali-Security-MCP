"""
Tests for EventBus (kali_mcp/core/event_bus.py)

Covers:
- Subscribe and emit
- Pattern matching (exact, wildcard, prefix)
- Priority ordering
- Handler timeout and error handling
- Event history management
- Unsubscribe
- Statistics tracking
- Thread safety
"""

import time
import threading
from unittest.mock import MagicMock, patch

import pytest

from kali_mcp.core.event_bus import EventBus, Event, Subscription


class TestSubscribeAndEmit:
    """Test basic subscribe/emit flow."""

    def test_subscribe_and_emit(self, event_bus):
        """Subscribe handler, emit event, verify handler called with correct Event."""
        handler = MagicMock()
        event_bus.subscribe("tool.result", handler, "test_sub")

        event_bus.emit("tool.result", {"tool_name": "nmap", "target": "10.0.0.1"}, source="test")

        handler.assert_called_once()
        event = handler.call_args[0][0]
        assert isinstance(event, Event)
        assert event.event_type == "tool.result"
        assert event.data["tool_name"] == "nmap"
        assert event.source == "test"

    def test_multiple_handlers(self, event_bus):
        """Multiple handlers for same event all get called."""
        h1 = MagicMock()
        h2 = MagicMock()
        event_bus.subscribe("tool.result", h1, "sub1")
        event_bus.subscribe("tool.result", h2, "sub2")

        event_bus.emit("tool.result", {"data": 1})

        h1.assert_called_once()
        h2.assert_called_once()

    def test_no_handler_no_crash(self, event_bus):
        """Emitting event with no subscribers does not crash."""
        event_bus.emit("unknown.event", {"data": "test"})


class TestPatternMatching:
    """Test event pattern matching logic."""

    def test_exact_match(self, event_bus):
        """Exact pattern 'tool.result' matches only 'tool.result'."""
        handler = MagicMock()
        event_bus.subscribe("tool.result", handler, "exact_sub")

        event_bus.emit("tool.result", {"match": True})
        event_bus.emit("tool.error", {"match": False})
        event_bus.emit("vuln.candidate", {"match": False})

        assert handler.call_count == 1

    def test_prefix_wildcard_match(self, event_bus):
        """Pattern 'tool.*' matches 'tool.result' and 'tool.error' but not 'vuln.candidate'."""
        handler = MagicMock()
        event_bus.subscribe("tool.*", handler, "wildcard_sub")

        event_bus.emit("tool.result", {})
        event_bus.emit("tool.error", {})
        event_bus.emit("vuln.candidate", {})

        assert handler.call_count == 2

    def test_global_wildcard_match(self, event_bus):
        """Pattern '*' matches every event type."""
        handler = MagicMock()
        event_bus.subscribe("*", handler, "global_sub")

        event_bus.emit("tool.result", {})
        event_bus.emit("vuln.candidate", {})
        event_bus.emit("custom.event", {})

        assert handler.call_count == 3

    def test_pattern_no_match(self, event_bus):
        """'vuln.*' does not match 'tool.result'."""
        handler = MagicMock()
        event_bus.subscribe("vuln.*", handler, "vuln_sub")

        event_bus.emit("tool.result", {})

        handler.assert_not_called()

    def test_static_pattern_matches(self):
        """Test the static _pattern_matches method directly."""
        assert EventBus._pattern_matches("*", "anything") is True
        assert EventBus._pattern_matches("tool.result", "tool.result") is True
        assert EventBus._pattern_matches("tool.result", "tool.error") is False
        assert EventBus._pattern_matches("tool.*", "tool.result") is True
        assert EventBus._pattern_matches("tool.*", "tool.error") is True
        assert EventBus._pattern_matches("tool.*", "vuln.candidate") is False
        assert EventBus._pattern_matches("tool.*", "tool") is False  # no dot after prefix


class TestPriorityOrdering:
    """Test handler priority execution order."""

    def test_priority_ordering(self, event_bus):
        """Higher priority handlers execute first."""
        call_order = []

        def low_handler(event):
            call_order.append("low")

        def high_handler(event):
            call_order.append("high")

        def medium_handler(event):
            call_order.append("medium")

        event_bus.subscribe("test.event", low_handler, "low_sub", priority=1)
        event_bus.subscribe("test.event", high_handler, "high_sub", priority=10)
        event_bus.subscribe("test.event", medium_handler, "med_sub", priority=5)

        event_bus.emit("test.event", {})

        assert call_order == ["high", "medium", "low"]


class TestHandlerErrorHandling:
    """Test handler timeout and error resilience."""

    def test_handler_error_does_not_crash_bus(self, event_bus):
        """Exception in handler doesn't prevent other handlers or crash the bus."""
        def bad_handler(event):
            raise ValueError("handler exploded")

        good_handler = MagicMock()

        event_bus.subscribe("test.event", bad_handler, "bad_sub", priority=10)
        event_bus.subscribe("test.event", good_handler, "good_sub", priority=1)

        # Should not raise
        event_bus.emit("test.event", {})

        # The good handler should still be called
        good_handler.assert_called_once()

    def test_handler_error_increments_stats(self, event_bus):
        """Handler errors are tracked in stats."""
        def bad_handler(event):
            raise RuntimeError("boom")

        event_bus.subscribe("test.event", bad_handler, "bad_sub")
        event_bus.emit("test.event", {})

        stats = event_bus.get_stats()
        assert stats["total_errors"] >= 1

    def test_handler_timeout_tracked(self, event_bus):
        """Handler that exceeds timeout produces a timeout in stats."""
        def slow_handler(event):
            time.sleep(10)  # Much longer than 5s timeout

        event_bus.subscribe("test.event", slow_handler, "slow_sub")

        # Patch HANDLER_TIMEOUT to a very small value for fast testing
        with patch("kali_mcp.core.event_bus.HANDLER_TIMEOUT", 0.1):
            event_bus.emit("test.event", {})

        stats = event_bus.get_stats()
        assert stats["total_timeouts"] >= 1


class TestEventHistory:
    """Test event history management."""

    def test_events_stored_in_history(self, event_bus):
        """Emitted events are stored in history."""
        event_bus.emit("e1", {"data": 1})
        event_bus.emit("e2", {"data": 2})

        stats = event_bus.get_stats()
        assert stats["history_size"] == 2

    def test_history_max_500(self, event_bus):
        """History is capped at 500 events."""
        for i in range(600):
            event_bus.emit("bulk.event", {"i": i})

        stats = event_bus.get_stats()
        assert stats["history_size"] == 500

    def test_get_recent_events_format(self, event_bus):
        """get_recent_events returns correctly formatted dicts."""
        event_bus.emit("tool.result", {"tool_name": "nmap"}, source="executor")

        recent = event_bus.get_recent_events(limit=10)
        assert len(recent) == 1
        item = recent[0]
        assert "event_type" in item
        assert "source" in item
        assert "timestamp" in item
        assert "data_keys" in item
        assert "data_preview" in item
        assert item["event_type"] == "tool.result"
        assert item["source"] == "executor"

    def test_get_recent_events_filtered(self, event_bus):
        """get_recent_events can filter by event_type pattern."""
        event_bus.emit("tool.result", {})
        event_bus.emit("vuln.candidate", {})
        event_bus.emit("tool.error", {})

        tool_events = event_bus.get_recent_events(event_type="tool.*", limit=10)
        # Should match tool.result and tool.error (pattern applied with _pattern_matches)
        # Note: get_recent_events uses _pattern_matches(event_type, e.event_type) with
        # event_type as pattern — so "tool.*" matches both tool.result and tool.error
        assert len(tool_events) == 2


class TestUnsubscribe:
    """Test unsubscription."""

    def test_unsubscribe_removes_handler(self, event_bus):
        """After unsubscribe, handler is no longer called."""
        handler = MagicMock()
        event_bus.subscribe("test.event", handler, "my_sub")

        # First emission should call it
        event_bus.emit("test.event", {})
        assert handler.call_count == 1

        # Unsubscribe
        event_bus.unsubscribe("test.event", "my_sub")

        # Second emission should NOT call it
        event_bus.emit("test.event", {})
        assert handler.call_count == 1

    def test_unsubscribe_nonexistent_pattern(self, event_bus):
        """Unsubscribing from non-existent pattern does not crash."""
        event_bus.unsubscribe("nonexistent.pattern", "nobody")


class TestGetStats:
    """Test statistics tracking."""

    def test_get_stats_structure(self, event_bus):
        """Stats dictionary has expected keys."""
        stats = event_bus.get_stats()
        assert "total_events" in stats
        assert "total_handled" in stats
        assert "total_errors" in stats
        assert "total_timeouts" in stats
        assert "by_type" in stats
        assert "subscriber_count" in stats
        assert "history_size" in stats

    def test_stats_track_emitted_and_handled(self, event_bus):
        """Stats correctly track emitted and handled counts."""
        handler = MagicMock()
        event_bus.subscribe("test.event", handler, "sub1")

        event_bus.emit("test.event", {})
        event_bus.emit("test.event", {})

        stats = event_bus.get_stats()
        assert stats["total_events"] == 2
        assert stats["total_handled"] == 2

    def test_stats_subscriber_count(self, event_bus):
        """Stats report correct subscriber count."""
        event_bus.subscribe("a", MagicMock(), "s1")
        event_bus.subscribe("b", MagicMock(), "s2")
        event_bus.subscribe("a", MagicMock(), "s3")

        stats = event_bus.get_stats()
        assert stats["subscriber_count"] == 3


class TestThreadSafety:
    """Test concurrent operations don't crash."""

    def test_concurrent_subscribe_emit(self, event_bus):
        """Concurrent subscribe and emit operations don't crash."""
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

        t1 = threading.Thread(target=subscribe_worker)
        t2 = threading.Thread(target=emit_worker)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert len(errors) == 0, f"Thread safety errors: {errors}"
