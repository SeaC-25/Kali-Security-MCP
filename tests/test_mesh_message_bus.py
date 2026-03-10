"""
Comprehensive unit tests for kali_mcp.core.mesh_message_bus

Covers:
- MessageTypeV2 enum
- MessagePriorityV2 enum
- MessageFilter ABC and all concrete filters (Type, Sender, Content, Priority)
- RoutingTable
- MeshMessageBus (init, subscribe_with_filter, publish, publish_async,
  routing, delivery, get_next_message, stats, history, clear_history)
- MessageHandler ABC
- HeartbeatHandler
- AckHandler
- Global convenience functions: create_message, broadcast_message
- Thread safety and edge cases
"""

import asyncio
import time
import uuid
from datetime import datetime
from threading import Thread, Barrier
from unittest.mock import MagicMock, patch, call

import pytest

from kali_mcp.core.ctf_agent_framework import (
    AgentMessage,
    MessageBus,
    MessagePriority,
    MessageType,
)
from kali_mcp.core.mesh_message_bus import (
    AckHandler,
    ContentFilter,
    HeartbeatHandler,
    MeshMessageBus,
    MessageFilter,
    MessageHandler,
    MessagePriorityV2,
    MessageTypeV2,
    PriorityFilter,
    RoutingTable,
    SenderFilter,
    TypeFilter,
    broadcast_message,
    create_message,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_msg(
    sender="agent_a",
    receiver="agent_b",
    msg_type=MessageType.PURE,
    content="hello",
    priority=MessagePriority.NORMAL,
    msg_id=None,
    metadata=None,
):
    return AgentMessage(
        id=msg_id or str(uuid.uuid4()),
        type=msg_type,
        sender=sender,
        receiver=receiver,
        content=content,
        priority=priority,
        metadata=metadata or {},
    )


# ===========================================================================
# MessageTypeV2 Enum
# ===========================================================================

class TestMessageTypeV2:
    """Verify every member exists with the correct value."""

    def test_pure(self):
        assert MessageTypeV2.PURE.value == "pure"

    def test_page(self):
        assert MessageTypeV2.PAGE.value == "page"

    def test_vulnerability(self):
        assert MessageTypeV2.VULNERABILITY.value == "vulnerability"

    def test_summary(self):
        assert MessageTypeV2.SUMMARY.value == "summary"

    def test_solution(self):
        assert MessageTypeV2.SOLUTION.value == "solution"

    def test_flag(self):
        assert MessageTypeV2.FLAG.value == "flag"

    def test_task(self):
        assert MessageTypeV2.TASK.value == "task"

    def test_status(self):
        assert MessageTypeV2.STATUS.value == "status"

    def test_error(self):
        assert MessageTypeV2.ERROR.value == "error"

    def test_coordination(self):
        assert MessageTypeV2.COORDINATION.value == "coordination"

    def test_negotiation(self):
        assert MessageTypeV2.NEGOTIATION.value == "negotiation"

    def test_resource_request(self):
        assert MessageTypeV2.RESOURCE_REQUEST.value == "resource_request"

    def test_resource_offer(self):
        assert MessageTypeV2.RESOURCE_OFFER.value == "resource_offer"

    def test_status_update(self):
        assert MessageTypeV2.STATUS_UPDATE.value == "status_update"

    def test_heartbeat(self):
        assert MessageTypeV2.HEARTBEAT.value == "heartbeat"

    def test_ack(self):
        assert MessageTypeV2.ACK.value == "ack"

    def test_total_members(self):
        assert len(MessageTypeV2) == 16

    def test_lookup_by_value(self):
        assert MessageTypeV2("coordination") is MessageTypeV2.COORDINATION

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            MessageTypeV2("nonexistent")


# ===========================================================================
# MessagePriorityV2 Enum
# ===========================================================================

class TestMessagePriorityV2:

    def test_low(self):
        assert MessagePriorityV2.LOW.value == 1

    def test_normal(self):
        assert MessagePriorityV2.NORMAL.value == 2

    def test_high(self):
        assert MessagePriorityV2.HIGH.value == 3

    def test_critical(self):
        assert MessagePriorityV2.CRITICAL.value == 4

    def test_urgent(self):
        assert MessagePriorityV2.URGENT.value == 5

    def test_total_members(self):
        assert len(MessagePriorityV2) == 5

    def test_ordering(self):
        assert MessagePriorityV2.LOW.value < MessagePriorityV2.NORMAL.value
        assert MessagePriorityV2.NORMAL.value < MessagePriorityV2.HIGH.value
        assert MessagePriorityV2.HIGH.value < MessagePriorityV2.CRITICAL.value
        assert MessagePriorityV2.CRITICAL.value < MessagePriorityV2.URGENT.value

    def test_lookup_by_value(self):
        assert MessagePriorityV2(3) is MessagePriorityV2.HIGH


# ===========================================================================
# MessageFilter (ABC) check
# ===========================================================================

class TestMessageFilterABC:

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            MessageFilter()

    def test_subclass_must_implement_match(self):
        class BadFilter(MessageFilter):
            pass
        with pytest.raises(TypeError):
            BadFilter()

    def test_subclass_with_match_works(self):
        class GoodFilter(MessageFilter):
            def match(self, message):
                return True
        f = GoodFilter()
        assert f.match(_make_msg()) is True


# ===========================================================================
# TypeFilter
# ===========================================================================

class TestTypeFilter:

    def test_match_single_type(self):
        f = TypeFilter([MessageType.PURE])
        assert f.match(_make_msg(msg_type=MessageType.PURE)) is True
        assert f.match(_make_msg(msg_type=MessageType.ERROR)) is False

    def test_match_multiple_types(self):
        f = TypeFilter([MessageType.PURE, MessageType.FLAG])
        assert f.match(_make_msg(msg_type=MessageType.PURE)) is True
        assert f.match(_make_msg(msg_type=MessageType.FLAG)) is True
        assert f.match(_make_msg(msg_type=MessageType.TASK)) is False

    def test_empty_type_list(self):
        f = TypeFilter([])
        assert f.match(_make_msg()) is False

    def test_stores_types(self):
        types = [MessageType.STATUS, MessageType.ERROR]
        f = TypeFilter(types)
        assert f.message_types is types


# ===========================================================================
# SenderFilter
# ===========================================================================

class TestSenderFilter:

    def test_match_single_sender(self):
        f = SenderFilter(["agent_a"])
        assert f.match(_make_msg(sender="agent_a")) is True
        assert f.match(_make_msg(sender="agent_b")) is False

    def test_match_multiple_senders(self):
        f = SenderFilter(["a", "b", "c"])
        assert f.match(_make_msg(sender="b")) is True
        assert f.match(_make_msg(sender="d")) is False

    def test_empty_senders(self):
        f = SenderFilter([])
        assert f.match(_make_msg(sender="x")) is False


# ===========================================================================
# ContentFilter
# ===========================================================================

class TestContentFilter:

    def test_match_returns_true(self):
        f = ContentFilter(lambda m: m.content == "hello")
        assert f.match(_make_msg(content="hello")) is True

    def test_match_returns_false(self):
        f = ContentFilter(lambda m: m.content == "goodbye")
        assert f.match(_make_msg(content="hello")) is False

    def test_exception_in_func_returns_false(self):
        def bad_filter(m):
            raise ValueError("boom")
        f = ContentFilter(bad_filter)
        assert f.match(_make_msg()) is False

    def test_complex_filter(self):
        f = ContentFilter(lambda m: isinstance(m.content, dict) and "key" in m.content)
        assert f.match(_make_msg(content={"key": "val"})) is True
        assert f.match(_make_msg(content={"other": 1})) is False
        assert f.match(_make_msg(content="string")) is False


# ===========================================================================
# PriorityFilter
# ===========================================================================

class TestPriorityFilter:

    def test_match_equal_priority(self):
        f = PriorityFilter(MessagePriority.NORMAL)
        assert f.match(_make_msg(priority=MessagePriority.NORMAL)) is True

    def test_match_higher_priority(self):
        f = PriorityFilter(MessagePriority.NORMAL)
        assert f.match(_make_msg(priority=MessagePriority.HIGH)) is True

    def test_no_match_lower_priority(self):
        f = PriorityFilter(MessagePriority.HIGH)
        assert f.match(_make_msg(priority=MessagePriority.LOW)) is False

    def test_critical_threshold(self):
        f = PriorityFilter(MessagePriority.CRITICAL)
        assert f.match(_make_msg(priority=MessagePriority.CRITICAL)) is True
        assert f.match(_make_msg(priority=MessagePriority.HIGH)) is False


# ===========================================================================
# RoutingTable
# ===========================================================================

class TestRoutingTable:

    def test_init_empty(self):
        rt = RoutingTable()
        assert rt.get_routes("any") == set()

    def test_add_and_get_route(self):
        rt = RoutingTable()
        rt.add_route("a", "b")
        assert rt.get_routes("a") == {"b"}

    def test_add_multiple_routes(self):
        rt = RoutingTable()
        rt.add_route("a", "b")
        rt.add_route("a", "c")
        assert rt.get_routes("a") == {"b", "c"}

    def test_remove_route(self):
        rt = RoutingTable()
        rt.add_route("a", "b")
        rt.add_route("a", "c")
        rt.remove_route("a", "b")
        assert rt.get_routes("a") == {"c"}

    def test_remove_nonexistent_route(self):
        rt = RoutingTable()
        rt.remove_route("x", "y")  # should not raise

    def test_remove_from_existing_set_nonexistent_target(self):
        rt = RoutingTable()
        rt.add_route("a", "b")
        rt.remove_route("a", "z")  # discard, no error
        assert rt.get_routes("a") == {"b"}

    def test_can_route_to_all(self):
        rt = RoutingTable()
        assert rt.can_route("a", "all") is True

    def test_can_route_no_routes_defaults_true(self):
        rt = RoutingTable()
        assert rt.can_route("a", "b") is True

    def test_can_route_with_explicit_route(self):
        rt = RoutingTable()
        rt.add_route("a", "b")
        assert rt.can_route("a", "b") is True
        assert rt.can_route("a", "c") is False

    def test_get_routes_returns_copy(self):
        rt = RoutingTable()
        rt.add_route("a", "b")
        routes = rt.get_routes("a")
        routes.add("z")
        assert rt.get_routes("a") == {"b"}

    def test_thread_safety_add(self):
        rt = RoutingTable()
        barrier = Barrier(10)

        def add_routes(agent_id):
            barrier.wait()
            for i in range(50):
                rt.add_route(agent_id, f"target_{i}")

        threads = [Thread(target=add_routes, args=(f"agent_{t}",)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for t in range(10):
            assert len(rt.get_routes(f"agent_{t}")) == 50


# ===========================================================================
# MeshMessageBus — Init & State
# ===========================================================================

class TestMeshMessageBusInit:

    def test_isinstance_of_message_bus(self):
        bus = MeshMessageBus()
        assert isinstance(bus, MessageBus)

    def test_has_routing_table(self):
        bus = MeshMessageBus()
        assert isinstance(bus.routing_table, RoutingTable)

    def test_subscription_filters_empty(self):
        bus = MeshMessageBus()
        assert bus.subscription_filters == {}

    def test_pending_acks_empty(self):
        bus = MeshMessageBus()
        assert bus.pending_acks == {}

    def test_message_history_empty(self):
        bus = MeshMessageBus()
        assert bus.message_history == []

    def test_max_history_default(self):
        bus = MeshMessageBus()
        assert bus.max_history == 10000

    def test_priority_queues_created(self):
        bus = MeshMessageBus()
        assert MessagePriority.HIGH in bus.priority_queues
        assert MessagePriority.NORMAL in bus.priority_queues
        assert MessagePriority.LOW in bus.priority_queues

    def test_stats_initialized(self):
        bus = MeshMessageBus()
        assert bus.stats["messages_sent"] == 0
        assert bus.stats["messages_delivered"] == 0
        assert bus.stats["messages_failed"] == 0
        assert bus.stats["broadcast_count"] == 0
        assert bus.stats["direct_message_count"] == 0


# ===========================================================================
# MeshMessageBus — subscribe_with_filter
# ===========================================================================

class TestSubscribeWithFilter:

    def test_subscribe_without_filters(self):
        bus = MeshMessageBus()
        cb = MagicMock()
        bus.subscribe_with_filter("agent_a", cb)
        assert "agent_a" in bus._subscribers
        assert "agent_a" not in bus.subscription_filters

    def test_subscribe_with_filters(self):
        bus = MeshMessageBus()
        cb = MagicMock()
        filters = [TypeFilter([MessageType.FLAG])]
        bus.subscribe_with_filter("agent_a", cb, filters=filters)
        assert "agent_a" in bus._subscribers
        assert bus.subscription_filters["agent_a"] == filters

    def test_subscribe_with_empty_filter_list(self):
        bus = MeshMessageBus()
        cb = MagicMock()
        bus.subscribe_with_filter("agent_a", cb, filters=[])
        assert "agent_a" not in bus.subscription_filters

    def test_subscribe_with_none_filters(self):
        bus = MeshMessageBus()
        cb = MagicMock()
        bus.subscribe_with_filter("agent_a", cb, filters=None)
        assert "agent_a" not in bus.subscription_filters


# ===========================================================================
# MeshMessageBus — publish (direct message)
# ===========================================================================

class TestPublishDirect:

    def test_direct_message_delivered(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("agent_b", lambda m: received.append(m))
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish(msg)
        assert len(received) == 1
        assert received[0] is msg

    def test_direct_message_stats(self):
        bus = MeshMessageBus()
        bus.subscribe("agent_b", lambda m: None)
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish(msg)
        assert bus.stats["messages_sent"] == 1
        assert bus.stats["direct_message_count"] == 1
        assert bus.stats["broadcast_count"] == 0

    def test_direct_message_history(self):
        bus = MeshMessageBus()
        bus.subscribe("agent_b", lambda m: None)
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish(msg)
        assert msg in bus.message_history

    def test_message_not_delivered_to_unsubscribed(self):
        bus = MeshMessageBus()
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish(msg)
        # no error, but stats show sent
        assert bus.stats["messages_sent"] == 1
        assert bus.stats["messages_delivered"] == 0

    def test_direct_message_blocked_by_filter(self):
        bus = MeshMessageBus()
        received = []
        filters = [TypeFilter([MessageType.FLAG])]
        bus.subscribe_with_filter("agent_b", lambda m: received.append(m), filters=filters)
        msg = _make_msg(sender="agent_a", receiver="agent_b", msg_type=MessageType.PURE)
        bus.publish(msg)
        assert len(received) == 0

    def test_direct_message_passes_filter(self):
        bus = MeshMessageBus()
        received = []
        filters = [TypeFilter([MessageType.FLAG])]
        bus.subscribe_with_filter("agent_b", lambda m: received.append(m), filters=filters)
        msg = _make_msg(sender="agent_a", receiver="agent_b", msg_type=MessageType.FLAG)
        bus.publish(msg)
        assert len(received) == 1

    def test_route_blocked(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("agent_b", lambda m: received.append(m))
        # Add explicit route that excludes agent_b
        bus.routing_table.add_route("agent_a", "agent_c")
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish(msg)
        assert len(received) == 0


# ===========================================================================
# MeshMessageBus — publish (broadcast)
# ===========================================================================

class TestPublishBroadcast:

    def test_broadcast_to_all_subscribers(self):
        bus = MeshMessageBus()
        received_b = []
        received_c = []
        bus.subscribe("agent_b", lambda m: received_b.append(m))
        bus.subscribe("agent_c", lambda m: received_c.append(m))
        msg = _make_msg(sender="agent_a", receiver="all")
        bus.publish(msg)
        assert len(received_b) == 1
        assert len(received_c) == 1

    def test_broadcast_skips_sender(self):
        bus = MeshMessageBus()
        received_a = []
        received_b = []
        bus.subscribe("agent_a", lambda m: received_a.append(m))
        bus.subscribe("agent_b", lambda m: received_b.append(m))
        msg = _make_msg(sender="agent_a", receiver="all")
        bus.publish(msg)
        assert len(received_a) == 0
        assert len(received_b) == 1

    def test_broadcast_stats(self):
        bus = MeshMessageBus()
        bus.subscribe("agent_b", lambda m: None)
        msg = _make_msg(sender="agent_a", receiver="all")
        bus.publish(msg)
        assert bus.stats["broadcast_count"] == 1
        assert bus.stats["direct_message_count"] == 0

    def test_broadcast_filtered(self):
        bus = MeshMessageBus()
        received = []
        filters = [PriorityFilter(MessagePriority.HIGH)]
        bus.subscribe_with_filter("agent_b", lambda m: received.append(m), filters=filters)
        # LOW priority - should be filtered
        msg = _make_msg(sender="agent_a", receiver="all", priority=MessagePriority.LOW)
        bus.publish(msg)
        assert len(received) == 0

    def test_broadcast_no_duplicate_delivery(self):
        """Ensure a subscriber receives a broadcast exactly once even when
        subscription filters are also in place."""
        bus = MeshMessageBus()
        received = []
        filters = [TypeFilter([MessageType.PURE])]
        bus.subscribe_with_filter("agent_b", lambda m: received.append(m), filters=filters)
        msg = _make_msg(sender="agent_a", receiver="all", msg_type=MessageType.PURE)
        bus.publish(msg)
        # _route_broadcast delivers once, _route_by_subscription sees
        # already-delivered agent and skips.
        assert len(received) == 1


# ===========================================================================
# MeshMessageBus — publish_async
# ===========================================================================

class TestPublishAsync:

    def test_publish_async_delivers(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("agent_b", lambda m: received.append(m))
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish_async(msg)
        # Wait for thread pool to finish
        bus._async_executor.shutdown(wait=True)
        assert len(received) == 1


# ===========================================================================
# MeshMessageBus — history management
# ===========================================================================

class TestHistoryManagement:

    def test_history_trimmed_at_max(self):
        bus = MeshMessageBus()
        bus.max_history = 5
        for i in range(8):
            bus.publish(_make_msg(content=f"msg_{i}"))
        assert len(bus.message_history) == 5
        assert bus.message_history[0].content == "msg_3"

    def test_clear_history(self):
        bus = MeshMessageBus()
        bus.publish(_make_msg())
        bus.publish(_make_msg())
        assert len(bus.message_history) == 2
        bus.clear_history()
        assert len(bus.message_history) == 0

    def test_get_history_default(self):
        bus = MeshMessageBus()
        for i in range(5):
            bus.publish(_make_msg(content=f"msg_{i}"))
        history = bus.get_history()
        assert len(history) == 5

    def test_get_history_with_limit(self):
        bus = MeshMessageBus()
        for i in range(10):
            bus.publish(_make_msg(content=f"msg_{i}"))
        history = bus.get_history(limit=3)
        assert len(history) == 3
        # Last 3 messages
        assert history[0].content == "msg_7"

    def test_get_history_filter_by_sender(self):
        bus = MeshMessageBus()
        bus.publish(_make_msg(sender="alice"))
        bus.publish(_make_msg(sender="bob"))
        bus.publish(_make_msg(sender="alice"))
        history = bus.get_history(sender="alice")
        assert len(history) == 2
        assert all(m.sender == "alice" for m in history)

    def test_get_history_filter_by_type(self):
        bus = MeshMessageBus()
        bus.publish(_make_msg(msg_type=MessageType.FLAG))
        bus.publish(_make_msg(msg_type=MessageType.ERROR))
        bus.publish(_make_msg(msg_type=MessageType.FLAG))
        history = bus.get_history(message_type=MessageType.FLAG)
        assert len(history) == 2

    def test_get_history_filter_combined(self):
        bus = MeshMessageBus()
        bus.publish(_make_msg(sender="alice", msg_type=MessageType.FLAG))
        bus.publish(_make_msg(sender="bob", msg_type=MessageType.FLAG))
        bus.publish(_make_msg(sender="alice", msg_type=MessageType.ERROR))
        history = bus.get_history(sender="alice", message_type=MessageType.FLAG)
        assert len(history) == 1

    def test_get_history_returns_copy(self):
        bus = MeshMessageBus()
        bus.publish(_make_msg())
        h1 = bus.get_history()
        h1.clear()
        h2 = bus.get_history()
        assert len(h2) == 1


# ===========================================================================
# MeshMessageBus — get_next_message
# ===========================================================================

class TestGetNextMessage:

    def test_empty_queue_returns_none(self):
        bus = MeshMessageBus()
        assert bus.get_next_message() is None

    def test_returns_published_message(self):
        bus = MeshMessageBus()
        msg = _make_msg(priority=MessagePriority.NORMAL)
        bus.publish(msg)
        result = bus.get_next_message(priority=MessagePriority.NORMAL)
        assert result is msg

    def test_returns_none_for_wrong_priority(self):
        bus = MeshMessageBus()
        msg = _make_msg(priority=MessagePriority.HIGH)
        bus.publish(msg)
        result = bus.get_next_message(priority=MessagePriority.LOW)
        assert result is None

    def test_queue_depleted(self):
        bus = MeshMessageBus()
        msg = _make_msg(priority=MessagePriority.NORMAL)
        bus.publish(msg)
        first = bus.get_next_message(priority=MessagePriority.NORMAL)
        assert first is msg
        second = bus.get_next_message(priority=MessagePriority.NORMAL)
        assert second is None

    def test_fallback_priority_queue(self):
        """Message with CRITICAL priority (not in priority_queues keys)
        should fall back to NORMAL queue."""
        bus = MeshMessageBus()
        msg = _make_msg(priority=MessagePriority.CRITICAL)
        bus.publish(msg)
        result = bus.get_next_message(priority=MessagePriority.NORMAL)
        assert result is msg


# ===========================================================================
# MeshMessageBus — get_next_message_async
# ===========================================================================

class TestGetNextMessageAsync:

    @pytest.mark.asyncio
    async def test_empty_queue_returns_none(self):
        bus = MeshMessageBus()
        result = await bus.get_next_message_async()
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_message(self):
        bus = MeshMessageBus()
        msg = _make_msg(priority=MessagePriority.NORMAL)
        bus.publish(msg)
        result = await bus.get_next_message_async(priority=MessagePriority.NORMAL)
        assert result is msg

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        bus = MeshMessageBus()
        result = await bus.get_next_message_async(
            priority=MessagePriority.NORMAL, timeout=0.01
        )
        assert result is None


# ===========================================================================
# MeshMessageBus — get_stats
# ===========================================================================

class TestGetStats:

    def test_stats_keys(self):
        bus = MeshMessageBus()
        stats = bus.get_stats()
        assert "messages_sent" in stats
        assert "messages_delivered" in stats
        assert "messages_failed" in stats
        assert "broadcast_count" in stats
        assert "direct_message_count" in stats
        assert "queue_sizes" in stats
        assert "subscriber_count" in stats
        assert "filter_count" in stats

    def test_subscriber_count(self):
        bus = MeshMessageBus()
        bus.subscribe("a", lambda m: None)
        bus.subscribe("b", lambda m: None)
        assert bus.get_stats()["subscriber_count"] == 2

    def test_filter_count(self):
        bus = MeshMessageBus()
        bus.subscribe_with_filter(
            "a", lambda m: None, filters=[TypeFilter([MessageType.PURE])]
        )
        assert bus.get_stats()["filter_count"] == 1

    def test_queue_sizes_after_publish(self):
        bus = MeshMessageBus()
        bus.publish(_make_msg(priority=MessagePriority.HIGH))
        stats = bus.get_stats()
        assert stats["queue_sizes"]["HIGH"] == 1
        assert stats["queue_sizes"]["NORMAL"] == 0


# ===========================================================================
# MeshMessageBus — delivery failures
# ===========================================================================

class TestDeliveryFailures:

    def test_callback_exception_increments_failed(self):
        bus = MeshMessageBus()

        def bad_callback(m):
            raise RuntimeError("oops")

        bus.subscribe("agent_b", bad_callback)
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish(msg)
        assert bus.stats["messages_failed"] >= 1

    def test_deliver_to_unsubscribed_agent_no_crash(self):
        bus = MeshMessageBus()
        # Call internal method directly
        bus._deliver_to_subscriber("nonexistent", _make_msg())
        # Should not raise

    def test_publish_exception_logged_and_failed(self):
        bus = MeshMessageBus()
        # Corrupt priority_queues to force exception
        bus.priority_queues = None
        msg = _make_msg()
        bus.publish(msg)  # Should not raise
        assert bus.stats["messages_failed"] == 1


# ===========================================================================
# MeshMessageBus — _route_direct
# ===========================================================================

class TestRouteDirect:

    def test_route_direct_returns_receiver(self):
        bus = MeshMessageBus()
        bus.subscribe("b", lambda m: None)
        msg = _make_msg(sender="a", receiver="b")
        result = bus._route_direct(msg)
        assert result == "b"

    def test_route_direct_returns_none_if_already_delivered(self):
        bus = MeshMessageBus()
        bus.subscribe("b", lambda m: None)
        msg = _make_msg(sender="a", receiver="b")
        result = bus._route_direct(msg, delivered_agents={"b"})
        assert result is None

    def test_route_direct_route_not_allowed(self):
        bus = MeshMessageBus()
        bus.subscribe("b", lambda m: None)
        bus.routing_table.add_route("a", "c")  # only c allowed
        msg = _make_msg(sender="a", receiver="b")
        result = bus._route_direct(msg)
        assert result is None

    def test_route_direct_filter_blocks(self):
        bus = MeshMessageBus()
        bus.subscribe("b", lambda m: None)
        bus.subscription_filters["b"] = [TypeFilter([MessageType.FLAG])]
        msg = _make_msg(sender="a", receiver="b", msg_type=MessageType.PURE)
        result = bus._route_direct(msg)
        assert result is None


# ===========================================================================
# MeshMessageBus — _route_broadcast
# ===========================================================================

class TestRouteBroadcast:

    def test_broadcast_skips_sender(self):
        bus = MeshMessageBus()
        received_a = []
        received_b = []
        bus.subscribe("a", lambda m: received_a.append(m))
        bus.subscribe("b", lambda m: received_b.append(m))
        msg = _make_msg(sender="a", receiver="all")
        bus._route_broadcast(msg)
        assert len(received_a) == 0
        assert len(received_b) == 1

    def test_broadcast_skips_already_delivered(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("b", lambda m: received.append(m))
        msg = _make_msg(sender="a", receiver="all")
        bus._route_broadcast(msg, delivered_agents={"b"})
        assert len(received) == 0

    def test_broadcast_respects_filter(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("b", lambda m: received.append(m))
        bus.subscription_filters["b"] = [SenderFilter(["c"])]
        msg = _make_msg(sender="a", receiver="all")
        bus._route_broadcast(msg)
        assert len(received) == 0


# ===========================================================================
# MeshMessageBus — _route_by_subscription
# ===========================================================================

class TestRouteBySubscription:

    def test_subscription_route_delivers(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("b", lambda m: received.append(m))
        bus.subscription_filters["b"] = [TypeFilter([MessageType.PURE])]
        msg = _make_msg(sender="a", receiver="all", msg_type=MessageType.PURE)
        bus._route_by_subscription(msg)
        assert len(received) == 1

    def test_subscription_route_skips_sender(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("a", lambda m: received.append(m))
        bus.subscription_filters["a"] = [TypeFilter([MessageType.PURE])]
        msg = _make_msg(sender="a", receiver="all", msg_type=MessageType.PURE)
        bus._route_by_subscription(msg)
        assert len(received) == 0

    def test_subscription_route_skips_delivered(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("b", lambda m: received.append(m))
        bus.subscription_filters["b"] = [TypeFilter([MessageType.PURE])]
        msg = _make_msg(sender="a", receiver="all", msg_type=MessageType.PURE)
        bus._route_by_subscription(msg, delivered_agents={"b"})
        assert len(received) == 0

    def test_subscription_route_filter_no_match(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("b", lambda m: received.append(m))
        bus.subscription_filters["b"] = [TypeFilter([MessageType.FLAG])]
        msg = _make_msg(sender="a", receiver="all", msg_type=MessageType.PURE)
        bus._route_by_subscription(msg)
        assert len(received) == 0


# ===========================================================================
# MeshMessageBus — _route_message integration
# ===========================================================================

class TestRouteMessage:

    def test_route_message_exception_does_not_propagate(self):
        bus = MeshMessageBus()
        # Force an exception in routing by making routing_table.can_route fail
        bus.routing_table.can_route = MagicMock(side_effect=RuntimeError("fail"))
        msg = _make_msg(sender="a", receiver="b")
        bus._route_message(msg)  # should not raise


# ===========================================================================
# MeshMessageBus — multiple callbacks
# ===========================================================================

class TestMultipleCallbacks:

    def test_multiple_callbacks_same_agent(self):
        bus = MeshMessageBus()
        results_1 = []
        results_2 = []
        bus.subscribe("agent_b", lambda m: results_1.append(m))
        bus.subscribe("agent_b", lambda m: results_2.append(m))
        msg = _make_msg(sender="agent_a", receiver="agent_b")
        bus.publish(msg)
        assert len(results_1) == 1
        assert len(results_2) == 1
        assert bus.stats["messages_delivered"] == 2


# ===========================================================================
# MessageHandler (ABC)
# ===========================================================================

class TestMessageHandlerABC:

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            MessageHandler()

    def test_subclass_must_implement_handle(self):
        class Bad(MessageHandler):
            pass
        with pytest.raises(TypeError):
            Bad()


# ===========================================================================
# HeartbeatHandler
# ===========================================================================

class TestHeartbeatHandler:

    def test_init(self):
        h = HeartbeatHandler("agent_x")
        assert h.agent_id == "agent_x"
        assert h.last_heartbeat <= time.time()

    @pytest.mark.asyncio
    async def test_handles_heartbeat(self):
        h = HeartbeatHandler("agent_x")
        old_hb = h.last_heartbeat
        time.sleep(0.01)
        msg = _make_msg(
            sender="agent_y",
            receiver="agent_x",
            msg_type=MessageTypeV2.HEARTBEAT,
        )
        response = await h.handle(msg)
        assert response is not None
        assert response.sender == "agent_x"
        assert response.receiver == "agent_y"
        assert response.type == MessageTypeV2.STATUS_UPDATE
        assert response.content["status"] == "alive"
        assert h.last_heartbeat > old_hb

    @pytest.mark.asyncio
    async def test_ignores_non_heartbeat(self):
        h = HeartbeatHandler("agent_x")
        msg = _make_msg(msg_type=MessageType.PURE)
        response = await h.handle(msg)
        assert response is None

    @pytest.mark.asyncio
    async def test_response_priority_is_low(self):
        h = HeartbeatHandler("agent_x")
        msg = _make_msg(
            sender="agent_y",
            receiver="agent_x",
            msg_type=MessageTypeV2.HEARTBEAT,
        )
        response = await h.handle(msg)
        assert response.priority == MessagePriority.LOW


# ===========================================================================
# AckHandler
# ===========================================================================

class TestAckHandler:

    def test_init(self):
        h = AckHandler()
        assert h.pending_messages == {}

    @pytest.mark.asyncio
    async def test_handles_ack_message(self):
        h = AckHandler()
        msg = _make_msg(msg_type=MessageTypeV2.ACK, msg_id="test_id")
        # The handler has a bug (uses `id` instead of `message.id`),
        # but we verify it does not crash.
        response = await h.handle(msg)
        assert response is None

    @pytest.mark.asyncio
    async def test_ignores_non_ack(self):
        h = AckHandler()
        msg = _make_msg(msg_type=MessageType.PURE)
        response = await h.handle(msg)
        assert response is None

    @pytest.mark.asyncio
    async def test_ack_removes_from_pending_bug(self):
        """The source code has a bug: `del self.pending_messages[id]` uses the
        builtin `id` function instead of `message.id`. When the message id IS
        found in pending_messages, the delete uses the wrong key and raises
        KeyError.  We verify this known bug behaviour."""
        h = AckHandler()
        pending_msg = _make_msg(msg_id="pending_1")
        h.pending_messages["pending_1"] = pending_msg

        ack_msg = _make_msg(msg_type=MessageTypeV2.ACK, msg_id="pending_1")
        # Because the code does `del self.pending_messages[id]` (builtin id()),
        # and builtin id() is not a key, it raises KeyError.
        with pytest.raises(KeyError):
            await h.handle(ack_msg)

    @pytest.mark.asyncio
    async def test_ack_message_not_in_pending(self):
        """When ACK message id is NOT in pending_messages, no deletion is
        attempted, so the handler returns None cleanly."""
        h = AckHandler()
        ack_msg = _make_msg(msg_type=MessageTypeV2.ACK, msg_id="unknown_id")
        response = await h.handle(ack_msg)
        assert response is None


# ===========================================================================
# create_message (convenience function)
# ===========================================================================

class TestCreateMessage:

    def test_basic_creation(self):
        msg = create_message(
            msg_type=MessageType.PURE,
            sender="alice",
            receiver="bob",
            content="hello",
        )
        assert msg.type == MessageType.PURE
        assert msg.sender == "alice"
        assert msg.receiver == "bob"
        assert msg.content == "hello"
        assert msg.priority == MessagePriority.NORMAL
        assert len(msg.id) > 0

    def test_with_priority(self):
        msg = create_message(
            msg_type=MessageType.FLAG,
            sender="s",
            receiver="r",
            content={},
            priority=MessagePriority.HIGH,
        )
        assert msg.priority == MessagePriority.HIGH

    def test_with_correlation_id(self):
        msg = create_message(
            msg_type=MessageType.TASK,
            sender="s",
            receiver="r",
            content="x",
            correlation_id="corr-123",
        )
        assert msg.metadata["correlation_id"] == "corr-123"

    def test_without_correlation_id(self):
        msg = create_message(
            msg_type=MessageType.TASK,
            sender="s",
            receiver="r",
            content="x",
        )
        assert "correlation_id" not in msg.metadata

    def test_requires_ack(self):
        msg = create_message(
            msg_type=MessageType.TASK,
            sender="s",
            receiver="r",
            content="x",
            requires_ack=True,
        )
        assert msg.metadata["requires_ack"] is True

    def test_no_requires_ack(self):
        msg = create_message(
            msg_type=MessageType.TASK,
            sender="s",
            receiver="r",
            content="x",
            requires_ack=False,
        )
        assert "requires_ack" not in msg.metadata

    def test_both_metadata_fields(self):
        msg = create_message(
            msg_type=MessageType.TASK,
            sender="s",
            receiver="r",
            content="x",
            correlation_id="c1",
            requires_ack=True,
        )
        assert msg.metadata["correlation_id"] == "c1"
        assert msg.metadata["requires_ack"] is True

    def test_unique_ids(self):
        ids = set()
        for _ in range(100):
            msg = create_message(
                msg_type=MessageType.PURE,
                sender="s",
                receiver="r",
                content="",
            )
            ids.add(msg.id)
        assert len(ids) == 100

    def test_content_any_type(self):
        msg = create_message(
            msg_type=MessageType.PURE,
            sender="s",
            receiver="r",
            content=[1, 2, 3],
        )
        assert msg.content == [1, 2, 3]


# ===========================================================================
# broadcast_message (convenience function)
# ===========================================================================

class TestBroadcastMessage:

    def test_receiver_is_all(self):
        msg = broadcast_message(
            msg_type=MessageType.STATUS,
            sender="agent_a",
            content="status update",
        )
        assert msg.receiver == "all"

    def test_default_priority(self):
        msg = broadcast_message(
            msg_type=MessageType.STATUS,
            sender="a",
            content="",
        )
        assert msg.priority == MessagePriority.NORMAL

    def test_custom_priority(self):
        msg = broadcast_message(
            msg_type=MessageType.FLAG,
            sender="a",
            content="found",
            priority=MessagePriority.HIGH,
        )
        assert msg.priority == MessagePriority.HIGH

    def test_type_preserved(self):
        msg = broadcast_message(
            msg_type=MessageType.VULNERABILITY,
            sender="scanner",
            content={"vuln": "sqli"},
        )
        assert msg.type == MessageType.VULNERABILITY


# ===========================================================================
# AgentMessage dataclass checks (from base framework, used extensively here)
# ===========================================================================

class TestAgentMessageDataclass:

    def test_default_priority(self):
        msg = AgentMessage(
            id="1", type=MessageType.PURE, sender="a", receiver="b", content=""
        )
        assert msg.priority == MessagePriority.NORMAL

    def test_default_metadata_is_dict(self):
        msg = AgentMessage(
            id="1", type=MessageType.PURE, sender="a", receiver="b", content=""
        )
        assert isinstance(msg.metadata, dict)
        assert len(msg.metadata) == 0

    def test_metadata_isolation(self):
        m1 = AgentMessage(
            id="1", type=MessageType.PURE, sender="a", receiver="b", content=""
        )
        m2 = AgentMessage(
            id="2", type=MessageType.PURE, sender="a", receiver="b", content=""
        )
        m1.metadata["key"] = "val"
        assert "key" not in m2.metadata

    def test_timestamp_auto(self):
        msg = AgentMessage(
            id="1", type=MessageType.PURE, sender="a", receiver="b", content=""
        )
        assert msg.timestamp is not None
        # Should parse as ISO format
        datetime.fromisoformat(msg.timestamp)

    def test_to_dict(self):
        msg = AgentMessage(
            id="42",
            type=MessageType.FLAG,
            sender="s",
            receiver="r",
            content={"flag": "found"},
            priority=MessagePriority.HIGH,
        )
        d = msg.to_dict()
        assert d["id"] == "42"
        assert d["type"] == "flag"
        assert d["sender"] == "s"
        assert d["receiver"] == "r"
        assert d["content"] == {"flag": "found"}
        assert d["priority"] == 3


# ===========================================================================
# Thread safety of MeshMessageBus
# ===========================================================================

class TestMeshBusThreadSafety:

    def test_concurrent_publish(self):
        bus = MeshMessageBus()
        received = []
        bus.subscribe("b", lambda m: received.append(m))
        barrier = Barrier(5)

        def publisher(i):
            barrier.wait()
            for j in range(20):
                bus.publish(_make_msg(sender=f"a_{i}", receiver="b", content=f"{i}_{j}"))

        threads = [Thread(target=publisher, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert bus.stats["messages_sent"] == 100
        assert len(bus.message_history) == 100

    def test_concurrent_subscribe_and_publish(self):
        bus = MeshMessageBus()
        barrier = Barrier(6)

        def subscriber(i):
            barrier.wait()
            bus.subscribe(f"sub_{i}", lambda m: None)

        def publisher():
            barrier.wait()
            for j in range(20):
                bus.publish(_make_msg(sender="pub", receiver="all"))

        threads = [Thread(target=subscriber, args=(i,)) for i in range(5)]
        threads.append(Thread(target=publisher))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # No crash is success

    def test_concurrent_clear_history(self):
        bus = MeshMessageBus()
        barrier = Barrier(3)

        def publisher():
            barrier.wait()
            for _ in range(50):
                bus.publish(_make_msg())

        def clearer():
            barrier.wait()
            for _ in range(10):
                bus.clear_history()
                time.sleep(0.001)

        t1 = Thread(target=publisher)
        t2 = Thread(target=publisher)
        t3 = Thread(target=clearer)
        for t in [t1, t2, t3]:
            t.start()
        for t in [t1, t2, t3]:
            t.join()
        # No crash is success


# ===========================================================================
# Edge cases and misc
# ===========================================================================

class TestEdgeCases:

    def test_publish_with_none_content(self):
        bus = MeshMessageBus()
        msg = _make_msg(content=None)
        bus.publish(msg)
        assert bus.message_history[-1].content is None

    def test_publish_with_empty_string_receiver(self):
        bus = MeshMessageBus()
        msg = _make_msg(receiver="")
        bus.publish(msg)
        assert bus.stats["messages_sent"] == 1

    def test_publish_with_complex_content(self):
        bus = MeshMessageBus()
        complex_content = {
            "nested": {"list": [1, 2, 3], "dict": {"a": True}},
            "tuple": (1, 2),
        }
        msg = _make_msg(content=complex_content)
        bus.publish(msg)
        assert bus.message_history[-1].content is complex_content

    def test_unsubscribe_clears_subscriber(self):
        bus = MeshMessageBus()
        bus.subscribe("agent_a", lambda m: None)
        assert "agent_a" in bus._subscribers
        bus.unsubscribe("agent_a")
        assert "agent_a" not in bus._subscribers

    def test_unsubscribe_nonexistent_no_crash(self):
        bus = MeshMessageBus()
        bus.unsubscribe("nonexistent")

    def test_many_priority_levels_in_messages(self):
        bus = MeshMessageBus()
        for p in MessagePriority:
            bus.publish(_make_msg(priority=p))
        assert bus.stats["messages_sent"] == len(MessagePriority)

    def test_message_with_metadata(self):
        msg = _make_msg(metadata={"custom": "value"})
        assert msg.metadata["custom"] == "value"

    def test_filter_with_multiple_filters(self):
        bus = MeshMessageBus()
        received = []
        filters = [
            TypeFilter([MessageType.FLAG]),
            SenderFilter(["scanner"]),
        ]
        bus.subscribe_with_filter("target", lambda m: received.append(m), filters=filters)
        # Both match
        bus.publish(_make_msg(sender="scanner", receiver="target", msg_type=MessageType.FLAG))
        assert len(received) == 1
        # Only type matches
        bus.publish(_make_msg(sender="other", receiver="target", msg_type=MessageType.FLAG))
        assert len(received) == 1
        # Only sender matches
        bus.publish(_make_msg(sender="scanner", receiver="target", msg_type=MessageType.PURE))
        assert len(received) == 1

    def test_publish_increments_delivered_per_callback(self):
        bus = MeshMessageBus()
        bus.subscribe("b", lambda m: None)
        bus.subscribe("b", lambda m: None)  # second callback
        msg = _make_msg(sender="a", receiver="b")
        bus.publish(msg)
        # Two callbacks -> 2 delivered
        assert bus.stats["messages_delivered"] == 2
