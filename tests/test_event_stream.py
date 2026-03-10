"""
Comprehensive tests for EventStream (kali_mcp/core/event_stream.py)

Covers:
- EventType(str, Enum): all 37 event types across 8 categories
- EventData dataclass: construction, to_dict() sparse serialization
- StreamEvent dataclass: construction, to_dict(), to_sse() SSE format
- EventEmitter class: emit, emit_sync, all emit_* helper methods
  - Phase events, thinking/ReAct events, tool events (with duration tracking),
    finding events, attack chain events, status events, task events
  - Thought truncation at 500 chars, observation truncation at 1000 chars
  - Tool duration calculation via _tool_start_times
  - Sequence counter increment on every emit
- EventManager class:
  - add_event() / add_event_sync(): UUID generation, history storage,
    cap at max_history=1000, queue push, callback dispatch
  - create_queue() / remove_queue(): queue management
  - add_callback() / remove_callback(): callback system
  - get_events(): filtering by after_sequence and limit
  - clear_session(): full cleanup
  - get_stats(): statistics dict
  - create_emitter(): factory method
  - stream_events(): async generator (history replay, live events, heartbeat)
- Global functions: get_event_manager() singleton, create_emitter(session_id)

Target: 140+ tests. Pure unit tests, pytest style.
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kali_mcp.core.event_stream import (
    EventType,
    EventData,
    StreamEvent,
    EventEmitter,
    EventManager,
    get_event_manager,
    create_emitter,
    _global_event_manager,
)


# ═══════════════════════════════════════════════════════════════
# EventType Enum
# ═══════════════════════════════════════════════════════════════

class TestEventType:
    """Verify EventType enum: membership, str subclass, categories."""

    # --- Phase events (3) ---

    def test_phase_start(self):
        assert EventType.PHASE_START.value == "phase_start"

    def test_phase_complete(self):
        assert EventType.PHASE_COMPLETE.value == "phase_complete"

    def test_phase_error(self):
        assert EventType.PHASE_ERROR.value == "phase_error"

    # --- Thinking / ReAct events (7) ---

    def test_thinking_start(self):
        assert EventType.THINKING_START.value == "thinking_start"

    def test_thinking_token(self):
        assert EventType.THINKING_TOKEN.value == "thinking_token"

    def test_thinking_end(self):
        assert EventType.THINKING_END.value == "thinking_end"

    def test_thought(self):
        assert EventType.THOUGHT.value == "thought"

    def test_action(self):
        assert EventType.ACTION.value == "action"

    def test_observation(self):
        assert EventType.OBSERVATION.value == "observation"

    def test_decision(self):
        assert EventType.DECISION.value == "decision"

    # --- Tool events (7) ---

    def test_tool_call(self):
        assert EventType.TOOL_CALL.value == "tool_call"

    def test_tool_start(self):
        assert EventType.TOOL_START.value == "tool_start"

    def test_tool_progress(self):
        assert EventType.TOOL_PROGRESS.value == "tool_progress"

    def test_tool_output(self):
        assert EventType.TOOL_OUTPUT.value == "tool_output"

    def test_tool_result(self):
        assert EventType.TOOL_RESULT.value == "tool_result"

    def test_tool_error(self):
        assert EventType.TOOL_ERROR.value == "tool_error"

    def test_tool_complete(self):
        assert EventType.TOOL_COMPLETE.value == "tool_complete"

    # --- Finding events (5) ---

    def test_finding_new(self):
        assert EventType.FINDING_NEW.value == "finding_new"

    def test_finding_verified(self):
        assert EventType.FINDING_VERIFIED.value == "finding_verified"

    def test_vulnerability(self):
        assert EventType.VULNERABILITY.value == "vulnerability"

    def test_flag_found(self):
        assert EventType.FLAG_FOUND.value == "flag_found"

    def test_credential_found(self):
        assert EventType.CREDENTIAL_FOUND.value == "credential_found"

    # --- Attack events (5) ---

    def test_attack_start(self):
        assert EventType.ATTACK_START.value == "attack_start"

    def test_attack_progress(self):
        assert EventType.ATTACK_PROGRESS.value == "attack_progress"

    def test_attack_success(self):
        assert EventType.ATTACK_SUCCESS.value == "attack_success"

    def test_attack_failed(self):
        assert EventType.ATTACK_FAILED.value == "attack_failed"

    def test_attack_complete(self):
        assert EventType.ATTACK_COMPLETE.value == "attack_complete"

    # --- Session events (3) ---

    def test_session_start(self):
        assert EventType.SESSION_START.value == "session_start"

    def test_session_update(self):
        assert EventType.SESSION_UPDATE.value == "session_update"

    def test_session_end(self):
        assert EventType.SESSION_END.value == "session_end"

    # --- Status events (5) ---

    def test_progress(self):
        assert EventType.PROGRESS.value == "progress"

    def test_info(self):
        assert EventType.INFO.value == "info"

    def test_warning(self):
        assert EventType.WARNING.value == "warning"

    def test_error(self):
        assert EventType.ERROR.value == "error"

    def test_debug(self):
        assert EventType.DEBUG.value == "debug"

    # --- Task events (4) ---

    def test_task_start(self):
        assert EventType.TASK_START.value == "task_start"

    def test_task_complete(self):
        assert EventType.TASK_COMPLETE.value == "task_complete"

    def test_task_error(self):
        assert EventType.TASK_ERROR.value == "task_error"

    def test_task_cancel(self):
        assert EventType.TASK_CANCEL.value == "task_cancel"

    # --- Heartbeat (1) ---

    def test_heartbeat(self):
        assert EventType.HEARTBEAT.value == "heartbeat"

    # --- Total count ---

    def test_total_event_count(self):
        """All 40 event types are present (8 categories)."""
        assert len(EventType) == 40

    # --- str subclass ---

    def test_is_str_subclass(self):
        assert isinstance(EventType.INFO, str)
        assert EventType.INFO == "info"

    def test_string_comparison(self):
        assert EventType.PHASE_START == "phase_start"

    def test_enum_identity(self):
        assert EventType("phase_start") is EventType.PHASE_START


# ═══════════════════════════════════════════════════════════════
# EventData dataclass
# ═══════════════════════════════════════════════════════════════

class TestEventData:
    """Verify EventData construction and to_dict() sparse serialization."""

    def test_minimal_construction(self):
        ed = EventData(event_type=EventType.INFO)
        assert ed.event_type == EventType.INFO
        assert ed.message == ""
        assert ed.phase is None

    def test_message_field(self):
        ed = EventData(event_type=EventType.INFO, message="hello")
        assert ed.message == "hello"

    def test_to_dict_always_includes_event_type_and_message(self):
        ed = EventData(event_type=EventType.INFO, message="test")
        d = ed.to_dict()
        assert d == {"event_type": "info", "message": "test"}

    def test_to_dict_includes_phase_when_set(self):
        ed = EventData(event_type=EventType.PHASE_START, phase="recon")
        d = ed.to_dict()
        assert d["phase"] == "recon"

    def test_to_dict_excludes_phase_when_none(self):
        ed = EventData(event_type=EventType.INFO)
        d = ed.to_dict()
        assert "phase" not in d

    def test_to_dict_includes_tool_name(self):
        ed = EventData(event_type=EventType.TOOL_CALL, tool_name="nmap")
        assert ed.to_dict()["tool_name"] == "nmap"

    def test_to_dict_excludes_tool_name_when_none(self):
        ed = EventData(event_type=EventType.INFO)
        assert "tool_name" not in ed.to_dict()

    def test_to_dict_includes_tool_input(self):
        inp = {"target": "10.0.0.1"}
        ed = EventData(event_type=EventType.TOOL_CALL, tool_input=inp)
        assert ed.to_dict()["tool_input"] == inp

    def test_to_dict_excludes_tool_input_when_none(self):
        ed = EventData(event_type=EventType.INFO)
        assert "tool_input" not in ed.to_dict()

    def test_to_dict_includes_tool_output(self):
        out = {"result": "ok"}
        ed = EventData(event_type=EventType.TOOL_RESULT, tool_output=out)
        assert ed.to_dict()["tool_output"] == out

    def test_to_dict_includes_tool_duration_ms_zero(self):
        ed = EventData(event_type=EventType.TOOL_RESULT, tool_duration_ms=0)
        assert ed.to_dict()["tool_duration_ms"] == 0

    def test_to_dict_excludes_tool_duration_ms_when_none(self):
        ed = EventData(event_type=EventType.INFO)
        assert "tool_duration_ms" not in ed.to_dict()

    def test_to_dict_includes_finding_id(self):
        ed = EventData(event_type=EventType.FINDING_NEW, finding_id="F-001")
        assert ed.to_dict()["finding_id"] == "F-001"

    def test_to_dict_includes_severity(self):
        ed = EventData(event_type=EventType.FINDING_NEW, severity="critical")
        assert ed.to_dict()["severity"] == "critical"

    def test_to_dict_includes_vulnerability_type(self):
        ed = EventData(event_type=EventType.VULNERABILITY, vulnerability_type="sqli")
        assert ed.to_dict()["vulnerability_type"] == "sqli"

    def test_to_dict_includes_flag(self):
        ed = EventData(event_type=EventType.FLAG_FOUND, flag="flag{test}")
        assert ed.to_dict()["flag"] == "flag{test}"

    def test_to_dict_includes_challenge_name(self):
        ed = EventData(event_type=EventType.FLAG_FOUND, challenge_name="web1")
        assert ed.to_dict()["challenge_name"] == "web1"

    def test_to_dict_includes_current_zero(self):
        ed = EventData(event_type=EventType.PROGRESS, current=0)
        assert ed.to_dict()["current"] == 0

    def test_to_dict_includes_total_zero(self):
        ed = EventData(event_type=EventType.PROGRESS, total=0)
        assert ed.to_dict()["total"] == 0

    def test_to_dict_includes_percentage_zero(self):
        ed = EventData(event_type=EventType.PROGRESS, percentage=0.0)
        assert ed.to_dict()["percentage"] == 0.0

    def test_to_dict_excludes_current_when_none(self):
        ed = EventData(event_type=EventType.INFO)
        assert "current" not in ed.to_dict()

    def test_to_dict_includes_metadata(self):
        meta = {"key": "value"}
        ed = EventData(event_type=EventType.INFO, metadata=meta)
        assert ed.to_dict()["metadata"] == meta

    def test_to_dict_excludes_metadata_when_none(self):
        ed = EventData(event_type=EventType.INFO)
        assert "metadata" not in ed.to_dict()

    def test_to_dict_all_fields_populated(self):
        ed = EventData(
            event_type=EventType.TOOL_RESULT,
            message="done",
            phase="exploit",
            tool_name="sqlmap",
            tool_input={"url": "http://x"},
            tool_output={"data": "leaked"},
            tool_duration_ms=1234,
            finding_id="F-X",
            severity="high",
            vulnerability_type="sqli",
            flag="flag{x}",
            challenge_name="web1",
            current=5,
            total=10,
            percentage=50.0,
            metadata={"extra": True},
        )
        d = ed.to_dict()
        assert d["event_type"] == "tool_result"
        assert d["message"] == "done"
        assert d["phase"] == "exploit"
        assert d["tool_name"] == "sqlmap"
        assert d["tool_input"]["url"] == "http://x"
        assert d["tool_output"]["data"] == "leaked"
        assert d["tool_duration_ms"] == 1234
        assert d["finding_id"] == "F-X"
        assert d["severity"] == "high"
        assert d["vulnerability_type"] == "sqli"
        assert d["flag"] == "flag{x}"
        assert d["challenge_name"] == "web1"
        assert d["current"] == 5
        assert d["total"] == 10
        assert d["percentage"] == 50.0
        assert d["metadata"]["extra"] is True

    def test_to_dict_event_type_as_string(self):
        """When event_type is a raw string instead of EventType enum."""
        ed = EventData(event_type="custom_event", message="test")
        d = ed.to_dict()
        assert d["event_type"] == "custom_event"

    def test_to_dict_excludes_empty_string_phase(self):
        """Empty string is falsy, should not be included."""
        ed = EventData(event_type=EventType.INFO, phase="")
        assert "phase" not in ed.to_dict()

    def test_to_dict_excludes_empty_dict_tool_input(self):
        """Empty dict is falsy, should not be included."""
        ed = EventData(event_type=EventType.INFO, tool_input={})
        assert "tool_input" not in ed.to_dict()


# ═══════════════════════════════════════════════════════════════
# StreamEvent dataclass
# ═══════════════════════════════════════════════════════════════

class TestStreamEvent:
    """Verify StreamEvent construction, to_dict(), to_sse()."""

    def test_minimal_construction(self):
        se = StreamEvent(event_type=EventType.INFO)
        assert se.event_type == EventType.INFO
        assert se.data == {}
        assert se.sequence == 0

    def test_timestamp_auto_generated(self):
        before = datetime.now(timezone.utc).isoformat()
        se = StreamEvent(event_type=EventType.INFO)
        after = datetime.now(timezone.utc).isoformat()
        assert before <= se.timestamp <= after

    def test_to_dict_always_includes_core_fields(self):
        se = StreamEvent(event_type=EventType.INFO, data={"k": "v"}, sequence=3)
        d = se.to_dict()
        assert d["event_type"] == "info"
        assert d["data"] == {"k": "v"}
        assert d["sequence"] == 3
        assert "timestamp" in d

    def test_to_dict_includes_session_id_when_set(self):
        se = StreamEvent(event_type=EventType.INFO, session_id="sid-1")
        d = se.to_dict()
        assert d["session_id"] == "sid-1"

    def test_to_dict_excludes_session_id_when_none(self):
        se = StreamEvent(event_type=EventType.INFO)
        assert "session_id" not in se.to_dict()

    def test_to_dict_includes_task_id(self):
        se = StreamEvent(event_type=EventType.INFO, task_id="t-1")
        assert se.to_dict()["task_id"] == "t-1"

    def test_to_dict_excludes_task_id_when_none(self):
        se = StreamEvent(event_type=EventType.INFO)
        assert "task_id" not in se.to_dict()

    def test_to_dict_includes_phase(self):
        se = StreamEvent(event_type=EventType.INFO, phase="recon")
        assert se.to_dict()["phase"] == "recon"

    def test_to_dict_includes_tool_name(self):
        se = StreamEvent(event_type=EventType.INFO, tool_name="nmap")
        assert se.to_dict()["tool_name"] == "nmap"

    def test_to_dict_event_type_as_string(self):
        se = StreamEvent(event_type="custom_type")
        d = se.to_dict()
        assert d["event_type"] == "custom_type"

    def test_to_sse_format(self):
        se = StreamEvent(event_type=EventType.INFO, data={"a": 1}, sequence=5)
        sse = se.to_sse()
        assert sse.startswith("event: info\n")
        assert "data: " in sse
        assert sse.endswith("\n\n")

    def test_to_sse_valid_json_in_data_line(self):
        se = StreamEvent(event_type=EventType.WARNING, data={"msg": "test"})
        sse = se.to_sse()
        lines = sse.strip().split("\n")
        data_line = [l for l in lines if l.startswith("data: ")][0]
        parsed = json.loads(data_line[len("data: "):])
        assert parsed["event_type"] == "warning"
        assert parsed["data"]["msg"] == "test"

    def test_to_sse_event_type_as_string_fallback(self):
        se = StreamEvent(event_type="my_custom")
        sse = se.to_sse()
        assert sse.startswith("event: my_custom\n")

    def test_to_sse_unicode_content(self):
        se = StreamEvent(event_type=EventType.INFO, data={"msg": "Unicode"})
        sse = se.to_sse()
        assert "Unicode" in sse  # ensure_ascii=False


# ═══════════════════════════════════════════════════════════════
# EventEmitter
# ═══════════════════════════════════════════════════════════════

class TestEventEmitterInit:
    """Test EventEmitter construction and state."""

    def test_init_stores_session_id(self):
        em = EventEmitter("sess-1")
        assert em.session_id == "sess-1"

    def test_init_no_manager(self):
        em = EventEmitter("sess-1")
        assert em.event_manager is None

    def test_init_with_manager(self):
        mgr = MagicMock()
        em = EventEmitter("sess-1", mgr)
        assert em.event_manager is mgr

    def test_init_sequence_zero(self):
        em = EventEmitter("sess-1")
        assert em._sequence == 0

    def test_init_current_phase_none(self):
        em = EventEmitter("sess-1")
        assert em._current_phase is None

    def test_init_tool_start_times_empty(self):
        em = EventEmitter("sess-1")
        assert em._tool_start_times == {}


class TestEventEmitterEmit:
    """Test emit() and emit_sync() core methods."""

    @pytest.fixture
    def mock_manager(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="evt-123")
        mgr.add_event_sync = MagicMock(return_value="evt-456")
        return mgr

    def test_emit_increments_sequence(self):
        em = EventEmitter("s1")
        asyncio.run(em.emit(EventData(event_type=EventType.INFO, message="a")))
        assert em._sequence == 1
        asyncio.run(em.emit(EventData(event_type=EventType.INFO, message="b")))
        assert em._sequence == 2

    def test_emit_sets_phase_from_current(self):
        em = EventEmitter("s1")
        em._current_phase = "recon"
        ed = EventData(event_type=EventType.INFO)
        asyncio.run(em.emit(ed))
        assert ed.phase == "recon"

    def test_emit_does_not_overwrite_explicit_phase(self):
        em = EventEmitter("s1")
        em._current_phase = "recon"
        ed = EventData(event_type=EventType.INFO, phase="exploit")
        asyncio.run(em.emit(ed))
        assert ed.phase == "exploit"

    def test_emit_returns_none_without_manager(self):
        em = EventEmitter("s1")
        result = asyncio.run(em.emit(EventData(event_type=EventType.INFO)))
        assert result is None

    def test_emit_returns_event_id_with_manager(self, mock_manager):
        em = EventEmitter("s1", mock_manager)
        result = asyncio.run(em.emit(EventData(event_type=EventType.INFO, message="hi")))
        assert result == "evt-123"

    def test_emit_calls_manager_add_event(self, mock_manager):
        em = EventEmitter("s1", mock_manager)
        asyncio.run(em.emit(EventData(event_type=EventType.INFO, message="hi")))
        mock_manager.add_event.assert_called_once()
        call_kwargs = mock_manager.add_event.call_args
        assert call_kwargs.kwargs["session_id"] == "s1"
        assert call_kwargs.kwargs["sequence"] == 1

    def test_emit_sync_increments_sequence(self):
        em = EventEmitter("s1")
        em.emit_sync(EventData(event_type=EventType.INFO))
        assert em._sequence == 1

    def test_emit_sync_returns_none_without_manager(self):
        em = EventEmitter("s1")
        result = em.emit_sync(EventData(event_type=EventType.INFO))
        assert result is None

    def test_emit_sync_returns_event_id_with_manager(self, mock_manager):
        em = EventEmitter("s1", mock_manager)
        result = em.emit_sync(EventData(event_type=EventType.INFO, message="x"))
        assert result == "evt-456"

    def test_emit_sync_sets_phase_from_current(self):
        em = EventEmitter("s1")
        em._current_phase = "scan"
        ed = EventData(event_type=EventType.INFO)
        em.emit_sync(ed)
        assert ed.phase == "scan"


class TestEventEmitterPhaseEvents:
    """Test emit_phase_start() and emit_phase_complete()."""

    def test_phase_start_sets_current_phase(self):
        em = EventEmitter("s1")
        asyncio.run(em.emit_phase_start("recon"))
        assert em._current_phase == "recon"

    def test_phase_start_default_message(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        asyncio.run(em.emit_phase_start("recon"))
        call_kwargs = mgr.add_event.call_args.kwargs
        assert "recon" in call_kwargs["message"]

    def test_phase_start_custom_message(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        asyncio.run(em.emit_phase_start("recon", message="Custom start"))
        call_kwargs = mgr.add_event.call_args.kwargs
        assert call_kwargs["message"] == "Custom start"

    def test_phase_complete_default_message(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        asyncio.run(em.emit_phase_complete("recon"))
        call_kwargs = mgr.add_event.call_args.kwargs
        assert "recon" in call_kwargs["message"]
        assert call_kwargs["event_type"] == "phase_complete"


class TestEventEmitterThinkingEvents:
    """Test thinking/ReAct event helpers."""

    @pytest.fixture
    def tracked_emitter(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        return em, mgr

    def test_emit_thinking_start(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_thinking_start("Analyzing"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "thinking_start"
        assert "Analyzing" in kw["message"]

    def test_emit_thought_short(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_thought("Short thought"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "thought"
        assert "Short thought" in kw["message"]
        assert "..." not in kw["message"]

    def test_emit_thought_truncation_at_500(self, tracked_emitter):
        em, mgr = tracked_emitter
        long_thought = "A" * 600
        asyncio.run(em.emit_thought(long_thought))
        kw = mgr.add_event.call_args.kwargs
        # The display in message should be truncated
        assert "..." in kw["message"]
        # But metadata should contain the full thought
        assert kw["metadata"]["thought"] == long_thought

    def test_emit_thought_exactly_500_no_truncation(self, tracked_emitter):
        em, mgr = tracked_emitter
        exactly_500 = "B" * 500
        asyncio.run(em.emit_thought(exactly_500))
        kw = mgr.add_event.call_args.kwargs
        assert "..." not in kw["message"]

    def test_emit_thought_501_truncation(self, tracked_emitter):
        em, mgr = tracked_emitter
        slightly_over = "C" * 501
        asyncio.run(em.emit_thought(slightly_over))
        kw = mgr.add_event.call_args.kwargs
        assert "..." in kw["message"]

    def test_emit_thought_iteration_in_metadata(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_thought("thought", iteration=3))
        kw = mgr.add_event.call_args.kwargs
        assert kw["metadata"]["iteration"] == 3

    def test_emit_decision(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_decision("use sqlmap", reason="found injection point"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "decision"
        assert "sqlmap" in kw["message"]
        assert "found injection point" in kw["message"]

    def test_emit_decision_no_reason(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_decision("skip"))
        kw = mgr.add_event.call_args.kwargs
        assert "skip" in kw["message"]

    def test_emit_action(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_action("nmap_scan", {"target": "10.0.0.1"}))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "action"
        assert "nmap_scan" in kw["message"]

    def test_emit_observation_short(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_observation("Port 80 open", tool_name="nmap"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "observation"
        assert kw["tool_name"] == "nmap"
        assert "..." not in kw["message"]

    def test_emit_observation_truncation_at_1000(self, tracked_emitter):
        em, mgr = tracked_emitter
        long_obs = "X" * 1200
        asyncio.run(em.emit_observation(long_obs))
        kw = mgr.add_event.call_args.kwargs
        assert "..." in kw["message"]
        # Full observation in metadata
        assert kw["metadata"]["observation"] == long_obs

    def test_emit_thinking_end(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_thinking_end("Done analyzing"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "thinking_end"
        assert "Done analyzing" in kw["message"]


class TestEventEmitterToolEvents:
    """Test tool-related event methods and duration tracking."""

    @pytest.fixture
    def tracked_emitter(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        return em, mgr

    def test_emit_tool_call_records_start_time(self, tracked_emitter):
        em, _ = tracked_emitter
        asyncio.run(em.emit_tool_call("nmap", {"target": "10.0.0.1"}))
        assert "nmap" in em._tool_start_times
        assert isinstance(em._tool_start_times["nmap"], float)

    def test_emit_tool_call_event_type(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_tool_call("nmap", {"target": "10.0.0.1"}))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "tool_call"
        assert kw["tool_name"] == "nmap"

    def test_emit_tool_call_custom_message(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_tool_call("nmap", {}, message="Custom"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["message"] == "Custom"

    def test_emit_tool_progress(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_tool_progress("nmap", 50.5))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "tool_progress"
        assert kw["percentage"] == 50.5

    def test_emit_tool_result_calculates_duration(self, tracked_emitter):
        em, mgr = tracked_emitter
        em._tool_start_times["nmap"] = time.time() - 1.5  # 1.5 seconds ago
        asyncio.run(em.emit_tool_result("nmap", {"result": "ok"}))
        kw = mgr.add_event.call_args.kwargs
        assert kw["tool_duration_ms"] >= 1400  # at least ~1.4 seconds
        assert "nmap" not in em._tool_start_times  # cleaned up

    def test_emit_tool_result_no_start_time(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_tool_result("unknown_tool", "result"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["tool_duration_ms"] == 0

    def test_emit_tool_result_string_output(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_tool_result("nmap", "string output"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["tool_output"] == {"result": "string output"}

    def test_emit_tool_result_dict_output(self, tracked_emitter):
        em, mgr = tracked_emitter
        out = {"ports": [80, 443]}
        asyncio.run(em.emit_tool_result("nmap", out))
        kw = mgr.add_event.call_args.kwargs
        assert kw["tool_output"] == out

    def test_emit_tool_result_object_with_to_dict(self, tracked_emitter):
        em, mgr = tracked_emitter
        obj = MagicMock()
        obj.to_dict.return_value = {"custom": "data"}
        asyncio.run(em.emit_tool_result("nmap", obj))
        kw = mgr.add_event.call_args.kwargs
        assert kw["tool_output"] == {"custom": "data"}

    def test_emit_tool_result_other_type(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_tool_result("nmap", 12345))
        kw = mgr.add_event.call_args.kwargs
        assert kw["tool_output"] == {"result": "12345"}

    def test_emit_tool_result_long_string_truncated(self, tracked_emitter):
        em, mgr = tracked_emitter
        long_str = "A" * 3000
        asyncio.run(em.emit_tool_result("nmap", long_str))
        kw = mgr.add_event.call_args.kwargs
        assert len(kw["tool_output"]["result"]) == 2000

    def test_emit_tool_error(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_tool_error("nmap", "timeout"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "tool_error"
        assert "timeout" in kw["message"]
        assert kw["metadata"]["error"] == "timeout"


class TestEventEmitterFindingEvents:
    """Test finding/flag/credential event methods."""

    @pytest.fixture
    def tracked_emitter(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        return em, mgr

    def test_emit_finding_new(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_finding("F-1", "SQL Injection", "high", "sqli"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "finding_new"
        assert kw["finding_id"] == "F-1"
        assert kw["severity"] == "high"

    def test_emit_finding_verified(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_finding("F-2", "XSS", "medium", "xss", is_verified=True))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "finding_verified"

    def test_emit_flag_found(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_flag_found("flag{test123}", challenge_name="web1", source="response"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "flag_found"
        assert kw["flag"] == "flag{test123}"
        assert kw["challenge_name"] == "web1"
        assert kw["metadata"]["source"] == "response"

    def test_emit_flag_found_minimal(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_flag_found("flag{x}"))
        kw = mgr.add_event.call_args.kwargs
        assert "flag{x}" in kw["message"]

    def test_emit_credential_found_with_password(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_credential_found("admin", "secret123", "ssh"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "credential_found"
        # Password is partially masked in message
        assert "sec***" in kw["message"]
        assert kw["metadata"]["password_found"] is True
        assert kw["metadata"]["service"] == "ssh"

    def test_emit_credential_found_without_password(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_credential_found("admin"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["metadata"]["password_found"] is False

    def test_emit_credential_found_without_service(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_credential_found("admin", "pass"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["metadata"]["service"] is None


class TestEventEmitterAttackEvents:
    """Test attack chain event methods."""

    @pytest.fixture
    def tracked_emitter(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        return em, mgr

    def test_emit_attack_start(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_attack_start("sqli", "http://target.com"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "attack_start"
        assert kw["metadata"]["attack_type"] == "sqli"
        assert kw["metadata"]["target"] == "http://target.com"

    def test_emit_attack_progress(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_attack_progress("brute", 5, 20))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "attack_progress"
        assert kw["current"] == 5
        assert kw["total"] == 20
        assert kw["percentage"] == 25.0

    def test_emit_attack_progress_zero_total(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_attack_progress("brute", 0, 0))
        kw = mgr.add_event.call_args.kwargs
        assert kw["percentage"] == 0

    def test_emit_attack_success(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_attack_success("sqli", "database dumped"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "attack_success"

    def test_emit_attack_failed(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_attack_failed("sqli", "WAF blocked"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "attack_failed"
        assert kw["metadata"]["reason"] == "WAF blocked"


class TestEventEmitterStatusEvents:
    """Test status/progress event methods."""

    @pytest.fixture
    def tracked_emitter(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        return em, mgr

    def test_emit_progress(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_progress(3, 10))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "progress"
        assert kw["current"] == 3
        assert kw["total"] == 10
        assert kw["percentage"] == 30.0

    def test_emit_progress_zero_total(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_progress(0, 0))
        kw = mgr.add_event.call_args.kwargs
        assert kw["percentage"] == 0

    def test_emit_info(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_info("scan complete", metadata={"x": 1}))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "info"
        assert kw["metadata"] == {"x": 1}

    def test_emit_warning(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_warning("rate limited"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "warning"

    def test_emit_error(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_error("connection refused"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "error"


class TestEventEmitterTaskEvents:
    """Test task lifecycle event methods."""

    @pytest.fixture
    def tracked_emitter(self):
        mgr = MagicMock(spec=EventManager)
        mgr.add_event = AsyncMock(return_value="x")
        em = EventEmitter("s1", mgr)
        return em, mgr

    def test_emit_task_complete(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_task_complete(findings_count=5, duration_ms=12000))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "task_complete"
        assert kw["metadata"]["findings_count"] == 5
        assert kw["metadata"]["duration_ms"] == 12000

    def test_emit_task_complete_default_message(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_task_complete(findings_count=3, duration_ms=5000))
        kw = mgr.add_event.call_args.kwargs
        assert "3" in kw["message"]
        assert "5.0" in kw["message"]

    def test_emit_task_error(self, tracked_emitter):
        em, mgr = tracked_emitter
        asyncio.run(em.emit_task_error("out of memory"))
        kw = mgr.add_event.call_args.kwargs
        assert kw["event_type"] == "task_error"
        assert kw["metadata"]["error"] == "out of memory"


# ═══════════════════════════════════════════════════════════════
# EventManager
# ═══════════════════════════════════════════════════════════════

class TestEventManagerInit:
    """Test EventManager construction."""

    def test_init_empty_queues(self):
        mgr = EventManager()
        assert mgr._event_queues == {}

    def test_init_empty_callbacks(self):
        mgr = EventManager()
        assert mgr._event_callbacks == {}

    def test_init_empty_history(self):
        mgr = EventManager()
        assert mgr._event_history == {}

    def test_init_max_history(self):
        mgr = EventManager()
        assert mgr._max_history == 1000


class TestEventManagerAddEvent:
    """Test add_event() async method."""

    def test_add_event_returns_uuid(self):
        mgr = EventManager()
        event_id = asyncio.run(mgr.add_event("s1", EventType.INFO, message="hi"))
        # Valid UUID4
        uuid.UUID(event_id, version=4)

    def test_add_event_stores_in_history(self):
        mgr = EventManager()
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="hi"))
        assert len(mgr._event_history["s1"]) == 1

    def test_add_event_history_data_structure(self):
        mgr = EventManager()
        asyncio.run(mgr.add_event("s1", EventType.INFO, sequence=5, message="hi"))
        evt = mgr._event_history["s1"][0]
        assert "id" in evt
        assert evt["session_id"] == "s1"
        assert evt["event_type"] == "info"
        assert evt["sequence"] == 5
        assert evt["message"] == "hi"
        assert "timestamp" in evt

    def test_add_event_string_event_type(self):
        mgr = EventManager()
        asyncio.run(mgr.add_event("s1", "custom_type", message="x"))
        evt = mgr._event_history["s1"][0]
        assert evt["event_type"] == "custom_type"

    def test_add_event_extra_kwargs(self):
        mgr = EventManager()
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="x", severity="high", custom="val"))
        evt = mgr._event_history["s1"][0]
        assert evt["severity"] == "high"
        assert evt["custom"] == "val"

    def test_add_event_caps_history_at_1000(self):
        mgr = EventManager()
        for i in range(1100):
            asyncio.run(mgr.add_event("s1", EventType.INFO, sequence=i, message=f"evt-{i}"))
        assert len(mgr._event_history["s1"]) == 1000
        # Should keep the last 1000
        assert mgr._event_history["s1"][0]["sequence"] == 100

    def test_add_event_pushes_to_queue(self):
        mgr = EventManager()
        q = mgr.create_queue("s1")
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="queued"))
        assert q.qsize() == 1

    def test_add_event_no_queue_no_error(self):
        mgr = EventManager()
        # Should not raise even without a queue
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="no queue"))

    def test_add_event_full_queue_no_crash(self):
        mgr = EventManager()
        q = mgr.create_queue("s1", maxsize=1)
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="first"))
        # Second event should not crash even with full queue
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="second"))
        assert q.qsize() == 1  # Only the first one made it

    def test_add_event_calls_sync_callback(self):
        mgr = EventManager()
        received = []
        mgr.add_callback("s1", lambda evt: received.append(evt))
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="cb"))
        assert len(received) == 1
        assert received[0]["message"] == "cb"

    def test_add_event_calls_async_callback(self):
        mgr = EventManager()
        received = []

        async def async_cb(evt):
            received.append(evt)

        mgr.add_callback("s1", async_cb)
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="async"))
        assert len(received) == 1

    def test_add_event_callback_error_does_not_crash(self):
        mgr = EventManager()

        def bad_callback(evt):
            raise ValueError("boom")

        mgr.add_callback("s1", bad_callback)
        # Should not raise
        asyncio.run(mgr.add_event("s1", EventType.INFO, message="safe"))
        assert len(mgr._event_history["s1"]) == 1

    def test_add_event_no_callback_for_session(self):
        mgr = EventManager()
        # No callbacks for s2
        asyncio.run(mgr.add_event("s2", EventType.INFO, message="x"))
        assert len(mgr._event_history["s2"]) == 1


class TestEventManagerAddEventSync:
    """Test add_event_sync() synchronous method."""

    def test_add_event_sync_returns_uuid(self):
        mgr = EventManager()
        event_id = mgr.add_event_sync("s1", EventType.INFO, message="hi")
        uuid.UUID(event_id, version=4)

    def test_add_event_sync_stores_in_history(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, message="sync")
        assert len(mgr._event_history["s1"]) == 1

    def test_add_event_sync_pushes_to_queue(self):
        mgr = EventManager()
        q = mgr.create_queue("s1")
        mgr.add_event_sync("s1", EventType.INFO, message="queued")
        assert q.qsize() == 1

    def test_add_event_sync_full_queue_no_crash(self):
        mgr = EventManager()
        q = mgr.create_queue("s1", maxsize=1)
        mgr.add_event_sync("s1", EventType.INFO, message="first")
        mgr.add_event_sync("s1", EventType.INFO, message="second")
        assert q.qsize() == 1

    def test_add_event_sync_string_event_type(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", "raw_string")
        evt = mgr._event_history["s1"][0]
        assert evt["event_type"] == "raw_string"

    def test_add_event_sync_extra_kwargs(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, message="x", tool_name="nmap")
        evt = mgr._event_history["s1"][0]
        assert evt["tool_name"] == "nmap"


class TestEventManagerQueueManagement:
    """Test create_queue() and remove_queue()."""

    def test_create_queue_returns_asyncio_queue(self):
        mgr = EventManager()
        q = mgr.create_queue("s1")
        assert isinstance(q, asyncio.Queue)

    def test_create_queue_default_maxsize(self):
        mgr = EventManager()
        q = mgr.create_queue("s1")
        assert q.maxsize == 5000

    def test_create_queue_custom_maxsize(self):
        mgr = EventManager()
        q = mgr.create_queue("s1", maxsize=10)
        assert q.maxsize == 10

    def test_create_queue_idempotent(self):
        mgr = EventManager()
        q1 = mgr.create_queue("s1")
        q2 = mgr.create_queue("s1")
        assert q1 is q2

    def test_remove_queue(self):
        mgr = EventManager()
        mgr.create_queue("s1")
        mgr.remove_queue("s1")
        assert "s1" not in mgr._event_queues

    def test_remove_queue_nonexistent_no_error(self):
        mgr = EventManager()
        mgr.remove_queue("nonexistent")  # Should not raise


class TestEventManagerCallbacks:
    """Test add_callback() and remove_callback()."""

    def test_add_callback(self):
        mgr = EventManager()
        cb = lambda evt: None
        mgr.add_callback("s1", cb)
        assert cb in mgr._event_callbacks["s1"]

    def test_add_multiple_callbacks(self):
        mgr = EventManager()
        cb1 = lambda evt: None
        cb2 = lambda evt: None
        mgr.add_callback("s1", cb1)
        mgr.add_callback("s1", cb2)
        assert len(mgr._event_callbacks["s1"]) == 2

    def test_remove_callback(self):
        mgr = EventManager()
        cb = lambda evt: None
        mgr.add_callback("s1", cb)
        mgr.remove_callback("s1", cb)
        assert cb not in mgr._event_callbacks["s1"]

    def test_remove_callback_nonexistent_session_no_error(self):
        mgr = EventManager()
        mgr.remove_callback("nonexistent", lambda evt: None)

    def test_remove_callback_nonexistent_callback_no_error(self):
        mgr = EventManager()
        mgr.add_callback("s1", lambda evt: None)
        mgr.remove_callback("s1", lambda evt: None)  # Different lambda, should not crash


class TestEventManagerGetEvents:
    """Test get_events() filtering."""

    def test_get_events_empty_session(self):
        mgr = EventManager()
        result = mgr.get_events("nonexistent")
        assert result == []

    def test_get_events_all(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, sequence=1, message="a")
        mgr.add_event_sync("s1", EventType.INFO, sequence=2, message="b")
        result = mgr.get_events("s1")
        assert len(result) == 2

    def test_get_events_after_sequence(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, sequence=1, message="a")
        mgr.add_event_sync("s1", EventType.INFO, sequence=2, message="b")
        mgr.add_event_sync("s1", EventType.INFO, sequence=3, message="c")
        result = mgr.get_events("s1", after_sequence=1)
        assert len(result) == 2
        assert result[0]["sequence"] == 2

    def test_get_events_limit(self):
        mgr = EventManager()
        for i in range(10):
            mgr.add_event_sync("s1", EventType.INFO, sequence=i + 1, message=f"e{i}")
        result = mgr.get_events("s1", limit=3)
        assert len(result) == 3

    def test_get_events_after_sequence_and_limit(self):
        mgr = EventManager()
        for i in range(10):
            mgr.add_event_sync("s1", EventType.INFO, sequence=i + 1, message=f"e{i}")
        result = mgr.get_events("s1", after_sequence=5, limit=2)
        assert len(result) == 2
        assert result[0]["sequence"] == 6

    def test_get_events_different_sessions_isolated(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, sequence=1, message="a")
        mgr.add_event_sync("s2", EventType.INFO, sequence=1, message="b")
        assert len(mgr.get_events("s1")) == 1
        assert len(mgr.get_events("s2")) == 1


class TestEventManagerClearSession:
    """Test clear_session() cleanup."""

    def test_clear_session_removes_history(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, message="x")
        mgr.clear_session("s1")
        assert "s1" not in mgr._event_history

    def test_clear_session_removes_queue(self):
        mgr = EventManager()
        mgr.create_queue("s1")
        mgr.clear_session("s1")
        assert "s1" not in mgr._event_queues

    def test_clear_session_removes_callbacks(self):
        mgr = EventManager()
        mgr.add_callback("s1", lambda evt: None)
        mgr.clear_session("s1")
        assert "s1" not in mgr._event_callbacks

    def test_clear_session_nonexistent_no_error(self):
        mgr = EventManager()
        mgr.clear_session("nonexistent")  # Should not raise

    def test_clear_session_partial_state(self):
        """Only queue exists, no history or callbacks."""
        mgr = EventManager()
        mgr.create_queue("s1")
        mgr.clear_session("s1")
        assert "s1" not in mgr._event_queues


class TestEventManagerGetStats:
    """Test get_stats() statistics."""

    def test_stats_empty_manager(self):
        mgr = EventManager()
        stats = mgr.get_stats()
        assert stats["active_sessions"] == 0
        assert stats["total_events"] == 0
        assert stats["sessions"] == {}

    def test_stats_with_one_session_bug_q_undefined(self):
        """get_stats() has a bug: line 826 references undefined 'q' variable.

        When a session has both a queue and history, get_stats() crashes with
        NameError because the dict comprehension uses 'q.qsize()' where 'q'
        is never bound. This test documents the current broken behavior.
        """
        mgr = EventManager()
        mgr.create_queue("s1")
        mgr.add_event_sync("s1", EventType.INFO, message="x")
        mgr.add_callback("s1", lambda evt: None)
        with pytest.raises(NameError, match="q"):
            mgr.get_stats()

    def test_stats_with_session_history_only(self):
        """get_stats() works when session has history but no queue,
        because the 'q.qsize()' branch is not taken.
        """
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, message="x")
        stats = mgr.get_stats()
        assert stats["active_sessions"] == 0
        assert stats["total_events"] == 1
        s1_stats = stats["sessions"]["s1"]
        assert s1_stats["history_size"] == 1
        assert s1_stats["queue_size"] == 0

    def test_stats_multiple_sessions(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, message="a")
        mgr.add_event_sync("s1", EventType.INFO, message="b")
        mgr.add_event_sync("s2", EventType.INFO, message="c")
        stats = mgr.get_stats()
        assert stats["total_events"] == 3
        assert "s1" in stats["sessions"]
        assert "s2" in stats["sessions"]

    def test_stats_session_without_queue(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, message="x")
        stats = mgr.get_stats()
        assert stats["sessions"]["s1"]["queue_size"] == 0


class TestEventManagerCreateEmitter:
    """Test create_emitter() factory."""

    def test_create_emitter_returns_event_emitter(self):
        mgr = EventManager()
        em = mgr.create_emitter("s1")
        assert isinstance(em, EventEmitter)

    def test_create_emitter_sets_session_id(self):
        mgr = EventManager()
        em = mgr.create_emitter("s1")
        assert em.session_id == "s1"

    def test_create_emitter_sets_manager(self):
        mgr = EventManager()
        em = mgr.create_emitter("s1")
        assert em.event_manager is mgr


class TestEventManagerStreamEvents:
    """Test stream_events() async generator."""

    def test_stream_events_yields_history(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, sequence=1, message="a")
        mgr.add_event_sync("s1", EventType.INFO, sequence=2, message="b")

        async def run():
            events = []
            async for evt in mgr.stream_events("s1", after_sequence=0, timeout=0.1):
                events.append(evt)
                if len(events) >= 2:
                    break
            return events

        events = asyncio.run(run())
        assert len(events) >= 2

    def test_stream_events_filters_by_after_sequence(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.INFO, sequence=1, message="a")
        mgr.add_event_sync("s1", EventType.INFO, sequence=2, message="b")

        async def run():
            events = []
            async for evt in mgr.stream_events("s1", after_sequence=1, timeout=0.1):
                events.append(evt)
                if evt.get("event_type") == EventType.HEARTBEAT.value:
                    break
            return events

        events = asyncio.run(run())
        data_events = [e for e in events if e.get("event_type") != "heartbeat"]
        assert len(data_events) == 1
        assert data_events[0]["sequence"] == 2

    def test_stream_events_heartbeat_on_timeout(self):
        mgr = EventManager()
        mgr.create_queue("s1")

        async def run():
            events = []
            async for evt in mgr.stream_events("s1", timeout=0.1):
                events.append(evt)
                if evt.get("event_type") == EventType.HEARTBEAT.value:
                    break
            return events

        events = asyncio.run(run())
        assert any(e.get("event_type") == "heartbeat" for e in events)

    def test_stream_events_stops_on_task_complete(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.TASK_COMPLETE, sequence=1, message="done")

        async def run():
            events = []
            async for evt in mgr.stream_events("s1"):
                events.append(evt)
            return events

        events = asyncio.run(run())
        assert len(events) == 1
        assert events[0]["event_type"] == "task_complete"

    def test_stream_events_stops_on_task_error_in_history(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.TASK_ERROR, sequence=1, message="fail")

        async def run():
            events = []
            async for evt in mgr.stream_events("s1"):
                events.append(evt)
            return events

        events = asyncio.run(run())
        assert events[0]["event_type"] == "task_error"

    def test_stream_events_stops_on_task_cancel_in_history(self):
        mgr = EventManager()
        mgr.add_event_sync("s1", EventType.TASK_CANCEL, sequence=1, message="cancelled")

        async def run():
            events = []
            async for evt in mgr.stream_events("s1"):
                events.append(evt)
            return events

        events = asyncio.run(run())
        assert events[0]["event_type"] == "task_cancel"

    def test_stream_events_creates_queue_if_missing(self):
        mgr = EventManager()

        async def run():
            # This should create the queue internally
            async for evt in mgr.stream_events("s1", timeout=0.05):
                break

        asyncio.run(run())
        assert "s1" in mgr._event_queues

    def test_stream_events_live_events(self):
        mgr = EventManager()
        q = mgr.create_queue("s1")

        async def run():
            events = []
            # Pre-populate queue with a terminal event
            await mgr.add_event("s1", EventType.TASK_COMPLETE, sequence=1, message="done")
            async for evt in mgr.stream_events("s1", timeout=1.0):
                events.append(evt)
            return events

        events = asyncio.run(run())
        terminal = [e for e in events if e.get("event_type") == "task_complete"]
        assert len(terminal) >= 1


# ═══════════════════════════════════════════════════════════════
# Global functions
# ═══════════════════════════════════════════════════════════════

class TestGlobalFunctions:
    """Test get_event_manager() and create_emitter() module-level functions."""

    def test_get_event_manager_returns_event_manager(self):
        import kali_mcp.core.event_stream as es
        old = es._global_event_manager
        try:
            es._global_event_manager = None
            mgr = get_event_manager()
            assert isinstance(mgr, EventManager)
        finally:
            es._global_event_manager = old

    def test_get_event_manager_singleton(self):
        import kali_mcp.core.event_stream as es
        old = es._global_event_manager
        try:
            es._global_event_manager = None
            mgr1 = get_event_manager()
            mgr2 = get_event_manager()
            assert mgr1 is mgr2
        finally:
            es._global_event_manager = old

    def test_create_emitter_returns_emitter(self):
        import kali_mcp.core.event_stream as es
        old = es._global_event_manager
        try:
            es._global_event_manager = None
            em = create_emitter("test-sess")
            assert isinstance(em, EventEmitter)
            assert em.session_id == "test-sess"
        finally:
            es._global_event_manager = old

    def test_create_emitter_uses_global_manager(self):
        import kali_mcp.core.event_stream as es
        old = es._global_event_manager
        try:
            es._global_event_manager = None
            em = create_emitter("s1")
            assert em.event_manager is get_event_manager()
        finally:
            es._global_event_manager = old


# ═══════════════════════════════════════════════════════════════
# Integration / Edge-case tests
# ═══════════════════════════════════════════════════════════════

class TestIntegration:
    """Integration tests: emitter + manager working together."""

    def test_full_tool_lifecycle(self):
        """Emit tool_call then tool_result, verify duration is tracked."""
        mgr = EventManager()
        em = mgr.create_emitter("sess-int")

        async def run():
            await em.emit_tool_call("nmap", {"target": "10.0.0.1"})
            # Simulate some delay
            await asyncio.sleep(0.05)
            await em.emit_tool_result("nmap", {"ports": [80]})

        asyncio.run(run())
        events = mgr.get_events("sess-int")
        assert len(events) == 2
        result_evt = events[1]
        assert result_evt["event_type"] == "tool_result"
        assert result_evt["tool_duration_ms"] >= 40

    def test_sequence_increments_across_events(self):
        mgr = EventManager()
        em = mgr.create_emitter("sess-seq")

        async def run():
            await em.emit_info("first")
            await em.emit_info("second")
            await em.emit_info("third")

        asyncio.run(run())
        events = mgr.get_events("sess-seq")
        sequences = [e["sequence"] for e in events]
        assert sequences == [1, 2, 3]

    def test_phase_propagated_to_subsequent_events(self):
        mgr = EventManager()
        em = mgr.create_emitter("sess-phase")

        async def run():
            await em.emit_phase_start("recon")
            await em.emit_info("scanning")
            await em.emit_phase_complete("recon")

        asyncio.run(run())
        events = mgr.get_events("sess-phase")
        # The info event should inherit the "recon" phase
        info_evt = [e for e in events if e.get("event_type") == "info"][0]
        assert info_evt.get("phase") == "recon"

    def test_emit_sync_lifecycle(self):
        mgr = EventManager()
        em = mgr.create_emitter("sess-sync")
        em.emit_sync(EventData(event_type=EventType.INFO, message="sync event"))
        events = mgr.get_events("sess-sync")
        assert len(events) == 1
        assert events[0]["message"] == "sync event"

    def test_multiple_sessions_isolated(self):
        mgr = EventManager()
        em1 = mgr.create_emitter("s1")
        em2 = mgr.create_emitter("s2")

        async def run():
            await em1.emit_info("msg1")
            await em2.emit_info("msg2")

        asyncio.run(run())
        assert len(mgr.get_events("s1")) == 1
        assert len(mgr.get_events("s2")) == 1

    def test_clear_session_fully_isolates(self):
        mgr = EventManager()
        em = mgr.create_emitter("s1")
        mgr.create_queue("s1")
        mgr.add_callback("s1", lambda evt: None)
        asyncio.run(em.emit_info("before clear"))
        mgr.clear_session("s1")
        assert mgr.get_events("s1") == []
        stats = mgr.get_stats()
        assert "s1" not in stats["sessions"]

    def test_callback_receives_correct_data(self):
        mgr = EventManager()
        captured = []
        mgr.add_callback("s1", lambda evt: captured.append(evt))
        em = mgr.create_emitter("s1")
        asyncio.run(em.emit_flag_found("flag{captured}", challenge_name="test"))
        assert len(captured) == 1
        assert captured[0]["flag"] == "flag{captured}"

    def test_history_cap_preserves_recent(self):
        mgr = EventManager()
        mgr._max_history = 5  # Override for test
        for i in range(10):
            asyncio.run(mgr.add_event("s1", EventType.INFO, sequence=i + 1, message=f"evt-{i}"))
        events = mgr.get_events("s1")
        assert len(events) == 5
        # Should keep the last 5 (sequence 6-10)
        assert events[0]["sequence"] == 6
