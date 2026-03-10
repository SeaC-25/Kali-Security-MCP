"""
Tests for AdaptiveExecutionEngine (kali_mcp/core/adaptive_exec_engine.py)

Covers:
- ExecutionContext dataclass: defaults, UUID generation, field independence,
  custom construction, state values
- AdaptiveExecutionEngine: init state, create_execution_context(),
  execute_adaptive_strategy(), _select_optimal_strategy(),
  _simulate_strategy_execution(), _evaluate_performance(),
  _trigger_adaptation(), _get_alternative_strategies(),
  get_execution_status(), get_adaptation_insights()
- Global singleton: adaptive_execution_engine
"""

import uuid
import time
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from kali_mcp.core.adaptive_exec_engine import (
    ExecutionContext,
    AdaptiveExecutionEngine,
    adaptive_execution_engine,
)


# ===========================================================================
# ExecutionContext dataclass
# ===========================================================================


class TestExecutionContextDefaults:
    """Verify every default field on a freshly constructed ExecutionContext."""

    def test_context_id_is_valid_uuid(self):
        ctx = ExecutionContext()
        parsed = uuid.UUID(ctx.context_id)
        assert str(parsed) == ctx.context_id

    def test_each_instance_gets_unique_context_id(self):
        ids = {ExecutionContext().context_id for _ in range(20)}
        assert len(ids) == 20

    def test_default_session_id_empty(self):
        assert ExecutionContext().session_id == ""

    def test_default_current_strategy_empty(self):
        assert ExecutionContext().current_strategy == ""

    def test_default_target_info_empty_dict(self):
        assert ExecutionContext().target_info == {}

    def test_default_execution_state_idle(self):
        assert ExecutionContext().execution_state == "idle"

    def test_default_performance_metrics_empty_dict(self):
        assert ExecutionContext().performance_metrics == {}

    def test_default_adaptation_history_empty_list(self):
        assert ExecutionContext().adaptation_history == []

    def test_default_created_at_is_recent(self):
        before = datetime.now()
        ctx = ExecutionContext()
        after = datetime.now()
        assert before <= ctx.created_at <= after

    def test_default_last_updated_is_recent(self):
        before = datetime.now()
        ctx = ExecutionContext()
        after = datetime.now()
        assert before <= ctx.last_updated <= after


class TestExecutionContextMutableFieldIndependence:
    """Ensure mutable defaults are not shared across instances."""

    def test_target_info_independence(self):
        a = ExecutionContext()
        b = ExecutionContext()
        a.target_info["key"] = "val"
        assert "key" not in b.target_info

    def test_performance_metrics_independence(self):
        a = ExecutionContext()
        b = ExecutionContext()
        a.performance_metrics["m"] = 1.0
        assert "m" not in b.performance_metrics

    def test_adaptation_history_independence(self):
        a = ExecutionContext()
        b = ExecutionContext()
        a.adaptation_history.append({"x": 1})
        assert len(b.adaptation_history) == 0


class TestExecutionContextCustomConstruction:
    """Verify that custom values override defaults."""

    def test_custom_session_id(self):
        ctx = ExecutionContext(session_id="sess-42")
        assert ctx.session_id == "sess-42"

    def test_custom_current_strategy(self):
        ctx = ExecutionContext(current_strategy="fast_scan")
        assert ctx.current_strategy == "fast_scan"

    def test_custom_target_info(self):
        info = {"type": "web", "url": "http://example.com"}
        ctx = ExecutionContext(target_info=info)
        assert ctx.target_info == info

    def test_custom_execution_state(self):
        ctx = ExecutionContext(execution_state="executing")
        assert ctx.execution_state == "executing"

    def test_custom_performance_metrics(self):
        metrics = {"score": 0.95}
        ctx = ExecutionContext(performance_metrics=metrics)
        assert ctx.performance_metrics == metrics

    def test_custom_adaptation_history(self):
        history = [{"trigger": "low_performance"}]
        ctx = ExecutionContext(adaptation_history=history)
        assert ctx.adaptation_history == history

    def test_custom_context_id(self):
        cid = "my-custom-id-123"
        ctx = ExecutionContext(context_id=cid)
        assert ctx.context_id == cid


class TestExecutionContextStateValues:
    """Test that execution_state field can hold all documented states."""

    @pytest.mark.parametrize("state", ["idle", "planning", "executing", "evaluating", "switching"])
    def test_valid_execution_states(self, state):
        ctx = ExecutionContext(execution_state=state)
        assert ctx.execution_state == state


# ===========================================================================
# AdaptiveExecutionEngine — Initialization
# ===========================================================================


class TestAdaptiveExecutionEngineInit:
    """Verify initial state of a fresh engine."""

    def test_empty_execution_contexts(self):
        engine = AdaptiveExecutionEngine()
        assert engine.execution_contexts == {}

    def test_empty_active_contexts(self):
        engine = AdaptiveExecutionEngine()
        assert engine.active_contexts == set()

    def test_default_adaptation_threshold(self):
        engine = AdaptiveExecutionEngine()
        assert engine.adaptation_threshold == 0.3

    def test_default_max_execution_time(self):
        engine = AdaptiveExecutionEngine()
        assert engine.max_execution_time == 300

    def test_empty_strategy_performance_history(self):
        engine = AdaptiveExecutionEngine()
        assert engine.strategy_performance_history == {}


# ===========================================================================
# AdaptiveExecutionEngine.create_execution_context()
# ===========================================================================


class TestCreateExecutionContext:
    """Tests for create_execution_context."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_returns_valid_uuid_string(self):
        cid = self.engine.create_execution_context("sess-1", {"type": "web"})
        uuid.UUID(cid)  # should not raise

    def test_context_stored_in_execution_contexts(self):
        cid = self.engine.create_execution_context("sess-1", {})
        assert cid in self.engine.execution_contexts

    def test_context_added_to_active_contexts(self):
        cid = self.engine.create_execution_context("sess-1", {})
        assert cid in self.engine.active_contexts

    def test_context_has_correct_session_id(self):
        cid = self.engine.create_execution_context("sess-42", {})
        assert self.engine.execution_contexts[cid].session_id == "sess-42"

    def test_context_has_correct_target_info(self):
        info = {"type": "network", "ip": "10.0.0.1"}
        cid = self.engine.create_execution_context("s", info)
        assert self.engine.execution_contexts[cid].target_info == info

    def test_default_strategy_is_auto(self):
        cid = self.engine.create_execution_context("s", {})
        assert self.engine.execution_contexts[cid].current_strategy == "auto"

    def test_custom_initial_strategy(self):
        cid = self.engine.create_execution_context("s", {}, initial_strategy="web_quick_scan")
        assert self.engine.execution_contexts[cid].current_strategy == "web_quick_scan"

    def test_execution_state_is_planning(self):
        cid = self.engine.create_execution_context("s", {})
        assert self.engine.execution_contexts[cid].execution_state == "planning"

    def test_multiple_contexts_are_independent(self):
        cid1 = self.engine.create_execution_context("s1", {"type": "web"})
        cid2 = self.engine.create_execution_context("s2", {"type": "network"})
        assert cid1 != cid2
        assert len(self.engine.active_contexts) == 2
        assert self.engine.execution_contexts[cid1].target_info["type"] == "web"
        assert self.engine.execution_contexts[cid2].target_info["type"] == "network"


# ===========================================================================
# AdaptiveExecutionEngine._select_optimal_strategy()
# ===========================================================================


class TestSelectOptimalStrategy:
    """Tests for _select_optimal_strategy."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_web_target_returns_web_strategy(self):
        ctx = ExecutionContext(target_info={"type": "web"})
        result = self.engine._select_optimal_strategy(ctx)
        assert result == "web_comprehensive"

    def test_network_target_returns_network_strategy(self):
        ctx = ExecutionContext(target_info={"type": "network"})
        result = self.engine._select_optimal_strategy(ctx)
        assert result == "network_recon"

    def test_database_target_returns_db_strategy(self):
        ctx = ExecutionContext(target_info={"type": "database"})
        result = self.engine._select_optimal_strategy(ctx)
        assert result == "db_discovery"

    def test_unknown_target_returns_general_strategy(self):
        ctx = ExecutionContext(target_info={"type": "unknown"})
        result = self.engine._select_optimal_strategy(ctx)
        assert result == "general_recon"

    def test_missing_type_key_returns_general_strategy(self):
        ctx = ExecutionContext(target_info={})
        result = self.engine._select_optimal_strategy(ctx)
        assert result == "general_recon"

    def test_unrecognized_type_returns_general_strategy(self):
        ctx = ExecutionContext(target_info={"type": "iot_device"})
        result = self.engine._select_optimal_strategy(ctx)
        assert result == "general_recon"


# ===========================================================================
# AdaptiveExecutionEngine._simulate_strategy_execution()
# ===========================================================================


class TestSimulateStrategyExecution:
    """Tests for _simulate_strategy_execution."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_result_contains_strategy_key(self):
        ctx = ExecutionContext()
        result = self.engine._simulate_strategy_execution("test_strat", ctx)
        assert result["strategy"] == "test_strat"

    def test_result_has_required_keys(self):
        ctx = ExecutionContext()
        result = self.engine._simulate_strategy_execution("s", ctx)
        for key in ("strategy", "steps_completed", "total_steps", "execution_time", "findings"):
            assert key in result

    def test_steps_completed_within_range(self):
        ctx = ExecutionContext()
        # random.randint called 3 times: steps_completed, total_steps, findings count
        with patch("random.randint", side_effect=[5, 8, 3]), \
             patch("random.uniform", return_value=80.0):
            result = self.engine._simulate_strategy_execution("s", ctx)
        assert result["steps_completed"] == 5
        assert result["total_steps"] == 8

    def test_execution_time_within_range(self):
        ctx = ExecutionContext()
        # random.randint called 3 times: steps_completed, total_steps, findings count
        with patch("random.randint", side_effect=[4, 7, 2]), \
             patch("random.uniform", return_value=100.5):
            result = self.engine._simulate_strategy_execution("s", ctx)
        assert result["execution_time"] == 100.5

    def test_findings_are_list_of_strings(self):
        ctx = ExecutionContext()
        result = self.engine._simulate_strategy_execution("s", ctx)
        assert isinstance(result["findings"], list)
        for f in result["findings"]:
            assert isinstance(f, str)

    def test_deterministic_with_seeded_random(self):
        ctx = ExecutionContext()
        with patch("random.randint", side_effect=[3, 5, 2]), \
             patch("random.uniform", return_value=60.0):
            result = self.engine._simulate_strategy_execution("s", ctx)
        assert result["steps_completed"] == 3
        assert result["total_steps"] == 5
        assert len(result["findings"]) == 2


# ===========================================================================
# AdaptiveExecutionEngine._evaluate_performance()
# ===========================================================================


class TestEvaluatePerformance:
    """Tests for _evaluate_performance."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_perfect_completion_fast_time(self):
        result = {"steps_completed": 10, "total_steps": 10, "execution_time": 0}
        score = self.engine._evaluate_performance(result)
        # 1.0 * 0.7 + 1.0 * 0.3 = 1.0
        assert score == pytest.approx(1.0)

    def test_zero_completion(self):
        result = {"steps_completed": 0, "total_steps": 10, "execution_time": 0}
        score = self.engine._evaluate_performance(result)
        # 0.0 * 0.7 + 1.0 * 0.3 = 0.3
        assert score == pytest.approx(0.3)

    def test_full_timeout(self):
        result = {"steps_completed": 10, "total_steps": 10, "execution_time": 300}
        score = self.engine._evaluate_performance(result)
        # 1.0 * 0.7 + 0.0 * 0.3 = 0.7
        assert score == pytest.approx(0.7)

    def test_half_completion_half_time(self):
        result = {"steps_completed": 5, "total_steps": 10, "execution_time": 150}
        score = self.engine._evaluate_performance(result)
        # 0.5 * 0.7 + 0.5 * 0.3 = 0.50
        assert score == pytest.approx(0.50)

    def test_zero_total_steps_returns_time_only(self):
        result = {"steps_completed": 0, "total_steps": 0, "execution_time": 150}
        score = self.engine._evaluate_performance(result)
        # completion_score=0, time_eff=0.5 → 0.0*0.7+0.5*0.3=0.15
        assert score == pytest.approx(0.15)

    def test_score_clamped_to_max_1(self):
        # Even if somehow the math exceeded 1.0, it's clamped
        result = {"steps_completed": 10, "total_steps": 10, "execution_time": -100}
        score = self.engine._evaluate_performance(result)
        assert score <= 1.0

    def test_score_clamped_to_min_0(self):
        result = {"steps_completed": 0, "total_steps": 10, "execution_time": 1000}
        score = self.engine._evaluate_performance(result)
        assert score >= 0.0

    def test_execution_time_exceeds_max(self):
        result = {"steps_completed": 5, "total_steps": 10, "execution_time": 600}
        score = self.engine._evaluate_performance(result)
        # time_efficiency = max(0, 1 - 600/300) = max(0, -1) = 0
        # 0.5*0.7 + 0*0.3 = 0.35
        assert score == pytest.approx(0.35)

    def test_missing_keys_use_defaults(self):
        score = self.engine._evaluate_performance({})
        # steps_completed=0, total_steps=1, execution_time=300
        # completion = 0/1 = 0, time_eff = 1-300/300=0
        # 0*0.7 + 0*0.3 = 0.0
        assert score == pytest.approx(0.0)

    def test_custom_max_execution_time(self):
        self.engine.max_execution_time = 100
        result = {"steps_completed": 10, "total_steps": 10, "execution_time": 50}
        score = self.engine._evaluate_performance(result)
        # 1.0*0.7 + 0.5*0.3 = 0.85
        assert score == pytest.approx(0.85)


# ===========================================================================
# AdaptiveExecutionEngine._get_alternative_strategies()
# ===========================================================================


class TestGetAlternativeStrategies:
    """Tests for _get_alternative_strategies."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_web_comprehensive_has_alternatives(self):
        alts = self.engine._get_alternative_strategies("web_comprehensive", "web")
        assert alts == ["web_quick_scan", "web_targeted"]

    def test_network_recon_has_alternatives(self):
        alts = self.engine._get_alternative_strategies("network_recon", "network")
        assert alts == ["network_fast_scan", "network_stealth"]

    def test_general_recon_has_alternatives(self):
        alts = self.engine._get_alternative_strategies("general_recon", "unknown")
        assert alts == ["adaptive_discovery", "minimal_scan"]

    def test_unknown_strategy_returns_general_fallback(self):
        alts = self.engine._get_alternative_strategies("nonexistent_strategy", "web")
        assert alts == ["general_recon"]

    def test_target_type_does_not_affect_mapping(self):
        # The method only looks at current_strategy, not target_type
        alts1 = self.engine._get_alternative_strategies("web_comprehensive", "web")
        alts2 = self.engine._get_alternative_strategies("web_comprehensive", "network")
        assert alts1 == alts2


# ===========================================================================
# AdaptiveExecutionEngine._trigger_adaptation()
# ===========================================================================


class TestTriggerAdaptation:
    """Tests for _trigger_adaptation."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_switches_strategy_when_alternatives_exist(self):
        ctx = ExecutionContext(
            current_strategy="web_comprehensive",
            target_info={"type": "web"}
        )
        result = self.engine._trigger_adaptation(ctx, 0.1)
        assert result["action_type"] == "strategy_switch"
        assert result["new_strategy"] == "web_quick_scan"

    def test_updates_context_strategy(self):
        ctx = ExecutionContext(
            current_strategy="web_comprehensive",
            target_info={"type": "web"}
        )
        self.engine._trigger_adaptation(ctx, 0.2)
        assert ctx.current_strategy == "web_quick_scan"

    def test_sets_execution_state_to_switching(self):
        ctx = ExecutionContext(
            current_strategy="network_recon",
            target_info={"type": "network"}
        )
        self.engine._trigger_adaptation(ctx, 0.1)
        assert ctx.execution_state == "switching"

    def test_appends_adaptation_record(self):
        ctx = ExecutionContext(
            current_strategy="general_recon",
            target_info={}
        )
        assert len(ctx.adaptation_history) == 0
        self.engine._trigger_adaptation(ctx, 0.25)
        assert len(ctx.adaptation_history) == 1
        record = ctx.adaptation_history[0]
        assert record["trigger"] == "low_performance"
        assert record["old_strategy"] == "general_recon"
        assert record["new_strategy"] == "adaptive_discovery"
        assert record["performance_score"] == 0.25

    def test_adaptation_record_has_timestamp(self):
        ctx = ExecutionContext(current_strategy="web_comprehensive", target_info={})
        self.engine._trigger_adaptation(ctx, 0.15)
        record = ctx.adaptation_history[0]
        assert "timestamp" in record
        # Should be a valid ISO format
        datetime.fromisoformat(record["timestamp"])

    def test_reason_contains_performance_score(self):
        ctx = ExecutionContext(current_strategy="network_recon", target_info={})
        result = self.engine._trigger_adaptation(ctx, 0.123)
        assert "0.12" in result["reason"]

    def test_returns_continue_when_unknown_strategy_gets_fallback(self):
        # _get_alternative_strategies returns ["general_recon"] for unknown,
        # so it WILL switch, not continue
        ctx = ExecutionContext(current_strategy="xyz_unknown", target_info={})
        result = self.engine._trigger_adaptation(ctx, 0.1)
        assert result["action_type"] == "strategy_switch"
        assert result["new_strategy"] == "general_recon"

    def test_multiple_adaptations_accumulate_history(self):
        ctx = ExecutionContext(current_strategy="web_comprehensive", target_info={})
        self.engine._trigger_adaptation(ctx, 0.1)
        # After first adaptation, strategy changed to web_quick_scan
        self.engine._trigger_adaptation(ctx, 0.05)
        assert len(ctx.adaptation_history) == 2
        assert ctx.adaptation_history[0]["old_strategy"] == "web_comprehensive"
        assert ctx.adaptation_history[1]["old_strategy"] == "web_quick_scan"


# ===========================================================================
# AdaptiveExecutionEngine.execute_adaptive_strategy()
# ===========================================================================


class TestExecuteAdaptiveStrategy:
    """Tests for execute_adaptive_strategy."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_nonexistent_context_returns_error(self):
        result = self.engine.execute_adaptive_strategy("no-such-id")
        assert result["success"] is False
        assert "error" in result

    def test_success_with_named_strategy(self):
        cid = self.engine.create_execution_context("s", {"type": "web"})
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 10, "total_steps": 10,
                                        "execution_time": 50, "findings": [],
                                        "strategy": "my_strat"}):
            result = self.engine.execute_adaptive_strategy(cid, "my_strat")
        assert result["success"] is True
        assert result["strategy_name"] == "my_strat"

    def test_auto_selects_strategy_when_none_given(self):
        cid = self.engine.create_execution_context("s", {"type": "web"})
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 10, "total_steps": 10,
                                        "execution_time": 50, "findings": [],
                                        "strategy": "web_comprehensive"}):
            result = self.engine.execute_adaptive_strategy(cid)
        assert result["strategy_name"] == "web_comprehensive"

    def test_result_contains_required_keys(self):
        cid = self.engine.create_execution_context("s", {})
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 5, "total_steps": 10,
                                        "execution_time": 100, "findings": [],
                                        "strategy": "x"}):
            result = self.engine.execute_adaptive_strategy(cid, "x")
        for key in ("success", "context_id", "strategy_name", "performance_score",
                     "execution_result", "adaptation_needed", "context_state"):
            assert key in result

    def test_high_performance_no_adaptation(self):
        cid = self.engine.create_execution_context("s", {})
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 10, "total_steps": 10,
                                        "execution_time": 0, "findings": [],
                                        "strategy": "x"}):
            result = self.engine.execute_adaptive_strategy(cid, "x")
        assert result["adaptation_needed"] is False
        assert "adaptation_action" not in result

    def test_low_performance_triggers_adaptation(self):
        cid = self.engine.create_execution_context("s", {"type": "web"})
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 0, "total_steps": 10,
                                        "execution_time": 300, "findings": [],
                                        "strategy": "web_comprehensive"}):
            result = self.engine.execute_adaptive_strategy(cid, "web_comprehensive")
        assert result["adaptation_needed"] is True
        assert "adaptation_action" in result
        assert result["adaptation_action"]["action_type"] == "strategy_switch"

    def test_context_strategy_updated(self):
        cid = self.engine.create_execution_context("s", {"type": "web"})
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 8, "total_steps": 10,
                                        "execution_time": 50, "findings": [],
                                        "strategy": "custom_strat"}):
            self.engine.execute_adaptive_strategy(cid, "custom_strat")
        ctx = self.engine.execution_contexts[cid]
        assert ctx.current_strategy == "custom_strat"

    def test_context_last_updated_is_set(self):
        cid = self.engine.create_execution_context("s", {})
        before = datetime.now()
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 5, "total_steps": 10,
                                        "execution_time": 100, "findings": [],
                                        "strategy": "x"}):
            self.engine.execute_adaptive_strategy(cid, "x")
        after = datetime.now()
        ctx = self.engine.execution_contexts[cid]
        assert before <= ctx.last_updated <= after

    def test_performance_score_is_float(self):
        cid = self.engine.create_execution_context("s", {})
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 5, "total_steps": 10,
                                        "execution_time": 100, "findings": [],
                                        "strategy": "x"}):
            result = self.engine.execute_adaptive_strategy(cid, "x")
        assert isinstance(result["performance_score"], float)

    def test_adaptation_threshold_boundary_exact(self):
        """Score exactly equal to threshold should NOT trigger adaptation."""
        cid = self.engine.create_execution_context("s", {})
        self.engine.adaptation_threshold = 0.5
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 5, "total_steps": 10,
                                        "execution_time": 100, "findings": [],
                                        "strategy": "x"}), \
             patch.object(self.engine, "_evaluate_performance", return_value=0.5):
            result = self.engine.execute_adaptive_strategy(cid, "x")
        # 0.5 < 0.5 is False
        assert result["adaptation_needed"] is False

    def test_adaptation_threshold_boundary_just_below(self):
        """Score just below threshold should trigger adaptation."""
        cid = self.engine.create_execution_context("s", {})
        self.engine.adaptation_threshold = 0.5
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 5, "total_steps": 10,
                                        "execution_time": 100, "findings": [],
                                        "strategy": "x"}), \
             patch.object(self.engine, "_evaluate_performance", return_value=0.499):
            result = self.engine.execute_adaptive_strategy(cid, "x")
        assert result["adaptation_needed"] is True


# ===========================================================================
# AdaptiveExecutionEngine.get_execution_status()
# ===========================================================================


class TestGetExecutionStatus:
    """Tests for get_execution_status."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_nonexistent_context_returns_error(self):
        result = self.engine.get_execution_status("no-such-id")
        assert "error" in result

    def test_returns_correct_context_id(self):
        cid = self.engine.create_execution_context("s", {})
        status = self.engine.get_execution_status(cid)
        assert status["context_id"] == cid

    def test_returns_session_id(self):
        cid = self.engine.create_execution_context("sess-99", {})
        status = self.engine.get_execution_status(cid)
        assert status["session_id"] == "sess-99"

    def test_returns_current_strategy(self):
        cid = self.engine.create_execution_context("s", {}, initial_strategy="fast")
        status = self.engine.get_execution_status(cid)
        assert status["current_strategy"] == "fast"

    def test_returns_execution_state(self):
        cid = self.engine.create_execution_context("s", {})
        status = self.engine.get_execution_status(cid)
        assert status["execution_state"] == "planning"

    def test_adaptation_count_zero_initially(self):
        cid = self.engine.create_execution_context("s", {})
        status = self.engine.get_execution_status(cid)
        assert status["adaptation_count"] == 0

    def test_adaptation_count_after_adaptation(self):
        cid = self.engine.create_execution_context("s", {"type": "web"})
        ctx = self.engine.execution_contexts[cid]
        ctx.adaptation_history.append({"trigger": "test"})
        ctx.adaptation_history.append({"trigger": "test2"})
        status = self.engine.get_execution_status(cid)
        assert status["adaptation_count"] == 2

    def test_last_updated_is_iso_format(self):
        cid = self.engine.create_execution_context("s", {})
        status = self.engine.get_execution_status(cid)
        # Should parse without error
        datetime.fromisoformat(status["last_updated"])

    def test_performance_metrics_returned(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        ctx.performance_metrics = {"cpu": 0.8}
        status = self.engine.get_execution_status(cid)
        assert status["performance_metrics"] == {"cpu": 0.8}


# ===========================================================================
# AdaptiveExecutionEngine.get_adaptation_insights()
# ===========================================================================


class TestGetAdaptationInsights:
    """Tests for get_adaptation_insights."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_nonexistent_context_returns_error(self):
        result = self.engine.get_adaptation_insights("no-such-id")
        assert "error" in result

    def test_empty_history_returns_zero_adaptations(self):
        cid = self.engine.create_execution_context("s", {})
        result = self.engine.get_adaptation_insights(cid)
        assert result["insights"]["total_adaptations"] == 0
        assert result["insights"]["strategy_switches"] == 0
        assert result["insights"]["adaptation_triggers"] == []
        assert result["insights"]["performance_trend"] == "stable"

    def test_tracks_adaptation_triggers(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        ctx.adaptation_history.append({"trigger": "low_performance"})
        ctx.adaptation_history.append({"trigger": "timeout"})
        result = self.engine.get_adaptation_insights(cid)
        assert result["insights"]["adaptation_triggers"] == ["low_performance", "timeout"]

    def test_counts_strategy_switches(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        ctx.adaptation_history.append(
            {"trigger": "low_performance", "action_type": "strategy_switch"}
        )
        ctx.adaptation_history.append(
            {"trigger": "timeout", "action_type": "continue"}
        )
        ctx.adaptation_history.append(
            {"trigger": "low_performance", "action_type": "strategy_switch"}
        )
        result = self.engine.get_adaptation_insights(cid)
        assert result["insights"]["strategy_switches"] == 2

    def test_returns_last_five_records(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        for i in range(10):
            ctx.adaptation_history.append({"trigger": f"trigger_{i}"})
        result = self.engine.get_adaptation_insights(cid)
        assert len(result["adaptation_history"]) == 5
        # Should be the last 5
        assert result["adaptation_history"][0]["trigger"] == "trigger_5"
        assert result["adaptation_history"][4]["trigger"] == "trigger_9"

    def test_fewer_than_five_records_returns_all(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        ctx.adaptation_history.append({"trigger": "t1"})
        ctx.adaptation_history.append({"trigger": "t2"})
        result = self.engine.get_adaptation_insights(cid)
        assert len(result["adaptation_history"]) == 2

    def test_message_contains_adaptation_count(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        for _ in range(3):
            ctx.adaptation_history.append({"trigger": "x"})
        result = self.engine.get_adaptation_insights(cid)
        assert "3" in result["message"]

    def test_context_id_in_result(self):
        cid = self.engine.create_execution_context("s", {})
        result = self.engine.get_adaptation_insights(cid)
        assert result["context_id"] == cid

    def test_missing_trigger_key_defaults_to_unknown(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        ctx.adaptation_history.append({"something_else": "val"})
        result = self.engine.get_adaptation_insights(cid)
        assert result["insights"]["adaptation_triggers"] == ["unknown"]

    def test_record_without_action_type_not_counted_as_switch(self):
        cid = self.engine.create_execution_context("s", {})
        ctx = self.engine.execution_contexts[cid]
        ctx.adaptation_history.append({"trigger": "x"})  # no action_type
        result = self.engine.get_adaptation_insights(cid)
        assert result["insights"]["strategy_switches"] == 0


# ===========================================================================
# Global singleton
# ===========================================================================


class TestGlobalSingleton:
    """Tests for the module-level adaptive_execution_engine instance."""

    def test_is_instance_of_engine(self):
        assert isinstance(adaptive_execution_engine, AdaptiveExecutionEngine)

    def test_singleton_is_importable(self):
        from kali_mcp.core.adaptive_exec_engine import adaptive_execution_engine as ae
        assert ae is adaptive_execution_engine

    def test_singleton_has_empty_initial_state(self):
        # Note: other tests might mutate it, but these attributes should exist
        assert hasattr(adaptive_execution_engine, "execution_contexts")
        assert hasattr(adaptive_execution_engine, "active_contexts")
        assert hasattr(adaptive_execution_engine, "adaptation_threshold")
        assert hasattr(adaptive_execution_engine, "max_execution_time")
        assert hasattr(adaptive_execution_engine, "strategy_performance_history")


# ===========================================================================
# Integration-style pure unit tests (no I/O, no subprocess)
# ===========================================================================


class TestFullWorkflow:
    """End-to-end workflow tests using only mock/patch — no external deps."""

    def setup_method(self):
        self.engine = AdaptiveExecutionEngine()

    def test_create_execute_status_insights_workflow(self):
        """Full lifecycle: create → execute → status → insights."""
        cid = self.engine.create_execution_context("session-1", {"type": "web"})

        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 8, "total_steps": 10,
                                        "execution_time": 60, "findings": ["vuln-1"],
                                        "strategy": "web_comprehensive"}):
            exec_result = self.engine.execute_adaptive_strategy(cid)
        assert exec_result["success"] is True

        status = self.engine.get_execution_status(cid)
        assert status["execution_state"] == "executing"

        insights = self.engine.get_adaptation_insights(cid)
        assert insights["insights"]["total_adaptations"] == 0

    def test_adaptation_switches_strategy_and_records_history(self):
        """Low performance triggers adaptation; verify state changes."""
        cid = self.engine.create_execution_context("s", {"type": "web"})

        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 0, "total_steps": 10,
                                        "execution_time": 299, "findings": [],
                                        "strategy": "web_comprehensive"}):
            result = self.engine.execute_adaptive_strategy(cid, "web_comprehensive")

        assert result["adaptation_needed"] is True

        ctx = self.engine.execution_contexts[cid]
        assert ctx.execution_state == "switching"
        assert len(ctx.adaptation_history) == 1
        assert ctx.adaptation_history[0]["old_strategy"] == "web_comprehensive"

    def test_multiple_executions_accumulate_state(self):
        """Multiple executions on the same context accumulate correctly."""
        cid = self.engine.create_execution_context("s", {"type": "network"})

        # First execution — high performance
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 10, "total_steps": 10,
                                        "execution_time": 30, "findings": ["f1"],
                                        "strategy": "network_recon"}):
            r1 = self.engine.execute_adaptive_strategy(cid, "network_recon")
        assert r1["adaptation_needed"] is False

        # Second execution — low performance
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 1, "total_steps": 10,
                                        "execution_time": 290, "findings": [],
                                        "strategy": "network_recon"}):
            r2 = self.engine.execute_adaptive_strategy(cid, "network_recon")
        assert r2["adaptation_needed"] is True

        insights = self.engine.get_adaptation_insights(cid)
        assert insights["insights"]["total_adaptations"] == 1

    def test_custom_adaptation_threshold(self):
        """Verify custom threshold changes adaptation behavior."""
        self.engine.adaptation_threshold = 0.9
        cid = self.engine.create_execution_context("s", {})

        # Score of 0.7 would normally not trigger adaptation at 0.3 threshold
        with patch.object(self.engine, "_simulate_strategy_execution",
                          return_value={"steps_completed": 8, "total_steps": 10,
                                        "execution_time": 60, "findings": [],
                                        "strategy": "x"}):
            result = self.engine.execute_adaptive_strategy(cid, "x")

        # But with 0.9 threshold, 0.7-ish score triggers it
        assert result["adaptation_needed"] is True
