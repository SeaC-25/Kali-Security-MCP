"""
Tests for MCP Session (kali_mcp/core/mcp_session.py)

Covers:
- SessionContext dataclass: defaults, UUID generation, mutable default independence,
  update_interaction(), add_conversation(), get_context_summary()
- StrategyEngine: strategy catalogue, analyze_context() indicator/confidence logic,
  get_strategy_tools(), update_strategy_effectiveness()
"""

import time
import uuid
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from kali_mcp.core.mcp_session import SessionContext, StrategyEngine


# ---------------------------------------------------------------------------
# SessionContext
# ---------------------------------------------------------------------------

class TestSessionContextDefaults:
    """Verify every default field on a freshly constructed SessionContext."""

    def test_session_id_is_valid_uuid(self):
        ctx = SessionContext()
        # Should not raise
        parsed = uuid.UUID(ctx.session_id)
        assert str(parsed) == ctx.session_id

    def test_each_instance_gets_unique_session_id(self):
        ids = {SessionContext().session_id for _ in range(20)}
        assert len(ids) == 20

    def test_default_target_empty(self):
        assert SessionContext().target == ""

    def test_default_attack_mode(self):
        assert SessionContext().attack_mode == "pentest"

    def test_default_start_time_is_recent(self):
        before = datetime.now()
        ctx = SessionContext()
        after = datetime.now()
        assert before <= ctx.start_time <= after

    def test_default_conversation_history_empty_list(self):
        assert SessionContext().conversation_history == []

    def test_default_discovered_assets_empty_dict(self):
        assert SessionContext().discovered_assets == {}

    def test_default_completed_tasks_empty_list(self):
        assert SessionContext().completed_tasks == []

    def test_default_current_strategy_none(self):
        assert SessionContext().current_strategy is None

    def test_default_context_metadata_empty_dict(self):
        assert SessionContext().context_metadata == {}

    def test_default_last_interaction_is_recent(self):
        before = datetime.now()
        ctx = SessionContext()
        after = datetime.now()
        assert before <= ctx.last_interaction <= after


class TestSessionContextMutableDefaultIndependence:
    """Mutating mutable defaults on one instance must NOT affect another."""

    def test_conversation_history_independence(self):
        a = SessionContext()
        b = SessionContext()
        a.conversation_history.append({"msg": "x"})
        assert b.conversation_history == []

    def test_discovered_assets_independence(self):
        a = SessionContext()
        b = SessionContext()
        a.discovered_assets["host"] = "10.0.0.1"
        assert b.discovered_assets == {}

    def test_completed_tasks_independence(self):
        a = SessionContext()
        b = SessionContext()
        a.completed_tasks.append("scan")
        assert b.completed_tasks == []

    def test_context_metadata_independence(self):
        a = SessionContext()
        b = SessionContext()
        a.context_metadata["key"] = "val"
        assert b.context_metadata == {}


class TestSessionContextCustomInit:
    """Verify explicit field overrides work correctly."""

    def test_custom_target_and_mode(self):
        ctx = SessionContext(target="10.0.0.1", attack_mode="ctf")
        assert ctx.target == "10.0.0.1"
        assert ctx.attack_mode == "ctf"

    def test_custom_strategy(self):
        ctx = SessionContext(current_strategy="web_comprehensive")
        assert ctx.current_strategy == "web_comprehensive"

    def test_custom_metadata(self):
        meta = {"scope": "internal"}
        ctx = SessionContext(context_metadata=meta)
        assert ctx.context_metadata == {"scope": "internal"}


class TestSessionContextUpdateInteraction:
    """Tests for update_interaction()."""

    def test_updates_last_interaction_to_now(self):
        ctx = SessionContext()
        old = ctx.last_interaction
        # Small sleep to guarantee time difference
        time.sleep(0.01)
        ctx.update_interaction()
        assert ctx.last_interaction > old

    def test_update_interaction_only_changes_last_interaction(self):
        ctx = SessionContext(target="host", attack_mode="ctf")
        original_target = ctx.target
        original_mode = ctx.attack_mode
        original_start = ctx.start_time
        ctx.update_interaction()
        assert ctx.target == original_target
        assert ctx.attack_mode == original_mode
        assert ctx.start_time == original_start


class TestSessionContextAddConversation:
    """Tests for add_conversation()."""

    def test_appends_to_conversation_history(self):
        ctx = SessionContext()
        ctx.add_conversation("hello", "hi there")
        assert len(ctx.conversation_history) == 1

    def test_multiple_conversations_append_in_order(self):
        ctx = SessionContext()
        ctx.add_conversation("msg1", "resp1")
        ctx.add_conversation("msg2", "resp2")
        ctx.add_conversation("msg3", "resp3")
        assert len(ctx.conversation_history) == 3
        assert ctx.conversation_history[0]["user_message"] == "msg1"
        assert ctx.conversation_history[2]["user_message"] == "msg3"

    def test_entry_contains_user_message(self):
        ctx = SessionContext()
        ctx.add_conversation("scan target", "scanning...")
        assert ctx.conversation_history[0]["user_message"] == "scan target"

    def test_entry_contains_ai_response(self):
        ctx = SessionContext()
        ctx.add_conversation("scan", "result here")
        assert ctx.conversation_history[0]["ai_response"] == "result here"

    def test_entry_contains_tools_used_when_provided(self):
        ctx = SessionContext()
        ctx.add_conversation("scan", "ok", tools_used=["nmap", "gobuster"])
        assert ctx.conversation_history[0]["tools_used"] == ["nmap", "gobuster"]

    def test_tools_used_defaults_to_empty_list(self):
        ctx = SessionContext()
        ctx.add_conversation("scan", "ok")
        assert ctx.conversation_history[0]["tools_used"] == []

    def test_tools_used_none_becomes_empty_list(self):
        ctx = SessionContext()
        ctx.add_conversation("scan", "ok", tools_used=None)
        assert ctx.conversation_history[0]["tools_used"] == []

    def test_entry_has_timestamp_string(self):
        ctx = SessionContext()
        ctx.add_conversation("a", "b")
        ts = ctx.conversation_history[0]["timestamp"]
        assert isinstance(ts, str)
        # Should be parseable as ISO datetime
        datetime.fromisoformat(ts)

    def test_entry_contains_session_context_snapshot(self):
        ctx = SessionContext(target="10.0.0.1", current_strategy="web_comprehensive")
        ctx.discovered_assets["web"] = ["http://10.0.0.1"]
        ctx.add_conversation("scan", "done")
        sc = ctx.conversation_history[0]["session_context"]
        assert sc["target"] == "10.0.0.1"
        assert sc["strategy"] == "web_comprehensive"
        assert sc["discovered_assets"] == 1

    def test_session_context_discovered_assets_count_updates(self):
        ctx = SessionContext()
        ctx.add_conversation("a", "b")
        assert ctx.conversation_history[0]["session_context"]["discovered_assets"] == 0
        ctx.discovered_assets["host1"] = "10.0.0.1"
        ctx.discovered_assets["host2"] = "10.0.0.2"
        ctx.add_conversation("c", "d")
        assert ctx.conversation_history[1]["session_context"]["discovered_assets"] == 2

    def test_add_conversation_updates_last_interaction(self):
        ctx = SessionContext()
        old = ctx.last_interaction
        time.sleep(0.01)
        ctx.add_conversation("x", "y")
        assert ctx.last_interaction > old


class TestSessionContextGetContextSummary:
    """Tests for get_context_summary()."""

    def test_returns_dict(self):
        ctx = SessionContext()
        summary = ctx.get_context_summary()
        assert isinstance(summary, dict)

    def test_summary_contains_all_expected_keys(self):
        ctx = SessionContext()
        summary = ctx.get_context_summary()
        expected_keys = {
            "session_id", "target", "attack_mode", "duration",
            "total_conversations", "discovered_assets", "completed_tasks",
            "current_strategy", "last_interaction"
        }
        assert set(summary.keys()) == expected_keys

    def test_session_id_matches(self):
        ctx = SessionContext()
        assert ctx.get_context_summary()["session_id"] == ctx.session_id

    def test_target_matches(self):
        ctx = SessionContext(target="example.com")
        assert ctx.get_context_summary()["target"] == "example.com"

    def test_attack_mode_matches(self):
        ctx = SessionContext(attack_mode="ctf")
        assert ctx.get_context_summary()["attack_mode"] == "ctf"

    def test_duration_is_string(self):
        ctx = SessionContext()
        assert isinstance(ctx.get_context_summary()["duration"], str)

    def test_total_conversations_count(self):
        ctx = SessionContext()
        ctx.add_conversation("a", "b")
        ctx.add_conversation("c", "d")
        assert ctx.get_context_summary()["total_conversations"] == 2

    def test_discovered_assets_count(self):
        ctx = SessionContext()
        ctx.discovered_assets["a"] = 1
        ctx.discovered_assets["b"] = 2
        ctx.discovered_assets["c"] = 3
        assert ctx.get_context_summary()["discovered_assets"] == 3

    def test_completed_tasks_count(self):
        ctx = SessionContext()
        ctx.completed_tasks.extend(["port_scan", "web_scan"])
        assert ctx.get_context_summary()["completed_tasks"] == 2

    def test_current_strategy_none_by_default(self):
        ctx = SessionContext()
        assert ctx.get_context_summary()["current_strategy"] is None

    def test_current_strategy_reflected(self):
        ctx = SessionContext(current_strategy="network_recon")
        assert ctx.get_context_summary()["current_strategy"] == "network_recon"

    def test_last_interaction_is_isoformat(self):
        ctx = SessionContext()
        iso = ctx.get_context_summary()["last_interaction"]
        assert isinstance(iso, str)
        datetime.fromisoformat(iso)

    def test_summary_with_empty_session(self):
        ctx = SessionContext()
        summary = ctx.get_context_summary()
        assert summary["total_conversations"] == 0
        assert summary["discovered_assets"] == 0
        assert summary["completed_tasks"] == 0


# ---------------------------------------------------------------------------
# StrategyEngine
# ---------------------------------------------------------------------------

class TestStrategyEngineInit:
    """Verify the strategy catalogue created at init."""

    @pytest.fixture
    def engine(self):
        return StrategyEngine()

    def test_has_exactly_five_strategies(self, engine):
        assert len(engine.strategies) == 5

    def test_strategy_names(self, engine):
        expected = {
            "web_comprehensive", "ctf_quick_solve", "network_recon",
            "pwn_exploitation", "adaptive_multi"
        }
        assert set(engine.strategies.keys()) == expected

    @pytest.mark.parametrize("name", [
        "web_comprehensive", "ctf_quick_solve", "network_recon",
        "pwn_exploitation", "adaptive_multi"
    ])
    def test_each_strategy_has_required_keys(self, engine, name):
        s = engine.strategies[name]
        for key in ("description", "tools", "conditions", "complexity", "estimated_time"):
            assert key in s, f"Strategy '{name}' missing key '{key}'"

    @pytest.mark.parametrize("name", [
        "web_comprehensive", "ctf_quick_solve", "network_recon",
        "pwn_exploitation", "adaptive_multi"
    ])
    def test_each_strategy_tools_is_nonempty_list(self, engine, name):
        tools = engine.strategies[name]["tools"]
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_web_comprehensive_tools(self, engine):
        tools = engine.strategies["web_comprehensive"]["tools"]
        assert "nmap_scan" in tools
        assert "sqlmap_scan" in tools

    def test_ctf_quick_solve_tools(self, engine):
        tools = engine.strategies["ctf_quick_solve"]["tools"]
        assert "ctf_quick_scan" in tools
        assert "get_detected_flags" in tools

    def test_pwn_exploitation_tools(self, engine):
        tools = engine.strategies["pwn_exploitation"]["tools"]
        assert "pwnpasi_auto_pwn" in tools

    def test_separate_engine_instances_are_independent(self):
        a = StrategyEngine()
        b = StrategyEngine()
        a.strategies["web_comprehensive"]["description"] = "modified"
        assert b.strategies["web_comprehensive"]["description"] != "modified"


class TestStrategyEngineGetStrategyTools:
    """Tests for get_strategy_tools()."""

    @pytest.fixture
    def engine(self):
        return StrategyEngine()

    @pytest.mark.parametrize("name", [
        "web_comprehensive", "ctf_quick_solve", "network_recon",
        "pwn_exploitation", "adaptive_multi"
    ])
    def test_returns_tools_for_valid_strategy(self, engine, name):
        tools = engine.get_strategy_tools(name)
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_returns_empty_list_for_unknown_strategy(self, engine):
        assert engine.get_strategy_tools("nonexistent") == []

    def test_returns_empty_list_for_empty_string(self, engine):
        assert engine.get_strategy_tools("") == []

    def test_returns_same_tools_as_direct_access(self, engine):
        for name in engine.strategies:
            assert engine.get_strategy_tools(name) == engine.strategies[name]["tools"]


class TestStrategyEngineAnalyzeContext:
    """Tests for analyze_context() — indicator detection, confidence, recommendations."""

    @pytest.fixture
    def engine(self):
        return StrategyEngine()

    # --- Return structure ---

    def test_returns_dict_with_expected_keys(self, engine):
        session = SessionContext()
        result = engine.analyze_context(session, "hello")
        expected = {"context_indicators", "recommended_strategies",
                    "confidence_scores", "target_analysis"}
        assert set(result.keys()) == expected

    def test_context_indicators_is_list(self, engine):
        session = SessionContext()
        result = engine.analyze_context(session, "hello")
        assert isinstance(result["context_indicators"], list)

    def test_recommended_strategies_is_list(self, engine):
        session = SessionContext()
        result = engine.analyze_context(session, "hello")
        assert isinstance(result["recommended_strategies"], list)

    def test_confidence_scores_is_dict(self, engine):
        session = SessionContext()
        result = engine.analyze_context(session, "hello")
        assert isinstance(result["confidence_scores"], dict)

    # --- Web indicators (checked against target.lower()) ---

    @pytest.mark.parametrize("target", [
        "http://example.com",
        "https://www.site.org",
        "www.test.com",
        "some.org/path",
        "web application at host",
    ])
    def test_web_indicator_detected(self, engine, target):
        session = SessionContext(target=target)
        result = engine.analyze_context(session, "scan it")
        assert "web_service_detected" in result["context_indicators"]
        assert result["confidence_scores"].get("web_comprehensive") == 0.8

    def test_web_indicator_case_insensitive(self, engine):
        session = SessionContext(target="HTTP://EXAMPLE.COM")
        result = engine.analyze_context(session, "scan")
        assert "web_service_detected" in result["context_indicators"]

    # --- CTF indicators (checked against user_input.lower()) ---

    @pytest.mark.parametrize("user_input", [
        "this is a ctf challenge",
        "find the flag",
        "solve this CTF Challenge",
        "解题 this problem",
    ])
    def test_ctf_indicator_detected(self, engine, user_input):
        session = SessionContext(target="something")
        result = engine.analyze_context(session, user_input)
        assert "ctf_mode" in result["context_indicators"]
        assert result["confidence_scores"].get("ctf_quick_solve") == 0.9

    def test_ctf_indicator_case_insensitive(self, engine):
        session = SessionContext()
        result = engine.analyze_context(session, "CTF FLAG")
        assert "ctf_mode" in result["context_indicators"]

    # --- Binary indicators (checked against user_input.lower()) ---

    @pytest.mark.parametrize("user_input", [
        "analyze this .exe file",
        "this is a binary exploitation",
        "pwn this program",
        "二进制 analysis",
    ])
    def test_binary_indicator_detected(self, engine, user_input):
        session = SessionContext()
        result = engine.analyze_context(session, user_input)
        assert "binary_file" in result["context_indicators"]
        assert result["confidence_scores"].get("pwn_exploitation") == 0.8

    # --- IP target indicator (regex on target) ---

    @pytest.mark.parametrize("target", [
        "192.168.1.100",
        "10.0.0.1",
        "172.16.0.50",
        "scan 192.168.1.1 now",
    ])
    def test_ip_indicator_detected(self, engine, target):
        session = SessionContext(target=target)
        result = engine.analyze_context(session, "scan it")
        assert "ip_target" in result["context_indicators"]
        assert result["confidence_scores"].get("network_recon") == 0.7

    def test_no_ip_indicator_for_non_ip(self, engine):
        session = SessionContext(target="example.com")
        result = engine.analyze_context(session, "scan it")
        assert "ip_target" not in result["context_indicators"]

    # --- Unknown / fallback indicator ---

    def test_unknown_target_when_no_indicators(self, engine):
        session = SessionContext(target="random_string_no_match")
        result = engine.analyze_context(session, "do something")
        assert "unknown_target" in result["context_indicators"]
        assert result["confidence_scores"].get("adaptive_multi") == 0.6

    def test_unknown_target_with_bu_zhidao(self, engine):
        """'不知道' in user_input forces unknown_target even if other indicators exist."""
        session = SessionContext(target="http://example.com")
        result = engine.analyze_context(session, "不知道怎么做")
        assert "unknown_target" in result["context_indicators"]

    # --- Target fallback to user_input when session.target is empty ---

    def test_empty_target_uses_user_input_for_detection(self, engine):
        session = SessionContext(target="")
        result = engine.analyze_context(session, "http://example.com")
        assert "web_service_detected" in result["context_indicators"]

    def test_empty_target_ip_in_user_input(self, engine):
        session = SessionContext(target="")
        result = engine.analyze_context(session, "192.168.1.1")
        assert "ip_target" in result["context_indicators"]

    # --- Multiple indicators can coexist ---

    def test_web_and_ctf_together(self, engine):
        session = SessionContext(target="http://ctf.example.com")
        result = engine.analyze_context(session, "ctf flag challenge")
        assert "web_service_detected" in result["context_indicators"]
        assert "ctf_mode" in result["context_indicators"]

    def test_web_and_ip_together(self, engine):
        session = SessionContext(target="http://192.168.1.1")
        result = engine.analyze_context(session, "scan web")
        assert "web_service_detected" in result["context_indicators"]
        assert "ip_target" in result["context_indicators"]

    def test_ctf_and_binary_together(self, engine):
        session = SessionContext(target="")
        result = engine.analyze_context(session, "ctf pwn challenge")
        assert "ctf_mode" in result["context_indicators"]
        assert "binary_file" in result["context_indicators"]

    def test_all_indicators_at_once(self, engine):
        session = SessionContext(target="http://192.168.1.1")
        result = engine.analyze_context(session, "ctf pwn flag 不知道")
        indicators = result["context_indicators"]
        assert "web_service_detected" in indicators
        assert "ip_target" in indicators
        assert "ctf_mode" in indicators
        assert "binary_file" in indicators
        assert "unknown_target" in indicators

    # --- Recommended strategies sorting and limiting ---

    def test_recommended_strategies_limited_to_3(self, engine):
        # Trigger all 5 confidence entries
        session = SessionContext(target="http://192.168.1.1")
        result = engine.analyze_context(session, "ctf pwn flag 不知道")
        assert len(result["recommended_strategies"]) <= 3

    def test_recommended_strategies_sorted_by_confidence_desc(self, engine):
        session = SessionContext(target="http://192.168.1.1")
        result = engine.analyze_context(session, "ctf flag")
        recs = result["recommended_strategies"]
        if len(recs) >= 2:
            confidences = [r["confidence"] for r in recs]
            assert confidences == sorted(confidences, reverse=True)

    def test_recommended_strategy_entry_structure(self, engine):
        session = SessionContext(target="http://example.com")
        result = engine.analyze_context(session, "scan web")
        for rec in result["recommended_strategies"]:
            assert "strategy" in rec
            assert "confidence" in rec
            assert "details" in rec
            assert isinstance(rec["details"], dict)

    def test_ctf_has_highest_confidence(self, engine):
        """CTF confidence (0.9) should rank above web (0.8) and others."""
        session = SessionContext(target="http://example.com")
        result = engine.analyze_context(session, "ctf flag")
        recs = result["recommended_strategies"]
        assert recs[0]["strategy"] == "ctf_quick_solve"
        assert recs[0]["confidence"] == 0.9

    def test_single_indicator_single_recommendation(self, engine):
        session = SessionContext(target="random_no_match")
        result = engine.analyze_context(session, "do something")
        assert len(result["recommended_strategies"]) == 1
        assert result["recommended_strategies"][0]["strategy"] == "adaptive_multi"


class TestStrategyEngineUpdateEffectiveness:
    """Tests for update_strategy_effectiveness()."""

    @pytest.fixture
    def engine(self):
        return StrategyEngine()

    def test_creates_effectiveness_list_on_first_call(self, engine):
        assert "effectiveness" not in engine.strategies["web_comprehensive"]
        engine.update_strategy_effectiveness("web_comprehensive", 0.85)
        assert "effectiveness" in engine.strategies["web_comprehensive"]
        assert engine.strategies["web_comprehensive"]["effectiveness"] == [0.85]

    def test_appends_to_existing_effectiveness(self, engine):
        engine.update_strategy_effectiveness("web_comprehensive", 0.7)
        engine.update_strategy_effectiveness("web_comprehensive", 0.9)
        engine.update_strategy_effectiveness("web_comprehensive", 0.5)
        assert engine.strategies["web_comprehensive"]["effectiveness"] == [0.7, 0.9, 0.5]

    def test_unknown_strategy_does_nothing(self, engine):
        original_keys = set(engine.strategies.keys())
        engine.update_strategy_effectiveness("nonexistent_strategy", 0.99)
        assert set(engine.strategies.keys()) == original_keys
        assert "nonexistent_strategy" not in engine.strategies

    def test_different_strategies_independent(self, engine):
        engine.update_strategy_effectiveness("web_comprehensive", 0.8)
        engine.update_strategy_effectiveness("ctf_quick_solve", 0.95)
        assert engine.strategies["web_comprehensive"]["effectiveness"] == [0.8]
        assert engine.strategies["ctf_quick_solve"]["effectiveness"] == [0.95]

    def test_boundary_values(self, engine):
        engine.update_strategy_effectiveness("network_recon", 0.0)
        engine.update_strategy_effectiveness("network_recon", 1.0)
        assert engine.strategies["network_recon"]["effectiveness"] == [0.0, 1.0]

    @pytest.mark.parametrize("name", [
        "web_comprehensive", "ctf_quick_solve", "network_recon",
        "pwn_exploitation", "adaptive_multi"
    ])
    def test_all_valid_strategies_accept_update(self, engine, name):
        engine.update_strategy_effectiveness(name, 0.5)
        assert engine.strategies[name]["effectiveness"] == [0.5]
