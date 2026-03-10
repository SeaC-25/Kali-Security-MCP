"""
Tests for strategy module (kali_mcp/core/strategy.py)

Covers:
- StrategyType enum
- StrategyStep: creation, to_dict
- Strategy: creation, get_success_rate, update_stats, to_dict
- StrategyEngine: init, register, get, list, recommend, select,
  record_execution, get_execution_history, get_stats
"""

import pytest

from kali_mcp.core.strategy import (
    StrategyType,
    StrategyStep,
    Strategy,
    StrategyEngine,
)


# ===================== StrategyType Tests =====================

class TestStrategyType:
    def test_values(self):
        assert StrategyType.RECONNAISSANCE.value == "reconnaissance"
        assert StrategyType.WEB_ATTACK.value == "web_attack"
        assert StrategyType.NETWORK_ATTACK.value == "network_attack"
        assert StrategyType.PASSWORD_ATTACK.value == "password_attack"
        assert StrategyType.EXPLOIT.value == "exploit"
        assert StrategyType.POST_EXPLOITATION.value == "post_exploitation"
        assert StrategyType.CTF_SOLVE.value == "ctf_solve"
        assert StrategyType.APT_CAMPAIGN.value == "apt_campaign"


# ===================== StrategyStep Tests =====================

class TestStrategyStep:
    def test_creation(self):
        step = StrategyStep(name="Port scan", tool="nmap_scan")
        assert step.name == "Port scan"
        assert step.tool == "nmap_scan"
        assert step.parameters == {}
        assert step.condition is None
        assert step.parallel is False
        assert step.timeout == 300
        assert step.required is True

    def test_creation_with_all_params(self):
        step = StrategyStep(
            name="SQL injection",
            tool="sqlmap_scan",
            parameters={"level": "2"},
            condition="has_forms",
            parallel=True,
            timeout=600,
            required=False
        )
        assert step.condition == "has_forms"
        assert step.parallel is True
        assert step.timeout == 600
        assert step.required is False

    def test_to_dict(self):
        step = StrategyStep(
            name="Scan", tool="nmap",
            parameters={"ports": "80"}, condition="always",
            parallel=True, timeout=120, required=False
        )
        d = step.to_dict()
        assert d["name"] == "Scan"
        assert d["tool"] == "nmap"
        assert d["parameters"]["ports"] == "80"
        assert d["condition"] == "always"
        assert d["parallel"] is True
        assert d["timeout"] == 120
        assert d["required"] is False


# ===================== Strategy Tests =====================

class TestStrategy:
    def test_creation(self):
        s = Strategy(
            strategy_id="test",
            name="Test Strategy",
            description="A test",
            strategy_type=StrategyType.RECONNAISSANCE,
        )
        assert s.strategy_id == "test"
        assert s.strategy_type == StrategyType.RECONNAISSANCE
        assert s.steps == []
        assert s.success_count == 0
        assert s.failure_count == 0

    def test_get_success_rate_default(self):
        s = Strategy("s", "n", "d", StrategyType.WEB_ATTACK)
        assert s.get_success_rate() == 0.5  # Default when no data

    def test_get_success_rate_with_data(self):
        s = Strategy("s", "n", "d", StrategyType.WEB_ATTACK)
        s.success_count = 3
        s.failure_count = 1
        assert s.get_success_rate() == 0.75

    def test_get_success_rate_all_failures(self):
        s = Strategy("s", "n", "d", StrategyType.WEB_ATTACK)
        s.failure_count = 5
        assert s.get_success_rate() == 0.0

    def test_update_stats_success(self):
        s = Strategy("s", "n", "d", StrategyType.WEB_ATTACK)
        s.update_stats(True, 10.0)
        assert s.success_count == 1
        assert s.failure_count == 0
        assert s.avg_execution_time == 10.0

    def test_update_stats_failure(self):
        s = Strategy("s", "n", "d", StrategyType.WEB_ATTACK)
        s.update_stats(False, 5.0)
        assert s.success_count == 0
        assert s.failure_count == 1
        assert s.avg_execution_time == 5.0

    def test_update_stats_sliding_average(self):
        s = Strategy("s", "n", "d", StrategyType.WEB_ATTACK)
        s.update_stats(True, 10.0)
        s.update_stats(True, 20.0)
        assert s.avg_execution_time == 15.0  # (10+20)/2

    def test_to_dict(self):
        s = Strategy(
            strategy_id="web1",
            name="Web Scan",
            description="Comprehensive web scan",
            strategy_type=StrategyType.WEB_ATTACK,
            target_types=["web"],
            tags=["comprehensive"],
            steps=[StrategyStep("Scan", "nmap")]
        )
        d = s.to_dict()
        assert d["id"] == "web1"
        assert d["name"] == "Web Scan"
        assert d["type"] == "web_attack"
        assert d["target_types"] == ["web"]
        assert d["tags"] == ["comprehensive"]
        assert len(d["steps"]) == 1
        assert d["success_rate"] == 0.5  # Default


# ===================== StrategyEngine Tests =====================

class TestStrategyEngineInit:
    def test_init_has_builtin_strategies(self):
        engine = StrategyEngine()
        assert len(engine._strategies) >= 6  # 6 builtin

    def test_builtin_strategy_ids(self):
        engine = StrategyEngine()
        assert "web_comprehensive" in engine._strategies
        assert "network_pentest" in engine._strategies
        assert "ctf_quick_solve" in engine._strategies
        assert "password_attack" in engine._strategies
        assert "apt_simulation" in engine._strategies
        assert "recon_comprehensive" in engine._strategies


class TestStrategyEngineRegister:
    def test_register_strategy(self):
        engine = StrategyEngine()
        custom = Strategy("custom", "Custom", "desc", StrategyType.EXPLOIT)
        engine.register_strategy(custom)
        assert "custom" in engine._strategies

    def test_get_strategy(self):
        engine = StrategyEngine()
        s = engine.get_strategy("web_comprehensive")
        assert s is not None
        assert s.name == "Web综合安全评估"

    def test_get_nonexistent(self):
        engine = StrategyEngine()
        assert engine.get_strategy("nope") is None


class TestStrategyEngineList:
    def test_list_all(self):
        engine = StrategyEngine()
        all_strategies = engine.list_strategies()
        assert len(all_strategies) >= 6

    def test_list_by_type(self):
        engine = StrategyEngine()
        web = engine.list_strategies(strategy_type=StrategyType.WEB_ATTACK)
        assert len(web) >= 1
        for s in web:
            assert s.strategy_type == StrategyType.WEB_ATTACK

    def test_list_by_target_type(self):
        engine = StrategyEngine()
        network = engine.list_strategies(target_type="network")
        assert len(network) >= 1
        for s in network:
            assert "network" in s.target_types


class TestStrategyEngineRecommend:
    def test_recommend_for_web(self):
        engine = StrategyEngine()
        recs = engine.recommend_strategy("http://target.com", "web")
        assert len(recs) > 0
        # First recommendation should be web-related
        assert "web" in recs[0].target_types

    def test_recommend_ctf_mode(self):
        engine = StrategyEngine()
        recs = engine.recommend_strategy(
            "http://ctf.com", "web",
            context={"mode": "ctf"}
        )
        assert len(recs) > 0

    def test_recommend_max_5(self):
        engine = StrategyEngine()
        recs = engine.recommend_strategy("10.0.0.1", "unknown")
        assert len(recs) <= 5


class TestStrategyEngineSelect:
    def test_select_best(self):
        engine = StrategyEngine()
        best = engine.select_strategy("http://target.com", "web")
        assert best is not None

    def test_select_by_type(self):
        engine = StrategyEngine()
        best = engine.select_strategy(
            "10.0.0.1", "network",
            strategy_type=StrategyType.NETWORK_ATTACK
        )
        assert best is not None
        assert best.strategy_type == StrategyType.NETWORK_ATTACK

    def test_select_nonmatching_type(self):
        engine = StrategyEngine()
        # POST_EXPLOITATION has no builtin
        result = engine.select_strategy(
            "t", "unknown",
            strategy_type=StrategyType.POST_EXPLOITATION
        )
        assert result is None


class TestStrategyEngineExecution:
    def test_record_execution(self):
        engine = StrategyEngine()
        engine.record_execution("web_comprehensive", True, 120.5)
        s = engine.get_strategy("web_comprehensive")
        assert s.success_count == 1
        assert s.avg_execution_time == 120.5

    def test_record_execution_unknown_strategy(self):
        engine = StrategyEngine()
        # Should not crash
        engine.record_execution("nonexistent", True, 10.0)
        assert len(engine._history) == 1

    def test_get_execution_history(self):
        engine = StrategyEngine()
        engine.record_execution("web_comprehensive", True, 10.0)
        engine.record_execution("network_pentest", False, 20.0)
        history = engine.get_execution_history()
        assert len(history) == 2
        assert history[0]["strategy_id"] == "web_comprehensive"
        assert history[1]["success"] is False

    def test_get_execution_history_limit(self):
        engine = StrategyEngine()
        for i in range(10):
            engine.record_execution("web_comprehensive", True, float(i))
        history = engine.get_execution_history(limit=5)
        assert len(history) == 5

    def test_get_stats(self):
        engine = StrategyEngine()
        engine.record_execution("web_comprehensive", True, 10.0)
        engine.record_execution("web_comprehensive", False, 5.0)
        stats = engine.get_stats()
        assert stats["registered_strategies"] >= 6
        assert stats["total_executions"] == 2
        assert stats["successful_executions"] == 1
        assert "50.0%" in stats["success_rate"]

    def test_get_stats_empty(self):
        engine = StrategyEngine()
        stats = engine.get_stats()
        assert stats["total_executions"] == 0
        assert "0.0%" in stats["success_rate"]
