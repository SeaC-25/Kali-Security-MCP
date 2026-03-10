"""
Tests for ChainReasoningEngine (kali_mcp/reasoning/chain_engine.py)

Covers:
- ReasoningStep: creation, to_dict
- ChainReasoningEngine: init, reason_chain, _reason_step,
  _generate_reasoning, _generate_next_thoughts, _should_continue_reasoning,
  result_to_finding, _update_stats, visualize_chain, get_summary
"""

import pytest
from unittest.mock import patch, MagicMock

from kali_mcp.reasoning.chain_engine import (
    ReasoningStep,
    ChainReasoningEngine,
)
from kali_mcp.reasoning.knowledge_graph import VulnerabilityType, AttackChain


# ===================== ReasoningStep Tests =====================

class TestReasoningStep:
    def test_creation(self):
        step = ReasoningStep(
            step_number=1,
            current_finding={"vulnerability_type": "sql_injection"},
            reasoning="Found SQL injection",
            action_taken="Try command injection",
            result={"success": True, "target_vuln": "command_injection"},
            next_thoughts=["Check for RCE"],
            confidence=0.8
        )
        assert step.step_number == 1
        assert step.reasoning == "Found SQL injection"
        assert step.confidence == 0.8
        assert step.timestamp is not None

    def test_to_dict(self):
        step = ReasoningStep(
            step_number=2,
            current_finding={"vulnerability_type": "xss"},
            reasoning="XSS found",
            action_taken="Steal cookie",
            result={"success": False},
            next_thoughts=["Try DOM XSS", "Try stored XSS"],
            confidence=0.6
        )
        d = step.to_dict()
        assert d["step"] == 2
        assert d["finding"]["vulnerability_type"] == "xss"
        assert d["reasoning"] == "XSS found"
        assert d["action"] == "Steal cookie"
        assert d["confidence"] == 0.6
        assert len(d["next_thoughts"]) == 2
        assert "timestamp" in d


# ===================== ChainReasoningEngine Init Tests =====================

class TestChainReasoningEngineInit:
    def test_init(self):
        engine = ChainReasoningEngine()
        assert engine.knowledge_graph is not None
        assert engine.autonomous_engine is not None
        assert engine.reasoning_chain == []
        assert engine.max_depth == 999
        assert engine.min_confidence == 0.3
        assert engine.ctf_mode is False
        assert engine.stats["total_reasoning_steps"] == 0


# ===================== _generate_reasoning Tests =====================

class TestGenerateReasoning:
    def test_basic_reasoning(self):
        engine = ChainReasoningEngine()
        chain = AttackChain(
            from_vuln=VulnerabilityType.SQL_INJECTION,
            to_vuln=VulnerabilityType.COMMAND_INJECTION,
            reasoning="exploit SQL to run commands",
            success_prob=0.7,
            time_cost=30,
            tools=["sqlmap"],
            conditions=[]
        )
        result = engine._generate_reasoning(
            {"vulnerability_type": "sql_injection"},
            chain,
            {}
        )
        assert "sql_injection" in result
        assert "command_injection" in result
        assert "70%" in result
        assert "30秒" in result


# ===================== _generate_next_thoughts Tests =====================

class TestGenerateNextThoughts:
    def test_pentest_mode(self):
        engine = ChainReasoningEngine()
        engine.ctf_mode = False
        chain = AttackChain(
            from_vuln=VulnerabilityType.SQL_INJECTION,
            to_vuln=VulnerabilityType.COMMAND_INJECTION,
            reasoning="test",
            success_prob=0.7,
            time_cost=30,
            tools=["sqlmap", "bash"],
            conditions=["has_shell"]
        )
        thoughts = engine._generate_next_thoughts(chain, {})
        assert any("command_injection" in t for t in thoughts)
        assert any("has_shell" in t for t in thoughts)
        assert any("渗透测试" in t for t in thoughts)

    def test_ctf_mode(self):
        engine = ChainReasoningEngine()
        engine.ctf_mode = True
        chain = AttackChain(
            from_vuln=VulnerabilityType.SQL_INJECTION,
            to_vuln=VulnerabilityType.FILE_INCLUSION,
            reasoning="test",
            success_prob=0.5,
            time_cost=20,
            tools=["sqlmap"],
            conditions=[]
        )
        thoughts = engine._generate_next_thoughts(chain, {})
        assert any("CTF" in t for t in thoughts)


# ===================== _should_continue_reasoning Tests =====================

class TestShouldContinueReasoning:
    def _make_step(self, confidence=0.5, vuln_type="sql_injection", success=False):
        return ReasoningStep(
            step_number=1,
            current_finding={"vulnerability_type": vuln_type},
            reasoning="test",
            action_taken="test",
            result={"success": success, "target_vuln": vuln_type},
            next_thoughts=[],
            confidence=confidence
        )

    def test_low_confidence_stops(self):
        engine = ChainReasoningEngine()
        step = self._make_step(confidence=0.1)
        assert engine._should_continue_reasoning(step, {}) is False

    def test_normal_confidence_continues(self):
        engine = ChainReasoningEngine()
        step = self._make_step(confidence=0.5)
        assert engine._should_continue_reasoning(step, {}) is True

    def test_ctf_flag_found_stops(self):
        engine = ChainReasoningEngine()
        engine.ctf_mode = True
        step = self._make_step(confidence=0.8)
        assert engine._should_continue_reasoning(
            step, {"flags_found": ["flag{test}"]}
        ) is False

    def test_objectives_achieved_stops(self):
        engine = ChainReasoningEngine()
        step = self._make_step(confidence=0.8)
        assert engine._should_continue_reasoning(
            step, {"objectives_achieved": True}
        ) is False

    def test_loop_detection(self):
        engine = ChainReasoningEngine()
        # Add 3 steps with same vuln type
        for i in range(3):
            engine.reasoning_chain.append(self._make_step(
                confidence=0.5, vuln_type="sql_injection"
            ))
        step = self._make_step(confidence=0.5, vuln_type="sql_injection")
        assert engine._should_continue_reasoning(step, {}) is False

    def test_no_loop_different_types(self):
        engine = ChainReasoningEngine()
        engine.reasoning_chain.append(self._make_step(vuln_type="sql_injection"))
        engine.reasoning_chain.append(self._make_step(vuln_type="command_injection"))
        engine.reasoning_chain.append(self._make_step(vuln_type="file_inclusion"))
        step = self._make_step(confidence=0.5)
        assert engine._should_continue_reasoning(step, {}) is True


# ===================== result_to_finding Tests =====================

class TestResultToFinding:
    def test_success_result(self):
        engine = ChainReasoningEngine()
        finding = engine.result_to_finding({
            "success": True,
            "target_vuln": "command_injection",
            "confidence": 0.9,
            "evidence": {"output": "root"}
        })
        assert finding["vulnerability_type"] == "command_injection"
        assert finding["confidence"] == 0.9
        assert finding["exploitable"] is True
        assert finding["evidence"]["output"] == "root"

    def test_failure_result(self):
        engine = ChainReasoningEngine()
        finding = engine.result_to_finding({
            "success": False,
            "target_vuln": "xss",
            "error": "WAF blocked"
        })
        assert finding["vulnerability_type"] == "xss"
        assert finding["confidence"] == 0.0
        assert finding["exploitable"] is False
        assert finding["error"] == "WAF blocked"

    def test_default_values(self):
        engine = ChainReasoningEngine()
        finding = engine.result_to_finding({"success": True})
        assert finding["vulnerability_type"] == "unknown"
        assert finding["confidence"] == 0.5


# ===================== _update_stats Tests =====================

class TestUpdateStats:
    def test_empty_chain(self):
        engine = ChainReasoningEngine()
        engine._update_stats()
        assert engine.stats["total_reasoning_steps"] == 0

    def test_with_steps(self):
        engine = ChainReasoningEngine()
        engine.reasoning_chain = [
            ReasoningStep(1, {}, "r", "a", {"success": True}, [], 0.8),
            ReasoningStep(2, {}, "r", "a", {"success": False}, [], 0.6),
            ReasoningStep(3, {}, "r", "a", {"success": True}, [], 0.7),
        ]
        engine._update_stats()
        assert engine.stats["total_reasoning_steps"] == 3
        assert engine.stats["successful_chains"] == 2
        assert engine.stats["failed_chains"] == 1
        assert abs(engine.stats["average_confidence"] - 0.7) < 0.01


# ===================== reason_chain Tests =====================

class TestReasonChain:
    def test_basic_chain(self):
        engine = ChainReasoningEngine()
        finding = {"vulnerability_type": "sql_injection"}
        chain = engine.reason_chain(finding, {}, max_depth=3)
        assert isinstance(chain, list)
        assert len(chain) <= 3
        # Stats should be updated
        assert engine.stats["total_reasoning_steps"] == len(chain)

    def test_ctf_mode_set(self):
        engine = ChainReasoningEngine()
        engine.reason_chain(
            {"vulnerability_type": "sql_injection"},
            {"mode": "ctf"},
            max_depth=2
        )
        assert engine.ctf_mode is True

    def test_unknown_vuln_type_empty(self):
        engine = ChainReasoningEngine()
        chain = engine.reason_chain(
            {"vulnerability_type": "nonexistent"},
            {},
            max_depth=2
        )
        assert chain == []

    def test_time_limit(self):
        engine = ChainReasoningEngine()
        chain = engine.reason_chain(
            {"vulnerability_type": "sql_injection"},
            {},
            max_depth=100,
            time_limit=1  # 1 second
        )
        # Should complete within time limit
        assert isinstance(chain, list)

    def test_chain_resets_on_each_call(self):
        engine = ChainReasoningEngine()
        engine.reason_chain(
            {"vulnerability_type": "sql_injection"}, {}, max_depth=2
        )
        first_len = len(engine.reasoning_chain)
        engine.reason_chain(
            {"vulnerability_type": "command_injection"}, {}, max_depth=2
        )
        # Chain should be fresh, not accumulated
        assert len(engine.reasoning_chain) <= 2


# ===================== Visualization and Summary Tests =====================

class TestVisualizationAndSummary:
    def test_visualize_empty(self):
        engine = ChainReasoningEngine()
        result = engine.visualize_chain()
        assert "推理链为空" in result

    def test_visualize_with_chain(self):
        engine = ChainReasoningEngine()
        engine.reasoning_chain = [
            ReasoningStep(
                1,
                {"vulnerability_type": "sql_injection"},
                "Found SQLi",
                "Try CMDi",
                {"success": True, "target_vuln": "command_injection"},
                ["Next step"],
                0.8
            )
        ]
        engine._update_stats()
        result = engine.visualize_chain()
        assert "步骤 1" in result
        assert "sql_injection" in result
        assert "推理统计" in result

    def test_visualize_autonomous_insights(self):
        engine = ChainReasoningEngine()
        engine.reasoning_chain = [
            ReasoningStep(
                1,
                {"vulnerability_type": "sql_injection"},
                "[自主推理] Cross domain",
                "Try novel path",
                {"insight_type": "cross_domain", "novelty": 0.7, "success": False},
                ["Innovative approach"],
                0.6
            )
        ]
        from kali_mcp.reasoning.autonomous_engine import AutonomousInsight
        engine.autonomous_insights = [
            AutonomousInsight("cross_domain", "test", 0.7, 0.6, 30)
        ]
        engine._update_stats()
        result = engine.visualize_chain()
        assert "自主推理" in result
        assert "cross_domain" in result

    def test_get_summary(self):
        engine = ChainReasoningEngine()
        engine.reasoning_chain = [
            ReasoningStep(1, {}, "r", "a", {"success": True}, [], 0.8),
        ]
        engine._update_stats()
        summary = engine.get_summary()
        assert summary["total_steps"] == 1
        assert summary["depth_reached"] == 1
        assert summary["max_depth"] == 999
        assert len(summary["chain"]) == 1
        assert "total_reasoning_steps" in summary["stats"]

    def test_get_summary_empty(self):
        engine = ChainReasoningEngine()
        summary = engine.get_summary()
        assert summary["total_steps"] == 0
        assert summary["chain"] == []
