"""
Tests for SequentialThinkingIntegrator (kali_mcp/reasoning/sequential_integration.py)

Covers:
- SequentialThinkingIntegrator: init, enhance_reasoning,
  _mcp_sequential_thinking, _deep_thinking, _analyze_result_meaning,
  _deduce_next_vectors, _evaluate_risk_reward,
  _get_success_implication, _get_failure_reason
"""

import pytest
from unittest.mock import MagicMock

from kali_mcp.reasoning.sequential_integration import SequentialThinkingIntegrator


# ===================== Init Tests =====================

class TestInit:
    def test_defaults(self):
        integrator = SequentialThinkingIntegrator()
        assert integrator.use_mcp_tool is True
        assert integrator.fallback_to_local is True


# ===================== _analyze_result_meaning Tests =====================

class TestAnalyzeResultMeaning:
    def test_success(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._analyze_result_meaning(
            {"action": "scan_ports", "result": {"success": True, "target_vuln": "sql_injection"}},
            {}
        )
        assert "scan_ports" in result
        assert "成功" in result

    def test_failure(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._analyze_result_meaning(
            {"action": "exploit", "result": {"success": False, "error": "timeout"}},
            {}
        )
        assert "exploit" in result
        assert "失败" in result

    def test_empty_action(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._analyze_result_meaning({"result": {}}, {})
        assert isinstance(result, str)


# ===================== _deduce_next_vectors Tests =====================

class TestDeduceNextVectors:
    def test_sql_injection(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._deduce_next_vectors(
            {"finding": {"vulnerability_type": "sql_injection"}}, {}
        )
        assert "passwd" in result or "WebShell" in result or "UDF" in result

    def test_command_injection(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._deduce_next_vectors(
            {"finding": {"vulnerability_type": "command_injection"}}, {}
        )
        assert "权限" in result or "后门" in result

    def test_file_inclusion(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._deduce_next_vectors(
            {"finding": {"vulnerability_type": "file_inclusion"}}, {}
        )
        assert "日志" in result or "配置" in result or "伪协议" in result

    def test_file_upload(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._deduce_next_vectors(
            {"finding": {"vulnerability_type": "file_upload"}}, {}
        )
        assert "WebShell" in result

    def test_xss(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._deduce_next_vectors(
            {"finding": {"vulnerability_type": "xss"}}, {}
        )
        assert "Cookie" in result or "CSRF" in result

    def test_unknown_vuln(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._deduce_next_vectors(
            {"finding": {"vulnerability_type": "unknown"}}, {}
        )
        assert "unknown" in result


# ===================== _evaluate_risk_reward Tests =====================

class TestEvaluateRiskReward:
    def test_high_confidence(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._evaluate_risk_reward({"confidence": 0.9}, {})
        assert "高" in result or "值得" in result

    def test_medium_confidence(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._evaluate_risk_reward({"confidence": 0.5}, {})
        assert "中等" in result

    def test_low_confidence(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._evaluate_risk_reward({"confidence": 0.2}, {})
        assert "低" in result

    def test_ctf_mode(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._evaluate_risk_reward(
            {"confidence": 0.5}, {"mode": "ctf"}
        )
        assert "CTF" in result

    def test_pentest_mode(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._evaluate_risk_reward(
            {"confidence": 0.5}, {"mode": "pentest"}
        )
        assert "渗透测试" in result


# ===================== _get_success_implication Tests =====================

class TestGetSuccessImplication:
    def test_sql_injection(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._get_success_implication(
            {"target_vuln": "sql_injection"}, {}
        )
        assert "数据库" in result

    def test_command_injection(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._get_success_implication(
            {"target_vuln": "command_injection"}, {}
        )
        assert "命令" in result

    def test_file_inclusion(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._get_success_implication(
            {"target_vuln": "file_inclusion"}, {}
        )
        assert "文件" in result

    def test_unknown(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._get_success_implication(
            {"target_vuln": "something_else"}, {}
        )
        assert "攻击能力" in result


# ===================== _get_failure_reason Tests =====================

class TestGetFailureReason:
    def test_with_error(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._get_failure_reason(
            {"error": "Connection refused"}, {}
        )
        assert "Connection refused" in result

    def test_default_error(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._get_failure_reason({}, {})
        assert "Unknown" in result


# ===================== _deep_thinking Tests =====================

class TestDeepThinking:
    def test_generates_three_thoughts(self):
        integrator = SequentialThinkingIntegrator()
        thoughts = integrator._deep_thinking(
            {"action": "scan", "result": {"success": True}, "finding": {"vulnerability_type": "sql_injection"}},
            {},
            5
        )
        assert len(thoughts) == 3

    def test_thought_structure(self):
        integrator = SequentialThinkingIntegrator()
        thoughts = integrator._deep_thinking(
            {"action": "test", "result": {}, "finding": {}},
            {},
            1
        )
        for t in thoughts:
            assert "thought" in t
            assert "thoughtNumber" in t
            assert "totalThoughts" in t
            assert "nextThoughtNeeded" in t
            assert "content" in t

    def test_last_thought_ends_chain(self):
        integrator = SequentialThinkingIntegrator()
        thoughts = integrator._deep_thinking({"action": "x", "result": {}, "finding": {}}, {}, 1)
        assert thoughts[-1]["nextThoughtNeeded"] is False
        assert thoughts[0]["nextThoughtNeeded"] is True

    def test_thought_numbering(self):
        integrator = SequentialThinkingIntegrator()
        thoughts = integrator._deep_thinking({"action": "x", "result": {}, "finding": {}}, {}, 10)
        assert thoughts[0]["thoughtNumber"] == 10
        assert thoughts[1]["thoughtNumber"] == 11
        assert thoughts[2]["thoughtNumber"] == 12


# ===================== _mcp_sequential_thinking Tests =====================

class TestMcpSequentialThinking:
    def test_with_local_chain(self):
        integrator = SequentialThinkingIntegrator()
        # Create a mock reasoning step
        mock_step = MagicMock()
        mock_step.to_dict.return_value = {
            "action": "scan",
            "result": {"success": True},
            "finding": {"vulnerability_type": "sql_injection"}
        }
        result = integrator._mcp_sequential_thinking(
            [mock_step], {"vulnerability_type": "sql_injection"}, {}
        )
        assert result is not None
        assert len(result) == 3  # 3 deep thoughts

    def test_empty_local_chain(self):
        integrator = SequentialThinkingIntegrator()
        result = integrator._mcp_sequential_thinking([], {}, {})
        assert result == []


# ===================== enhance_reasoning Tests =====================

class TestEnhanceReasoning:
    def test_with_mcp_tool_enabled(self):
        integrator = SequentialThinkingIntegrator()
        integrator.use_mcp_tool = True

        # Mock the reasoning engine
        mock_engine = MagicMock()
        mock_step = MagicMock()
        mock_step.to_dict.return_value = {
            "action": "scan",
            "result": {"success": True},
            "finding": {"vulnerability_type": "sql_injection"}
        }
        mock_engine.reason_chain.return_value = [mock_step]

        result = integrator.enhance_reasoning(
            mock_engine,
            {"vulnerability_type": "sql_injection"},
            {}
        )
        assert len(result) > 0

    def test_with_mcp_tool_disabled(self):
        integrator = SequentialThinkingIntegrator()
        integrator.use_mcp_tool = False

        mock_engine = MagicMock()
        mock_step = MagicMock()
        mock_step.to_dict.return_value = {"step": 1}
        mock_engine.reason_chain.return_value = [mock_step]

        result = integrator.enhance_reasoning(mock_engine, {}, {})
        # Should only have local chain results
        assert len(result) == 1

    def test_mcp_failure_with_fallback(self):
        integrator = SequentialThinkingIntegrator()
        integrator.use_mcp_tool = True
        integrator.fallback_to_local = True

        mock_engine = MagicMock()
        mock_engine.reason_chain.return_value = []

        # Even if MCP fails, should return gracefully
        result = integrator.enhance_reasoning(mock_engine, {}, {})
        assert isinstance(result, list)

    def test_empty_reasoning_chain(self):
        integrator = SequentialThinkingIntegrator()
        mock_engine = MagicMock()
        mock_engine.reason_chain.return_value = []

        result = integrator.enhance_reasoning(mock_engine, {}, {})
        assert isinstance(result, list)
