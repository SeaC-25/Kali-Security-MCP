"""
Tests for MCP Session (kali_mcp/core/mcp_session.py)

Covers:
- SessionContext dataclass
- StrategyEngine strategy selection and analysis
"""

import pytest

from kali_mcp.core.mcp_session import SessionContext, StrategyEngine


class TestSessionContext:
    """Test SessionContext dataclass."""

    def test_default_values(self):
        ctx = SessionContext()
        assert ctx.session_id  # UUID generated
        assert ctx.target == ""
        assert ctx.attack_mode == "pentest"
        assert ctx.conversation_history == []
        assert ctx.completed_tasks == []

    def test_with_target(self):
        ctx = SessionContext(target="10.0.0.1", attack_mode="ctf")
        assert ctx.target == "10.0.0.1"
        assert ctx.attack_mode == "ctf"

    def test_add_conversation(self):
        ctx = SessionContext(target="10.0.0.1")
        ctx.add_conversation("scan this", "scanning...", ["nmap"])
        assert len(ctx.conversation_history) == 1
        entry = ctx.conversation_history[0]
        assert entry["user_message"] == "scan this"
        assert entry["tools_used"] == ["nmap"]

    def test_update_interaction(self):
        ctx = SessionContext()
        old_time = ctx.last_interaction
        ctx.update_interaction()
        assert ctx.last_interaction >= old_time

    def test_context_summary(self):
        ctx = SessionContext(target="10.0.0.1", attack_mode="ctf")
        ctx.discovered_assets["web"] = ["http://10.0.0.1"]
        ctx.completed_tasks.append("port_scan")
        summary = ctx.get_context_summary()
        assert summary["target"] == "10.0.0.1"
        assert summary["attack_mode"] == "ctf"
        assert summary["discovered_assets"] == 1
        assert summary["completed_tasks"] == 1


class TestStrategyEngine:
    """Test StrategyEngine."""

    @pytest.fixture
    def engine(self):
        return StrategyEngine()

    def test_has_strategies(self, engine):
        assert "web_comprehensive" in engine.strategies
        assert "ctf_quick_solve" in engine.strategies
        assert "network_recon" in engine.strategies
        assert "pwn_exploitation" in engine.strategies
        assert "adaptive_multi" in engine.strategies

    def test_get_strategy_tools(self, engine):
        tools = engine.get_strategy_tools("web_comprehensive")
        assert "nmap_scan" in tools
        assert len(tools) > 0

    def test_get_unknown_strategy_tools(self, engine):
        tools = engine.get_strategy_tools("nonexistent")
        assert tools == []

    def test_analyze_web_context(self, engine):
        session = SessionContext(target="http://example.com")
        analysis = engine.analyze_context(session, "scan the web app")
        assert "web_service_detected" in analysis["context_indicators"]
        assert any(
            r["strategy"] == "web_comprehensive"
            for r in analysis["recommended_strategies"]
        )

    def test_analyze_ctf_context(self, engine):
        session = SessionContext(target="http://ctf.com")
        analysis = engine.analyze_context(session, "解题 find the flag")
        assert "ctf_mode" in analysis["context_indicators"]

    def test_analyze_ip_target(self, engine):
        session = SessionContext(target="192.168.1.100")
        analysis = engine.analyze_context(session, "scan the target")
        assert "ip_target" in analysis["context_indicators"]

    def test_analyze_pwn_context(self, engine):
        session = SessionContext(target="")
        analysis = engine.analyze_context(session, "analyze this binary pwn challenge")
        assert "binary_file" in analysis["context_indicators"]

    def test_analyze_unknown_target(self, engine):
        session = SessionContext(target="something")
        analysis = engine.analyze_context(session, "不知道怎么做")
        assert "unknown_target" in analysis["context_indicators"]

    def test_update_effectiveness(self, engine):
        engine.update_strategy_effectiveness("web_comprehensive", 0.85)
        assert "effectiveness" in engine.strategies["web_comprehensive"]
        assert 0.85 in engine.strategies["web_comprehensive"]["effectiveness"]
