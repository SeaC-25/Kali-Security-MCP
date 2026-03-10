"""
Tests for ai_context module (kali_mcp/core/ai_context.py)

Covers:
- AIContextManager: init, create_session, get_or_create_session,
  analyze_user_intent, update_knowledge_base, get_session_insights
"""

import pytest

from kali_mcp.core.ai_context import AIContextManager


# ===================== Init Tests =====================

class TestAIContextManagerInit:
    def test_defaults(self):
        mgr = AIContextManager()
        assert mgr.sessions == {}
        assert mgr.current_session is None
        assert mgr.strategy_engine is not None
        assert "common_ports" in mgr.global_knowledge_base
        assert "ctf_flag_patterns" in mgr.global_knowledge_base
        assert "vulnerability_signatures" in mgr.global_knowledge_base
        assert "successful_payloads" in mgr.global_knowledge_base

    def test_common_ports(self):
        mgr = AIContextManager()
        ports = mgr.global_knowledge_base["common_ports"]
        assert ports[80] == "HTTP"
        assert ports[443] == "HTTPS"
        assert ports[22] == "SSH"
        assert ports[21] == "FTP"
        assert ports[3389] == "RDP"


# ===================== create_session Tests =====================

class TestCreateSession:
    def test_creates_session(self):
        mgr = AIContextManager()
        session = mgr.create_session(target="10.0.0.1", attack_mode="pentest")
        assert session is not None
        assert session.target == "10.0.0.1"
        assert session.attack_mode == "pentest"
        assert session.session_id in mgr.sessions
        assert mgr.current_session is session

    def test_creates_default_session(self):
        mgr = AIContextManager()
        session = mgr.create_session()
        assert session is not None
        assert session.target == ""
        assert session.attack_mode == "pentest"

    def test_multiple_sessions(self):
        mgr = AIContextManager()
        s1 = mgr.create_session(target="t1")
        s2 = mgr.create_session(target="t2")
        assert len(mgr.sessions) == 2
        assert mgr.current_session is s2


# ===================== get_or_create_session Tests =====================

class TestGetOrCreateSession:
    def test_get_existing_by_id(self):
        mgr = AIContextManager()
        s1 = mgr.create_session(target="t1")
        sid = s1.session_id

        # Create second session to change current
        mgr.create_session(target="t2")

        # Get first by ID
        retrieved = mgr.get_or_create_session(session_id=sid)
        assert retrieved.target == "t1"
        assert mgr.current_session is retrieved

    def test_get_current_when_exists(self):
        mgr = AIContextManager()
        s1 = mgr.create_session(target="existing")
        retrieved = mgr.get_or_create_session()
        assert retrieved is s1

    def test_create_new_when_none(self):
        mgr = AIContextManager()
        session = mgr.get_or_create_session()
        assert session is not None
        assert len(mgr.sessions) == 1

    def test_nonexistent_id_falls_back(self):
        mgr = AIContextManager()
        mgr.create_session(target="fallback")
        result = mgr.get_or_create_session(session_id="nonexistent")
        # Should fall back to current session
        assert result.target == "fallback"


# ===================== analyze_user_intent Tests =====================

class TestAnalyzeUserIntent:
    def test_security_testing(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("请扫描一下这个目标")
        assert result["primary_intent"] == "security_testing"

    def test_scan_keyword(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("scan the target 192.168.1.1")
        assert result["primary_intent"] == "security_testing"

    def test_ctf_solving(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("帮我解这个ctf题目")
        assert result["primary_intent"] == "ctf_solving"

    def test_flag_keyword(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("找到flag")
        assert result["primary_intent"] == "ctf_solving"

    def test_analysis_intent(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("分析一下这个二进制文件")
        assert result["primary_intent"] == "analysis"

    def test_reverse_keyword(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("reverse this binary")
        assert result["primary_intent"] == "analysis"

    def test_exploitation_intent(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("攻击这个目标")
        assert result["primary_intent"] == "exploitation"

    def test_exploit_keyword(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("exploit the vulnerability")
        assert result["primary_intent"] == "exploitation"

    def test_unknown_intent(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("hello world")
        assert result["primary_intent"] == "unknown"

    def test_url_extraction(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("test http://example.com/api/v1")
        assert result["target_extraction"] == "http://example.com/api/v1"

    def test_ip_extraction(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("scan 192.168.1.100 for vulnerabilities")
        assert result["target_extraction"] == "192.168.1.100"

    def test_ip_overrides_url(self):
        """When both URL and IP are present, IP comes second and overrides."""
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("http://example.com at 10.0.0.1")
        assert result["target_extraction"] == "10.0.0.1"

    def test_high_urgency(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("紧急 scan the target")
        assert result["urgency_level"] == "high"

    def test_urgent_keyword(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("urgent: scan now")
        assert result["urgency_level"] == "high"

    def test_fast_keyword(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("快速扫描一下")
        assert result["urgency_level"] == "high"

    def test_low_urgency(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("详细分析一下目标")
        assert result["urgency_level"] == "low"

    def test_comprehensive_keyword(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("comprehensive scan needed")
        assert result["urgency_level"] == "low"

    def test_normal_urgency(self):
        mgr = AIContextManager()
        result = mgr.analyze_user_intent("scan the target")
        assert result["urgency_level"] == "normal"


# ===================== update_knowledge_base Tests =====================

class TestUpdateKnowledgeBase:
    def test_update_existing_category(self):
        mgr = AIContextManager()
        mgr.update_knowledge_base("common_ports", 8080, "HTTP-Alt")
        assert mgr.global_knowledge_base["common_ports"][8080] == "HTTP-Alt"

    def test_create_new_category(self):
        mgr = AIContextManager()
        mgr.update_knowledge_base("custom_data", "key1", "value1")
        assert mgr.global_knowledge_base["custom_data"]["key1"] == "value1"

    def test_overwrite_value(self):
        mgr = AIContextManager()
        mgr.update_knowledge_base("vulnerability_signatures", "sqli", "old")
        mgr.update_knowledge_base("vulnerability_signatures", "sqli", "new")
        assert mgr.global_knowledge_base["vulnerability_signatures"]["sqli"] == "new"


# ===================== get_session_insights Tests =====================

class TestGetSessionInsights:
    def test_insights_new_session(self):
        mgr = AIContextManager()
        insights = mgr.get_session_insights()
        assert "session_summary" in insights
        assert "progress_analysis" in insights
        assert "next_recommendations" in insights
        assert "knowledge_gaps" in insights
        # Should recommend initial reconnaissance
        assert len(insights["next_recommendations"]) > 0
        assert insights["next_recommendations"][0]["action"] == "开始初始侦察"

    def test_insights_existing_session(self):
        mgr = AIContextManager()
        session = mgr.create_session(target="10.0.0.1")
        insights = mgr.get_session_insights(session_id=session.session_id)
        assert insights["progress_analysis"]["completed_phases"] == 0

    def test_insights_with_completed_tasks(self):
        mgr = AIContextManager()
        session = mgr.create_session(target="10.0.0.1")
        session.completed_tasks.append("port_scan")
        session.discovered_assets["open_ports"] = [80, 443]
        insights = mgr.get_session_insights(session_id=session.session_id)
        assert insights["progress_analysis"]["completed_phases"] == 1
        assert insights["progress_analysis"]["discovered_assets"] > 0
        # Should suggest deeper analysis
        recs = insights["next_recommendations"]
        assert any("漏洞" in r["action"] for r in recs)
