"""
Tests for IntentAnalyzer (kali_mcp/core/intent_analyzer.py)

Covers:
- Target extraction (URL, IP, CIDR, domain)
- Intent classification (recon, vuln_scan, exploitation, CTF, APT)
- Constraint detection (time, auth, scope)
- Priority assessment
- Strategy and tool suggestions
- Internal IP detection
- CTF domain detection
"""

import pytest

from kali_mcp.core.intent_analyzer import (
    IntentAnalyzer,
    AttackIntent,
    TargetType,
    ConstraintType,
    TargetInfo,
    IntentAnalysis,
)


@pytest.fixture
def analyzer():
    return IntentAnalyzer()


# ===================== Internal IP Detection =====================

class TestIsInternalIP:
    def test_10_x(self, analyzer):
        assert analyzer._is_internal_ip("10.0.0.1") is True

    def test_172_16(self, analyzer):
        assert analyzer._is_internal_ip("172.16.0.1") is True

    def test_172_31(self, analyzer):
        assert analyzer._is_internal_ip("172.31.255.255") is True

    def test_172_15_not_internal(self, analyzer):
        assert analyzer._is_internal_ip("172.15.0.1") is False

    def test_172_32_not_internal(self, analyzer):
        assert analyzer._is_internal_ip("172.32.0.1") is False

    def test_192_168(self, analyzer):
        assert analyzer._is_internal_ip("192.168.1.1") is True

    def test_public_ip(self, analyzer):
        assert analyzer._is_internal_ip("8.8.8.8") is False

    def test_invalid_ip(self, analyzer):
        assert analyzer._is_internal_ip("not-an-ip") is False

    def test_empty(self, analyzer):
        assert analyzer._is_internal_ip("") is False


# ===================== CTF Domain Detection =====================

class TestIsCTFDomain:
    def test_ctf_keyword(self, analyzer):
        assert analyzer._is_ctf_domain("ctf.example.com") is True

    def test_hackthebox(self, analyzer):
        assert analyzer._is_ctf_domain("app.hackthebox.com") is True

    def test_tryhackme(self, analyzer):
        assert analyzer._is_ctf_domain("tryhackme.com") is True

    def test_normal_domain(self, analyzer):
        assert analyzer._is_ctf_domain("example.com") is False


# ===================== Target Extraction =====================

class TestTargetExtraction:
    def test_extract_url(self, analyzer):
        result = analyzer.analyze("scan http://example.com/login")
        urls = [t for t in result.targets if t.type == TargetType.URL]
        assert len(urls) >= 1
        assert urls[0].protocol == "http"

    def test_extract_https(self, analyzer):
        result = analyzer.analyze("test https://secure.example.com")
        urls = [t for t in result.targets if t.type == TargetType.URL]
        assert len(urls) >= 1
        assert urls[0].protocol == "https"

    def test_extract_ip(self, analyzer):
        result = analyzer.analyze("scan 192.168.1.100")
        ips = [t for t in result.targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1

    def test_extract_ip_internal_flag(self, analyzer):
        result = analyzer.analyze("scan 10.0.0.5")
        ips = [t for t in result.targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1
        assert ips[0].is_internal is True

    def test_extract_domain(self, analyzer):
        result = analyzer.analyze("recon example.com")
        domains = [t for t in result.targets if t.type == TargetType.DOMAIN]
        assert len(domains) >= 1

    def test_no_targets(self, analyzer):
        result = analyzer.analyze("help me with hacking")
        # May or may not find targets depending on regex
        assert isinstance(result.targets, list)


# ===================== Intent Classification =====================

class TestIntentClassification:
    def test_recon_intent(self, analyzer):
        result = analyzer.analyze("scan 10.0.0.1")
        assert result.intent == AttackIntent.RECONNAISSANCE

    def test_vuln_scan_intent(self, analyzer):
        result = analyzer.analyze("漏洞扫描 http://example.com")
        assert result.intent == AttackIntent.VULNERABILITY_SCANNING

    def test_exploit_intent(self, analyzer):
        result = analyzer.analyze("exploit the target, getshell")
        assert result.intent == AttackIntent.EXPLOITATION

    def test_ctf_intent(self, analyzer):
        result = analyzer.analyze("ctf 解题 找flag")
        assert result.intent == AttackIntent.CTF_SOLVING

    def test_apt_intent(self, analyzer):
        result = analyzer.analyze("全面 渗透测试 全流程 apt攻击")
        assert result.intent == AttackIntent.APT_SIMULATION

    def test_privesc_intent(self, analyzer):
        result = analyzer.analyze("提权 获取root权限")
        assert result.intent == AttackIntent.PRIVILEGE_ESCALATION

    def test_default_recon(self, analyzer):
        result = analyzer.analyze("hello")
        assert result.intent == AttackIntent.RECONNAISSANCE


# ===================== Constraint Detection =====================

class TestConstraintDetection:
    def test_time_constraint(self, analyzer):
        result = analyzer.analyze("快速扫描 10.0.0.1")
        types = [c["type"] for c in result.constraints]
        assert ConstraintType.TIME_LIMIT in types

    def test_auth_constraint(self, analyzer):
        result = analyzer.analyze("授权测试 example.com")
        types = [c["type"] for c in result.constraints]
        assert ConstraintType.AUTHORIZATION in types

    def test_scope_constraint(self, analyzer):
        result = analyzer.analyze("只扫描80端口")
        types = [c["type"] for c in result.constraints]
        assert ConstraintType.SCOPE in types

    def test_no_constraints(self, analyzer):
        result = analyzer.analyze("scan 10.0.0.1")
        # May have zero or more constraints
        assert isinstance(result.constraints, list)


# ===================== Priority Assessment =====================

class TestPriority:
    def test_high_priority_keywords(self, analyzer):
        result = analyzer.analyze("紧急 扫描 10.0.0.1")
        assert result.priority >= 7

    def test_low_priority_keywords(self, analyzer):
        result = analyzer.analyze("稍后 测试 10.0.0.1")
        assert result.priority <= 4

    def test_ctf_boosts_priority(self, analyzer):
        result = analyzer.analyze("ctf flag")
        assert result.priority >= 7

    def test_clamped_range(self, analyzer):
        result = analyzer.analyze("some input")
        assert 1 <= result.priority <= 10


# ===================== Strategy Suggestion =====================

class TestStrategy:
    def test_ctf_strategy(self, analyzer):
        result = analyzer.analyze("ctf challenge flag")
        assert result.suggested_strategy == "ctf_intensive"

    def test_recon_strategy(self, analyzer):
        result = analyzer.analyze("scan 10.0.0.1")
        assert result.suggested_strategy == "fast_recon"


# ===================== Confidence Calculation =====================

class TestConfidence:
    def test_with_targets_higher(self, analyzer):
        r1 = analyzer.analyze("hello world")
        r2 = analyzer.analyze("scan http://example.com")
        # Having a target should generally increase confidence
        assert r2.confidence >= r1.confidence

    def test_bounded(self, analyzer):
        result = analyzer.analyze("ctf http://example.com flag exploit")
        assert result.confidence <= 1.0


# ===================== Full Analysis =====================

class TestFullAnalysis:
    def test_analysis_returns_correct_type(self, analyzer):
        result = analyzer.analyze("scan http://ctf.example.com for flag")
        assert isinstance(result, IntentAnalysis)
        assert result.user_input == "scan http://ctf.example.com for flag"
        assert isinstance(result.reasoning, list)
        assert len(result.reasoning) > 0

    def test_required_tools_populated(self, analyzer):
        result = analyzer.analyze("漏洞扫描 http://example.com")
        assert isinstance(result.required_tools, list)
        assert len(result.required_tools) > 0
