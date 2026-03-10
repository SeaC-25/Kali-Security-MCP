"""
Tests for intent module (kali_mcp/ai/intent.py)

Covers:
- IntentType enum
- TargetType enum
- Intent: creation, to_dict
- IntentAnalyzer: init, analyze (intent identification, target extraction,
  suggested tools, parameters), get_history, suggest_next_intent
- get_intent_analyzer global factory
"""

import pytest

from kali_mcp.ai.intent import (
    IntentType,
    TargetType,
    Intent,
    IntentAnalyzer,
    get_intent_analyzer,
)


# ===================== IntentType Tests =====================

class TestIntentType:
    def test_member_count(self):
        assert len(IntentType) == 21

    def test_reconnaissance_values(self):
        assert IntentType.RECONNAISSANCE.value == "reconnaissance"
        assert IntentType.PORT_SCAN.value == "port_scan"
        assert IntentType.SERVICE_ENUM.value == "service_enum"
        assert IntentType.SUBDOMAIN_ENUM.value == "subdomain_enum"
        assert IntentType.OSINT.value == "osint"

    def test_web_attack_values(self):
        assert IntentType.WEB_SCAN.value == "web_scan"
        assert IntentType.DIR_SCAN.value == "directory_scan"
        assert IntentType.SQL_INJECTION.value == "sql_injection"
        assert IntentType.XSS.value == "xss"
        assert IntentType.FILE_UPLOAD.value == "file_upload"

    def test_network_attack_values(self):
        assert IntentType.NETWORK_ATTACK.value == "network_attack"
        assert IntentType.PASSWORD_ATTACK.value == "password_attack"
        assert IntentType.SMB_ATTACK.value == "smb_attack"

    def test_exploit_values(self):
        assert IntentType.EXPLOIT.value == "exploit"
        assert IntentType.PRIVILEGE_ESCALATION.value == "privilege_escalation"

    def test_pwn_values(self):
        assert IntentType.BINARY_ANALYSIS.value == "binary_analysis"
        assert IntentType.PWN_EXPLOIT.value == "pwn_exploit"

    def test_ctf_values(self):
        assert IntentType.CTF_SOLVE.value == "ctf_solve"
        assert IntentType.FLAG_HUNT.value == "flag_hunt"

    def test_general_values(self):
        assert IntentType.COMPREHENSIVE.value == "comprehensive"
        assert IntentType.UNKNOWN.value == "unknown"


# ===================== TargetType Tests =====================

class TestTargetType:
    def test_values(self):
        assert TargetType.WEB.value == "web"
        assert TargetType.NETWORK.value == "network"
        assert TargetType.BINARY.value == "binary"
        assert TargetType.DOMAIN.value == "domain"
        assert TargetType.CTF.value == "ctf"
        assert TargetType.UNKNOWN.value == "unknown"

    def test_member_count(self):
        assert len(TargetType) == 6


# ===================== Intent Tests =====================

class TestIntent:
    def test_defaults(self):
        intent = Intent(intent_type=IntentType.UNKNOWN, confidence=0.5)
        assert intent.target_type == TargetType.UNKNOWN
        assert intent.extracted_target == ""
        assert intent.suggested_tools == []
        assert intent.parameters == {}
        assert intent.reasoning == ""

    def test_with_values(self):
        intent = Intent(
            intent_type=IntentType.SQL_INJECTION,
            confidence=0.9,
            target_type=TargetType.WEB,
            extracted_target="http://target.com",
            suggested_tools=["sqlmap_scan"],
            parameters={"level": 3},
            reasoning="Found SQL keywords",
        )
        assert intent.intent_type == IntentType.SQL_INJECTION
        assert intent.confidence == 0.9
        assert intent.target_type == TargetType.WEB

    def test_to_dict(self):
        intent = Intent(
            intent_type=IntentType.PORT_SCAN,
            confidence=0.8,
            target_type=TargetType.NETWORK,
            extracted_target="10.0.0.1",
            suggested_tools=["nmap_scan"],
            parameters={"ports": "80,443"},
            reasoning="Port scan requested",
        )
        d = intent.to_dict()
        assert d["intent"] == "port_scan"
        assert d["confidence"] == 0.8
        assert d["target_type"] == "network"
        assert d["target"] == "10.0.0.1"
        assert d["tools"] == ["nmap_scan"]
        assert d["parameters"]["ports"] == "80,443"
        assert d["reasoning"] == "Port scan requested"

    def test_mutable_defaults_independent(self):
        i1 = Intent(intent_type=IntentType.UNKNOWN, confidence=0.5)
        i2 = Intent(intent_type=IntentType.UNKNOWN, confidence=0.5)
        i1.suggested_tools.append("nmap")
        i1.parameters["key"] = "val"
        assert i2.suggested_tools == []
        assert i2.parameters == {}


# ===================== IntentAnalyzer Init Tests =====================

class TestIntentAnalyzerInit:
    def test_defaults(self):
        analyzer = IntentAnalyzer()
        assert analyzer.history == []

    def test_class_maps_exist(self):
        assert len(IntentAnalyzer.INTENT_KEYWORDS) > 0
        assert len(IntentAnalyzer.INTENT_TOOLS) > 0
        assert len(IntentAnalyzer.TARGET_PATTERNS) > 0


# ===================== analyze - Intent Identification Tests =====================

class TestAnalyzeIntentIdentification:
    def test_port_scan(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("扫描目标端口")
        assert result.intent_type == IntentType.PORT_SCAN

    def test_nmap_keyword(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("use nmap to scan")
        assert result.intent_type == IntentType.PORT_SCAN

    def test_sql_injection(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("测试SQL注入漏洞")
        assert result.intent_type == IntentType.SQL_INJECTION

    def test_sqlmap_keyword(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("run sqlmap against the target")
        assert result.intent_type == IntentType.SQL_INJECTION

    def test_xss(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("测试xss跨站脚本")
        assert result.intent_type == IntentType.XSS

    def test_dir_scan(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("扫描目录路径文件")
        assert result.intent_type == IntentType.DIR_SCAN

    def test_password_attack(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("密码爆破登录")
        assert result.intent_type == IntentType.PASSWORD_ATTACK

    def test_subdomain_enum(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("枚举子域名")
        assert result.intent_type == IntentType.SUBDOMAIN_ENUM

    def test_exploit(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("利用漏洞exploit")
        assert result.intent_type == IntentType.EXPLOIT

    def test_binary_analysis(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("分析二进制binary文件")
        assert result.intent_type == IntentType.BINARY_ANALYSIS

    def test_pwn(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("pwn overflow溢出")
        assert result.intent_type == IntentType.PWN_EXPLOIT

    def test_ctf(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("ctf解题找flag")
        assert result.intent_type == IntentType.CTF_SOLVE

    def test_comprehensive(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("全面渗透测试")
        assert result.intent_type == IntentType.COMPREHENSIVE

    def test_osint(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("信息收集osint")
        assert result.intent_type == IntentType.OSINT

    def test_unknown(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("hello world")
        assert result.intent_type == IntentType.UNKNOWN
        assert result.confidence == 0.3

    def test_confidence_range(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("nmap scan port")
        assert 0 < result.confidence <= 1.0


# ===================== analyze - Target Extraction Tests =====================

class TestAnalyzeTargetExtraction:
    def test_web_url(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("扫描 http://example.com/api 端口")
        assert result.target_type == TargetType.WEB
        assert result.extracted_target == "http://example.com/api"

    def test_https_url(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("scan https://secure.site.com")
        assert result.target_type == TargetType.WEB
        assert result.extracted_target == "https://secure.site.com"

    def test_ip_address(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("扫描 192.168.1.100 端口")
        assert result.target_type == TargetType.NETWORK
        assert result.extracted_target == "192.168.1.100"

    def test_cidr(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("scan 10.0.0.0/24")
        assert result.target_type == TargetType.NETWORK

    def test_binary_path(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("分析 /tmp/challenge.elf binary")
        assert result.target_type == TargetType.BINARY
        assert ".elf" in result.extracted_target

    def test_domain(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("枚举 example.com 子域名")
        assert result.target_type == TargetType.DOMAIN

    def test_no_target(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("help me")
        assert result.target_type == TargetType.UNKNOWN
        assert result.extracted_target == ""

    def test_web_takes_priority_over_domain(self):
        """Web URL patterns are checked before domain patterns."""
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("扫描 http://example.com 端口")
        assert result.target_type == TargetType.WEB


# ===================== analyze - Suggested Tools Tests =====================

class TestAnalyzeSuggestedTools:
    def test_sql_tools(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("sql injection test")
        assert "sqlmap_scan" in result.suggested_tools

    def test_tools_limit(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("comprehensive scan")
        assert len(result.suggested_tools) <= 5

    def test_web_target_adds_whatweb(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("sql injection http://target.com")
        assert "whatweb_scan" in result.suggested_tools

    def test_network_target_adds_nmap(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("exploit 192.168.1.1 vulnerability")
        if result.target_type == TargetType.NETWORK:
            assert "nmap_scan" in result.suggested_tools

    def test_binary_target_adds_pwn_check(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("分析 /tmp/test.elf binary")
        if result.target_type == TargetType.BINARY:
            assert "quick_pwn_check" in result.suggested_tools


# ===================== analyze - Parameter Extraction Tests =====================

class TestAnalyzeParameterExtraction:
    def test_port_extraction(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("扫描端口:80,443 nmap")
        assert result.parameters.get("ports") == "80,443"

    def test_username_extraction(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("用户名:admin 密码爆破")
        assert result.parameters.get("username") == "admin"

    def test_depth_thorough(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("全面深度扫描")
        assert result.parameters.get("depth") == "thorough"

    def test_depth_quick(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("快速扫描端口")
        assert result.parameters.get("depth") == "quick"

    def test_no_params(self):
        analyzer = IntentAnalyzer()
        result = analyzer.analyze("hello world")
        assert result.parameters == {}


# ===================== analyze - History Tests =====================

class TestAnalyzeHistory:
    def test_records_history(self):
        analyzer = IntentAnalyzer()
        analyzer.analyze("scan port")
        analyzer.analyze("sql injection")
        assert len(analyzer.history) == 2

    def test_get_history(self):
        analyzer = IntentAnalyzer()
        analyzer.analyze("nmap scan")
        analyzer.analyze("sqlmap test")
        history = analyzer.get_history()
        assert len(history) == 2
        assert history[0]["intent"] == IntentType.PORT_SCAN.value

    def test_get_history_limit(self):
        analyzer = IntentAnalyzer()
        for i in range(20):
            analyzer.analyze(f"scan port {i}")
        history = analyzer.get_history(limit=5)
        assert len(history) == 5


# ===================== suggest_next_intent Tests =====================

class TestSuggestNextIntent:
    def test_after_port_scan(self):
        analyzer = IntentAnalyzer()
        intent = Intent(intent_type=IntentType.PORT_SCAN, confidence=0.9)
        suggestions = analyzer.suggest_next_intent(intent)
        assert len(suggestions) > 0
        assert any("端口" in s or "服务" in s or "漏洞" in s for s in suggestions)

    def test_after_dir_scan(self):
        analyzer = IntentAnalyzer()
        intent = Intent(intent_type=IntentType.DIR_SCAN, confidence=0.9)
        suggestions = analyzer.suggest_next_intent(intent)
        assert len(suggestions) > 0

    def test_after_subdomain(self):
        analyzer = IntentAnalyzer()
        intent = Intent(intent_type=IntentType.SUBDOMAIN_ENUM, confidence=0.9)
        suggestions = analyzer.suggest_next_intent(intent)
        assert len(suggestions) > 0

    def test_no_suggestion_for_unknown(self):
        analyzer = IntentAnalyzer()
        intent = Intent(intent_type=IntentType.UNKNOWN, confidence=0.3)
        suggestions = analyzer.suggest_next_intent(intent)
        assert suggestions == []


# ===================== get_intent_analyzer Tests =====================

class TestGetIntentAnalyzer:
    def test_returns_instance(self):
        import kali_mcp.ai.intent as mod
        mod._global_analyzer = None
        analyzer = get_intent_analyzer()
        assert isinstance(analyzer, IntentAnalyzer)

    def test_returns_same_instance(self):
        import kali_mcp.ai.intent as mod
        mod._global_analyzer = None
        a1 = get_intent_analyzer()
        a2 = get_intent_analyzer()
        assert a1 is a2
