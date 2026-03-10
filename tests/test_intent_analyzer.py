"""
Comprehensive tests for IntentAnalyzer (kali_mcp/core/intent_analyzer.py)

Covers every public and private method, all enum values, dataclass defaults,
edge cases, and integration through the full analyze() pipeline.

Sections:
- Enums: AttackIntent, TargetType, ConstraintType
- Dataclasses: TargetInfo, IntentAnalysis, ContextHint
- IntentAnalyzer.__init__
- IntentAnalyzer._is_internal_ip
- IntentAnalyzer._is_ctf_domain
- IntentAnalyzer._analyze_target
- IntentAnalyzer._extract_targets
- IntentAnalyzer._identify_intent
- IntentAnalyzer._detect_constraints
- IntentAnalyzer._assess_priority
- IntentAnalyzer._suggest_strategy
- IntentAnalyzer._suggest_tools
- IntentAnalyzer._calculate_confidence
- IntentAnalyzer.analyze (full pipeline integration)
"""

import pytest
from datetime import datetime
from dataclasses import fields

from kali_mcp.core.intent_analyzer import (
    IntentAnalyzer,
    AttackIntent,
    TargetType,
    ConstraintType,
    TargetInfo,
    IntentAnalysis,
    ContextHint,
)


# ========================= Fixtures =========================


@pytest.fixture
def analyzer():
    """Fresh IntentAnalyzer instance for each test."""
    return IntentAnalyzer()


# ========================= Enum Tests =========================


class TestAttackIntentEnum:
    """Verify all AttackIntent members and their string values."""

    def test_member_count(self):
        assert len(AttackIntent) == 11

    @pytest.mark.parametrize(
        "member, value",
        [
            (AttackIntent.RECONNAISSANCE, "reconnaissance"),
            (AttackIntent.VULNERABILITY_SCANNING, "vuln_scan"),
            (AttackIntent.EXPLOITATION, "exploitation"),
            (AttackIntent.PRIVILEGE_ESCALATION, "privilege_escal"),
            (AttackIntent.LATERAL_MOVEMENT, "lateral_movement"),
            (AttackIntent.DATA_EXFILTRATION, "data_exfiltration"),
            (AttackIntent.PERSISTENCE, "persistence"),
            (AttackIntent.COVERAGE_ANALYSIS, "coverage_analysis"),
            (AttackIntent.FULL_COMPROMISE, "full_compromise"),
            (AttackIntent.CTF_SOLVING, "ctf_solving"),
            (AttackIntent.APT_SIMULATION, "apt_simulation"),
        ],
    )
    def test_member_value(self, member, value):
        assert member.value == value

    def test_lookup_by_value(self):
        assert AttackIntent("reconnaissance") == AttackIntent.RECONNAISSANCE

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            AttackIntent("nonexistent")


class TestTargetTypeEnum:
    """Verify all TargetType members and their string values."""

    def test_member_count(self):
        assert len(TargetType) == 7

    @pytest.mark.parametrize(
        "member, value",
        [
            (TargetType.URL, "url"),
            (TargetType.IP_ADDRESS, "ip"),
            (TargetType.DOMAIN, "domain"),
            (TargetType.NETWORK_RANGE, "network"),
            (TargetType.FILE, "file"),
            (TargetType.BINARY, "binary"),
            (TargetType.UNKNOWN, "unknown"),
        ],
    )
    def test_member_value(self, member, value):
        assert member.value == value


class TestConstraintTypeEnum:
    """Verify all ConstraintType members and their string values."""

    def test_member_count(self):
        assert len(ConstraintType) == 6

    @pytest.mark.parametrize(
        "member, value",
        [
            (ConstraintType.AUTHORIZATION, "authorization"),
            (ConstraintType.TIME_LIMIT, "time_limit"),
            (ConstraintType.SCOPE, "scope"),
            (ConstraintType.IMPACT_LEVEL, "impact_level"),
            (ConstraintType.RESOURCE_LIMIT, "resource_limit"),
            (ConstraintType.LEGAL, "legal"),
        ],
    )
    def test_member_value(self, member, value):
        assert member.value == value


# ========================= Dataclass Tests =========================


class TestTargetInfoDataclass:
    """Verify TargetInfo field names, defaults, and construction."""

    def test_required_fields(self):
        t = TargetInfo(original="x", type=TargetType.URL, value="x")
        assert t.original == "x"
        assert t.type == TargetType.URL
        assert t.value == "x"

    def test_default_optional_fields(self):
        t = TargetInfo(original="x", type=TargetType.URL, value="x")
        assert t.protocol is None
        assert t.port is None
        assert t.path is None
        assert t.is_ctf is False
        assert t.is_internal is False
        assert t.confidence == 1.0

    def test_all_fields_set(self):
        t = TargetInfo(
            original="http://ctf.local:8080/flag",
            type=TargetType.URL,
            value="http://ctf.local:8080/flag",
            protocol="http",
            port=8080,
            path="/flag",
            is_ctf=True,
            is_internal=True,
            confidence=0.95,
        )
        assert t.protocol == "http"
        assert t.port == 8080
        assert t.path == "/flag"
        assert t.is_ctf is True
        assert t.is_internal is True
        assert t.confidence == 0.95


class TestIntentAnalysisDataclass:
    """Verify IntentAnalysis field names, defaults, and construction."""

    def test_required_fields(self):
        ia = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[],
            constraints=[],
        )
        assert ia.user_input == "test"
        assert ia.intent == AttackIntent.RECONNAISSANCE
        assert ia.targets == []
        assert ia.constraints == []

    def test_default_optional_fields(self):
        ia = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[],
            constraints=[],
        )
        assert ia.priority == 5
        assert ia.confidence == 0.0
        assert ia.suggested_strategy is None
        assert ia.estimated_duration is None
        assert ia.required_tools == []
        assert isinstance(ia.analysis_time, datetime)
        assert ia.reasoning == []

    def test_mutable_defaults_are_independent(self):
        """Ensure default_factory lists are not shared between instances."""
        ia1 = IntentAnalysis(
            user_input="a", intent=AttackIntent.RECONNAISSANCE,
            targets=[], constraints=[],
        )
        ia2 = IntentAnalysis(
            user_input="b", intent=AttackIntent.RECONNAISSANCE,
            targets=[], constraints=[],
        )
        ia1.required_tools.append("nmap")
        ia1.reasoning.append("step1")
        assert ia2.required_tools == []
        assert ia2.reasoning == []


class TestContextHintDataclass:
    """Verify ContextHint construction and default weight."""

    def test_basic_construction(self):
        ch = ContextHint(
            keywords={"ctf", "flag"},
            patterns=[r"\bctf\b"],
            intent=AttackIntent.CTF_SOLVING,
        )
        assert ch.keywords == {"ctf", "flag"}
        assert ch.patterns == [r"\bctf\b"]
        assert ch.intent == AttackIntent.CTF_SOLVING
        assert ch.weight == 1.0

    def test_custom_weight(self):
        ch = ContextHint(
            keywords=set(),
            patterns=[],
            intent=AttackIntent.RECONNAISSANCE,
            weight=3.5,
        )
        assert ch.weight == 3.5


# ========================= IntentAnalyzer.__init__ =========================


class TestIntentAnalyzerInit:
    """Verify that __init__ sets up all required internal state."""

    def test_intent_keywords_populated(self, analyzer):
        kw = analyzer._intent_keywords
        assert isinstance(kw, dict)
        assert len(kw) > 0
        # Spot-check a few intents are present
        assert AttackIntent.RECONNAISSANCE in kw
        assert AttackIntent.CTF_SOLVING in kw
        assert AttackIntent.APT_SIMULATION in kw

    def test_context_hints_populated(self, analyzer):
        hints = analyzer._context_hints
        assert isinstance(hints, list)
        assert len(hints) >= 3  # at least CTF, APT, vuln_scan hints

    def test_target_patterns_populated(self, analyzer):
        pats = analyzer._target_patterns
        assert isinstance(pats, dict)
        assert "url" in pats
        assert "ip_with_port" in pats
        assert "cidr" in pats
        assert "domain" in pats

    def test_ctf_platforms_set(self, analyzer):
        platforms = analyzer._ctf_platforms
        assert isinstance(platforms, set)
        assert "ctf" in platforms
        assert "hackthebox" in platforms
        assert "tryhackme" in platforms
        assert "portswigger" in platforms
        assert "picoctf" in platforms
        assert "dasctf" in platforms


# ========================= _is_internal_ip =========================


class TestIsInternalIP:
    """RFC1918 private address detection."""

    # --- 10.0.0.0/8 ---
    @pytest.mark.parametrize(
        "ip",
        ["10.0.0.0", "10.0.0.1", "10.255.255.255", "10.1.2.3"],
    )
    def test_10_block(self, analyzer, ip):
        assert analyzer._is_internal_ip(ip) is True

    # --- 172.16.0.0/12 ---
    @pytest.mark.parametrize(
        "ip",
        ["172.16.0.1", "172.20.1.1", "172.31.255.255"],
    )
    def test_172_16_to_31(self, analyzer, ip):
        assert analyzer._is_internal_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        ["172.15.255.255", "172.32.0.0", "172.0.0.1"],
    )
    def test_172_outside_range(self, analyzer, ip):
        assert analyzer._is_internal_ip(ip) is False

    # --- 192.168.0.0/16 ---
    @pytest.mark.parametrize(
        "ip",
        ["192.168.0.1", "192.168.1.1", "192.168.255.255"],
    )
    def test_192_168_block(self, analyzer, ip):
        assert analyzer._is_internal_ip(ip) is True

    def test_192_167_not_internal(self, analyzer):
        assert analyzer._is_internal_ip("192.167.1.1") is False

    def test_192_169_not_internal(self, analyzer):
        assert analyzer._is_internal_ip("192.169.1.1") is False

    # --- Public IPs ---
    @pytest.mark.parametrize(
        "ip",
        ["8.8.8.8", "1.1.1.1", "142.250.80.46", "93.184.216.34"],
    )
    def test_public_ips(self, analyzer, ip):
        assert analyzer._is_internal_ip(ip) is False

    # --- Invalid inputs ---
    def test_empty_string(self, analyzer):
        assert analyzer._is_internal_ip("") is False

    def test_garbage_string(self, analyzer):
        assert analyzer._is_internal_ip("not-an-ip") is False

    def test_too_few_octets(self, analyzer):
        assert analyzer._is_internal_ip("10.0.1") is False

    def test_too_many_octets(self, analyzer):
        assert analyzer._is_internal_ip("10.0.0.1.5") is False

    def test_non_numeric_octet_in_10_block(self, analyzer):
        # The 10.x check returns True after parsing only the first octet,
        # so "10.abc.0.1" is considered internal (first_octet == 10).
        assert analyzer._is_internal_ip("10.abc.0.1") is True

    def test_non_numeric_octet_in_172_block(self, analyzer):
        # For 172.x, it tries int(parts[1]) which raises ValueError -> False
        assert analyzer._is_internal_ip("172.abc.0.1") is False

    def test_cidr_notation_10_block(self, analyzer):
        # "10.0.0.0/8" -> first_octet=10 -> returns True before parsing later parts
        assert analyzer._is_internal_ip("10.0.0.0/8") is True

    def test_cidr_notation_192_block(self, analyzer):
        # "192.168.0.0/16" -> parts[3]='0/16' is never parsed in 192.168 branch
        # so it still returns True (first_octet==192 and int(parts[1])==168)
        assert analyzer._is_internal_ip("192.168.0.0/16") is True

    def test_cidr_notation_172_block(self, analyzer):
        # "172.16.0.0/12" -> first_octet=172, int(parts[1])=16 -> True
        assert analyzer._is_internal_ip("172.16.0.0/12") is True


# ========================= _is_ctf_domain =========================


class TestIsCTFDomain:
    """CTF platform domain detection."""

    @pytest.mark.parametrize(
        "domain",
        [
            "ctf.example.com",
            "challenge.ctf.org",
            "app.hackthebox.com",
            "tryhackme.com",
            "labs.portswigger.net",
            "picoctf.org",
            "dasctf.com",
        ],
    )
    def test_ctf_domains_detected(self, analyzer, domain):
        assert analyzer._is_ctf_domain(domain) is True

    @pytest.mark.parametrize(
        "domain",
        [
            "example.com",
            "google.com",
            "github.com",
            "192.168.1.1",
        ],
    )
    def test_non_ctf_domains(self, analyzer, domain):
        assert analyzer._is_ctf_domain(domain) is False

    def test_case_insensitive(self, analyzer):
        assert analyzer._is_ctf_domain("CTF.EXAMPLE.COM") is True
        assert analyzer._is_ctf_domain("HackTheBox.com") is True

    def test_empty_string(self, analyzer):
        assert analyzer._is_ctf_domain("") is False


# ========================= _analyze_target =========================


class TestAnalyzeTarget:
    """Single target value analysis (URL parsing, IP:PORT parsing)."""

    # --- URL parsing ---
    def test_http_url(self, analyzer):
        t = analyzer._analyze_target("http://example.com/login")
        assert t is not None
        assert t.type == TargetType.URL
        assert t.protocol == "http"
        assert t.path == "/login"
        assert t.port is None

    def test_https_url(self, analyzer):
        t = analyzer._analyze_target("https://secure.example.com/api")
        assert t is not None
        assert t.type == TargetType.URL
        assert t.protocol == "https"
        assert t.path == "/api"

    def test_url_with_port(self, analyzer):
        t = analyzer._analyze_target("http://example.com:8080/path")
        assert t is not None
        assert t.type == TargetType.URL
        assert t.port == 8080
        assert t.protocol == "http"
        assert t.path == "/path"

    def test_url_ctf_domain(self, analyzer):
        t = analyzer._analyze_target("http://ctf.challenge.org/flag")
        assert t is not None
        assert t.is_ctf is True

    def test_url_non_ctf_domain(self, analyzer):
        t = analyzer._analyze_target("http://example.com/page")
        assert t is not None
        assert t.is_ctf is False

    def test_url_no_path(self, analyzer):
        t = analyzer._analyze_target("http://example.com")
        assert t is not None
        assert t.type == TargetType.URL
        # urlparse returns '' for path when there's no trailing slash
        assert t.path is not None

    # --- IP:PORT parsing ---
    def test_ip_port(self, analyzer):
        t = analyzer._analyze_target("192.168.1.1:8080")
        assert t is not None
        assert t.type == TargetType.IP_ADDRESS
        assert t.value == "192.168.1.1"
        assert t.port == 8080

    def test_ip_port_internal(self, analyzer):
        t = analyzer._analyze_target("10.0.0.5:22")
        assert t is not None
        assert t.is_internal is True
        assert t.port == 22

    def test_ip_port_public(self, analyzer):
        t = analyzer._analyze_target("8.8.8.8:53")
        assert t is not None
        assert t.is_internal is False

    # --- Returns None for unrecognized ---
    def test_plain_ip_returns_none(self, analyzer):
        """_analyze_target only handles URL and IP:PORT, not plain IP."""
        result = analyzer._analyze_target("192.168.1.1")
        assert result is None

    def test_plain_domain_returns_none(self, analyzer):
        result = analyzer._analyze_target("example.com")
        assert result is None

    def test_garbage_returns_none(self, analyzer):
        result = analyzer._analyze_target("some random text")
        assert result is None

    def test_empty_returns_none(self, analyzer):
        result = analyzer._analyze_target("")
        assert result is None

    def test_cidr_returns_none(self, analyzer):
        result = analyzer._analyze_target("192.168.1.0/24")
        assert result is None


# ========================= _extract_targets =========================


class TestExtractTargets:
    """Target extraction from user input strings."""

    def test_single_http_url(self, analyzer):
        targets = analyzer._extract_targets("scan http://example.com/login")
        urls = [t for t in targets if t.type == TargetType.URL]
        assert len(urls) >= 1
        assert urls[0].protocol == "http"

    def test_single_https_url(self, analyzer):
        targets = analyzer._extract_targets("test https://secure.example.com")
        urls = [t for t in targets if t.type == TargetType.URL]
        assert len(urls) >= 1
        assert urls[0].protocol == "https"

    def test_multiple_urls(self, analyzer):
        targets = analyzer._extract_targets(
            "scan http://a.com and https://b.com"
        )
        urls = [t for t in targets if t.type == TargetType.URL]
        assert len(urls) >= 2

    def test_ip_with_port(self, analyzer):
        targets = analyzer._extract_targets("connect to 192.168.1.1:8080")
        ips = [t for t in targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1
        assert ips[0].port == 8080

    def test_plain_ip_fallback(self, analyzer):
        """When no structured target is found, fallback IP regex should fire."""
        targets = analyzer._extract_targets("scan 10.0.0.5")
        ips = [t for t in targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1
        assert ips[0].is_internal is True

    def test_cidr_extraction(self, analyzer):
        """CIDR should be matched by the cidr pattern in target_patterns."""
        targets = analyzer._extract_targets("scan 192.168.1.0/24 network")
        # The CIDR match goes through _analyze_target which returns None,
        # but the fallback IP regex may pick it up as an IP.
        assert isinstance(targets, list)

    def test_domain_fallback(self, analyzer):
        """When no URL/IP pattern matches, fallback domain regex should fire."""
        targets = analyzer._extract_targets("recon example.com")
        domains = [t for t in targets if t.type == TargetType.DOMAIN]
        assert len(domains) >= 1

    def test_ctf_domain_flag_set(self, analyzer):
        targets = analyzer._extract_targets("solve ctf.challenge.org")
        ctf_targets = [t for t in targets if t.is_ctf]
        assert len(ctf_targets) >= 1

    def test_deduplication(self, analyzer):
        targets = analyzer._extract_targets(
            "scan http://example.com and also http://example.com"
        )
        urls = [t for t in targets if t.type == TargetType.URL]
        # Same URL should appear only once
        assert len(urls) == 1

    def test_no_targets_in_generic_text(self, analyzer):
        targets = analyzer._extract_targets("help me learn hacking basics")
        # Should return empty or near-empty list
        assert isinstance(targets, list)

    def test_mixed_url_and_ip(self, analyzer):
        targets = analyzer._extract_targets(
            "scan http://web.com and 10.0.0.5"
        )
        urls = [t for t in targets if t.type == TargetType.URL]
        # The URL should be found via primary patterns
        assert len(urls) >= 1

    def test_internal_ip_flag_in_fallback(self, analyzer):
        targets = analyzer._extract_targets("scan 172.16.5.10")
        ips = [t for t in targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1
        assert ips[0].is_internal is True

    def test_public_ip_flag_in_fallback(self, analyzer):
        targets = analyzer._extract_targets("scan 8.8.8.8")
        ips = [t for t in targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1
        assert ips[0].is_internal is False


# ========================= _identify_intent =========================


class TestIdentifyIntent:
    """Intent identification from keywords and context hints."""

    # --- Keyword-based intent ---
    def test_recon_keywords(self, analyzer):
        targets = []
        assert analyzer._identify_intent("scan the network", targets) == AttackIntent.RECONNAISSANCE

    def test_recon_chinese_keywords(self, analyzer):
        assert analyzer._identify_intent("信息收集目标", []) == AttackIntent.RECONNAISSANCE

    def test_vuln_scan_keywords(self, analyzer):
        assert analyzer._identify_intent("漏洞扫描 target", []) == AttackIntent.VULNERABILITY_SCANNING

    def test_vuln_scan_english(self, analyzer):
        assert analyzer._identify_intent("check for vuln", []) == AttackIntent.VULNERABILITY_SCANNING

    def test_exploitation_keywords(self, analyzer):
        assert analyzer._identify_intent("exploit the service", []) == AttackIntent.EXPLOITATION

    def test_exploitation_getshell(self, analyzer):
        assert analyzer._identify_intent("getshell on target", []) == AttackIntent.EXPLOITATION

    def test_privesc_keywords(self, analyzer):
        assert analyzer._identify_intent("提权 get root", []) == AttackIntent.PRIVILEGE_ESCALATION

    def test_lateral_movement_keywords(self, analyzer):
        assert analyzer._identify_intent("横向移动 内网渗透", []) == AttackIntent.LATERAL_MOVEMENT

    def test_data_exfiltration_keywords(self, analyzer):
        assert analyzer._identify_intent("dump 数据库 数据", []) == AttackIntent.DATA_EXFILTRATION

    def test_ctf_keywords(self, analyzer):
        assert analyzer._identify_intent("ctf flag 解题", []) == AttackIntent.CTF_SOLVING

    def test_apt_keywords(self, analyzer):
        assert analyzer._identify_intent("apt 攻击链 红队", []) == AttackIntent.APT_SIMULATION

    # --- Context hints boost scoring ---
    def test_ctf_context_hint_weight(self, analyzer):
        """CTF context hint has weight=2.0 so it should dominate."""
        intent = analyzer._identify_intent("find the flag in this ctf", [])
        assert intent == AttackIntent.CTF_SOLVING

    def test_apt_context_hint(self, analyzer):
        intent = analyzer._identify_intent("全流程 apt simulation", [])
        assert intent == AttackIntent.APT_SIMULATION

    # --- Default fallbacks based on target type ---
    def test_default_ctf_from_target(self, analyzer):
        target = TargetInfo(
            original="http://ctf.org", type=TargetType.URL,
            value="http://ctf.org", is_ctf=True,
        )
        intent = analyzer._identify_intent("something", [target])
        assert intent == AttackIntent.CTF_SOLVING

    def test_default_exploitation_from_binary_target(self, analyzer):
        target = TargetInfo(
            original="/tmp/bin", type=TargetType.BINARY, value="/tmp/bin",
        )
        intent = analyzer._identify_intent("analyze this", [target])
        assert intent == AttackIntent.EXPLOITATION

    def test_default_recon_from_file_target(self, analyzer):
        target = TargetInfo(
            original="/tmp/data.pcap", type=TargetType.FILE, value="/tmp/data.pcap",
        )
        intent = analyzer._identify_intent("look at this", [target])
        assert intent == AttackIntent.RECONNAISSANCE

    def test_default_recon_no_keywords_no_targets(self, analyzer):
        intent = analyzer._identify_intent("hello world", [])
        assert intent == AttackIntent.RECONNAISSANCE

    # --- Case insensitivity ---
    def test_case_insensitive_keywords(self, analyzer):
        intent = analyzer._identify_intent("EXPLOIT THE TARGET", [])
        assert intent == AttackIntent.EXPLOITATION


# ========================= _detect_constraints =========================


class TestDetectConstraints:
    """Constraint detection from user input."""

    def test_time_constraint_fast(self, analyzer):
        constraints = analyzer._detect_constraints("快速扫描目标")
        types = [c["type"] for c in constraints]
        assert ConstraintType.TIME_LIMIT in types
        time_c = [c for c in constraints if c["type"] == ConstraintType.TIME_LIMIT]
        assert any(c.get("mode") == "fast" for c in time_c)

    @pytest.mark.parametrize("kw", ["分钟", "小时内", "小时", "秒内", "急"])
    def test_time_keywords(self, analyzer, kw):
        constraints = analyzer._detect_constraints(f"5{kw}完成")
        types = [c["type"] for c in constraints]
        assert ConstraintType.TIME_LIMIT in types

    def test_auth_constraint(self, analyzer):
        constraints = analyzer._detect_constraints("已授权的测试")
        types = [c["type"] for c in constraints]
        assert ConstraintType.AUTHORIZATION in types

    @pytest.mark.parametrize("kw", ["授权", "许可", "允许", "合法", "正式"])
    def test_auth_keywords(self, analyzer, kw):
        constraints = analyzer._detect_constraints(f"这是{kw}的")
        types = [c["type"] for c in constraints]
        assert ConstraintType.AUTHORIZATION in types

    def test_scope_constraint(self, analyzer):
        constraints = analyzer._detect_constraints("只扫描80端口")
        types = [c["type"] for c in constraints]
        assert ConstraintType.SCOPE in types

    @pytest.mark.parametrize("kw", ["只扫描", "仅", "不要", "避免", "限制"])
    def test_scope_keywords(self, analyzer, kw):
        constraints = analyzer._detect_constraints(f"{kw}攻击生产环境")
        types = [c["type"] for c in constraints]
        assert ConstraintType.SCOPE in types

    def test_ctf_constraint_by_keyword(self, analyzer):
        constraints = analyzer._detect_constraints("ctf challenge")
        types = [c["type"] for c in constraints]
        assert ConstraintType.TIME_LIMIT in types
        ctf_c = [c for c in constraints if c.get("mode") == "aggressive"]
        assert len(ctf_c) >= 1

    def test_ctf_constraint_by_platform_keyword(self, analyzer):
        constraints = analyzer._detect_constraints("solve the pico challenge")
        ctf_c = [c for c in constraints if c.get("mode") == "aggressive"]
        assert len(ctf_c) >= 1

    def test_no_constraints(self, analyzer):
        constraints = analyzer._detect_constraints("scan 10.0.0.1")
        assert isinstance(constraints, list)
        # No specific constraint keywords, but might still be empty
        # Just verify it doesn't crash

    def test_multiple_constraints(self, analyzer):
        constraints = analyzer._detect_constraints("快速 授权 只扫描 ctf")
        types = [c["type"] for c in constraints]
        assert ConstraintType.TIME_LIMIT in types
        assert ConstraintType.AUTHORIZATION in types
        assert ConstraintType.SCOPE in types


# ========================= _assess_priority =========================


class TestAssessPriority:
    """Priority assessment (1-10 range, keyword and intent adjustments)."""

    def test_default_priority(self, analyzer):
        p = analyzer._assess_priority("some input", AttackIntent.RECONNAISSANCE)
        assert p == 5

    @pytest.mark.parametrize("kw", ["紧急", "重要", "关键", "立即", "马上", "ctf", "flag"])
    def test_high_priority_keywords(self, analyzer, kw):
        p = analyzer._assess_priority(f"{kw} scan", AttackIntent.RECONNAISSANCE)
        assert p == 8

    @pytest.mark.parametrize("kw", ["后台", "稍后", "有空", "慢速", "测试"])
    def test_low_priority_keywords(self, analyzer, kw):
        p = analyzer._assess_priority(f"{kw} scan", AttackIntent.RECONNAISSANCE)
        assert p == 3

    def test_ctf_intent_boosts_to_at_least_7(self, analyzer):
        # Default priority=5, CTF max(5,7)=7
        p = analyzer._assess_priority("some input", AttackIntent.CTF_SOLVING)
        assert p >= 7

    def test_ctf_intent_with_high_keyword(self, analyzer):
        # High keyword sets 8, CTF max(8,7)=8
        p = analyzer._assess_priority("紧急 task", AttackIntent.CTF_SOLVING)
        assert p == 8

    def test_apt_intent_caps_at_6(self, analyzer):
        # Default priority=5, APT min(5,6)=5
        p = analyzer._assess_priority("some input", AttackIntent.APT_SIMULATION)
        assert p == 5

    def test_apt_intent_with_high_keyword(self, analyzer):
        # High keyword sets 8, APT min(8,6)=6
        p = analyzer._assess_priority("紧急 attack", AttackIntent.APT_SIMULATION)
        assert p == 6

    def test_priority_clamped_min(self, analyzer):
        # Even with the lowest possible adjustments, should be >= 1
        p = analyzer._assess_priority("稍后", AttackIntent.APT_SIMULATION)
        assert p >= 1

    def test_priority_clamped_max(self, analyzer):
        p = analyzer._assess_priority("紧急 ctf flag 立即", AttackIntent.CTF_SOLVING)
        assert p <= 10

    def test_both_high_and_low_keywords(self, analyzer):
        """When both high and low keywords present, low wins (runs second)."""
        p = analyzer._assess_priority("紧急 测试", AttackIntent.RECONNAISSANCE)
        # High sets 8, then low overrides to 3
        assert p == 3


# ========================= _suggest_strategy =========================


class TestSuggestStrategy:
    """Strategy suggestion based on intent."""

    @pytest.mark.parametrize(
        "intent, expected",
        [
            (AttackIntent.CTF_SOLVING, "ctf_intensive"),
            (AttackIntent.APT_SIMULATION, "comprehensive_apt"),
            (AttackIntent.RECONNAISSANCE, "fast_recon"),
            (AttackIntent.VULNERABILITY_SCANNING, "vuln_scan"),
            (AttackIntent.EXPLOITATION, "exploit_chain"),
        ],
    )
    def test_known_strategies(self, analyzer, intent, expected):
        assert analyzer._suggest_strategy(intent, []) == expected

    @pytest.mark.parametrize(
        "intent",
        [
            AttackIntent.PRIVILEGE_ESCALATION,
            AttackIntent.LATERAL_MOVEMENT,
            AttackIntent.DATA_EXFILTRATION,
            AttackIntent.PERSISTENCE,
            AttackIntent.COVERAGE_ANALYSIS,
            AttackIntent.FULL_COMPROMISE,
        ],
    )
    def test_default_balanced(self, analyzer, intent):
        assert analyzer._suggest_strategy(intent, []) == "balanced"


# ========================= _suggest_tools =========================


class TestSuggestTools:
    """Tool suggestion based on intent and target types."""

    def test_recon_tools(self, analyzer):
        tools = analyzer._suggest_tools(AttackIntent.RECONNAISSANCE, [])
        assert "nmap_scan" in tools
        assert "subfinder_scan" in tools
        assert "whatweb_scan" in tools

    def test_vuln_scan_tools(self, analyzer):
        tools = analyzer._suggest_tools(AttackIntent.VULNERABILITY_SCANNING, [])
        assert "nuclei_scan" in tools
        assert "nikto_scan" in tools
        assert "sqlmap_scan" in tools

    def test_exploitation_tools(self, analyzer):
        tools = analyzer._suggest_tools(AttackIntent.EXPLOITATION, [])
        assert "metasploit_run" in tools
        assert "searchsploit_search" in tools

    def test_ctf_tools(self, analyzer):
        tools = analyzer._suggest_tools(AttackIntent.CTF_SOLVING, [])
        assert "intelligent_ctf_solve" in tools
        assert "ctf_web_attack" in tools

    def test_default_tools(self, analyzer):
        """Intents not explicitly mapped get nmap + nuclei."""
        tools = analyzer._suggest_tools(AttackIntent.PERSISTENCE, [])
        assert "nmap_scan" in tools
        assert "nuclei_scan" in tools

    def test_url_target_extends_tools(self, analyzer):
        target = TargetInfo(
            original="http://example.com", type=TargetType.URL,
            value="http://example.com",
        )
        tools = analyzer._suggest_tools(AttackIntent.RECONNAISSANCE, [target])
        assert "gobuster_scan" in tools
        assert "dirb_scan" in tools

    def test_domain_target_extends_tools(self, analyzer):
        target = TargetInfo(
            original="example.com", type=TargetType.DOMAIN, value="example.com",
        )
        tools = analyzer._suggest_tools(AttackIntent.RECONNAISSANCE, [target])
        assert "amass_enum" in tools
        assert "dnsrecon_scan" in tools

    def test_deduplication(self, analyzer):
        """Even if tool appears in both base and extension, result is deduplicated."""
        target = TargetInfo(
            original="http://x.com", type=TargetType.URL, value="http://x.com",
        )
        tools = analyzer._suggest_tools(AttackIntent.RECONNAISSANCE, [target])
        assert len(tools) == len(set(tools))

    def test_multiple_targets_extend(self, analyzer):
        t1 = TargetInfo(
            original="http://x.com", type=TargetType.URL, value="http://x.com",
        )
        t2 = TargetInfo(
            original="example.com", type=TargetType.DOMAIN, value="example.com",
        )
        tools = analyzer._suggest_tools(AttackIntent.RECONNAISSANCE, [t1, t2])
        assert "gobuster_scan" in tools
        assert "amass_enum" in tools


# ========================= _calculate_confidence =========================


class TestCalculateConfidence:
    """Confidence calculation logic."""

    def test_base_confidence_no_targets(self, analyzer):
        c = analyzer._calculate_confidence([], AttackIntent.RECONNAISSANCE)
        assert c == 0.5

    def test_with_targets_adds_02(self, analyzer):
        target = TargetInfo(
            original="x", type=TargetType.UNKNOWN, value="x",
        )
        c = analyzer._calculate_confidence([target], AttackIntent.RECONNAISSANCE)
        # 0.5 + 0.2 (has targets) = 0.7
        # type is UNKNOWN so no +0.1
        # intent is RECONNAISSANCE so no +0.1
        assert c == pytest.approx(0.7)

    def test_known_type_adds_01(self, analyzer):
        target = TargetInfo(
            original="x", type=TargetType.URL, value="x",
        )
        c = analyzer._calculate_confidence([target], AttackIntent.RECONNAISSANCE)
        # 0.5 + 0.2 + 0.1 (type not UNKNOWN) = 0.8
        assert c == pytest.approx(0.8)

    def test_non_recon_intent_adds_01(self, analyzer):
        c = analyzer._calculate_confidence([], AttackIntent.EXPLOITATION)
        # 0.5 + 0.1 (intent not RECON) = 0.6
        assert c == pytest.approx(0.6)

    def test_max_confidence(self, analyzer):
        target = TargetInfo(
            original="x", type=TargetType.URL, value="x",
        )
        c = analyzer._calculate_confidence([target], AttackIntent.EXPLOITATION)
        # 0.5 + 0.2 + 0.1 + 0.1 = 0.9
        assert c == pytest.approx(0.9)

    def test_capped_at_1(self, analyzer):
        """Even if somehow all bonuses stack, result should not exceed 1.0."""
        target = TargetInfo(
            original="x", type=TargetType.URL, value="x",
        )
        c = analyzer._calculate_confidence([target], AttackIntent.CTF_SOLVING)
        assert c <= 1.0

    def test_uses_first_target_for_type_check(self, analyzer):
        """Only targets[0].type is checked for the UNKNOWN bonus."""
        t1 = TargetInfo(original="x", type=TargetType.UNKNOWN, value="x")
        t2 = TargetInfo(original="y", type=TargetType.URL, value="y")
        c = analyzer._calculate_confidence([t1, t2], AttackIntent.RECONNAISSANCE)
        # type is UNKNOWN (from first target), so no +0.1 for type
        assert c == pytest.approx(0.7)


# ========================= analyze() Integration =========================


class TestAnalyzeIntegration:
    """Full pipeline integration tests through analyze()."""

    def test_returns_intent_analysis(self, analyzer):
        result = analyzer.analyze("scan http://example.com")
        assert isinstance(result, IntentAnalysis)

    def test_user_input_preserved(self, analyzer):
        text = "scan http://example.com for vulns"
        result = analyzer.analyze(text)
        assert result.user_input == text

    def test_reasoning_populated(self, analyzer):
        result = analyzer.analyze("scan http://example.com")
        assert isinstance(result.reasoning, list)
        assert len(result.reasoning) >= 4  # targets, intent, constraints, priority

    def test_analysis_time_is_datetime(self, analyzer):
        result = analyzer.analyze("test")
        assert isinstance(result.analysis_time, datetime)

    def test_ctf_url_full_pipeline(self, analyzer):
        result = analyzer.analyze("find the flag at http://ctf.challenge.org/vuln")
        assert result.intent == AttackIntent.CTF_SOLVING
        assert result.suggested_strategy == "ctf_intensive"
        assert result.priority >= 7
        urls = [t for t in result.targets if t.type == TargetType.URL]
        assert len(urls) >= 1
        assert urls[0].is_ctf is True

    def test_recon_ip_full_pipeline(self, analyzer):
        result = analyzer.analyze("scan 10.0.0.1")
        assert result.intent == AttackIntent.RECONNAISSANCE
        assert result.suggested_strategy == "fast_recon"
        ips = [t for t in result.targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1
        assert ips[0].is_internal is True

    def test_vuln_scan_full_pipeline(self, analyzer):
        result = analyzer.analyze("漏洞扫描 http://example.com")
        assert result.intent == AttackIntent.VULNERABILITY_SCANNING
        assert result.suggested_strategy == "vuln_scan"
        assert "nuclei_scan" in result.required_tools
        assert len(result.required_tools) > 0

    def test_exploit_full_pipeline(self, analyzer):
        result = analyzer.analyze("exploit target and getshell")
        assert result.intent == AttackIntent.EXPLOITATION
        assert result.suggested_strategy == "exploit_chain"

    def test_apt_full_pipeline(self, analyzer):
        result = analyzer.analyze("全面 渗透测试 全流程 apt 攻击链")
        assert result.intent == AttackIntent.APT_SIMULATION
        assert result.suggested_strategy == "comprehensive_apt"
        assert result.priority <= 6

    def test_privesc_full_pipeline(self, analyzer):
        result = analyzer.analyze("提权 获取root权限")
        assert result.intent == AttackIntent.PRIVILEGE_ESCALATION

    def test_lateral_movement_full_pipeline(self, analyzer):
        result = analyzer.analyze("横向移动 内网渗透 跳板")
        assert result.intent == AttackIntent.LATERAL_MOVEMENT

    def test_data_exfil_full_pipeline(self, analyzer):
        result = analyzer.analyze("dump 数据库 窃取数据")
        assert result.intent == AttackIntent.DATA_EXFILTRATION

    def test_empty_input(self, analyzer):
        result = analyzer.analyze("")
        assert isinstance(result, IntentAnalysis)
        assert result.user_input == ""
        assert result.intent == AttackIntent.RECONNAISSANCE  # default

    def test_no_targets_confidence(self, analyzer):
        result = analyzer.analyze("hello world")
        assert result.confidence == pytest.approx(0.5)

    def test_url_with_constraints(self, analyzer):
        result = analyzer.analyze("快速 授权 漏洞扫描 http://example.com")
        assert result.intent == AttackIntent.VULNERABILITY_SCANNING
        types = [c["type"] for c in result.constraints]
        assert ConstraintType.TIME_LIMIT in types
        assert ConstraintType.AUTHORIZATION in types

    def test_multiple_targets(self, analyzer):
        result = analyzer.analyze(
            "scan http://a.com and http://b.com"
        )
        urls = [t for t in result.targets if t.type == TargetType.URL]
        assert len(urls) >= 2

    def test_ip_port_in_sentence(self, analyzer):
        result = analyzer.analyze("connect to 192.168.1.1:22 via ssh")
        ips = [t for t in result.targets if t.type == TargetType.IP_ADDRESS]
        assert len(ips) >= 1
        assert ips[0].port == 22

    def test_confidence_increases_with_targets_and_intent(self, analyzer):
        r_none = analyzer.analyze("hello")
        r_target = analyzer.analyze("scan http://example.com")
        r_full = analyzer.analyze("漏洞扫描 http://example.com")
        assert r_target.confidence > r_none.confidence
        assert r_full.confidence >= r_target.confidence

    def test_required_tools_deduplicated(self, analyzer):
        result = analyzer.analyze("scan http://a.com and http://b.com")
        assert len(result.required_tools) == len(set(result.required_tools))

    def test_url_extends_tools_with_gobuster(self, analyzer):
        result = analyzer.analyze("scan http://example.com")
        assert "gobuster_scan" in result.required_tools

    def test_domain_extends_tools_with_amass(self, analyzer):
        result = analyzer.analyze("recon example.com")
        # Verify domain tools are suggested
        has_dns_tool = (
            "amass_enum" in result.required_tools
            or "dnsrecon_scan" in result.required_tools
        )
        assert has_dns_tool


# ========================= Edge Cases =========================


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_unicode_input(self, analyzer):
        result = analyzer.analyze("扫描目标 http://example.com 漏洞")
        assert isinstance(result, IntentAnalysis)

    def test_very_long_input(self, analyzer):
        long_input = "scan " * 1000 + "http://example.com"
        result = analyzer.analyze(long_input)
        assert isinstance(result, IntentAnalysis)

    def test_special_characters_in_url(self, analyzer):
        result = analyzer.analyze(
            "scan http://example.com/path?q=test&x=1#section"
        )
        urls = [t for t in result.targets if t.type == TargetType.URL]
        assert len(urls) >= 1

    def test_url_with_encoded_characters(self, analyzer):
        result = analyzer.analyze("scan http://example.com/%2F%2F")
        urls = [t for t in result.targets if t.type == TargetType.URL]
        assert len(urls) >= 1

    def test_ip_at_boundary_172_16(self, analyzer):
        assert analyzer._is_internal_ip("172.16.0.0") is True

    def test_ip_at_boundary_172_31(self, analyzer):
        assert analyzer._is_internal_ip("172.31.255.255") is True

    def test_newlines_in_input(self, analyzer):
        result = analyzer.analyze("scan\nhttp://example.com\n漏洞")
        assert isinstance(result, IntentAnalysis)

    def test_tabs_in_input(self, analyzer):
        result = analyzer.analyze("scan\thttp://example.com")
        assert isinstance(result, IntentAnalysis)

    def test_competing_intents_highest_score_wins(self, analyzer):
        """When multiple intent keywords present, highest scoring intent wins."""
        # "ctf flag 解题" has 3 CTF keywords + context hints
        # vs "scan" which is 1 RECON keyword
        result = analyzer.analyze("ctf flag 解题 scan")
        assert result.intent == AttackIntent.CTF_SOLVING

    def test_only_whitespace_input(self, analyzer):
        result = analyzer.analyze("   ")
        assert isinstance(result, IntentAnalysis)
        assert result.intent == AttackIntent.RECONNAISSANCE

    def test_url_with_https_port_443(self, analyzer):
        t = analyzer._analyze_target("https://example.com:443/path")
        assert t is not None
        assert t.port == 443
        assert t.protocol == "https"
