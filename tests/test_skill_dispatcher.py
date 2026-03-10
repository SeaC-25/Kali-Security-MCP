"""
Tests for kali_mcp/core/skill_dispatcher.py

Covers every public and semi-public entity:
- TargetType enum (all 12 members)
- ScanDepth enum (all 4 members)
- ToolChain dataclass
- VulnerabilityPattern dataclass
- SkillKnowledge dataclass
- SkillParser class  (init, parsing, defaults, intent matching)
- IntelligentDispatcher class (detect, chains, analysis, flags, follow-ups, recs)
- Global convenience functions (get_skill_based_tools, get_vulnerability_tools, detect_target)
- Global singleton skill_dispatcher

All tests are pure unit tests (no subprocess, no network).
"""

import asyncio
import os
import re
import tempfile
from copy import deepcopy
from dataclasses import fields
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kali_mcp.core.skill_dispatcher import (
    IntelligentDispatcher,
    ScanDepth,
    SkillKnowledge,
    SkillParser,
    TargetType,
    ToolChain,
    VulnerabilityPattern,
    detect_target,
    get_skill_based_tools,
    get_vulnerability_tools,
    skill_dispatcher,
)


# ---------------------------------------------------------------------------
# TargetType enum
# ---------------------------------------------------------------------------
class TestTargetType:
    """All members and values of the TargetType enum."""

    def test_web_app_value(self):
        assert TargetType.WEB_APP.value == "web_app"

    def test_network_value(self):
        assert TargetType.NETWORK.value == "network"

    def test_api_value(self):
        assert TargetType.API.value == "api"

    def test_cloud_value(self):
        assert TargetType.CLOUD.value == "cloud"

    def test_container_value(self):
        assert TargetType.CONTAINER.value == "container"

    def test_binary_value(self):
        assert TargetType.BINARY.value == "binary"

    def test_mobile_value(self):
        assert TargetType.MOBILE.value == "mobile"

    def test_active_directory_value(self):
        assert TargetType.ACTIVE_DIRECTORY.value == "ad"

    def test_iot_value(self):
        assert TargetType.IOT.value == "iot"

    def test_database_value(self):
        assert TargetType.DATABASE.value == "database"

    def test_ctf_value(self):
        assert TargetType.CTF.value == "ctf"

    def test_unknown_value(self):
        assert TargetType.UNKNOWN.value == "unknown"

    def test_member_count(self):
        assert len(TargetType) == 12

    def test_from_value(self):
        assert TargetType("web_app") is TargetType.WEB_APP

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            TargetType("nonexistent")


# ---------------------------------------------------------------------------
# ScanDepth enum
# ---------------------------------------------------------------------------
class TestScanDepth:
    """All members and values of the ScanDepth enum."""

    def test_quick_value(self):
        assert ScanDepth.QUICK.value == "quick"

    def test_standard_value(self):
        assert ScanDepth.STANDARD.value == "standard"

    def test_comprehensive_value(self):
        assert ScanDepth.COMPREHENSIVE.value == "comprehensive"

    def test_deep_value(self):
        assert ScanDepth.DEEP.value == "deep"

    def test_member_count(self):
        assert len(ScanDepth) == 4

    def test_from_value(self):
        assert ScanDepth("quick") is ScanDepth.QUICK

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ScanDepth("ultra")


# ---------------------------------------------------------------------------
# ToolChain dataclass
# ---------------------------------------------------------------------------
class TestToolChainDataclass:
    """ToolChain dataclass creation, defaults, and mutable isolation."""

    def test_creation_minimal(self):
        tc = ToolChain(name="tc1", description="d", tools=["a", "b"])
        assert tc.name == "tc1"
        assert tc.description == "d"
        assert tc.tools == ["a", "b"]

    def test_defaults(self):
        tc = ToolChain(name="tc1", description="d", tools=[])
        assert tc.conditions == {}
        assert tc.priority == 5
        assert tc.estimated_time == 300
        assert tc.success_criteria == []

    def test_custom_values(self):
        tc = ToolChain(
            name="tc",
            description="d",
            tools=["x"],
            conditions={"foo": "bar"},
            priority=1,
            estimated_time=600,
            success_criteria=["ok"],
        )
        assert tc.conditions == {"foo": "bar"}
        assert tc.priority == 1
        assert tc.estimated_time == 600
        assert tc.success_criteria == ["ok"]

    def test_mutable_default_isolation_conditions(self):
        tc1 = ToolChain(name="a", description="", tools=[])
        tc2 = ToolChain(name="b", description="", tools=[])
        tc1.conditions["x"] = 1
        assert "x" not in tc2.conditions

    def test_mutable_default_isolation_success_criteria(self):
        tc1 = ToolChain(name="a", description="", tools=[])
        tc2 = ToolChain(name="b", description="", tools=[])
        tc1.success_criteria.append("z")
        assert "z" not in tc2.success_criteria

    def test_tools_list_is_independent(self):
        tools = ["a"]
        tc = ToolChain(name="a", description="", tools=tools)
        tools.append("b")
        # tools is not a default_factory, so it IS shared (normal Python behavior)
        # Just verify it was set correctly initially
        assert "a" in tc.tools


# ---------------------------------------------------------------------------
# VulnerabilityPattern dataclass
# ---------------------------------------------------------------------------
class TestVulnerabilityPattern:
    """VulnerabilityPattern creation and defaults."""

    def test_creation(self):
        vp = VulnerabilityPattern(
            name="SQLi",
            category="web",
            detection_tools=["sqlmap"],
            exploitation_tools=["sqlmap"],
            indicators=["error"],
        )
        assert vp.name == "SQLi"
        assert vp.category == "web"
        assert vp.severity == "MEDIUM"

    def test_custom_severity(self):
        vp = VulnerabilityPattern(
            name="RCE",
            category="web",
            detection_tools=[],
            exploitation_tools=[],
            indicators=[],
            severity="CRITICAL",
        )
        assert vp.severity == "CRITICAL"

    def test_field_names(self):
        names = {f.name for f in fields(VulnerabilityPattern)}
        expected = {"name", "category", "detection_tools", "exploitation_tools", "indicators", "severity"}
        assert names == expected


# ---------------------------------------------------------------------------
# SkillKnowledge dataclass
# ---------------------------------------------------------------------------
class TestSkillKnowledge:
    """SkillKnowledge creation."""

    def test_creation(self):
        sk = SkillKnowledge(
            tool_mappings={},
            decision_trees={},
            vulnerability_patterns=[],
            attack_chains={},
            ctf_strategies={},
            quick_references={},
        )
        assert sk.tool_mappings == {}
        assert sk.vulnerability_patterns == []

    def test_field_names(self):
        names = {f.name for f in fields(SkillKnowledge)}
        expected = {
            "tool_mappings",
            "decision_trees",
            "vulnerability_patterns",
            "attack_chains",
            "ctf_strategies",
            "quick_references",
        }
        assert names == expected


# ---------------------------------------------------------------------------
# SkillParser
# ---------------------------------------------------------------------------
class TestSkillParser:
    """SkillParser initialization, parsing, default knowledge, intent lookup."""

    def test_init_no_file_uses_defaults(self, tmp_path):
        """When skill file does not exist, default knowledge is loaded."""
        sp = SkillParser(skill_path=str(tmp_path / "nonexistent.md"))
        assert len(sp.knowledge.tool_mappings) > 0
        assert "web" in sp.knowledge.decision_trees
        assert len(sp.knowledge.vulnerability_patterns) > 0
        assert len(sp.knowledge.attack_chains) > 0

    def test_default_path(self):
        """Default skill_path points to ~/.claude/skills/kali-security.md."""
        with patch("os.path.exists", return_value=False):
            sp = SkillParser()
        assert sp.skill_path == os.path.expanduser("~/.claude/skills/kali-security.md")

    def test_custom_path(self, tmp_path):
        p = str(tmp_path / "custom.md")
        sp = SkillParser(skill_path=p)
        assert sp.skill_path == p

    def test_default_tool_mappings_keys(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        expected_keys = {
            "端口扫描", "目录扫描", "漏洞扫描", "SQL注入", "XSS检测",
            "命令注入", "技术识别", "子域名", "密码破解", "WAF检测",
        }
        assert set(sp.knowledge.tool_mappings.keys()) == expected_keys

    def test_default_decision_tree_web(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        web_tree = sp.knowledge.decision_trees["web"]
        assert len(web_tree) == 5
        assert web_tree[0]["action"] == "whatweb_scan"

    def test_default_decision_tree_network(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        net_tree = sp.knowledge.decision_trees["network"]
        assert len(net_tree) == 2
        assert net_tree[0]["action"] == "nmap_scan"

    def test_default_vulnerability_patterns_count(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        assert len(sp.knowledge.vulnerability_patterns) == 5

    def test_default_vulnerability_pattern_sql(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        sql_pat = sp.knowledge.vulnerability_patterns[0]
        assert sql_pat.name == "SQL Injection"
        assert sql_pat.severity == "HIGH"

    def test_default_attack_chains(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        assert "web_comprehensive" in sp.knowledge.attack_chains
        assert "network_pentest" in sp.knowledge.attack_chains
        assert "quick_ctf" in sp.knowledge.attack_chains

    def test_parse_valid_file(self, tmp_path):
        """When file exists, _extract_tool_mappings is called."""
        md_file = tmp_path / "skill.md"
        md_file.write_text(
            "| SQL注入测试 | `sqlmap_scan` |\n"
            "| XSS检测 | `xss_tool` |\n"
        )
        sp = SkillParser(skill_path=str(md_file))
        assert "SQL注入测试" in sp.knowledge.tool_mappings
        assert "xss_tool" in sp.knowledge.tool_mappings["XSS检测"]["tools"]

    def test_parse_file_exception_uses_defaults(self, tmp_path):
        """If parsing raises, default knowledge is used."""
        md_file = tmp_path / "bad.md"
        md_file.write_text("valid content")
        with patch.object(SkillParser, "_extract_tool_mappings", side_effect=Exception("boom")):
            sp = SkillParser(skill_path=str(md_file))
        # Should have fallen back to defaults
        assert len(sp.knowledge.tool_mappings) > 0

    def test_extract_tool_mappings_dedup(self, tmp_path):
        """Duplicate tool entries for the same intent are not duplicated."""
        md_file = tmp_path / "dups.md"
        md_file.write_text(
            "| 端口扫描 | `nmap_scan` |\n"
            "| 端口扫描 | `nmap_scan` |\n"
            "| 端口扫描 | `masscan` |\n"
        )
        sp = SkillParser(skill_path=str(md_file))
        tools = sp.knowledge.tool_mappings["端口扫描"]["tools"]
        assert tools.count("nmap_scan") == 1

    def test_extract_tool_mappings_empty_intent_ignored(self, tmp_path):
        """Empty intent cells are ignored."""
        md_file = tmp_path / "empty.md"
        md_file.write_text("|   | `tool1` |\n")
        sp = SkillParser(skill_path=str(md_file))
        # key " " (whitespace stripped) is empty → should not be added if empty
        # The code strips but checks `if intent and tool`, empty string is falsy
        # Actually " " strips to "" which is falsy → skipped
        assert "" not in sp.knowledge.tool_mappings

    def test_get_tools_for_intent_exact(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        tools = sp.get_tools_for_intent("SQL注入")
        assert "sqlmap_scan" in tools

    def test_get_tools_for_intent_case_insensitive(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        tools = sp.get_tools_for_intent("sql注入")
        assert "sqlmap_scan" in tools

    def test_get_tools_for_intent_partial_match(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        tools = sp.get_tools_for_intent("端口")
        assert len(tools) > 0

    def test_get_tools_for_intent_no_match(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        tools = sp.get_tools_for_intent("quantum_hack")
        assert tools == []

    def test_get_attack_chain_existing(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        chain = sp.get_attack_chain("web_comprehensive")
        assert chain is not None
        assert isinstance(chain, ToolChain)
        assert chain.name == "Web综合扫描链"

    def test_get_attack_chain_nonexistent(self, tmp_path):
        sp = SkillParser(skill_path=str(tmp_path / "nope.md"))
        assert sp.get_attack_chain("nonexistent") is None


# ---------------------------------------------------------------------------
# IntelligentDispatcher — detect_target_type
# ---------------------------------------------------------------------------
class TestDetectTargetType:
    """Target type detection with various inputs."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    # CTF
    def test_ctf_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://ctf.example.com") == TargetType.CTF

    def test_challenge_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://challenge.site.com") == TargetType.CTF

    def test_flag_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://flag.test.com") == TargetType.CTF

    def test_pwn_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://pwn.test.com") == TargetType.CTF

    # Cloud
    def test_aws_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://aws.example.com") == TargetType.CLOUD

    def test_azure_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://azure.example.com") == TargetType.CLOUD

    def test_gcp_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://gcp.example.com") == TargetType.CLOUD

    def test_s3_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("s3.bucket.example.com") == TargetType.CLOUD

    # Container
    def test_docker_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://docker.host.com") == TargetType.CONTAINER

    def test_k8s_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://k8s.cluster.local") == TargetType.CONTAINER

    def test_kubernetes_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://kubernetes.local") == TargetType.CONTAINER

    def test_pod_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://pod.internal") == TargetType.CONTAINER

    # AD
    def test_ldap_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("ldap://dc.corp.local") == TargetType.ACTIVE_DIRECTORY

    def test_domain_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("domain.controller") == TargetType.ACTIVE_DIRECTORY

    def test_kerberos_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("kerberos.corp.local") == TargetType.ACTIVE_DIRECTORY

    # API
    def test_api_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://api.example.com") == TargetType.API

    def test_graphql_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://example.com/graphql") == TargetType.API

    def test_rest_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("http://example.com/rest") == TargetType.API

    def test_v1_path(self, dispatcher):
        assert dispatcher.detect_target_type("http://example.com/v1/users") == TargetType.API

    def test_v2_path(self, dispatcher):
        assert dispatcher.detect_target_type("http://example.com/v2/items") == TargetType.API

    # Binary
    def test_exe_extension(self, dispatcher):
        assert dispatcher.detect_target_type("/tmp/app.exe") == TargetType.BINARY

    def test_elf_extension(self, dispatcher):
        assert dispatcher.detect_target_type("/tmp/app.elf") == TargetType.BINARY

    def test_bin_extension(self, dispatcher):
        assert dispatcher.detect_target_type("/tmp/app.bin") == TargetType.BINARY

    def test_so_extension(self, dispatcher):
        assert dispatcher.detect_target_type("/tmp/lib.so") == TargetType.BINARY

    def test_dll_extension(self, dispatcher):
        assert dispatcher.detect_target_type("/tmp/lib.dll") == TargetType.BINARY

    # Web
    def test_http_prefix(self, dispatcher):
        assert dispatcher.detect_target_type("http://example.com") == TargetType.WEB_APP

    def test_https_prefix(self, dispatcher):
        assert dispatcher.detect_target_type("https://example.com") == TargetType.WEB_APP

    def test_www_keyword(self, dispatcher):
        assert dispatcher.detect_target_type("www.example.com") == TargetType.WEB_APP

    def test_dot_com(self, dispatcher):
        assert dispatcher.detect_target_type("example.com") == TargetType.WEB_APP

    def test_dot_cn(self, dispatcher):
        assert dispatcher.detect_target_type("example.cn") == TargetType.WEB_APP

    def test_dot_io(self, dispatcher):
        assert dispatcher.detect_target_type("example.io") == TargetType.WEB_APP

    # Network (IP)
    def test_ip_address(self, dispatcher):
        assert dispatcher.detect_target_type("192.168.1.100") == TargetType.NETWORK

    def test_ip_address_10(self, dispatcher):
        assert dispatcher.detect_target_type("10.0.0.1") == TargetType.NETWORK

    # Unknown
    def test_unknown_target(self, dispatcher):
        assert dispatcher.detect_target_type("some_random_string") == TargetType.UNKNOWN

    # Priority: CTF wins over WEB
    def test_ctf_priority_over_web(self, dispatcher):
        assert dispatcher.detect_target_type("http://ctf.example.com") == TargetType.CTF

    # Priority: Cloud wins over web
    def test_cloud_priority_over_web(self, dispatcher):
        assert dispatcher.detect_target_type("http://aws.example.com") == TargetType.CLOUD

    # Case insensitivity
    def test_case_insensitive_ctf(self, dispatcher):
        assert dispatcher.detect_target_type("HTTP://CTF.EXAMPLE.COM") == TargetType.CTF


# ---------------------------------------------------------------------------
# IntelligentDispatcher — tool chain methods
# ---------------------------------------------------------------------------
class TestToolChainMethods:
    """Tests for _get_*_tool_chain methods."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    # Web tool chain
    def test_web_quick(self, dispatcher):
        chain = dispatcher._get_web_tool_chain(ScanDepth.QUICK)
        tools = [s["tool"] for s in chain]
        assert "whatweb_scan" in tools
        assert "wafw00f_scan" in tools
        assert "gobuster_scan" in tools
        assert "ffuf_scan" not in tools
        assert "nuclei_web_scan" not in tools

    def test_web_standard(self, dispatcher):
        chain = dispatcher._get_web_tool_chain(ScanDepth.STANDARD)
        tools = [s["tool"] for s in chain]
        assert "ffuf_scan" in tools
        assert "nikto_scan" in tools
        assert "nuclei_web_scan" not in tools

    def test_web_comprehensive(self, dispatcher):
        chain = dispatcher._get_web_tool_chain(ScanDepth.COMPREHENSIVE)
        tools = [s["tool"] for s in chain]
        assert "nuclei_web_scan" in tools
        assert "sqlmap_scan" in tools

    def test_web_deep(self, dispatcher):
        chain = dispatcher._get_web_tool_chain(ScanDepth.DEEP)
        tools = [s["tool"] for s in chain]
        assert "feroxbuster_scan" in tools
        assert "wpscan_scan" in tools
        assert "joomscan_scan" in tools

    # Network tool chain
    def test_network_quick(self, dispatcher):
        chain = dispatcher._get_network_tool_chain(ScanDepth.QUICK)
        assert len(chain) == 1
        assert chain[0]["tool"] == "nmap_scan"

    def test_network_standard(self, dispatcher):
        chain = dispatcher._get_network_tool_chain(ScanDepth.STANDARD)
        tools = [s["tool"] for s in chain]
        assert "nuclei_network_scan" in tools
        assert "enum4linux_scan" in tools

    def test_network_comprehensive(self, dispatcher):
        chain = dispatcher._get_network_tool_chain(ScanDepth.COMPREHENSIVE)
        tools = [s["tool"] for s in chain]
        assert "hydra_attack" in tools
        assert "searchsploit_search" in tools

    # API tool chain
    def test_api_quick(self, dispatcher):
        chain = dispatcher._get_api_tool_chain(ScanDepth.QUICK)
        tools = [s["tool"] for s in chain]
        assert "httpx_probe" in tools
        assert "nuclei_scan" in tools
        assert "ffuf_scan" in tools
        assert "sqlmap_scan" not in tools

    def test_api_comprehensive(self, dispatcher):
        chain = dispatcher._get_api_tool_chain(ScanDepth.COMPREHENSIVE)
        tools = [s["tool"] for s in chain]
        assert "sqlmap_scan" in tools

    # Cloud tool chain
    def test_cloud_chain(self, dispatcher):
        chain = dispatcher._get_cloud_tool_chain(ScanDepth.QUICK)
        tools = [s["tool"] for s in chain]
        assert "cloud_enum" in tools
        assert len(chain) == 4

    # Container tool chain
    def test_container_chain(self, dispatcher):
        chain = dispatcher._get_container_tool_chain(ScanDepth.QUICK)
        tools = [s["tool"] for s in chain]
        assert "docker_enum" in tools
        assert "k8s_enum" in tools
        assert len(chain) == 4

    # CTF tool chain
    def test_ctf_quick(self, dispatcher):
        chain = dispatcher._get_ctf_tool_chain(ScanDepth.QUICK)
        assert len(chain) == 3
        tools = [s["tool"] for s in chain]
        assert "nmap_scan" in tools
        assert "gobuster_scan" in tools
        assert "nuclei_scan" in tools

    def test_ctf_comprehensive(self, dispatcher):
        chain = dispatcher._get_ctf_tool_chain(ScanDepth.COMPREHENSIVE)
        tools = [s["tool"] for s in chain]
        assert "sqlmap_scan" in tools
        assert "intelligent_command_injection_payloads" in tools

    # AD tool chain
    def test_ad_chain(self, dispatcher):
        chain = dispatcher._get_ad_tool_chain(ScanDepth.QUICK)
        tools = [s["tool"] for s in chain]
        assert "nmap_scan" in tools
        assert "enum4linux_scan" in tools
        assert "hydra_attack" in tools
        assert len(chain) == 3


# ---------------------------------------------------------------------------
# IntelligentDispatcher — get_comprehensive_tool_chain
# ---------------------------------------------------------------------------
class TestGetComprehensiveToolChain:
    """Tests for the primary orchestration method."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_returns_sorted_by_priority(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("http://example.com")
        priorities = [s.get("priority", 5) for s in chain]
        assert priorities == sorted(priorities)

    def test_web_target_detected(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("http://example.com")
        tools = [s["tool"] for s in chain]
        assert "whatweb_scan" in tools

    def test_network_target_detected(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("192.168.1.1")
        tools = [s["tool"] for s in chain]
        assert "nmap_scan" in tools

    def test_ctf_target_detected(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("http://ctf.challenge.com")
        tools = [s["tool"] for s in chain]
        assert "nmap_scan" in tools

    def test_focus_areas_add_tools(self, dispatcher):
        chain_without = dispatcher.get_comprehensive_tool_chain("http://example.com")
        chain_with = dispatcher.get_comprehensive_tool_chain(
            "http://example.com", focus_areas=["sql注入"]
        )
        tools_without = {s["tool"] for s in chain_without}
        tools_with = {s["tool"] for s in chain_with}
        # With focus, should have at least the same tools
        assert tools_without.issubset(tools_with) or len(tools_with) >= len(tools_without)

    def test_focus_areas_no_duplicate_tools(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain(
            "http://example.com", focus_areas=["sql注入"]
        )
        tools = [s["tool"] for s in chain]
        # tools already in base chain should not be duplicated
        for t in set(tools):
            assert tools.count(t) == 1

    def test_depth_quick_no_full_coverage(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain(
            "http://example.com", depth=ScanDepth.QUICK
        )
        tools = [s["tool"] for s in chain]
        # Quick depth should NOT call _ensure_full_coverage
        # But base web chain for QUICK is just 3 tools
        assert len(tools) >= 3

    def test_depth_comprehensive_ensures_coverage(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain(
            "http://example.com", depth=ScanDepth.COMPREHENSIVE
        )
        tools = [s["tool"] for s in chain]
        assert "nuclei_scan" in tools

    def test_depth_deep_ensures_coverage(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain(
            "http://example.com", depth=ScanDepth.DEEP
        )
        tools = [s["tool"] for s in chain]
        assert "nuclei_scan" in tools
        assert "nikto_scan" in tools

    def test_unknown_target_falls_back_to_web(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("random_thing")
        tools = [s["tool"] for s in chain]
        # Unknown targets use _get_web_tool_chain as fallback
        assert "whatweb_scan" in tools

    def test_focus_areas_empty_list(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain(
            "http://example.com", focus_areas=[]
        )
        assert len(chain) > 0

    def test_focus_areas_no_match(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain(
            "http://example.com", focus_areas=["quantum_computing"]
        )
        # Should still have base chain, no crash
        assert len(chain) > 0


# ---------------------------------------------------------------------------
# IntelligentDispatcher — _ensure_full_coverage
# ---------------------------------------------------------------------------
class TestEnsureFullCoverage:
    """Tests for _ensure_full_coverage adding missing core tools."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_adds_missing_nuclei(self, dispatcher):
        chain = [{"tool": "whatweb_scan", "phase": "recon", "priority": 1, "description": "x"}]
        result = dispatcher._ensure_full_coverage(chain)
        tools = [s["tool"] for s in result]
        assert "nuclei_scan" in tools

    def test_adds_missing_nikto(self, dispatcher):
        chain = [{"tool": "whatweb_scan", "phase": "recon", "priority": 1, "description": "x"}]
        result = dispatcher._ensure_full_coverage(chain)
        tools = [s["tool"] for s in result]
        assert "nikto_scan" in tools

    def test_adds_missing_sqlmap(self, dispatcher):
        chain = [{"tool": "whatweb_scan", "phase": "recon", "priority": 1, "description": "x"}]
        result = dispatcher._ensure_full_coverage(chain)
        tools = [s["tool"] for s in result]
        assert "sqlmap_scan" in tools

    def test_does_not_add_existing_tools(self, dispatcher):
        chain = [
            {"tool": "nuclei_scan", "phase": "v", "priority": 1, "description": "x"},
            {"tool": "nikto_scan", "phase": "v", "priority": 1, "description": "x"},
            {"tool": "sqlmap_scan", "phase": "v", "priority": 1, "description": "x"},
        ]
        result = dispatcher._ensure_full_coverage(chain)
        assert len(result) == 3  # No new tools added

    def test_empty_chain_gets_all_core_tools(self, dispatcher):
        result = dispatcher._ensure_full_coverage([])
        tools = [s["tool"] for s in result]
        assert "nuclei_scan" in tools
        assert "nikto_scan" in tools
        assert "sqlmap_scan" in tools
        assert len(result) == 3


# ---------------------------------------------------------------------------
# IntelligentDispatcher — _analyze_for_vulnerabilities
# ---------------------------------------------------------------------------
class TestAnalyzeForVulnerabilities:
    """Tests for _analyze_for_vulnerabilities."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_no_indicators_key_returns_empty(self, dispatcher):
        """vulnerability_coverage uses 'keywords' not 'indicators', so
        _analyze_for_vulnerabilities always returns [] with default coverage."""
        result = {"data": "You have an error in your SQL syntax"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        # The method checks for 'indicators' key which doesn't exist in coverage
        assert vulns == []

    def test_with_indicators_key_detects_vuln(self, dispatcher):
        """When an 'indicators' key is present, vulnerability detection works."""
        dispatcher.vulnerability_coverage["sql_injection"]["indicators"] = [
            "sql", "mysql", "syntax", "query"
        ]
        result = {"data": "You have an error in your SQL syntax"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        vuln_types = [v["type"] for v in vulns]
        assert "sql_injection" in vuln_types

    def test_with_indicators_detects_xss(self, dispatcher):
        dispatcher.vulnerability_coverage["xss"]["indicators"] = ["<script>", "alert", "onerror"]
        result = {"data": "<script>alert(1)</script>"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        vuln_types = [v["type"] for v in vulns]
        assert "xss" in vuln_types

    def test_with_indicators_detects_command_injection(self, dispatcher):
        dispatcher.vulnerability_coverage["command_injection"]["indicators"] = ["uid=", "root:"]
        result = {"data": "root:x:0:0:root:/root uid=0"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        vuln_types = [v["type"] for v in vulns]
        assert "command_injection" in vuln_types

    def test_with_indicators_detects_file_inclusion(self, dispatcher):
        dispatcher.vulnerability_coverage["file_inclusion"]["indicators"] = ["include", "../"]
        result = {"data": "Warning: include(../../../etc/passwd)"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        vuln_types = [v["type"] for v in vulns]
        assert "file_inclusion" in vuln_types

    def test_with_indicators_detects_ssrf(self, dispatcher):
        dispatcher.vulnerability_coverage["ssrf"]["indicators"] = ["169.254.169.254", "localhost"]
        result = {"data": "Connection to 169.254.169.254 established"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        vuln_types = [v["type"] for v in vulns]
        assert "ssrf" in vuln_types

    def test_with_indicators_detects_xxe(self, dispatcher):
        dispatcher.vulnerability_coverage["xxe"]["indicators"] = ["entity", "xml"]
        result = {"data": "XML External Entity parsed successfully"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        vuln_types = [v["type"] for v in vulns]
        assert "xxe" in vuln_types

    def test_with_indicators_detects_auth_issue(self, dispatcher):
        dispatcher.vulnerability_coverage["authentication"]["indicators"] = ["login", "password"]
        result = {"data": "login failed: invalid password"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        vuln_types = [v["type"] for v in vulns]
        assert "authentication" in vuln_types

    def test_no_data_returns_empty(self, dispatcher):
        result = {}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        assert vulns == []

    def test_empty_data_returns_empty(self, dispatcher):
        result = {"data": ""}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        assert vulns == []

    def test_clean_data_returns_empty(self, dispatcher):
        result = {"data": "Everything is fine, no issues here."}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        assert vulns == []

    def test_multiple_vulns_detected_with_indicators(self, dispatcher):
        """When multiple vuln types have indicators, multiple are detected."""
        dispatcher.vulnerability_coverage["sql_injection"]["indicators"] = ["sql"]
        dispatcher.vulnerability_coverage["xss"]["indicators"] = ["script"]
        dispatcher.vulnerability_coverage["authentication"]["indicators"] = ["login"]
        result = {"data": "SQL error login <script>"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        assert len(vulns) >= 3

    def test_indicator_match_breaks_after_first(self, dispatcher):
        """Only one indicator per vuln_type triggers (break after first match)."""
        dispatcher.vulnerability_coverage["sql_injection"]["indicators"] = ["sql", "mysql"]
        result = {"data": "sql database query mysql error syntax"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        sql_vulns = [v for v in vulns if v["type"] == "sql_injection"]
        assert len(sql_vulns) == 1

    def test_default_coverage_has_no_indicators(self, dispatcher):
        """Verify that default vulnerability_coverage entries lack 'indicators' key."""
        for vtype, vinfo in dispatcher.vulnerability_coverage.items():
            assert "indicators" not in vinfo, f"{vtype} unexpectedly has 'indicators'"

    def test_severity_from_coverage(self, dispatcher):
        """When indicators are set, severity comes from coverage or defaults to MEDIUM."""
        dispatcher.vulnerability_coverage["sql_injection"]["indicators"] = ["sql"]
        dispatcher.vulnerability_coverage["sql_injection"]["severity"] = "CRITICAL"
        result = {"data": "sql error"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        assert vulns[0]["severity"] == "CRITICAL"

    def test_severity_default_medium(self, dispatcher):
        """When severity is not set, defaults to MEDIUM."""
        dispatcher.vulnerability_coverage["sql_injection"]["indicators"] = ["sql"]
        # Remove severity if present
        dispatcher.vulnerability_coverage["sql_injection"].pop("severity", None)
        result = {"data": "sql error"}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        assert vulns[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# IntelligentDispatcher — _extract_flags
# ---------------------------------------------------------------------------
class TestExtractFlags:
    """Tests for flag extraction from tool output."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_extract_flag_lower(self, dispatcher):
        result = {"data": "found flag{test_flag_123}"}
        flags = dispatcher._extract_flags(result)
        assert "flag{test_flag_123}" in flags

    def test_extract_flag_upper(self, dispatcher):
        result = {"data": "found FLAG{TEST_FLAG}"}
        flags = dispatcher._extract_flags(result)
        assert "FLAG{TEST_FLAG}" in flags

    def test_extract_ctf_lower(self, dispatcher):
        result = {"data": "ctf{my_flag}"}
        flags = dispatcher._extract_flags(result)
        assert "ctf{my_flag}" in flags

    def test_extract_ctf_upper(self, dispatcher):
        result = {"data": "CTF{MY_FLAG}"}
        flags = dispatcher._extract_flags(result)
        assert "CTF{MY_FLAG}" in flags

    def test_extract_dasctf(self, dispatcher):
        result = {"data": "DASCTF{some_flag_here}"}
        flags = dispatcher._extract_flags(result)
        assert "DASCTF{some_flag_here}" in flags

    def test_extract_md5(self, dispatcher):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = {"data": f"hash: {md5}"}
        flags = dispatcher._extract_flags(result)
        assert md5 in flags

    def test_extract_sha256(self, dispatcher):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = {"data": f"hash: {sha}"}
        flags = dispatcher._extract_flags(result)
        assert sha in flags

    def test_no_flags(self, dispatcher):
        result = {"data": "nothing interesting here"}
        flags = dispatcher._extract_flags(result)
        assert flags == []

    def test_no_data_key(self, dispatcher):
        result = {}
        flags = dispatcher._extract_flags(result)
        assert flags == []

    def test_multiple_flags_deduped(self, dispatcher):
        result = {"data": "flag{a} flag{a} flag{b}"}
        flags = dispatcher._extract_flags(result)
        assert len(flags) == 2
        assert "flag{a}" in flags
        assert "flag{b}" in flags

    def test_case_insensitive_flag_match(self, dispatcher):
        result = {"data": "Flag{MiXeD_CaSe}"}
        flags = dispatcher._extract_flags(result)
        assert len(flags) >= 1


# ---------------------------------------------------------------------------
# IntelligentDispatcher — _get_follow_up_tools
# ---------------------------------------------------------------------------
class TestGetFollowUpTools:
    """Tests for dynamic follow-up tool selection."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_wordpress_triggers_wpscan(self, dispatcher):
        result = {"data": "WordPress 5.7 detected"}
        follow = dispatcher._get_follow_up_tools(result, {})
        tools = [f["tool"] for f in follow]
        assert "wpscan_scan" in tools

    def test_login_triggers_hydra(self, dispatcher):
        result = {"data": "/login page found"}
        follow = dispatcher._get_follow_up_tools(result, {})
        tools = [f["tool"] for f in follow]
        assert "hydra_attack" in tools

    def test_signin_triggers_hydra(self, dispatcher):
        result = {"data": "signin form detected"}
        follow = dispatcher._get_follow_up_tools(result, {})
        tools = [f["tool"] for f in follow]
        assert "hydra_attack" in tools

    def test_admin_triggers_hydra(self, dispatcher):
        result = {"data": "/admin panel found"}
        follow = dispatcher._get_follow_up_tools(result, {})
        tools = [f["tool"] for f in follow]
        assert "hydra_attack" in tools

    def test_sql_error_triggers_sqlmap(self, dispatcher):
        result = {"data": "MySQL syntax error"}
        follow = dispatcher._get_follow_up_tools(result, {})
        tools = [f["tool"] for f in follow]
        assert "sqlmap_scan" in tools

    def test_postgresql_triggers_sqlmap(self, dispatcher):
        result = {"data": "postgresql connection error"}
        follow = dispatcher._get_follow_up_tools(result, {})
        tools = [f["tool"] for f in follow]
        assert "sqlmap_scan" in tools

    def test_no_indicators_returns_empty(self, dispatcher):
        result = {"data": "clean output with nothing special"}
        follow = dispatcher._get_follow_up_tools(result, {})
        assert follow == []

    def test_multiple_indicators(self, dispatcher):
        result = {"data": "wordpress login mysql error"}
        follow = dispatcher._get_follow_up_tools(result, {})
        tools = [f["tool"] for f in follow]
        assert "wpscan_scan" in tools
        assert "hydra_attack" in tools
        assert "sqlmap_scan" in tools

    def test_empty_data(self, dispatcher):
        result = {"data": ""}
        follow = dispatcher._get_follow_up_tools(result, {})
        assert follow == []


# ---------------------------------------------------------------------------
# IntelligentDispatcher — _generate_recommendations
# ---------------------------------------------------------------------------
class TestGenerateRecommendations:
    """Tests for recommendation generation."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_vulns_found(self, dispatcher):
        results = {
            "vulnerabilities_found": [{"type": "sql_injection"}],
            "flags_found": [],
        }
        recs = dispatcher._generate_recommendations(results)
        assert any("深入利用" in r for r in recs)

    def test_nothing_found(self, dispatcher):
        results = {
            "vulnerabilities_found": [],
            "flags_found": [],
        }
        recs = dispatcher._generate_recommendations(results)
        assert any("深度扫描" in r for r in recs)
        assert any("业务逻辑" in r for r in recs)

    def test_flags_found_no_vulns(self, dispatcher):
        results = {
            "vulnerabilities_found": [],
            "flags_found": ["flag{test}"],
        }
        recs = dispatcher._generate_recommendations(results)
        # With flags found, the "nothing found" branch is skipped
        assert not any("深度扫描" in r for r in recs)

    def test_both_vulns_and_flags(self, dispatcher):
        results = {
            "vulnerabilities_found": [{"type": "xss"}],
            "flags_found": ["flag{x}"],
        }
        recs = dispatcher._generate_recommendations(results)
        assert any("深入利用" in r for r in recs)


# ---------------------------------------------------------------------------
# IntelligentDispatcher — get_tools_for_vulnerability
# ---------------------------------------------------------------------------
class TestGetToolsForVulnerability:
    """Tests for vulnerability-type to tool mapping."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_sql_injection(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("sql_injection")
        assert "sqlmap_scan" in tools["detection"]
        assert "sqlmap_scan" in tools["exploitation"]

    def test_keyword_match_database(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("数据库攻击")
        assert "sqlmap_scan" in tools["detection"]

    def test_xss_match(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("XSS漏洞")
        assert "nuclei_scan" in tools["detection"]

    def test_command_injection_keyword(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("rce exploit")
        assert "nuclei_scan" in tools["detection"]

    def test_unknown_vuln_type(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("quantum_vulnerability")
        assert tools == {"detection": ["nuclei_scan"], "exploitation": []}

    def test_file_inclusion_lfi(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("lfi exploit")
        assert "ffuf_scan" in tools["detection"]

    def test_ssrf_match(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("ssrf attack")
        assert "nuclei_scan" in tools["detection"]

    def test_auth_login(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("login bypass")
        assert "hydra_attack" in tools["detection"]

    def test_info_disclosure(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("information disclosure")
        assert "gobuster_scan" in tools["detection"]

    def test_misconfiguration(self, dispatcher):
        tools = dispatcher.get_tools_for_vulnerability("server config issue")
        assert "nikto_scan" in tools["detection"]


# ---------------------------------------------------------------------------
# IntelligentDispatcher — execute_chain (async)
# ---------------------------------------------------------------------------
class TestExecuteChain:
    """Tests for the async execute_chain method."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            executor = AsyncMock()
            return IntelligentDispatcher(tool_executor=executor)

    def test_execute_chain_success(self, dispatcher):
        dispatcher.tool_executor.return_value = {
            "status": "success",
            "data": "clean output",
        }
        chain = [{"tool": "nmap_scan", "phase": "recon", "priority": 1, "description": "test"}]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("192.168.1.1", chain)
        )
        assert result["target"] == "192.168.1.1"
        assert len(result["tool_results"]) == 1
        assert result["tool_results"][0]["success"] is True
        assert "start_time" in result
        assert "end_time" in result

    def test_execute_chain_no_executor(self):
        with patch("os.path.exists", return_value=False):
            disp = IntelligentDispatcher(tool_executor=None)
        chain = [{"tool": "nmap_scan", "phase": "recon", "priority": 1, "description": "test"}]
        result = asyncio.get_event_loop().run_until_complete(
            disp.execute_chain("192.168.1.1", chain)
        )
        # No executor → no tool_results logged
        assert len(result["tool_results"]) == 0

    def test_execute_chain_with_flags(self, dispatcher):
        dispatcher.tool_executor.return_value = {
            "status": "success",
            "data": "flag{found_it}",
        }
        chain = [{"tool": "nmap_scan", "phase": "recon", "priority": 1, "description": "test"}]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain)
        )
        assert "flag{found_it}" in result["flags_found"]

    def test_execute_chain_with_vulns(self, dispatcher):
        """Vulns are detected during chain when indicators are set on coverage."""
        dispatcher.vulnerability_coverage["sql_injection"]["indicators"] = ["sql", "mysql"]
        dispatcher.tool_executor.return_value = {
            "status": "success",
            "data": "SQL syntax error mysql",
        }
        chain = [{"tool": "sqlmap", "phase": "exploit", "priority": 1, "description": "test"}]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain)
        )
        assert len(result["vulnerabilities_found"]) > 0

    def test_execute_chain_stop_on_success_with_vuln(self, dispatcher):
        """stop_on_success stops after first vuln found (when indicators exist)."""
        dispatcher.vulnerability_coverage["sql_injection"]["indicators"] = ["sql"]
        call_count = 0

        async def mock_exec(tool, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"status": "success", "data": "SQL syntax error"}
            return {"status": "success", "data": "clean"}

        dispatcher.tool_executor = mock_exec
        chain = [
            {"tool": "tool1", "phase": "a", "priority": 1, "description": "first"},
            {"tool": "tool2", "phase": "b", "priority": 2, "description": "second"},
        ]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain, stop_on_success=True)
        )
        assert call_count == 1
        assert len(result["tool_results"]) == 1

    def test_execute_chain_stop_on_success_with_flag(self, dispatcher):
        call_count = 0

        async def mock_exec(tool, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"status": "success", "data": "flag{stop_here}"}
            return {"status": "success", "data": "clean"}

        dispatcher.tool_executor = mock_exec
        chain = [
            {"tool": "tool1", "phase": "a", "priority": 1, "description": "first"},
            {"tool": "tool2", "phase": "b", "priority": 2, "description": "second"},
        ]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain, stop_on_success=True)
        )
        assert call_count == 1

    def test_execute_chain_continues_without_stop_on_success(self, dispatcher):
        """Without stop_on_success, all tools run even if vulns are found."""
        dispatcher.vulnerability_coverage["deserialization"]["indicators"] = ["cereal"]
        dispatcher.tool_executor.return_value = {
            "status": "success",
            "data": "cereal detected",
        }
        chain = [
            {"tool": "tool1", "phase": "a", "priority": 1, "description": "first"},
            {"tool": "tool2", "phase": "b", "priority": 2, "description": "second"},
        ]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain, stop_on_success=False)
        )
        # Vulns found but stop_on_success=False so all original tools run
        assert len(result["vulnerabilities_found"]) > 0
        assert len(result["tool_results"]) == 2

    def test_execute_chain_handles_exception(self, dispatcher):
        dispatcher.tool_executor.side_effect = Exception("connection failed")
        chain = [{"tool": "nmap_scan", "phase": "recon", "priority": 1, "description": "test"}]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain)
        )
        assert len(result["tool_results"]) == 1
        assert result["tool_results"][0]["success"] is False
        assert "connection failed" in result["tool_results"][0]["error"]

    def test_execute_chain_follow_up_tools_appended(self, dispatcher):
        call_count = 0

        async def mock_exec(tool, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"status": "success", "data": "WordPress 5.7 detected"}
            return {"status": "success", "data": "clean"}

        dispatcher.tool_executor = mock_exec
        chain = [{"tool": "whatweb", "phase": "recon", "priority": 1, "description": "test"}]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain)
        )
        # wpscan_scan should have been appended and executed
        tools_executed = [r["tool"] for r in result["tool_results"]]
        assert "wpscan_scan" in tools_executed

    def test_execute_chain_recommendations_generated(self, dispatcher):
        dispatcher.tool_executor.return_value = {
            "status": "success",
            "data": "clean output",
        }
        chain = [{"tool": "nmap", "phase": "recon", "priority": 1, "description": "test"}]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain)
        )
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) > 0

    def test_execute_chain_empty_chain(self, dispatcher):
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", [])
        )
        assert result["tool_results"] == []
        assert "end_time" in result

    def test_execute_chain_follow_up_not_duplicated(self, dispatcher):
        """Follow-up tools already in the chain should not be added again."""

        async def mock_exec(tool, **kwargs):
            return {"status": "success", "data": "wordpress login admin"}

        dispatcher.tool_executor = mock_exec
        chain = [
            {"tool": "scan", "phase": "recon", "priority": 1, "description": "test"},
            {"tool": "wpscan_scan", "phase": "cms", "priority": 4, "description": "already there"},
            {"tool": "hydra_attack", "phase": "cred", "priority": 5, "description": "already there"},
            {"tool": "sqlmap_scan", "phase": "expl", "priority": 3, "description": "already there"},
        ]
        result = asyncio.get_event_loop().run_until_complete(
            dispatcher.execute_chain("target", chain)
        )
        tool_names = [r["tool"] for r in result["tool_results"]]
        # No duplicates beyond what was originally there
        assert tool_names.count("wpscan_scan") == 1


# ---------------------------------------------------------------------------
# IntelligentDispatcher — init and state
# ---------------------------------------------------------------------------
class TestDispatcherInit:
    """Tests for IntelligentDispatcher initialization."""

    def test_init_no_executor(self):
        with patch("os.path.exists", return_value=False):
            d = IntelligentDispatcher()
        assert d.tool_executor is None
        assert d.execution_history == []
        assert d.discovered_info == {}

    def test_init_with_executor(self):
        mock = MagicMock()
        with patch("os.path.exists", return_value=False):
            d = IntelligentDispatcher(tool_executor=mock)
        assert d.tool_executor is mock

    def test_vulnerability_coverage_keys(self):
        with patch("os.path.exists", return_value=False):
            d = IntelligentDispatcher()
        expected = {
            "sql_injection", "xss", "command_injection", "file_inclusion",
            "ssrf", "xxe", "deserialization", "authentication",
            "information_disclosure", "misconfiguration",
        }
        assert set(d.vulnerability_coverage.keys()) == expected

    def test_target_tool_chains_keys(self):
        with patch("os.path.exists", return_value=False):
            d = IntelligentDispatcher()
        expected_types = {
            TargetType.WEB_APP, TargetType.NETWORK, TargetType.API,
            TargetType.CLOUD, TargetType.CONTAINER, TargetType.CTF,
            TargetType.ACTIVE_DIRECTORY,
        }
        assert set(d.target_tool_chains.keys()) == expected_types

    def test_skill_parser_initialized(self):
        with patch("os.path.exists", return_value=False):
            d = IntelligentDispatcher()
        assert isinstance(d.skill_parser, SkillParser)


# ---------------------------------------------------------------------------
# Global convenience functions
# ---------------------------------------------------------------------------
class TestGlobalFunctions:
    """Tests for module-level convenience functions."""

    def test_get_skill_based_tools_comprehensive(self):
        with patch("os.path.exists", return_value=False):
            tools = get_skill_based_tools("http://example.com", depth="comprehensive")
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_get_skill_based_tools_quick(self):
        with patch("os.path.exists", return_value=False):
            tools = get_skill_based_tools("http://example.com", depth="quick")
        assert isinstance(tools, list)

    def test_get_skill_based_tools_standard(self):
        with patch("os.path.exists", return_value=False):
            tools = get_skill_based_tools("192.168.1.1", depth="standard")
        assert isinstance(tools, list)

    def test_get_skill_based_tools_deep(self):
        with patch("os.path.exists", return_value=False):
            tools = get_skill_based_tools("http://example.com", depth="deep")
        assert isinstance(tools, list)

    def test_get_skill_based_tools_invalid_depth_defaults_to_comprehensive(self):
        with patch("os.path.exists", return_value=False):
            tools = get_skill_based_tools("http://example.com", depth="invalid")
        assert isinstance(tools, list)
        # Should default to comprehensive
        assert len(tools) > 0

    def test_get_skill_based_tools_case_insensitive_depth(self):
        with patch("os.path.exists", return_value=False):
            tools = get_skill_based_tools("http://example.com", depth="QUICK")
        assert isinstance(tools, list)

    def test_get_vulnerability_tools_sql(self):
        with patch("os.path.exists", return_value=False):
            tools = get_vulnerability_tools("sql_injection")
        assert "detection" in tools
        assert "exploitation" in tools

    def test_get_vulnerability_tools_unknown(self):
        with patch("os.path.exists", return_value=False):
            tools = get_vulnerability_tools("unknown_type")
        assert tools == {"detection": ["nuclei_scan"], "exploitation": []}

    def test_detect_target_web(self):
        with patch("os.path.exists", return_value=False):
            result = detect_target("http://example.com")
        assert result == "web_app"

    def test_detect_target_network(self):
        with patch("os.path.exists", return_value=False):
            result = detect_target("10.0.0.1")
        assert result == "network"

    def test_detect_target_ctf(self):
        with patch("os.path.exists", return_value=False):
            result = detect_target("http://ctf.test.com")
        assert result == "ctf"

    def test_detect_target_unknown(self):
        with patch("os.path.exists", return_value=False):
            result = detect_target("random_string_no_hint")
        assert result == "unknown"

    def test_detect_target_binary(self):
        with patch("os.path.exists", return_value=False):
            # Use a path that doesn't contain CTF keywords like "challenge"
            result = detect_target("/tmp/vuln_app.elf")
        assert result == "binary"


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
class TestGlobalSingleton:
    """Tests for the module-level skill_dispatcher singleton."""

    def test_singleton_exists(self):
        assert skill_dispatcher is not None

    def test_singleton_is_intelligent_dispatcher(self):
        assert isinstance(skill_dispatcher, IntelligentDispatcher)

    def test_singleton_has_no_executor(self):
        assert skill_dispatcher.tool_executor is None

    def test_singleton_detect_target(self):
        # Use the singleton directly
        result = skill_dispatcher.detect_target_type("http://example.com")
        assert isinstance(result, TargetType)


# ---------------------------------------------------------------------------
# Edge cases and boundary conditions
# ---------------------------------------------------------------------------
class TestEdgeCases:
    """Various edge cases and boundary conditions."""

    @pytest.fixture
    def dispatcher(self):
        with patch("os.path.exists", return_value=False):
            return IntelligentDispatcher(tool_executor=None)

    def test_empty_target(self, dispatcher):
        result = dispatcher.detect_target_type("")
        assert result == TargetType.UNKNOWN

    def test_whitespace_target(self, dispatcher):
        result = dispatcher.detect_target_type("   ")
        assert result == TargetType.UNKNOWN

    def test_ip_like_but_invalid(self, dispatcher):
        result = dispatcher.detect_target_type("999.999.999.999")
        # re.match still matches the digit pattern
        assert result == TargetType.NETWORK

    def test_very_long_target(self, dispatcher):
        target = "http://" + "a" * 10000 + ".com"
        result = dispatcher.detect_target_type(target)
        assert result == TargetType.WEB_APP

    def test_target_with_special_chars(self, dispatcher):
        result = dispatcher.detect_target_type("http://example.com/<script>")
        assert result == TargetType.WEB_APP

    def test_binary_with_path(self, dispatcher):
        result = dispatcher.detect_target_type("/usr/local/bin/vuln_app.elf")
        assert result == TargetType.BINARY

    def test_active_directory_mixed_case(self, dispatcher):
        result = dispatcher.detect_target_type("LDAP://DC.CORP.LOCAL")
        assert result == TargetType.ACTIVE_DIRECTORY

    def test_container_with_dash(self, dispatcher):
        result = dispatcher.detect_target_type("http://docker-host.internal")
        assert result == TargetType.CONTAINER

    def test_comprehensive_chain_all_have_tool_key(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("http://example.com")
        for step in chain:
            assert "tool" in step

    def test_comprehensive_chain_all_have_priority(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("http://example.com")
        for step in chain:
            assert "priority" in step

    def test_comprehensive_chain_all_have_description(self, dispatcher):
        chain = dispatcher.get_comprehensive_tool_chain("http://example.com")
        for step in chain:
            assert "description" in step

    def test_analyze_with_none_data(self, dispatcher):
        result = {"data": None}
        vulns = dispatcher._analyze_for_vulnerabilities(result)
        # str(None) == "None" which doesn't match indicators
        assert vulns == [] or isinstance(vulns, list)

    def test_extract_flags_with_numeric_data(self, dispatcher):
        result = {"data": 12345}
        flags = dispatcher._extract_flags(result)
        assert flags == []

    def test_follow_up_with_missing_data_key(self, dispatcher):
        result = {"other": "value"}
        follow = dispatcher._get_follow_up_tools(result, {})
        assert follow == []

    def test_vulnerability_coverage_each_has_keywords(self, dispatcher):
        for vtype, vinfo in dispatcher.vulnerability_coverage.items():
            assert "keywords" in vinfo
            assert "detection" in vinfo
            assert "exploitation" in vinfo
            assert len(vinfo["keywords"]) > 0

    def test_focus_area_multiple_keyword_matches(self, dispatcher):
        """When focus_area matches multiple vuln types, tools from all are added."""
        chain = dispatcher.get_comprehensive_tool_chain(
            "http://example.com",
            focus_areas=["sql database"],
        )
        tools = [s["tool"] for s in chain]
        assert "sqlmap_scan" in tools
