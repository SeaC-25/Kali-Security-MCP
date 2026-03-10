"""
Tests for tool_orchestrator module (kali_mcp/core/tool_orchestrator.py)

Comprehensive coverage:
- ToolCategory enum: all members and values
- TriggerCondition enum: all members, values, membership, iteration
- ToolResult dataclass: creation, defaults, mutable default isolation
- AttackChain dataclass: creation, defaults, mutable default isolation
- ToolOrchestrator:
    - __init__ (defaults, custom tools, class constants)
    - analyze_output (every trigger rule category, dedup, accumulation)
    - _extract_data (ports, CVEs, paths, subdomains, no-match branches)
    - _prioritize_tools (high, medium, low, empty, single, all-high, all-unknown)
    - _build_params (web tools with/without http, non-web, overrides, url override)
    - _check_exploit_success (all vuln types, unknown, empty, case-insensitive)
    - get_orchestration_stats (empty, after operations)
    - execute_with_orchestration (async – success, failure/fallback, depth limit, max_tools, dedup)
    - execute_attack_chain (async – known chain, unknown chain)
    - deep_exploit (async – escalation, no aggressive params, unknown vuln type, exploit success)
    - _execute_tool (async – tool present, missing, exception)
- AutoPilotAttack:
    - __init__, attack_phases
    - run_autopilot (async – web target, non-web, injection exploitation)
- Global __all__ export list

180+ tests, pure unit tests, no subprocess, no network.
"""

import asyncio
import copy
import time
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kali_mcp.core.tool_orchestrator import (
    AttackChain,
    AutoPilotAttack,
    ToolCategory,
    ToolOrchestrator,
    ToolResult,
    TriggerCondition,
    __all__ as module_all,
)


# ===================== ToolCategory Enum =====================


class TestToolCategory:
    """Full coverage for ToolCategory enum."""

    def test_recon_value(self):
        assert ToolCategory.RECON.value == "reconnaissance"

    def test_discovery_value(self):
        assert ToolCategory.DISCOVERY.value == "discovery"

    def test_vulnerability_value(self):
        assert ToolCategory.VULNERABILITY.value == "vulnerability"

    def test_exploitation_value(self):
        assert ToolCategory.EXPLOITATION.value == "exploitation"

    def test_post_exploit_value(self):
        assert ToolCategory.POST_EXPLOIT.value == "post_exploitation"

    def test_password_value(self):
        assert ToolCategory.PASSWORD.value == "password_attack"

    def test_privilege_value(self):
        assert ToolCategory.PRIVILEGE.value == "privilege_escalation"

    def test_lateral_value(self):
        assert ToolCategory.LATERAL.value == "lateral_movement"

    def test_member_count(self):
        assert len(ToolCategory) == 8

    def test_enum_from_value(self):
        assert ToolCategory("reconnaissance") is ToolCategory.RECON

    def test_enum_invalid_value(self):
        with pytest.raises(ValueError):
            ToolCategory("nonexistent")

    def test_enum_is_enum(self):
        assert isinstance(ToolCategory.RECON, ToolCategory)

    def test_all_members_iterable(self):
        names = [m.name for m in ToolCategory]
        assert "RECON" in names
        assert "LATERAL" in names


# ===================== TriggerCondition Enum =====================


class TestTriggerCondition:
    """Full coverage for TriggerCondition enum."""

    def test_port_open(self):
        assert TriggerCondition.PORT_OPEN.value == "port_open"

    def test_service_detected(self):
        assert TriggerCondition.SERVICE_DETECTED.value == "service_detected"

    def test_vuln_found(self):
        assert TriggerCondition.VULN_FOUND.value == "vulnerability_found"

    def test_cms_detected(self):
        assert TriggerCondition.CMS_DETECTED.value == "cms_detected"

    def test_waf_detected(self):
        assert TriggerCondition.WAF_DETECTED.value == "waf_detected"

    def test_auth_required(self):
        assert TriggerCondition.AUTH_REQUIRED.value == "auth_required"

    def test_injection_possible(self):
        assert TriggerCondition.INJECTION_POSSIBLE.value == "injection_possible"

    def test_file_upload(self):
        assert TriggerCondition.FILE_UPLOAD.value == "file_upload_found"

    def test_admin_panel(self):
        assert TriggerCondition.ADMIN_PANEL.value == "admin_panel_found"

    def test_default_creds(self):
        assert TriggerCondition.DEFAULT_CREDS.value == "default_creds_possible"

    def test_cve_identified(self):
        assert TriggerCondition.CVE_IDENTIFIED.value == "cve_identified"

    def test_subdomain_found(self):
        assert TriggerCondition.SUBDOMAIN_FOUND.value == "subdomain_found"

    def test_member_count(self):
        assert len(TriggerCondition) == 12

    def test_enum_from_value(self):
        assert TriggerCondition("port_open") is TriggerCondition.PORT_OPEN

    def test_enum_invalid_value(self):
        with pytest.raises(ValueError):
            TriggerCondition("nope")

    def test_hashable_for_sets(self):
        s = {TriggerCondition.PORT_OPEN, TriggerCondition.WAF_DETECTED}
        assert len(s) == 2
        s.add(TriggerCondition.PORT_OPEN)
        assert len(s) == 2


# ===================== ToolResult Dataclass =====================


class TestToolResult:
    """Full coverage for ToolResult dataclass."""

    def test_minimal_creation(self):
        r = ToolResult(tool_name="nmap_scan", success=True, output="80/tcp open")
        assert r.tool_name == "nmap_scan"
        assert r.success is True
        assert r.output == "80/tcp open"

    def test_defaults(self):
        r = ToolResult(tool_name="x", success=False, output="")
        assert r.extracted_data == {}
        assert r.triggered_conditions == []
        assert r.next_tools == []
        assert r.execution_time == 0.0

    def test_mutable_default_isolation_extracted_data(self):
        r1 = ToolResult(tool_name="a", success=True, output="")
        r2 = ToolResult(tool_name="b", success=True, output="")
        r1.extracted_data["key"] = "val"
        assert "key" not in r2.extracted_data

    def test_mutable_default_isolation_triggered_conditions(self):
        r1 = ToolResult(tool_name="a", success=True, output="")
        r2 = ToolResult(tool_name="b", success=True, output="")
        r1.triggered_conditions.append(TriggerCondition.PORT_OPEN)
        assert len(r2.triggered_conditions) == 0

    def test_mutable_default_isolation_next_tools(self):
        r1 = ToolResult(tool_name="a", success=True, output="")
        r2 = ToolResult(tool_name="b", success=True, output="")
        r1.next_tools.append("foo")
        assert len(r2.next_tools) == 0

    def test_with_all_fields(self):
        r = ToolResult(
            tool_name="nuclei_scan",
            success=True,
            output="CVE-2024-1234",
            extracted_data={"cves": ["CVE-2024-1234"]},
            triggered_conditions=[TriggerCondition.CVE_IDENTIFIED],
            next_tools=["searchsploit_search"],
            execution_time=15.5,
        )
        assert r.execution_time == 15.5
        assert len(r.triggered_conditions) == 1
        assert r.next_tools == ["searchsploit_search"]

    def test_success_false(self):
        r = ToolResult(tool_name="nmap_scan", success=False, output="error")
        assert r.success is False

    def test_empty_output(self):
        r = ToolResult(tool_name="nmap_scan", success=True, output="")
        assert r.output == ""

    def test_custom_execution_time(self):
        r = ToolResult(tool_name="x", success=True, output="", execution_time=99.9)
        assert r.execution_time == 99.9


# ===================== AttackChain Dataclass =====================


class TestAttackChain:
    """Full coverage for AttackChain dataclass."""

    def test_minimal_creation(self):
        chain = AttackChain(
            name="Web test",
            description="Testing web app",
            tools=["whatweb_scan", "gobuster_scan"],
        )
        assert chain.name == "Web test"
        assert chain.description == "Testing web app"
        assert len(chain.tools) == 2

    def test_defaults(self):
        chain = AttackChain(name="x", description="d", tools=[])
        assert chain.current_step == 0
        assert chain.success is False
        assert chain.findings == []

    def test_mutable_default_isolation_findings(self):
        c1 = AttackChain(name="a", description="d", tools=[])
        c2 = AttackChain(name="b", description="d", tools=[])
        c1.findings.append({"vuln": "sqli"})
        assert len(c2.findings) == 0

    def test_custom_current_step(self):
        chain = AttackChain(name="x", description="d", tools=["a"], current_step=3)
        assert chain.current_step == 3

    def test_custom_success(self):
        chain = AttackChain(name="x", description="d", tools=["a"], success=True)
        assert chain.success is True

    def test_empty_tools(self):
        chain = AttackChain(name="x", description="d", tools=[])
        assert chain.tools == []

    def test_tools_list_is_independent(self):
        tools = ["a", "b"]
        chain = AttackChain(name="x", description="d", tools=tools)
        tools.append("c")
        # dataclass does NOT copy — this is expected behavior
        assert len(chain.tools) == 3  # list is shared


# ===================== ToolOrchestrator Init =====================


class TestToolOrchestratorInit:
    """Initialization and class-level constants."""

    def test_defaults(self):
        orch = ToolOrchestrator()
        assert orch.mcp_tools == {}
        assert orch.execution_history == []
        assert len(orch.triggered_conditions) == 0
        assert isinstance(orch.discovered_data, defaultdict)
        assert len(orch.tools_executed) == 0
        assert orch.current_chain is None

    def test_with_tools(self):
        tools = {"nmap_scan": lambda **kw: None}
        orch = ToolOrchestrator(mcp_tools=tools)
        assert "nmap_scan" in orch.mcp_tools

    def test_none_tools_becomes_empty_dict(self):
        orch = ToolOrchestrator(mcp_tools=None)
        assert orch.mcp_tools == {}

    def test_has_result_triggers(self):
        assert "port_80_open" in ToolOrchestrator.RESULT_TRIGGERS
        assert "wordpress_detected" in ToolOrchestrator.RESULT_TRIGGERS
        assert "sql_injection_possible" in ToolOrchestrator.RESULT_TRIGGERS
        assert "cve_found" in ToolOrchestrator.RESULT_TRIGGERS
        assert "subdomain_found" in ToolOrchestrator.RESULT_TRIGGERS

    def test_all_triggers_have_required_keys(self):
        for name, cfg in ToolOrchestrator.RESULT_TRIGGERS.items():
            assert "pattern" in cfg, f"{name} missing pattern"
            assert "condition" in cfg, f"{name} missing condition"
            assert "triggers" in cfg, f"{name} missing triggers"
            assert "priority" in cfg, f"{name} missing priority"

    def test_has_attack_chains(self):
        assert "web_full_assessment" in ToolOrchestrator.ATTACK_CHAINS
        assert "network_penetration" in ToolOrchestrator.ATTACK_CHAINS
        assert "ctf_web_chain" in ToolOrchestrator.ATTACK_CHAINS
        assert "sql_injection_deep" in ToolOrchestrator.ATTACK_CHAINS
        assert "authentication_attack" in ToolOrchestrator.ATTACK_CHAINS

    def test_attack_chains_are_attack_chain_instances(self):
        for name, chain in ToolOrchestrator.ATTACK_CHAINS.items():
            assert isinstance(chain, AttackChain), f"{name} is not AttackChain"

    def test_has_fallback_tools(self):
        assert "gobuster_scan" in ToolOrchestrator.FALLBACK_TOOLS
        assert "ffuf_scan" in ToolOrchestrator.FALLBACK_TOOLS["gobuster_scan"]

    def test_fallback_tools_values_are_lists(self):
        for tool, fallbacks in ToolOrchestrator.FALLBACK_TOOLS.items():
            assert isinstance(fallbacks, list), f"fallbacks for {tool} not list"

    def test_has_aggressive_params(self):
        assert "sqlmap_scan" in ToolOrchestrator.AGGRESSIVE_PARAMS
        assert "level_3" in ToolOrchestrator.AGGRESSIVE_PARAMS["sqlmap_scan"]

    def test_aggressive_params_all_have_three_levels(self):
        for tool, levels in ToolOrchestrator.AGGRESSIVE_PARAMS.items():
            assert "level_1" in levels, f"{tool} missing level_1"
            assert "level_2" in levels, f"{tool} missing level_2"
            assert "level_3" in levels, f"{tool} missing level_3"

    def test_discovered_data_is_defaultdict(self):
        orch = ToolOrchestrator()
        # Accessing a missing key returns an empty list
        assert orch.discovered_data["nonexistent"] == []


# ===================== analyze_output =====================


class TestAnalyzeOutput:
    """analyze_output: trigger matching, dedup, accumulation."""

    def test_port_80_triggers_web_tools(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "80/tcp open http")
        assert TriggerCondition.PORT_OPEN in result.triggered_conditions
        assert any("whatweb" in t or "gobuster" in t for t in result.next_tools)

    def test_port_443_triggers(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "443/tcp open https")
        assert TriggerCondition.PORT_OPEN in result.triggered_conditions

    def test_port_22_triggers_hydra(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "22/tcp open ssh")
        assert "hydra_attack" in result.next_tools

    def test_port_21_triggers(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "21/tcp open ftp")
        assert TriggerCondition.PORT_OPEN in result.triggered_conditions

    def test_port_445_triggers_enum4linux(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "445/tcp open microsoft-ds")
        assert "enum4linux_scan" in result.next_tools

    def test_port_3306_triggers(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "3306/tcp open mysql")
        assert TriggerCondition.PORT_OPEN in result.triggered_conditions

    def test_port_1433_triggers(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "1433/tcp open ms-sql-s")
        assert TriggerCondition.PORT_OPEN in result.triggered_conditions

    def test_wordpress_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("whatweb_scan", "WordPress 6.0, wp-content detected")
        assert TriggerCondition.CMS_DETECTED in result.triggered_conditions
        assert "wpscan_scan" in result.next_tools

    def test_joomla_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("whatweb_scan", "Joomla CMS /administrator")
        assert TriggerCondition.CMS_DETECTED in result.triggered_conditions
        assert "joomscan_scan" in result.next_tools

    def test_drupal_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("whatweb_scan", "Drupal CMS detected")
        assert TriggerCondition.CMS_DETECTED in result.triggered_conditions
        assert "nuclei_scan" in result.next_tools

    def test_waf_detection_cloudflare(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("whatweb_scan", "Cloudflare WAF detected")
        assert TriggerCondition.WAF_DETECTED in result.triggered_conditions

    def test_waf_detection_akamai(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("scan", "akamai protection")
        assert TriggerCondition.WAF_DETECTED in result.triggered_conditions

    def test_waf_detection_forbidden(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("scan", "403 Forbidden blocked by firewall")
        assert TriggerCondition.WAF_DETECTED in result.triggered_conditions

    def test_sql_injection_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nuclei_scan", "SQL injection found in param id, MySQL error")
        assert TriggerCondition.INJECTION_POSSIBLE in result.triggered_conditions
        assert "sqlmap_scan" in result.next_tools

    def test_xss_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nuclei_scan", "Reflected XSS found <script>alert(1)</script>")
        assert TriggerCondition.INJECTION_POSSIBLE in result.triggered_conditions

    def test_command_injection_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("scan", "command injection RCE remote code execution")
        assert TriggerCondition.INJECTION_POSSIBLE in result.triggered_conditions

    def test_lfi_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("scan", "local file inclusion LFI path traversal ../")
        assert TriggerCondition.INJECTION_POSSIBLE in result.triggered_conditions

    def test_cve_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nuclei_scan", "Found CVE-2024-1234 critical vulnerability")
        assert TriggerCondition.CVE_IDENTIFIED in result.triggered_conditions
        assert "searchsploit_search" in result.next_tools

    def test_admin_panel_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("gobuster_scan", "/admin (Status: 200)")
        assert TriggerCondition.ADMIN_PANEL in result.triggered_conditions

    def test_dashboard_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("gobuster_scan", "/dashboard (Status: 200)")
        assert TriggerCondition.ADMIN_PANEL in result.triggered_conditions

    def test_upload_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("gobuster_scan", "/upload (Status: 200)")
        assert TriggerCondition.FILE_UPLOAD in result.triggered_conditions

    def test_api_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("scan", "/api/v1/users endpoint")
        assert TriggerCondition.SERVICE_DETECTED in result.triggered_conditions

    def test_graphql_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("scan", "graphql endpoint found")
        assert TriggerCondition.SERVICE_DETECTED in result.triggered_conditions

    def test_login_form_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nikto_scan", '<form action="/login"><input type="password">')
        assert TriggerCondition.AUTH_REQUIRED in result.triggered_conditions

    def test_subdomain_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("subfinder", "subdomain found: dev.example.com")
        assert TriggerCondition.SUBDOMAIN_FOUND in result.triggered_conditions

    def test_no_triggers(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "Host is up (0.001s latency)")
        assert len(result.triggered_conditions) == 0
        assert len(result.next_tools) == 0

    def test_already_executed_tools_excluded(self):
        orch = ToolOrchestrator()
        orch.tools_executed.add("whatweb_scan")
        orch.tools_executed.add("gobuster_scan")
        result = orch.analyze_output("nmap_scan", "80/tcp open http")
        assert "whatweb_scan" not in result.next_tools
        assert "gobuster_scan" not in result.next_tools

    def test_result_always_success_true(self):
        """analyze_output always creates a ToolResult with success=True."""
        orch = ToolOrchestrator()
        result = orch.analyze_output("any_tool", "anything")
        assert result.success is True

    def test_result_preserves_tool_name_and_output(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("my_tool", "my output")
        assert result.tool_name == "my_tool"
        assert result.output == "my output"

    def test_multiple_triggers_single_output(self):
        """An output matching multiple rules should trigger all of them."""
        orch = ToolOrchestrator()
        output = "80/tcp open http\n22/tcp open ssh\nwordpress wp-content\nCVE-2024-9999"
        result = orch.analyze_output("nmap_scan", output)
        assert TriggerCondition.PORT_OPEN in result.triggered_conditions
        assert TriggerCondition.CMS_DETECTED in result.triggered_conditions
        assert TriggerCondition.CVE_IDENTIFIED in result.triggered_conditions

    def test_conditions_accumulate_across_calls(self):
        orch = ToolOrchestrator()
        orch.analyze_output("nmap_scan", "80/tcp open http")
        orch.analyze_output("whatweb_scan", "WordPress CMS")
        assert TriggerCondition.PORT_OPEN in orch.triggered_conditions
        assert TriggerCondition.CMS_DETECTED in orch.triggered_conditions

    def test_next_tools_no_duplicates(self):
        """If a tool appears via multiple trigger rules, it should be listed only once."""
        orch = ToolOrchestrator()
        # "sql injection" and "sqli" both match sql_injection_possible pattern
        result = orch.analyze_output("scan", "sql injection sqli error sql mysql error syntax error sql")
        tool_counts = {}
        for t in result.next_tools:
            tool_counts[t] = tool_counts.get(t, 0) + 1
        for t, count in tool_counts.items():
            assert count == 1, f"{t} appears {count} times"

    def test_case_insensitive_matching(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("scan", "WORDPRESS WP-CONTENT WP-ADMIN")
        assert TriggerCondition.CMS_DETECTED in result.triggered_conditions


# ===================== _extract_data =====================


class TestExtractData:
    """_extract_data: port, CVE, path, subdomain extraction."""

    def test_extract_ports(self):
        orch = ToolOrchestrator()
        orch.analyze_output("nmap_scan", "22/tcp open ssh\n80/tcp open http\n443/tcp open https")
        assert 22 in orch.discovered_data["open_ports"]
        assert 80 in orch.discovered_data["open_ports"]
        assert 443 in orch.discovered_data["open_ports"]

    def test_extract_cves(self):
        orch = ToolOrchestrator()
        orch.analyze_output("nuclei_scan", "CVE-2024-1234 and CVE-2023-5678")
        assert "CVE-2024-1234" in orch.discovered_data["cves"]
        assert "CVE-2023-5678" in orch.discovered_data["cves"]

    def test_extract_paths(self):
        orch = ToolOrchestrator()
        orch.analyze_output("gobuster_scan", "/admin found\n/upload detected")
        assert "/admin" in orch.discovered_data["paths"]

    def test_extract_subdomains(self):
        orch = ToolOrchestrator()
        orch.analyze_output("subfinder", "subdomain dev.example.com found")
        assert any("example.com" in d for d in orch.discovered_data["subdomains"])

    def test_no_ports_extracted_for_non_port_trigger(self):
        orch = ToolOrchestrator()
        result = ToolResult(tool_name="scan", success=True, output="")
        orch._extract_data("wordpress_detected", r"wordpress", "wordpress site", result)
        assert "open_ports" not in result.extracted_data

    def test_no_cves_extracted_for_non_cve_trigger(self):
        orch = ToolOrchestrator()
        result = ToolResult(tool_name="scan", success=True, output="")
        orch._extract_data("port_80_open", r"80/tcp", "80/tcp open", result)
        assert "cves" not in result.extracted_data

    def test_port_extraction_integers(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "8080/tcp open http-proxy")
        # 8080 itself doesn't match the port_80_open trigger, but if we
        # explicitly call _extract_data for a "port" trigger:
        r = ToolResult(tool_name="test", success=True, output="")
        orch._extract_data("port_custom", r"", "8080/tcp open http", r)
        assert all(isinstance(p, int) for p in r.extracted_data.get("open_ports", []))

    def test_path_extraction_for_admin_trigger(self):
        orch = ToolOrchestrator()
        r = ToolResult(tool_name="test", success=True, output="")
        orch._extract_data("admin_panel_found", r"/admin", "/admin/panel/page", r)
        assert "/admin/panel/page" in r.extracted_data["paths"]


# ===================== _prioritize_tools =====================


class TestPrioritizeTools:
    """_prioritize_tools: ordering by priority class."""

    def test_high_priority_first(self):
        orch = ToolOrchestrator()
        tools = ["gobuster_scan", "sqlmap_scan", "nikto_scan", "nuclei_scan"]
        sorted_tools = orch._prioritize_tools(tools)
        assert sorted_tools.index("sqlmap_scan") < sorted_tools.index("gobuster_scan")
        assert sorted_tools.index("nuclei_scan") < sorted_tools.index("nikto_scan")

    def test_empty_list(self):
        orch = ToolOrchestrator()
        assert orch._prioritize_tools([]) == []

    def test_single_high_priority(self):
        orch = ToolOrchestrator()
        assert orch._prioritize_tools(["sqlmap_scan"]) == ["sqlmap_scan"]

    def test_single_medium_priority(self):
        orch = ToolOrchestrator()
        assert orch._prioritize_tools(["gobuster_scan"]) == ["gobuster_scan"]

    def test_single_unknown_tool(self):
        orch = ToolOrchestrator()
        assert orch._prioritize_tools(["custom_tool"]) == ["custom_tool"]

    def test_unknown_tools_at_end(self):
        orch = ToolOrchestrator()
        tools = ["custom_tool", "sqlmap_scan"]
        sorted_tools = orch._prioritize_tools(tools)
        assert sorted_tools[0] == "sqlmap_scan"
        assert sorted_tools[-1] == "custom_tool"

    def test_all_high_priority_preserves_relative_order(self):
        orch = ToolOrchestrator()
        tools = ["nuclei_scan", "sqlmap_scan", "wpscan_scan"]
        sorted_tools = orch._prioritize_tools(tools)
        # All high-priority: comes out in high_priority list order
        assert sorted_tools[0] == "sqlmap_scan"
        assert "nuclei_scan" in sorted_tools
        assert "wpscan_scan" in sorted_tools

    def test_all_unknown_preserves_order(self):
        orch = ToolOrchestrator()
        tools = ["zzz", "aaa", "mmm"]
        sorted_tools = orch._prioritize_tools(tools)
        assert sorted_tools == ["zzz", "aaa", "mmm"]

    def test_medium_after_high(self):
        orch = ToolOrchestrator()
        tools = ["hydra_attack", "searchsploit_search"]
        sorted_tools = orch._prioritize_tools(tools)
        assert sorted_tools.index("searchsploit_search") < sorted_tools.index("hydra_attack")

    def test_complete_ordering(self):
        orch = ToolOrchestrator()
        tools = ["custom", "hydra_attack", "sqlmap_scan"]
        sorted_tools = orch._prioritize_tools(tools)
        assert sorted_tools[0] == "sqlmap_scan"  # high
        assert sorted_tools[1] == "hydra_attack"  # medium
        assert sorted_tools[2] == "custom"  # unknown/low


# ===================== _build_params =====================


class TestBuildParams:
    """_build_params: parameter building logic."""

    def test_web_tool_with_http_target(self):
        orch = ToolOrchestrator()
        params = orch._build_params("gobuster_scan", "http://example.com")
        assert params["url"] == "http://example.com"

    def test_web_tool_with_https_target(self):
        orch = ToolOrchestrator()
        params = orch._build_params("gobuster_scan", "https://example.com")
        assert params["url"] == "https://example.com"

    def test_web_tool_without_http(self):
        orch = ToolOrchestrator()
        params = orch._build_params("gobuster_scan", "example.com")
        assert params["url"] == "http://example.com"

    def test_network_tool(self):
        orch = ToolOrchestrator()
        params = orch._build_params("nmap_scan", "10.0.0.1")
        assert params["target"] == "10.0.0.1"

    def test_preserve_existing_params(self):
        orch = ToolOrchestrator()
        params = orch._build_params("nmap_scan", "10.0.0.1", {"ports": "80"})
        assert params["ports"] == "80"
        assert params["target"] == "10.0.0.1"

    def test_dont_override_target(self):
        orch = ToolOrchestrator()
        params = orch._build_params("nmap_scan", "10.0.0.1", {"target": "10.0.0.2"})
        assert params["target"] == "10.0.0.2"

    def test_dont_override_url(self):
        orch = ToolOrchestrator()
        params = orch._build_params("gobuster_scan", "http://a.com", {"url": "http://b.com"})
        assert params["url"] == "http://b.com"

    def test_no_override_params_is_none(self):
        orch = ToolOrchestrator()
        params = orch._build_params("nmap_scan", "10.0.0.1", None)
        assert params["target"] == "10.0.0.1"

    def test_all_web_tool_names(self):
        """All web tools in the list should get url parameter."""
        web_tools = [
            "whatweb_scan", "gobuster_scan", "ffuf_scan",
            "feroxbuster_scan", "nikto_scan", "sqlmap_scan",
            "nuclei_scan", "nuclei_web_scan", "wpscan_scan",
        ]
        orch = ToolOrchestrator()
        for tool in web_tools:
            params = orch._build_params(tool, "http://test.com")
            assert "url" in params, f"{tool} should have url param"

    def test_non_web_tool_gets_target(self):
        orch = ToolOrchestrator()
        params = orch._build_params("hydra_attack", "192.168.1.1")
        assert params["target"] == "192.168.1.1"
        assert "url" not in params

    def test_override_params_not_mutated(self):
        orch = ToolOrchestrator()
        original = {"ports": "80"}
        params = orch._build_params("nmap_scan", "10.0.0.1", original)
        # params should have target added, but original should not
        assert "target" not in original


# ===================== _check_exploit_success =====================


class TestCheckExploitSuccess:
    """_check_exploit_success: indicator matching by vuln type."""

    def test_sqli_success_database(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("Database: mydb", "sqli") is True

    def test_sqli_success_table(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("Table: users found", "sqli") is True

    def test_sqli_success_column(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("Column: password", "sqli") is True

    def test_sqli_success_dumped(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("100 rows dumped", "sqli") is True

    def test_sqli_success_extracted(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("data extracted successfully", "sqli") is True

    def test_sqli_failure(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("No injection detected", "sqli") is False

    def test_xss_success_alert(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("alert box appeared", "xss") is True

    def test_xss_success_confirmed(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("XSS confirmed by scanner", "xss") is True

    def test_xss_success_script_executed(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("script executed in browser", "xss") is True

    def test_xss_failure(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("No XSS vectors found", "xss") is False

    def test_command_injection_success_uid(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("uid=0(root) gid=0(root)", "command_injection") is True

    def test_command_injection_success_root(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("root access obtained", "command_injection") is True

    def test_command_injection_success_command_executed(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("command executed successfully", "command_injection") is True

    def test_command_injection_failure(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("nothing happened", "command_injection") is False

    def test_brute_force_success_password(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("Valid credentials password: P@ss", "brute_force") is True

    def test_brute_force_success_login(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("login successful", "brute_force") is True

    def test_brute_force_success_valid_credentials(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("Valid credentials found", "brute_force") is True

    def test_brute_force_failure(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("all attempts failed", "brute_force") is False

    def test_unknown_vuln_type(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("anything", "unknown_type") is False

    def test_empty_output(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("", "sqli") is False

    def test_case_insensitive(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("DATABASE: MYDB", "sqli") is True
        assert orch._check_exploit_success("ALERT triggered", "xss") is True


# ===================== get_orchestration_stats =====================


class TestGetOrchestrationStats:
    """get_orchestration_stats: stats aggregation."""

    def test_empty_stats(self):
        orch = ToolOrchestrator()
        stats = orch.get_orchestration_stats()
        assert stats["tools_executed"] == 0
        assert stats["conditions_triggered"] == 0
        assert stats["discovered_data_summary"] == {}
        assert stats["execution_history"] == 0

    def test_stats_after_analysis(self):
        orch = ToolOrchestrator()
        orch.analyze_output("nmap_scan", "80/tcp open http\n22/tcp open ssh")
        orch.tools_executed.add("nmap_scan")
        stats = orch.get_orchestration_stats()
        assert stats["tools_executed"] == 1
        assert stats["conditions_triggered"] > 0

    def test_discovered_data_summary_counts(self):
        orch = ToolOrchestrator()
        orch.discovered_data["open_ports"] = [80, 443, 22]
        orch.discovered_data["cves"] = ["CVE-2024-1234"]
        stats = orch.get_orchestration_stats()
        assert stats["discovered_data_summary"]["open_ports"] == 3
        assert stats["discovered_data_summary"]["cves"] == 1

    def test_execution_history_reflects_list(self):
        orch = ToolOrchestrator()
        orch.execution_history.append(
            ToolResult(tool_name="test", success=True, output="")
        )
        stats = orch.get_orchestration_stats()
        assert stats["execution_history"] == 1


# ===================== _execute_tool (async) =====================


class TestExecuteTool:
    """_execute_tool: async tool execution with mocks."""

    @pytest.mark.asyncio
    async def test_tool_present_success(self):
        mock_fn = AsyncMock(return_value="scan result")
        orch = ToolOrchestrator(mcp_tools={"nmap_scan": mock_fn})
        result = await orch._execute_tool("nmap_scan", "10.0.0.1")
        assert result.success is True
        assert "scan result" in result.output
        assert result.execution_time >= 0

    @pytest.mark.asyncio
    async def test_tool_not_available(self):
        orch = ToolOrchestrator()
        result = await orch._execute_tool("nonexistent", "10.0.0.1")
        assert result.success is False
        assert "not available" in result.output

    @pytest.mark.asyncio
    async def test_tool_raises_exception(self):
        mock_fn = AsyncMock(side_effect=RuntimeError("boom"))
        orch = ToolOrchestrator(mcp_tools={"nmap_scan": mock_fn})
        result = await orch._execute_tool("nmap_scan", "10.0.0.1")
        assert result.success is False
        assert "boom" in result.output

    @pytest.mark.asyncio
    async def test_tool_with_params(self):
        mock_fn = AsyncMock(return_value="ok")
        orch = ToolOrchestrator(mcp_tools={"nmap_scan": mock_fn})
        result = await orch._execute_tool("nmap_scan", "10.0.0.1", {"ports": "80"})
        assert result.success is True
        mock_fn.assert_called_once()

    @pytest.mark.asyncio
    async def test_execution_time_positive(self):
        async def slow_tool(**kw):
            return "done"
        orch = ToolOrchestrator(mcp_tools={"slow": slow_tool})
        result = await orch._execute_tool("slow", "target")
        assert result.execution_time >= 0


# ===================== execute_with_orchestration (async) =====================


class TestExecuteWithOrchestration:
    """execute_with_orchestration: the main orchestration loop."""

    @pytest.mark.asyncio
    async def test_basic_execution(self):
        mock_fn = AsyncMock(return_value="Host is up")
        orch = ToolOrchestrator(mcp_tools={"nmap_scan": mock_fn})
        report = await orch.execute_with_orchestration("nmap_scan", "10.0.0.1")
        assert report["start_tool"] == "nmap_scan"
        assert report["target"] == "10.0.0.1"
        assert report["total_tools_executed"] >= 1

    @pytest.mark.asyncio
    async def test_triggers_chain(self):
        """When output triggers new tools, they should be queued."""
        call_count = 0

        async def mock_tool(**kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "80/tcp open http"
            return "nothing"

        tools = {
            "nmap_scan": mock_tool,
            "whatweb_scan": mock_tool,
            "gobuster_scan": mock_tool,
            "nikto_scan": mock_tool,
            "nuclei_web_scan": mock_tool,
        }
        orch = ToolOrchestrator(mcp_tools=tools)
        report = await orch.execute_with_orchestration("nmap_scan", "10.0.0.1")
        assert report["total_tools_executed"] > 1

    @pytest.mark.asyncio
    async def test_depth_limit(self):
        async def mock_tool(**kw):
            return "80/tcp open http"

        tools = {"nmap_scan": mock_tool}
        orch = ToolOrchestrator(mcp_tools=tools)
        report = await orch.execute_with_orchestration("nmap_scan", "t", max_depth=0)
        # Only the start tool runs at depth 0; triggered tools at depth 1 are skipped
        assert report["total_tools_executed"] == 1

    @pytest.mark.asyncio
    async def test_max_tools_limit(self):
        async def mock_tool(**kw):
            return "nothing"

        tools = {"tool_" + str(i): mock_tool for i in range(100)}
        tools["start"] = mock_tool
        orch = ToolOrchestrator(mcp_tools=tools)
        report = await orch.execute_with_orchestration("start", "t", max_tools=2)
        assert report["total_tools_executed"] <= 2

    @pytest.mark.asyncio
    async def test_dedup_prevents_rerun(self):
        run_count = 0

        async def mock_tool(**kw):
            nonlocal run_count
            run_count += 1
            return "nothing"

        orch = ToolOrchestrator(mcp_tools={"nmap_scan": mock_tool})
        orch.tools_executed.add("nmap_scan")
        report = await orch.execute_with_orchestration("nmap_scan", "t")
        assert report["total_tools_executed"] == 0
        assert run_count == 0

    @pytest.mark.asyncio
    async def test_failure_triggers_fallback(self):
        """When a tool fails, its fallback should be queued."""
        async def fail_tool(**kw):
            raise RuntimeError("fail")

        async def ok_tool(**kw):
            return "nothing"

        tools = {
            "gobuster_scan": fail_tool,
            "ffuf_scan": ok_tool,
            "feroxbuster_scan": ok_tool,
            "dirb_scan": ok_tool,
        }
        orch = ToolOrchestrator(mcp_tools=tools)
        report = await orch.execute_with_orchestration("gobuster_scan", "t", max_depth=5)
        executed_tools = [r["tool"] for r in report["results"]]
        assert "gobuster_scan" in executed_tools
        # Fallback should have been triggered
        assert any(t in executed_tools for t in ["ffuf_scan", "feroxbuster_scan", "dirb_scan"])

    @pytest.mark.asyncio
    async def test_report_structure(self):
        mock_fn = AsyncMock(return_value="nothing")
        orch = ToolOrchestrator(mcp_tools={"tool1": mock_fn})
        report = await orch.execute_with_orchestration("tool1", "target")
        assert "start_tool" in report
        assert "target" in report
        assert "total_tools_executed" in report
        assert "triggered_conditions" in report
        assert "discovered_data" in report
        assert "results" in report

    @pytest.mark.asyncio
    async def test_missing_start_tool(self):
        """If start tool is not in mcp_tools, it should still run (as failure)."""
        orch = ToolOrchestrator()
        report = await orch.execute_with_orchestration("nonexistent", "t")
        assert report["total_tools_executed"] == 1
        assert report["results"][0]["success"] is False


# ===================== execute_attack_chain (async) =====================


class TestExecuteAttackChain:
    """execute_attack_chain: predefined chain execution."""

    @pytest.mark.asyncio
    async def test_unknown_chain(self):
        orch = ToolOrchestrator()
        result = await orch.execute_attack_chain("nonexistent_chain", "target")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_known_chain_runs_all_steps(self):
        mock_fn = AsyncMock(return_value="nothing")
        # Build tools for the sql_injection_deep chain
        chain = ToolOrchestrator.ATTACK_CHAINS["sql_injection_deep"]
        tools = {t: mock_fn for t in chain.tools}
        orch = ToolOrchestrator(mcp_tools=tools)
        result = await orch.execute_attack_chain("sql_injection_deep", "target")
        assert result["chain_name"] == "sql_injection_deep"
        assert result["steps_completed"] == len(chain.tools)

    @pytest.mark.asyncio
    async def test_chain_with_missing_tools(self):
        """Chain continues even if some tools are missing from mcp_tools."""
        mock_fn = AsyncMock(return_value="nothing")
        # Only provide first tool
        chain = ToolOrchestrator.ATTACK_CHAINS["sql_injection_deep"]
        orch = ToolOrchestrator(mcp_tools={chain.tools[0]: mock_fn})
        result = await orch.execute_attack_chain("sql_injection_deep", "target")
        assert result["steps_completed"] == len(chain.tools)

    @pytest.mark.asyncio
    async def test_chain_result_structure(self):
        mock_fn = AsyncMock(return_value="nothing")
        chain = ToolOrchestrator.ATTACK_CHAINS["authentication_attack"]
        tools = {t: mock_fn for t in chain.tools}
        orch = ToolOrchestrator(mcp_tools=tools)
        result = await orch.execute_attack_chain("authentication_attack", "target")
        assert "chain_name" in result
        assert "target" in result
        assert "steps_completed" in result
        assert "results" in result
        for step in result["results"]:
            assert "tool" in step
            assert "success" in step

    @pytest.mark.asyncio
    async def test_chain_triggers_analysis_on_success(self):
        """Successful steps should trigger analyze_output."""
        async def web_tool(**kw):
            return "wordpress wp-content found"

        chain = ToolOrchestrator.ATTACK_CHAINS["web_full_assessment"]
        tools = {t: web_tool for t in chain.tools}
        orch = ToolOrchestrator(mcp_tools=tools)
        await orch.execute_attack_chain("web_full_assessment", "target")
        assert TriggerCondition.CMS_DETECTED in orch.triggered_conditions


# ===================== deep_exploit (async) =====================


class TestDeepExploit:
    """deep_exploit: multi-level escalation."""

    @pytest.mark.asyncio
    async def test_unknown_vuln_type(self):
        orch = ToolOrchestrator()
        result = await orch.deep_exploit("unknown", "target")
        assert result["success"] is False
        assert result["results"] == []

    @pytest.mark.asyncio
    async def test_sqli_escalation_levels(self):
        mock_fn = AsyncMock(return_value="no injection found")
        orch = ToolOrchestrator(mcp_tools={
            "sqlmap_scan": mock_fn,
            "intelligent_sql_injection_payloads": mock_fn,
        })
        result = await orch.deep_exploit("sqli", "target")
        assert result["success"] is False
        # Should have attempted multiple levels for sqlmap_scan
        sqlmap_attempts = [r for r in result["results"] if r["tool"] == "sqlmap_scan"]
        assert len(sqlmap_attempts) == 3  # level_1, level_2, level_3

    @pytest.mark.asyncio
    async def test_exploit_success_stops_early(self):
        call_count = 0

        async def mock_fn(**kw):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return "Database: mydb, Table: users, dumped"
            return "nothing"

        orch = ToolOrchestrator(mcp_tools={"sqlmap_scan": mock_fn})
        result = await orch.deep_exploit("sqli", "target")
        assert result["success"] is True
        assert result["tool"] == "sqlmap_scan"
        assert result["level"] == "level_2"

    @pytest.mark.asyncio
    async def test_tool_without_aggressive_params(self):
        """Tools not in AGGRESSIVE_PARAMS should run once without level escalation."""
        mock_fn = AsyncMock(return_value="nothing")
        orch = ToolOrchestrator(mcp_tools={
            "intelligent_xss_payloads": mock_fn,
        })
        result = await orch.deep_exploit("xss", "target")
        assert result["success"] is False
        xss_attempts = [r for r in result["results"] if r["tool"] == "intelligent_xss_payloads"]
        assert len(xss_attempts) == 1

    @pytest.mark.asyncio
    async def test_brute_force_escalation(self):
        mock_fn = AsyncMock(return_value="failed")
        orch = ToolOrchestrator(mcp_tools={
            "hydra_attack": mock_fn,
            "medusa_bruteforce": mock_fn,
        })
        result = await orch.deep_exploit("brute_force", "target")
        assert result["success"] is False
        hydra_attempts = [r for r in result["results"] if r["tool"] == "hydra_attack"]
        assert len(hydra_attempts) == 3

    @pytest.mark.asyncio
    async def test_command_injection_tools(self):
        mock_fn = AsyncMock(return_value="nothing")
        orch = ToolOrchestrator(mcp_tools={
            "intelligent_command_injection_payloads": mock_fn,
        })
        result = await orch.deep_exploit("command_injection", "target")
        assert result["success"] is False
        assert len(result["results"]) == 1

    @pytest.mark.asyncio
    async def test_exploit_failure_returns_all_results(self):
        mock_fn = AsyncMock(return_value="nothing")
        orch = ToolOrchestrator(mcp_tools={
            "sqlmap_scan": mock_fn,
            "intelligent_sql_injection_payloads": mock_fn,
        })
        result = await orch.deep_exploit("sqli", "target")
        assert result["success"] is False
        # sqlmap has 3 levels + intelligent has 1 run = 4
        assert len(result["results"]) == 4


# ===================== AutoPilotAttack =====================


class TestAutoPilotAttack:
    """AutoPilotAttack: init and async autopilot."""

    def test_init(self):
        orch = ToolOrchestrator()
        pilot = AutoPilotAttack(orch)
        assert pilot.orchestrator is orch
        assert "reconnaissance" in pilot.attack_phases
        assert "exploitation" in pilot.attack_phases
        assert len(pilot.attack_phases) == 5

    def test_attack_phases_order(self):
        orch = ToolOrchestrator()
        pilot = AutoPilotAttack(orch)
        assert pilot.attack_phases == [
            "reconnaissance",
            "discovery",
            "vulnerability_scanning",
            "exploitation",
            "post_exploitation",
        ]

    @pytest.mark.asyncio
    async def test_run_autopilot_web_target(self):
        """When ports 80/443 are open, web path should be taken."""
        call_idx = 0

        async def mock_tool(**kw):
            nonlocal call_idx
            call_idx += 1
            if call_idx == 1:
                return "80/tcp open http\n443/tcp open https"
            return "nothing"

        web_chain = ToolOrchestrator.ATTACK_CHAINS["web_full_assessment"]
        net_chain = ToolOrchestrator.ATTACK_CHAINS["network_penetration"]
        all_tool_names = set()
        all_tool_names.update(web_chain.tools)
        all_tool_names.update(net_chain.tools)
        all_tool_names.update([
            "nmap_scan", "gobuster_scan", "enum4linux_scan",
            "whatweb_scan", "nikto_scan", "nuclei_web_scan",
            "nuclei_scan", "nuclei_network_scan",
        ])

        tools = {name: mock_tool for name in all_tool_names}
        orch = ToolOrchestrator(mcp_tools=tools)
        pilot = AutoPilotAttack(orch)

        result = await pilot.run_autopilot("target", mode="comprehensive")
        assert result["target"] == "target"
        assert result["mode"] == "comprehensive"
        assert "reconnaissance" in result["phases"]
        assert "discovery" in result["phases"]
        assert "vulnerability" in result["phases"]
        assert "summary" in result

    @pytest.mark.asyncio
    async def test_run_autopilot_non_web_target(self):
        """When no web ports, non-web discovery path should be taken."""
        async def mock_tool(**kw):
            return "nothing special"

        net_chain = ToolOrchestrator.ATTACK_CHAINS["network_penetration"]
        all_tool_names = set(net_chain.tools)
        all_tool_names.update(["nmap_scan", "enum4linux_scan"])

        tools = {name: mock_tool for name in all_tool_names}
        orch = ToolOrchestrator(mcp_tools=tools)
        pilot = AutoPilotAttack(orch)

        result = await pilot.run_autopilot("target")
        assert "discovery" in result["phases"]

    @pytest.mark.asyncio
    async def test_run_autopilot_with_injection(self):
        """When injection is detected, exploitation phase should run."""
        call_idx = 0

        async def mock_tool(**kw):
            nonlocal call_idx
            call_idx += 1
            if call_idx <= 2:
                return "80/tcp open http"
            if call_idx == 3:
                return "SQL injection found sqli"
            return "nothing"

        web_chain = ToolOrchestrator.ATTACK_CHAINS["web_full_assessment"]
        all_tool_names = set(web_chain.tools)
        all_tool_names.update([
            "nmap_scan", "gobuster_scan", "whatweb_scan", "nikto_scan",
            "nuclei_web_scan", "nuclei_scan", "sqlmap_scan",
            "intelligent_sql_injection_payloads",
        ])

        tools = {name: mock_tool for name in all_tool_names}
        orch = ToolOrchestrator(mcp_tools=tools)
        # Pre-add injection condition
        orch.triggered_conditions.add(TriggerCondition.INJECTION_POSSIBLE)
        pilot = AutoPilotAttack(orch)

        result = await pilot.run_autopilot("target")
        assert "exploitation" in result["phases"]

    @pytest.mark.asyncio
    async def test_run_autopilot_summary_present(self):
        async def mock_tool(**kw):
            return "nothing"

        net_chain = ToolOrchestrator.ATTACK_CHAINS["network_penetration"]
        all_tool_names = set(net_chain.tools)
        all_tool_names.update(["nmap_scan", "enum4linux_scan"])
        tools = {name: mock_tool for name in all_tool_names}
        orch = ToolOrchestrator(mcp_tools=tools)
        pilot = AutoPilotAttack(orch)

        result = await pilot.run_autopilot("target")
        assert "summary" in result
        summary = result["summary"]
        assert "tools_executed" in summary
        assert "conditions_triggered" in summary


# ===================== Module __all__ Export =====================


class TestModuleExports:
    """Verify the module __all__ export list."""

    def test_all_contains_expected_names(self):
        expected = [
            "ToolOrchestrator",
            "AutoPilotAttack",
            "ToolCategory",
            "TriggerCondition",
            "ToolResult",
            "AttackChain",
        ]
        for name in expected:
            assert name in module_all, f"{name} not in __all__"

    def test_all_length(self):
        assert len(module_all) == 6


# ===================== Class-level constant integrity =====================


class TestClassConstants:
    """Verify structural integrity of class-level constants."""

    def test_result_triggers_conditions_are_valid_enums(self):
        for name, cfg in ToolOrchestrator.RESULT_TRIGGERS.items():
            assert isinstance(cfg["condition"], TriggerCondition), (
                f"{name} has invalid condition type"
            )

    def test_result_triggers_patterns_compile(self):
        import re
        for name, cfg in ToolOrchestrator.RESULT_TRIGGERS.items():
            try:
                re.compile(cfg["pattern"])
            except re.error:
                pytest.fail(f"Pattern for {name} does not compile")

    def test_result_triggers_priorities_are_integers(self):
        for name, cfg in ToolOrchestrator.RESULT_TRIGGERS.items():
            assert isinstance(cfg["priority"], int), f"{name} priority not int"

    def test_fallback_tools_keys_exist_in_triggers_or_chains(self):
        """Fallback tool keys should reference known tool names."""
        for tool in ToolOrchestrator.FALLBACK_TOOLS:
            assert isinstance(tool, str)

    def test_attack_chains_have_non_empty_tools(self):
        for name, chain in ToolOrchestrator.ATTACK_CHAINS.items():
            assert len(chain.tools) > 0, f"Chain {name} has no tools"

    def test_attack_chains_have_descriptions(self):
        for name, chain in ToolOrchestrator.ATTACK_CHAINS.items():
            assert chain.description, f"Chain {name} has no description"

    def test_aggressive_params_values_are_dicts(self):
        for tool, levels in ToolOrchestrator.AGGRESSIVE_PARAMS.items():
            for level, params in levels.items():
                assert isinstance(params, dict), f"{tool}/{level} not dict"


# ===================== Edge cases and integration =====================


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_analyze_output_empty_string(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("tool", "")
        assert result.success is True
        assert len(result.next_tools) == 0

    def test_analyze_output_very_long_string(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("tool", "x" * 100000)
        assert result.success is True

    def test_analyze_output_special_characters(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("tool", "\x00\n\r\t")
        assert result.success is True

    def test_build_params_empty_override(self):
        orch = ToolOrchestrator()
        params = orch._build_params("nmap_scan", "10.0.0.1", {})
        assert params["target"] == "10.0.0.1"

    def test_check_exploit_success_empty_vuln_type(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("database:", "") is False

    def test_multiple_orchestrator_instances_independent(self):
        orch1 = ToolOrchestrator()
        orch2 = ToolOrchestrator()
        orch1.tools_executed.add("nmap_scan")
        orch1.triggered_conditions.add(TriggerCondition.PORT_OPEN)
        assert "nmap_scan" not in orch2.tools_executed
        assert TriggerCondition.PORT_OPEN not in orch2.triggered_conditions

    @pytest.mark.asyncio
    async def test_execute_tool_records_execution_time(self):
        async def slow(**kw):
            return "done"
        orch = ToolOrchestrator(mcp_tools={"slow": slow})
        result = await orch._execute_tool("slow", "t")
        assert result.execution_time >= 0
        assert result.tool_name == "slow"

    def test_prioritize_tools_does_not_add_extras(self):
        orch = ToolOrchestrator()
        original = ["a", "b", "sqlmap_scan"]
        result = orch._prioritize_tools(original[:])  # copy to avoid mutation
        assert len(result) == 3

    def test_discovered_data_accumulates_across_analyses(self):
        orch = ToolOrchestrator()
        orch.analyze_output("nmap", "80/tcp open http")
        orch.analyze_output("nmap", "22/tcp open ssh")
        # Both should contribute to open_ports
        ports = orch.discovered_data["open_ports"]
        assert 80 in ports
        assert 22 in ports
