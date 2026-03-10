"""
Tests for tool_orchestrator module (kali_mcp/core/tool_orchestrator.py)

Covers:
- ToolCategory enum
- TriggerCondition enum
- ToolResult dataclass
- AttackChain dataclass
- ToolOrchestrator: init, analyze_output, _extract_data, _prioritize_tools,
  _build_params, _check_exploit_success, get_orchestration_stats
- AutoPilotAttack: init, attack_phases
"""

import pytest

from kali_mcp.core.tool_orchestrator import (
    ToolCategory,
    TriggerCondition,
    ToolResult,
    AttackChain,
    ToolOrchestrator,
    AutoPilotAttack,
)


# ===================== Enum Tests =====================

class TestToolCategory:
    def test_values(self):
        assert ToolCategory.RECON.value == "reconnaissance"
        assert ToolCategory.DISCOVERY.value == "discovery"
        assert ToolCategory.VULNERABILITY.value == "vulnerability"
        assert ToolCategory.EXPLOITATION.value == "exploitation"
        assert ToolCategory.POST_EXPLOIT.value == "post_exploitation"
        assert ToolCategory.PASSWORD.value == "password_attack"
        assert ToolCategory.PRIVILEGE.value == "privilege_escalation"
        assert ToolCategory.LATERAL.value == "lateral_movement"


class TestTriggerCondition:
    def test_values(self):
        assert TriggerCondition.PORT_OPEN.value == "port_open"
        assert TriggerCondition.CMS_DETECTED.value == "cms_detected"
        assert TriggerCondition.WAF_DETECTED.value == "waf_detected"
        assert TriggerCondition.INJECTION_POSSIBLE.value == "injection_possible"
        assert TriggerCondition.FILE_UPLOAD.value == "file_upload_found"
        assert TriggerCondition.CVE_IDENTIFIED.value == "cve_identified"
        assert TriggerCondition.SUBDOMAIN_FOUND.value == "subdomain_found"


# ===================== ToolResult Tests =====================

class TestToolResult:
    def test_creation(self):
        r = ToolResult(tool_name="nmap_scan", success=True, output="80/tcp open")
        assert r.tool_name == "nmap_scan"
        assert r.success is True
        assert r.extracted_data == {}
        assert r.triggered_conditions == []
        assert r.next_tools == []
        assert r.execution_time == 0.0

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


# ===================== AttackChain Tests =====================

class TestAttackChain:
    def test_creation(self):
        chain = AttackChain(
            name="Web test",
            description="Testing web app",
            tools=["whatweb_scan", "gobuster_scan"],
        )
        assert chain.name == "Web test"
        assert chain.current_step == 0
        assert chain.success is False
        assert chain.findings == []
        assert len(chain.tools) == 2


# ===================== ToolOrchestrator Init Tests =====================

class TestToolOrchestratorInit:
    def test_defaults(self):
        orch = ToolOrchestrator()
        assert orch.mcp_tools == {}
        assert orch.execution_history == []
        assert len(orch.triggered_conditions) == 0
        assert orch.current_chain is None

    def test_with_tools(self):
        tools = {"nmap_scan": lambda **kw: None}
        orch = ToolOrchestrator(mcp_tools=tools)
        assert "nmap_scan" in orch.mcp_tools

    def test_has_result_triggers(self):
        assert "port_80_open" in ToolOrchestrator.RESULT_TRIGGERS
        assert "wordpress_detected" in ToolOrchestrator.RESULT_TRIGGERS
        assert "sql_injection_possible" in ToolOrchestrator.RESULT_TRIGGERS

    def test_has_attack_chains(self):
        assert "web_full_assessment" in ToolOrchestrator.ATTACK_CHAINS
        assert "network_penetration" in ToolOrchestrator.ATTACK_CHAINS
        assert "ctf_web_chain" in ToolOrchestrator.ATTACK_CHAINS

    def test_has_fallback_tools(self):
        assert "gobuster_scan" in ToolOrchestrator.FALLBACK_TOOLS
        assert "ffuf_scan" in ToolOrchestrator.FALLBACK_TOOLS["gobuster_scan"]

    def test_has_aggressive_params(self):
        assert "sqlmap_scan" in ToolOrchestrator.AGGRESSIVE_PARAMS
        assert "level_3" in ToolOrchestrator.AGGRESSIVE_PARAMS["sqlmap_scan"]


# ===================== analyze_output Tests =====================

class TestAnalyzeOutput:
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

    def test_port_445_triggers_enum4linux(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "445/tcp open microsoft-ds")
        assert "enum4linux_scan" in result.next_tools

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

    def test_waf_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("whatweb_scan", "Cloudflare WAF detected")
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

    def test_cve_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nuclei_scan", "Found CVE-2024-1234 critical vulnerability")
        assert TriggerCondition.CVE_IDENTIFIED in result.triggered_conditions
        assert "searchsploit_search" in result.next_tools

    def test_admin_panel_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("gobuster_scan", "/admin (Status: 200)")
        assert TriggerCondition.ADMIN_PANEL in result.triggered_conditions

    def test_upload_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("gobuster_scan", "/upload (Status: 200)")
        assert TriggerCondition.FILE_UPLOAD in result.triggered_conditions

    def test_login_form_detection(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nikto_scan", '<form action="/login"><input type="password">')
        assert TriggerCondition.AUTH_REQUIRED in result.triggered_conditions

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


# ===================== _extract_data Tests =====================

class TestExtractData:
    def test_extract_ports(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nmap_scan", "22/tcp open ssh\n80/tcp open http\n443/tcp open https")
        assert 22 in orch.discovered_data["open_ports"]
        assert 80 in orch.discovered_data["open_ports"]
        assert 443 in orch.discovered_data["open_ports"]

    def test_extract_cves(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("nuclei_scan", "CVE-2024-1234 and CVE-2023-5678")
        assert "CVE-2024-1234" in orch.discovered_data["cves"]
        assert "CVE-2023-5678" in orch.discovered_data["cves"]

    def test_extract_paths(self):
        orch = ToolOrchestrator()
        result = orch.analyze_output("gobuster_scan", "/admin found\n/upload detected")
        assert "/admin" in orch.discovered_data["paths"]


# ===================== _prioritize_tools Tests =====================

class TestPrioritizeTools:
    def test_high_priority_first(self):
        orch = ToolOrchestrator()
        tools = ["gobuster_scan", "sqlmap_scan", "nikto_scan", "nuclei_scan"]
        sorted_tools = orch._prioritize_tools(tools)
        # sqlmap and nuclei should be before gobuster and nikto
        assert sorted_tools.index("sqlmap_scan") < sorted_tools.index("gobuster_scan")
        assert sorted_tools.index("nuclei_scan") < sorted_tools.index("nikto_scan")

    def test_empty_list(self):
        orch = ToolOrchestrator()
        assert orch._prioritize_tools([]) == []

    def test_unknown_tools_at_end(self):
        orch = ToolOrchestrator()
        tools = ["custom_tool", "sqlmap_scan"]
        sorted_tools = orch._prioritize_tools(tools)
        assert sorted_tools[0] == "sqlmap_scan"
        assert sorted_tools[-1] == "custom_tool"


# ===================== _build_params Tests =====================

class TestBuildParams:
    def test_web_tool_with_http_target(self):
        orch = ToolOrchestrator()
        params = orch._build_params("gobuster_scan", "http://example.com")
        assert params["url"] == "http://example.com"

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


# ===================== _check_exploit_success Tests =====================

class TestCheckExploitSuccess:
    def test_sqli_success(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("Database: mydb, Table: users, dumped 100 rows", "sqli") is True

    def test_sqli_failure(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("No injection detected", "sqli") is False

    def test_command_injection_success(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("uid=0(root) gid=0(root)", "command_injection") is True

    def test_brute_force_success(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("Valid credentials found: admin/password: P@ss123", "brute_force") is True

    def test_xss_success(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("XSS confirmed, alert triggered", "xss") is True

    def test_unknown_vuln_type(self):
        orch = ToolOrchestrator()
        assert orch._check_exploit_success("anything", "unknown_type") is False


# ===================== get_orchestration_stats Tests =====================

class TestGetOrchestrationStats:
    def test_empty_stats(self):
        orch = ToolOrchestrator()
        stats = orch.get_orchestration_stats()
        assert stats["tools_executed"] == 0
        assert stats["conditions_triggered"] == 0

    def test_stats_after_analysis(self):
        orch = ToolOrchestrator()
        orch.analyze_output("nmap_scan", "80/tcp open http\n22/tcp open ssh")
        orch.tools_executed.add("nmap_scan")
        stats = orch.get_orchestration_stats()
        assert stats["tools_executed"] == 1
        assert stats["conditions_triggered"] > 0


# ===================== AutoPilotAttack Tests =====================

class TestAutoPilotAttack:
    def test_init(self):
        orch = ToolOrchestrator()
        pilot = AutoPilotAttack(orch)
        assert pilot.orchestrator is orch
        assert "reconnaissance" in pilot.attack_phases
        assert "exploitation" in pilot.attack_phases
        assert len(pilot.attack_phases) == 5
