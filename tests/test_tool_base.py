"""
Tests for tools/base.py (Finding, ToolResult)

Covers:
- Finding dataclass
- ToolResult: add_finding, flag detection, extract_flags, filtering, serialization
"""

import pytest

from kali_mcp.tools.base import (
    Finding,
    ToolResult,
    ToolCategory,
    RiskLevel,
)


# ===================== Finding Tests =====================

class TestFinding:
    def test_to_dict(self):
        f = Finding(finding_type="port", value="80", severity="info",
                    details={"service": "http"})
        d = f.to_dict()
        assert d["type"] == "port"
        assert d["value"] == "80"
        assert d["severity"] == "info"
        assert d["details"]["service"] == "http"

    def test_defaults(self):
        f = Finding(finding_type="port", value="80")
        assert f.severity == "info"
        assert f.confidence == 1.0
        assert f.details == {}


# ===================== ToolResult Tests =====================

class TestToolResult:
    def test_basic_creation(self):
        r = ToolResult(success=True, tool_name="nmap", target="10.0.0.1")
        assert r.success is True
        assert r.findings == []
        assert r.flags_found == []

    def test_add_finding(self):
        r = ToolResult(success=True)
        r.add_finding("port", "80", severity="info", service="http")
        assert len(r.findings) == 1
        assert r.findings[0].finding_type == "port"
        assert r.findings[0].details == {"service": "http"}

    def test_add_finding_flag_type(self):
        r = ToolResult(success=True)
        r.add_finding("flag", "flag{test123}")
        assert "flag{test123}" in r.flags_found

    def test_add_finding_auto_detects_flag(self):
        r = ToolResult(success=True)
        r.add_finding("vulnerability", "Found flag{hidden_value} in response")
        assert "flag{hidden_value}" in r.flags_found

    def test_no_duplicate_flags(self):
        r = ToolResult(success=True)
        r.add_finding("flag", "flag{dup}")
        r.add_finding("flag", "flag{dup}")
        assert r.flags_found.count("flag{dup}") == 1


# ===================== Flag Detection Tests =====================

class TestFlagDetection:
    def test_is_flag_lowercase(self):
        r = ToolResult(success=True)
        assert r._is_flag("flag{test}") is True

    def test_is_flag_uppercase(self):
        r = ToolResult(success=True)
        assert r._is_flag("FLAG{TEST}") is True

    def test_is_flag_ctf(self):
        r = ToolResult(success=True)
        assert r._is_flag("CTF{example}") is True

    def test_is_flag_dasctf(self):
        r = ToolResult(success=True)
        assert r._is_flag("DASCTF{value}") is True

    def test_is_flag_md5(self):
        r = ToolResult(success=True)
        assert r._is_flag("a" * 32) is True

    def test_is_flag_sha1(self):
        r = ToolResult(success=True)
        assert r._is_flag("b" * 40) is True

    def test_is_flag_sha256(self):
        r = ToolResult(success=True)
        assert r._is_flag("c" * 64) is True

    def test_not_flag(self):
        r = ToolResult(success=True)
        assert r._is_flag("normal text") is False

    def test_extract_flags(self):
        r = ToolResult(success=True)
        text = "Output: flag{secret1} and also FLAG{SECRET2}"
        flags = r.extract_flags(text)
        assert "flag{secret1}" in flags
        assert "FLAG{SECRET2}" in flags

    def test_extract_no_flags(self):
        r = ToolResult(success=True)
        assert r.extract_flags("no flags here") == []


# ===================== Result Filtering Tests =====================

class TestResultFiltering:
    def test_get_ports(self):
        r = ToolResult(success=True)
        r.add_finding("port", "80")
        r.add_finding("port", "443")
        r.add_finding("service", "http")
        assert r.get_ports() == ["80", "443"]

    def test_get_services(self):
        r = ToolResult(success=True)
        r.add_finding("service", "http", severity="info")
        r.add_finding("port", "80")
        services = r.get_services()
        assert len(services) == 1
        assert services[0]["type"] == "service"

    def test_get_vulnerabilities(self):
        r = ToolResult(success=True)
        r.add_finding("vulnerability", "SQL Injection", severity="critical")
        r.add_finding("port", "80")
        vulns = r.get_vulnerabilities()
        assert len(vulns) == 1
        assert vulns[0]["severity"] == "critical"


# ===================== Serialization Tests =====================

class TestSerialization:
    def test_to_dict(self):
        r = ToolResult(success=True, tool_name="nmap", target="t")
        r.add_finding("port", "80")
        d = r.to_dict()
        assert d["success"] is True
        assert d["tool"] == "nmap"
        assert d["findings_count"] == 1
        assert d["error"] is None

    def test_to_dict_with_error(self):
        r = ToolResult(success=False, error_message="timeout")
        d = r.to_dict()
        assert d["error"] == "timeout"

    def test_to_mcp_response(self):
        r = ToolResult(success=True, raw_output="long output")
        resp = r.to_mcp_response()
        assert "raw_output" in resp

    def test_str_success(self):
        r = ToolResult(success=True, tool_name="nmap", summary="Done")
        assert "nmap" in str(r)

    def test_str_failure(self):
        r = ToolResult(success=False, tool_name="nmap", summary="Failed")
        assert "nmap" in str(r)


# ===================== Suggest Next Step Tests =====================

class TestSuggestNextStep:
    def test_suggest(self):
        r = ToolResult(success=True)
        r.suggest_next_step("Run gobuster", tool="gobuster_scan")
        assert "Run gobuster" in r.next_steps
        assert "gobuster_scan" in r.recommended_tools


# ===================== Enum Tests =====================

class TestEnums:
    def test_tool_category(self):
        assert ToolCategory.NETWORK.value == "network"
        assert ToolCategory.WEB.value == "web"

    def test_risk_level(self):
        assert RiskLevel.INFO.value == "info"
        assert RiskLevel.CRITICAL.value == "critical"
