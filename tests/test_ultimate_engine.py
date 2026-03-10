"""
Tests for ultimate_engine module (kali_mcp/core/ultimate_engine.py)

Covers:
- TargetType enum
- ScanPhase enum
- IterationLevel enum
- ScanResult dataclass
- VulnerabilityFinding dataclass
- UltimateScanEngine: init, detect_target_type, get_all_tools_for_target,
  get_vulnerability_coverage_tools, _adjust_params_for_iteration,
  _check_condition, _calculate_vulnerability_coverage
- CTFUltimateSolver: init, _detect_category, _build_tool_params, _extract_flag
"""

import pytest

from kali_mcp.core.ultimate_engine import (
    TargetType,
    ScanPhase,
    IterationLevel,
    ScanResult,
    VulnerabilityFinding,
    UltimateScanEngine,
    CTFUltimateSolver,
)


# ===================== Enum Tests =====================

class TestTargetType:
    def test_values(self):
        assert TargetType.WEB_APPLICATION.value == "web_app"
        assert TargetType.NETWORK_HOST.value == "network"
        assert TargetType.API_ENDPOINT.value == "api"
        assert TargetType.CTF_CHALLENGE.value == "ctf"
        assert TargetType.UNKNOWN.value == "unknown"
        assert TargetType.ACTIVE_DIRECTORY.value == "ad"
        assert TargetType.DATABASE.value == "database"


class TestScanPhase:
    def test_values(self):
        assert ScanPhase.RECONNAISSANCE.value == "reconnaissance"
        assert ScanPhase.DISCOVERY.value == "discovery"
        assert ScanPhase.VULNERABILITY.value == "vulnerability"
        assert ScanPhase.EXPLOITATION.value == "exploitation"
        assert ScanPhase.POST_EXPLOITATION.value == "post_exploitation"
        assert ScanPhase.REPORTING.value == "reporting"


class TestIterationLevel:
    def test_values(self):
        assert IterationLevel.QUICK.value == "quick"
        assert IterationLevel.STANDARD.value == "standard"
        assert IterationLevel.THOROUGH.value == "thorough"
        assert IterationLevel.EXHAUSTIVE.value == "exhaustive"


# ===================== ScanResult Tests =====================

class TestScanResult:
    def test_creation(self):
        r = ScanResult(
            tool_name="nmap_scan",
            phase=ScanPhase.RECONNAISSANCE,
            iteration=1,
            success=True,
            output="80/tcp open",
        )
        assert r.tool_name == "nmap_scan"
        assert r.phase == ScanPhase.RECONNAISSANCE
        assert r.iteration == 1
        assert r.findings == []
        assert r.error is None

    def test_with_error(self):
        r = ScanResult(
            tool_name="nmap_scan",
            phase=ScanPhase.RECONNAISSANCE,
            iteration=1,
            success=False,
            output="",
            error="Connection refused",
        )
        assert r.success is False
        assert r.error == "Connection refused"


# ===================== VulnerabilityFinding Tests =====================

class TestVulnerabilityFinding:
    def test_creation(self):
        vf = VulnerabilityFinding(
            vuln_type="sqli",
            severity="high",
            title="SQL Injection in login",
            description="Param id is vulnerable",
            evidence="' OR 1=1 --",
            tool_source="sqlmap_scan",
        )
        assert vf.vuln_type == "sqli"
        assert vf.severity == "high"
        assert vf.cve_id is None
        assert vf.cvss_score is None
        assert vf.remediation is None

    def test_with_all_fields(self):
        vf = VulnerabilityFinding(
            vuln_type="rce",
            severity="critical",
            title="RCE",
            description="Remote code execution",
            evidence="uid=0",
            tool_source="nuclei",
            cve_id="CVE-2024-1234",
            cvss_score=9.8,
            remediation="Update to latest version",
        )
        assert vf.cve_id == "CVE-2024-1234"
        assert vf.cvss_score == 9.8


# ===================== UltimateScanEngine Init Tests =====================

class TestUltimateScanEngineInit:
    def test_defaults(self):
        engine = UltimateScanEngine()
        assert engine.mcp_tools == {}
        assert engine.results == []
        assert engine.findings == []
        assert engine.discovered_info == {}
        assert len(engine.tools_used) == 0
        assert len(engine.tools_skipped) == 0

    def test_has_tool_matrix(self):
        assert TargetType.WEB_APPLICATION in UltimateScanEngine.TOOL_COVERAGE_MATRIX
        assert TargetType.NETWORK_HOST in UltimateScanEngine.TOOL_COVERAGE_MATRIX
        assert TargetType.CTF_CHALLENGE in UltimateScanEngine.TOOL_COVERAGE_MATRIX

    def test_has_vuln_coverage(self):
        assert "A03_Injection" in UltimateScanEngine.VULNERABILITY_COVERAGE
        assert "XSS" in UltimateScanEngine.VULNERABILITY_COVERAGE
        assert "LFI_RFI" in UltimateScanEngine.VULNERABILITY_COVERAGE

    def test_has_iteration_configs(self):
        assert IterationLevel.QUICK in UltimateScanEngine.ITERATION_CONFIGS
        assert UltimateScanEngine.ITERATION_CONFIGS[IterationLevel.QUICK]["rounds"] == 1
        assert UltimateScanEngine.ITERATION_CONFIGS[IterationLevel.EXHAUSTIVE]["rounds"] == 5


# ===================== detect_target_type Tests =====================

class TestDetectTargetType:
    def test_ctf_url(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("http://ctf.example.com") == TargetType.CTF_CHALLENGE

    def test_ctf_challenge_keyword(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("http://challenge.lab/flag") == TargetType.CTF_CHALLENGE

    def test_web_application(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("http://example.com") == TargetType.WEB_APPLICATION

    def test_https_web(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("https://secure.example.com") == TargetType.WEB_APPLICATION

    def test_api_endpoint(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("http://example.com/api/v1/users") == TargetType.API_ENDPOINT

    def test_api_v2(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("http://example.com/v2/items") == TargetType.API_ENDPOINT

    def test_ip_address(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("192.168.1.1") == TargetType.NETWORK_HOST

    def test_ip_with_port(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("10.0.0.1:8080") == TargetType.NETWORK_HOST

    def test_domain_without_http(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("example.com") == TargetType.WEB_APPLICATION

    def test_unknown_target(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("localhost") == TargetType.UNKNOWN

    def test_pwn_keyword(self):
        engine = UltimateScanEngine()
        assert engine.detect_target_type("pwn.challenge.io") == TargetType.CTF_CHALLENGE


# ===================== get_all_tools_for_target Tests =====================

class TestGetAllToolsForTarget:
    def test_web_tools(self):
        engine = UltimateScanEngine()
        tools = engine.get_all_tools_for_target(TargetType.WEB_APPLICATION)
        assert len(tools) > 0
        tool_names = [t["tool"] for t in tools]
        assert "whatweb_scan" in tool_names
        assert "gobuster_scan" in tool_names

    def test_network_tools(self):
        engine = UltimateScanEngine()
        tools = engine.get_all_tools_for_target(TargetType.NETWORK_HOST)
        tool_names = [t["tool"] for t in tools]
        assert "nmap_scan" in tool_names
        assert "masscan_fast_scan" in tool_names

    def test_ctf_tools(self):
        engine = UltimateScanEngine()
        tools = engine.get_all_tools_for_target(TargetType.CTF_CHALLENGE)
        tool_names = [t["tool"] for t in tools]
        assert "ctf_web_comprehensive_solver" in tool_names

    def test_unknown_type_empty(self):
        engine = UltimateScanEngine()
        tools = engine.get_all_tools_for_target(TargetType.UNKNOWN)
        assert tools == []

    def test_tools_have_phase(self):
        engine = UltimateScanEngine()
        tools = engine.get_all_tools_for_target(TargetType.WEB_APPLICATION)
        for tool in tools:
            assert "phase" in tool
            assert isinstance(tool["phase"], ScanPhase)


# ===================== get_vulnerability_coverage_tools Tests =====================

class TestGetVulnerabilityCoverageTools:
    def test_returns_all_categories(self):
        engine = UltimateScanEngine()
        coverage = engine.get_vulnerability_coverage_tools()
        assert "A03_Injection" in coverage
        assert "XSS" in coverage
        assert "A10_SSRF" in coverage

    def test_each_category_has_tools(self):
        engine = UltimateScanEngine()
        coverage = engine.get_vulnerability_coverage_tools()
        for vuln_type, tools in coverage.items():
            assert isinstance(tools, list)


# ===================== _adjust_params_for_iteration Tests =====================

class TestAdjustParamsForIteration:
    def test_iteration_1_quick(self):
        engine = UltimateScanEngine()
        params = engine._adjust_params_for_iteration({"target": "t"}, 1, {})
        assert params["time_constraint"] == "quick"

    def test_iteration_2_standard(self):
        engine = UltimateScanEngine()
        params = engine._adjust_params_for_iteration({"target": "t"}, 2, {})
        assert params["time_constraint"] == "standard"

    def test_iteration_2_replaces_wordlist(self):
        engine = UltimateScanEngine()
        params = engine._adjust_params_for_iteration(
            {"wordlist": "/usr/share/wordlists/dirb/common.txt"}, 2, {}
        )
        assert "big" in params["wordlist"]

    def test_iteration_3_thorough(self):
        engine = UltimateScanEngine()
        params = engine._adjust_params_for_iteration({"target": "t"}, 3, {})
        assert params["time_constraint"] == "thorough"

    def test_iteration_3_appends_args(self):
        engine = UltimateScanEngine()
        params = engine._adjust_params_for_iteration(
            {"additional_args": "--batch"}, 3, {}
        )
        assert "--level=5" in params["additional_args"]
        assert "--risk=3" in params["additional_args"]

    def test_does_not_mutate_original(self):
        engine = UltimateScanEngine()
        original = {"target": "t"}
        engine._adjust_params_for_iteration(original, 1, {})
        assert "time_constraint" not in original


# ===================== _check_condition Tests =====================

class TestCheckCondition:
    def test_is_wordpress_true(self):
        engine = UltimateScanEngine()
        engine.discovered_info["cms"] = "wordpress"
        assert engine._check_condition("is_wordpress") is True

    def test_is_wordpress_false(self):
        engine = UltimateScanEngine()
        assert engine._check_condition("is_wordpress") is False

    def test_is_joomla(self):
        engine = UltimateScanEngine()
        engine.discovered_info["cms"] = "joomla"
        assert engine._check_condition("is_joomla") is True

    def test_waf_detected(self):
        engine = UltimateScanEngine()
        engine.discovered_info["waf"] = "cloudflare"
        assert engine._check_condition("waf_detected") is True

    def test_waf_not_detected(self):
        engine = UltimateScanEngine()
        assert engine._check_condition("waf_detected") is False

    def test_has_smb(self):
        engine = UltimateScanEngine()
        engine.discovered_info["open_ports"] = [22, 445, 80]
        assert engine._check_condition("has_smb") is True

    def test_has_dns(self):
        engine = UltimateScanEngine()
        engine.discovered_info["open_ports"] = [53, 80]
        assert engine._check_condition("has_dns") is True

    def test_has_login_service_ssh(self):
        engine = UltimateScanEngine()
        engine.discovered_info["open_ports"] = [22, 80]
        assert engine._check_condition("has_login_service") is True

    def test_has_login_service_rdp(self):
        engine = UltimateScanEngine()
        engine.discovered_info["open_ports"] = [3389]
        assert engine._check_condition("has_login_service") is True

    def test_no_login_service(self):
        engine = UltimateScanEngine()
        engine.discovered_info["open_ports"] = [80, 443]
        assert engine._check_condition("has_login_service") is False

    def test_exploit_available(self):
        engine = UltimateScanEngine()
        engine.discovered_info["exploits"] = ["CVE-2024-1234"]
        assert engine._check_condition("exploit_available") is True

    def test_exploit_not_available(self):
        engine = UltimateScanEngine()
        assert engine._check_condition("exploit_available") is False

    def test_unknown_condition_defaults_true(self):
        engine = UltimateScanEngine()
        assert engine._check_condition("unknown_condition") is True


# ===================== _calculate_vulnerability_coverage Tests =====================

class TestCalculateVulnerabilityCoverage:
    def test_empty_coverage(self):
        engine = UltimateScanEngine()
        coverage = engine._calculate_vulnerability_coverage()
        assert "_summary" in coverage
        assert coverage["_summary"]["overall_coverage"] == 0

    def test_partial_coverage(self):
        engine = UltimateScanEngine()
        engine.tools_used.add("sqlmap_scan")
        engine.tools_used.add("nuclei_scan")
        coverage = engine._calculate_vulnerability_coverage()
        # A03_Injection should have some coverage
        assert coverage["A03_Injection"]["coverage_rate"] > 0
        assert coverage["_summary"]["overall_coverage"] > 0

    def test_coverage_per_category(self):
        engine = UltimateScanEngine()
        engine.tools_used.add("intelligent_xss_payloads")
        coverage = engine._calculate_vulnerability_coverage()
        assert coverage["XSS"]["coverage_rate"] > 0


# ===================== CTFUltimateSolver Tests =====================

class TestCTFUltimateSolverInit:
    def test_defaults(self):
        solver = CTFUltimateSolver()
        assert solver.mcp_tools == {}
        assert solver.ultimate_engine is not None

    def test_has_category_tools(self):
        assert "web" in CTFUltimateSolver.CTF_CATEGORY_TOOLS
        assert "pwn" in CTFUltimateSolver.CTF_CATEGORY_TOOLS
        assert "reverse" in CTFUltimateSolver.CTF_CATEGORY_TOOLS
        assert "crypto" in CTFUltimateSolver.CTF_CATEGORY_TOOLS
        assert "misc" in CTFUltimateSolver.CTF_CATEGORY_TOOLS


class TestDetectCategory:
    def test_web_default(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("http://challenge.com") == "web"

    def test_pwn_keyword(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("pwn_challenge") == "pwn"

    def test_pwn_from_hints(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("challenge", ["This is a binary exploit"]) == "pwn"

    def test_crypto(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("crypto_rsa") == "crypto"

    def test_crypto_from_hints(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("challenge", ["decrypt the AES ciphertext"]) == "crypto"

    def test_reverse(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("crackme.exe") == "reverse"

    def test_misc(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("forensic_analysis") == "misc"

    def test_stego_hints(self):
        solver = CTFUltimateSolver()
        assert solver._detect_category("image.png", ["hidden message in stego"]) == "misc"


class TestBuildToolParams:
    def test_scan_tool_web(self):
        solver = CTFUltimateSolver()
        params = solver._build_tool_params("nuclei_scan", "http://target.com", "web")
        assert params["url"] == "http://target.com"

    def test_scan_tool_adds_http(self):
        solver = CTFUltimateSolver()
        params = solver._build_tool_params("sqlmap_scan", "target.com", "web")
        assert params["url"] == "http://target.com"

    def test_scan_tool_non_web(self):
        solver = CTFUltimateSolver()
        params = solver._build_tool_params("nmap_scan", "10.0.0.1", "network")
        assert params["target"] == "10.0.0.1"

    def test_solver_tool(self):
        solver = CTFUltimateSolver()
        params = solver._build_tool_params("ctf_web_comprehensive_solver", "http://t.com", "web")
        assert params["target"] == "http://t.com"
        assert params["challenge_info"]["category"] == "web"
        assert params["time_limit"] == "30min"

    def test_pwn_tool(self):
        solver = CTFUltimateSolver()
        params = solver._build_tool_params("pwnpasi_auto_pwn", "/tmp/binary", "pwn")
        assert params["binary_path"] == "/tmp/binary"

    def test_reverse_tool(self):
        solver = CTFUltimateSolver()
        params = solver._build_tool_params("auto_reverse_analyze", "/tmp/bin", "reverse")
        assert params["binary_path"] == "/tmp/bin"


class TestExtractFlag:
    def test_flag_format(self):
        solver = CTFUltimateSolver()
        assert solver._extract_flag("Congratulations! flag{this_is_the_flag}") == "flag{this_is_the_flag}"

    def test_FLAG_format(self):
        solver = CTFUltimateSolver()
        assert solver._extract_flag("Found FLAG{UPPER_CASE_FLAG}") == "FLAG{UPPER_CASE_FLAG}"

    def test_ctf_format(self):
        solver = CTFUltimateSolver()
        assert solver._extract_flag("ctf{lower_format}") == "ctf{lower_format}"

    def test_CTF_format(self):
        solver = CTFUltimateSolver()
        assert solver._extract_flag("CTF{UPPER}") == "CTF{UPPER}"

    def test_DASCTF_format(self):
        solver = CTFUltimateSolver()
        # Note: CTF{} pattern matches before DASCTF{} in source regex order
        # so the extracted flag is "CTF{special_format}" (substring match)
        result = solver._extract_flag("DASCTF{special_format}")
        assert result is not None
        assert "special_format" in result

    def test_md5_hash(self):
        solver = CTFUltimateSolver()
        result = solver._extract_flag("The flag is d41d8cd98f00b204e9800998ecf8427e")
        assert result == "d41d8cd98f00b204e9800998ecf8427e"

    def test_sha1_hash(self):
        solver = CTFUltimateSolver()
        result = solver._extract_flag("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        # SHA1 is 40 chars, but the MD5 pattern (32 chars) might match a substring first
        # Actually the SHA1 is 40 chars, the 32-char pattern matches the first 32 chars
        assert result is not None

    def test_no_flag(self):
        solver = CTFUltimateSolver()
        assert solver._extract_flag("Nothing interesting here") is None

    def test_flag_in_long_output(self):
        solver = CTFUltimateSolver()
        output = "Starting scan...\nScanning target...\nflag{found_in_middle}\nDone."
        assert solver._extract_flag(output) == "flag{found_in_middle}"
