"""
Tests for ResultParser (kali_mcp/core/result_parser.py)

Covers:
- NmapParser: open ports, services, OS detection, properties
- GobusterParser: paths, status codes, categorized paths
- NucleiParser: findings, severities, CVE extraction
- WhatwebParser: technologies, CMS, server, language
- SqlmapParser: injection detection, DBMS, parameters
- WafParser: WAF detection and identification
- SmartParamsBuilder: parameter construction from parsed results
- auto_parse: automatic tool-to-parser routing
"""

import pytest

from kali_mcp.core.result_parser import (
    ResultParser, SmartParamsBuilder,
    NmapResult, GobusterResult, NucleiResult,
    SqlmapResult, WhatwebResult, WafResult,
    PortInfo, PathInfo, VulnFinding, TechInfo,
)


class TestParseNmap:
    """Test nmap output parsing."""

    def test_parse_nmap_open_ports(self, nmap_output_with_ports):
        """Parse nmap output and extract open ports."""
        result = ResultParser.parse_nmap(nmap_output_with_ports, "192.168.1.100")

        assert isinstance(result, NmapResult)
        assert result.target == "192.168.1.100"
        assert result.is_up is True
        assert 22 in result.open_ports
        assert 80 in result.open_ports
        assert 443 in result.open_ports
        assert 3306 in result.open_ports

    def test_parse_nmap_service_names(self, nmap_output_with_ports):
        """Services are correctly extracted."""
        result = ResultParser.parse_nmap(nmap_output_with_ports)

        services = {p.service for p in result.ports}
        assert "ssh" in services
        assert "http" in services
        assert "mysql" in services

    def test_parse_nmap_has_web_service(self, nmap_output_with_ports):
        """has_web_service property detects HTTP ports."""
        result = ResultParser.parse_nmap(nmap_output_with_ports)

        assert result.has_web_service is True

    def test_parse_nmap_has_database(self, nmap_output_with_ports):
        """has_database property detects MySQL port."""
        result = ResultParser.parse_nmap(nmap_output_with_ports)

        assert result.has_database is True

    def test_parse_nmap_has_ssh(self, nmap_output_with_ports):
        """has_ssh property detects SSH service."""
        result = ResultParser.parse_nmap(nmap_output_with_ports)

        assert result.has_ssh is True

    def test_parse_nmap_os_guess(self, nmap_output_with_ports):
        """OS guess is extracted."""
        result = ResultParser.parse_nmap(nmap_output_with_ports)

        assert "Linux" in result.os_guess

    def test_parse_nmap_hostname(self, nmap_output_with_ports):
        """Hostname is extracted from scan report line."""
        result = ResultParser.parse_nmap(nmap_output_with_ports)

        assert result.hostname == "192.168.1.100"

    def test_parse_nmap_ssl_service_rename(self):
        """ssl/http is converted to https."""
        output = "443/tcp  open  ssl/http    nginx 1.18.0"
        result = ResultParser.parse_nmap(output)

        assert len(result.ports) == 1
        assert result.ports[0].service == "https"

    def test_parse_nmap_no_ports(self, nmap_output_empty):
        """Parse nmap output with no open ports."""
        result = ResultParser.parse_nmap(nmap_output_empty)

        assert result.open_ports == []
        assert result.is_up is False

    def test_parse_nmap_empty_string(self):
        """Empty input returns empty NmapResult."""
        result = ResultParser.parse_nmap("")

        assert isinstance(result, NmapResult)
        assert result.open_ports == []

    def test_parse_nmap_web_urls(self, nmap_output_with_ports):
        """web_urls property constructs correct URLs."""
        result = ResultParser.parse_nmap(nmap_output_with_ports, "192.168.1.100")

        urls = result.web_urls
        assert len(urls) >= 1
        assert any("http://" in u for u in urls)

    def test_parse_nmap_http_ports(self, nmap_output_with_ports):
        """http_ports property returns only HTTP service ports."""
        result = ResultParser.parse_nmap(nmap_output_with_ports)

        http_ports = result.http_ports
        assert 80 in http_ports
        assert 22 not in http_ports
        assert 3306 not in http_ports

    def test_parse_nmap_version_extraction(self):
        """Version is extracted from service line."""
        output = "22/tcp   open  ssh     OpenSSH 8.2p1"
        result = ResultParser.parse_nmap(output)

        assert result.ports[0].version == "8.2p1"


class TestParseGobuster:
    """Test gobuster output parsing."""

    def test_parse_gobuster_paths(self, gobuster_output):
        """Parse gobuster output and extract paths."""
        result = ResultParser.parse_gobuster(gobuster_output, "http://target.com")

        assert isinstance(result, GobusterResult)
        assert len(result.paths) >= 5
        path_names = [p.path for p in result.paths]
        assert "/admin" in path_names
        assert "/login" in path_names
        assert "/api/v1" in path_names

    def test_parse_gobuster_status_codes(self, gobuster_output):
        """Status codes are correctly parsed."""
        result = ResultParser.parse_gobuster(gobuster_output)

        admin_path = [p for p in result.paths if p.path == "/admin"][0]
        assert admin_path.status_code == 200
        assert admin_path.size == 1234

    def test_parse_gobuster_redirect(self, gobuster_output):
        """Redirect targets are extracted."""
        result = ResultParser.parse_gobuster(gobuster_output)

        login_path = [p for p in result.paths if p.path == "/login"][0]
        assert login_path.status_code == 302
        assert login_path.redirect == "/auth/login"

    def test_parse_gobuster_interesting_paths(self, gobuster_output):
        """interesting_paths filters out 403/404."""
        result = ResultParser.parse_gobuster(gobuster_output)

        interesting = result.interesting_paths
        assert "/admin" in interesting
        assert "/static" not in interesting  # 403

    def test_parse_gobuster_admin_paths(self, gobuster_output):
        """admin_paths detects admin-related paths."""
        result = ResultParser.parse_gobuster(gobuster_output)

        assert "/admin" in result.admin_paths

    def test_parse_gobuster_api_paths(self, gobuster_output):
        """api_paths detects API-related paths."""
        result = ResultParser.parse_gobuster(gobuster_output)

        assert "/api/v1" in result.api_paths

    def test_parse_gobuster_upload_paths(self, gobuster_output):
        """upload_paths detects upload-related paths."""
        result = ResultParser.parse_gobuster(gobuster_output)

        assert "/upload" in result.upload_paths

    def test_parse_gobuster_login_paths(self, gobuster_output):
        """login_paths detects login-related paths."""
        result = ResultParser.parse_gobuster(gobuster_output)

        assert "/login" in result.login_paths

    def test_parse_gobuster_empty(self):
        """Empty input returns empty GobusterResult."""
        result = ResultParser.parse_gobuster("")

        assert isinstance(result, GobusterResult)
        assert result.paths == []


class TestParseNuclei:
    """Test nuclei output parsing."""

    def test_parse_nuclei_findings(self, nuclei_output):
        """Parse nuclei output and extract findings."""
        result = ResultParser.parse_nuclei(nuclei_output, "192.168.1.100")

        assert isinstance(result, NucleiResult)
        assert len(result.findings) >= 3

    def test_parse_nuclei_severities(self, nuclei_output):
        """Severity levels are correctly extracted."""
        result = ResultParser.parse_nuclei(nuclei_output)

        severities = {f.severity for f in result.findings}
        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities

    def test_parse_nuclei_cve_extraction(self, nuclei_output):
        """CVE IDs are extracted from template names."""
        result = ResultParser.parse_nuclei(nuclei_output)

        cve_list = result.cve_list
        assert "CVE-2021-44228" in cve_list

    def test_parse_nuclei_critical_findings(self, nuclei_output):
        """critical_findings property filters correctly."""
        result = ResultParser.parse_nuclei(nuclei_output)

        assert len(result.critical_findings) == 1
        assert result.has_critical is True

    def test_parse_nuclei_high_findings(self, nuclei_output):
        """high_findings property filters correctly."""
        result = ResultParser.parse_nuclei(nuclei_output)

        assert len(result.high_findings) == 1

    def test_parse_nuclei_empty(self):
        """Empty input returns empty NucleiResult."""
        result = ResultParser.parse_nuclei("")

        assert isinstance(result, NucleiResult)
        assert result.findings == []
        assert result.has_critical is False

    def test_parse_nuclei_json_format(self):
        """JSON format nuclei output is also parsed."""
        import json
        json_line = json.dumps({
            "template-id": "CVE-2023-1234",
            "info": {
                "name": "Test Vuln",
                "severity": "high",
                "classification": {"cve-id": "CVE-2023-1234"},
            },
            "matched-at": "http://target.com/path",
        })

        result = ResultParser.parse_nuclei(json_line)

        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"
        assert result.findings[0].name == "Test Vuln"


class TestParseWhatweb:
    """Test whatweb output parsing."""

    def test_parse_whatweb_technologies(self, whatweb_output):
        """Parse whatweb output and extract technologies."""
        result = ResultParser.parse_whatweb(whatweb_output, "http://192.168.1.100")

        assert isinstance(result, WhatwebResult)
        assert len(result.technologies) > 0

    def test_parse_whatweb_server(self, whatweb_output):
        """Server is identified."""
        result = ResultParser.parse_whatweb(whatweb_output)

        assert "Apache" in result.server

    def test_parse_whatweb_language(self, whatweb_output):
        """Language is identified."""
        result = ResultParser.parse_whatweb(whatweb_output)

        assert result.language == "PHP"

    def test_parse_whatweb_cms(self, whatweb_output):
        """CMS is identified."""
        result = ResultParser.parse_whatweb(whatweb_output)

        assert result.cms == "WordPress"

    def test_parse_whatweb_is_wordpress(self, whatweb_output):
        """is_wordpress property works."""
        result = ResultParser.parse_whatweb(whatweb_output)

        assert result.is_wordpress is True

    def test_parse_whatweb_is_php(self, whatweb_output):
        """is_php property works."""
        result = ResultParser.parse_whatweb(whatweb_output)

        assert result.is_php is True

    def test_parse_whatweb_empty(self):
        """Empty input returns empty WhatwebResult."""
        result = ResultParser.parse_whatweb("")

        assert isinstance(result, WhatwebResult)
        assert result.technologies == []


class TestParseSqlmap:
    """Test sqlmap output parsing."""

    def test_parse_sqlmap_vulnerable(self):
        """Detect SQL injection vulnerability."""
        output = """\
[INFO] the back-end DBMS is MySQL
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
[INFO] GET parameter 'id' is vulnerable
back-end DBMS: MySQL >= 5.0
"""
        result = ResultParser.parse_sqlmap(output, "http://target.com?id=1")

        assert result.is_vulnerable is True
        assert "MySQL" in result.dbms
        assert "boolean-based" in result.injection_type
        assert "id" in result.injectable_params

    def test_parse_sqlmap_databases(self):
        """Database names are extracted."""
        output = """\
available databases [3]:
[*] information_schema
[*] mysql
[*] webapp_db
"""
        result = ResultParser.parse_sqlmap(output)

        assert "information_schema" in result.databases
        assert "mysql" in result.databases
        assert "webapp_db" in result.databases

    def test_parse_sqlmap_not_vulnerable(self):
        """Non-vulnerable output."""
        output = "[WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable"
        result = ResultParser.parse_sqlmap(output)

        assert result.is_vulnerable is False

    def test_parse_sqlmap_empty(self):
        """Empty input returns empty SqlmapResult."""
        result = ResultParser.parse_sqlmap("")

        assert isinstance(result, SqlmapResult)
        assert result.is_vulnerable is False


class TestParseWafw00f:
    """Test WAF detection parsing."""

    def test_parse_waf_detected(self):
        """WAF detected in output."""
        output = "[*] The site http://target.com is behind Cloudflare (Cloudflare Inc.)"
        result = ResultParser.parse_wafw00f(output, "http://target.com")

        assert result.has_waf is True
        assert "Cloudflare" in result.waf_name

    def test_parse_no_waf(self):
        """No WAF detected."""
        output = "[*] No WAF detected by the generic detection"
        result = ResultParser.parse_wafw00f(output)

        assert result.has_waf is False

    def test_parse_waf_empty(self):
        """Empty input."""
        result = ResultParser.parse_wafw00f("")

        assert isinstance(result, WafResult)
        assert result.has_waf is False


class TestAutoParse:
    """Test auto_parse routing."""

    def test_auto_parse_nmap(self, nmap_output_with_ports):
        """auto_parse routes nmap output correctly."""
        result = ResultParser.auto_parse("nmap", nmap_output_with_ports, "192.168.1.100")
        assert isinstance(result, NmapResult)

    def test_auto_parse_gobuster(self, gobuster_output):
        """auto_parse routes gobuster output correctly."""
        result = ResultParser.auto_parse("gobuster", gobuster_output)
        assert isinstance(result, GobusterResult)

    def test_auto_parse_nuclei(self, nuclei_output):
        """auto_parse routes nuclei output correctly."""
        result = ResultParser.auto_parse("nuclei", nuclei_output)
        assert isinstance(result, NucleiResult)

    def test_auto_parse_unknown_tool(self):
        """Unknown tool returns None."""
        result = ResultParser.auto_parse("unknown_tool", "some output")
        assert result is None

    def test_auto_parse_aliases(self):
        """ffuf and dirb are aliases for gobuster parser."""
        output = "/test                (Status: 200) [Size: 100]"
        for tool in ["ffuf", "dirb", "feroxbuster"]:
            result = ResultParser.auto_parse(tool, output)
            assert isinstance(result, GobusterResult)


class TestSmartParamsBuilder:
    """Test SmartParamsBuilder parameter construction."""

    def test_build_gobuster_params_with_web_service(self):
        """Build gobuster params when web service is found."""
        nmap_result = NmapResult(target="192.168.1.100")
        nmap_result.ports = [
            PortInfo(port=80, state="open", service="http"),
        ]

        params = SmartParamsBuilder.build_gobuster_params(nmap_result, "192.168.1.100")

        assert params is not None
        assert "url" in params
        assert "http://" in params["url"]

    def test_build_gobuster_params_no_web(self):
        """No gobuster params when no web service."""
        nmap_result = NmapResult(target="192.168.1.100")
        nmap_result.ports = [
            PortInfo(port=22, state="open", service="ssh"),
        ]

        params = SmartParamsBuilder.build_gobuster_params(nmap_result, "192.168.1.100")

        assert params is None

    def test_build_nuclei_params(self):
        """Build nuclei params based on nmap results."""
        nmap_result = NmapResult(target="192.168.1.100")
        nmap_result.ports = [
            PortInfo(port=80, state="open", service="http", product="Apache"),
        ]

        params = SmartParamsBuilder.build_nuclei_params(nmap_result, "192.168.1.100")

        assert params is not None
        assert "target" in params
        assert "severity" in params

    def test_build_wpscan_params_wordpress(self):
        """Build wpscan params when WordPress is detected."""
        whatweb_result = WhatwebResult()
        whatweb_result.cms = "WordPress"

        params = SmartParamsBuilder.build_wpscan_params(whatweb_result, "http://target.com")

        assert params is not None
        assert params["target"] == "http://target.com"

    def test_build_wpscan_params_no_wordpress(self):
        """No wpscan params when no WordPress."""
        whatweb_result = WhatwebResult()
        whatweb_result.cms = "Joomla"

        params = SmartParamsBuilder.build_wpscan_params(whatweb_result, "http://target.com")

        assert params is None

    def test_choose_wordlist_default(self):
        """Default wordlist when no info available."""
        wordlist = SmartParamsBuilder.choose_wordlist()

        assert "common.txt" in wordlist

    def test_choose_wordlist_php(self):
        """PHP wordlist selection."""
        whatweb = WhatwebResult(language="PHP")
        wordlist = SmartParamsBuilder.choose_wordlist(whatweb)

        assert wordlist.endswith(".txt")
