"""
Tests for zero_day_vulns module (kali_mcp/vulnerabilities/zero_day_vulns.py)

Covers:
- get_vulnerabilities() return type, length, and element types
- VulnCategory: all entries are ZERO_DAY
- VulnSeverity: all entries are CRITICAL or HIGH
- VulnType: all vuln_types lists contain valid VulnType members
- Vulnerability dataclass fields for every entry:
    cve_id, name, category, publish_date, cvss_score, severity,
    affected_products, vuln_types, description, exploit_available,
    exploit_method, required_tools, affected_versions, references,
    tags, poc_available, patch_available, detection_methods, mitre_technique
- Per-entry field correctness for all 16 vulnerabilities
- Data integrity invariants:
    CVSS >= 7.0, unique CVE IDs, non-empty lists, date ranges,
    tag content, reference URL formats, detection method counts
- Vulnerability.to_dict() round-trip on zero-day entries
- Vulnerability.from_dict() round-trip on zero-day entries
- Vulnerability.matches_product() on zero-day entries
- Vulnerability.matches_version() on zero-day entries
- Edge cases: empty product match, partial product match, version matching
"""

import pytest
from datetime import date
from typing import List

from kali_mcp.vulnerabilities.zero_day_vulns import get_vulnerabilities
from kali_mcp.vulnerabilities.vuln_database import (
    Vulnerability,
    VulnCategory,
    VulnSeverity,
    VulnType,
)


# ===================== Fixture =====================


@pytest.fixture
def vulns() -> List[Vulnerability]:
    """Return the full list of zero-day vulnerabilities."""
    return get_vulnerabilities()


@pytest.fixture
def vuln_by_cve(vulns) -> dict:
    """Return a dict mapping CVE ID -> Vulnerability."""
    return {v.cve_id: v for v in vulns}


# ===================== get_vulnerabilities() basics =====================


class TestGetVulnerabilitiesBasics:
    def test_returns_list(self, vulns):
        assert isinstance(vulns, list)

    def test_returns_non_empty(self, vulns):
        assert len(vulns) > 0

    def test_returns_16_entries(self, vulns):
        assert len(vulns) == 16

    def test_all_elements_are_vulnerability_instances(self, vulns):
        for v in vulns:
            assert isinstance(v, Vulnerability)

    def test_returns_new_list_each_call(self):
        a = get_vulnerabilities()
        b = get_vulnerabilities()
        assert a is not b

    def test_entries_independent_between_calls(self):
        a = get_vulnerabilities()
        b = get_vulnerabilities()
        assert a[0] is not b[0]


# ===================== Cross-cutting invariants =====================


class TestCrossCuttingInvariants:
    def test_all_category_is_zero_day(self, vulns):
        for v in vulns:
            assert v.category == VulnCategory.ZERO_DAY, f"{v.cve_id} category != ZERO_DAY"

    def test_all_cvss_at_least_7(self, vulns):
        for v in vulns:
            assert v.cvss_score >= 7.0, f"{v.cve_id} CVSS {v.cvss_score} < 7.0"

    def test_all_cvss_at_most_10(self, vulns):
        for v in vulns:
            assert v.cvss_score <= 10.0, f"{v.cve_id} CVSS {v.cvss_score} > 10.0"

    def test_all_severity_critical_or_high(self, vulns):
        for v in vulns:
            assert v.severity in (VulnSeverity.CRITICAL, VulnSeverity.HIGH), (
                f"{v.cve_id} severity {v.severity} not CRITICAL or HIGH"
            )

    def test_all_cve_ids_unique(self, vulns):
        cve_ids = [v.cve_id for v in vulns]
        assert len(cve_ids) == len(set(cve_ids))

    def test_all_cve_ids_start_with_cve_prefix(self, vulns):
        for v in vulns:
            assert v.cve_id.startswith("CVE-"), f"{v.cve_id} doesn't start with CVE-"

    def test_all_cve_ids_match_year_format(self, vulns):
        for v in vulns:
            parts = v.cve_id.split("-")
            assert len(parts) == 3
            year = int(parts[1])
            assert 2024 <= year <= 2025, f"{v.cve_id} year {year} out of range"

    def test_all_names_non_empty(self, vulns):
        for v in vulns:
            assert len(v.name) > 0

    def test_all_descriptions_non_empty(self, vulns):
        for v in vulns:
            assert len(v.description) > 0

    def test_all_exploit_available_is_true(self, vulns):
        for v in vulns:
            assert v.exploit_available is True, f"{v.cve_id} exploit_available is False"

    def test_all_exploit_methods_non_empty(self, vulns):
        for v in vulns:
            assert v.exploit_method is not None
            assert len(v.exploit_method) > 0

    def test_all_affected_products_non_empty(self, vulns):
        for v in vulns:
            assert len(v.affected_products) > 0

    def test_all_vuln_types_non_empty(self, vulns):
        for v in vulns:
            assert len(v.vuln_types) > 0

    def test_all_vuln_types_are_valid_enum(self, vulns):
        for v in vulns:
            for vt in v.vuln_types:
                assert isinstance(vt, VulnType)

    def test_all_required_tools_non_empty(self, vulns):
        for v in vulns:
            assert len(v.required_tools) > 0

    def test_all_affected_versions_non_empty(self, vulns):
        for v in vulns:
            assert len(v.affected_versions) > 0

    def test_all_references_non_empty(self, vulns):
        for v in vulns:
            assert len(v.references) > 0

    def test_all_references_are_urls(self, vulns):
        for v in vulns:
            for ref in v.references:
                assert ref.startswith("http://") or ref.startswith("https://"), (
                    f"{v.cve_id} reference '{ref}' is not a URL"
                )

    def test_all_tags_non_empty(self, vulns):
        for v in vulns:
            assert len(v.tags) > 0

    def test_all_tags_contain_0day(self, vulns):
        for v in vulns:
            assert "0day" in v.tags, f"{v.cve_id} tags don't contain '0day'"

    def test_all_poc_available_is_true(self, vulns):
        for v in vulns:
            assert v.poc_available is True

    def test_all_detection_methods_non_empty(self, vulns):
        for v in vulns:
            assert len(v.detection_methods) >= 3, (
                f"{v.cve_id} has fewer than 3 detection methods"
            )

    def test_all_mitre_techniques_non_empty(self, vulns):
        for v in vulns:
            assert v.mitre_technique is not None
            assert len(v.mitre_technique) > 0

    def test_all_mitre_techniques_start_with_t(self, vulns):
        for v in vulns:
            assert v.mitre_technique.startswith("T"), (
                f"{v.cve_id} MITRE technique '{v.mitre_technique}' doesn't start with T"
            )

    def test_all_publish_dates_in_2024(self, vulns):
        for v in vulns:
            assert v.publish_date.year == 2024, (
                f"{v.cve_id} publish_date year {v.publish_date.year} != 2024"
            )

    def test_all_publish_dates_not_in_future(self, vulns):
        for v in vulns:
            assert v.publish_date <= date.today(), f"{v.cve_id} publish_date is in the future"


# ===================== Per-entry CVE ID correctness =====================


class TestSpecificCVEIds:
    EXPECTED_CVES = [
        "CVE-2024-3400",
        "CVE-2024-3094",
        "CVE-2024-23897",
        "CVE-2024-25600",
        "CVE-2024-21762",
        "CVE-2024-24573",
        "CVE-2024-27983",
        "CVE-2024-0204",
        "CVE-2024-21887",
        "CVE-2024-28121",
        "CVE-2024-27456",
        "CVE-2024-22024",
        "CVE-2024-22274",
        "CVE-2024-2924",
        "CVE-2024-28755",
        "CVE-2024-31650",
    ]

    def test_all_expected_cves_present(self, vulns):
        actual = {v.cve_id for v in vulns}
        for cve in self.EXPECTED_CVES:
            assert cve in actual, f"Missing expected CVE: {cve}"

    def test_no_unexpected_cves(self, vulns):
        expected = set(self.EXPECTED_CVES)
        actual = {v.cve_id for v in vulns}
        assert actual == expected


# ===================== Per-entry detailed tests =====================


class TestCVE_2024_3400:
    def test_name(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3400"]
        assert v.name == "Palo Alto GlobalProtect RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3400"].cvss_score == 9.1

    def test_severity(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3400"].severity == VulnSeverity.CRITICAL

    def test_publish_date(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3400"].publish_date == date(2024, 4, 14)

    def test_affected_products(self, vuln_by_cve):
        prods = vuln_by_cve["CVE-2024-3400"].affected_products
        assert "Palo Alto GlobalProtect" in prods
        assert "Palo Alto Networks Firewall" in prods

    def test_vuln_types(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-3400"].vuln_types
        assert VulnType.RCE in vt
        assert VulnType.AUTHENTICATION_BYPASS in vt

    def test_required_tools(self, vuln_by_cve):
        tools = vuln_by_cve["CVE-2024-3400"].required_tools
        assert "curl" in tools
        assert "python3" in tools
        assert "nmap" in tools

    def test_patch_not_available(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3400"].patch_available is False

    def test_tags(self, vuln_by_cve):
        tags = vuln_by_cve["CVE-2024-3400"].tags
        assert "vpn" in tags
        assert "rce" in tags
        assert "critical" in tags


class TestCVE_2024_3094:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3094"].name == "XZ Utils Backdoor"

    def test_cvss_perfect_10(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3094"].cvss_score == 10.0

    def test_publish_date(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3094"].publish_date == date(2024, 3, 29)

    def test_affected_products_includes_linux(self, vuln_by_cve):
        prods = vuln_by_cve["CVE-2024-3094"].affected_products
        assert any("Linux" in p for p in prods)

    def test_vuln_types_include_priv_esc(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-3094"].vuln_types
        assert VulnType.PRIVILEGE_ESCALATION in vt

    def test_tags_include_supply_chain(self, vuln_by_cve):
        tags = vuln_by_cve["CVE-2024-3094"].tags
        assert "supply-chain" in tags
        assert "backdoor" in tags

    def test_patch_available(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3094"].patch_available is True

    def test_affected_versions(self, vuln_by_cve):
        versions = vuln_by_cve["CVE-2024-3094"].affected_versions
        assert "XZ Utils 5.6.0" in versions
        assert "XZ Utils 5.6.1" in versions

    def test_required_tools_include_ssh(self, vuln_by_cve):
        assert "ssh" in vuln_by_cve["CVE-2024-3094"].required_tools


class TestCVE_2024_23897:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-23897"].name == "Atlassian Bitbucket RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-23897"].cvss_score == 9.1

    def test_affected_products_count(self, vuln_by_cve):
        assert len(vuln_by_cve["CVE-2024-23897"].affected_products) == 3

    def test_required_tools(self, vuln_by_cve):
        tools = vuln_by_cve["CVE-2024-23897"].required_tools
        assert "burpsuite" in tools


class TestCVE_2024_25600:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-25600"].name == "ChainWiki PHP RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-25600"].cvss_score == 9.8

    def test_vuln_types_include_file_inclusion(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-25600"].vuln_types
        assert VulnType.FILE_INCLUSION in vt

    def test_patch_not_available(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-25600"].patch_available is False

    def test_tags_include_php(self, vuln_by_cve):
        assert "php" in vuln_by_cve["CVE-2024-25600"].tags

    def test_tags_include_file_upload(self, vuln_by_cve):
        assert "file-upload" in vuln_by_cve["CVE-2024-25600"].tags


class TestCVE_2024_21762:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-21762"].name == "Fortinet SSLVPN RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-21762"].cvss_score == 9.8

    def test_vuln_types_include_buffer_overflow(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-21762"].vuln_types
        assert VulnType.BUFFER_OVERFLOW in vt

    def test_required_tools_include_metasploit(self, vuln_by_cve):
        assert "metasploit" in vuln_by_cve["CVE-2024-21762"].required_tools

    def test_tags_include_fortinet(self, vuln_by_cve):
        assert "fortinet" in vuln_by_cve["CVE-2024-21762"].tags


class TestCVE_2024_24573:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-24573"].name == "Veeam Backup & Replication RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-24573"].cvss_score == 9.8

    def test_required_tools_include_ysoserial(self, vuln_by_cve):
        assert "ysoserial" in vuln_by_cve["CVE-2024-24573"].required_tools

    def test_tags_include_backup(self, vuln_by_cve):
        assert "backup" in vuln_by_cve["CVE-2024-24573"].tags


class TestCVE_2024_27983:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-27983"].name == "Cisco NX-OS RCE"

    def test_vuln_types_include_priv_esc(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-27983"].vuln_types
        assert VulnType.PRIVILEGE_ESCALATION in vt

    def test_tags_include_cisco(self, vuln_by_cve):
        assert "cisco" in vuln_by_cve["CVE-2024-27983"].tags

    def test_tags_include_network(self, vuln_by_cve):
        assert "network" in vuln_by_cve["CVE-2024-27983"].tags


class TestCVE_2024_0204:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-0204"].name == "GoAnywhere MFT Authentication Bypass"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-0204"].cvss_score == 9.8

    def test_vuln_types_include_auth_bypass(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-0204"].vuln_types
        assert VulnType.AUTHENTICATION_BYPASS in vt

    def test_tags_include_auth_bypass(self, vuln_by_cve):
        assert "auth-bypass" in vuln_by_cve["CVE-2024-0204"].tags

    def test_tags_include_mft(self, vuln_by_cve):
        assert "mft" in vuln_by_cve["CVE-2024-0204"].tags


class TestCVE_2024_21887:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-21887"].name == "Atlassian Confluence RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-21887"].cvss_score == 9.8

    def test_vuln_types_include_buffer_overflow(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-21887"].vuln_types
        assert VulnType.BUFFER_OVERFLOW in vt

    def test_required_tools_include_ognl(self, vuln_by_cve):
        assert "ognl" in vuln_by_cve["CVE-2024-21887"].required_tools

    def test_tags_include_confluence(self, vuln_by_cve):
        assert "confluence" in vuln_by_cve["CVE-2024-21887"].tags


class TestCVE_2024_28121:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-28121"].name == "Apache Kafka UI RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-28121"].cvss_score == 8.8

    def test_severity_is_high_not_critical(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-28121"].severity == VulnSeverity.HIGH

    def test_tags_include_kafka(self, vuln_by_cve):
        assert "kafka" in vuln_by_cve["CVE-2024-28121"].tags

    def test_tags_include_apache(self, vuln_by_cve):
        assert "apache" in vuln_by_cve["CVE-2024-28121"].tags


class TestCVE_2024_27456:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-27456"].name == "Ivanti Connect Secure RCE"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-27456"].cvss_score == 9.8

    def test_tags_include_ivanti(self, vuln_by_cve):
        assert "ivanti" in vuln_by_cve["CVE-2024-27456"].tags

    def test_tags_include_vpn(self, vuln_by_cve):
        assert "vpn" in vuln_by_cve["CVE-2024-27456"].tags


class TestCVE_2024_22024:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-22024"].name == "Veeam Service Provider Console RCE"

    def test_affected_products(self, vuln_by_cve):
        prods = vuln_by_cve["CVE-2024-22024"].affected_products
        assert "Veeam Service Provider Console" in prods

    def test_tags_include_veeam(self, vuln_by_cve):
        assert "veeam" in vuln_by_cve["CVE-2024-22024"].tags


class TestCVE_2024_22274:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-22274"].name == "SolarWinds Web Help Desk RCE"

    def test_required_tools_include_ysoserial(self, vuln_by_cve):
        assert "ysoserial" in vuln_by_cve["CVE-2024-22274"].required_tools

    def test_tags_include_solarwinds(self, vuln_by_cve):
        assert "solarwinds" in vuln_by_cve["CVE-2024-22274"].tags


class TestCVE_2024_2924:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-2924"].name == "Progress MOVEit Transfer RCE"

    def test_vuln_types_include_sqli(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-2924"].vuln_types
        assert VulnType.SQL_INJECTION in vt

    def test_required_tools_include_sqlmap(self, vuln_by_cve):
        assert "sqlmap" in vuln_by_cve["CVE-2024-2924"].required_tools

    def test_tags_include_moveit(self, vuln_by_cve):
        assert "moveit" in vuln_by_cve["CVE-2024-2924"].tags

    def test_tags_include_sqli(self, vuln_by_cve):
        assert "sqli" in vuln_by_cve["CVE-2024-2924"].tags


class TestCVE_2024_28755:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-28755"].name == "Veeam Backup Agent RCE"

    def test_vuln_types_include_priv_esc(self, vuln_by_cve):
        vt = vuln_by_cve["CVE-2024-28755"].vuln_types
        assert VulnType.PRIVILEGE_ESCALATION in vt

    def test_affected_products(self, vuln_by_cve):
        prods = vuln_by_cve["CVE-2024-28755"].affected_products
        assert "Veeam Agent for Linux" in prods
        assert "Veeam Agent for Windows" in prods


class TestCVE_2024_31650:
    def test_name(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-31650"].name == "PaperCut NG Authentication Bypass"

    def test_cvss(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-31650"].cvss_score == 9.8

    def test_affected_products(self, vuln_by_cve):
        prods = vuln_by_cve["CVE-2024-31650"].affected_products
        assert "PaperCut NG" in prods
        assert "PaperCut MF" in prods

    def test_tags_include_papercut(self, vuln_by_cve):
        assert "papercut" in vuln_by_cve["CVE-2024-31650"].tags

    def test_tags_include_auth_bypass(self, vuln_by_cve):
        assert "auth-bypass" in vuln_by_cve["CVE-2024-31650"].tags


# ===================== Severity distribution =====================


class TestSeverityDistribution:
    def test_count_critical(self, vulns):
        critical = [v for v in vulns if v.severity == VulnSeverity.CRITICAL]
        assert len(critical) == 15

    def test_count_high(self, vulns):
        high = [v for v in vulns if v.severity == VulnSeverity.HIGH]
        assert len(high) == 1

    def test_only_kafka_is_high(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-28121"].severity == VulnSeverity.HIGH


# ===================== patch_available distribution =====================


class TestPatchDistribution:
    def test_count_unpatched(self, vulns):
        unpatched = [v for v in vulns if not v.patch_available]
        assert len(unpatched) == 2

    def test_unpatched_are_paloalto_and_chainwiki(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3400"].patch_available is False
        assert vuln_by_cve["CVE-2024-25600"].patch_available is False

    def test_count_patched(self, vulns):
        patched = [v for v in vulns if v.patch_available]
        assert len(patched) == 14


# ===================== VulnType coverage =====================


class TestVulnTypeCoverage:
    def test_rce_appears_in_all(self, vulns):
        for v in vulns:
            assert VulnType.RCE in v.vuln_types or VulnType.AUTHENTICATION_BYPASS in v.vuln_types, (
                f"{v.cve_id} has neither RCE nor AUTH_BYPASS"
            )

    def test_rce_count(self, vulns):
        rce = [v for v in vulns if VulnType.RCE in v.vuln_types]
        assert len(rce) == 16  # all have RCE

    def test_auth_bypass_count(self, vulns):
        ab = [v for v in vulns if VulnType.AUTHENTICATION_BYPASS in v.vuln_types]
        assert ab  # at least some have auth bypass

    def test_sql_injection_count(self, vulns):
        sqli = [v for v in vulns if VulnType.SQL_INJECTION in v.vuln_types]
        assert len(sqli) == 1  # only MOVEit

    def test_buffer_overflow_count(self, vulns):
        bof = [v for v in vulns if VulnType.BUFFER_OVERFLOW in v.vuln_types]
        assert len(bof) == 2  # Fortinet and Confluence

    def test_privilege_escalation_count(self, vulns):
        pe = [v for v in vulns if VulnType.PRIVILEGE_ESCALATION in v.vuln_types]
        assert len(pe) == 3  # XZ, Cisco, Veeam Agent

    def test_file_inclusion_count(self, vulns):
        fi = [v for v in vulns if VulnType.FILE_INCLUSION in v.vuln_types]
        assert len(fi) == 1  # ChainWiki


# ===================== Date range tests =====================


class TestDateRanges:
    def test_earliest_date(self, vulns):
        earliest = min(v.publish_date for v in vulns)
        assert earliest == date(2024, 1, 16)

    def test_latest_date(self, vulns):
        latest = max(v.publish_date for v in vulns)
        assert latest == date(2024, 4, 16)

    def test_all_dates_in_q1_q2_2024(self, vulns):
        for v in vulns:
            assert 1 <= v.publish_date.month <= 4


# ===================== to_dict round-trip =====================


class TestToDictRoundTrip:
    def test_to_dict_returns_dict(self, vulns):
        d = vulns[0].to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_all_keys(self, vulns):
        d = vulns[0].to_dict()
        expected_keys = {
            "cve_id", "name", "category", "publish_date", "cvss_score",
            "severity", "affected_products", "vuln_types", "description",
            "exploit_available", "exploit_method", "required_tools",
            "affected_versions", "references", "tags", "poc_available",
            "patch_available", "detection_methods", "mitre_technique",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_category_is_string(self, vulns):
        d = vulns[0].to_dict()
        assert d["category"] == "0day"

    def test_to_dict_severity_is_string(self, vulns):
        d = vulns[0].to_dict()
        assert isinstance(d["severity"], str)

    def test_to_dict_vuln_types_are_strings(self, vulns):
        d = vulns[0].to_dict()
        for vt in d["vuln_types"]:
            assert isinstance(vt, str)

    def test_to_dict_publish_date_is_iso(self, vulns):
        d = vulns[0].to_dict()
        assert isinstance(d["publish_date"], str)
        assert "-" in d["publish_date"]

    def test_from_dict_roundtrip(self, vulns):
        for v in vulns:
            d = v.to_dict()
            reconstructed = Vulnerability.from_dict(d)
            assert reconstructed.cve_id == v.cve_id
            assert reconstructed.name == v.name
            assert reconstructed.category == v.category
            assert reconstructed.cvss_score == v.cvss_score
            assert reconstructed.severity == v.severity
            assert reconstructed.exploit_available == v.exploit_available
            assert reconstructed.poc_available == v.poc_available
            assert reconstructed.patch_available == v.patch_available
            assert reconstructed.tags == v.tags
            assert reconstructed.affected_products == v.affected_products
            assert reconstructed.required_tools == v.required_tools

    def test_from_dict_preserves_vuln_types(self, vulns):
        for v in vulns:
            d = v.to_dict()
            r = Vulnerability.from_dict(d)
            assert r.vuln_types == v.vuln_types

    def test_from_dict_preserves_detection_methods(self, vulns):
        for v in vulns:
            d = v.to_dict()
            r = Vulnerability.from_dict(d)
            assert r.detection_methods == v.detection_methods


# ===================== matches_product =====================


class TestMatchesProduct:
    def test_exact_product_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3400"]
        assert v.matches_product("Palo Alto GlobalProtect") is True

    def test_case_insensitive_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3400"]
        assert v.matches_product("palo alto globalprotect") is True

    def test_partial_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3400"]
        assert v.matches_product("GlobalProtect") is True

    def test_no_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3400"]
        assert v.matches_product("Apache Tomcat") is False

    def test_empty_string_no_match(self, vuln_by_cve):
        # Empty string is substring of everything, so this should match
        v = vuln_by_cve["CVE-2024-3400"]
        result = v.matches_product("")
        assert result is True  # "" is in every string

    def test_xz_utils_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3094"]
        assert v.matches_product("XZ Utils") is True

    def test_linux_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3094"]
        assert v.matches_product("Linux") is True

    def test_confluence_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-21887"]
        assert v.matches_product("Confluence") is True


# ===================== matches_version =====================


class TestMatchesVersion:
    def test_exact_version_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3094"]
        assert v.matches_version("XZ Utils 5.6.0") is True

    def test_partial_version_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3094"]
        assert v.matches_version("5.6.0") is True

    def test_no_version_match(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3094"]
        assert v.matches_version("9.9.9") is False

    def test_case_insensitive_version(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3094"]
        assert v.matches_version("xz utils 5.6.0") is True


# ===================== CVSS score statistics =====================


class TestCVSSStatistics:
    def test_max_cvss(self, vulns):
        assert max(v.cvss_score for v in vulns) == 10.0

    def test_min_cvss(self, vulns):
        assert min(v.cvss_score for v in vulns) == 8.8

    def test_average_cvss_above_9(self, vulns):
        avg = sum(v.cvss_score for v in vulns) / len(vulns)
        assert avg > 9.0

    def test_cvss_10_is_xz(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-3094"].cvss_score == 10.0

    def test_cvss_88_is_kafka(self, vuln_by_cve):
        assert vuln_by_cve["CVE-2024-28121"].cvss_score == 8.8


# ===================== Tags consistency =====================


class TestTagsConsistency:
    def test_rce_tag_in_most_entries(self, vulns):
        rce_tagged = [v for v in vulns if "rce" in v.tags]
        assert len(rce_tagged) >= 14

    def test_critical_tag_in_most_critical_entries(self, vulns):
        critical_with_tag = [
            v for v in vulns
            if v.severity == VulnSeverity.CRITICAL and "critical" in v.tags
        ]
        # Most critical-severity entries carry the "critical" tag
        assert len(critical_with_tag) >= 12

    def test_chainwiki_critical_no_critical_tag(self, vuln_by_cve):
        """CVE-2024-25600 is CRITICAL but does not carry the 'critical' tag."""
        v = vuln_by_cve["CVE-2024-25600"]
        assert v.severity == VulnSeverity.CRITICAL
        assert "critical" not in v.tags

    def test_vpn_tag_in_vpn_products(self, vuln_by_cve):
        assert "vpn" in vuln_by_cve["CVE-2024-3400"].tags
        assert "vpn" in vuln_by_cve["CVE-2024-27456"].tags
        assert "vpn" in vuln_by_cve["CVE-2024-21762"].tags


# ===================== Detection methods content =====================


class TestDetectionMethods:
    def test_all_have_at_least_3_methods(self, vulns):
        for v in vulns:
            assert len(v.detection_methods) >= 3

    def test_detection_methods_are_strings(self, vulns):
        for v in vulns:
            for dm in v.detection_methods:
                assert isinstance(dm, str)
                assert len(dm) > 0

    def test_some_have_4_methods(self, vulns):
        four_methods = [v for v in vulns if len(v.detection_methods) == 4]
        assert len(four_methods) > 0

    def test_banner_detection_common(self, vulns):
        banner = [v for v in vulns if any("banner" in dm.lower() for dm in v.detection_methods)]
        assert len(banner) > 5


# ===================== References content =====================


class TestReferences:
    def test_all_have_at_least_one_ref(self, vulns):
        for v in vulns:
            assert len(v.references) >= 1

    def test_most_have_two_refs(self, vulns):
        two_refs = [v for v in vulns if len(v.references) >= 2]
        assert len(two_refs) >= 14

    def test_nvd_reference_common(self, vulns):
        nvd = [v for v in vulns if any("nvd.nist.gov" in r for r in v.references)]
        assert len(nvd) >= 14

    def test_all_refs_https(self, vulns):
        for v in vulns:
            for ref in v.references:
                assert ref.startswith("https://")


# ===================== MITRE technique =====================


class TestMITRETechnique:
    def test_all_have_mitre(self, vulns):
        for v in vulns:
            assert v.mitre_technique is not None

    def test_all_mitre_contain_dash(self, vulns):
        for v in vulns:
            assert " - " in v.mitre_technique

    def test_most_are_t1190(self, vulns):
        t1190 = [v for v in vulns if "T1190" in v.mitre_technique]
        assert len(t1190) >= 15

    def test_xz_has_supply_chain_mitre(self, vuln_by_cve):
        v = vuln_by_cve["CVE-2024-3094"]
        assert "T1195" in v.mitre_technique
        assert "Supply Chain" in v.mitre_technique


# ===================== Enum value tests =====================


class TestEnumValues:
    def test_vuln_category_zero_day_value(self):
        assert VulnCategory.ZERO_DAY.value == "0day"

    def test_vuln_severity_critical_value(self):
        assert VulnSeverity.CRITICAL.value == "CRITICAL"

    def test_vuln_severity_high_value(self):
        assert VulnSeverity.HIGH.value == "HIGH"

    def test_vuln_type_rce_value(self):
        assert VulnType.RCE.value == "RCE"

    def test_vuln_type_auth_bypass_value(self):
        assert VulnType.AUTHENTICATION_BYPASS.value == "Authentication Bypass"

    def test_vuln_type_sqli_value(self):
        assert VulnType.SQL_INJECTION.value == "SQL Injection"

    def test_vuln_type_buffer_overflow_value(self):
        assert VulnType.BUFFER_OVERFLOW.value == "Buffer Overflow"

    def test_vuln_type_priv_esc_value(self):
        assert VulnType.PRIVILEGE_ESCALATION.value == "Privilege Escalation"

    def test_vuln_type_file_inclusion_value(self):
        assert VulnType.FILE_INCLUSION.value == "File Inclusion"
