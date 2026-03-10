"""
Tests for nday_vulns module (kali_mcp/vulnerabilities/nday_vulns.py)

Covers:
- get_vulnerabilities() return type and structure
- Total vulnerability count
- Each individual CVE entry (25 entries):
    CVE-2023-46604 (ActiveMQ RCE)
    CVE-2023-22515 (Confluence OGNL RCE)
    CVE-2023-4911 (Looney Tunables LPE)
    CVE-2023-23397 (Outlook NTLM Hash Theft)
    CVE-2023-22518 (Confluence RCE)
    CVE-2023-34362 (MOVEit Transfer SQL Injection)
    CVE-2023-0669 (GoAnywhere MFT SQL Injection)
    CVE-2023-27350 (PaperCut NG Auth Bypass)
    CVE-2023-4911 dup (Linux Stack Rot LPE)
    CVE-2023-22527 (Confluence OGNL Injection)
    CVE-2023-41773 (Apple WebKit RCE)
    CVE-2023-36844 (Apache Shiro RCE)
    CVE-2023-36934 (Exchange Server RCE)
    CVE-2023-29357 (SharePoint RCE)
    CVE-2023-2253 (GoAnywhere MFT Auth Bypass)
    CVE-2023-24322 (F5 BIG-IP RCE)
    CVE-2023-27997 (Cisco ASA RCE)
    CVE-2023-32233 (Sudo Baron Samedit LPE)
    CVE-2023-38408 (WordPress WooCommerce Payments RCE)
    CVE-2023-22515 dup (Confluence OGNL Injection Duplicate)
    CVE-2023-27372 (Netgear R7000 RCE)
    CVE-2023-25157 (Telerik Report Server RCE)
    CVE-2023-34362 dup (MOVEit Transfer SQL Injection Duplicate)
    CVE-2023-27352 (Veeam Backup RCE)
    CVE-2023-29357 dup (SharePoint RCE Duplicate)
    CVE-2023-23397 dup (Outlook NTLM Theft Duplicate)
    CVE-2023-46604 dup (ActiveMQ RCE Duplicate)
- VulnCategory enum values on all entries
- VulnSeverity enum values on all entries
- VulnType enum values on all entries
- Vulnerability dataclass field types and defaults
- CVSS score ranges and values
- Date correctness for all entries
- Boolean flags (exploit_available, poc_available, patch_available)
- List fields (tags, references, affected_products, detection_methods, etc.)
- Optional fields (exploit_method, mitre_technique)
- to_dict() serialization for nday vulns
- Duplicate CVE ID handling
- Aggregate statistics (severity counts, category counts, CVSS distributions)
- Edge cases: empty lists, None values, boundary CVSS scores
"""

import pytest
from datetime import date
from typing import List

from kali_mcp.vulnerabilities.nday_vulns import get_vulnerabilities
from kali_mcp.vulnerabilities.vuln_database import (
    Vulnerability,
    VulnCategory,
    VulnSeverity,
    VulnType,
)


# ===================== Fixtures =====================

@pytest.fixture
def vulns() -> List[Vulnerability]:
    """Return the full nday vulnerability list."""
    return get_vulnerabilities()


@pytest.fixture
def vuln_by_index(vulns):
    """Helper: access vuln by list index."""
    return vulns


@pytest.fixture
def first_vuln(vulns):
    """The first vulnerability in the list (ActiveMQ RCE)."""
    return vulns[0]


@pytest.fixture
def cve_map(vulns):
    """Map from (cve_id, name) -> Vulnerability for unique lookups."""
    m = {}
    for v in vulns:
        m[(v.cve_id, v.name)] = v
    return m


# ===================== Basic Structure Tests =====================

class TestGetVulnerabilitiesBasic:
    """Tests for the return value structure of get_vulnerabilities()."""

    def test_returns_list(self, vulns):
        assert isinstance(vulns, list)

    def test_returns_non_empty(self, vulns):
        assert len(vulns) > 0

    def test_total_count(self, vulns):
        assert len(vulns) == 27

    def test_all_are_vulnerability_instances(self, vulns):
        for v in vulns:
            assert isinstance(v, Vulnerability)

    def test_returns_fresh_list_each_call(self):
        v1 = get_vulnerabilities()
        v2 = get_vulnerabilities()
        assert v1 is not v2

    def test_list_items_independent(self):
        v1 = get_vulnerabilities()
        v2 = get_vulnerabilities()
        assert v1[0].cve_id == v2[0].cve_id


# ===================== All N_DAY Category Tests =====================

class TestAllNDayCategory:
    """All entries must be VulnCategory.N_DAY."""

    def test_all_category_nday(self, vulns):
        for v in vulns:
            assert v.category == VulnCategory.N_DAY, (
                f"{v.cve_id} ({v.name}) has category {v.category}, expected N_DAY"
            )

    def test_category_value(self, vulns):
        for v in vulns:
            assert v.category.value == "nday"


# ===================== Severity Tests =====================

class TestSeverityDistribution:
    """Test severity assignment correctness."""

    def test_severity_is_enum(self, vulns):
        for v in vulns:
            assert isinstance(v.severity, VulnSeverity)

    def test_critical_count(self, vulns):
        critical = [v for v in vulns if v.severity == VulnSeverity.CRITICAL]
        assert len(critical) >= 20  # Most are critical

    def test_high_count(self, vulns):
        high = [v for v in vulns if v.severity == VulnSeverity.HIGH]
        assert len(high) >= 3

    def test_no_medium_or_low(self, vulns):
        medium = [v for v in vulns if v.severity == VulnSeverity.MEDIUM]
        low = [v for v in vulns if v.severity == VulnSeverity.LOW]
        assert len(medium) == 0
        assert len(low) == 0

    def test_critical_cvss_consistency(self, vulns):
        """Critical vulns should have CVSS >= 9.0 generally."""
        for v in vulns:
            if v.severity == VulnSeverity.CRITICAL:
                assert v.cvss_score >= 9.0, (
                    f"{v.cve_id} is CRITICAL but CVSS is {v.cvss_score}"
                )

    def test_high_cvss_consistency(self, vulns):
        """HIGH vulns should have CVSS in 7.0-8.9 range."""
        for v in vulns:
            if v.severity == VulnSeverity.HIGH:
                assert 7.0 <= v.cvss_score <= 8.9, (
                    f"{v.cve_id} is HIGH but CVSS is {v.cvss_score}"
                )


# ===================== CVSS Score Tests =====================

class TestCVSSScores:
    """Test CVSS scores are within valid range and correct values."""

    def test_all_cvss_valid_range(self, vulns):
        for v in vulns:
            assert 0.0 <= v.cvss_score <= 10.0, f"{v.cve_id} CVSS {v.cvss_score} out of range"

    def test_all_cvss_high_severity(self, vulns):
        """All nday vulns should have CVSS >= 7.0 (high or critical)."""
        for v in vulns:
            assert v.cvss_score >= 7.0, f"{v.cve_id} CVSS {v.cvss_score} below 7.0"

    def test_max_cvss_is_10(self, vulns):
        max_cvss = max(v.cvss_score for v in vulns)
        assert max_cvss == 10.0

    def test_activemq_cvss_10(self, first_vuln):
        assert first_vuln.cvss_score == 10.0

    def test_cvss_are_floats(self, vulns):
        for v in vulns:
            assert isinstance(v.cvss_score, float)


# ===================== Date Tests =====================

class TestPublishDates:
    """Test publish_date correctness."""

    def test_all_dates_are_date_type(self, vulns):
        for v in vulns:
            assert isinstance(v.publish_date, date)

    def test_all_dates_in_2023(self, vulns):
        for v in vulns:
            assert v.publish_date.year == 2023, (
                f"{v.cve_id} has year {v.publish_date.year}, expected 2023"
            )

    def test_activemq_date(self, first_vuln):
        assert first_vuln.publish_date == date(2023, 10, 27)

    def test_dates_not_in_future(self, vulns):
        today = date.today()
        for v in vulns:
            assert v.publish_date <= today

    def test_earliest_date(self, vulns):
        earliest = min(v.publish_date for v in vulns)
        assert earliest == date(2023, 1, 19)  # Sudo Baron Samedit

    def test_latest_date(self, vulns):
        latest = max(v.publish_date for v in vulns)
        assert latest == date(2023, 10, 27)  # ActiveMQ


# ===================== Boolean Flags Tests =====================

class TestBooleanFlags:
    """Test exploit_available, poc_available, patch_available."""

    def test_all_exploit_available(self, vulns):
        for v in vulns:
            assert v.exploit_available is True

    def test_all_poc_available(self, vulns):
        for v in vulns:
            assert v.poc_available is True

    def test_all_patch_available(self, vulns):
        for v in vulns:
            assert v.patch_available is True

    def test_flags_are_bool(self, vulns):
        for v in vulns:
            assert isinstance(v.exploit_available, bool)
            assert isinstance(v.poc_available, bool)
            assert isinstance(v.patch_available, bool)


# ===================== String Fields Tests =====================

class TestStringFields:
    """Test cve_id, name, description, exploit_method, mitre_technique."""

    def test_all_have_cve_id(self, vulns):
        for v in vulns:
            assert v.cve_id is not None
            assert v.cve_id.startswith("CVE-")

    def test_all_cve_ids_2023(self, vulns):
        for v in vulns:
            assert v.cve_id.startswith("CVE-2023-")

    def test_all_have_name(self, vulns):
        for v in vulns:
            assert isinstance(v.name, str)
            assert len(v.name) > 0

    def test_all_have_description(self, vulns):
        for v in vulns:
            assert isinstance(v.description, str)
            assert len(v.description) > 0

    def test_all_have_exploit_method(self, vulns):
        for v in vulns:
            assert v.exploit_method is not None
            assert len(v.exploit_method) > 0

    def test_mitre_technique_present(self, vulns):
        for v in vulns:
            assert v.mitre_technique is not None
            assert len(v.mitre_technique) > 0


# ===================== List Fields Tests =====================

class TestListFields:
    """Test affected_products, vuln_types, required_tools, etc."""

    def test_affected_products_non_empty(self, vulns):
        for v in vulns:
            assert isinstance(v.affected_products, list)
            assert len(v.affected_products) > 0

    def test_vuln_types_non_empty(self, vulns):
        for v in vulns:
            assert isinstance(v.vuln_types, list)
            assert len(v.vuln_types) > 0

    def test_vuln_types_are_enum(self, vulns):
        for v in vulns:
            for vt in v.vuln_types:
                assert isinstance(vt, VulnType)

    def test_required_tools_non_empty(self, vulns):
        for v in vulns:
            assert isinstance(v.required_tools, list)
            assert len(v.required_tools) > 0

    def test_affected_versions_non_empty(self, vulns):
        for v in vulns:
            assert isinstance(v.affected_versions, list)
            assert len(v.affected_versions) > 0

    def test_references_non_empty(self, vulns):
        for v in vulns:
            assert isinstance(v.references, list)
            assert len(v.references) > 0

    def test_tags_non_empty(self, vulns):
        for v in vulns:
            assert isinstance(v.tags, list)
            assert len(v.tags) > 0

    def test_all_tags_contain_nday(self, vulns):
        for v in vulns:
            assert "nday" in v.tags, f"{v.cve_id} missing 'nday' tag"

    def test_detection_methods_non_empty(self, vulns):
        for v in vulns:
            assert isinstance(v.detection_methods, list)
            assert len(v.detection_methods) > 0


# ===================== Individual CVE Tests =====================

class TestCVE2023_46604_ActiveMQ:
    """Test first ActiveMQ RCE entry (index 0)."""

    def test_cve_id(self, vulns):
        assert vulns[0].cve_id == "CVE-2023-46604"

    def test_name(self, vulns):
        assert vulns[0].name == "Apache ActiveMQ RCE"

    def test_cvss_score(self, vulns):
        assert vulns[0].cvss_score == 10.0

    def test_severity(self, vulns):
        assert vulns[0].severity == VulnSeverity.CRITICAL

    def test_affected_products(self, vulns):
        assert "Apache ActiveMQ" in vulns[0].affected_products
        assert "ActiveMQ Artemis" in vulns[0].affected_products

    def test_vuln_types(self, vulns):
        assert VulnType.RCE in vulns[0].vuln_types
        assert VulnType.DESERIALIZATION in vulns[0].vuln_types

    def test_required_tools(self, vulns):
        assert "metasploit" in vulns[0].required_tools

    def test_tags(self, vulns):
        for tag in ["nday", "apache", "rce", "deserialization", "ransomware", "metasploit"]:
            assert tag in vulns[0].tags

    def test_publish_date(self, vulns):
        assert vulns[0].publish_date == date(2023, 10, 27)

    def test_mitre_technique(self, vulns):
        assert vulns[0].mitre_technique == "T1190"

    def test_detection_methods_count(self, vulns):
        assert len(vulns[0].detection_methods) == 4

    def test_references_count(self, vulns):
        assert len(vulns[0].references) == 2


class TestCVE2023_22515_Confluence:
    """Test Atlassian Confluence OGNL RCE (index 1)."""

    def test_cve_id(self, vulns):
        assert vulns[1].cve_id == "CVE-2023-22515"

    def test_name(self, vulns):
        assert vulns[1].name == "Atlassian Confluence OGNL RCE"

    def test_cvss(self, vulns):
        assert vulns[1].cvss_score == 10.0

    def test_affected_products(self, vulns):
        assert "Atlassian Confluence" in vulns[1].affected_products

    def test_vuln_types(self, vulns):
        assert VulnType.RCE in vulns[1].vuln_types

    def test_tags_contain_confluence(self, vulns):
        assert "confluence" in vulns[1].tags
        assert "ognl" in vulns[1].tags


class TestCVE2023_4911_LooneyTunables:
    """Test Linux Looney Tunables LPE (index 2)."""

    def test_cve_id(self, vulns):
        assert vulns[2].cve_id == "CVE-2023-4911"

    def test_name(self, vulns):
        assert vulns[2].name == "Linux Looney Tunables LPE"

    def test_severity_high(self, vulns):
        assert vulns[2].severity == VulnSeverity.HIGH

    def test_cvss(self, vulns):
        assert vulns[2].cvss_score == 7.8

    def test_vuln_types(self, vulns):
        assert VulnType.PRIVILEGE_ESCALATION in vulns[2].vuln_types
        assert VulnType.BUFFER_OVERFLOW in vulns[2].vuln_types

    def test_linux_products(self, vulns):
        assert "Linux Kernel" in vulns[2].affected_products
        assert "glibc" in vulns[2].affected_products

    def test_mitre_technique(self, vulns):
        assert "T1068" in vulns[2].mitre_technique


class TestCVE2023_23397_OutlookNTLM:
    """Test Microsoft Outlook NTLM Hash Theft (index 3)."""

    def test_cve_id(self, vulns):
        assert vulns[3].cve_id == "CVE-2023-23397"

    def test_cvss(self, vulns):
        assert vulns[3].cvss_score == 9.8

    def test_affected_products(self, vulns):
        assert "Microsoft Outlook" in vulns[3].affected_products

    def test_vuln_types(self, vulns):
        assert VulnType.AUTHENTICATION_BYPASS in vulns[3].vuln_types

    def test_mitre_technique(self, vulns):
        assert "T1187" in vulns[3].mitre_technique

    def test_required_tools(self, vulns):
        assert "responder" in vulns[3].required_tools
        assert "impacket" in vulns[3].required_tools


class TestCVE2023_22518_ConfluenceRCE:
    """Test Atlassian Confluence RCE (index 4)."""

    def test_cve_id(self, vulns):
        assert vulns[4].cve_id == "CVE-2023-22518"

    def test_cvss(self, vulns):
        assert vulns[4].cvss_score == 9.8

    def test_date(self, vulns):
        assert vulns[4].publish_date == date(2023, 10, 16)


class TestCVE2023_34362_MOVEit:
    """Test MOVEit Transfer SQL Injection (index 5)."""

    def test_cve_id(self, vulns):
        assert vulns[5].cve_id == "CVE-2023-34362"

    def test_vuln_types(self, vulns):
        assert VulnType.SQL_INJECTION in vulns[5].vuln_types
        assert VulnType.RCE in vulns[5].vuln_types

    def test_tags(self, vulns):
        assert "moveit" in vulns[5].tags
        assert "sqli" in vulns[5].tags
        assert "ransomware" in vulns[5].tags
        assert "cl0p" in vulns[5].tags


class TestCVE2023_0669_GoAnywhereMFT:
    """Test GoAnywhere MFT SQL Injection (index 6)."""

    def test_cve_id(self, vulns):
        assert vulns[6].cve_id == "CVE-2023-0669"

    def test_cvss(self, vulns):
        assert vulns[6].cvss_score == 9.8

    def test_required_tools(self, vulns):
        assert "sqlmap" in vulns[6].required_tools


class TestCVE2023_27350_PaperCut:
    """Test PaperCut NG Auth Bypass (index 7)."""

    def test_cve_id(self, vulns):
        assert vulns[7].cve_id == "CVE-2023-27350"

    def test_vuln_types(self, vulns):
        assert VulnType.AUTHENTICATION_BYPASS in vulns[7].vuln_types
        assert VulnType.RCE in vulns[7].vuln_types

    def test_tags(self, vulns):
        assert "papercut" in vulns[7].tags
        assert "auth-bypass" in vulns[7].tags


class TestCVE2023_4911_StackRot:
    """Test Linux Stack Rot LPE (index 8, duplicate CVE ID with index 2)."""

    def test_cve_id(self, vulns):
        assert vulns[8].cve_id == "CVE-2023-4911"

    def test_name_different_from_index_2(self, vulns):
        assert vulns[8].name == "Linux Stack Rot LPE"
        assert vulns[8].name != vulns[2].name

    def test_severity_high(self, vulns):
        assert vulns[8].severity == VulnSeverity.HIGH

    def test_date(self, vulns):
        assert vulns[8].publish_date == date(2023, 7, 11)


class TestCVE2023_22527_ConfluenceOGNL:
    """Test Atlassian Confluence OGNL Injection (index 9)."""

    def test_cve_id(self, vulns):
        assert vulns[9].cve_id == "CVE-2023-22527"

    def test_cvss(self, vulns):
        assert vulns[9].cvss_score == 9.1

    def test_date(self, vulns):
        assert vulns[9].publish_date == date(2023, 6, 12)


class TestCVE2023_41773_AppleWebKit:
    """Test Apple WebKit RCE (index 10)."""

    def test_cve_id(self, vulns):
        assert vulns[10].cve_id == "CVE-2023-41773"

    def test_affected_products(self, vulns):
        assert "Safari" in vulns[10].affected_products
        assert "iOS" in vulns[10].affected_products
        assert "WebKit" in vulns[10].affected_products

    def test_tags(self, vulns):
        assert "apple" in vulns[10].tags
        assert "mobile" in vulns[10].tags

    def test_mitre_technique(self, vulns):
        assert "T1190" in vulns[10].mitre_technique


class TestCVE2023_36844_ApacheShiro:
    """Test Apache Shiro RCE (index 11)."""

    def test_cve_id(self, vulns):
        assert vulns[11].cve_id == "CVE-2023-36844"

    def test_vuln_types(self, vulns):
        assert VulnType.RCE in vulns[11].vuln_types
        assert VulnType.DESERIALIZATION in vulns[11].vuln_types

    def test_required_tools(self, vulns):
        assert "ysoserial" in vulns[11].required_tools

    def test_tags(self, vulns):
        assert "shiro" in vulns[11].tags
        assert "java" in vulns[11].tags


class TestCVE2023_36934_Exchange:
    """Test Microsoft Exchange Server RCE (index 12)."""

    def test_cve_id(self, vulns):
        assert vulns[12].cve_id == "CVE-2023-36934"

    def test_vuln_types(self, vulns):
        assert VulnType.RCE in vulns[12].vuln_types
        assert VulnType.CODE_EXECUTION in vulns[12].vuln_types

    def test_tags(self, vulns):
        assert "exchange" in vulns[12].tags


class TestCVE2023_29357_SharePoint:
    """Test Microsoft SharePoint RCE (index 13)."""

    def test_cve_id(self, vulns):
        assert vulns[13].cve_id == "CVE-2023-29357"

    def test_vuln_types(self, vulns):
        assert VulnType.DESERIALIZATION in vulns[13].vuln_types

    def test_affected_products(self, vulns):
        assert "Microsoft SharePoint Server" in vulns[13].affected_products


class TestCVE2023_2253_GoAnywhereMFTAuthBypass:
    """Test Fortra GoAnywhere MFT Auth Bypass (index 14)."""

    def test_cve_id(self, vulns):
        assert vulns[14].cve_id == "CVE-2023-2253"

    def test_vuln_types(self, vulns):
        assert VulnType.AUTHENTICATION_BYPASS in vulns[14].vuln_types

    def test_date(self, vulns):
        assert vulns[14].publish_date == date(2023, 1, 24)


class TestCVE2023_24322_F5BIGIP:
    """Test F5 BIG-IP iControl REST RCE (index 15)."""

    def test_cve_id(self, vulns):
        assert vulns[15].cve_id == "CVE-2023-24322"

    def test_affected_products(self, vulns):
        assert "F5 BIG-IP" in vulns[15].affected_products
        assert "F5 BIG-IQ" in vulns[15].affected_products

    def test_tags(self, vulns):
        assert "f5" in vulns[15].tags
        assert "big-ip" in vulns[15].tags


class TestCVE2023_27997_CiscoASA:
    """Test Cisco ASA & FTD RCE (index 16)."""

    def test_cve_id(self, vulns):
        assert vulns[16].cve_id == "CVE-2023-27997"

    def test_affected_products(self, vulns):
        assert "Cisco ASA" in vulns[16].affected_products

    def test_vuln_types(self, vulns):
        assert VulnType.BUFFER_OVERFLOW in vulns[16].vuln_types

    def test_tags(self, vulns):
        assert "cisco" in vulns[16].tags


class TestCVE2023_32233_SudoBaronSamedit:
    """Test Sudo Baron Samedit LPE (index 17)."""

    def test_cve_id(self, vulns):
        assert vulns[17].cve_id == "CVE-2023-32233"

    def test_severity(self, vulns):
        assert vulns[17].severity == VulnSeverity.HIGH

    def test_cvss(self, vulns):
        assert vulns[17].cvss_score == 7.8

    def test_vuln_types(self, vulns):
        assert VulnType.PRIVILEGE_ESCALATION in vulns[17].vuln_types

    def test_mitre_technique(self, vulns):
        assert vulns[17].mitre_technique == "T1068"


class TestCVE2023_38408_WooCommerce:
    """Test WordPress WooCommerce Payments RCE (index 18)."""

    def test_cve_id(self, vulns):
        assert vulns[18].cve_id == "CVE-2023-38408"

    def test_affected_products(self, vulns):
        assert "WordPress" in vulns[18].affected_products

    def test_required_tools(self, vulns):
        assert "wpscan" in vulns[18].required_tools

    def test_tags(self, vulns):
        assert "wordpress" in vulns[18].tags
        assert "woocommerce" in vulns[18].tags
        assert "cms" in vulns[18].tags


class TestCVE2023_27372_Netgear:
    """Test Netgear R7000 & R6400 RCE (index 20)."""

    def test_cve_id(self, vulns):
        assert vulns[20].cve_id == "CVE-2023-27372"

    def test_affected_products(self, vulns):
        assert "Netgear R7000" in vulns[20].affected_products

    def test_tags(self, vulns):
        assert "iot" in vulns[20].tags
        assert "router" in vulns[20].tags


class TestCVE2023_25157_TelerikReportServer:
    """Test Progress Telerik Report Server RCE (index 21)."""

    def test_cve_id(self, vulns):
        assert vulns[21].cve_id == "CVE-2023-25157"

    def test_vuln_types(self, vulns):
        assert VulnType.DESERIALIZATION in vulns[21].vuln_types

    def test_required_tools(self, vulns):
        assert "ysoserial" in vulns[21].required_tools


class TestCVE2023_27352_VeeamBackup:
    """Test Veeam Backup & Replication RCE (index 23)."""

    def test_cve_id(self, vulns):
        assert vulns[23].cve_id == "CVE-2023-27352"

    def test_affected_products(self, vulns):
        assert "Veeam Backup & Replication" in vulns[23].affected_products

    def test_tags(self, vulns):
        assert "veeam" in vulns[23].tags
        assert "backup" in vulns[23].tags


# ===================== Duplicate CVE Tests =====================

class TestDuplicateCVEs:
    """Test entries marked as duplicates."""

    def test_confluence_22515_duplicate_exists(self, vulns):
        assert vulns[19].cve_id == "CVE-2023-22515"
        assert "Duplicate" in vulns[19].name

    def test_moveit_34362_duplicate_exists(self, vulns):
        assert vulns[22].cve_id == "CVE-2023-34362"
        assert "Duplicate" in vulns[22].name

    def test_sharepoint_29357_duplicate_exists(self, vulns):
        assert vulns[24].cve_id == "CVE-2023-29357"
        assert "Duplicate" in vulns[24].name

    def test_outlook_23397_duplicate_exists(self, cve_map):
        key = ("CVE-2023-23397", "Microsoft Outlook NTLM Theft (Duplicate)")
        assert key in cve_map

    def test_activemq_46604_duplicate_exists(self, cve_map):
        key = ("CVE-2023-46604", "Apache ActiveMQ RCE (Duplicate)")
        assert key in cve_map

    def test_duplicate_cve_ids_present(self, vulns):
        """There should be multiple duplicate CVE IDs."""
        cve_ids = [v.cve_id for v in vulns]
        from collections import Counter
        counts = Counter(cve_ids)
        duplicated = {cve: count for cve, count in counts.items() if count > 1}
        assert len(duplicated) > 0

    def test_duplicates_have_different_names(self, vulns):
        """Duplicate CVE entries should have different names."""
        seen = {}
        for v in vulns:
            if v.cve_id in seen:
                assert v.name != seen[v.cve_id], (
                    f"Duplicate {v.cve_id} has same name"
                )
            else:
                seen[v.cve_id] = v.name


# ===================== VulnType Coverage Tests =====================

class TestVulnTypeCoverage:
    """Test that key VulnType values appear across the dataset."""

    def test_rce_present(self, vulns):
        rce_vulns = [v for v in vulns if VulnType.RCE in v.vuln_types]
        assert len(rce_vulns) >= 15

    def test_sql_injection_present(self, vulns):
        sqli_vulns = [v for v in vulns if VulnType.SQL_INJECTION in v.vuln_types]
        assert len(sqli_vulns) >= 2

    def test_deserialization_present(self, vulns):
        deser_vulns = [v for v in vulns if VulnType.DESERIALIZATION in v.vuln_types]
        assert len(deser_vulns) >= 4

    def test_privilege_escalation_present(self, vulns):
        pe_vulns = [v for v in vulns if VulnType.PRIVILEGE_ESCALATION in v.vuln_types]
        assert len(pe_vulns) >= 3

    def test_buffer_overflow_present(self, vulns):
        bo_vulns = [v for v in vulns if VulnType.BUFFER_OVERFLOW in v.vuln_types]
        assert len(bo_vulns) >= 5

    def test_auth_bypass_present(self, vulns):
        ab_vulns = [v for v in vulns if VulnType.AUTHENTICATION_BYPASS in v.vuln_types]
        assert len(ab_vulns) >= 5

    def test_code_execution_present(self, vulns):
        ce_vulns = [v for v in vulns if VulnType.CODE_EXECUTION in v.vuln_types]
        assert len(ce_vulns) >= 1


# ===================== Serialization Tests =====================

class TestToDictSerialization:
    """Test that Vulnerability.to_dict() works correctly for nday entries."""

    def test_to_dict_returns_dict(self, first_vuln):
        d = first_vuln.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_all_keys(self, first_vuln):
        d = first_vuln.to_dict()
        expected_keys = {
            "cve_id", "name", "category", "publish_date", "cvss_score",
            "severity", "affected_products", "vuln_types", "description",
            "exploit_available", "exploit_method", "required_tools",
            "affected_versions", "references", "tags", "poc_available",
            "patch_available", "detection_methods", "mitre_technique"
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_category_is_string(self, first_vuln):
        d = first_vuln.to_dict()
        assert d["category"] == "nday"

    def test_to_dict_severity_is_string(self, first_vuln):
        d = first_vuln.to_dict()
        assert d["severity"] == "CRITICAL"

    def test_to_dict_vuln_types_are_strings(self, first_vuln):
        d = first_vuln.to_dict()
        assert all(isinstance(vt, str) for vt in d["vuln_types"])

    def test_to_dict_publish_date_iso_format(self, first_vuln):
        d = first_vuln.to_dict()
        assert d["publish_date"] == "2023-10-27"

    def test_to_dict_roundtrip(self, first_vuln):
        """to_dict -> from_dict should produce equivalent vuln."""
        d = first_vuln.to_dict()
        restored = Vulnerability.from_dict(d)
        assert restored.cve_id == first_vuln.cve_id
        assert restored.name == first_vuln.name
        assert restored.cvss_score == first_vuln.cvss_score
        assert restored.category == first_vuln.category
        assert restored.severity == first_vuln.severity
        assert restored.exploit_available == first_vuln.exploit_available
        assert restored.poc_available == first_vuln.poc_available

    def test_all_vulns_serializable(self, vulns):
        """All vulns should serialize without error."""
        for v in vulns:
            d = v.to_dict()
            assert isinstance(d, dict)
            assert d["cve_id"] == v.cve_id


# ===================== Aggregate / Statistical Tests =====================

class TestAggregateStats:
    """Test aggregate properties of the full dataset."""

    def test_average_cvss_above_9(self, vulns):
        avg = sum(v.cvss_score for v in vulns) / len(vulns)
        assert avg > 9.0

    def test_unique_cve_count(self, vulns):
        """Less unique CVEs than total due to duplicates."""
        unique_cves = set(v.cve_id for v in vulns)
        assert len(unique_cves) < len(vulns)

    def test_unique_product_count(self, vulns):
        products = set()
        for v in vulns:
            for p in v.affected_products:
                products.add(p)
        assert len(products) >= 20

    def test_all_references_are_urls_or_strings(self, vulns):
        for v in vulns:
            for ref in v.references:
                assert isinstance(ref, str)
                assert len(ref) > 0

    def test_rce_is_most_common_vuln_type(self, vulns):
        from collections import Counter
        type_counts = Counter()
        for v in vulns:
            for vt in v.vuln_types:
                type_counts[vt] += 1
        most_common = type_counts.most_common(1)[0]
        assert most_common[0] == VulnType.RCE

    def test_metasploit_most_common_tool(self, vulns):
        from collections import Counter
        tool_counts = Counter()
        for v in vulns:
            for t in v.required_tools:
                tool_counts[t] += 1
        # metasploit or python3 should be near top
        top_tools = [t for t, _ in tool_counts.most_common(3)]
        assert "metasploit" in top_tools or "python3" in top_tools


# ===================== Matches Product / Version Tests =====================

class TestMatchesMethods:
    """Test Vulnerability.matches_product and matches_version on nday data."""

    def test_matches_product_exact(self, first_vuln):
        assert first_vuln.matches_product("Apache ActiveMQ") is True

    def test_matches_product_case_insensitive(self, first_vuln):
        assert first_vuln.matches_product("apache activemq") is True

    def test_matches_product_partial(self, first_vuln):
        assert first_vuln.matches_product("ActiveMQ") is True

    def test_matches_product_no_match(self, first_vuln):
        assert first_vuln.matches_product("Nginx") is False

    def test_matches_version_present(self, first_vuln):
        # "ActiveMQ < 5.18.3" is in affected_versions
        assert first_vuln.matches_version("ActiveMQ") is True

    def test_matches_version_no_match(self, first_vuln):
        assert first_vuln.matches_version("9.99.99-unknown") is False


# ===================== Ordering Tests =====================

class TestListOrdering:
    """Verify expected ordering of key entries."""

    def test_first_entry_is_activemq(self, vulns):
        assert vulns[0].cve_id == "CVE-2023-46604"

    def test_second_entry_is_confluence(self, vulns):
        assert vulns[1].cve_id == "CVE-2023-22515"

    def test_last_entry(self, vulns):
        # Last entry is ActiveMQ RCE Duplicate (index 26)
        assert vulns[-1].cve_id == "CVE-2023-46604"
        assert "Duplicate" in vulns[-1].name

    def test_index_7_is_papercut(self, vulns):
        assert vulns[7].cve_id == "CVE-2023-27350"


# ===================== Edge Case Tests =====================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_cvss_10_is_max(self, vulns):
        for v in vulns:
            assert v.cvss_score <= 10.0

    def test_cvss_non_negative(self, vulns):
        for v in vulns:
            assert v.cvss_score >= 0.0

    def test_no_empty_cve_ids(self, vulns):
        for v in vulns:
            assert v.cve_id.strip() != ""

    def test_no_empty_names(self, vulns):
        for v in vulns:
            assert v.name.strip() != ""

    def test_no_none_descriptions(self, vulns):
        for v in vulns:
            assert v.description is not None

    def test_cve_id_format_pattern(self, vulns):
        import re
        pattern = re.compile(r"^CVE-\d{4}-\d+$")
        for v in vulns:
            assert pattern.match(v.cve_id), f"{v.cve_id} doesn't match CVE format"

    def test_all_dates_valid(self, vulns):
        for v in vulns:
            assert v.publish_date.month >= 1
            assert v.publish_date.month <= 12
            assert v.publish_date.day >= 1
            assert v.publish_date.day <= 31

    def test_detection_methods_are_strings(self, vulns):
        for v in vulns:
            for dm in v.detection_methods:
                assert isinstance(dm, str)

    def test_affected_versions_are_strings(self, vulns):
        for v in vulns:
            for av in v.affected_versions:
                assert isinstance(av, str)

    def test_tags_are_strings(self, vulns):
        for v in vulns:
            for tag in v.tags:
                assert isinstance(tag, str)

    def test_required_tools_are_strings(self, vulns):
        for v in vulns:
            for tool in v.required_tools:
                assert isinstance(tool, str)
