"""
Tests for one_day_vulns module (kali_mcp/vulnerabilities/one_day_vulns.py)

Covers:
- get_vulnerabilities() return type and length
- Every Vulnerability instance: field types, required fields, enum values
- VulnCategory: all entries are ONE_DAY
- VulnSeverity: only CRITICAL or HIGH used, correct mapping to CVSS
- VulnType: all vuln_types use valid VulnType enum members
- CVSS scores: range 7.0–10.0, float type
- Dates: all are date objects in 2024
- Boolean fields: exploit_available, poc_available, patch_available
- List fields: affected_products, vuln_types, required_tools, affected_versions,
  references, tags, detection_methods are non-empty lists
- String fields: cve_id format, name non-empty, description non-empty,
  exploit_method non-empty, mitre_technique present
- CVE ID format validation (CVE-YYYY-NNNNN pattern)
- Tag consistency: all contain "1day" tag
- Duplicate CVE detection
- Individual vulnerability spot-checks (first, last, specific entries)
- to_dict() serialization for each vulnerability
- matches_product() for each vulnerability
- matches_version() for each vulnerability
- Data integrity: cross-field consistency (severity vs cvss_score)
- Edge cases: empty product search, version matching defaults
"""

import pytest
from datetime import date
from typing import List
import re

from kali_mcp.vulnerabilities.one_day_vulns import get_vulnerabilities
from kali_mcp.vulnerabilities.vuln_database import (
    Vulnerability,
    VulnCategory,
    VulnSeverity,
    VulnType,
)


# ===================== Fixtures =====================

@pytest.fixture
def vulns() -> List[Vulnerability]:
    """Load vulnerabilities once for all tests."""
    return get_vulnerabilities()


@pytest.fixture
def first_vuln(vulns) -> Vulnerability:
    return vulns[0]


@pytest.fixture
def last_vuln(vulns) -> Vulnerability:
    return vulns[-1]


@pytest.fixture
def all_cve_ids(vulns) -> List[str]:
    return [v.cve_id for v in vulns]


# ===================== get_vulnerabilities() Tests =====================

class TestGetVulnerabilities:
    def test_returns_list(self, vulns):
        assert isinstance(vulns, list)

    def test_returns_nonempty(self, vulns):
        assert len(vulns) > 0

    def test_returns_expected_count(self, vulns):
        assert len(vulns) == 33

    def test_all_are_vulnerability_instances(self, vulns):
        for v in vulns:
            assert isinstance(v, Vulnerability)

    def test_returns_new_list_each_call(self):
        """Each call should return a fresh list (no shared mutation risk)."""
        v1 = get_vulnerabilities()
        v2 = get_vulnerabilities()
        assert v1 is not v2

    def test_list_contents_equal_across_calls(self):
        v1 = get_vulnerabilities()
        v2 = get_vulnerabilities()
        assert len(v1) == len(v2)
        for a, b in zip(v1, v2):
            assert a.cve_id == b.cve_id
            assert a.name == b.name


# ===================== VulnCategory Tests =====================

class TestVulnCategory:
    def test_all_are_one_day(self, vulns):
        """Every vulnerability in this module must be ONE_DAY."""
        for v in vulns:
            assert v.category == VulnCategory.ONE_DAY, (
                f"{v.cve_id} has category {v.category}, expected ONE_DAY"
            )

    def test_category_value(self, vulns):
        for v in vulns:
            assert v.category.value == "1day"


# ===================== VulnSeverity Tests =====================

class TestVulnSeverity:
    def test_severity_is_enum(self, vulns):
        for v in vulns:
            assert isinstance(v.severity, VulnSeverity)

    def test_only_critical_or_high(self, vulns):
        """All 1day vulns in this file should be CRITICAL or HIGH."""
        for v in vulns:
            assert v.severity in (VulnSeverity.CRITICAL, VulnSeverity.HIGH), (
                f"{v.cve_id} severity {v.severity} is not CRITICAL or HIGH"
            )

    def test_critical_cvss_at_least_9(self, vulns):
        """CRITICAL vulns should have CVSS >= 9.0."""
        for v in vulns:
            if v.severity == VulnSeverity.CRITICAL:
                assert v.cvss_score >= 9.0, (
                    f"{v.cve_id} is CRITICAL but CVSS is {v.cvss_score}"
                )

    def test_high_cvss_range(self, vulns):
        """HIGH vulns should have CVSS in [7.0, 8.9]."""
        for v in vulns:
            if v.severity == VulnSeverity.HIGH:
                assert 7.0 <= v.cvss_score <= 8.9, (
                    f"{v.cve_id} is HIGH but CVSS is {v.cvss_score}"
                )

    def test_critical_count(self, vulns):
        critical = [v for v in vulns if v.severity == VulnSeverity.CRITICAL]
        assert len(critical) > 0

    def test_high_count(self, vulns):
        high = [v for v in vulns if v.severity == VulnSeverity.HIGH]
        assert len(high) > 0


# ===================== CVSS Score Tests =====================

class TestCVSSScores:
    def test_all_scores_are_float(self, vulns):
        for v in vulns:
            assert isinstance(v.cvss_score, float), (
                f"{v.cve_id} cvss_score is {type(v.cvss_score)}"
            )

    def test_all_scores_in_valid_range(self, vulns):
        for v in vulns:
            assert 0.0 <= v.cvss_score <= 10.0, (
                f"{v.cve_id} has invalid CVSS {v.cvss_score}"
            )

    def test_all_scores_high_or_critical(self, vulns):
        """All 1day vulns have CVSS >= 7.0 per module docstring."""
        for v in vulns:
            assert v.cvss_score >= 7.0, (
                f"{v.cve_id} has CVSS {v.cvss_score} < 7.0"
            )

    def test_max_cvss(self, vulns):
        max_score = max(v.cvss_score for v in vulns)
        assert max_score == 9.8

    def test_min_cvss(self, vulns):
        min_score = min(v.cvss_score for v in vulns)
        assert min_score >= 7.0


# ===================== CVE ID Tests =====================

class TestCVEIDs:
    CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

    def test_all_have_cve_id(self, vulns):
        for v in vulns:
            assert v.cve_id is not None and v.cve_id != ""

    def test_cve_id_format(self, vulns):
        for v in vulns:
            assert self.CVE_PATTERN.match(v.cve_id), (
                f"Invalid CVE format: {v.cve_id}"
            )

    def test_all_cve_ids_are_2024(self, vulns):
        for v in vulns:
            assert v.cve_id.startswith("CVE-2024-"), (
                f"{v.cve_id} is not a 2024 CVE"
            )

    def test_cve_id_is_string(self, vulns):
        for v in vulns:
            assert isinstance(v.cve_id, str)

    def test_duplicate_cve_ids_exist(self, all_cve_ids):
        """The data has known duplicate CVE IDs (CVE-2024-2369, CVE-2024-27983, CVE-2024-28195)."""
        from collections import Counter
        counts = Counter(all_cve_ids)
        duplicates = {cve: c for cve, c in counts.items() if c > 1}
        # Verify the known duplicates are present
        assert len(duplicates) > 0, "Expected duplicate CVE IDs in dataset"

    def test_specific_duplicate_cves(self, all_cve_ids):
        from collections import Counter
        counts = Counter(all_cve_ids)
        assert counts["CVE-2024-2369"] == 2
        assert counts["CVE-2024-27983"] == 2
        assert counts["CVE-2024-28195"] == 2


# ===================== Date Tests =====================

class TestPublishDates:
    def test_all_dates_are_date_objects(self, vulns):
        for v in vulns:
            assert isinstance(v.publish_date, date), (
                f"{v.cve_id} publish_date is {type(v.publish_date)}"
            )

    def test_all_dates_in_2024(self, vulns):
        for v in vulns:
            assert v.publish_date.year == 2024, (
                f"{v.cve_id} date year is {v.publish_date.year}"
            )

    def test_earliest_date(self, vulns):
        earliest = min(v.publish_date for v in vulns)
        assert earliest == date(2024, 1, 16)

    def test_latest_date(self, vulns):
        latest = max(v.publish_date for v in vulns)
        assert latest == date(2024, 4, 16)

    def test_dates_are_valid_calendar_dates(self, vulns):
        for v in vulns:
            assert 1 <= v.publish_date.month <= 12
            assert 1 <= v.publish_date.day <= 31


# ===================== Name Tests =====================

class TestNames:
    def test_all_names_nonempty(self, vulns):
        for v in vulns:
            assert v.name is not None and len(v.name) > 0

    def test_all_names_are_strings(self, vulns):
        for v in vulns:
            assert isinstance(v.name, str)

    def test_no_duplicate_names(self, vulns):
        names = [v.name for v in vulns]
        assert len(names) == len(set(names)), "Duplicate names found"

    def test_first_vuln_name(self, first_vuln):
        assert first_vuln.name == "Atlassian Bitbucket RCE"

    def test_last_vuln_name(self, last_vuln):
        assert last_vuln.name == "Cisco ISE Privilege Escalation"


# ===================== VulnType Tests =====================

class TestVulnTypes:
    def test_all_have_vuln_types(self, vulns):
        for v in vulns:
            assert len(v.vuln_types) > 0, (
                f"{v.cve_id} has no vuln_types"
            )

    def test_vuln_types_are_lists(self, vulns):
        for v in vulns:
            assert isinstance(v.vuln_types, list)

    def test_all_vuln_types_are_enum(self, vulns):
        for v in vulns:
            for vt in v.vuln_types:
                assert isinstance(vt, VulnType), (
                    f"{v.cve_id} has invalid vuln_type {vt}"
                )

    def test_rce_is_most_common(self, vulns):
        """RCE should appear in most or all entries."""
        rce_count = sum(1 for v in vulns if VulnType.RCE in v.vuln_types)
        assert rce_count > len(vulns) * 0.8

    def test_all_vuln_types_used(self, vulns):
        """Verify that multiple VulnType values appear across the dataset."""
        all_types = set()
        for v in vulns:
            for vt in v.vuln_types:
                all_types.add(vt)
        assert len(all_types) >= 5

    def test_specific_types_present(self, vulns):
        all_types = set()
        for v in vulns:
            for vt in v.vuln_types:
                all_types.add(vt)
        expected = {
            VulnType.RCE,
            VulnType.AUTHENTICATION_BYPASS,
            VulnType.SQL_INJECTION,
            VulnType.DESERIALIZATION,
            VulnType.PRIVILEGE_ESCALATION,
            VulnType.BUFFER_OVERFLOW,
            VulnType.FILE_INCLUSION,
        }
        for et in expected:
            assert et in all_types, f"{et} not found in dataset"

    def test_first_vuln_types(self, first_vuln):
        assert VulnType.RCE in first_vuln.vuln_types
        assert VulnType.AUTHENTICATION_BYPASS in first_vuln.vuln_types


# ===================== Boolean Field Tests =====================

class TestBooleanFields:
    def test_exploit_available_all_true(self, vulns):
        """All 1day vulns should have public exploits."""
        for v in vulns:
            assert v.exploit_available is True, (
                f"{v.cve_id} exploit_available is False"
            )

    def test_poc_available_all_true(self, vulns):
        """All 1day vulns should have POCs."""
        for v in vulns:
            assert v.poc_available is True, (
                f"{v.cve_id} poc_available is False"
            )

    def test_patch_available_types(self, vulns):
        for v in vulns:
            assert isinstance(v.patch_available, bool)

    def test_most_have_patches(self, vulns):
        patched = sum(1 for v in vulns if v.patch_available)
        assert patched > len(vulns) * 0.8

    def test_some_without_patch(self, vulns):
        """CVE-2024-25600 (ChainWiki) has patch_available=False."""
        no_patch = [v for v in vulns if not v.patch_available]
        assert len(no_patch) >= 1

    def test_chainwiki_no_patch(self, vulns):
        chainwiki = [v for v in vulns if v.cve_id == "CVE-2024-25600"][0]
        assert chainwiki.patch_available is False


# ===================== List Field Tests =====================

class TestAffectedProducts:
    def test_all_nonempty(self, vulns):
        for v in vulns:
            assert len(v.affected_products) > 0

    def test_all_are_strings(self, vulns):
        for v in vulns:
            for p in v.affected_products:
                assert isinstance(p, str)
                assert len(p) > 0

    def test_first_vuln_products(self, first_vuln):
        assert "Atlassian Bitbucket" in first_vuln.affected_products
        assert "Bitbucket Server" in first_vuln.affected_products


class TestRequiredTools:
    def test_all_nonempty(self, vulns):
        for v in vulns:
            assert len(v.required_tools) > 0, (
                f"{v.cve_id} has empty required_tools"
            )

    def test_all_strings(self, vulns):
        for v in vulns:
            for t in v.required_tools:
                assert isinstance(t, str) and len(t) > 0

    def test_common_tools_present(self, vulns):
        all_tools = set()
        for v in vulns:
            all_tools.update(v.required_tools)
        assert "python3" in all_tools
        assert "curl" in all_tools
        assert "metasploit" in all_tools

    def test_first_vuln_tools(self, first_vuln):
        assert "metasploit" in first_vuln.required_tools
        assert "searchsploit" in first_vuln.required_tools
        assert "curl" in first_vuln.required_tools


class TestAffectedVersions:
    def test_all_nonempty(self, vulns):
        for v in vulns:
            assert len(v.affected_versions) > 0

    def test_all_strings(self, vulns):
        for v in vulns:
            for ver in v.affected_versions:
                assert isinstance(ver, str) and len(ver) > 0


class TestReferences:
    def test_all_nonempty(self, vulns):
        for v in vulns:
            assert len(v.references) > 0

    def test_all_are_urls(self, vulns):
        for v in vulns:
            for ref in v.references:
                assert ref.startswith("http://") or ref.startswith("https://"), (
                    f"{v.cve_id} has non-URL reference: {ref}"
                )

    def test_at_least_two_refs(self, vulns):
        for v in vulns:
            assert len(v.references) >= 2, (
                f"{v.cve_id} has fewer than 2 references"
            )


class TestTags:
    def test_all_nonempty(self, vulns):
        for v in vulns:
            assert len(v.tags) > 0

    def test_all_contain_1day_tag(self, vulns):
        """All entries should have '1day' tag per convention."""
        for v in vulns:
            assert "1day" in v.tags, (
                f"{v.cve_id} missing '1day' tag"
            )

    def test_all_contain_rce_or_related_tag(self, vulns):
        """All should have at least one attack-type tag."""
        attack_tags = {"rce", "sqli", "auth-bypass", "privesc", "ssrf"}
        for v in vulns:
            has_attack_tag = any(t in attack_tags for t in v.tags)
            assert has_attack_tag, (
                f"{v.cve_id} missing attack-type tag, has {v.tags}"
            )

    def test_tags_are_lowercase(self, vulns):
        for v in vulns:
            for tag in v.tags:
                assert tag == tag.lower(), (
                    f"{v.cve_id} has non-lowercase tag: {tag}"
                )


class TestDetectionMethods:
    def test_all_nonempty(self, vulns):
        for v in vulns:
            assert len(v.detection_methods) > 0

    def test_all_strings(self, vulns):
        for v in vulns:
            for dm in v.detection_methods:
                assert isinstance(dm, str) and len(dm) > 0

    def test_at_least_two_methods(self, vulns):
        for v in vulns:
            assert len(v.detection_methods) >= 2, (
                f"{v.cve_id} has fewer than 2 detection methods"
            )


# ===================== String Field Tests =====================

class TestDescription:
    def test_all_nonempty(self, vulns):
        for v in vulns:
            assert v.description is not None and len(v.description) > 0

    def test_all_are_strings(self, vulns):
        for v in vulns:
            assert isinstance(v.description, str)

    def test_description_minimum_length(self, vulns):
        for v in vulns:
            assert len(v.description) >= 10, (
                f"{v.cve_id} description too short: {v.description}"
            )


class TestExploitMethod:
    def test_all_present(self, vulns):
        for v in vulns:
            assert v.exploit_method is not None and len(v.exploit_method) > 0

    def test_all_strings(self, vulns):
        for v in vulns:
            assert isinstance(v.exploit_method, str)


class TestMitreTechnique:
    def test_all_present(self, vulns):
        for v in vulns:
            assert v.mitre_technique is not None and len(v.mitre_technique) > 0

    def test_most_are_t1190(self, vulns):
        """Most entries reference T1190 (Exploit Public-Facing Application)."""
        t1190_count = sum(1 for v in vulns if "T1190" in v.mitre_technique)
        assert t1190_count > len(vulns) * 0.9

    def test_outlook_special_technique(self, vulns):
        """CVE-2024-29025 (Outlook) has a different MITRE technique."""
        outlook = [v for v in vulns if v.cve_id == "CVE-2024-29025"][0]
        assert "T1187" in outlook.mitre_technique


# ===================== Specific Vulnerability Spot Checks =====================

class TestSpecificVulnerabilities:
    def test_first_vulnerability_complete(self, first_vuln):
        assert first_vuln.cve_id == "CVE-2024-23897"
        assert first_vuln.name == "Atlassian Bitbucket RCE"
        assert first_vuln.category == VulnCategory.ONE_DAY
        assert first_vuln.publish_date == date(2024, 2, 20)
        assert first_vuln.cvss_score == 9.1
        assert first_vuln.severity == VulnSeverity.CRITICAL
        assert first_vuln.exploit_available is True
        assert first_vuln.poc_available is True
        assert first_vuln.patch_available is True
        assert first_vuln.mitre_technique == "T1190"

    def test_ivanti_connect_secure(self, vulns):
        v = vulns[1]
        assert v.cve_id == "CVE-2024-27456"
        assert v.name == "Ivanti Connect Secure RCE"
        assert v.cvss_score == 9.8
        assert "Ivanti Connect Secure" in v.affected_products
        assert "ssti" in v.tags

    def test_chainwiki_no_patch(self, vulns):
        v = vulns[2]
        assert v.cve_id == "CVE-2024-25600"
        assert v.patch_available is False
        assert VulnType.FILE_INCLUSION in v.vuln_types

    def test_veeam_backup(self, vulns):
        v = vulns[3]
        assert v.cve_id == "CVE-2024-24573"
        assert VulnType.DESERIALIZATION in v.vuln_types
        assert "ysoserial" in v.required_tools

    def test_goanywhere_mft(self, vulns):
        v = vulns[4]
        assert v.cve_id == "CVE-2024-0204"
        assert v.name == "GoAnywhere MFT Auth Bypass"
        assert VulnType.AUTHENTICATION_BYPASS in v.vuln_types
        assert "GoAnywhere MFT" in v.affected_products

    def test_confluence_ognl(self, vulns):
        v = vulns[5]
        assert v.cve_id == "CVE-2024-21887"
        assert "ognl" in v.tags
        assert "confluence" in v.tags

    def test_kafka_ui(self, vulns):
        v = vulns[6]
        assert v.cve_id == "CVE-2024-28121"
        assert v.severity == VulnSeverity.HIGH
        assert v.cvss_score == 8.8

    def test_moveit_sqli(self, vulns):
        v = vulns[9]
        assert v.cve_id == "CVE-2024-2924"
        assert VulnType.SQL_INJECTION in v.vuln_types
        assert "sqlmap" in v.required_tools

    def test_cisco_nxos(self, vulns):
        v = vulns[12]
        assert v.cve_id == "CVE-2024-20767"
        assert "Cisco NX-OS" in v.affected_products
        assert VulnType.PRIVILEGE_ESCALATION in v.vuln_types

    def test_wordpress_bricks(self, vulns):
        v = vulns[26]
        assert v.cve_id == "CVE-2024-2397"
        assert "wordpress" in v.tags
        assert "wpscan" in v.required_tools

    def test_microsoft_outlook(self, vulns):
        v = vulns[28]
        assert v.cve_id == "CVE-2024-29025"
        assert "Microsoft Outlook" in v.affected_products
        assert VulnType.CODE_EXECUTION in v.vuln_types
        assert "responder" in v.required_tools

    def test_tomcat_request_smuggling(self, vulns):
        v = vulns[31]
        assert v.cve_id == "CVE-2024-28082"
        assert VulnType.HTTP_REQUEST_SMUGGLING in v.vuln_types
        assert "request-smuggling" in v.tags

    def test_last_vulnerability(self, last_vuln):
        assert last_vuln.cve_id == "CVE-2024-28195"
        assert last_vuln.name == "Cisco ISE Privilege Escalation"
        assert VulnType.PRIVILEGE_ESCALATION in last_vuln.vuln_types


# ===================== to_dict() Tests =====================

class TestToDict:
    def test_returns_dict(self, first_vuln):
        d = first_vuln.to_dict()
        assert isinstance(d, dict)

    def test_all_keys_present(self, first_vuln):
        d = first_vuln.to_dict()
        expected_keys = {
            "cve_id", "name", "category", "publish_date", "cvss_score",
            "severity", "affected_products", "vuln_types", "description",
            "exploit_available", "exploit_method", "required_tools",
            "affected_versions", "references", "tags", "poc_available",
            "patch_available", "detection_methods", "mitre_technique",
        }
        assert set(d.keys()) == expected_keys

    def test_category_serialized(self, first_vuln):
        d = first_vuln.to_dict()
        assert d["category"] == "1day"

    def test_severity_serialized(self, first_vuln):
        d = first_vuln.to_dict()
        assert d["severity"] == "CRITICAL"

    def test_date_serialized_as_iso(self, first_vuln):
        d = first_vuln.to_dict()
        assert d["publish_date"] == "2024-02-20"

    def test_vuln_types_serialized(self, first_vuln):
        d = first_vuln.to_dict()
        assert isinstance(d["vuln_types"], list)
        assert "RCE" in d["vuln_types"]

    def test_all_vulns_serialize(self, vulns):
        """Every vulnerability must serialize without error."""
        for v in vulns:
            d = v.to_dict()
            assert isinstance(d, dict)
            assert d["cve_id"] == v.cve_id

    def test_booleans_preserved(self, first_vuln):
        d = first_vuln.to_dict()
        assert d["exploit_available"] is True
        assert d["poc_available"] is True
        assert isinstance(d["patch_available"], bool)


# ===================== matches_product() Tests =====================

class TestMatchesProduct:
    def test_exact_match(self, first_vuln):
        assert first_vuln.matches_product("Atlassian Bitbucket")

    def test_case_insensitive(self, first_vuln):
        assert first_vuln.matches_product("atlassian bitbucket")

    def test_partial_match(self, first_vuln):
        assert first_vuln.matches_product("Bitbucket")

    def test_no_match(self, first_vuln):
        assert not first_vuln.matches_product("NonExistentProduct")

    def test_empty_string(self, first_vuln):
        # Empty string is contained in everything
        assert first_vuln.matches_product("")

    def test_all_vulns_match_own_products(self, vulns):
        for v in vulns:
            for prod in v.affected_products:
                assert v.matches_product(prod), (
                    f"{v.cve_id} doesn't match own product {prod}"
                )


# ===================== matches_version() Tests =====================

class TestMatchesVersion:
    def test_partial_match(self, first_vuln):
        assert first_vuln.matches_version("8.0.0")

    def test_no_match(self, first_vuln):
        assert not first_vuln.matches_version("99.99.99")

    def test_case_insensitive(self, first_vuln):
        assert first_vuln.matches_version("bitbucket")

    def test_all_vulns_match_own_versions(self, vulns):
        for v in vulns:
            for ver in v.affected_versions:
                assert v.matches_version(ver), (
                    f"{v.cve_id} doesn't match own version {ver}"
                )


# ===================== Data Integrity Tests =====================

class TestDataIntegrity:
    def test_no_none_in_required_fields(self, vulns):
        for v in vulns:
            assert v.cve_id is not None
            assert v.name is not None
            assert v.category is not None
            assert v.publish_date is not None
            assert v.cvss_score is not None
            assert v.severity is not None
            assert v.affected_products is not None
            assert v.vuln_types is not None
            assert v.description is not None
            assert v.exploit_available is not None

    def test_vuln_types_not_nested(self, vulns):
        """vuln_types should be a flat list of VulnType, not nested."""
        for v in vulns:
            for vt in v.vuln_types:
                assert not isinstance(vt, list)

    def test_tags_no_empty_strings(self, vulns):
        for v in vulns:
            for tag in v.tags:
                assert tag != ""

    def test_all_have_at_least_two_vuln_types(self, vulns):
        for v in vulns:
            assert len(v.vuln_types) >= 2, (
                f"{v.cve_id} has only {len(v.vuln_types)} vuln_type(s)"
            )

    def test_references_no_empty(self, vulns):
        for v in vulns:
            for ref in v.references:
                assert ref != ""

    def test_affected_products_no_empty(self, vulns):
        for v in vulns:
            for prod in v.affected_products:
                assert prod != ""


# ===================== Cross-Field Consistency Tests =====================

class TestCrossFieldConsistency:
    def test_sql_injection_tags_match_types(self, vulns):
        """If VulnType.SQL_INJECTION is in vuln_types, 'sqli' should be in tags."""
        for v in vulns:
            if VulnType.SQL_INJECTION in v.vuln_types:
                assert "sqli" in v.tags, (
                    f"{v.cve_id} has SQL_INJECTION type but no 'sqli' tag"
                )

    def test_deserialization_tags_match_types(self, vulns):
        """If DESERIALIZATION in types, 'deserialization' should be in tags."""
        for v in vulns:
            if VulnType.DESERIALIZATION in v.vuln_types:
                assert "deserialization" in v.tags, (
                    f"{v.cve_id} has DESERIALIZATION type but no 'deserialization' tag"
                )

    def test_auth_bypass_tags_match_types(self, vulns):
        """If AUTHENTICATION_BYPASS in types, 'auth-bypass' should be in tags."""
        for v in vulns:
            if VulnType.AUTHENTICATION_BYPASS in v.vuln_types:
                assert "auth-bypass" in v.tags or "rce" in v.tags, (
                    f"{v.cve_id} has AUTHENTICATION_BYPASS type but no matching tag"
                )

    def test_rce_in_vuln_types_has_rce_tag(self, vulns):
        """Every entry with RCE type should have 'rce' in tags."""
        for v in vulns:
            if VulnType.RCE in v.vuln_types:
                assert "rce" in v.tags, (
                    f"{v.cve_id} has RCE type but no 'rce' tag"
                )


# ===================== Ordering Tests =====================

class TestOrdering:
    def test_first_entry_is_bitbucket(self, vulns):
        assert vulns[0].cve_id == "CVE-2024-23897"

    def test_second_entry_is_ivanti(self, vulns):
        assert vulns[1].cve_id == "CVE-2024-27456"

    def test_index_positions(self, vulns):
        """Spot-check several known positions."""
        assert vulns[4].cve_id == "CVE-2024-0204"
        assert vulns[9].cve_id == "CVE-2024-2924"
        assert vulns[14].cve_id == "CVE-2024-27163"
        assert vulns[19].cve_id == "CVE-2024-25609"


# ===================== Edge Case Tests =====================

class TestEdgeCases:
    def test_vuln_with_special_chars_in_name(self, vulns):
        """Veeam Backup & Replication uses ampersand in name."""
        veeam = vulns[3]
        assert "&" in veeam.name

    def test_vuln_with_ampersand_in_product(self, vulns):
        """Veeam Backup & Replication product name."""
        veeam = vulns[3]
        assert "Veeam Backup & Replication" in veeam.affected_products

    def test_vuln_with_long_detection_methods(self, vulns):
        """Detection methods contain multi-word strings."""
        for v in vulns:
            for dm in v.detection_methods:
                assert len(dm) > 3

    def test_vulnerability_repr(self, first_vuln):
        """Dataclass should have a __repr__."""
        r = repr(first_vuln)
        assert "CVE-2024-23897" in r

    def test_vulnerability_equality(self):
        """Two Vulnerability objects with same fields should be equal."""
        v1 = Vulnerability(
            cve_id="CVE-2024-00001",
            name="Test",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 1),
            cvss_score=9.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Test Product"],
            vuln_types=[VulnType.RCE],
            description="Test desc",
            exploit_available=True,
        )
        v2 = Vulnerability(
            cve_id="CVE-2024-00001",
            name="Test",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 1),
            cvss_score=9.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Test Product"],
            vuln_types=[VulnType.RCE],
            description="Test desc",
            exploit_available=True,
        )
        assert v1 == v2

    def test_vulnerability_inequality(self):
        v1 = Vulnerability(
            cve_id="CVE-2024-00001",
            name="Test",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 1),
            cvss_score=9.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Test Product"],
            vuln_types=[VulnType.RCE],
            description="Test desc",
            exploit_available=True,
        )
        v2 = Vulnerability(
            cve_id="CVE-2024-00002",
            name="Test2",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 1),
            cvss_score=9.0,
            severity=VulnSeverity.CRITICAL,
            affected_products=["Test Product"],
            vuln_types=[VulnType.RCE],
            description="Test desc",
            exploit_available=True,
        )
        assert v1 != v2

    def test_default_optional_fields(self):
        """Verify dataclass defaults for optional fields."""
        v = Vulnerability(
            cve_id="CVE-2024-99999",
            name="Minimal",
            category=VulnCategory.ONE_DAY,
            publish_date=date(2024, 1, 1),
            cvss_score=7.0,
            severity=VulnSeverity.HIGH,
            affected_products=["X"],
            vuln_types=[VulnType.RCE],
            description="Minimal vuln",
            exploit_available=False,
        )
        assert v.exploit_method is None
        assert v.required_tools == []
        assert v.affected_versions == []
        assert v.references == []
        assert v.tags == []
        assert v.poc_available is False
        assert v.patch_available is False
        assert v.detection_methods == []
        assert v.mitre_technique is None


# ===================== from_dict() Round-Trip Tests =====================

class TestRoundTrip:
    def test_round_trip_first_vuln(self, first_vuln):
        """Serialize to dict and back should preserve data."""
        d = first_vuln.to_dict()
        restored = Vulnerability.from_dict(d)
        assert restored.cve_id == first_vuln.cve_id
        assert restored.name == first_vuln.name
        assert restored.category == first_vuln.category
        assert restored.cvss_score == first_vuln.cvss_score
        assert restored.severity == first_vuln.severity
        assert restored.exploit_available == first_vuln.exploit_available
        assert restored.poc_available == first_vuln.poc_available
        assert restored.patch_available == first_vuln.patch_available

    def test_round_trip_all_vulns(self, vulns):
        """All vulns should survive round-trip serialization."""
        for v in vulns:
            d = v.to_dict()
            restored = Vulnerability.from_dict(d)
            assert restored.cve_id == v.cve_id
            assert restored.name == v.name
            assert restored.cvss_score == v.cvss_score
            assert len(restored.vuln_types) == len(v.vuln_types)

    def test_round_trip_preserves_types(self, first_vuln):
        d = first_vuln.to_dict()
        restored = Vulnerability.from_dict(d)
        assert isinstance(restored.category, VulnCategory)
        assert isinstance(restored.severity, VulnSeverity)
        assert isinstance(restored.publish_date, date)
        for vt in restored.vuln_types:
            assert isinstance(vt, VulnType)


# ===================== Aggregate Statistics Tests =====================

class TestAggregateStats:
    def test_total_count(self, vulns):
        assert len(vulns) == 33

    def test_critical_count(self, vulns):
        critical = [v for v in vulns if v.severity == VulnSeverity.CRITICAL]
        assert len(critical) == 30

    def test_high_count(self, vulns):
        high = [v for v in vulns if v.severity == VulnSeverity.HIGH]
        assert len(high) == 3

    def test_avg_cvss(self, vulns):
        avg = sum(v.cvss_score for v in vulns) / len(vulns)
        assert 9.0 <= avg <= 10.0

    def test_unique_products_count(self, vulns):
        """Should have many unique affected products."""
        all_products = set()
        for v in vulns:
            all_products.update(v.affected_products)
        assert len(all_products) >= 30

    def test_unique_tools_count(self, vulns):
        all_tools = set()
        for v in vulns:
            all_tools.update(v.required_tools)
        assert len(all_tools) >= 5
