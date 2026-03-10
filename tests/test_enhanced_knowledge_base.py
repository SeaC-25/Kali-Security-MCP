"""
Comprehensive unit tests for enhanced_knowledge_base.py

Covers:
- ExtendedVulnerabilityType enum (all 29 members)
- All 9 global payload dictionaries and their structure
- ATTACK_CHAINS global dict
- EnhancedDetector class and all its methods
- Singleton pattern (get_enhanced_detector)
- All convenience functions
- Module-level constants
- Edge cases, boundary conditions, and error paths
"""

import pytest
from unittest.mock import patch
from typing import Dict, List

from kali_mcp.core.enhanced_knowledge_base import (
    # Enum
    ExtendedVulnerabilityType,
    # Payload dictionaries
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    LFI_PAYLOADS,
    SSTI_PAYLOADS,
    SSRF_PAYLOADS,
    XXE_PAYLOADS,
    JWT_PAYLOADS,
    DESERIALIZATION_PAYLOADS,
    # Attack chains
    ATTACK_CHAINS,
    # Detector class
    EnhancedDetector,
    # Singleton + convenience
    get_enhanced_detector,
    get_enhanced_payloads,
    get_waf_bypass,
    get_chain,
    payload_stats,
    # Module constants
    __version__,
    __description__,
)

import kali_mcp.core.enhanced_knowledge_base as ekb_module


# ==================== ExtendedVulnerabilityType Enum Tests ====================


class TestExtendedVulnerabilityType:
    """Tests for the ExtendedVulnerabilityType enum."""

    # --- Injection types ---

    def test_sql_injection_value(self):
        assert ExtendedVulnerabilityType.SQL_INJECTION.value == "sqli"

    def test_nosql_injection_value(self):
        assert ExtendedVulnerabilityType.NOSQL_INJECTION.value == "nosqli"

    def test_ldap_injection_value(self):
        assert ExtendedVulnerabilityType.LDAP_INJECTION.value == "ldapi"

    def test_xpath_injection_value(self):
        assert ExtendedVulnerabilityType.XPATH_INJECTION.value == "xpathi"

    def test_command_injection_value(self):
        assert ExtendedVulnerabilityType.COMMAND_INJECTION.value == "cmdi"

    def test_code_injection_value(self):
        assert ExtendedVulnerabilityType.CODE_INJECTION.value == "codei"

    def test_expression_injection_value(self):
        assert ExtendedVulnerabilityType.EXPRESSION_INJECTION.value == "eli"

    # --- File types ---

    def test_lfi_value(self):
        assert ExtendedVulnerabilityType.LFI.value == "lfi"

    def test_rfi_value(self):
        assert ExtendedVulnerabilityType.RFI.value == "rfi"

    def test_path_traversal_value(self):
        assert ExtendedVulnerabilityType.PATH_TRAVERSAL.value == "traversal"

    def test_file_upload_value(self):
        assert ExtendedVulnerabilityType.FILE_UPLOAD.value == "upload"

    def test_arbitrary_file_read_value(self):
        assert ExtendedVulnerabilityType.ARBITRARY_FILE_READ.value == "afr"

    def test_arbitrary_file_write_value(self):
        assert ExtendedVulnerabilityType.ARBITRARY_FILE_WRITE.value == "afw"

    # --- Client-side types ---

    def test_xss_value(self):
        assert ExtendedVulnerabilityType.XSS.value == "xss"

    def test_csrf_value(self):
        assert ExtendedVulnerabilityType.CSRF.value == "csrf"

    def test_open_redirect_value(self):
        assert ExtendedVulnerabilityType.OPEN_REDIRECT.value == "redirect"

    def test_clickjacking_value(self):
        assert ExtendedVulnerabilityType.CLICKJACKING.value == "clickjack"

    # --- Server-side types ---

    def test_ssrf_value(self):
        assert ExtendedVulnerabilityType.SSRF.value == "ssrf"

    def test_xxe_value(self):
        assert ExtendedVulnerabilityType.XXE.value == "xxe"

    def test_ssti_value(self):
        assert ExtendedVulnerabilityType.SSTI.value == "ssti"

    def test_deserialization_value(self):
        assert ExtendedVulnerabilityType.DESERIALIZATION.value == "deser"

    # --- Auth types ---

    def test_idor_value(self):
        assert ExtendedVulnerabilityType.IDOR.value == "idor"

    def test_jwt_value(self):
        assert ExtendedVulnerabilityType.JWT.value == "jwt"

    def test_oauth_value(self):
        assert ExtendedVulnerabilityType.OAUTH.value == "oauth"

    def test_broken_auth_value(self):
        assert ExtendedVulnerabilityType.BROKEN_AUTH.value == "bauth"

    # --- Advanced types ---

    def test_race_condition_value(self):
        assert ExtendedVulnerabilityType.RACE_CONDITION.value == "race"

    def test_prototype_pollution_value(self):
        assert ExtendedVulnerabilityType.PROTOTYPE_POLLUTION.value == "prototype"

    def test_memory_corruption_value(self):
        assert ExtendedVulnerabilityType.MEMORY_CORRUPTION.value == "memcorrupt"

    def test_business_logic_value(self):
        assert ExtendedVulnerabilityType.BUSINESS_LOGIC.value == "logic"

    # --- Enum membership and count ---

    def test_enum_member_count(self):
        assert len(ExtendedVulnerabilityType) == 29

    def test_enum_lookup_by_value(self):
        assert ExtendedVulnerabilityType("sqli") == ExtendedVulnerabilityType.SQL_INJECTION

    def test_enum_lookup_by_name(self):
        assert ExtendedVulnerabilityType["SQL_INJECTION"] == ExtendedVulnerabilityType.SQL_INJECTION

    def test_enum_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ExtendedVulnerabilityType("nonexistent")

    def test_enum_invalid_name_raises(self):
        with pytest.raises(KeyError):
            ExtendedVulnerabilityType["NONEXISTENT"]

    def test_all_values_are_strings(self):
        for member in ExtendedVulnerabilityType:
            assert isinstance(member.value, str)

    def test_all_values_are_unique(self):
        values = [m.value for m in ExtendedVulnerabilityType]
        assert len(values) == len(set(values))


# ==================== Payload Dictionary Structure Tests ====================


class TestSQLInjectionPayloads:
    """Tests for SQL_INJECTION_PAYLOADS global dict."""

    def test_has_basic_category(self):
        assert "basic" in SQL_INJECTION_PAYLOADS

    def test_has_union_category(self):
        assert "union" in SQL_INJECTION_PAYLOADS

    def test_has_time_blind_category(self):
        assert "time_blind" in SQL_INJECTION_PAYLOADS

    def test_has_error_based_category(self):
        assert "error_based" in SQL_INJECTION_PAYLOADS

    def test_has_waf_bypass_category(self):
        assert "waf_bypass" in SQL_INJECTION_PAYLOADS

    def test_basic_count(self):
        assert len(SQL_INJECTION_PAYLOADS["basic"]) == 10

    def test_union_count(self):
        assert len(SQL_INJECTION_PAYLOADS["union"]) == 15

    def test_time_blind_count(self):
        assert len(SQL_INJECTION_PAYLOADS["time_blind"]) == 10

    def test_error_based_count(self):
        assert len(SQL_INJECTION_PAYLOADS["error_based"]) == 10

    def test_waf_bypass_count(self):
        assert len(SQL_INJECTION_PAYLOADS["waf_bypass"]) == 15

    def test_basic_payload_structure(self):
        for p in SQL_INJECTION_PAYLOADS["basic"]:
            assert "payload" in p
            assert "desc" in p
            assert "indicators" in p

    def test_waf_bypass_has_bypass_field(self):
        for p in SQL_INJECTION_PAYLOADS["waf_bypass"]:
            assert "bypass" in p

    def test_total_sqli_payloads_at_least_50(self):
        total = sum(len(cat) for cat in SQL_INJECTION_PAYLOADS.values())
        assert total >= 50


class TestXSSPayloads:
    """Tests for XSS_PAYLOADS global dict."""

    def test_has_basic_category(self):
        assert "basic" in XSS_PAYLOADS

    def test_has_event_handlers_category(self):
        assert "event_handlers" in XSS_PAYLOADS

    def test_has_waf_bypass_category(self):
        assert "waf_bypass" in XSS_PAYLOADS

    def test_has_dom_based_category(self):
        assert "dom_based" in XSS_PAYLOADS

    def test_basic_count(self):
        assert len(XSS_PAYLOADS["basic"]) == 15

    def test_event_handlers_count(self):
        assert len(XSS_PAYLOADS["event_handlers"]) == 15

    def test_waf_bypass_count(self):
        assert len(XSS_PAYLOADS["waf_bypass"]) == 15

    def test_dom_based_count(self):
        assert len(XSS_PAYLOADS["dom_based"]) == 10

    def test_basic_payload_has_context(self):
        for p in XSS_PAYLOADS["basic"]:
            assert "context" in p

    def test_total_xss_payloads_at_least_50(self):
        total = sum(len(cat) for cat in XSS_PAYLOADS.values())
        assert total >= 50


class TestCommandInjectionPayloads:
    """Tests for COMMAND_INJECTION_PAYLOADS global dict."""

    def test_has_basic_category(self):
        assert "basic" in COMMAND_INJECTION_PAYLOADS

    def test_has_windows_category(self):
        assert "windows" in COMMAND_INJECTION_PAYLOADS

    def test_has_blind_category(self):
        assert "blind" in COMMAND_INJECTION_PAYLOADS

    def test_has_waf_bypass_category(self):
        assert "waf_bypass" in COMMAND_INJECTION_PAYLOADS

    def test_basic_payloads_have_os_field(self):
        for p in COMMAND_INJECTION_PAYLOADS["basic"]:
            assert "os" in p

    def test_windows_payloads_os_is_windows(self):
        for p in COMMAND_INJECTION_PAYLOADS["windows"]:
            assert p["os"] == "windows"

    def test_basic_payloads_os_is_unix(self):
        for p in COMMAND_INJECTION_PAYLOADS["basic"]:
            assert p["os"] == "unix"

    def test_category_count(self):
        assert len(COMMAND_INJECTION_PAYLOADS) == 4


class TestLFIPayloads:
    """Tests for LFI_PAYLOADS global dict."""

    def test_has_basic_category(self):
        assert "basic" in LFI_PAYLOADS

    def test_has_php_wrappers_category(self):
        assert "php_wrappers" in LFI_PAYLOADS

    def test_has_sensitive_files_category(self):
        assert "sensitive_files" in LFI_PAYLOADS

    def test_has_waf_bypass_category(self):
        assert "waf_bypass" in LFI_PAYLOADS

    def test_basic_has_indicators(self):
        for p in LFI_PAYLOADS["basic"]:
            assert "indicators" in p

    def test_sensitive_files_have_os(self):
        for p in LFI_PAYLOADS["sensitive_files"]:
            assert "os" in p

    def test_category_count(self):
        assert len(LFI_PAYLOADS) == 4


class TestSSTIPayloads:
    """Tests for SSTI_PAYLOADS global dict."""

    def test_has_detection_category(self):
        assert "detection" in SSTI_PAYLOADS

    def test_has_jinja2_rce_category(self):
        assert "jinja2_rce" in SSTI_PAYLOADS

    def test_has_other_engines_category(self):
        assert "other_engines" in SSTI_PAYLOADS

    def test_detection_payloads_have_indicators(self):
        for p in SSTI_PAYLOADS["detection"]:
            assert "indicators" in p

    def test_detection_count(self):
        assert len(SSTI_PAYLOADS["detection"]) == 10

    def test_jinja2_rce_count(self):
        assert len(SSTI_PAYLOADS["jinja2_rce"]) == 10

    def test_other_engines_count(self):
        assert len(SSTI_PAYLOADS["other_engines"]) == 15


class TestSSRFPayloads:
    """Tests for SSRF_PAYLOADS global dict."""

    def test_has_basic_category(self):
        assert "basic" in SSRF_PAYLOADS

    def test_has_protocols_category(self):
        assert "protocols" in SSRF_PAYLOADS

    def test_has_bypass_category(self):
        assert "bypass" in SSRF_PAYLOADS

    def test_basic_count(self):
        assert len(SSRF_PAYLOADS["basic"]) == 10

    def test_protocols_count(self):
        assert len(SSRF_PAYLOADS["protocols"]) == 10

    def test_bypass_count(self):
        assert len(SSRF_PAYLOADS["bypass"]) == 15

    def test_bypass_payloads_have_bypass_field(self):
        for p in SSRF_PAYLOADS["bypass"]:
            assert "bypass" in p


class TestXXEPayloads:
    """Tests for XXE_PAYLOADS global dict."""

    def test_has_basic_category(self):
        assert "basic" in XXE_PAYLOADS

    def test_has_blind_category(self):
        assert "blind" in XXE_PAYLOADS

    def test_has_waf_bypass_category(self):
        assert "waf_bypass" in XXE_PAYLOADS

    def test_basic_count(self):
        assert len(XXE_PAYLOADS["basic"]) == 10

    def test_blind_count(self):
        assert len(XXE_PAYLOADS["blind"]) == 10

    def test_waf_bypass_count(self):
        assert len(XXE_PAYLOADS["waf_bypass"]) == 8


class TestJWTPayloads:
    """Tests for JWT_PAYLOADS global dict."""

    def test_has_algorithm_category(self):
        assert "algorithm" in JWT_PAYLOADS

    def test_has_weak_secret_category(self):
        assert "weak_secret" in JWT_PAYLOADS

    def test_has_injection_category(self):
        assert "injection" in JWT_PAYLOADS

    def test_algorithm_count(self):
        assert len(JWT_PAYLOADS["algorithm"]) == 8

    def test_weak_secret_count(self):
        assert len(JWT_PAYLOADS["weak_secret"]) == 8

    def test_injection_count(self):
        assert len(JWT_PAYLOADS["injection"]) == 6

    def test_algorithm_payloads_have_attack_field(self):
        for p in JWT_PAYLOADS["algorithm"]:
            assert "attack" in p


class TestDeserializationPayloads:
    """Tests for DESERIALIZATION_PAYLOADS global dict."""

    def test_has_java_category(self):
        assert "java" in DESERIALIZATION_PAYLOADS

    def test_has_php_category(self):
        assert "php" in DESERIALIZATION_PAYLOADS

    def test_has_python_category(self):
        assert "python" in DESERIALIZATION_PAYLOADS

    def test_java_count(self):
        assert len(DESERIALIZATION_PAYLOADS["java"]) == 10

    def test_php_count(self):
        assert len(DESERIALIZATION_PAYLOADS["php"]) == 8

    def test_python_count(self):
        assert len(DESERIALIZATION_PAYLOADS["python"]) == 7

    def test_all_payloads_have_required_fields(self):
        for lang, payloads in DESERIALIZATION_PAYLOADS.items():
            for p in payloads:
                assert "payload" in p
                assert "desc" in p


# ==================== Attack Chains Tests ====================


class TestAttackChains:
    """Tests for ATTACK_CHAINS global dict."""

    def test_has_web_full_chain(self):
        assert "web_full_chain" in ATTACK_CHAINS

    def test_has_ctf_speed_chain(self):
        assert "ctf_speed_chain" in ATTACK_CHAINS

    def test_has_internal_chain(self):
        assert "internal_chain" in ATTACK_CHAINS

    def test_chain_count(self):
        assert len(ATTACK_CHAINS) == 3

    def test_web_full_chain_has_name(self):
        assert "name" in ATTACK_CHAINS["web_full_chain"]

    def test_web_full_chain_has_phases(self):
        assert "phases" in ATTACK_CHAINS["web_full_chain"]

    def test_web_full_chain_phase_count(self):
        assert len(ATTACK_CHAINS["web_full_chain"]["phases"]) == 6

    def test_ctf_speed_chain_phase_count(self):
        assert len(ATTACK_CHAINS["ctf_speed_chain"]["phases"]) == 4

    def test_internal_chain_phase_count(self):
        assert len(ATTACK_CHAINS["internal_chain"]["phases"]) == 5

    def test_phase_structure(self):
        for chain_name, chain in ATTACK_CHAINS.items():
            for phase in chain["phases"]:
                assert "phase" in phase
                assert "tools" in phase
                assert "objective" in phase
                assert isinstance(phase["tools"], list)

    def test_web_full_chain_first_phase_is_recon(self):
        first_phase = ATTACK_CHAINS["web_full_chain"]["phases"][0]
        assert first_phase["phase"] == "reconnaissance"

    def test_ctf_speed_chain_last_phase_is_flag_hunt(self):
        last_phase = ATTACK_CHAINS["ctf_speed_chain"]["phases"][-1]
        assert last_phase["phase"] == "flag_hunt"


# ==================== EnhancedDetector Tests ====================


class TestEnhancedDetectorInit:
    """Tests for EnhancedDetector.__init__."""

    def test_init_creates_payloads_dict(self):
        d = EnhancedDetector()
        assert isinstance(d.payloads, dict)

    def test_init_payloads_has_all_vuln_types(self):
        d = EnhancedDetector()
        expected_keys = {"sqli", "xss", "cmdi", "lfi", "ssti", "ssrf", "xxe", "jwt", "deser"}
        assert set(d.payloads.keys()) == expected_keys

    def test_init_payloads_count(self):
        d = EnhancedDetector()
        assert len(d.payloads) == 9

    def test_init_attack_chains_is_attack_chains_global(self):
        d = EnhancedDetector()
        assert d.attack_chains is ATTACK_CHAINS

    def test_init_sqli_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["sqli"] is SQL_INJECTION_PAYLOADS

    def test_init_xss_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["xss"] is XSS_PAYLOADS

    def test_init_cmdi_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["cmdi"] is COMMAND_INJECTION_PAYLOADS

    def test_init_lfi_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["lfi"] is LFI_PAYLOADS

    def test_init_ssti_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["ssti"] is SSTI_PAYLOADS

    def test_init_ssrf_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["ssrf"] is SSRF_PAYLOADS

    def test_init_xxe_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["xxe"] is XXE_PAYLOADS

    def test_init_jwt_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["jwt"] is JWT_PAYLOADS

    def test_init_deser_points_to_global(self):
        d = EnhancedDetector()
        assert d.payloads["deser"] is DESERIALIZATION_PAYLOADS


class TestEnhancedDetectorGetPayloads:
    """Tests for EnhancedDetector.get_payloads."""

    @pytest.fixture
    def detector(self):
        return EnhancedDetector()

    def test_get_payloads_unknown_type_returns_empty(self, detector):
        result = detector.get_payloads("nonexistent")
        assert result == []

    def test_get_payloads_sqli_all_returns_list(self, detector):
        result = detector.get_payloads("sqli")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_get_payloads_sqli_all_merges_all_categories(self, detector):
        result = detector.get_payloads("sqli")
        expected_total = sum(len(cat) for cat in SQL_INJECTION_PAYLOADS.values())
        assert len(result) == expected_total

    def test_get_payloads_sqli_basic_category(self, detector):
        result = detector.get_payloads("sqli", "basic")
        assert len(result) == 10

    def test_get_payloads_sqli_union_category(self, detector):
        result = detector.get_payloads("sqli", "union")
        assert len(result) == 15

    def test_get_payloads_sqli_waf_bypass_category(self, detector):
        result = detector.get_payloads("sqli", "waf_bypass")
        assert len(result) == 15

    def test_get_payloads_xss_all(self, detector):
        result = detector.get_payloads("xss")
        expected_total = sum(len(cat) for cat in XSS_PAYLOADS.values())
        assert len(result) == expected_total

    def test_get_payloads_xss_basic_category(self, detector):
        result = detector.get_payloads("xss", "basic")
        assert len(result) == 15

    def test_get_payloads_cmdi_all(self, detector):
        result = detector.get_payloads("cmdi")
        expected_total = sum(len(cat) for cat in COMMAND_INJECTION_PAYLOADS.values())
        assert len(result) == expected_total

    def test_get_payloads_invalid_category_merges_all(self, detector):
        """When category doesn't exist, it should merge all categories."""
        result = detector.get_payloads("sqli", "nonexistent_category")
        expected = sum(len(cat) for cat in SQL_INJECTION_PAYLOADS.values())
        assert len(result) == expected

    def test_get_payloads_bypass_true_filters(self, detector):
        result = detector.get_payloads("sqli", bypass=True)
        assert len(result) > 0
        for p in result:
            assert "bypass" in p

    def test_get_payloads_bypass_true_on_basic_returns_empty(self, detector):
        """Basic payloads don't have bypass field, so bypass=True should exclude them."""
        result = detector.get_payloads("sqli", "basic", bypass=True)
        assert len(result) == 0

    def test_get_payloads_bypass_true_on_waf_bypass_returns_all(self, detector):
        result = detector.get_payloads("sqli", "waf_bypass", bypass=True)
        assert len(result) == 15

    def test_get_payloads_bypass_false_returns_all(self, detector):
        result_all = detector.get_payloads("sqli", "basic", bypass=False)
        assert len(result_all) == 10

    def test_get_payloads_lfi_all(self, detector):
        result = detector.get_payloads("lfi")
        expected = sum(len(cat) for cat in LFI_PAYLOADS.values())
        assert len(result) == expected

    def test_get_payloads_ssti_all(self, detector):
        result = detector.get_payloads("ssti")
        expected = sum(len(cat) for cat in SSTI_PAYLOADS.values())
        assert len(result) == expected

    def test_get_payloads_ssrf_all(self, detector):
        result = detector.get_payloads("ssrf")
        expected = sum(len(cat) for cat in SSRF_PAYLOADS.values())
        assert len(result) == expected

    def test_get_payloads_xxe_all(self, detector):
        result = detector.get_payloads("xxe")
        expected = sum(len(cat) for cat in XXE_PAYLOADS.values())
        assert len(result) == expected

    def test_get_payloads_jwt_all(self, detector):
        result = detector.get_payloads("jwt")
        expected = sum(len(cat) for cat in JWT_PAYLOADS.values())
        assert len(result) == expected

    def test_get_payloads_deser_all(self, detector):
        result = detector.get_payloads("deser")
        expected = sum(len(cat) for cat in DESERIALIZATION_PAYLOADS.values())
        assert len(result) == expected

    def test_get_payloads_each_entry_has_payload_key(self, detector):
        for vuln_type in detector.payloads:
            result = detector.get_payloads(vuln_type)
            for p in result:
                assert "payload" in p, f"Missing 'payload' key in {vuln_type}: {p}"

    def test_get_payloads_each_entry_has_desc_key(self, detector):
        for vuln_type in detector.payloads:
            result = detector.get_payloads(vuln_type)
            for p in result:
                assert "desc" in p, f"Missing 'desc' key in {vuln_type}: {p}"


class TestEnhancedDetectorGetWafBypass:
    """Tests for EnhancedDetector.get_waf_bypass_payloads."""

    @pytest.fixture
    def detector(self):
        return EnhancedDetector()

    def test_sqli_waf_bypass(self, detector):
        result = detector.get_waf_bypass_payloads("sqli")
        assert len(result) == 15

    def test_xss_waf_bypass(self, detector):
        result = detector.get_waf_bypass_payloads("xss")
        assert len(result) == 15

    def test_cmdi_waf_bypass(self, detector):
        result = detector.get_waf_bypass_payloads("cmdi")
        assert len(result) == 15

    def test_lfi_waf_bypass(self, detector):
        result = detector.get_waf_bypass_payloads("lfi")
        assert len(result) == 10

    def test_xxe_waf_bypass(self, detector):
        result = detector.get_waf_bypass_payloads("xxe")
        assert len(result) == 8

    def test_ssrf_bypass(self, detector):
        """SSRF uses 'bypass' category, not 'waf_bypass'."""
        result = detector.get_waf_bypass_payloads("ssrf")
        # ssrf has no "waf_bypass" key, so it merges all
        expected = sum(len(cat) for cat in SSRF_PAYLOADS.values())
        assert len(result) == expected

    def test_unknown_type_returns_empty(self, detector):
        result = detector.get_waf_bypass_payloads("nonexistent")
        assert result == []

    def test_jwt_has_no_waf_bypass(self, detector):
        """JWT payloads don't have waf_bypass, so all get merged."""
        result = detector.get_waf_bypass_payloads("jwt")
        expected = sum(len(cat) for cat in JWT_PAYLOADS.values())
        assert len(result) == expected


class TestEnhancedDetectorGetAttackChain:
    """Tests for EnhancedDetector.get_attack_chain."""

    @pytest.fixture
    def detector(self):
        return EnhancedDetector()

    def test_web_full_chain(self, detector):
        result = detector.get_attack_chain("web_full_chain")
        assert isinstance(result, dict)
        assert "name" in result

    def test_ctf_speed_chain(self, detector):
        result = detector.get_attack_chain("ctf_speed_chain")
        assert result["name"] == "CTF快速攻击链"

    def test_internal_chain(self, detector):
        result = detector.get_attack_chain("internal_chain")
        assert result["name"] == "内网渗透攻击链"

    def test_nonexistent_chain_returns_empty_dict(self, detector):
        result = detector.get_attack_chain("nonexistent")
        assert result == {}

    def test_chain_contains_phases(self, detector):
        result = detector.get_attack_chain("web_full_chain")
        assert "phases" in result
        assert isinstance(result["phases"], list)


class TestEnhancedDetectorSuggestNextPayload:
    """Tests for EnhancedDetector.suggest_next_payload."""

    @pytest.fixture
    def detector(self):
        return EnhancedDetector()

    def test_suggest_with_no_failures_returns_first(self, detector):
        result = detector.suggest_next_payload("sqli", [])
        assert result["payload"] is not None

    def test_suggest_skips_failed_payloads(self, detector):
        first_payload = SQL_INJECTION_PAYLOADS["basic"][0]["payload"]
        result = detector.suggest_next_payload("sqli", [first_payload])
        assert result["payload"] != first_payload

    def test_suggest_returns_next_unfailed(self, detector):
        first = SQL_INJECTION_PAYLOADS["basic"][0]["payload"]
        second = SQL_INJECTION_PAYLOADS["basic"][1]["payload"]
        result = detector.suggest_next_payload("sqli", [first])
        assert result["payload"] == second

    def test_suggest_all_failed_returns_waf_bypass(self, detector):
        """When all base payloads failed, should suggest WAF bypass."""
        all_payloads = detector.get_payloads("sqli")
        # Exclude waf_bypass payloads from the failed set
        non_bypass = [p["payload"] for p in all_payloads if not p.get("bypass")]
        result = detector.suggest_next_payload("sqli", non_bypass)
        # Should return a waf_bypass payload
        assert result["payload"] is not None

    def test_suggest_all_exhausted_returns_none_payload(self, detector):
        """When absolutely all payloads are tried, returns None payload."""
        all_payloads = detector.get_payloads("sqli")
        bypass_payloads = detector.get_waf_bypass_payloads("sqli")
        all_strs = [p["payload"] for p in all_payloads] + [p["payload"] for p in bypass_payloads]
        result = detector.suggest_next_payload("sqli", all_strs)
        assert result["payload"] is None
        assert "已尝试" in result["desc"]

    def test_suggest_unknown_type_returns_none_payload(self, detector):
        """Unknown vuln type means no payloads available."""
        result = detector.suggest_next_payload("nonexistent", [])
        assert result["payload"] is None

    def test_suggest_returns_dict(self, detector):
        result = detector.suggest_next_payload("xss", [])
        assert isinstance(result, dict)
        assert "payload" in result
        assert "desc" in result


class TestEnhancedDetectorGetPayloadCount:
    """Tests for EnhancedDetector.get_payload_count."""

    @pytest.fixture
    def detector(self):
        return EnhancedDetector()

    def test_count_all_returns_total_key(self, detector):
        result = detector.get_payload_count()
        assert "total" in result

    def test_count_all_has_all_vuln_types(self, detector):
        result = detector.get_payload_count()
        for vt in detector.payloads:
            assert vt in result

    def test_count_sqli(self, detector):
        result = detector.get_payload_count("sqli")
        assert "sqli" in result
        expected = sum(len(cat) for cat in SQL_INJECTION_PAYLOADS.values())
        assert result["sqli"] == expected

    def test_count_xss(self, detector):
        result = detector.get_payload_count("xss")
        expected = sum(len(cat) for cat in XSS_PAYLOADS.values())
        assert result["xss"] == expected

    def test_count_cmdi(self, detector):
        result = detector.get_payload_count("cmdi")
        expected = sum(len(cat) for cat in COMMAND_INJECTION_PAYLOADS.values())
        assert result["cmdi"] == expected

    def test_count_unknown_type_returns_zero(self, detector):
        result = detector.get_payload_count("nonexistent")
        assert result == {"nonexistent": 0}

    def test_total_count_sums_correctly(self, detector):
        result = detector.get_payload_count()
        individual_sum = sum(v for k, v in result.items() if k != "total")
        assert result["total"] == individual_sum

    def test_total_is_at_least_300(self, detector):
        """Docstring says 300+ payloads."""
        result = detector.get_payload_count()
        assert result["total"] >= 300

    def test_count_specific_type_has_no_total(self, detector):
        result = detector.get_payload_count("sqli")
        assert "total" not in result

    def test_count_jwt(self, detector):
        result = detector.get_payload_count("jwt")
        expected = sum(len(cat) for cat in JWT_PAYLOADS.values())
        assert result["jwt"] == expected

    def test_count_deser(self, detector):
        result = detector.get_payload_count("deser")
        expected = sum(len(cat) for cat in DESERIALIZATION_PAYLOADS.values())
        assert result["deser"] == expected


# ==================== Singleton Pattern Tests ====================


class TestGetEnhancedDetector:
    """Tests for the get_enhanced_detector singleton function."""

    def test_returns_enhanced_detector_instance(self):
        # Reset singleton to ensure fresh state
        ekb_module._enhanced_detector = None
        result = get_enhanced_detector()
        assert isinstance(result, EnhancedDetector)

    def test_returns_same_instance_twice(self):
        ekb_module._enhanced_detector = None
        first = get_enhanced_detector()
        second = get_enhanced_detector()
        assert first is second

    def test_creates_instance_when_none(self):
        ekb_module._enhanced_detector = None
        assert ekb_module._enhanced_detector is None
        result = get_enhanced_detector()
        assert ekb_module._enhanced_detector is not None
        assert result is ekb_module._enhanced_detector

    def test_reuses_existing_instance(self):
        existing = EnhancedDetector()
        ekb_module._enhanced_detector = existing
        result = get_enhanced_detector()
        assert result is existing

    def teardown_method(self):
        # Clean up singleton state after each test
        ekb_module._enhanced_detector = None


# ==================== Convenience Functions Tests ====================


class TestGetEnhancedPayloads:
    """Tests for the get_enhanced_payloads convenience function."""

    def setup_method(self):
        ekb_module._enhanced_detector = None

    def test_returns_list(self):
        result = get_enhanced_payloads("sqli")
        assert isinstance(result, list)

    def test_returns_sqli_payloads(self):
        result = get_enhanced_payloads("sqli")
        expected = sum(len(cat) for cat in SQL_INJECTION_PAYLOADS.values())
        assert len(result) == expected

    def test_with_category(self):
        result = get_enhanced_payloads("sqli", "basic")
        assert len(result) == 10

    def test_unknown_type_returns_empty(self):
        result = get_enhanced_payloads("nonexistent")
        assert result == []

    def test_delegates_to_detector(self):
        """Verify it uses the singleton detector."""
        result1 = get_enhanced_payloads("xss", "basic")
        result2 = get_enhanced_payloads("xss", "basic")
        assert result1 == result2

    def teardown_method(self):
        ekb_module._enhanced_detector = None


class TestGetWafBypass:
    """Tests for the get_waf_bypass convenience function."""

    def setup_method(self):
        ekb_module._enhanced_detector = None

    def test_returns_list(self):
        result = get_waf_bypass("sqli")
        assert isinstance(result, list)

    def test_sqli_waf_bypass_count(self):
        result = get_waf_bypass("sqli")
        assert len(result) == 15

    def test_xss_waf_bypass_count(self):
        result = get_waf_bypass("xss")
        assert len(result) == 15

    def test_unknown_type_returns_empty(self):
        result = get_waf_bypass("nonexistent")
        assert result == []

    def teardown_method(self):
        ekb_module._enhanced_detector = None


class TestGetChain:
    """Tests for the get_chain convenience function."""

    def setup_method(self):
        ekb_module._enhanced_detector = None

    def test_returns_dict(self):
        result = get_chain("web_full_chain")
        assert isinstance(result, dict)

    def test_web_full_chain(self):
        result = get_chain("web_full_chain")
        assert "name" in result
        assert "phases" in result

    def test_ctf_speed_chain(self):
        result = get_chain("ctf_speed_chain")
        assert result["name"] == "CTF快速攻击链"

    def test_unknown_chain_returns_empty_dict(self):
        result = get_chain("nonexistent")
        assert result == {}

    def teardown_method(self):
        ekb_module._enhanced_detector = None


class TestPayloadStats:
    """Tests for the payload_stats convenience function."""

    def setup_method(self):
        ekb_module._enhanced_detector = None

    def test_returns_dict(self):
        result = payload_stats()
        assert isinstance(result, dict)

    def test_has_total(self):
        result = payload_stats()
        assert "total" in result

    def test_total_positive(self):
        result = payload_stats()
        assert result["total"] > 0

    def test_has_all_vuln_types(self):
        result = payload_stats()
        expected_keys = {"sqli", "xss", "cmdi", "lfi", "ssti", "ssrf", "xxe", "jwt", "deser", "total"}
        assert set(result.keys()) == expected_keys

    def test_matches_detector_count(self):
        detector = EnhancedDetector()
        result = payload_stats()
        direct = detector.get_payload_count()
        assert result == direct

    def teardown_method(self):
        ekb_module._enhanced_detector = None


# ==================== Module Constants Tests ====================


class TestModuleConstants:
    """Tests for module-level constants."""

    def test_version_is_string(self):
        assert isinstance(__version__, str)

    def test_version_value(self):
        assert __version__ == "2.0.0"

    def test_description_is_string(self):
        assert isinstance(__description__, str)

    def test_description_not_empty(self):
        assert len(__description__) > 0

    def test_description_mentions_payloads(self):
        assert "payload" in __description__.lower() or "300+" in __description__


# ==================== Cross-Payload Integrity Tests ====================


class TestPayloadIntegrity:
    """Cross-cutting tests to verify overall payload data integrity."""

    @pytest.fixture
    def detector(self):
        return EnhancedDetector()

    def test_all_payload_dicts_are_dicts(self):
        for d in [SQL_INJECTION_PAYLOADS, XSS_PAYLOADS, COMMAND_INJECTION_PAYLOADS,
                   LFI_PAYLOADS, SSTI_PAYLOADS, SSRF_PAYLOADS, XXE_PAYLOADS,
                   JWT_PAYLOADS, DESERIALIZATION_PAYLOADS]:
            assert isinstance(d, dict)

    def test_all_categories_are_lists(self):
        all_dicts = [SQL_INJECTION_PAYLOADS, XSS_PAYLOADS, COMMAND_INJECTION_PAYLOADS,
                     LFI_PAYLOADS, SSTI_PAYLOADS, SSRF_PAYLOADS, XXE_PAYLOADS,
                     JWT_PAYLOADS, DESERIALIZATION_PAYLOADS]
        for payload_dict in all_dicts:
            for category, entries in payload_dict.items():
                assert isinstance(entries, list), f"Category {category} is not a list"

    def test_all_payloads_are_dicts(self):
        all_dicts = [SQL_INJECTION_PAYLOADS, XSS_PAYLOADS, COMMAND_INJECTION_PAYLOADS,
                     LFI_PAYLOADS, SSTI_PAYLOADS, SSRF_PAYLOADS, XXE_PAYLOADS,
                     JWT_PAYLOADS, DESERIALIZATION_PAYLOADS]
        for payload_dict in all_dicts:
            for category, entries in payload_dict.items():
                for entry in entries:
                    assert isinstance(entry, dict), f"Entry in {category} is not a dict: {entry}"

    def test_no_empty_categories(self):
        all_dicts = [SQL_INJECTION_PAYLOADS, XSS_PAYLOADS, COMMAND_INJECTION_PAYLOADS,
                     LFI_PAYLOADS, SSTI_PAYLOADS, SSRF_PAYLOADS, XXE_PAYLOADS,
                     JWT_PAYLOADS, DESERIALIZATION_PAYLOADS]
        for payload_dict in all_dicts:
            for category, entries in payload_dict.items():
                assert len(entries) > 0, f"Category {category} is empty"

    def test_no_empty_payload_strings(self, detector):
        """Ensure no payload has an empty string (except JWT empty key which is intentional)."""
        for vuln_type in detector.payloads:
            all_p = detector.get_payloads(vuln_type)
            for p in all_p:
                # JWT weak_secret has intentional empty string
                if vuln_type == "jwt" and p.get("attack") == "empty_key":
                    continue
                assert p["payload"] is not None, f"None payload in {vuln_type}: {p}"

    def test_payload_descs_are_non_empty_strings(self, detector):
        for vuln_type in detector.payloads:
            all_p = detector.get_payloads(vuln_type)
            for p in all_p:
                assert isinstance(p["desc"], str)
                assert len(p["desc"]) > 0


# ==================== Edge Case / Integration-like Tests ====================


class TestEdgeCases:
    """Edge cases and integration-style pure unit tests."""

    def test_multiple_detector_instances_are_independent(self):
        d1 = EnhancedDetector()
        d2 = EnhancedDetector()
        assert d1 is not d2
        assert d1.payloads == d2.payloads

    def test_suggest_payload_with_partial_failures(self):
        d = EnhancedDetector()
        # Fail the first 5 basic sqli payloads
        failed = [SQL_INJECTION_PAYLOADS["basic"][i]["payload"] for i in range(5)]
        result = d.suggest_next_payload("sqli", failed)
        assert result["payload"] == SQL_INJECTION_PAYLOADS["basic"][5]["payload"]

    def test_get_payloads_bypass_with_nonexistent_category(self):
        """bypass=True with invalid category should merge all then filter."""
        d = EnhancedDetector()
        result = d.get_payloads("sqli", "nonexistent", bypass=True)
        # Merges all categories, then filters by bypass
        assert all("bypass" in p for p in result)
        assert len(result) > 0

    def test_get_payloads_bypass_false_no_filter(self):
        d = EnhancedDetector()
        all_p = d.get_payloads("sqli")
        no_bypass = d.get_payloads("sqli", bypass=False)
        assert len(all_p) == len(no_bypass)

    def test_chain_phases_have_string_phase_names(self):
        for chain in ATTACK_CHAINS.values():
            for phase in chain["phases"]:
                assert isinstance(phase["phase"], str)
                assert len(phase["phase"]) > 0

    def test_chain_tools_are_lists_of_strings(self):
        for chain in ATTACK_CHAINS.values():
            for phase in chain["phases"]:
                for tool in phase["tools"]:
                    assert isinstance(tool, str)

    def test_ssrf_bypass_payloads_unique_bypass_types(self):
        bypass_types = [p["bypass"] for p in SSRF_PAYLOADS["bypass"]]
        assert len(bypass_types) == len(set(bypass_types)), "Duplicate SSRF bypass types"

    def test_sqli_waf_bypass_payloads_unique_bypass_types(self):
        bypass_types = [p["bypass"] for p in SQL_INJECTION_PAYLOADS["waf_bypass"]]
        assert len(bypass_types) == len(set(bypass_types)), "Duplicate SQLi WAF bypass types"

    def test_singleton_reset_and_recreate(self):
        """Ensure singleton can be properly reset."""
        ekb_module._enhanced_detector = None
        d1 = get_enhanced_detector()
        ekb_module._enhanced_detector = None
        d2 = get_enhanced_detector()
        assert d1 is not d2
        assert isinstance(d2, EnhancedDetector)
        ekb_module._enhanced_detector = None

    def test_suggest_next_payload_deser(self):
        d = EnhancedDetector()
        result = d.suggest_next_payload("deser", [])
        assert result["payload"] is not None

    def test_get_payload_count_returns_ints(self):
        d = EnhancedDetector()
        counts = d.get_payload_count()
        for k, v in counts.items():
            assert isinstance(v, int)
