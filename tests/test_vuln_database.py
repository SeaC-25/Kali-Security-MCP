"""
Tests for VulnerabilityDatabase (kali_mcp/vulnerabilities/vuln_database.py)

Covers:
- Vulnerability dataclass (to_dict, from_dict, matches_product, matches_version)
- VulnerabilityDatabase CRUD and search
- Severity/product/CVE/recent/exploitable search
- Confidence calculation
- Statistics
"""

from datetime import date, timedelta

import pytest

from kali_mcp.vulnerabilities.vuln_database import (
    Vulnerability,
    VulnerabilityDatabase,
    VulnCategory,
    VulnSeverity,
    VulnType,
)


def _make_vuln(**overrides):
    defaults = {
        "cve_id": "CVE-2024-0001",
        "name": "Test Vuln",
        "category": VulnCategory.ONE_DAY,
        "publish_date": date.today() - timedelta(days=30),
        "cvss_score": 9.8,
        "severity": VulnSeverity.CRITICAL,
        "affected_products": ["Apache"],
        "vuln_types": [VulnType.RCE],
        "description": "A test vulnerability",
        "exploit_available": True,
    }
    defaults.update(overrides)
    return Vulnerability(**defaults)


# ===================== Vulnerability Dataclass Tests =====================

class TestVulnerability:
    def test_to_dict(self):
        v = _make_vuln()
        d = v.to_dict()
        assert d["cve_id"] == "CVE-2024-0001"
        assert d["severity"] == "CRITICAL"
        assert d["category"] == "1day"
        assert d["vuln_types"] == ["RCE"]

    def test_from_dict_roundtrip(self):
        v = _make_vuln(exploit_method="curl payload", poc_available=True)
        d = v.to_dict()
        restored = Vulnerability.from_dict(d)
        assert restored.cve_id == v.cve_id
        assert restored.exploit_method == "curl payload"
        assert restored.poc_available is True
        assert restored.severity == VulnSeverity.CRITICAL

    def test_matches_product_exact(self):
        v = _make_vuln(affected_products=["Apache HTTP Server"])
        assert v.matches_product("Apache HTTP Server") is True

    def test_matches_product_substring(self):
        v = _make_vuln(affected_products=["Apache HTTP Server"])
        assert v.matches_product("apache") is True

    def test_matches_product_reverse_substring(self):
        v = _make_vuln(affected_products=["Apache"])
        assert v.matches_product("Apache HTTP Server 2.4") is True

    def test_not_matches_product(self):
        v = _make_vuln(affected_products=["Nginx"])
        assert v.matches_product("Apache") is False

    def test_matches_version_no_restrictions(self):
        v = _make_vuln(affected_versions=[])
        assert v.matches_version("2.4.49") is True

    def test_matches_version_hit(self):
        v = _make_vuln(affected_versions=["2.4.49", "2.4.50"])
        assert v.matches_version("2.4.49") is True

    def test_matches_version_miss(self):
        v = _make_vuln(affected_versions=["2.4.49"])
        assert v.matches_version("3.0.0") is False


# ===================== VulnCategory / VulnSeverity Enums =====================

class TestEnums:
    def test_category_values(self):
        assert VulnCategory.ZERO_DAY.value == "0day"
        assert VulnCategory.ONE_DAY.value == "1day"
        assert VulnCategory.N_DAY.value == "nday"

    def test_severity_values(self):
        assert VulnSeverity.CRITICAL.value == "CRITICAL"
        assert VulnSeverity.LOW.value == "LOW"

    def test_vuln_type_values(self):
        assert VulnType.RCE.value == "RCE"
        assert VulnType.SQL_INJECTION.value == "SQL Injection"


# ===================== VulnerabilityDatabase Tests =====================

@pytest.fixture
def db():
    return VulnerabilityDatabase()


class TestDatabaseAdd:
    def test_add_and_stats(self, db):
        db.add_vulnerability(_make_vuln())
        assert db.stats["total"] == 1
        assert db.stats["critical"] == 1
        assert db.stats["with_exploit"] == 1

    def test_add_multiple(self, db):
        db.add_vulnerability(_make_vuln(cve_id="CVE-2024-0001"))
        db.add_vulnerability(_make_vuln(
            cve_id="CVE-2024-0002",
            severity=VulnSeverity.HIGH,
            cvss_score=7.5,
            exploit_available=False,
        ))
        assert db.stats["total"] == 2
        assert db.stats["critical"] == 1
        assert db.stats["high"] == 1
        assert db.stats["with_exploit"] == 1

    def test_indexes_built(self, db):
        db.add_vulnerability(_make_vuln(cve_id="CVE-2024-0001"))
        assert "CVE-2024-0001" in db.cve_index
        assert VulnSeverity.CRITICAL in db.severity_index


class TestSearchByProduct:
    def test_exact_match(self, db):
        db.add_vulnerability(_make_vuln(affected_products=["Apache"]))
        results = db.search_by_product("Apache")
        assert len(results) == 1

    def test_partial_match(self, db):
        db.add_vulnerability(_make_vuln(affected_products=["Apache HTTP Server"]))
        results = db.search_by_product("Apache")
        assert len(results) >= 1

    def test_no_match(self, db):
        db.add_vulnerability(_make_vuln(affected_products=["Nginx"]))
        results = db.search_by_product("Apache")
        assert len(results) == 0

    def test_sorted_by_cvss(self, db):
        db.add_vulnerability(_make_vuln(cve_id="C1", cvss_score=5.0, affected_products=["Apache"]))
        db.add_vulnerability(_make_vuln(cve_id="C2", cvss_score=9.8, affected_products=["Apache"]))
        results = db.search_by_product("Apache")
        assert results[0].cvss_score >= results[-1].cvss_score


class TestSearchBySeverity:
    def test_critical_only(self, db):
        db.add_vulnerability(_make_vuln(cve_id="C1", severity=VulnSeverity.CRITICAL))
        db.add_vulnerability(_make_vuln(cve_id="C2", severity=VulnSeverity.LOW))
        results = db.search_by_severity(VulnSeverity.CRITICAL)
        assert len(results) == 1

    def test_high_and_above(self, db):
        db.add_vulnerability(_make_vuln(cve_id="C1", severity=VulnSeverity.CRITICAL))
        db.add_vulnerability(_make_vuln(cve_id="C2", severity=VulnSeverity.HIGH))
        db.add_vulnerability(_make_vuln(cve_id="C3", severity=VulnSeverity.LOW))
        results = db.search_by_severity(VulnSeverity.HIGH)
        assert len(results) == 2


class TestSearchByCVE:
    def test_found(self, db):
        db.add_vulnerability(_make_vuln(cve_id="CVE-2024-3400"))
        result = db.search_by_cve("CVE-2024-3400")
        assert result is not None
        assert result.cve_id == "CVE-2024-3400"

    def test_not_found(self, db):
        assert db.search_by_cve("CVE-9999-0000") is None


class TestSearchRecent:
    def test_recent_included(self, db):
        db.add_vulnerability(_make_vuln(publish_date=date.today() - timedelta(days=10)))
        results = db.search_recent(days=30)
        assert len(results) == 1

    def test_old_excluded(self, db):
        db.add_vulnerability(_make_vuln(publish_date=date.today() - timedelta(days=365)))
        results = db.search_recent(days=30)
        assert len(results) == 0


class TestSearchExploitable:
    def test_exploitable(self, db):
        db.add_vulnerability(_make_vuln(exploit_available=True, cvss_score=9.8))
        db.add_vulnerability(_make_vuln(
            cve_id="C2", exploit_available=False, cvss_score=9.0))
        results = db.search_exploitable(min_cvss=7.0)
        assert len(results) == 1

    def test_filter_by_product(self, db):
        db.add_vulnerability(_make_vuln(
            affected_products=["Apache"], exploit_available=True))
        db.add_vulnerability(_make_vuln(
            cve_id="C2", affected_products=["Nginx"], exploit_available=True))
        results = db.search_exploitable(product_name="Apache")
        assert len(results) == 1

    def test_filter_by_min_cvss(self, db):
        db.add_vulnerability(_make_vuln(exploit_available=True, cvss_score=6.0))
        results = db.search_exploitable(min_cvss=7.0)
        assert len(results) == 0


class TestConfidence:
    def test_base_confidence(self, db):
        v = _make_vuln(cvss_score=10.0, poc_available=False,
                       category=VulnCategory.N_DAY, exploit_method=None)
        conf = db._calculate_confidence(v, {})
        assert 0.5 <= conf <= 1.0

    def test_max_confidence(self, db):
        v = _make_vuln(cvss_score=10.0, poc_available=True,
                       category=VulnCategory.ZERO_DAY, exploit_method="curl")
        conf = db._calculate_confidence(v, {})
        assert conf == 1.0

    def test_poc_boosts(self, db):
        v_no = _make_vuln(poc_available=False, category=VulnCategory.N_DAY,
                          exploit_method=None)
        v_yes = _make_vuln(poc_available=True, category=VulnCategory.N_DAY,
                           exploit_method=None)
        assert db._calculate_confidence(v_yes, {}) > db._calculate_confidence(v_no, {})


class TestRecommendation:
    def test_with_product(self, db):
        db.add_vulnerability(_make_vuln(
            affected_products=["Apache"], exploit_available=True, cvss_score=9.8))
        recs = db.get_exploit_recommendation({"product": "Apache"})
        assert len(recs) >= 1
        assert "confidence" in recs[0]

    def test_with_service(self, db):
        db.add_vulnerability(_make_vuln(
            affected_products=["SSH"], exploit_available=True, cvss_score=8.0))
        recs = db.get_exploit_recommendation({"service": "SSH"})
        assert len(recs) >= 1

    def test_empty_target(self, db):
        recs = db.get_exploit_recommendation({})
        assert recs == []

    def test_filters_low_cvss(self, db):
        db.add_vulnerability(_make_vuln(
            affected_products=["Apache"], exploit_available=True, cvss_score=4.0))
        recs = db.get_exploit_recommendation({"product": "Apache"})
        assert len(recs) == 0


class TestStatistics:
    def test_empty(self, db):
        stats = db.get_statistics()
        assert stats["total"] == 0
        assert stats["avg_cvss"] == 0

    def test_with_data(self, db):
        db.add_vulnerability(_make_vuln(cvss_score=8.0))
        db.add_vulnerability(_make_vuln(cve_id="C2", cvss_score=6.0,
                                        severity=VulnSeverity.MEDIUM))
        stats = db.get_statistics()
        assert stats["total"] == 2
        assert stats["avg_cvss"] == 7.0
        assert stats["products_count"] >= 1
