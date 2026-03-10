"""
Tests for vuln_models module (kali_mcp/core/vuln_models.py)

Covers:
- VulnStatus enum
- VulnSeverity enum
- VulnSource enum
- VulnConfidence enum
- VulnRecord: creation, defaults, unique IDs, mutable defaults,
  severity_order, to_dict, from_dict, round-trip, field filtering
"""

import pytest

from kali_mcp.core.vuln_models import (
    VulnStatus,
    VulnSeverity,
    VulnSource,
    VulnConfidence,
    VulnRecord,
)


# ===================== VulnStatus Tests =====================

class TestVulnStatus:
    def test_values(self):
        assert VulnStatus.CANDIDATE.value == "candidate"
        assert VulnStatus.VERIFYING.value == "verifying"
        assert VulnStatus.VERIFIED.value == "verified"
        assert VulnStatus.FAILED.value == "failed"
        assert VulnStatus.DISMISSED.value == "dismissed"

    def test_member_count(self):
        assert len(VulnStatus) == 5


# ===================== VulnSeverity Tests =====================

class TestVulnSeverity:
    def test_values(self):
        assert VulnSeverity.CRITICAL.value == "critical"
        assert VulnSeverity.HIGH.value == "high"
        assert VulnSeverity.MEDIUM.value == "medium"
        assert VulnSeverity.LOW.value == "low"
        assert VulnSeverity.INFO.value == "info"

    def test_member_count(self):
        assert len(VulnSeverity) == 5


# ===================== VulnSource Tests =====================

class TestVulnSource:
    def test_values(self):
        assert VulnSource.BLACKBOX.value == "blackbox"
        assert VulnSource.WHITEBOX.value == "whitebox"
        assert VulnSource.MANUAL.value == "manual"
        assert VulnSource.CROSS_VALIDATED.value == "cross_validated"

    def test_member_count(self):
        assert len(VulnSource) == 4


# ===================== VulnConfidence Tests =====================

class TestVulnConfidence:
    def test_values(self):
        assert VulnConfidence.VERY_HIGH.value == "very_high"
        assert VulnConfidence.HIGH.value == "high"
        assert VulnConfidence.MEDIUM.value == "medium"
        assert VulnConfidence.LOW.value == "low"

    def test_member_count(self):
        assert len(VulnConfidence) == 4


# ===================== VulnRecord Creation Tests =====================

class TestVulnRecordCreation:
    def test_defaults(self):
        rec = VulnRecord()
        assert rec.vuln_id.startswith("VULN-")
        assert len(rec.vuln_id) == 13  # "VULN-" + 8 hex chars
        assert rec.title == ""
        assert rec.vuln_type == ""
        assert rec.severity == "medium"
        assert rec.confidence == "medium"
        assert rec.status == "candidate"
        assert rec.source == "blackbox"
        assert rec.target == ""
        assert rec.endpoint == ""
        assert rec.params == ""
        assert rec.payload == ""
        assert rec.evidence == ""
        assert rec.cvss_score == 0.0
        assert rec.discovered_by == ""
        assert rec.verified_by is None
        assert rec.discovered_at != ""
        assert rec.verified_at is None
        assert rec.related_fragments == []
        assert rec.tags == []

    def test_unique_ids(self):
        r1 = VulnRecord()
        r2 = VulnRecord()
        assert r1.vuln_id != r2.vuln_id

    def test_with_values(self):
        rec = VulnRecord(
            title="SQL Injection in login",
            vuln_type="sqli",
            severity="critical",
            confidence="very_high",
            status="verified",
            source="blackbox",
            target="http://target.com",
            endpoint="/login",
            params="username",
            payload="' OR 1=1 --",
            evidence="Database error in response",
            cvss_score=9.8,
            discovered_by="sqlmap",
            verified_by="manual",
            tags=["sqli", "login"],
            related_fragments=["FRAG-1234"],
        )
        assert rec.title == "SQL Injection in login"
        assert rec.vuln_type == "sqli"
        assert rec.severity == "critical"
        assert rec.cvss_score == 9.8
        assert len(rec.tags) == 2
        assert len(rec.related_fragments) == 1

    def test_mutable_defaults_independent(self):
        r1 = VulnRecord()
        r2 = VulnRecord()
        r1.tags.append("test")
        r1.related_fragments.append("FRAG-X")
        assert r2.tags == []
        assert r2.related_fragments == []


# ===================== VulnRecord severity_order Tests =====================

class TestVulnRecordSeverityOrder:
    def test_critical(self):
        assert VulnRecord(severity="critical").severity_order == 5

    def test_high(self):
        assert VulnRecord(severity="high").severity_order == 4

    def test_medium(self):
        assert VulnRecord(severity="medium").severity_order == 3

    def test_low(self):
        assert VulnRecord(severity="low").severity_order == 2

    def test_info(self):
        assert VulnRecord(severity="info").severity_order == 1

    def test_unknown(self):
        assert VulnRecord(severity="unknown").severity_order == 0


# ===================== VulnRecord to_dict Tests =====================

class TestVulnRecordToDict:
    def test_basic(self):
        rec = VulnRecord(title="Test", severity="high", target="10.0.0.1")
        d = rec.to_dict()
        assert d["title"] == "Test"
        assert d["severity"] == "high"
        assert d["target"] == "10.0.0.1"

    def test_includes_all_fields(self):
        rec = VulnRecord()
        d = rec.to_dict()
        expected_keys = {
            "vuln_id", "title", "vuln_type", "severity", "confidence",
            "status", "source", "target", "endpoint", "params", "payload",
            "evidence", "cvss_score", "discovered_by", "verified_by",
            "discovered_at", "verified_at", "related_fragments", "tags",
        }
        assert set(d.keys()) == expected_keys

    def test_lists_are_copies(self):
        rec = VulnRecord(tags=["a", "b"])
        d = rec.to_dict()
        d["tags"].append("c")
        assert len(rec.tags) == 2

    def test_cvss_preserved(self):
        rec = VulnRecord(cvss_score=7.5)
        d = rec.to_dict()
        assert d["cvss_score"] == 7.5

    def test_none_fields(self):
        rec = VulnRecord()
        d = rec.to_dict()
        assert d["verified_by"] is None
        assert d["verified_at"] is None


# ===================== VulnRecord from_dict Tests =====================

class TestVulnRecordFromDict:
    def test_basic(self):
        data = {"title": "XSS", "vuln_type": "xss", "severity": "high"}
        rec = VulnRecord.from_dict(data)
        assert rec.title == "XSS"
        assert rec.vuln_type == "xss"
        assert rec.severity == "high"

    def test_ignores_extra_keys(self):
        data = {"title": "Test", "extra_field": "ignored", "foo": 42}
        rec = VulnRecord.from_dict(data)
        assert rec.title == "Test"
        assert not hasattr(rec, "extra_field")

    def test_missing_fields_use_defaults(self):
        data = {"title": "Only Title"}
        rec = VulnRecord.from_dict(data)
        assert rec.title == "Only Title"
        assert rec.severity == "medium"
        assert rec.status == "candidate"

    def test_round_trip(self):
        original = VulnRecord(
            title="RCE in API",
            vuln_type="rce",
            severity="critical",
            confidence="very_high",
            status="verified",
            source="manual",
            target="http://api.test.com",
            endpoint="/exec",
            params="cmd",
            payload="; cat /etc/passwd",
            evidence="root:x:0:0",
            cvss_score=10.0,
            discovered_by="manual_test",
            verified_by="team_lead",
            tags=["rce", "critical"],
            related_fragments=["FRAG-AAAA"],
        )
        d = original.to_dict()
        restored = VulnRecord.from_dict(d)
        assert restored.title == original.title
        assert restored.vuln_type == original.vuln_type
        assert restored.severity == original.severity
        assert restored.cvss_score == original.cvss_score
        assert restored.tags == original.tags
        assert restored.related_fragments == original.related_fragments
        assert restored.vuln_id == original.vuln_id

    def test_with_custom_id(self):
        data = {"vuln_id": "VULN-CUSTOM01", "title": "Custom"}
        rec = VulnRecord.from_dict(data)
        assert rec.vuln_id == "VULN-CUSTOM01"
