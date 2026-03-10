"""
Tests for VulnManager and VulnModels (kali_mcp/core/vuln_manager.py, vuln_models.py)

Covers:
- VulnRecord creation, serialization, and deserialization
- VulnStatus/VulnSeverity enums
- VulnManager CRUD operations (SQLite-backed)
- Verification lifecycle (candidate → verifying → verified/failed)
- Cross-validation
- Statistics and report export
"""

import tempfile
import os

import pytest

from kali_mcp.core.vuln_models import VulnRecord, VulnStatus, VulnSeverity, VulnSource, VulnConfidence
from kali_mcp.core.vuln_manager import VulnManager


@pytest.fixture
def tmp_db():
    """Create a temp database path for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def vm(tmp_db):
    """Create a VulnManager with temp database."""
    return VulnManager(db_path=tmp_db)


def _make_vuln(**overrides):
    """Helper to create a VulnRecord."""
    defaults = {
        "title": "Test SQL Injection",
        "vuln_type": "sqli",
        "severity": "high",
        "target": "http://example.com",
        "endpoint": "/api/users",
        "params": "id",
        "payload": "' OR 1=1--",
        "discovered_by": "sqlmap",
    }
    defaults.update(overrides)
    return VulnRecord(**defaults)


# ===================== VulnModels Tests =====================

class TestVulnRecord:
    """Test VulnRecord dataclass."""

    def test_default_values(self):
        v = VulnRecord()
        assert v.vuln_id.startswith("VULN-")
        assert v.status == "candidate"
        assert v.severity == "medium"

    def test_to_dict(self):
        v = _make_vuln()
        d = v.to_dict()
        assert d["title"] == "Test SQL Injection"
        assert d["vuln_type"] == "sqli"
        assert isinstance(d["tags"], list)

    def test_from_dict(self):
        original = _make_vuln()
        d = original.to_dict()
        restored = VulnRecord.from_dict(d)
        assert restored.title == original.title
        assert restored.vuln_type == original.vuln_type

    def test_from_dict_ignores_extra_keys(self):
        d = {"title": "Test", "vuln_type": "xss", "unknown_key": "value"}
        v = VulnRecord.from_dict(d)
        assert v.title == "Test"

    def test_severity_order(self):
        assert VulnRecord(severity="critical").severity_order == 5
        assert VulnRecord(severity="high").severity_order == 4
        assert VulnRecord(severity="medium").severity_order == 3
        assert VulnRecord(severity="low").severity_order == 2
        assert VulnRecord(severity="info").severity_order == 1
        assert VulnRecord(severity="unknown").severity_order == 0


class TestVulnEnums:
    """Test enum values."""

    def test_vuln_status_values(self):
        assert VulnStatus.CANDIDATE.value == "candidate"
        assert VulnStatus.VERIFIED.value == "verified"
        assert VulnStatus.FAILED.value == "failed"

    def test_vuln_severity_values(self):
        assert VulnSeverity.CRITICAL.value == "critical"
        assert VulnSeverity.INFO.value == "info"

    def test_vuln_source_values(self):
        assert VulnSource.BLACKBOX.value == "blackbox"
        assert VulnSource.CROSS_VALIDATED.value == "cross_validated"

    def test_vuln_confidence_values(self):
        assert VulnConfidence.VERY_HIGH.value == "very_high"


# ===================== VulnManager CRUD Tests =====================

class TestVulnManagerCRUD:
    """Test basic CRUD operations."""

    def test_issue_and_get(self, vm):
        vuln = _make_vuln()
        vid = vm.issue_vuln(vuln)
        assert vid == vuln.vuln_id

        retrieved = vm.get_by_id(vid)
        assert retrieved is not None
        assert retrieved.title == "Test SQL Injection"
        assert retrieved.vuln_type == "sqli"

    def test_get_nonexistent(self, vm):
        assert vm.get_by_id("VULN-FAKE") is None

    def test_get_all(self, vm):
        vm.issue_vuln(_make_vuln(title="Vuln 1"))
        vm.issue_vuln(_make_vuln(title="Vuln 2"))
        all_vulns = vm.get_all()
        assert len(all_vulns) == 2

    def test_get_candidates(self, vm):
        vm.issue_vuln(_make_vuln(severity="critical"))
        vm.issue_vuln(_make_vuln(severity="low"))
        candidates = vm.get_candidates()
        assert len(candidates) == 2
        # Critical should come first
        assert candidates[0].severity == "critical"

    def test_get_by_type(self, vm):
        vm.issue_vuln(_make_vuln(vuln_type="sqli"))
        vm.issue_vuln(_make_vuln(vuln_type="xss"))
        sqli_vulns = vm.get_by_type("sqli")
        assert len(sqli_vulns) == 1

    def test_get_by_target(self, vm):
        vm.issue_vuln(_make_vuln(target="http://example.com"))
        vm.issue_vuln(_make_vuln(target="http://other.com"))
        results = vm.get_by_target("example.com")
        assert len(results) == 1


# ===================== Verification Lifecycle Tests =====================

class TestVerificationLifecycle:
    """Test verification state machine."""

    def test_start_verification(self, vm):
        vuln = _make_vuln()
        vid = vm.issue_vuln(vuln)

        ok = vm.start_verification(vid)
        assert ok is True

        record = vm.get_by_id(vid)
        assert record.status == "verifying"

    def test_start_verification_non_candidate_fails(self, vm):
        vuln = _make_vuln()
        vid = vm.issue_vuln(vuln)
        vm.start_verification(vid)

        # Try to start verification again (already verifying)
        ok = vm.start_verification(vid)
        assert ok is False

    def test_submit_verified(self, vm):
        vuln = _make_vuln()
        vid = vm.issue_vuln(vuln)
        vm.start_verification(vid)

        ok = vm.submit_result(vid, verified=True, evidence="Confirmed", verified_by="manual")
        assert ok is True

        record = vm.get_by_id(vid)
        assert record.status == "verified"
        assert record.verified_by == "manual"

    def test_submit_failed(self, vm):
        vuln = _make_vuln()
        vid = vm.issue_vuln(vuln)
        vm.start_verification(vid)

        ok = vm.submit_result(vid, verified=False)
        assert ok is True

        record = vm.get_by_id(vid)
        assert record.status == "failed"

    def test_get_verified(self, vm):
        v1 = _make_vuln(cvss_score=9.8)
        v2 = _make_vuln(cvss_score=5.0)
        vid1 = vm.issue_vuln(v1)
        vid2 = vm.issue_vuln(v2)

        for vid in [vid1, vid2]:
            vm.start_verification(vid)
            vm.submit_result(vid, verified=True)

        verified = vm.get_verified()
        assert len(verified) == 2
        # Higher CVSS first
        assert verified[0].cvss_score == 9.8

    def test_dismiss(self, vm):
        vuln = _make_vuln()
        vid = vm.issue_vuln(vuln)
        ok = vm.dismiss(vid)
        assert ok is True
        record = vm.get_by_id(vid)
        assert record.status == "dismissed"

    def test_get_one_candidate(self, vm):
        vm.issue_vuln(_make_vuln(severity="low"))
        vm.issue_vuln(_make_vuln(severity="critical"))
        top = vm.get_one_candidate()
        assert top is not None
        assert top.severity == "critical"


# ===================== Cross-Validation Tests =====================

class TestCrossValidation:
    """Test cross-validation between blackbox and whitebox findings."""

    def test_high_match_score(self, vm):
        bb = _make_vuln(source="blackbox", target="http://example.com",
                        endpoint="/api", vuln_type="sqli")
        wb = _make_vuln(source="whitebox", target="http://example.com",
                        endpoint="/api", vuln_type="sqli")
        bb_id = vm.issue_vuln(bb)
        wb_id = vm.issue_vuln(wb)

        score = vm.cross_validate(bb_id, wb_id)
        assert score >= 0.7

        # Both should be upgraded to very_high confidence
        bb_record = vm.get_by_id(bb_id)
        assert bb_record.confidence == "very_high"

    def test_low_match_score(self, vm):
        bb = _make_vuln(source="blackbox", target="http://example.com",
                        endpoint="/api", vuln_type="sqli")
        wb = _make_vuln(source="whitebox", target="http://other.com",
                        endpoint="/login", vuln_type="xss")
        bb_id = vm.issue_vuln(bb)
        wb_id = vm.issue_vuln(wb)

        score = vm.cross_validate(bb_id, wb_id)
        assert score < 0.7

    def test_nonexistent_vuln(self, vm):
        score = vm.cross_validate("FAKE-1", "FAKE-2")
        assert score == 0.0


# ===================== Statistics and Reports =====================

class TestStatisticsAndReports:
    """Test statistics and report export."""

    def test_empty_statistics(self, vm):
        stats = vm.get_statistics()
        assert stats["total"] == 0
        assert stats["verified"] == 0

    def test_statistics_with_data(self, vm):
        vm.issue_vuln(_make_vuln(severity="critical"))
        vm.issue_vuln(_make_vuln(severity="high"))
        stats = vm.get_statistics()
        assert stats["total"] == 2
        assert stats["candidates"] == 2

    def test_export_json_report(self, vm):
        vm.issue_vuln(_make_vuln())
        report = vm.export_report("json")
        import json
        data = json.loads(report)
        assert "statistics" in data
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) == 1

    def test_export_markdown_report(self, vm):
        vm.issue_vuln(_make_vuln(severity="critical", title="Critical Bug"))
        report = vm.export_report("markdown")
        assert "漏洞评估报告" in report
        assert "Critical Bug" in report
