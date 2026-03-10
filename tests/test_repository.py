"""
Tests for database repositories (kali_mcp/database/repository.py)

Covers:
- ScanRecord, VulnRecord, SessionRecord dataclasses
- ScanRepository: save, find_by_target, find_by_tool, get_recent, get_stats
- VulnRepository: save, find_by_target, find_by_severity, get_stats
- SessionRepository: save, find_by_id, get_recent, update_status
"""

import os
import tempfile
from datetime import datetime

import pytest

from kali_mcp.database.repository import (
    ScanRecord,
    VulnRecord,
    SessionRecord,
    ScanRepository,
    VulnRepository,
    SessionRepository,
)


# ===================== Dataclass Tests =====================

class TestScanRecord:
    def test_creation(self):
        r = ScanRecord(
            id=None,
            target="10.0.0.1",
            tool_name="nmap",
            timestamp="2025-01-01T00:00:00",
            success=True,
            summary="Scan complete",
            findings_count=3,
            raw_output="output",
            findings_json="[]",
            execution_time=5.0,
        )
        assert r.target == "10.0.0.1"
        assert r.tool_name == "nmap"
        assert r.success is True


class TestVulnRecord:
    def test_creation(self):
        r = VulnRecord(
            id=None,
            target="http://example.com",
            vuln_type="sqli",
            severity="high",
            description="SQL injection found",
            evidence="id=1' OR 1=1",
            discovered_at="2025-01-01",
            tool_name="sqlmap",
        )
        assert r.severity == "high"
        assert r.cve_id is None

    def test_with_cve(self):
        r = VulnRecord(
            id=None,
            target="t",
            vuln_type="rce",
            severity="critical",
            description="RCE",
            evidence="",
            discovered_at="2025-01-01",
            tool_name="nuclei",
            cve_id="CVE-2024-1234",
        )
        assert r.cve_id == "CVE-2024-1234"


class TestSessionRecord:
    def test_creation(self):
        r = SessionRecord(
            id=None,
            session_id="sess-001",
            target="10.0.0.1",
            mode="pentest",
            start_time="2025-01-01T00:00:00",
            end_time=None,
            status="active",
            tools_used="nmap,gobuster",
            findings_count=5,
            flags_found="",
        )
        assert r.session_id == "sess-001"
        assert r.end_time is None


# ===================== ScanRepository Tests =====================

@pytest.fixture
def scan_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def scan_repo(scan_db):
    return ScanRepository(db_path=scan_db)


class TestScanRepoSave:
    def test_save_returns_id(self, scan_repo):
        rec = ScanRecord(
            id=None, target="10.0.0.1", tool_name="nmap",
            timestamp="2025-01-01T00:00:00", success=True,
            summary="OK", findings_count=2, raw_output="out",
            findings_json="[]", execution_time=1.5,
        )
        rid = scan_repo.save(rec)
        assert isinstance(rid, int)
        assert rid >= 1

    def test_save_multiple(self, scan_repo):
        for i in range(3):
            rec = ScanRecord(
                id=None, target=f"target{i}", tool_name="nmap",
                timestamp="2025-01-01", success=True,
                summary="", findings_count=0, raw_output="",
                findings_json="", execution_time=0,
            )
            scan_repo.save(rec)
        results = scan_repo.get_recent(10)
        assert len(results) == 3


class TestScanRepoQuery:
    def test_find_by_target(self, scan_repo):
        scan_repo.save(ScanRecord(
            id=None, target="10.0.0.1", tool_name="nmap",
            timestamp="2025-01-01", success=True,
            summary="", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        scan_repo.save(ScanRecord(
            id=None, target="10.0.0.2", tool_name="nmap",
            timestamp="2025-01-01", success=True,
            summary="", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        results = scan_repo.find_by_target("10.0.0.1")
        assert len(results) == 1
        assert results[0].target == "10.0.0.1"

    def test_find_by_tool(self, scan_repo):
        scan_repo.save(ScanRecord(
            id=None, target="t", tool_name="nmap",
            timestamp="2025-01-01", success=True,
            summary="", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        scan_repo.save(ScanRecord(
            id=None, target="t", tool_name="gobuster",
            timestamp="2025-01-01", success=True,
            summary="", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        results = scan_repo.find_by_tool("nmap")
        assert len(results) == 1
        assert results[0].tool_name == "nmap"

    def test_get_recent_ordering(self, scan_repo):
        scan_repo.save(ScanRecord(
            id=None, target="t", tool_name="nmap",
            timestamp="2025-01-01", success=True,
            summary="first", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        scan_repo.save(ScanRecord(
            id=None, target="t", tool_name="nmap",
            timestamp="2025-01-02", success=True,
            summary="second", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        results = scan_repo.get_recent(10)
        assert results[0].timestamp >= results[1].timestamp

    def test_get_stats(self, scan_repo):
        scan_repo.save(ScanRecord(
            id=None, target="t", tool_name="nmap",
            timestamp="2025-01-01", success=True,
            summary="", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        scan_repo.save(ScanRecord(
            id=None, target="t", tool_name="nmap",
            timestamp="2025-01-01", success=False,
            summary="", findings_count=0, raw_output="",
            findings_json="", execution_time=0,
        ))
        stats = scan_repo.get_stats()
        assert stats["total_scans"] == 2
        assert stats["successful_scans"] == 1
        assert stats["success_rate"] == 0.5
        assert "nmap" in stats["tool_stats"]

    def test_get_stats_empty(self, scan_repo):
        stats = scan_repo.get_stats()
        assert stats["total_scans"] == 0
        assert stats["success_rate"] == 0


# ===================== VulnRepository Tests =====================

@pytest.fixture
def vuln_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def vuln_repo(vuln_db):
    return VulnRepository(db_path=vuln_db)


class TestVulnRepoSave:
    def test_save_returns_id(self, vuln_repo):
        rec = VulnRecord(
            id=None, target="http://example.com", vuln_type="sqli",
            severity="high", description="SQL injection",
            evidence="id=1'", discovered_at="2025-01-01",
            tool_name="sqlmap",
        )
        rid = vuln_repo.save(rec)
        assert isinstance(rid, int)
        assert rid >= 1


class TestVulnRepoQuery:
    def test_find_by_target(self, vuln_repo):
        vuln_repo.save(VulnRecord(
            id=None, target="http://example.com", vuln_type="sqli",
            severity="high", description="", evidence="",
            discovered_at="2025-01-01", tool_name="sqlmap",
        ))
        results = vuln_repo.find_by_target("http://example.com")
        assert len(results) == 1
        assert results[0].vuln_type == "sqli"

    def test_find_by_severity(self, vuln_repo):
        vuln_repo.save(VulnRecord(
            id=None, target="t", vuln_type="sqli",
            severity="critical", description="", evidence="",
            discovered_at="2025-01-01", tool_name="sqlmap",
        ))
        vuln_repo.save(VulnRecord(
            id=None, target="t", vuln_type="info_leak",
            severity="low", description="", evidence="",
            discovered_at="2025-01-01", tool_name="nikto",
        ))
        crits = vuln_repo.find_by_severity("critical")
        assert len(crits) == 1
        assert crits[0].severity == "critical"

    def test_get_stats(self, vuln_repo):
        vuln_repo.save(VulnRecord(
            id=None, target="t", vuln_type="sqli",
            severity="high", description="", evidence="",
            discovered_at="2025-01-01", tool_name="sqlmap",
        ))
        vuln_repo.save(VulnRecord(
            id=None, target="t", vuln_type="xss",
            severity="medium", description="", evidence="",
            discovered_at="2025-01-01", tool_name="nuclei",
        ))
        stats = vuln_repo.get_stats()
        assert stats["total"] == 2
        assert "high" in stats["by_severity"]
        assert "sqli" in stats["by_type"]


# ===================== SessionRepository Tests =====================

@pytest.fixture
def session_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def session_repo(session_db):
    return SessionRepository(db_path=session_db)


class TestSessionRepoSave:
    def test_save_returns_id(self, session_repo):
        rec = SessionRecord(
            id=None, session_id="sess-001", target="10.0.0.1",
            mode="pentest", start_time="2025-01-01T00:00:00",
            end_time=None, status="active",
            tools_used="nmap", findings_count=0, flags_found="",
        )
        rid = session_repo.save(rec)
        assert isinstance(rid, int)


class TestSessionRepoQuery:
    def test_find_by_id(self, session_repo):
        session_repo.save(SessionRecord(
            id=None, session_id="sess-001", target="10.0.0.1",
            mode="pentest", start_time="2025-01-01",
            end_time=None, status="active",
            tools_used="nmap", findings_count=0, flags_found="",
        ))
        result = session_repo.find_by_id("sess-001")
        assert result is not None
        assert result.session_id == "sess-001"
        assert result.mode == "pentest"

    def test_find_by_id_nonexistent(self, session_repo):
        result = session_repo.find_by_id("not-exist")
        assert result is None

    def test_get_recent(self, session_repo):
        for i in range(3):
            session_repo.save(SessionRecord(
                id=None, session_id=f"sess-{i:03d}", target="t",
                mode="pentest", start_time=f"2025-01-0{i+1}",
                end_time=None, status="active",
                tools_used="", findings_count=0, flags_found="",
            ))
        results = session_repo.get_recent(10)
        assert len(results) == 3

    def test_update_status(self, session_repo):
        session_repo.save(SessionRecord(
            id=None, session_id="sess-upd", target="t",
            mode="pentest", start_time="2025-01-01",
            end_time=None, status="active",
            tools_used="", findings_count=0, flags_found="",
        ))
        session_repo.update_status("sess-upd", "completed", "2025-01-01T01:00:00")
        result = session_repo.find_by_id("sess-upd")
        assert result.status == "completed"
        assert result.end_time == "2025-01-01T01:00:00"

    def test_update_status_without_end_time(self, session_repo):
        session_repo.save(SessionRecord(
            id=None, session_id="sess-upd2", target="t",
            mode="ctf", start_time="2025-01-01",
            end_time=None, status="active",
            tools_used="", findings_count=0, flags_found="",
        ))
        session_repo.update_status("sess-upd2", "paused")
        result = session_repo.find_by_id("sess-upd2")
        assert result.status == "paused"
        assert result.end_time is None
