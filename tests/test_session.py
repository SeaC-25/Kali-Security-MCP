"""
Tests for session module (kali_mcp/core/session.py)

Covers:
- AttackMode, SessionStatus enums
- DiscoveredAsset, AttackStep dataclasses
- SessionContext: creation, add_asset, add_step, add_flag, get_ports,
  get_services, get_vulnerabilities, get_summary, to_dict, from_dict
- SessionManager: create, get, list, end, set_current, get_or_create, stats
"""

import tempfile
import os
import time

import pytest

from kali_mcp.core.session import (
    AttackMode,
    SessionStatus,
    DiscoveredAsset,
    AttackStep,
    SessionContext,
    SessionManager,
)


# ===================== Enum Tests =====================

class TestAttackMode:
    def test_values(self):
        assert AttackMode.CTF.value == "ctf"
        assert AttackMode.PENTEST.value == "pentest"
        assert AttackMode.APT.value == "apt"
        assert AttackMode.VULN_RESEARCH.value == "vuln_research"
        assert AttackMode.AWD.value == "awd"


class TestSessionStatus:
    def test_values(self):
        assert SessionStatus.ACTIVE.value == "active"
        assert SessionStatus.PAUSED.value == "paused"
        assert SessionStatus.COMPLETED.value == "completed"
        assert SessionStatus.FAILED.value == "failed"


# ===================== DiscoveredAsset Tests =====================

class TestDiscoveredAsset:
    def test_creation(self):
        asset = DiscoveredAsset(
            asset_type="port",
            value="80",
            source_tool="nmap"
        )
        assert asset.asset_type == "port"
        assert asset.value == "80"
        assert asset.source_tool == "nmap"
        assert asset.confidence == 1.0

    def test_to_dict(self):
        asset = DiscoveredAsset(
            asset_type="service",
            value="http",
            source_tool="nmap",
            confidence=0.9,
            metadata={"version": "Apache 2.4"}
        )
        d = asset.to_dict()
        assert d["type"] == "service"
        assert d["value"] == "http"
        assert d["source"] == "nmap"
        assert d["confidence"] == 0.9
        assert d["metadata"]["version"] == "Apache 2.4"


# ===================== AttackStep Tests =====================

class TestAttackStep:
    def test_creation(self):
        step = AttackStep(
            step_id="step-001",
            tool_name="nmap",
            command="nmap -sV 10.0.0.1",
            success=True,
            output_summary="Found 3 open ports"
        )
        assert step.step_id == "step-001"
        assert step.tool_name == "nmap"
        assert step.success is True
        assert step.duration == 0.0

    def test_to_dict(self):
        step = AttackStep(
            step_id="step-002",
            tool_name="gobuster",
            command="gobuster dir -u http://target",
            success=False,
            output_summary="timeout",
            duration=30.5
        )
        d = step.to_dict()
        assert d["step_id"] == "step-002"
        assert d["tool"] == "gobuster"
        assert d["success"] is False
        assert d["duration"] == 30.5


# ===================== SessionContext Tests =====================

class TestSessionContext:
    def test_creation(self):
        ctx = SessionContext(
            session_id="sess-001",
            target="10.0.0.1"
        )
        assert ctx.session_id == "sess-001"
        assert ctx.target == "10.0.0.1"
        assert ctx.mode == AttackMode.PENTEST
        assert ctx.status == SessionStatus.ACTIVE
        assert ctx.flags_found == []
        assert ctx.tools_used == set()

    def test_add_asset(self):
        ctx = SessionContext(session_id="s1", target="t")
        asset = DiscoveredAsset("port", "80", "nmap")
        ctx.add_asset(asset)
        assert len(ctx.discovered_assets) == 1
        assert ctx.discovered_assets[0].value == "80"

    def test_add_step(self):
        ctx = SessionContext(session_id="s1", target="t")
        step = AttackStep("s1", "nmap", "nmap t", True, "OK")
        ctx.add_step(step)
        assert len(ctx.attack_steps) == 1
        assert "nmap" in ctx.tools_used

    def test_add_conversation(self):
        ctx = SessionContext(session_id="s1", target="t")
        ctx.add_conversation("user", "scan target")
        assert len(ctx.conversation_history) == 1
        assert ctx.conversation_history[0]["role"] == "user"
        assert ctx.conversation_history[0]["content"] == "scan target"

    def test_add_flag(self):
        ctx = SessionContext(session_id="s1", target="t")
        ctx.add_flag("flag{test123}")
        assert "flag{test123}" in ctx.flags_found
        # Also adds as asset
        assert any(a.asset_type == "flag" for a in ctx.discovered_assets)

    def test_add_flag_no_duplicate(self):
        ctx = SessionContext(session_id="s1", target="t")
        ctx.add_flag("flag{dup}")
        ctx.add_flag("flag{dup}")
        assert ctx.flags_found.count("flag{dup}") == 1

    def test_get_ports(self):
        ctx = SessionContext(session_id="s1", target="t")
        ctx.add_asset(DiscoveredAsset("port", "80", "nmap"))
        ctx.add_asset(DiscoveredAsset("port", "443", "nmap"))
        ctx.add_asset(DiscoveredAsset("service", "http", "nmap"))
        assert ctx.get_ports() == ["80", "443"]

    def test_get_services(self):
        ctx = SessionContext(session_id="s1", target="t")
        ctx.add_asset(DiscoveredAsset("service", "http", "nmap"))
        ctx.add_asset(DiscoveredAsset("port", "80", "nmap"))
        services = ctx.get_services()
        assert len(services) == 1
        assert services[0]["value"] == "http"

    def test_get_vulnerabilities(self):
        ctx = SessionContext(session_id="s1", target="t")
        ctx.add_asset(DiscoveredAsset("vulnerability", "SQLi", "sqlmap"))
        ctx.add_asset(DiscoveredAsset("port", "80", "nmap"))
        vulns = ctx.get_vulnerabilities()
        assert len(vulns) == 1
        assert vulns[0]["value"] == "SQLi"

    def test_get_summary(self):
        ctx = SessionContext(session_id="s1", target="10.0.0.1", mode=AttackMode.CTF)
        ctx.add_step(AttackStep("s1", "nmap", "cmd", True, "OK"))
        ctx.add_step(AttackStep("s2", "gobuster", "cmd", False, "fail"))
        ctx.add_flag("flag{test}")
        summary = ctx.get_summary()
        assert summary["session_id"] == "s1"
        assert summary["target"] == "10.0.0.1"
        assert summary["mode"] == "ctf"
        assert summary["steps_count"] == 2
        assert summary["flags_found"] == 1
        assert summary["success_rate"] == 50.0

    def test_success_rate_empty(self):
        ctx = SessionContext(session_id="s1", target="t")
        assert ctx._calculate_success_rate() == 0.0

    def test_to_dict(self):
        ctx = SessionContext(session_id="s1", target="t", mode=AttackMode.APT)
        ctx.add_asset(DiscoveredAsset("port", "80", "nmap"))
        ctx.add_step(AttackStep("s1", "nmap", "cmd", True, "OK"))
        ctx.add_flag("flag{x}")
        d = ctx.to_dict()
        assert d["session_id"] == "s1"
        assert d["mode"] == "apt"
        assert len(d["discovered_assets"]) == 2  # port + flag
        assert len(d["attack_steps"]) == 1
        assert "flag{x}" in d["flags_found"]

    def test_from_dict_round_trip(self):
        ctx = SessionContext(
            session_id="s1", target="10.0.0.1",
            mode=AttackMode.CTF, challenge_category="web"
        )
        ctx.add_asset(DiscoveredAsset("port", "80", "nmap", confidence=0.95))
        ctx.add_step(AttackStep("s1", "nmap", "nmap -sV t", True, "OK", duration=5.0))
        ctx.add_flag("flag{roundtrip}")
        ctx.metadata["key"] = "value"

        d = ctx.to_dict()
        restored = SessionContext.from_dict(d)

        assert restored.session_id == "s1"
        assert restored.target == "10.0.0.1"
        assert restored.mode == AttackMode.CTF
        assert restored.challenge_category == "web"
        assert "flag{roundtrip}" in restored.flags_found
        assert restored.metadata["key"] == "value"
        # Assets: port + flag from add_flag
        assert len(restored.discovered_assets) == 2
        assert len(restored.attack_steps) == 1
        assert restored.attack_steps[0].tool_name == "nmap"


# ===================== SessionManager Tests =====================

class TestSessionManager:
    def test_create_session(self):
        mgr = SessionManager()
        session = mgr.create_session("10.0.0.1")
        assert session.target == "10.0.0.1"
        assert session.mode == AttackMode.PENTEST
        assert session.status == SessionStatus.ACTIVE

    def test_create_session_with_name(self):
        mgr = SessionManager()
        session = mgr.create_session("t", session_name="my-session")
        assert session.session_id == "my-session"

    def test_create_session_duplicate_name(self):
        mgr = SessionManager()
        s1 = mgr.create_session("t", session_name="dup")
        s2 = mgr.create_session("t", session_name="dup")
        assert s1.session_id != s2.session_id

    def test_get_session(self):
        mgr = SessionManager()
        created = mgr.create_session("t")
        retrieved = mgr.get_session(created.session_id)
        assert retrieved is created

    def test_get_current_session(self):
        mgr = SessionManager()
        session = mgr.create_session("t")
        # get_session with None returns current
        current = mgr.get_session()
        assert current is session

    def test_get_session_none_when_empty(self):
        mgr = SessionManager()
        assert mgr.get_session() is None

    def test_set_current_session(self):
        mgr = SessionManager()
        s1 = mgr.create_session("t1")
        s2 = mgr.create_session("t2")
        # s2 is now current
        assert mgr.get_session() is s2
        # Switch back to s1
        assert mgr.set_current_session(s1.session_id) is True
        assert mgr.get_session() is s1

    def test_set_current_session_invalid(self):
        mgr = SessionManager()
        assert mgr.set_current_session("nonexistent") is False

    def test_end_session(self):
        mgr = SessionManager()
        session = mgr.create_session("t")
        ended = mgr.end_session(session.session_id)
        assert ended.status == SessionStatus.COMPLETED
        # Current session should be cleared
        assert mgr.get_session() is None

    def test_end_session_none(self):
        mgr = SessionManager()
        assert mgr.end_session("nonexistent") is None

    def test_end_current_session(self):
        mgr = SessionManager()
        mgr.create_session("t")
        ended = mgr.end_session()  # Ends current
        assert ended.status == SessionStatus.COMPLETED

    def test_list_sessions(self):
        mgr = SessionManager()
        mgr.create_session("t1")
        mgr.create_session("t2")
        sessions = mgr.list_sessions()
        assert len(sessions) == 2

    def test_get_or_create_session_creates(self):
        mgr = SessionManager()
        session = mgr.get_or_create_session("10.0.0.1")
        assert session.target == "10.0.0.1"

    def test_get_or_create_session_reuses(self):
        mgr = SessionManager()
        s1 = mgr.get_or_create_session("10.0.0.1")
        s2 = mgr.get_or_create_session("10.0.0.1")
        assert s1 is s2

    def test_get_or_create_session_new_target(self):
        mgr = SessionManager()
        s1 = mgr.get_or_create_session("10.0.0.1")
        s2 = mgr.get_or_create_session("10.0.0.2")
        assert s1 is not s2

    def test_get_stats(self):
        mgr = SessionManager()
        mgr.create_session("t1")
        mgr.create_session("t2")
        mgr.end_session()  # End t2 (current)
        stats = mgr.get_stats()
        assert stats["total_sessions"] == 2
        assert stats["active_sessions"] == 1
        assert stats["completed_sessions"] == 1

    def test_storage_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = SessionManager(storage_dir=tmpdir)
            session = mgr.create_session("10.0.0.1", session_name="test-save")
            session.add_flag("flag{saved}")
            mgr.end_session(session.session_id)

            # Create a new manager and load
            mgr2 = SessionManager(storage_dir=tmpdir)
            loaded = mgr2.load_session("test-save")
            assert loaded is not None
            assert loaded.target == "10.0.0.1"
            assert "flag{saved}" in loaded.flags_found

    def test_load_nonexistent_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = SessionManager(storage_dir=tmpdir)
            assert mgr.load_session("nope") is None

    def test_load_no_storage_dir(self):
        mgr = SessionManager()
        assert mgr.load_session("anything") is None
