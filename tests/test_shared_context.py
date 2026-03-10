"""
Tests for shared_context module (kali_mcp/core/shared_context.py)

Covers:
- SharedMessage: creation, to_dict
- Key constants
- SharedContext: init, set_key/get_key, get_all_keys, delete_key,
  broadcast, get_broadcasts, get_recent_broadcasts, get_statistics
"""

import os
import json
import tempfile
import pytest

from kali_mcp.core.shared_context import (
    SharedMessage,
    SharedContext,
    KEY_TARGET_ENV,
    KEY_SOURCE_CODE,
    KEY_VULN_CANDIDATES,
    KEY_CREDENTIALS,
    KEY_ATTACK_SURFACE,
    KEY_TECH_STACK,
    KEY_OPEN_PORTS,
    KEY_ENDPOINTS,
)


# ===================== SharedMessage Tests =====================

class TestSharedMessage:
    def test_defaults(self):
        msg = SharedMessage()
        assert msg.agent_id == ""
        assert msg.message_type == ""
        assert msg.content == ""
        assert msg.data == {}
        assert msg.timestamp != ""

    def test_with_values(self):
        msg = SharedMessage(
            agent_id="recon_agent",
            message_type="discovery",
            content="Found open port 80",
            data={"port": 80, "service": "http"},
        )
        assert msg.agent_id == "recon_agent"
        assert msg.message_type == "discovery"
        assert msg.data["port"] == 80

    def test_to_dict(self):
        msg = SharedMessage(agent_id="a1", message_type="alert", content="test")
        d = msg.to_dict()
        assert d["agent_id"] == "a1"
        assert d["message_type"] == "alert"
        assert d["content"] == "test"
        assert "timestamp" in d
        assert "data" in d

    def test_mutable_data_independent(self):
        m1 = SharedMessage()
        m2 = SharedMessage()
        m1.data["key"] = "val"
        assert m2.data == {}


# ===================== Key Constants Tests =====================

class TestKeyConstants:
    def test_constants_defined(self):
        assert KEY_TARGET_ENV == "TargetEnvInfo"
        assert KEY_SOURCE_CODE == "SourceCodeInfo"
        assert KEY_VULN_CANDIDATES == "VulnCandidates"
        assert KEY_CREDENTIALS == "Credentials"
        assert KEY_ATTACK_SURFACE == "AttackSurface"
        assert KEY_TECH_STACK == "TechStack"
        assert KEY_OPEN_PORTS == "OpenPorts"
        assert KEY_ENDPOINTS == "Endpoints"


# ===================== SharedContext Init Tests =====================

@pytest.fixture
def ctx(tmp_path):
    """Create a SharedContext with a temporary database."""
    db_path = str(tmp_path / "test_shared_context.db")
    return SharedContext(db_path=db_path)


class TestSharedContextInit:
    def test_creates_db(self, tmp_path):
        db_path = str(tmp_path / "init_test.db")
        ctx = SharedContext(db_path=db_path)
        assert os.path.exists(db_path)

    def test_empty_initial_state(self, ctx):
        stats = ctx.get_statistics()
        assert stats["key_count"] == 0
        assert stats["broadcast_count"] == 0
        assert stats["memory_broadcasts"] == 0


# ===================== KeyMessage (set/get/delete) Tests =====================

class TestKeyMessages:
    def test_set_and_get_string(self, ctx):
        ctx.set_key("test_key", "test_value", updated_by="test_agent")
        result = ctx.get_key("test_key")
        assert result == "test_value"

    def test_set_and_get_dict(self, ctx):
        data = {"ports": [80, 443], "os": "Linux"}
        ctx.set_key(KEY_OPEN_PORTS, data, updated_by="nmap")
        result = ctx.get_key(KEY_OPEN_PORTS)
        assert result["ports"] == [80, 443]
        assert result["os"] == "Linux"

    def test_set_and_get_list(self, ctx):
        ctx.set_key("endpoints", ["/api/v1", "/admin"], updated_by="gobuster")
        result = ctx.get_key("endpoints")
        assert result == ["/api/v1", "/admin"]

    def test_get_nonexistent_key(self, ctx):
        result = ctx.get_key("nonexistent")
        assert result is None

    def test_overwrite_key(self, ctx):
        ctx.set_key("k", "v1", updated_by="a1")
        ctx.set_key("k", "v2", updated_by="a2")
        result = ctx.get_key("k")
        assert result == "v2"

    def test_get_all_keys_empty(self, ctx):
        result = ctx.get_all_keys()
        assert result == {}

    def test_get_all_keys_populated(self, ctx):
        ctx.set_key("k1", "v1", updated_by="agent1")
        ctx.set_key("k2", {"nested": True}, updated_by="agent2")
        result = ctx.get_all_keys()
        assert "k1" in result
        assert "k2" in result
        assert result["k1"]["value"] == "v1"
        assert result["k1"]["updated_by"] == "agent1"
        assert result["k2"]["value"]["nested"] is True

    def test_delete_key_existing(self, ctx):
        ctx.set_key("to_delete", "val")
        assert ctx.delete_key("to_delete") is True
        assert ctx.get_key("to_delete") is None

    def test_delete_key_nonexistent(self, ctx):
        assert ctx.delete_key("nonexistent") is False

    def test_set_numeric_value(self, ctx):
        ctx.set_key("count", 42)
        result = ctx.get_key("count")
        assert result == 42

    def test_set_boolean_value(self, ctx):
        ctx.set_key("flag", True)
        result = ctx.get_key("flag")
        assert result is True


# ===================== Broadcast Tests =====================

class TestBroadcast:
    def test_broadcast_and_retrieve(self, ctx):
        ctx.broadcast("agent1", "discovery", "Found SQL injection",
                      data={"vuln": "sqli"})
        broadcasts = ctx.get_broadcasts(limit=10)
        assert len(broadcasts) == 1
        assert broadcasts[0]["agent_id"] == "agent1"
        assert broadcasts[0]["message_type"] == "discovery"
        assert broadcasts[0]["content"] == "Found SQL injection"
        assert broadcasts[0]["data"]["vuln"] == "sqli"

    def test_multiple_broadcasts(self, ctx):
        ctx.broadcast("a1", "discovery", "msg1")
        ctx.broadcast("a2", "alert", "msg2")
        ctx.broadcast("a1", "status", "msg3")
        broadcasts = ctx.get_broadcasts(limit=10)
        assert len(broadcasts) == 3

    def test_broadcast_limit(self, ctx):
        for i in range(10):
            ctx.broadcast("agent", "status", f"msg{i}")
        broadcasts = ctx.get_broadcasts(limit=3)
        assert len(broadcasts) == 3

    def test_broadcast_filter_by_agent(self, ctx):
        ctx.broadcast("a1", "discovery", "from a1")
        ctx.broadcast("a2", "discovery", "from a2")
        ctx.broadcast("a1", "alert", "from a1 again")
        broadcasts = ctx.get_broadcasts(limit=10, agent_id="a1")
        assert len(broadcasts) == 2
        assert all(b["agent_id"] == "a1" for b in broadcasts)

    def test_broadcast_filter_by_type(self, ctx):
        ctx.broadcast("a1", "discovery", "disc")
        ctx.broadcast("a1", "alert", "alert")
        ctx.broadcast("a2", "discovery", "disc2")
        broadcasts = ctx.get_broadcasts(limit=10, message_type="discovery")
        assert len(broadcasts) == 2

    def test_broadcast_no_data(self, ctx):
        ctx.broadcast("a1", "status", "no data")
        broadcasts = ctx.get_broadcasts(limit=1)
        assert broadcasts[0]["data"] == {}

    def test_get_recent_broadcasts_memory(self, ctx):
        ctx.broadcast("a1", "d", "m1")
        ctx.broadcast("a2", "d", "m2")
        ctx.broadcast("a3", "d", "m3")
        recent = ctx.get_recent_broadcasts(count=2)
        assert len(recent) == 2
        assert recent[0].agent_id == "a2"
        assert recent[1].agent_id == "a3"

    def test_broadcast_memory_cap(self, ctx):
        """Test that memory broadcasts are capped at _max_broadcasts."""
        ctx._max_broadcasts = 5
        for i in range(10):
            ctx.broadcast("agent", "status", f"msg{i}")
        assert len(ctx._broadcasts) == 5
        # Should keep the most recent
        assert ctx._broadcasts[-1].content == "msg9"


# ===================== Statistics Tests =====================

class TestStatistics:
    def test_statistics_with_data(self, ctx):
        ctx.set_key("k1", "v1")
        ctx.set_key("k2", "v2")
        ctx.broadcast("a1", "d", "m1")
        ctx.broadcast("a2", "d", "m2")
        ctx.broadcast("a3", "d", "m3")
        stats = ctx.get_statistics()
        assert stats["key_count"] == 2
        assert stats["broadcast_count"] == 3
        assert stats["memory_broadcasts"] == 3

    def test_statistics_after_delete(self, ctx):
        ctx.set_key("k1", "v1")
        ctx.set_key("k2", "v2")
        ctx.delete_key("k1")
        stats = ctx.get_statistics()
        assert stats["key_count"] == 1


# ===================== Persistence Tests =====================

class TestPersistence:
    def test_data_persists_across_instances(self, tmp_path):
        db_path = str(tmp_path / "persist_test.db")

        ctx1 = SharedContext(db_path=db_path)
        ctx1.set_key("persist_key", {"data": "persisted"})
        ctx1.broadcast("agent", "discovery", "persisted broadcast")

        ctx2 = SharedContext(db_path=db_path)
        assert ctx2.get_key("persist_key") == {"data": "persisted"}
        broadcasts = ctx2.get_broadcasts(limit=10)
        assert len(broadcasts) == 1
        assert broadcasts[0]["content"] == "persisted broadcast"
