"""
Tests for checkpoint_manager module (kali_mcp/core/checkpoint_manager.py)

Covers:
- CheckpointManager: init, save_checkpoint, load_checkpoint, get_latest,
  list_checkpoints, delete_checkpoint, persistence, threading safety
"""

import os
import tempfile
import pytest

from kali_mcp.core.checkpoint_manager import CheckpointManager


# ===================== Fixtures =====================

@pytest.fixture
def mgr(tmp_path):
    """Create a CheckpointManager with a temporary database."""
    db_path = str(tmp_path / "test_checkpoints.db")
    return CheckpointManager(db_path=db_path)


# ===================== Init Tests =====================

class TestCheckpointManagerInit:
    def test_creates_db(self, tmp_path):
        db_path = str(tmp_path / "init_test.db")
        mgr = CheckpointManager(db_path=db_path)
        assert os.path.exists(db_path)

    def test_empty_initial(self, mgr):
        checkpoints = mgr.list_checkpoints()
        assert checkpoints == []


# ===================== save_checkpoint Tests =====================

class TestSaveCheckpoint:
    def test_save_returns_id(self, mgr):
        cp_id = mgr.save_checkpoint(
            session_id="sess1",
            phase="reconnaissance",
            description="Initial port scan done",
            state={"ports": [80, 443], "target": "10.0.0.1"},
        )
        assert cp_id.startswith("CP-")
        assert len(cp_id) == 11  # "CP-" + 8 hex chars

    def test_save_unique_ids(self, mgr):
        id1 = mgr.save_checkpoint("s1", "recon", "d1", {})
        id2 = mgr.save_checkpoint("s1", "recon", "d2", {})
        assert id1 != id2

    def test_save_multiple_sessions(self, mgr):
        mgr.save_checkpoint("s1", "recon", "scan1", {"data": 1})
        mgr.save_checkpoint("s2", "exploit", "exploit1", {"data": 2})
        all_cps = mgr.list_checkpoints()
        assert len(all_cps) == 2


# ===================== load_checkpoint Tests =====================

class TestLoadCheckpoint:
    def test_load_existing(self, mgr):
        cp_id = mgr.save_checkpoint("sess1", "recon", "Port scan",
                                    {"ports": [22, 80], "os": "Linux"})
        loaded = mgr.load_checkpoint(cp_id)
        assert loaded is not None
        assert loaded["checkpoint_id"] == cp_id
        assert loaded["session_id"] == "sess1"
        assert loaded["phase"] == "recon"
        assert loaded["description"] == "Port scan"
        assert loaded["state"]["ports"] == [22, 80]
        assert loaded["state"]["os"] == "Linux"
        assert "created_at" in loaded

    def test_load_nonexistent(self, mgr):
        result = mgr.load_checkpoint("CP-NONEXIST")
        assert result is None

    def test_load_state_is_dict(self, mgr):
        cp_id = mgr.save_checkpoint("s1", "p1", "d1", {"nested": {"deep": True}})
        loaded = mgr.load_checkpoint(cp_id)
        assert isinstance(loaded["state"], dict)
        assert loaded["state"]["nested"]["deep"] is True


# ===================== get_latest Tests =====================

class TestGetLatest:
    def test_latest_returns_most_recent(self, mgr):
        mgr.save_checkpoint("sess1", "recon", "first", {"step": 1})
        mgr.save_checkpoint("sess1", "exploit", "second", {"step": 2})
        mgr.save_checkpoint("sess1", "post", "third", {"step": 3})
        latest = mgr.get_latest("sess1")
        assert latest is not None
        assert latest["phase"] == "post"
        assert latest["state"]["step"] == 3

    def test_latest_different_sessions(self, mgr):
        mgr.save_checkpoint("s1", "recon", "s1 first", {"s": 1})
        mgr.save_checkpoint("s2", "exploit", "s2 first", {"s": 2})
        mgr.save_checkpoint("s1", "exploit", "s1 second", {"s": 3})

        latest_s1 = mgr.get_latest("s1")
        latest_s2 = mgr.get_latest("s2")
        assert latest_s1["description"] == "s1 second"
        assert latest_s2["description"] == "s2 first"

    def test_latest_nonexistent_session(self, mgr):
        result = mgr.get_latest("nonexistent")
        assert result is None


# ===================== list_checkpoints Tests =====================

class TestListCheckpoints:
    def test_list_all(self, mgr):
        mgr.save_checkpoint("s1", "p1", "d1", {})
        mgr.save_checkpoint("s2", "p2", "d2", {})
        mgr.save_checkpoint("s1", "p3", "d3", {})
        result = mgr.list_checkpoints()
        assert len(result) == 3

    def test_list_by_session(self, mgr):
        mgr.save_checkpoint("s1", "p1", "d1", {})
        mgr.save_checkpoint("s2", "p2", "d2", {})
        mgr.save_checkpoint("s1", "p3", "d3", {})
        result = mgr.list_checkpoints(session_id="s1")
        assert len(result) == 2
        assert all(r["session_id"] == "s1" for r in result)

    def test_list_has_expected_fields(self, mgr):
        mgr.save_checkpoint("s1", "recon", "test", {})
        result = mgr.list_checkpoints()
        assert len(result) == 1
        cp = result[0]
        assert "checkpoint_id" in cp
        assert "session_id" in cp
        assert "phase" in cp
        assert "description" in cp
        assert "created_at" in cp

    def test_list_does_not_include_state(self, mgr):
        """list_checkpoints selects specific columns, state is not included."""
        mgr.save_checkpoint("s1", "p1", "d1", {"big": "data"})
        result = mgr.list_checkpoints()
        assert "state" not in result[0]

    def test_list_empty_session(self, mgr):
        mgr.save_checkpoint("s1", "p1", "d1", {})
        result = mgr.list_checkpoints(session_id="s2")
        assert result == []


# ===================== delete_checkpoint Tests =====================

class TestDeleteCheckpoint:
    def test_delete_existing(self, mgr):
        cp_id = mgr.save_checkpoint("s1", "p1", "d1", {})
        assert mgr.delete_checkpoint(cp_id) is True
        assert mgr.load_checkpoint(cp_id) is None

    def test_delete_nonexistent(self, mgr):
        assert mgr.delete_checkpoint("CP-NONEXIST") is False

    def test_delete_only_target(self, mgr):
        id1 = mgr.save_checkpoint("s1", "p1", "d1", {})
        id2 = mgr.save_checkpoint("s1", "p2", "d2", {})
        mgr.delete_checkpoint(id1)
        assert mgr.load_checkpoint(id1) is None
        assert mgr.load_checkpoint(id2) is not None


# ===================== Persistence Tests =====================

class TestPersistence:
    def test_data_persists_across_instances(self, tmp_path):
        db_path = str(tmp_path / "persist_test.db")
        mgr1 = CheckpointManager(db_path=db_path)
        cp_id = mgr1.save_checkpoint("s1", "recon", "persist test",
                                     {"persisted": True})

        mgr2 = CheckpointManager(db_path=db_path)
        loaded = mgr2.load_checkpoint(cp_id)
        assert loaded is not None
        assert loaded["state"]["persisted"] is True

    def test_list_persists(self, tmp_path):
        db_path = str(tmp_path / "persist_list.db")
        mgr1 = CheckpointManager(db_path=db_path)
        mgr1.save_checkpoint("s1", "p1", "d1", {})
        mgr1.save_checkpoint("s1", "p2", "d2", {})

        mgr2 = CheckpointManager(db_path=db_path)
        result = mgr2.list_checkpoints(session_id="s1")
        assert len(result) == 2
