"""
Tests for ChainManager and ChainModels (kali_mcp/core/chain_manager.py, chain_models.py)

Covers:
- ChainStep and AttackChain dataclass creation and serialization
- ChainManager CRUD with SQLite
- Step management
- Status transitions
- Feasibility analysis
- Statistics
"""

import tempfile
import os

import pytest

from kali_mcp.core.chain_models import ChainStep, AttackChain, ChainStatus
from kali_mcp.core.chain_manager import ChainManager


@pytest.fixture
def tmp_db():
    """Create temp database path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def cm(tmp_db):
    """Create a ChainManager with temp database."""
    return ChainManager(db_path=tmp_db)


def _make_step(**overrides):
    defaults = {
        "title": "Port Scan",
        "action": "nmap -sV target",
        "tool_used": "nmap",
        "precondition": "",
        "expected_result": "Open ports found",
    }
    defaults.update(overrides)
    return ChainStep(**defaults)


def _make_chain(**overrides):
    defaults = {
        "title": "Web Attack Chain",
        "description": "Full web attack",
        "impact_level": "high",
    }
    defaults.update(overrides)
    return AttackChain(**defaults)


# ===================== ChainModels Tests =====================

class TestChainStep:
    """Test ChainStep dataclass."""

    def test_default_values(self):
        step = ChainStep()
        assert step.order == 0
        assert step.title == ""

    def test_to_dict(self):
        step = _make_step()
        d = step.to_dict()
        assert d["title"] == "Port Scan"
        assert d["tool_used"] == "nmap"

    def test_from_dict(self):
        step = _make_step()
        d = step.to_dict()
        restored = ChainStep.from_dict(d)
        assert restored.title == step.title
        assert restored.tool_used == step.tool_used

    def test_from_dict_ignores_extra(self):
        d = {"title": "Test", "action": "do", "extra_field": "ignored"}
        step = ChainStep.from_dict(d)
        assert step.title == "Test"


class TestAttackChain:
    """Test AttackChain dataclass."""

    def test_default_values(self):
        chain = AttackChain()
        assert chain.chain_id.startswith("CHAIN-")
        assert chain.status == "draft"
        assert chain.feasibility_score == 0

    def test_to_dict(self):
        chain = _make_chain()
        chain.steps = [_make_step()]
        d = chain.to_dict()
        assert d["title"] == "Web Attack Chain"
        assert len(d["steps"]) == 1

    def test_from_dict(self):
        chain = _make_chain()
        chain.steps = [_make_step()]
        d = chain.to_dict()
        restored = AttackChain.from_dict(d)
        assert restored.title == chain.title
        assert len(restored.steps) == 1

    def test_impact_order(self):
        assert AttackChain(impact_level="critical").impact_order == 4
        assert AttackChain(impact_level="high").impact_order == 3
        assert AttackChain(impact_level="medium").impact_order == 2
        assert AttackChain(impact_level="low").impact_order == 1
        assert AttackChain(impact_level="unknown").impact_order == 0


class TestChainStatus:
    """Test ChainStatus enum."""

    def test_status_values(self):
        assert ChainStatus.DRAFT.value == "draft"
        assert ChainStatus.ANALYZING.value == "analyzing"
        assert ChainStatus.CONFIRMED.value == "confirmed"
        assert ChainStatus.EXECUTED.value == "executed"
        assert ChainStatus.FAILED.value == "failed"


# ===================== ChainManager CRUD Tests =====================

class TestChainManagerCRUD:
    """Test ChainManager CRUD operations."""

    def test_create_and_get(self, cm):
        chain = _make_chain()
        cid = cm.create_chain(chain)
        assert cid == chain.chain_id

        retrieved = cm.get_by_id(cid)
        assert retrieved is not None
        assert retrieved.title == "Web Attack Chain"

    def test_get_nonexistent(self, cm):
        assert cm.get_by_id("CHAIN-FAKE") is None

    def test_get_all(self, cm):
        cm.create_chain(_make_chain(title="Chain 1"))
        cm.create_chain(_make_chain(title="Chain 2"))
        chains = cm.get_all()
        assert len(chains) == 2

    def test_get_all_by_status(self, cm):
        c1 = _make_chain(title="Draft")
        c2 = _make_chain(title="Confirmed")
        cm.create_chain(c1)
        cm.create_chain(c2)
        cm.update_status(c2.chain_id, "confirmed")

        drafts = cm.get_all(status="draft")
        assert len(drafts) == 1
        assert drafts[0].title == "Draft"


# ===================== Step Management Tests =====================

class TestStepManagement:
    """Test adding steps to chains."""

    def test_add_step(self, cm):
        chain = _make_chain()
        cm.create_chain(chain)

        step = _make_step(title="Scan Ports")
        ok = cm.add_step(chain.chain_id, step)
        assert ok is True

        retrieved = cm.get_by_id(chain.chain_id)
        assert len(retrieved.steps) == 1
        assert retrieved.steps[0].title == "Scan Ports"
        assert retrieved.steps[0].order == 1

    def test_add_multiple_steps(self, cm):
        chain = _make_chain()
        cm.create_chain(chain)

        cm.add_step(chain.chain_id, _make_step(title="Step 1"))
        cm.add_step(chain.chain_id, _make_step(title="Step 2"))
        cm.add_step(chain.chain_id, _make_step(title="Step 3"))

        retrieved = cm.get_by_id(chain.chain_id)
        assert len(retrieved.steps) == 3
        assert retrieved.steps[2].order == 3

    def test_add_step_nonexistent_chain(self, cm):
        ok = cm.add_step("CHAIN-FAKE", _make_step())
        assert ok is False


# ===================== Status Management Tests =====================

class TestStatusManagement:
    """Test status transitions."""

    def test_update_status(self, cm):
        chain = _make_chain()
        cm.create_chain(chain)

        ok = cm.update_status(chain.chain_id, "confirmed")
        assert ok is True

        retrieved = cm.get_by_id(chain.chain_id)
        assert retrieved.status == "confirmed"

    def test_update_nonexistent(self, cm):
        ok = cm.update_status("CHAIN-FAKE", "confirmed")
        assert ok is False


# ===================== Feasibility Analysis Tests =====================

class TestFeasibilityAnalysis:
    """Test feasibility scoring."""

    def test_no_steps_low_score(self, cm):
        chain = _make_chain()
        cm.create_chain(chain)
        result = cm.analyze_feasibility(chain.chain_id)
        assert result["score"] == 0
        assert result["recommendation"] == "不建议执行"

    def test_with_steps(self, cm):
        chain = _make_chain()
        cm.create_chain(chain)
        cm.add_step(chain.chain_id, _make_step(title="Recon"))
        cm.add_step(chain.chain_id, _make_step(title="Exploit"))

        result = cm.analyze_feasibility(chain.chain_id)
        assert result["score"] > 0

    def test_with_steps_and_evidence(self, cm):
        chain = _make_chain(fragments=["FRAG-1"], vulns=["VULN-1"])
        chain.steps = [_make_step()]
        cm.create_chain(chain)

        result = cm.analyze_feasibility(chain.chain_id)
        # Steps + evidence should give decent score
        assert result["score"] >= 20

    def test_nonexistent_chain(self, cm):
        result = cm.analyze_feasibility("CHAIN-FAKE")
        assert result["score"] == 0

    def test_high_feasibility(self, cm):
        chain = _make_chain(fragments=["F1", "F2", "F3"], vulns=["V1"])
        cm.create_chain(chain)
        for i in range(4):
            cm.add_step(chain.chain_id, _make_step(
                title=f"Step {i+1}",
                precondition=f"Step {i} complete" if i > 0 else "",
            ))

        result = cm.analyze_feasibility(chain.chain_id)
        assert result["score"] >= 60
        assert result["recommendation"] == "可执行"


# ===================== Statistics Tests =====================

class TestChainStatistics:
    """Test statistics method."""

    def test_empty_stats(self, cm):
        stats = cm.get_statistics()
        assert stats["total"] == 0

    def test_stats_with_data(self, cm):
        cm.create_chain(_make_chain(title="C1"))
        c2 = _make_chain(title="C2")
        cm.create_chain(c2)
        cm.update_status(c2.chain_id, "confirmed")

        stats = cm.get_statistics()
        assert stats["total"] == 2
        assert stats["draft"] == 1
        assert stats["confirmed"] == 1
