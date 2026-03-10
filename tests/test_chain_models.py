"""
Tests for chain_models module (kali_mcp/core/chain_models.py)

Covers:
- ChainStatus enum
- ChainStep: creation, defaults, to_dict, from_dict, field filtering
- AttackChain: creation, defaults, to_dict, from_dict, impact_order property,
  round-trip serialization, steps handling
"""

import pytest

from kali_mcp.core.chain_models import (
    ChainStatus,
    ChainStep,
    AttackChain,
)


# ===================== ChainStatus Tests =====================

class TestChainStatus:
    def test_values(self):
        assert ChainStatus.DRAFT.value == "draft"
        assert ChainStatus.ANALYZING.value == "analyzing"
        assert ChainStatus.CONFIRMED.value == "confirmed"
        assert ChainStatus.EXECUTED.value == "executed"
        assert ChainStatus.FAILED.value == "failed"

    def test_member_count(self):
        assert len(ChainStatus) == 5


# ===================== ChainStep Tests =====================

class TestChainStepCreation:
    def test_defaults(self):
        step = ChainStep()
        assert step.order == 0
        assert step.title == ""
        assert step.description == ""
        assert step.precondition == ""
        assert step.action == ""
        assert step.expected_result == ""
        assert step.tool_used == ""
        assert step.fragment_id is None
        assert step.vuln_id is None

    def test_with_values(self):
        step = ChainStep(
            order=1,
            title="Reconnaissance",
            description="Scan target ports",
            precondition="Target IP known",
            action="nmap -sV target",
            expected_result="Open ports discovered",
            tool_used="nmap_scan",
            fragment_id="FRAG-1234",
            vuln_id="VULN-5678",
        )
        assert step.order == 1
        assert step.title == "Reconnaissance"
        assert step.tool_used == "nmap_scan"
        assert step.fragment_id == "FRAG-1234"
        assert step.vuln_id == "VULN-5678"


class TestChainStepToDict:
    def test_to_dict(self):
        step = ChainStep(order=1, title="Test", action="run")
        d = step.to_dict()
        assert d["order"] == 1
        assert d["title"] == "Test"
        assert d["action"] == "run"
        assert d["fragment_id"] is None
        assert d["vuln_id"] is None

    def test_to_dict_includes_all_fields(self):
        step = ChainStep()
        d = step.to_dict()
        expected_keys = {"order", "title", "description", "precondition",
                         "action", "expected_result", "tool_used",
                         "fragment_id", "vuln_id"}
        assert set(d.keys()) == expected_keys


class TestChainStepFromDict:
    def test_from_dict(self):
        data = {"order": 2, "title": "Exploit", "action": "sqlmap", "tool_used": "sqlmap_scan"}
        step = ChainStep.from_dict(data)
        assert step.order == 2
        assert step.title == "Exploit"
        assert step.action == "sqlmap"
        assert step.tool_used == "sqlmap_scan"

    def test_from_dict_ignores_extra_keys(self):
        data = {"order": 1, "title": "Test", "unknown_field": "should_be_ignored",
                "another_extra": 42}
        step = ChainStep.from_dict(data)
        assert step.order == 1
        assert step.title == "Test"
        assert not hasattr(step, "unknown_field")

    def test_from_dict_missing_fields_use_defaults(self):
        data = {"order": 5}
        step = ChainStep.from_dict(data)
        assert step.order == 5
        assert step.title == ""
        assert step.action == ""

    def test_round_trip(self):
        original = ChainStep(order=3, title="Persist", action="cron", tool_used="bash",
                             fragment_id="F1", vuln_id="V1")
        d = original.to_dict()
        restored = ChainStep.from_dict(d)
        assert restored.order == original.order
        assert restored.title == original.title
        assert restored.action == original.action
        assert restored.fragment_id == original.fragment_id
        assert restored.vuln_id == original.vuln_id


# ===================== AttackChain Tests =====================

class TestAttackChainCreation:
    def test_defaults(self):
        chain = AttackChain()
        assert chain.chain_id.startswith("CHAIN-")
        assert len(chain.chain_id) == 14  # "CHAIN-" + 8 hex chars
        assert chain.title == ""
        assert chain.description == ""
        assert chain.steps == []
        assert chain.fragments == []
        assert chain.vulns == []
        assert chain.feasibility_score == 0
        assert chain.impact_level == "medium"
        assert chain.status == "draft"
        assert chain.created_at != ""

    def test_unique_ids(self):
        chain1 = AttackChain()
        chain2 = AttackChain()
        assert chain1.chain_id != chain2.chain_id

    def test_with_values(self):
        chain = AttackChain(
            title="SQL to RCE",
            description="Exploit SQL injection to achieve RCE",
            fragments=["FRAG-1"],
            vulns=["VULN-1", "VULN-2"],
            feasibility_score=85,
            impact_level="critical",
            status="confirmed",
        )
        assert chain.title == "SQL to RCE"
        assert chain.feasibility_score == 85
        assert chain.impact_level == "critical"
        assert len(chain.vulns) == 2

    def test_with_steps(self):
        step1 = ChainStep(order=1, title="Recon", action="nmap")
        step2 = ChainStep(order=2, title="Exploit", action="sqlmap")
        chain = AttackChain(title="Test", steps=[step1, step2])
        assert len(chain.steps) == 2
        assert chain.steps[0].title == "Recon"
        assert chain.steps[1].title == "Exploit"


class TestAttackChainImpactOrder:
    def test_critical(self):
        chain = AttackChain(impact_level="critical")
        assert chain.impact_order == 4

    def test_high(self):
        chain = AttackChain(impact_level="high")
        assert chain.impact_order == 3

    def test_medium(self):
        chain = AttackChain(impact_level="medium")
        assert chain.impact_order == 2

    def test_low(self):
        chain = AttackChain(impact_level="low")
        assert chain.impact_order == 1

    def test_unknown(self):
        chain = AttackChain(impact_level="unknown")
        assert chain.impact_order == 0


class TestAttackChainToDict:
    def test_basic(self):
        chain = AttackChain(title="Test Chain", impact_level="high")
        d = chain.to_dict()
        assert d["title"] == "Test Chain"
        assert d["impact_level"] == "high"
        assert d["steps"] == []

    def test_with_steps(self):
        step = ChainStep(order=1, title="Step1", action="run")
        chain = AttackChain(title="T", steps=[step])
        d = chain.to_dict()
        assert len(d["steps"]) == 1
        assert d["steps"][0]["order"] == 1
        assert d["steps"][0]["title"] == "Step1"

    def test_steps_are_dicts(self):
        step = ChainStep(order=1, title="A")
        chain = AttackChain(steps=[step])
        d = chain.to_dict()
        assert isinstance(d["steps"][0], dict)


class TestAttackChainFromDict:
    def test_basic(self):
        data = {"title": "Restored Chain", "impact_level": "critical", "status": "executed"}
        chain = AttackChain.from_dict(data)
        assert chain.title == "Restored Chain"
        assert chain.impact_level == "critical"
        assert chain.status == "executed"

    def test_with_steps_dicts(self):
        data = {
            "title": "With Steps",
            "steps": [
                {"order": 1, "title": "Recon", "action": "nmap"},
                {"order": 2, "title": "Exploit", "action": "sqlmap"},
            ]
        }
        chain = AttackChain.from_dict(data)
        assert len(chain.steps) == 2
        assert isinstance(chain.steps[0], ChainStep)
        assert chain.steps[0].title == "Recon"
        assert chain.steps[1].action == "sqlmap"

    def test_ignores_extra_keys(self):
        data = {"title": "Test", "extra_key": "ignored"}
        chain = AttackChain.from_dict(data)
        assert chain.title == "Test"

    def test_round_trip(self):
        step1 = ChainStep(order=1, title="A", action="a")
        step2 = ChainStep(order=2, title="B", action="b")
        original = AttackChain(
            title="Full Chain",
            description="Test round trip",
            steps=[step1, step2],
            fragments=["F1"],
            vulns=["V1", "V2"],
            feasibility_score=75,
            impact_level="high",
            status="confirmed",
        )
        d = original.to_dict()
        restored = AttackChain.from_dict(d)
        assert restored.title == original.title
        assert restored.description == original.description
        assert restored.feasibility_score == original.feasibility_score
        assert restored.impact_level == original.impact_level
        assert restored.status == original.status
        assert len(restored.steps) == 2
        assert restored.steps[0].title == "A"
        assert restored.steps[1].title == "B"

    def test_from_dict_pops_steps(self):
        """from_dict pops 'steps' from data before creating chain"""
        data = {"title": "T", "steps": [{"order": 1}]}
        chain = AttackChain.from_dict(data)
        # steps should have been removed from data dict
        assert "steps" not in data
        assert len(chain.steps) == 1
