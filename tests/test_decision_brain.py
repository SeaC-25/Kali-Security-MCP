"""
Tests for DecisionBrain (kali_mcp/core/decision_brain.py)

Covers:
- Start decisions with different target types
- Post-recon decisions based on discovered ports
- Mid-scan decisions based on progress/vulns
- Pre-exploit decisions with confidence and CTF mode
- Final decisions with flags and vulns
- Context updates and reassessment triggers
- ML optimizer recommendations
- Unknown intervention points
"""

from unittest.mock import MagicMock

import pytest

from kali_mcp.core.decision_brain import DecisionBrain


class TestDecideStart:
    """Test _decide_start for different target types."""

    def test_decide_start_web_target(self, decision_brain):
        """URL target produces web_focused strategy."""
        result = decision_brain.decide("start", {"target": "http://example.com/app"})

        assert result["action"] == "proceed"
        assert result["strategy"] == "web_focused"
        assert "web_assessment" in result["recommendations"]
        assert result["point"] == "start"

    def test_decide_start_ctf_target(self, decision_brain):
        """CTF keyword in target produces aggressive strategy."""
        result = decision_brain.decide("start", {"target": "http://ctf.challenge.com/flag"})

        assert result["action"] == "proceed"
        assert result["strategy"] == "aggressive"
        assert "ctf_mode" in result["recommendations"]

    def test_decide_start_internal_target(self, decision_brain):
        """Internal IP produces methodical strategy."""
        result = decision_brain.decide("start", {"target": "192.168.1.100"})

        assert result["action"] == "proceed"
        assert result["strategy"] == "methodical"
        assert "internal_pentest" in result["recommendations"]

    def test_decide_start_generic_target(self, decision_brain):
        """Generic hostname produces balanced strategy."""
        result = decision_brain.decide("start", {"target": "target.local"})

        assert result["action"] == "proceed"
        assert result["strategy"] == "balanced"
        assert "general_scan" in result["recommendations"]

    def test_decide_start_with_mode(self, decision_brain):
        """Mode parameter is logged in thinking."""
        result = decision_brain.decide("start", {"target": "10.0.0.1", "mode": "aggressive"})

        assert any("aggressive" in t for t in result["thinking"])

    def test_decide_start_records_decision(self, decision_brain):
        """Decision is recorded in history."""
        decision_brain.decide("start", {"target": "10.0.0.1"})

        decisions = decision_brain.get_decisions()
        assert len(decisions) == 1
        assert decisions[0]["point"] == "start"


class TestDecidePostRecon:
    """Test _decide_post_recon based on discovered ports and services."""

    def test_post_recon_with_web_ports(self, decision_brain):
        """Ports [80, 443] produce web_scan action."""
        result = decision_brain.decide("post_recon", {
            "open_ports": [80, 443],
            "services": [],
            "technologies": [],
        })

        assert result["action"] == "focus_scan"
        next_tools = [a["tool"] for a in result["next_actions"]]
        assert "web_scan" in next_tools

    def test_post_recon_with_db_ports(self, decision_brain):
        """Port 3306 triggers db_enum action."""
        result = decision_brain.decide("post_recon", {
            "open_ports": [3306],
            "services": [],
            "technologies": [],
        })

        assert result["action"] == "focus_scan"
        next_tools = [a["tool"] for a in result["next_actions"]]
        assert "db_enum" in next_tools

    def test_post_recon_with_ssh_service(self, decision_brain):
        """SSH service triggers brute_force action."""
        result = decision_brain.decide("post_recon", {
            "open_ports": [22],
            "services": ["ssh"],
            "technologies": [],
        })

        assert result["action"] == "focus_scan"
        next_tools = [a["tool"] for a in result["next_actions"]]
        assert "brute_force" in next_tools

    def test_post_recon_empty(self, decision_brain):
        """No ports discovered produces expand_scan action."""
        result = decision_brain.decide("post_recon", {
            "open_ports": [],
            "services": [],
            "technologies": [],
        })

        assert result["action"] == "expand_scan"

    def test_post_recon_multiple_services(self, decision_brain):
        """Multiple services produce multiple next_actions."""
        result = decision_brain.decide("post_recon", {
            "open_ports": [80, 443, 3306, 22],
            "services": ["http", "ssh", "mysql"],
            "technologies": [],
        })

        assert result["action"] == "focus_scan"
        assert len(result["next_actions"]) >= 2


class TestDecideMidScan:
    """Test _decide_mid_scan based on progress and findings."""

    def test_mid_scan_high_vulns(self, decision_brain):
        """5+ vulns found triggers shift_to_exploit."""
        result = decision_brain.decide("mid_scan", {
            "vulns_found": 6,
            "elapsed_minutes": 10,
            "total_targets": 10,
            "scanned": 5,
        })

        assert result["action"] == "shift_to_exploit"

    def test_mid_scan_high_value_vuln(self, decision_brain):
        """High value vuln flag from EventBus triggers immediate exploit."""
        decision_brain.trigger_reassessment({"severity": "critical"})

        result = decision_brain.decide("mid_scan", {
            "vulns_found": 1,
            "elapsed_minutes": 5,
            "total_targets": 10,
            "scanned": 3,
        })

        assert result["action"] == "shift_to_exploit"

    def test_mid_scan_no_progress(self, decision_brain):
        """High progress (>70%) with 0 vulns triggers change_strategy."""
        result = decision_brain.decide("mid_scan", {
            "vulns_found": 0,
            "elapsed_minutes": 15,
            "total_targets": 10,
            "scanned": 8,
        })

        assert result["action"] == "change_strategy"

    def test_mid_scan_normal_progress(self, decision_brain):
        """Normal progress with some findings produces continue."""
        result = decision_brain.decide("mid_scan", {
            "vulns_found": 2,
            "elapsed_minutes": 10,
            "total_targets": 10,
            "scanned": 4,
        })

        assert result["action"] == "continue"

    def test_mid_scan_long_elapsed_low_findings(self, decision_brain):
        """Long elapsed time with few findings triggers adjust_scope."""
        result = decision_brain.decide("mid_scan", {
            "vulns_found": 1,
            "elapsed_minutes": 35,
            "total_targets": 10,
            "scanned": 5,
        })

        assert result["action"] == "adjust_scope"


class TestDecidePreExploit:
    """Test _decide_pre_exploit for risk assessment."""

    def test_pre_exploit_ctf_mode(self, decision_brain):
        """CTF mode always allows exploit."""
        result = decision_brain.decide("pre_exploit", {
            "vuln_type": "sqli",
            "confidence": 0.3,
            "severity": "medium",
            "is_ctf": True,
        })

        assert result["action"] == "exploit"

    def test_pre_exploit_low_confidence(self, decision_brain):
        """Low confidence (<50%) triggers verify_first."""
        result = decision_brain.decide("pre_exploit", {
            "vuln_type": "rce",
            "confidence": 0.3,
            "severity": "high",
            "is_ctf": False,
        })

        assert result["action"] == "verify_first"

    def test_pre_exploit_high_confidence(self, decision_brain):
        """High confidence and severity allows exploit."""
        result = decision_brain.decide("pre_exploit", {
            "vuln_type": "rce",
            "confidence": 0.9,
            "severity": "critical",
            "is_ctf": False,
        })

        assert result["action"] == "exploit"
        assert result["risk_level"] == "high"

    def test_pre_exploit_medium_severity(self, decision_brain):
        """Medium severity with adequate confidence allows exploit with low risk."""
        result = decision_brain.decide("pre_exploit", {
            "vuln_type": "xss",
            "confidence": 0.7,
            "severity": "medium",
            "is_ctf": False,
        })

        assert result["action"] == "exploit"
        assert result["risk_level"] == "low"


class TestDecideFinal:
    """Test _decide_final for report generation."""

    def test_final_with_flags(self, decision_brain):
        """Flags found produces report_with_flags action."""
        result = decision_brain.decide("final", {
            "total_vulns": 3,
            "critical_vulns": 1,
            "exploited": 1,
            "flags_found": ["flag{test_123}"],
        })

        assert result["action"] == "report_with_flags"
        assert result["flags"] == ["flag{test_123}"]
        assert result["summary"]["flags"] == 1

    def test_final_with_vulns_no_flags(self, decision_brain):
        """Vulns but no flags produces full_report."""
        result = decision_brain.decide("final", {
            "total_vulns": 5,
            "critical_vulns": 0,
            "exploited": 2,
            "flags_found": [],
        })

        assert result["action"] == "full_report"
        assert result["summary"]["total_vulns"] == 5

    def test_final_no_findings(self, decision_brain):
        """No vulns and no flags produces no_findings_report."""
        result = decision_brain.decide("final", {
            "total_vulns": 0,
            "critical_vulns": 0,
            "exploited": 0,
            "flags_found": [],
        })

        assert result["action"] == "no_findings_report"


class TestContextAndReassessment:
    """Test update_context and trigger_reassessment."""

    def test_update_context(self, decision_brain):
        """update_context properly updates live context."""
        decision_brain.update_context({
            "last_tool": "nmap",
            "last_success": True,
            "last_target": "10.0.0.1",
        })

        assert decision_brain._live_context["last_tool"] == "nmap"
        assert decision_brain._live_context["last_success"] is True
        assert "nmap" in decision_brain._live_context["tools_used"]

    def test_update_context_tools_used_no_duplicates(self, decision_brain):
        """Same tool reported twice doesn't duplicate in tools_used."""
        decision_brain.update_context({"last_tool": "nmap"})
        decision_brain.update_context({"last_tool": "nmap"})

        assert decision_brain._live_context["tools_used"].count("nmap") == 1

    def test_trigger_reassessment_high_severity(self, decision_brain):
        """High severity triggers high_value_vuln_found flag."""
        decision_brain.trigger_reassessment({"severity": "high"})

        assert decision_brain._live_context["high_value_vuln_found"] is True
        assert decision_brain._live_context["vulns_seen"] == 1

    def test_trigger_reassessment_critical_severity(self, decision_brain):
        """Critical severity also triggers high_value flag."""
        decision_brain.trigger_reassessment({"severity": "critical"})

        assert decision_brain._live_context["high_value_vuln_found"] is True

    def test_trigger_reassessment_medium_no_flag(self, decision_brain):
        """Medium severity does not trigger high_value flag."""
        decision_brain.trigger_reassessment({"severity": "medium"})

        assert decision_brain._live_context.get("high_value_vuln_found") is not True
        assert decision_brain._live_context["vulns_seen"] == 1


class TestMLRecommendations:
    """Test ML optimizer integration."""

    def test_ml_recommendations_included(self):
        """With mock ML optimizer, recommendations are included in start decision."""
        mock_ml = MagicMock()
        mock_ml.recommend_tools_for_target.return_value = ["nmap", "gobuster", "nuclei"]

        brain = DecisionBrain(ml_optimizer=mock_ml)
        result = brain.decide("start", {"target": "http://target.com"})

        assert result["ml_recommendations"] == ["nmap", "gobuster", "nuclei"]
        mock_ml.recommend_tools_for_target.assert_called_once_with("http://target.com")

    def test_no_ml_optimizer(self):
        """Without ML optimizer, ml_recommendations is empty list."""
        brain = DecisionBrain(ml_optimizer=None)
        result = brain.decide("start", {"target": "http://target.com"})

        assert result["ml_recommendations"] == []


class TestUnknownPoint:
    """Test handling of unknown intervention points."""

    def test_unknown_point_returns_continue(self, decision_brain):
        """Unknown intervention point returns continue action."""
        result = decision_brain.decide("nonexistent_point", {})

        assert result["action"] == "continue"
        assert "nonexistent_point" in result["reason"]


class TestDecisionHistory:
    """Test decision recording and retrieval."""

    def test_get_decisions(self, decision_brain):
        """All decisions are recorded and retrievable."""
        decision_brain.decide("start", {"target": "10.0.0.1"})
        decision_brain.decide("post_recon", {"open_ports": [80]})

        decisions = decision_brain.get_decisions()
        assert len(decisions) == 2
        assert decisions[0]["point"] == "start"
        assert decisions[1]["point"] == "post_recon"

    def test_clear(self, decision_brain):
        """clear() removes all decision history."""
        decision_brain.decide("start", {"target": "10.0.0.1"})
        decision_brain.clear()

        assert decision_brain.get_decisions() == []
