"""
Tests for recommend module (kali_mcp/ai/recommend.py)

Covers:
- Recommendation: creation, to_dict
- ToolRecommender: init, recommend (by type, services, phase),
  update_score, get_tool_stats, suggest_tool_chain, get_all_scores
- get_tool_recommender global factory
"""

import pytest

from kali_mcp.ai.recommend import (
    Recommendation,
    ToolRecommender,
    get_tool_recommender,
)


# ===================== Recommendation Tests =====================

class TestRecommendation:
    def test_defaults(self):
        rec = Recommendation(tool_name="nmap_scan", score=0.9, reason="Port scan")
        assert rec.tool_name == "nmap_scan"
        assert rec.score == 0.9
        assert rec.reason == "Port scan"
        assert rec.priority == 1
        assert rec.parameters == {}

    def test_with_params(self):
        rec = Recommendation(
            tool_name="sqlmap_scan",
            score=0.8,
            reason="SQL injection test",
            priority=2,
            parameters={"level": 3, "risk": 2},
        )
        assert rec.priority == 2
        assert rec.parameters["level"] == 3

    def test_to_dict(self):
        rec = Recommendation(
            tool_name="gobuster_scan",
            score=0.85,
            reason="Dir scan",
            priority=3,
            parameters={"mode": "dir"},
        )
        d = rec.to_dict()
        assert d["tool"] == "gobuster_scan"
        assert d["score"] == 0.85
        assert d["reason"] == "Dir scan"
        assert d["priority"] == 3
        assert d["parameters"]["mode"] == "dir"

    def test_mutable_params_independent(self):
        r1 = Recommendation(tool_name="t1", score=0.5, reason="r")
        r2 = Recommendation(tool_name="t2", score=0.5, reason="r")
        r1.parameters["key"] = "val"
        assert r2.parameters == {}


# ===================== ToolRecommender Init Tests =====================

class TestToolRecommenderInit:
    def test_defaults(self):
        rec = ToolRecommender()
        assert rec.history == []
        assert rec.tool_scores["any_tool"] == 0.5  # defaultdict
        assert rec.tool_success_count["any_tool"] == 0
        assert rec.tool_failure_count["any_tool"] == 0

    def test_class_maps_exist(self):
        assert "web" in ToolRecommender.TARGET_TOOL_MAP
        assert "network" in ToolRecommender.TARGET_TOOL_MAP
        assert "domain" in ToolRecommender.TARGET_TOOL_MAP
        assert "binary" in ToolRecommender.TARGET_TOOL_MAP
        assert "ctf" in ToolRecommender.TARGET_TOOL_MAP

    def test_service_map_exists(self):
        assert "ssh" in ToolRecommender.SERVICE_TOOL_MAP
        assert "http" in ToolRecommender.SERVICE_TOOL_MAP
        assert "wordpress" in ToolRecommender.SERVICE_TOOL_MAP

    def test_phase_map_exists(self):
        assert "reconnaissance" in ToolRecommender.PHASE_TOOL_MAP
        assert "scanning" in ToolRecommender.PHASE_TOOL_MAP
        assert "exploitation" in ToolRecommender.PHASE_TOOL_MAP
        assert "post_exploitation" in ToolRecommender.PHASE_TOOL_MAP


# ===================== recommend Tests =====================

class TestRecommend:
    def test_web_target(self):
        rec = ToolRecommender()
        results = rec.recommend(target="http://target.com", target_type="web")
        assert len(results) > 0
        tool_names = [r.tool_name for r in results]
        assert "whatweb_scan" in tool_names

    def test_network_target(self):
        rec = ToolRecommender()
        results = rec.recommend(target="10.0.0.1", target_type="network")
        tool_names = [r.tool_name for r in results]
        assert "nmap_scan" in tool_names

    def test_binary_target(self):
        rec = ToolRecommender()
        results = rec.recommend(target="/tmp/binary", target_type="binary")
        tool_names = [r.tool_name for r in results]
        assert "quick_pwn_check" in tool_names

    def test_ctf_target(self):
        rec = ToolRecommender()
        results = rec.recommend(target="http://ctf.com", target_type="ctf")
        tool_names = [r.tool_name for r in results]
        assert "intelligent_ctf_solve" in tool_names

    def test_unknown_target_empty(self):
        rec = ToolRecommender()
        results = rec.recommend(target="test", target_type="unknown_type")
        assert results == []

    def test_limit(self):
        rec = ToolRecommender()
        results = rec.recommend(target="http://t.com", target_type="web", limit=2)
        assert len(results) <= 2

    def test_priorities_set(self):
        rec = ToolRecommender()
        results = rec.recommend(target="http://t.com", target_type="web", limit=5)
        for i, r in enumerate(results):
            assert r.priority == i + 1

    def test_deduplication(self):
        rec = ToolRecommender()
        # Use services that might duplicate tools from target_type
        results = rec.recommend(
            target="http://t.com",
            target_type="web",
            context={"services": ["http"]},
        )
        tool_names = [r.tool_name for r in results]
        assert len(tool_names) == len(set(tool_names))

    def test_with_services(self):
        rec = ToolRecommender()
        results = rec.recommend(
            target="10.0.0.1",
            target_type="network",
            context={"services": ["ssh", "http"]},
        )
        tool_names = [r.tool_name for r in results]
        assert "hydra_attack" in tool_names

    def test_with_phase(self):
        rec = ToolRecommender()
        results = rec.recommend(
            target="http://t.com",
            target_type="web",
            context={"phase": "exploitation"},
        )
        tool_names = [r.tool_name for r in results]
        assert "sqlmap_scan" in tool_names

    def test_sorted_by_score(self):
        rec = ToolRecommender()
        results = rec.recommend(target="http://t.com", target_type="web")
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_score_multiplied_by_tool_score(self):
        rec = ToolRecommender()
        # Default tool_score is 0.5
        results = rec.recommend(target="http://t.com", target_type="web")
        # whatweb_scan base score is 0.9, multiplied by 0.5 = 0.45
        whatweb = [r for r in results if r.tool_name == "whatweb_scan"]
        if whatweb:
            assert abs(whatweb[0].score - 0.45) < 0.01


# ===================== update_score Tests =====================

class TestUpdateScore:
    def test_success_increases_score(self):
        rec = ToolRecommender()
        initial = rec.tool_scores["nmap_scan"]
        rec.update_score("nmap_scan", success=True, findings_count=0)
        assert rec.tool_scores["nmap_scan"] > initial

    def test_failure_decreases_score(self):
        rec = ToolRecommender()
        initial = rec.tool_scores["nmap_scan"]
        rec.update_score("nmap_scan", success=False)
        assert rec.tool_scores["nmap_scan"] < initial

    def test_success_bonus_with_findings(self):
        rec = ToolRecommender()
        rec.update_score("t1", success=True, findings_count=0)
        score_0 = rec.tool_scores["t1"]
        rec.tool_scores["t2"] = 0.5
        rec.update_score("t2", success=True, findings_count=5)
        score_5 = rec.tool_scores["t2"]
        assert score_5 > score_0  # more findings = higher bonus

    def test_max_score_cap(self):
        rec = ToolRecommender()
        rec.tool_scores["t1"] = 0.98
        rec.update_score("t1", success=True, findings_count=10)
        assert rec.tool_scores["t1"] <= 1.0

    def test_min_score_cap(self):
        rec = ToolRecommender()
        rec.tool_scores["t1"] = 0.12
        rec.update_score("t1", success=False)
        assert rec.tool_scores["t1"] >= 0.1

    def test_success_count_incremented(self):
        rec = ToolRecommender()
        rec.update_score("nmap", success=True)
        assert rec.tool_success_count["nmap"] == 1

    def test_failure_count_incremented(self):
        rec = ToolRecommender()
        rec.update_score("nmap", success=False)
        assert rec.tool_failure_count["nmap"] == 1

    def test_history_recorded(self):
        rec = ToolRecommender()
        rec.update_score("nmap", success=True, findings_count=3)
        assert len(rec.history) == 1
        assert rec.history[0]["tool"] == "nmap"
        assert rec.history[0]["success"] is True
        assert rec.history[0]["findings"] == 3

    def test_success_formula(self):
        """success bonus = 0.05 + min(0.1, findings * 0.02)"""
        rec = ToolRecommender()
        rec.tool_scores["t1"] = 0.5
        rec.update_score("t1", success=True, findings_count=3)
        # bonus = min(0.1, 3 * 0.02) = 0.06
        # new = 0.5 + 0.05 + 0.06 = 0.61
        assert abs(rec.tool_scores["t1"] - 0.61) < 0.001

    def test_failure_formula(self):
        """failure penalty = -0.03"""
        rec = ToolRecommender()
        rec.tool_scores["t1"] = 0.5
        rec.update_score("t1", success=False)
        assert abs(rec.tool_scores["t1"] - 0.47) < 0.001


# ===================== get_tool_stats Tests =====================

class TestGetToolStats:
    def test_empty_stats(self):
        rec = ToolRecommender()
        stats = rec.get_tool_stats("nmap")
        assert stats["tool"] == "nmap"
        assert stats["score"] == 0.5
        assert stats["success_count"] == 0
        assert stats["failure_count"] == 0
        assert stats["success_rate"] == 0

    def test_with_data(self):
        rec = ToolRecommender()
        rec.update_score("nmap", True)
        rec.update_score("nmap", True)
        rec.update_score("nmap", False)
        stats = rec.get_tool_stats("nmap")
        assert stats["success_count"] == 2
        assert stats["failure_count"] == 1
        assert abs(stats["success_rate"] - 2 / 3) < 0.01


# ===================== suggest_tool_chain Tests =====================

class TestSuggestToolChain:
    def test_web_comprehensive(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("web", "comprehensive")
        assert "whatweb_scan" in chain
        assert "gobuster_scan" in chain
        assert len(chain) == 5

    def test_web_quick(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("web", "quick")
        assert len(chain) == 3
        assert "whatweb_scan" in chain

    def test_web_stealth(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("web", "stealth")
        assert len(chain) == 2

    def test_network_comprehensive(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("network", "comprehensive")
        assert "nmap_scan" in chain

    def test_binary(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("binary", "comprehensive")
        assert "quick_pwn_check" in chain

    def test_ctf(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("ctf", "comprehensive")
        assert "intelligent_ctf_solve" in chain

    def test_unknown_type_fallback(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("alien_type", "comprehensive")
        # Falls back to web
        assert "whatweb_scan" in chain

    def test_unknown_objective_fallback(self):
        rec = ToolRecommender()
        chain = rec.suggest_tool_chain("web", "unknown_objective")
        # Falls back to comprehensive
        assert len(chain) == 5


# ===================== get_all_scores Tests =====================

class TestGetAllScores:
    def test_empty(self):
        rec = ToolRecommender()
        scores = rec.get_all_scores()
        assert isinstance(scores, dict)

    def test_after_updates(self):
        rec = ToolRecommender()
        rec.update_score("nmap", True)
        rec.update_score("sqlmap", False)
        scores = rec.get_all_scores()
        assert "nmap" in scores
        assert "sqlmap" in scores


# ===================== get_tool_recommender Tests =====================

class TestGetToolRecommender:
    def test_returns_instance(self):
        import kali_mcp.ai.recommend as mod
        # Reset global
        mod._global_recommender = None
        rec = get_tool_recommender()
        assert isinstance(rec, ToolRecommender)

    def test_returns_same_instance(self):
        import kali_mcp.ai.recommend as mod
        mod._global_recommender = None
        r1 = get_tool_recommender()
        r2 = get_tool_recommender()
        assert r1 is r2
