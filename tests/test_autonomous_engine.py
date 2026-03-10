"""
Tests for AutonomousReasoningEngine (kali_mcp/reasoning/autonomous_engine.py)

Covers:
- AutonomousInsight: creation, to_dict
- AutonomousReasoningEngine: init, generate_autonomous_insights,
  cross_domain_reasoning, reverse_engineering_reasoning,
  mutation_based_reasoning, pattern_matching_reasoning,
  curiosity_driven_exploration, stats, visualization
"""

import pytest

from kali_mcp.reasoning.autonomous_engine import (
    AutonomousInsight,
    AutonomousReasoningEngine,
)
from kali_mcp.reasoning.knowledge_graph import VulnerabilityType


# ===================== AutonomousInsight Tests =====================

class TestAutonomousInsight:
    def test_creation(self):
        insight = AutonomousInsight(
            insight_type="cross_domain",
            reasoning="Test reasoning",
            novelty_score=0.8,
            feasibility=0.6,
            estimated_time=30
        )
        assert insight.insight_type == "cross_domain"
        assert insight.reasoning == "Test reasoning"
        assert insight.novelty_score == 0.8
        assert insight.feasibility == 0.6
        assert insight.estimated_time == 30
        assert insight.timestamp is not None

    def test_to_dict(self):
        insight = AutonomousInsight(
            insight_type="mutation",
            reasoning="Mutate payload",
            novelty_score=0.5,
            feasibility=0.7,
            estimated_time=45
        )
        d = insight.to_dict()
        assert d["type"] == "mutation"
        assert d["reasoning"] == "Mutate payload"
        assert d["novelty"] == 0.5
        assert d["feasibility"] == 0.7
        assert d["time"] == 45
        assert "timestamp" in d


# ===================== AutonomousReasoningEngine Init Tests =====================

class TestEngineInit:
    def test_init(self):
        engine = AutonomousReasoningEngine()
        assert engine.knowledge_graph is not None
        assert engine.insights_history == []
        assert engine.exploration_stats["total_insights"] == 0

    def test_has_cross_domain_mappings(self):
        engine = AutonomousReasoningEngine()
        assert "sql_injection" in engine.cross_domain_mappings
        assert "command_injection" in engine.cross_domain_mappings
        assert "file_inclusion" in engine.cross_domain_mappings
        assert "xss" in engine.cross_domain_mappings
        assert "ssrf" in engine.cross_domain_mappings

    def test_has_innovation_patterns(self):
        engine = AutonomousReasoningEngine()
        assert len(engine.innovation_patterns) > 0


# ===================== Cross Domain Reasoning Tests =====================

class TestCrossDomainReasoning:
    def test_sql_injection_cross_domain(self):
        engine = AutonomousReasoningEngine()
        insights = engine._cross_domain_reasoning(
            VulnerabilityType.SQL_INJECTION, {}, []
        )
        assert len(insights) > 0
        for insight in insights:
            assert insight.insight_type == "cross_domain"
            assert insight.novelty_score == 0.7

    def test_unknown_vuln_no_mapping(self):
        engine = AutonomousReasoningEngine()
        # PWN has no cross_domain_mappings
        insights = engine._cross_domain_reasoning(
            VulnerabilityType.PWN, {}, []
        )
        assert insights == []

    def test_skips_attempted_chains(self):
        engine = AutonomousReasoningEngine()
        # Attempt all possible chains from sql_injection
        attempted = [
            "sql_injection->to_command_injection",
            "sql_injection->to_file_inclusion",
            "sql_injection->to_ssrf",
        ]
        insights = engine._cross_domain_reasoning(
            VulnerabilityType.SQL_INJECTION, {}, attempted
        )
        assert insights == []


# ===================== Reverse Engineering Reasoning Tests =====================

class TestReverseEngineeringReasoning:
    def test_generates_insights(self):
        engine = AutonomousReasoningEngine()
        insights = engine._reverse_engineering_reasoning(
            VulnerabilityType.SQL_INJECTION, {}, []
        )
        assert len(insights) > 0
        for insight in insights:
            assert insight.insight_type == "reverse_engineering"
            assert insight.novelty_score == 0.5
            assert insight.feasibility == 0.7

    def test_skips_attempted(self):
        engine = AutonomousReasoningEngine()
        attempted = [
            "sql_injection->privilege_escalation",
            "sql_injection->command_injection",
            "sql_injection->file_inclusion",
            "sql_injection->flag",
        ]
        insights = engine._reverse_engineering_reasoning(
            VulnerabilityType.SQL_INJECTION, {}, attempted
        )
        assert len(insights) == 0


# ===================== Mutation Based Reasoning Tests =====================

class TestMutationBasedReasoning:
    def test_generates_tool_mutations(self):
        engine = AutonomousReasoningEngine()
        # Use a vuln type that has chains with multiple tools
        insights = engine._mutation_based_reasoning(
            VulnerabilityType.SQL_INJECTION,
            {},
            []
        )
        # May or may not generate depending on chain.tools length
        for insight in insights:
            assert insight.insight_type == "mutation"

    def test_waf_detected_adds_bypass(self):
        engine = AutonomousReasoningEngine()
        insights = engine._mutation_based_reasoning(
            VulnerabilityType.SQL_INJECTION,
            {"waf_detected": True},
            []
        )
        # Should have WAF bypass mutations
        waf_insights = [i for i in insights if "WAF" in i.reasoning]
        assert len(waf_insights) > 0


# ===================== Pattern Matching Reasoning Tests =====================

class TestPatternMatchingReasoning:
    def test_upload_pattern(self):
        engine = AutonomousReasoningEngine()
        finding = {
            "vulnerability_type": "sql_injection",
            "evidence": {"has_upload": True}
        }
        insights = engine._pattern_matching_reasoning(finding, {}, [])
        assert any("上传" in i.reasoning for i in insights)

    def test_db_type_pattern(self):
        engine = AutonomousReasoningEngine()
        finding = {
            "vulnerability_type": "sql_injection",
            "evidence": {"db_type": "MySQL"}
        }
        insights = engine._pattern_matching_reasoning(finding, {}, [])
        assert any("MySQL" in i.reasoning for i in insights)

    def test_waf_pattern(self):
        engine = AutonomousReasoningEngine()
        finding = {
            "vulnerability_type": "xss",
            "evidence": {}
        }
        insights = engine._pattern_matching_reasoning(
            finding, {"waf_detected": True}, []
        )
        assert any("WAF" in i.reasoning for i in insights)

    def test_no_patterns_match(self):
        engine = AutonomousReasoningEngine()
        finding = {
            "vulnerability_type": "xss",
            "evidence": {}
        }
        insights = engine._pattern_matching_reasoning(finding, {}, [])
        assert insights == []


# ===================== Curiosity Driven Exploration Tests =====================

class TestCuriosityDrivenExploration:
    def test_generates_explorations(self):
        engine = AutonomousReasoningEngine()
        insights = engine._curiosity_driven_exploration(
            VulnerabilityType.SQL_INJECTION, {}, []
        )
        # Random-based, should produce 0-3 insights
        for insight in insights:
            assert insight.insight_type == "exploration"
            assert insight.novelty_score == 0.9
            assert insight.feasibility == 0.3
            assert insight.estimated_time == 60

    def test_skips_attempted(self):
        engine = AutonomousReasoningEngine()
        # Attempt all possible targets
        all_types = [v.value for v in VulnerabilityType]
        attempted = [f"sql_injection->{t}" for t in all_types]
        insights = engine._curiosity_driven_exploration(
            VulnerabilityType.SQL_INJECTION, {}, attempted
        )
        assert insights == []


# ===================== Generate Autonomous Insights Tests =====================

class TestGenerateAutonomousInsights:
    def test_sql_injection_insights(self):
        engine = AutonomousReasoningEngine()
        finding = {"vulnerability_type": "sql_injection"}
        insights = engine.generate_autonomous_insights(finding, {})
        assert len(insights) > 0

    def test_unknown_vuln_type_returns_empty(self):
        engine = AutonomousReasoningEngine()
        finding = {"vulnerability_type": "nonexistent_type"}
        insights = engine.generate_autonomous_insights(finding, {})
        assert insights == []

    def test_sorted_by_composite_score(self):
        engine = AutonomousReasoningEngine()
        finding = {"vulnerability_type": "sql_injection"}
        insights = engine.generate_autonomous_insights(finding, {})
        if len(insights) >= 2:
            for i in range(len(insights) - 1):
                score_a = insights[i].novelty_score * 0.6 + insights[i].feasibility * 0.4
                score_b = insights[i + 1].novelty_score * 0.6 + insights[i + 1].feasibility * 0.4
                assert score_a >= score_b

    def test_updates_history(self):
        engine = AutonomousReasoningEngine()
        finding = {"vulnerability_type": "command_injection"}
        insights = engine.generate_autonomous_insights(
            finding, {"shell_access": True}
        )
        assert len(engine.insights_history) == len(insights)

    def test_updates_stats(self):
        engine = AutonomousReasoningEngine()
        finding = {"vulnerability_type": "sql_injection"}
        insights = engine.generate_autonomous_insights(finding, {})
        assert engine.exploration_stats["total_insights"] == len(insights)


# ===================== Stats and Visualization Tests =====================

class TestStatsAndVisualization:
    def test_get_exploration_stats(self):
        engine = AutonomousReasoningEngine()
        stats = engine.get_exploration_stats()
        assert "total_insights" in stats
        assert "recent_insights" in stats
        assert stats["total_insights"] == 0

    def test_stats_after_insights(self):
        engine = AutonomousReasoningEngine()
        finding = {"vulnerability_type": "sql_injection"}
        engine.generate_autonomous_insights(finding, {})
        stats = engine.get_exploration_stats()
        assert stats["total_insights"] > 0
        assert len(stats["recent_insights"]) > 0

    def test_visualize_empty(self):
        engine = AutonomousReasoningEngine()
        result = engine.visualize_insights([])
        assert "未生成" in result

    def test_visualize_with_insights(self):
        engine = AutonomousReasoningEngine()
        insights = [
            AutonomousInsight("cross_domain", "Test", 0.7, 0.6, 30),
            AutonomousInsight("mutation", "Test2", 0.5, 0.8, 20),
        ]
        result = engine.visualize_insights(insights)
        assert "洞察 1" in result
        assert "洞察 2" in result
        assert "cross_domain" in result
        assert "总计: 2" in result
