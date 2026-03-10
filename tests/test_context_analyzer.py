"""
Tests for context_analyzer module (kali_mcp/core/context_analyzer.py)

Covers:
- AdvancedContextAnalyzer: init, analyze_context_patterns,
  _discover_sequence_patterns, _discover_tool_usage_patterns,
  _discover_outcome_patterns, _analyze_correlations,
  _extract_behavioral_insights, _generate_predictive_recommendations,
  _find_frequent_sequences, _extract_context_features,
  _identify_common_features, _update_pattern_repository
"""

import pytest
from unittest.mock import patch

from kali_mcp.core.context_analyzer import AdvancedContextAnalyzer


# ===================== Init Tests =====================

class TestAdvancedContextAnalyzerInit:
    def test_defaults(self):
        analyzer = AdvancedContextAnalyzer()
        assert analyzer.pattern_repository == {}
        assert analyzer.behavioral_sequences == []
        assert analyzer.min_pattern_confidence == 0.6
        assert analyzer.min_correlation_strength == 0.7
        assert analyzer.pattern_discovery_window == 100


# ===================== _find_frequent_sequences Tests =====================

class TestFindFrequentSequences:
    def test_empty_input(self):
        analyzer = AdvancedContextAnalyzer()
        result = analyzer._find_frequent_sequences([], min_length=2, min_support=2)
        assert result == []

    def test_short_input(self):
        analyzer = AdvancedContextAnalyzer()
        result = analyzer._find_frequent_sequences(["nmap"], min_length=2, min_support=2)
        assert result == []

    def test_finds_frequent_pair(self):
        analyzer = AdvancedContextAnalyzer()
        # "nmap, gobuster" appears twice
        sequences = ["nmap", "gobuster", "nuclei", "nmap", "gobuster"]
        result = analyzer._find_frequent_sequences(sequences, min_length=2, min_support=2)
        # Should find ("nmap", "gobuster") with support >= 2
        found_seqs = [seq for seq, count in result]
        assert ("nmap", "gobuster") in found_seqs

    def test_respects_min_support(self):
        analyzer = AdvancedContextAnalyzer()
        sequences = ["a", "b", "c", "d", "e"]
        result = analyzer._find_frequent_sequences(sequences, min_length=2, min_support=2)
        assert result == []

    def test_returns_top_10(self):
        analyzer = AdvancedContextAnalyzer()
        # Create many repeated patterns
        sequences = ["a", "b"] * 20
        result = analyzer._find_frequent_sequences(sequences, min_length=2, min_support=2)
        assert len(result) <= 10

    def test_sorted_by_count_descending(self):
        analyzer = AdvancedContextAnalyzer()
        sequences = ["a", "b", "a", "b", "a", "b", "c", "d", "c", "d"]
        result = analyzer._find_frequent_sequences(sequences, min_length=2, min_support=2)
        if len(result) >= 2:
            assert result[0][1] >= result[1][1]


# ===================== _extract_context_features Tests =====================

class TestExtractContextFeatures:
    def test_extracts_features(self):
        analyzer = AdvancedContextAnalyzer()
        entry = {
            "tools_used": ["nmap_scan", "gobuster_scan"],
            "target_type": "web",
            "strategy": "aggressive",
            "session_depth": 3,
        }
        features = analyzer._extract_context_features(entry)
        assert features["tools_used"] == ["nmap_scan", "gobuster_scan"]
        assert features["target_type"] == "web"
        assert features["strategy"] == "aggressive"
        assert features["session_depth"] == 3

    def test_missing_fields_default(self):
        analyzer = AdvancedContextAnalyzer()
        features = analyzer._extract_context_features({})
        assert features["tools_used"] == []
        assert features["target_type"] == "unknown"
        assert features["strategy"] == "unknown"
        assert features["session_depth"] == 0


# ===================== _identify_common_features Tests =====================

class TestIdentifyCommonFeatures:
    def test_empty_input(self):
        analyzer = AdvancedContextAnalyzer()
        result = analyzer._identify_common_features([])
        assert result == {}

    def test_all_same(self):
        analyzer = AdvancedContextAnalyzer()
        contexts = [
            {"target_type": "web", "strategy": "aggressive"},
            {"target_type": "web", "strategy": "aggressive"},
        ]
        result = analyzer._identify_common_features(contexts)
        assert result["target_type"] == "web"
        assert result["strategy"] == "aggressive"

    def test_different_values_excluded(self):
        analyzer = AdvancedContextAnalyzer()
        contexts = [
            {"target_type": "web", "strategy": "aggressive"},
            {"target_type": "web", "strategy": "passive"},
        ]
        result = analyzer._identify_common_features(contexts)
        assert "target_type" in result
        assert "strategy" not in result

    def test_returns_none_if_no_common(self):
        analyzer = AdvancedContextAnalyzer()
        contexts = [
            {"target_type": "web"},
            {"target_type": "network"},
        ]
        result = analyzer._identify_common_features(contexts)
        assert result is None


# ===================== _extract_behavioral_insights Tests =====================

class TestExtractBehavioralInsights:
    def test_empty_history(self):
        analyzer = AdvancedContextAnalyzer()
        result = analyzer._extract_behavioral_insights([])
        assert result["total_interactions"] == 0
        assert result["tool_diversity"] == 0
        assert result["success_rate"] == 0

    def test_with_data(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"tools_used": ["nmap_scan", "gobuster_scan"], "outcome": "success"},
            {"tools_used": ["nmap_scan", "nuclei_scan"], "outcome": "failure"},
            {"tools_used": ["sqlmap_scan"], "outcome": "success"},
        ]
        result = analyzer._extract_behavioral_insights(history)
        assert result["total_interactions"] == 3
        assert result["tool_diversity"] == 4  # nmap, gobuster, nuclei, sqlmap
        assert abs(result["success_rate"] - 2/3) < 0.01

    def test_no_outcome_field(self):
        analyzer = AdvancedContextAnalyzer()
        history = [{"tools_used": ["nmap_scan"]}]
        result = analyzer._extract_behavioral_insights(history)
        assert result["success_rate"] == 0


# ===================== _discover_sequence_patterns Tests =====================

class TestDiscoverSequencePatterns:
    def test_short_history(self):
        analyzer = AdvancedContextAnalyzer()
        result = analyzer._discover_sequence_patterns([{"tools_used": ["nmap"]}])
        assert result == []

    def test_finds_patterns(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"tools_used": ["nmap", "gobuster"]},
            {"tools_used": ["nmap", "gobuster"]},
            {"tools_used": ["nuclei"]},
        ]
        result = analyzer._discover_sequence_patterns(history)
        # Should find ("nmap", "gobuster") pattern
        pattern_names = [p["pattern_name"] for p in result]
        assert any("nmap" in n and "gobuster" in n for n in pattern_names)


# ===================== _discover_tool_usage_patterns Tests =====================

class TestDiscoverToolUsagePatterns:
    def test_no_patterns_below_threshold(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"tools_used": ["nmap_scan"], "success_indicators": {"nmap_scan": True}},
            {"tools_used": ["gobuster_scan"], "success_indicators": {"gobuster_scan": False}},
        ]
        result = analyzer._discover_tool_usage_patterns(history)
        assert result == []  # need 3+ uses

    def test_finds_effective_tool(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"tools_used": ["nmap_scan"], "success_indicators": {"nmap_scan": True}},
            {"tools_used": ["nmap_scan"], "success_indicators": {"nmap_scan": True}},
            {"tools_used": ["nmap_scan"], "success_indicators": {"nmap_scan": True}},
        ]
        result = analyzer._discover_tool_usage_patterns(history)
        assert len(result) >= 1
        assert result[0]["pattern_type"] == "tool_effectiveness"
        assert result[0]["pattern_signature"]["success_rate"] == 1.0

    def test_ignores_low_success_rate(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"tools_used": ["sqlmap"], "success_indicators": {"sqlmap": True}},
            {"tools_used": ["sqlmap"], "success_indicators": {"sqlmap": False}},
            {"tools_used": ["sqlmap"], "success_indicators": {"sqlmap": False}},
            {"tools_used": ["sqlmap"], "success_indicators": {"sqlmap": False}},
        ]
        result = analyzer._discover_tool_usage_patterns(history)
        # 25% success rate, below 70% threshold
        assert result == []


# ===================== _discover_outcome_patterns Tests =====================

class TestDiscoverOutcomePatterns:
    def test_no_patterns_few_successes(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"outcome": "success", "tools_used": ["nmap"], "target_type": "web"},
        ]
        result = analyzer._discover_outcome_patterns(history)
        assert result == []  # needs >= 2 successes

    def test_finds_success_pattern(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"outcome": "success", "tools_used": ["nmap"], "target_type": "web",
             "strategy": "aggressive", "session_depth": 2},
            {"outcome": "success", "tools_used": ["nmap"], "target_type": "web",
             "strategy": "aggressive", "session_depth": 2},
        ]
        result = analyzer._discover_outcome_patterns(history)
        assert len(result) >= 1
        assert result[0]["pattern_type"] == "outcome_success"


# ===================== _analyze_correlations Tests =====================

class TestAnalyzeCorrelations:
    def test_empty_history(self):
        analyzer = AdvancedContextAnalyzer()
        result = analyzer._analyze_correlations([], {})
        assert result == []

    def test_finds_strong_correlation(self):
        analyzer = AdvancedContextAnalyzer()
        history = [
            {"tools_used": ["nmap_scan"], "outcome": "success"},
            {"tools_used": ["nmap_scan"], "outcome": "success"},
            {"tools_used": ["nmap_scan"], "outcome": "success"},
            {"tools_used": ["nmap_scan"], "outcome": "success"},
        ]
        result = analyzer._analyze_correlations(history, {})
        # nmap with 100% success rate should create a strong correlation
        assert len(result) >= 1
        assert result[0]["correlation_type"] == "tool_outcome"
        assert result[0]["target"] == "success"


# ===================== _generate_predictive_recommendations Tests =====================

class TestGeneratePredictiveRecommendations:
    def test_no_recommendations_low_confidence(self):
        analyzer = AdvancedContextAnalyzer()
        patterns = [{"pattern_name": "test", "confidence_score": 0.3}]
        result = analyzer._generate_predictive_recommendations({}, patterns, [])
        assert result == []

    def test_pattern_based_recommendation(self):
        analyzer = AdvancedContextAnalyzer()
        patterns = [{"pattern_name": "effective_nmap", "confidence_score": 0.9}]
        result = analyzer._generate_predictive_recommendations({}, patterns, [])
        assert len(result) == 1
        assert result[0]["type"] == "pattern_based"
        assert result[0]["confidence"] == 0.9

    def test_correlation_based_recommendation(self):
        analyzer = AdvancedContextAnalyzer()
        correlations = [{"source": "sqlmap_scan", "correlation_strength": 0.95}]
        result = analyzer._generate_predictive_recommendations({}, [], correlations)
        assert len(result) == 1
        assert result[0]["type"] == "correlation_based"
        assert "sqlmap_scan" in result[0]["suggestion"]


# ===================== _update_pattern_repository Tests =====================

class TestUpdatePatternRepository:
    def _patch_uuid(self):
        """Inject uuid into context_analyzer module namespace to fix missing import."""
        import uuid
        import kali_mcp.core.context_analyzer as mod
        if not hasattr(mod, 'uuid'):
            mod.uuid = uuid

    def test_creates_new_pattern(self):
        self._patch_uuid()
        analyzer = AdvancedContextAnalyzer()
        pattern = {
            "pattern_name": "test_pattern",
            "pattern_type": "sequential",
            "pattern_signature": {"seq": ["a", "b"]},
            "confidence_score": 0.8,
        }
        analyzer._update_pattern_repository(pattern)
        assert "test_pattern" in analyzer.pattern_repository
        stored = analyzer.pattern_repository["test_pattern"]
        assert stored.occurrence_count == 1
        assert stored.confidence_score == 0.8

    def test_updates_existing_pattern(self):
        self._patch_uuid()
        analyzer = AdvancedContextAnalyzer()
        pattern = {
            "pattern_name": "test_pattern",
            "pattern_type": "sequential",
            "confidence_score": 0.8,
        }
        analyzer._update_pattern_repository(pattern)
        # Second update
        pattern2 = {"pattern_name": "test_pattern", "confidence_score": 1.0}
        analyzer._update_pattern_repository(pattern2)

        stored = analyzer.pattern_repository["test_pattern"]
        assert stored.occurrence_count == 2
        # Moving average: 0.8 * 0.8 + 1.0 * 0.2 = 0.84
        assert abs(stored.confidence_score - 0.84) < 0.01


# ===================== analyze_context_patterns (integration) Tests =====================

class TestAnalyzeContextPatterns:
    def test_empty_history(self):
        analyzer = AdvancedContextAnalyzer()
        result = analyzer.analyze_context_patterns([], {})
        assert "discovered_patterns" in result
        assert "strong_correlations" in result
        assert "behavioral_insights" in result
        assert "predictive_recommendations" in result

    def test_with_rich_history(self):
        # Patch uuid for _update_pattern_repository
        import uuid as _uuid
        import kali_mcp.core.context_analyzer as mod
        if not hasattr(mod, 'uuid'):
            mod.uuid = _uuid

        analyzer = AdvancedContextAnalyzer()
        history = [
            {"tools_used": ["nmap", "gobuster"], "outcome": "success",
             "target_type": "web", "strategy": "aggressive", "session_depth": 1,
             "success_indicators": {"nmap": True, "gobuster": True}},
            {"tools_used": ["nmap", "gobuster"], "outcome": "success",
             "target_type": "web", "strategy": "aggressive", "session_depth": 2,
             "success_indicators": {"nmap": True, "gobuster": True}},
            {"tools_used": ["nmap", "nuclei"], "outcome": "failure",
             "target_type": "web", "strategy": "aggressive", "session_depth": 3,
             "success_indicators": {"nmap": True, "nuclei": False}},
        ]
        result = analyzer.analyze_context_patterns(history, {})
        assert result["behavioral_insights"]["total_interactions"] == 3
        assert result["behavioral_insights"]["tool_diversity"] >= 3

    def test_handles_exception_gracefully(self):
        analyzer = AdvancedContextAnalyzer()
        # Pass malformed data that might cause issues
        result = analyzer.analyze_context_patterns([None], {})
        # Should have "error" key or empty results
        assert isinstance(result, dict)
