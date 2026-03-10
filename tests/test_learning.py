"""
Tests for learning module (kali_mcp/ai/learning.py)

Covers:
- AttackOutcome enum
- AttackRecord: creation, defaults, to_dict
- Pattern: creation
- LearningEngine: init, record_attack, _update_stats, analyze_patterns,
  get_optimization_suggestions, get_tool_effectiveness, get_best_tools_for_target,
  get_summary, reset, _save_history, _load_history
- get_learning_engine global factory
"""

import pytest
import json
import tempfile
from pathlib import Path

from kali_mcp.ai.learning import (
    AttackOutcome,
    AttackRecord,
    Pattern,
    LearningEngine,
    get_learning_engine,
)


# ===================== AttackOutcome Tests =====================

class TestAttackOutcome:
    def test_values(self):
        assert AttackOutcome.SUCCESS.value == "success"
        assert AttackOutcome.PARTIAL.value == "partial"
        assert AttackOutcome.FAILURE.value == "failure"
        assert AttackOutcome.TIMEOUT.value == "timeout"
        assert AttackOutcome.BLOCKED.value == "blocked"

    def test_member_count(self):
        assert len(AttackOutcome) == 5


# ===================== AttackRecord Tests =====================

class TestAttackRecord:
    def test_creation(self):
        rec = AttackRecord(
            timestamp=1000.0,
            target_type="web",
            tool_name="nmap_scan",
            outcome=AttackOutcome.SUCCESS,
            findings_count=5,
            execution_time=10.5,
        )
        assert rec.timestamp == 1000.0
        assert rec.target_type == "web"
        assert rec.tool_name == "nmap_scan"
        assert rec.outcome == AttackOutcome.SUCCESS
        assert rec.findings_count == 5
        assert rec.execution_time == 10.5
        assert rec.parameters == {}
        assert rec.context == {}
        assert rec.error_message == ""

    def test_with_params(self):
        rec = AttackRecord(
            timestamp=1000.0,
            target_type="network",
            tool_name="hydra",
            outcome=AttackOutcome.FAILURE,
            findings_count=0,
            execution_time=60.0,
            parameters={"service": "ssh"},
            context={"target": "10.0.0.1"},
            error_message="Connection refused",
        )
        assert rec.parameters["service"] == "ssh"
        assert rec.error_message == "Connection refused"

    def test_to_dict(self):
        rec = AttackRecord(
            timestamp=1000.0,
            target_type="web",
            tool_name="sqlmap",
            outcome=AttackOutcome.SUCCESS,
            findings_count=3,
            execution_time=20.0,
        )
        d = rec.to_dict()
        assert d["outcome"] == "success"  # enum value, not enum object
        assert d["tool_name"] == "sqlmap"
        assert d["findings_count"] == 3

    def test_to_dict_all_outcomes(self):
        for outcome in AttackOutcome:
            rec = AttackRecord(
                timestamp=1.0,
                target_type="t",
                tool_name="t",
                outcome=outcome,
                findings_count=0,
                execution_time=0,
            )
            d = rec.to_dict()
            assert d["outcome"] == outcome.value

    def test_mutable_defaults(self):
        r1 = AttackRecord(timestamp=1.0, target_type="t", tool_name="t",
                          outcome=AttackOutcome.SUCCESS, findings_count=0, execution_time=0)
        r2 = AttackRecord(timestamp=2.0, target_type="t", tool_name="t",
                          outcome=AttackOutcome.SUCCESS, findings_count=0, execution_time=0)
        r1.parameters["key"] = "val"
        r1.context["k"] = "v"
        assert r2.parameters == {}
        assert r2.context == {}


# ===================== Pattern Tests =====================

class TestPattern:
    def test_creation(self):
        p = Pattern(
            pattern_type="high_success_tool",
            description="nmap works well",
            confidence=0.85,
            occurrences=10,
            recommendation="Use nmap more",
        )
        assert p.pattern_type == "high_success_tool"
        assert p.confidence == 0.85
        assert p.occurrences == 10


# ===================== LearningEngine Init Tests =====================

class TestLearningEngineInit:
    def test_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            assert engine.records == []
            assert engine.patterns == []
            assert engine.data_dir == Path(d)

    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as d:
            subdir = str(Path(d) / "sub" / "dir")
            engine = LearningEngine(data_dir=subdir)
            assert Path(subdir).exists()

    def test_default_stats(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            # defaultdict should return default values
            assert engine.tool_stats["any_tool"]["success"] == 0
            assert engine.target_type_stats["any_type"]["attacks"] == 0


# ===================== record_attack Tests =====================

class TestRecordAttack:
    def test_basic_recording(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap_scan", AttackOutcome.SUCCESS, findings_count=3, execution_time=5.0)
            assert len(engine.records) == 1
            assert engine.records[0].tool_name == "nmap_scan"

    def test_updates_tool_stats_success(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS, findings_count=2, execution_time=10.0)
            stats = engine.tool_stats["nmap"]
            assert stats["success"] == 1
            assert stats["failure"] == 0
            assert stats["total_time"] == 10.0
            assert stats["total_findings"] == 2

    def test_updates_tool_stats_failure(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "sqlmap", AttackOutcome.FAILURE, execution_time=5.0)
            stats = engine.tool_stats["sqlmap"]
            assert stats["success"] == 0
            assert stats["failure"] == 1

    def test_updates_target_type_stats(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            engine.record_attack("web", "nikto", AttackOutcome.FAILURE)
            assert engine.target_type_stats["web"]["attacks"] == 2
            assert engine.target_type_stats["web"]["success"] == 1

    def test_partial_counts_as_failure_in_stats(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.PARTIAL)
            assert engine.tool_stats["nmap"]["failure"] == 1

    def test_with_optional_params(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack(
                "web", "nmap", AttackOutcome.SUCCESS,
                parameters={"ports": "80,443"},
                context={"target": "10.0.0.1"},
                error_message=""
            )
            assert engine.records[0].parameters["ports"] == "80,443"

    def test_saves_every_10_records(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            for i in range(10):
                engine.record_attack("web", f"tool_{i}", AttackOutcome.SUCCESS)
            history_file = Path(d) / "attack_history.json"
            assert history_file.exists()


# ===================== analyze_patterns Tests =====================

class TestAnalyzePatterns:
    def test_no_patterns_few_records(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            for i in range(3):
                engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            patterns = engine.analyze_patterns()
            # need >= 5 total to detect patterns
            assert len(patterns) == 0

    def test_high_success_tool_pattern(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            # 5 successes, 0 failures → 100% success rate
            for i in range(5):
                engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            patterns = engine.analyze_patterns()
            high_success = [p for p in patterns if p.pattern_type == "high_success_tool"]
            assert len(high_success) == 1
            assert "nmap" in high_success[0].description

    def test_low_success_tool_pattern(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            # 1 success, 4 failures → 20% success rate
            engine.record_attack("web", "sqlmap", AttackOutcome.SUCCESS)
            for i in range(4):
                engine.record_attack("web", "sqlmap", AttackOutcome.FAILURE)
            patterns = engine.analyze_patterns()
            low_success = [p for p in patterns if p.pattern_type == "low_success_tool"]
            assert len(low_success) == 1

    def test_effective_target_type_pattern(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            # 4 success, 1 failure → 80% success rate on "web"
            for i in range(4):
                engine.record_attack("web", f"tool_{i}", AttackOutcome.SUCCESS)
            engine.record_attack("web", "tool_x", AttackOutcome.FAILURE)
            patterns = engine.analyze_patterns()
            effective = [p for p in patterns if p.pattern_type == "effective_target_type"]
            assert len(effective) == 1

    def test_slow_execution_pattern(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "slow_tool", AttackOutcome.SUCCESS, execution_time=120.0)
            engine.record_attack("web", "slow_tool", AttackOutcome.SUCCESS, execution_time=120.0)
            # Need at least 5 total for tool patterns, but slow_tool has avg_time > 60
            # The slow_tools check only requires total > 0
            patterns = engine.analyze_patterns()
            slow = [p for p in patterns if p.pattern_type == "slow_execution"]
            assert len(slow) == 1

    def test_confidence_capped_at_1(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            for i in range(25):
                engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            patterns = engine.analyze_patterns()
            for p in patterns:
                assert p.confidence <= 1.0

    def test_stores_patterns(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            assert engine.patterns == []
            for i in range(5):
                engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            engine.analyze_patterns()
            assert len(engine.patterns) > 0


# ===================== get_optimization_suggestions Tests =====================

class TestGetOptimizationSuggestions:
    def test_empty(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            suggestions = engine.get_optimization_suggestions()
            assert isinstance(suggestions, list)

    def test_includes_pattern_suggestions(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            for i in range(5):
                engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            suggestions = engine.get_optimization_suggestions()
            types = [s["type"] for s in suggestions]
            assert "high_success_tool" in types

    def test_high_finding_tools_suggestion(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nuclei", AttackOutcome.SUCCESS, findings_count=10)
            suggestions = engine.get_optimization_suggestions()
            types = [s["type"] for s in suggestions]
            assert "high_finding_tools" in types

    def test_suggestion_format(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            for i in range(5):
                engine.record_attack("web", "nmap", AttackOutcome.SUCCESS, findings_count=6)
            suggestions = engine.get_optimization_suggestions()
            for s in suggestions:
                assert "type" in s
                assert "confidence" in s


# ===================== get_tool_effectiveness Tests =====================

class TestGetToolEffectiveness:
    def test_unknown_tool(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            result = engine.get_tool_effectiveness("unknown_tool")
            assert result["total_executions"] == 0
            assert result["success_rate"] == 0
            assert result["avg_execution_time"] == 0

    def test_with_data(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS, findings_count=3, execution_time=10.0)
            engine.record_attack("web", "nmap", AttackOutcome.FAILURE, findings_count=0, execution_time=5.0)
            result = engine.get_tool_effectiveness("nmap")
            assert result["total_executions"] == 2
            assert result["success_count"] == 1
            assert result["failure_count"] == 1
            assert result["success_rate"] == 0.5
            assert result["avg_execution_time"] == 7.5
            assert result["avg_findings"] == 1.5


# ===================== get_best_tools_for_target Tests =====================

class TestGetBestToolsForTarget:
    def test_no_records(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            result = engine.get_best_tools_for_target("web")
            assert result == []

    def test_needs_minimum_2_uses(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            result = engine.get_best_tools_for_target("web")
            assert result == []

    def test_returns_tools_sorted_by_score(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            # nmap: 2 success, 0 failure, 10 findings → high score
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS, findings_count=5)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS, findings_count=5)
            # sqlmap: 1 success, 1 failure, 0 findings → lower score
            engine.record_attack("web", "sqlmap", AttackOutcome.SUCCESS)
            engine.record_attack("web", "sqlmap", AttackOutcome.FAILURE)
            result = engine.get_best_tools_for_target("web")
            assert len(result) == 2
            assert result[0]["tool"] == "nmap"
            assert result[0]["score"] > result[1]["score"]

    def test_filters_by_target_type(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            engine.record_attack("network", "masscan", AttackOutcome.SUCCESS)
            engine.record_attack("network", "masscan", AttackOutcome.SUCCESS)
            web_tools = engine.get_best_tools_for_target("web")
            assert all(t["tool"] == "nmap" for t in web_tools)

    def test_limit(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            for tool in ["t1", "t2", "t3", "t4"]:
                engine.record_attack("web", tool, AttackOutcome.SUCCESS)
                engine.record_attack("web", tool, AttackOutcome.SUCCESS)
            result = engine.get_best_tools_for_target("web", limit=2)
            assert len(result) == 2

    def test_score_formula(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            # 2 success, 0 failure → success_rate = 1.0
            # 20 findings / (2 * 10) = 1.0 → capped at 1.0
            # score = 1.0 * 0.6 + 1.0 * 0.4 = 1.0
            engine.record_attack("web", "tool", AttackOutcome.SUCCESS, findings_count=10)
            engine.record_attack("web", "tool", AttackOutcome.SUCCESS, findings_count=10)
            result = engine.get_best_tools_for_target("web")
            assert abs(result[0]["score"] - 1.0) < 0.01


# ===================== save/load Tests =====================

class TestSaveLoad:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            engine1 = LearningEngine(data_dir=d)
            engine1.record_attack("web", "nmap", AttackOutcome.SUCCESS, findings_count=3, execution_time=10.0)
            engine1._save_history()

            engine2 = LearningEngine(data_dir=d)
            assert len(engine2.records) == 1
            assert engine2.records[0].tool_name == "nmap"
            assert engine2.records[0].outcome == AttackOutcome.SUCCESS

    def test_load_stats(self):
        with tempfile.TemporaryDirectory() as d:
            engine1 = LearningEngine(data_dir=d)
            engine1.record_attack("web", "nmap", AttackOutcome.SUCCESS, execution_time=5.0)
            engine1._save_history()

            engine2 = LearningEngine(data_dir=d)
            assert engine2.tool_stats["nmap"]["success"] >= 1

    def test_load_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            # No crash when file doesn't exist
            assert engine.records == []

    def test_saves_max_1000_records(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            for i in range(1050):
                engine.record_attack("web", "tool", AttackOutcome.SUCCESS)
            engine._save_history()

            history_file = Path(d) / "attack_history.json"
            with open(history_file) as f:
                data = json.load(f)
            assert len(data["records"]) == 1000


# ===================== get_summary Tests =====================

class TestGetSummary:
    def test_empty(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            summary = engine.get_summary()
            assert summary["total_records"] == 0
            assert summary["tools_tracked"] == 0
            assert summary["target_types_tracked"] == 0
            assert summary["patterns_identified"] == 0

    def test_with_data(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            engine.record_attack("network", "masscan", AttackOutcome.FAILURE)
            summary = engine.get_summary()
            assert summary["total_records"] == 2
            assert summary["tools_tracked"] == 2
            assert summary["target_types_tracked"] == 2


# ===================== reset Tests =====================

class TestReset:
    def test_clears_all(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            engine.analyze_patterns()
            engine._save_history()
            engine.reset()
            assert engine.records == []
            assert engine.patterns == []
            assert len(engine.tool_stats) == 0
            assert len(engine.target_type_stats) == 0

    def test_deletes_history_file(self):
        with tempfile.TemporaryDirectory() as d:
            engine = LearningEngine(data_dir=d)
            engine.record_attack("web", "nmap", AttackOutcome.SUCCESS)
            engine._save_history()
            history_file = Path(d) / "attack_history.json"
            assert history_file.exists()
            engine.reset()
            assert not history_file.exists()


# ===================== get_learning_engine Tests =====================

class TestGetLearningEngine:
    def test_returns_instance(self):
        import kali_mcp.ai.learning as mod
        mod._global_engine = None
        engine = get_learning_engine()
        assert isinstance(engine, LearningEngine)

    def test_returns_same_instance(self):
        import kali_mcp.ai.learning as mod
        mod._global_engine = None
        e1 = get_learning_engine()
        e2 = get_learning_engine()
        assert e1 is e2
