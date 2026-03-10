"""
Tests for MLStrategyOptimizer (kali_mcp/core/ml_optimizer.py)

Covers:
- Database initialization
- Recording tool outcomes
- Tool success rate calculation
- Tool duration tracking
- Target type classification
- Tool recommendations
- Learning summary
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from kali_mcp.core.ml_optimizer import MLStrategyOptimizer


@pytest.fixture
def ml(tmp_path):
    """Create MLStrategyOptimizer with temp database via env var."""
    db_path = str(tmp_path / "test_learning.db")
    with patch.dict(os.environ, {"KALI_MCP_LEARNING_DB": db_path}):
        optimizer = MLStrategyOptimizer()
    return optimizer


class TestInit:
    """Test initialization."""

    def test_creates_database(self, tmp_path):
        db_path = str(tmp_path / "init_test.db")
        with patch.dict(os.environ, {"KALI_MCP_LEARNING_DB": db_path}):
            ml = MLStrategyOptimizer()
        assert os.path.exists(db_path)

    def test_default_strategy_weights(self, ml):
        assert len(ml.strategy_weights) > 0
        assert "web_comprehensive" in ml.strategy_weights


class TestRecordOutcome:
    """Test recording tool execution outcomes."""

    def test_record_success(self, ml):
        ml.record_tool_outcome(
            tool_name="nmap",
            target="192.168.1.1",
            success=True,
            duration=5.0,
        )
        rate = ml.get_tool_success_rate("nmap")
        assert rate == 1.0

    def test_record_failure(self, ml):
        ml.record_tool_outcome("nmap", "10.0.0.1", False, 2.0)
        rate = ml.get_tool_success_rate("nmap")
        assert rate == 0.0

    def test_mixed_results(self, ml):
        ml.record_tool_outcome("nmap", "10.0.0.1", True, 3.0)
        ml.record_tool_outcome("nmap", "10.0.0.2", False, 2.0)
        rate = ml.get_tool_success_rate("nmap")
        assert rate == 0.5

    def test_multiple_tools(self, ml):
        ml.record_tool_outcome("nmap", "10.0.0.1", True, 3.0)
        ml.record_tool_outcome("sqlmap", "10.0.0.1", True, 10.0)
        assert ml.get_tool_success_rate("nmap") == 1.0
        assert ml.get_tool_success_rate("sqlmap") == 1.0


class TestToolDuration:
    """Test tool duration tracking."""

    def test_avg_duration(self, ml):
        ml.record_tool_outcome("nmap", "10.0.0.1", True, 5.0)
        ml.record_tool_outcome("nmap", "10.0.0.2", True, 15.0)
        avg = ml.get_tool_avg_duration("nmap")
        assert avg == 10.0

    def test_unknown_tool_duration(self, ml):
        avg = ml.get_tool_avg_duration("unknown_tool")
        assert avg == 0


class TestSuccessRate:
    """Test success rate calculation."""

    def test_unknown_tool_returns_neutral(self, ml):
        """No data returns 0.5 (neutral)."""
        rate = ml.get_tool_success_rate("unknown_tool")
        assert rate == 0.5

    def test_all_success(self, ml):
        for i in range(5):
            ml.record_tool_outcome("nmap", f"10.0.0.{i}", True, 3.0)
        assert ml.get_tool_success_rate("nmap") == 1.0

    def test_all_failure(self, ml):
        for i in range(3):
            ml.record_tool_outcome("nmap", f"10.0.0.{i}", False, 2.0)
        assert ml.get_tool_success_rate("nmap") == 0.0


class TestTargetClassification:
    """Test target type classification."""

    def test_web_target(self, ml):
        assert ml._classify_target_type_simple("http://example.com") == "web"

    def test_web_target_https(self, ml):
        assert ml._classify_target_type_simple("https://example.com/api") == "web"

    def test_network_cidr(self, ml):
        assert ml._classify_target_type_simple("192.168.1.0/24") == "network"

    def test_domain_target(self, ml):
        assert ml._classify_target_type_simple("example.com") == "domain"

    def test_binary_target(self, ml):
        assert ml._classify_target_type_simple("/tmp/challenge.elf") == "binary"

    def test_empty_target(self, ml):
        assert ml._classify_target_type_simple("") == "unknown"


class TestRecommendations:
    """Test tool recommendation engine."""

    def test_recommend_with_history(self, ml):
        # Build history for web target type
        ml.record_tool_outcome("nmap", "http://example.com", True, 5.0)
        ml.record_tool_outcome("gobuster", "http://example.com", True, 10.0)
        ml.record_tool_outcome("sqlmap", "http://example.com", False, 20.0)

        recs = ml.recommend_tools_for_target("web")
        assert isinstance(recs, list)
        if len(recs) >= 2:
            tool_names = [r["tool"] for r in recs]
            # Successful tools should be recommended
            assert "nmap" in tool_names or "gobuster" in tool_names

    def test_recommend_empty_type(self, ml):
        recs = ml.recommend_tools_for_target("nonexistent_type")
        assert isinstance(recs, list)


class TestLearningSummary:
    """Test learning summary."""

    def test_empty_summary(self, ml):
        summary = ml.get_learning_summary()
        assert summary["total_records"] == 0

    def test_summary_with_data(self, ml):
        ml.record_tool_outcome("nmap", "10.0.0.1", True, 5.0)
        ml.record_tool_outcome("sqlmap", "10.0.0.1", True, 10.0)
        ml.record_tool_outcome("nmap", "10.0.0.2", False, 3.0)

        summary = ml.get_learning_summary()
        assert summary["total_records"] == 3
        assert summary["unique_tools"] >= 2
