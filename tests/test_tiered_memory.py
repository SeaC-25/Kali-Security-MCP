#!/usr/bin/env python3
"""
Tests for kali_mcp/core/tiered_memory.py

Covers:
- MemoryEntry dataclass
- TieredMemory initialization
- Working memory: add, auto-summarize on overflow
- Important memory: mark, priority-based eviction
- Summary memory: auto-summarize, limit enforcement
- Context retrieval across tiers
- Statistics and clear
"""

import pytest
from datetime import datetime

from kali_mcp.core.tiered_memory import MemoryEntry, TieredMemory


# ============ MemoryEntry Tests ============

class TestMemoryEntry:
    """Tests for the MemoryEntry dataclass."""

    def test_default_values(self):
        entry = MemoryEntry()
        assert entry.content == ""
        assert entry.source == ""
        assert entry.category == "interaction"
        assert entry.importance == "normal"
        assert entry.metadata == {}
        # timestamp should be an ISO-format string
        datetime.fromisoformat(entry.timestamp)

    def test_custom_values(self):
        entry = MemoryEntry(
            content="found SQL injection",
            source="sqlmap",
            category="vuln",
            importance="critical",
            metadata={"url": "http://target/login"},
        )
        assert entry.content == "found SQL injection"
        assert entry.source == "sqlmap"
        assert entry.category == "vuln"
        assert entry.importance == "critical"
        assert entry.metadata == {"url": "http://target/login"}

    def test_to_dict(self):
        entry = MemoryEntry(content="test", source="agent1")
        d = entry.to_dict()
        assert isinstance(d, dict)
        assert d["content"] == "test"
        assert d["source"] == "agent1"
        assert d["category"] == "interaction"
        assert d["importance"] == "normal"
        assert "timestamp" in d
        assert "metadata" in d

    def test_separate_metadata_instances(self):
        """Each entry should get its own metadata dict."""
        e1 = MemoryEntry()
        e2 = MemoryEntry()
        e1.metadata["key"] = "val"
        assert "key" not in e2.metadata


# ============ TieredMemory Initialization ============

class TestTieredMemoryInit:
    """Tests for TieredMemory construction and defaults."""

    def test_default_limits(self):
        mem = TieredMemory()
        assert mem._working_limit == 10
        assert mem._important_limit == 50
        assert mem._summary_limit == 20

    def test_custom_limits(self):
        mem = TieredMemory(working_limit=5, important_limit=20, summary_limit=10)
        assert mem._working_limit == 5
        assert mem._important_limit == 20
        assert mem._summary_limit == 10

    def test_empty_on_init(self):
        mem = TieredMemory()
        assert len(mem.working_memory) == 0
        assert len(mem.important_memory) == 0
        assert len(mem.summary_memory) == 0


# ============ Working Memory ============

class TestWorkingMemory:
    """Tests for add_interaction and working memory behavior."""

    def test_add_single_interaction(self):
        mem = TieredMemory()
        mem.add_interaction("scan target 10.0.0.1", source="nmap")
        assert len(mem.working_memory) == 1
        assert mem.working_memory[0].content == "scan target 10.0.0.1"
        assert mem.working_memory[0].source == "nmap"
        assert mem.working_memory[0].category == "interaction"

    def test_add_interaction_with_metadata(self):
        mem = TieredMemory()
        meta = {"port": 80}
        mem.add_interaction("found port", source="nmap", metadata=meta)
        assert mem.working_memory[0].metadata == {"port": 80}

    def test_add_interaction_none_metadata_defaults_to_empty_dict(self):
        mem = TieredMemory()
        mem.add_interaction("test")
        assert mem.working_memory[0].metadata == {}

    def test_within_limit_no_summarize(self):
        mem = TieredMemory(working_limit=5)
        for i in range(5):
            mem.add_interaction(f"entry {i}")
        assert len(mem.working_memory) == 5
        assert len(mem.summary_memory) == 0

    def test_over_limit_triggers_auto_summarize(self):
        mem = TieredMemory(working_limit=5)
        for i in range(6):
            mem.add_interaction(f"entry {i}", source="tool")
        # After auto_summarize, working_memory should keep last 3
        assert len(mem.working_memory) == 3
        assert len(mem.summary_memory) == 1

    def test_auto_summarize_preserves_latest_entries(self):
        mem = TieredMemory(working_limit=5)
        for i in range(6):
            mem.add_interaction(f"entry {i}")
        # The last 3 entries added were "entry 3", "entry 4", "entry 5"
        contents = [e.content for e in mem.working_memory]
        assert contents == ["entry 3", "entry 4", "entry 5"]

    def test_repeated_overflow(self):
        """Multiple overflows should accumulate summaries."""
        mem = TieredMemory(working_limit=4)
        for i in range(12):
            mem.add_interaction(f"entry {i}", source="s")
        # After multiple summarize cycles, working should have <= 4 entries
        assert len(mem.working_memory) <= 4
        assert len(mem.summary_memory) >= 1


# ============ Important Memory ============

class TestImportantMemory:
    """Tests for mark_important and eviction logic."""

    def test_mark_important_basic(self):
        mem = TieredMemory()
        mem.mark_important("SQL injection found", reason="vuln detected", source="sqlmap")
        assert len(mem.important_memory) == 1
        entry = mem.important_memory[0]
        assert entry.content == "SQL injection found"
        assert entry.importance == "high"
        assert entry.category == "discovery"
        assert entry.metadata == {"reason": "vuln detected"}

    def test_mark_important_custom_importance(self):
        mem = TieredMemory()
        mem.mark_important("root creds", reason="critical finding",
                           importance="critical", category="credential")
        assert mem.important_memory[0].importance == "critical"
        assert mem.important_memory[0].category == "credential"

    def test_within_limit_no_eviction(self):
        mem = TieredMemory(important_limit=5)
        for i in range(5):
            mem.mark_important(f"finding {i}", reason="test")
        assert len(mem.important_memory) == 5

    def test_over_limit_evicts_low_importance(self):
        mem = TieredMemory(important_limit=3)
        mem.mark_important("low item", reason="r", importance="low")
        mem.mark_important("critical item", reason="r", importance="critical")
        mem.mark_important("high item", reason="r", importance="high")
        # This 4th entry triggers eviction
        mem.mark_important("normal item", reason="r", importance="normal")
        assert len(mem.important_memory) == 3
        # The low item should have been evicted (lowest priority)
        importances = [e.importance for e in mem.important_memory]
        assert "low" not in importances
        assert "critical" in importances

    def test_eviction_priority_order(self):
        """When over limit, entries are sorted by importance descending and truncated."""
        mem = TieredMemory(important_limit=2)
        mem.mark_important("A", reason="r", importance="low")
        mem.mark_important("B", reason="r", importance="normal")
        mem.mark_important("C", reason="r", importance="critical")
        # After the 3rd insert, we should have the top 2 by importance
        assert len(mem.important_memory) == 2
        importances = [e.importance for e in mem.important_memory]
        assert importances[0] == "critical"
        assert importances[1] == "normal"


# ============ Summary Memory ============

class TestSummaryMemory:
    """Tests for auto_summarize behavior."""

    def test_auto_summarize_empty_working(self):
        mem = TieredMemory()
        result = mem.auto_summarize()
        assert result == ""

    def test_auto_summarize_too_few_entries(self):
        """With <= 3 entries, to_summarize is empty, so no summary produced."""
        mem = TieredMemory()
        mem.add_interaction("a")
        mem.add_interaction("b")
        mem.add_interaction("c")
        result = mem.auto_summarize()
        assert result == ""
        assert len(mem.summary_memory) == 0

    def test_auto_summarize_produces_summary_string(self):
        mem = TieredMemory(working_limit=100)  # high limit to avoid auto-trigger
        for i in range(6):
            mem.add_interaction(f"entry {i}", source="agent1", category="interaction")
        summary = mem.auto_summarize()
        assert len(summary) > 0
        assert "3" in summary  # 3 entries summarized (6 - last 3)
        assert "agent1" in summary

    def test_auto_summarize_trims_working_to_last_3(self):
        mem = TieredMemory(working_limit=100)
        for i in range(10):
            mem.add_interaction(f"entry {i}")
        mem.auto_summarize()
        assert len(mem.working_memory) == 3
        assert mem.working_memory[-1].content == "entry 9"

    def test_summary_limit_enforcement(self):
        mem = TieredMemory(working_limit=100, summary_limit=3)
        # Manually call auto_summarize multiple times
        for batch in range(5):
            for i in range(5):
                mem.add_interaction(f"batch{batch}_entry{i}", source="s")
            mem.auto_summarize()
        assert len(mem.summary_memory) <= 3

    def test_summary_keeps_latest_when_over_limit(self):
        mem = TieredMemory(working_limit=100, summary_limit=2)
        # Build enough entries to generate multiple summaries
        for batch in range(4):
            # Reset working memory for next batch
            mem.working_memory = []
            for i in range(5):
                mem.add_interaction(f"batch{batch}_entry{i}", source=f"src{batch}")
            mem.auto_summarize()
        # Should keep the latest 2 summaries
        assert len(mem.summary_memory) == 2

    def test_summary_includes_sources_and_categories(self):
        mem = TieredMemory(working_limit=100)
        mem.add_interaction("a", source="nmap", category="scan")
        mem.add_interaction("b", source="gobuster", category="discovery")
        mem.add_interaction("c", source="nmap", category="scan")
        mem.add_interaction("d")  # ensure > 3 entries for non-empty to_summarize
        mem.add_interaction("e")
        mem.add_interaction("f")
        summary = mem.auto_summarize()
        assert "nmap" in summary or "gobuster" in summary
        assert "scan" in summary or "discovery" in summary


# ============ Context Retrieval ============

class TestGetContext:
    """Tests for get_context across tiers."""

    def test_empty_context(self):
        mem = TieredMemory()
        ctx = mem.get_context()
        assert ctx == []

    def test_context_with_working_only(self):
        mem = TieredMemory()
        mem.add_interaction("test entry")
        ctx = mem.get_context()
        assert len(ctx) == 1
        assert ctx[0]["layer"] == "working"
        assert len(ctx[0]["entries"]) == 1

    def test_context_with_important_only(self):
        mem = TieredMemory()
        mem.mark_important("vuln found", reason="test")
        ctx = mem.get_context()
        assert len(ctx) == 1
        assert ctx[0]["layer"] == "important"

    def test_context_with_all_three_tiers(self):
        mem = TieredMemory(working_limit=4)
        # Generate summary by overflowing working memory
        for i in range(5):
            mem.add_interaction(f"entry {i}", source="s")
        # Add important
        mem.mark_important("critical vuln", reason="test")
        ctx = mem.get_context()
        layers = [c["layer"] for c in ctx]
        assert "summary" in layers
        assert "important" in layers
        assert "working" in layers

    def test_context_order_summary_important_working(self):
        """Context layers should appear in order: summary, important, working."""
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"entry {i}", source="s")
        mem.mark_important("vuln", reason="r")
        ctx = mem.get_context()
        layers = [c["layer"] for c in ctx]
        assert layers.index("summary") < layers.index("important")
        assert layers.index("important") < layers.index("working")

    def test_context_exclude_summary(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"entry {i}", source="s")
        ctx = mem.get_context(include_summary=False)
        layers = [c["layer"] for c in ctx]
        assert "summary" not in layers

    def test_context_limits_important_to_10(self):
        mem = TieredMemory(important_limit=50)
        for i in range(20):
            mem.mark_important(f"item {i}", reason="r")
        ctx = mem.get_context()
        important_layer = [c for c in ctx if c["layer"] == "important"][0]
        assert len(important_layer["entries"]) <= 10

    def test_context_limits_summary_to_5(self):
        mem = TieredMemory(working_limit=100, summary_limit=20)
        # Generate many summaries
        for batch in range(8):
            mem.working_memory = []
            for i in range(5):
                mem.add_interaction(f"b{batch}_e{i}", source="s")
            mem.auto_summarize()
        ctx = mem.get_context()
        summary_layer = [c for c in ctx if c["layer"] == "summary"][0]
        assert len(summary_layer["entries"]) <= 5

    def test_context_working_entries_are_dicts(self):
        mem = TieredMemory()
        mem.add_interaction("test")
        ctx = mem.get_context()
        working = ctx[0]
        assert working["layer"] == "working"
        entry = working["entries"][0]
        assert isinstance(entry, dict)
        assert "content" in entry


# ============ Statistics ============

class TestStatistics:
    """Tests for get_statistics."""

    def test_empty_statistics(self):
        mem = TieredMemory(working_limit=10, important_limit=50, summary_limit=20)
        stats = mem.get_statistics()
        assert stats["working_count"] == 0
        assert stats["working_limit"] == 10
        assert stats["important_count"] == 0
        assert stats["important_limit"] == 50
        assert stats["summary_count"] == 0
        assert stats["summary_limit"] == 20

    def test_statistics_after_operations(self):
        mem = TieredMemory(working_limit=5, important_limit=10, summary_limit=5)
        mem.add_interaction("a")
        mem.add_interaction("b")
        mem.mark_important("vuln", reason="r")
        stats = mem.get_statistics()
        assert stats["working_count"] == 2
        assert stats["important_count"] == 1
        assert stats["summary_count"] == 0

    def test_statistics_after_summarize(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"e{i}", source="s")
        stats = mem.get_statistics()
        assert stats["working_count"] == 3  # trimmed to last 3
        assert stats["summary_count"] == 1


# ============ Clear ============

class TestClear:
    """Tests for clear method."""

    def test_clear_empties_all_tiers(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"e{i}", source="s")
        mem.mark_important("vuln", reason="r")
        mem.clear()
        assert len(mem.working_memory) == 0
        assert len(mem.important_memory) == 0
        assert len(mem.summary_memory) == 0

    def test_clear_allows_reuse(self):
        mem = TieredMemory()
        mem.add_interaction("before clear")
        mem.clear()
        mem.add_interaction("after clear")
        assert len(mem.working_memory) == 1
        assert mem.working_memory[0].content == "after clear"
