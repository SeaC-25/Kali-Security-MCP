#!/usr/bin/env python3
"""
Tests for kali_mcp/core/tiered_memory.py

Covers:
- MemoryEntry dataclass: defaults, custom values, to_dict, mutable default independence
- TieredMemory initialization: default/custom limits, empty state
- Working memory: add_interaction, metadata handling, auto-summarize trigger
- Important memory: mark_important, priority-based eviction, sorting stability
- Summary memory: auto_summarize edge cases, limit enforcement, content format
- Context retrieval: layer ordering, per-layer entry limits, include_summary toggle
- Statistics: accurate counts/limits across operations
- Clear: full reset and reusability
- Edge cases: exactly-at-limit, single entry, unknown importance, empty sources
"""

import pytest
from datetime import datetime
from unittest.mock import patch

from kali_mcp.core.tiered_memory import MemoryEntry, TieredMemory


# ═══════════════════════════════════════════════
#  MemoryEntry Dataclass
# ═══════════════════════════════════════════════

class TestMemoryEntry:
    """Tests for the MemoryEntry dataclass."""

    def test_default_values(self):
        entry = MemoryEntry()
        assert entry.content == ""
        assert entry.source == ""
        assert entry.category == "interaction"
        assert entry.importance == "normal"
        assert entry.metadata == {}
        # timestamp should be a valid ISO-format string
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

    def test_to_dict_returns_all_fields(self):
        entry = MemoryEntry(content="test", source="agent1")
        d = entry.to_dict()
        assert isinstance(d, dict)
        assert d["content"] == "test"
        assert d["source"] == "agent1"
        assert d["category"] == "interaction"
        assert d["importance"] == "normal"
        assert "timestamp" in d
        assert "metadata" in d
        assert isinstance(d["metadata"], dict)

    def test_to_dict_is_plain_dict_not_reference(self):
        """to_dict should produce a new dict each call."""
        entry = MemoryEntry(content="x", metadata={"k": "v"})
        d1 = entry.to_dict()
        d2 = entry.to_dict()
        assert d1 == d2
        assert d1 is not d2

    def test_separate_metadata_instances(self):
        """Each entry should get its own metadata dict (mutable default safety)."""
        e1 = MemoryEntry()
        e2 = MemoryEntry()
        e1.metadata["key"] = "val"
        assert "key" not in e2.metadata

    def test_separate_timestamp_per_entry(self):
        """Two entries created in sequence should each have their own timestamp."""
        e1 = MemoryEntry()
        e2 = MemoryEntry()
        # Both should parse, and be strings (not the same object if created at different times)
        datetime.fromisoformat(e1.timestamp)
        datetime.fromisoformat(e2.timestamp)
        assert isinstance(e1.timestamp, str)
        assert isinstance(e2.timestamp, str)

    def test_custom_timestamp(self):
        entry = MemoryEntry(timestamp="2025-01-15T10:30:00")
        assert entry.timestamp == "2025-01-15T10:30:00"

    def test_to_dict_preserves_custom_metadata(self):
        entry = MemoryEntry(metadata={"nested": {"a": 1}, "list": [1, 2]})
        d = entry.to_dict()
        assert d["metadata"]["nested"] == {"a": 1}
        assert d["metadata"]["list"] == [1, 2]


# ═══════════════════════════════════════════════
#  TieredMemory Initialization
# ═══════════════════════════════════════════════

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

    def test_lists_are_independent_instances(self):
        """Two TieredMemory instances should not share list objects."""
        m1 = TieredMemory()
        m2 = TieredMemory()
        m1.working_memory.append(MemoryEntry(content="only in m1"))
        assert len(m2.working_memory) == 0


# ═══════════════════════════════════════════════
#  Working Memory (add_interaction)
# ═══════════════════════════════════════════════

class TestWorkingMemory:
    """Tests for add_interaction and working memory behavior."""

    def test_add_single_interaction(self):
        mem = TieredMemory()
        mem.add_interaction("scan target 10.0.0.1", source="nmap")
        assert len(mem.working_memory) == 1
        assert mem.working_memory[0].content == "scan target 10.0.0.1"
        assert mem.working_memory[0].source == "nmap"
        assert mem.working_memory[0].category == "interaction"

    def test_add_interaction_custom_category(self):
        mem = TieredMemory()
        mem.add_interaction("test", category="discovery")
        assert mem.working_memory[0].category == "discovery"

    def test_add_interaction_with_metadata(self):
        mem = TieredMemory()
        meta = {"port": 80, "state": "open"}
        mem.add_interaction("found port", source="nmap", metadata=meta)
        assert mem.working_memory[0].metadata == {"port": 80, "state": "open"}

    def test_add_interaction_none_metadata_defaults_to_empty_dict(self):
        mem = TieredMemory()
        mem.add_interaction("test")
        assert mem.working_memory[0].metadata == {}

    def test_add_interaction_explicit_none_metadata(self):
        """Passing metadata=None explicitly should produce empty dict."""
        mem = TieredMemory()
        mem.add_interaction("test", metadata=None)
        assert mem.working_memory[0].metadata == {}

    def test_entries_preserve_insertion_order(self):
        mem = TieredMemory()
        for i in range(5):
            mem.add_interaction(f"entry_{i}")
        contents = [e.content for e in mem.working_memory]
        assert contents == [f"entry_{i}" for i in range(5)]

    def test_exactly_at_limit_no_summarize(self):
        """Adding exactly working_limit entries should NOT trigger auto_summarize."""
        mem = TieredMemory(working_limit=5)
        for i in range(5):
            mem.add_interaction(f"entry {i}")
        assert len(mem.working_memory) == 5
        assert len(mem.summary_memory) == 0

    def test_one_over_limit_triggers_auto_summarize(self):
        """Adding working_limit + 1 entries triggers auto_summarize."""
        mem = TieredMemory(working_limit=5)
        for i in range(6):
            mem.add_interaction(f"entry {i}", source="tool")
        # After auto_summarize: working keeps last 3, summary gets 1
        assert len(mem.working_memory) == 3
        assert len(mem.summary_memory) == 1

    def test_auto_summarize_preserves_latest_three_entries(self):
        mem = TieredMemory(working_limit=5)
        for i in range(6):
            mem.add_interaction(f"entry {i}")
        # Before auto_summarize, entries 0-5 exist. After, last 3 kept: 3, 4, 5
        contents = [e.content for e in mem.working_memory]
        assert contents == ["entry 3", "entry 4", "entry 5"]

    def test_repeated_overflow_accumulates_summaries(self):
        """Multiple overflows should accumulate summaries."""
        mem = TieredMemory(working_limit=4)
        for i in range(12):
            mem.add_interaction(f"entry {i}", source="s")
        assert len(mem.working_memory) <= 4
        assert len(mem.summary_memory) >= 1

    def test_overflow_with_limit_4_detailed(self):
        """Trace exact behavior with working_limit=4, adding 5 entries."""
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"e{i}", source="src")
        # 5th add triggers summarize: 5 entries, to_summarize = [:-3] = first 2
        # working keeps last 3: e2, e3, e4
        assert len(mem.working_memory) == 3
        contents = [e.content for e in mem.working_memory]
        assert contents == ["e2", "e3", "e4"]
        assert len(mem.summary_memory) == 1


# ═══════════════════════════════════════════════
#  Important Memory (mark_important)
# ═══════════════════════════════════════════════

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
        assert entry.source == "sqlmap"

    def test_mark_important_custom_importance_and_category(self):
        mem = TieredMemory()
        mem.mark_important("root creds", reason="critical finding",
                           importance="critical", category="credential")
        assert mem.important_memory[0].importance == "critical"
        assert mem.important_memory[0].category == "credential"

    def test_mark_important_default_source(self):
        mem = TieredMemory()
        mem.mark_important("item", reason="r")
        assert mem.important_memory[0].source == ""

    def test_exactly_at_limit_no_eviction(self):
        mem = TieredMemory(important_limit=5)
        for i in range(5):
            mem.mark_important(f"finding {i}", reason="test")
        assert len(mem.important_memory) == 5

    def test_over_limit_evicts_lowest_importance(self):
        mem = TieredMemory(important_limit=3)
        mem.mark_important("low item", reason="r", importance="low")
        mem.mark_important("critical item", reason="r", importance="critical")
        mem.mark_important("high item", reason="r", importance="high")
        # 4th entry triggers eviction
        mem.mark_important("normal item", reason="r", importance="normal")
        assert len(mem.important_memory) == 3
        importances = [e.importance for e in mem.important_memory]
        assert "low" not in importances
        assert "critical" in importances

    def test_eviction_keeps_top_n_by_importance(self):
        """When over limit, entries are sorted by importance desc and truncated."""
        mem = TieredMemory(important_limit=2)
        mem.mark_important("A", reason="r", importance="low")
        mem.mark_important("B", reason="r", importance="normal")
        mem.mark_important("C", reason="r", importance="critical")
        assert len(mem.important_memory) == 2
        importances = [e.importance for e in mem.important_memory]
        assert importances[0] == "critical"
        assert importances[1] == "normal"

    def test_eviction_all_same_importance(self):
        """When all entries have same importance, limit is still enforced."""
        mem = TieredMemory(important_limit=3)
        for i in range(5):
            mem.mark_important(f"item {i}", reason="r", importance="high")
        assert len(mem.important_memory) == 3

    def test_eviction_with_unknown_importance_value(self):
        """Unknown importance maps to 0 in importance_order, should be evicted first."""
        mem = TieredMemory(important_limit=2)
        mem.mark_important("unknown", reason="r", importance="banana")
        mem.mark_important("high", reason="r", importance="high")
        mem.mark_important("normal", reason="r", importance="normal")
        assert len(mem.important_memory) == 2
        importances = [e.importance for e in mem.important_memory]
        # "banana" maps to 0, should be evicted
        assert "banana" not in importances
        assert "high" in importances
        assert "normal" in importances

    def test_eviction_preserves_importance_order(self):
        """After eviction, entries are sorted descending by importance."""
        mem = TieredMemory(important_limit=4)
        mem.mark_important("a", reason="r", importance="low")
        mem.mark_important("b", reason="r", importance="critical")
        mem.mark_important("c", reason="r", importance="normal")
        mem.mark_important("d", reason="r", importance="high")
        mem.mark_important("e", reason="r", importance="critical")
        # After eviction: 4 entries, sorted desc
        assert len(mem.important_memory) == 4
        order = [e.importance for e in mem.important_memory]
        expected_map = {"critical": 4, "high": 3, "normal": 2, "low": 1}
        values = [expected_map.get(imp, 0) for imp in order]
        assert values == sorted(values, reverse=True)

    def test_mark_important_does_not_affect_working_memory(self):
        mem = TieredMemory()
        mem.mark_important("item", reason="r")
        assert len(mem.working_memory) == 0

    def test_important_limit_of_one(self):
        """Edge case: important_limit=1 should always keep only highest priority."""
        mem = TieredMemory(important_limit=1)
        mem.mark_important("low", reason="r", importance="low")
        assert len(mem.important_memory) == 1
        assert mem.important_memory[0].importance == "low"
        mem.mark_important("critical", reason="r", importance="critical")
        assert len(mem.important_memory) == 1
        assert mem.important_memory[0].importance == "critical"


# ═══════════════════════════════════════════════
#  Summary Memory (auto_summarize)
# ═══════════════════════════════════════════════

class TestAutoSummarize:
    """Tests for auto_summarize behavior."""

    def test_auto_summarize_empty_working(self):
        mem = TieredMemory()
        result = mem.auto_summarize()
        assert result == ""
        assert len(mem.summary_memory) == 0

    def test_auto_summarize_one_entry_returns_empty(self):
        """Single entry: len <= 3, so to_summarize is empty."""
        mem = TieredMemory()
        mem.working_memory.append(MemoryEntry(content="solo"))
        result = mem.auto_summarize()
        assert result == ""
        assert len(mem.summary_memory) == 0
        # Working memory should remain unchanged
        assert len(mem.working_memory) == 1

    def test_auto_summarize_two_entries_returns_empty(self):
        mem = TieredMemory()
        for i in range(2):
            mem.working_memory.append(MemoryEntry(content=f"e{i}"))
        result = mem.auto_summarize()
        assert result == ""

    def test_auto_summarize_three_entries_returns_empty(self):
        """Exactly 3 entries: to_summarize = [:-3] = [], so no summary."""
        mem = TieredMemory()
        for i in range(3):
            mem.working_memory.append(MemoryEntry(content=f"e{i}"))
        result = mem.auto_summarize()
        assert result == ""
        assert len(mem.summary_memory) == 0
        assert len(mem.working_memory) == 3

    def test_auto_summarize_four_entries(self):
        """4 entries: to_summarize = [0], summary of 1 entry. Keeps last 3."""
        mem = TieredMemory(working_limit=100)
        for i in range(4):
            mem.working_memory.append(
                MemoryEntry(content=f"e{i}", source="src", category="cat")
            )
        result = mem.auto_summarize()
        assert result != ""
        assert "1" in result  # 1 entry summarized
        assert len(mem.working_memory) == 3
        assert len(mem.summary_memory) == 1
        contents = [e.content for e in mem.working_memory]
        assert contents == ["e1", "e2", "e3"]

    def test_auto_summarize_produces_expected_format(self):
        """Summary string should contain timestamp range, count, sources, categories."""
        mem = TieredMemory(working_limit=100)
        for i in range(6):
            mem.working_memory.append(
                MemoryEntry(content=f"entry {i}", source="agent1", category="interaction")
            )
        summary = mem.auto_summarize()
        assert len(summary) > 0
        # Should contain count of summarized entries (6 - 3 = 3)
        assert "3" in summary
        assert "agent1" in summary
        assert "interaction" in summary
        # Should contain timestamp range marker
        assert "~" in summary

    def test_auto_summarize_multiple_sources_and_categories(self):
        mem = TieredMemory(working_limit=100)
        mem.working_memory.append(MemoryEntry(content="a", source="nmap", category="scan"))
        mem.working_memory.append(MemoryEntry(content="b", source="gobuster", category="discovery"))
        mem.working_memory.append(MemoryEntry(content="c", source="nmap", category="scan"))
        mem.working_memory.append(MemoryEntry(content="d", source="", category="interaction"))
        mem.working_memory.append(MemoryEntry(content="e"))
        mem.working_memory.append(MemoryEntry(content="f"))
        summary = mem.auto_summarize()
        # Sources "nmap" and "gobuster" should appear (empty source excluded from set)
        assert "nmap" in summary or "gobuster" in summary

    def test_auto_summarize_no_sources_shows_unknown(self):
        """When all entries have empty source, summary shows 'unknown'."""
        mem = TieredMemory(working_limit=100)
        for i in range(5):
            mem.working_memory.append(MemoryEntry(content=f"e{i}", source=""))
        summary = mem.auto_summarize()
        assert "unknown" in summary

    def test_auto_summarize_trims_working_to_last_3(self):
        mem = TieredMemory(working_limit=100)
        for i in range(10):
            mem.working_memory.append(MemoryEntry(content=f"entry {i}"))
        mem.auto_summarize()
        assert len(mem.working_memory) == 3
        assert mem.working_memory[-1].content == "entry 9"
        assert mem.working_memory[0].content == "entry 7"

    def test_summary_limit_enforcement(self):
        mem = TieredMemory(working_limit=100, summary_limit=3)
        for batch in range(5):
            # Reset working for fresh summarize
            mem.working_memory = []
            for i in range(5):
                mem.working_memory.append(
                    MemoryEntry(content=f"b{batch}_e{i}", source="s")
                )
            mem.auto_summarize()
        assert len(mem.summary_memory) <= 3

    def test_summary_keeps_latest_when_over_limit(self):
        mem = TieredMemory(working_limit=100, summary_limit=2)
        summaries_generated = []
        for batch in range(4):
            mem.working_memory = []
            for i in range(5):
                mem.working_memory.append(
                    MemoryEntry(content=f"b{batch}_e{i}", source=f"src{batch}")
                )
            s = mem.auto_summarize()
            summaries_generated.append(s)
        # Should keep the latest 2 summaries
        assert len(mem.summary_memory) == 2
        # The kept summaries should be the last two generated
        assert mem.summary_memory[-1] == summaries_generated[-1]
        assert mem.summary_memory[-2] == summaries_generated[-2]

    def test_summary_limit_of_one(self):
        mem = TieredMemory(working_limit=100, summary_limit=1)
        for batch in range(3):
            mem.working_memory = []
            for i in range(5):
                mem.working_memory.append(MemoryEntry(content=f"b{batch}", source="s"))
            mem.auto_summarize()
        assert len(mem.summary_memory) == 1

    def test_auto_summarize_return_value_matches_stored(self):
        """The returned summary string should be the same as what's stored."""
        mem = TieredMemory(working_limit=100)
        for i in range(5):
            mem.working_memory.append(MemoryEntry(content=f"e{i}", source="s"))
        result = mem.auto_summarize()
        assert result == mem.summary_memory[-1]


# ═══════════════════════════════════════════════
#  Context Retrieval (get_context)
# ═══════════════════════════════════════════════

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

    def test_context_with_summary_only(self):
        """Manually populate summary_memory to test isolation."""
        mem = TieredMemory()
        mem.summary_memory.append("a summary string")
        ctx = mem.get_context()
        assert len(ctx) == 1
        assert ctx[0]["layer"] == "summary"

    def test_context_with_all_three_tiers(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"entry {i}", source="s")
        mem.mark_important("critical vuln", reason="test")
        ctx = mem.get_context()
        layers = [c["layer"] for c in ctx]
        assert "summary" in layers
        assert "important" in layers
        assert "working" in layers

    def test_context_order_is_summary_important_working(self):
        """Layers should appear in order: summary → important → working."""
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
        assert "working" in layers

    def test_context_exclude_summary_still_shows_important(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"entry {i}", source="s")
        mem.mark_important("item", reason="r")
        ctx = mem.get_context(include_summary=False)
        layers = [c["layer"] for c in ctx]
        assert "summary" not in layers
        assert "important" in layers
        assert "working" in layers

    def test_context_limits_important_entries_to_10(self):
        mem = TieredMemory(important_limit=50)
        for i in range(20):
            mem.mark_important(f"item {i}", reason="r")
        ctx = mem.get_context()
        important_layer = [c for c in ctx if c["layer"] == "important"][0]
        assert len(important_layer["entries"]) == 10

    def test_context_important_entries_are_last_10(self):
        """get_context uses [-10:] so it should return the last 10 entries."""
        mem = TieredMemory(important_limit=50)
        for i in range(15):
            mem.mark_important(f"item {i}", reason="r")
        ctx = mem.get_context()
        important_layer = [c for c in ctx if c["layer"] == "important"][0]
        # Should contain items 5-14 (last 10)
        contents = [e["content"] for e in important_layer["entries"]]
        assert "item 5" in contents
        assert "item 14" in contents

    def test_context_limits_summary_entries_to_5(self):
        mem = TieredMemory(working_limit=100, summary_limit=20)
        for batch in range(8):
            mem.working_memory = []
            for i in range(5):
                mem.working_memory.append(
                    MemoryEntry(content=f"b{batch}_e{i}", source="s")
                )
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
        assert "source" in entry
        assert "timestamp" in entry

    def test_context_important_entries_are_dicts(self):
        mem = TieredMemory()
        mem.mark_important("finding", reason="r")
        ctx = mem.get_context()
        important = ctx[0]
        entry = important["entries"][0]
        assert isinstance(entry, dict)
        assert entry["content"] == "finding"
        assert entry["metadata"] == {"reason": "r"}

    def test_context_summary_entries_are_strings(self):
        """Summary entries are raw strings, not dicts."""
        mem = TieredMemory()
        mem.summary_memory.append("summary text")
        ctx = mem.get_context()
        assert ctx[0]["layer"] == "summary"
        assert isinstance(ctx[0]["entries"][0], str)

    def test_context_with_fewer_than_5_summaries(self):
        """When summary count < 5, all summaries should be returned."""
        mem = TieredMemory()
        mem.summary_memory = ["s1", "s2", "s3"]
        ctx = mem.get_context()
        summary_layer = ctx[0]
        assert len(summary_layer["entries"]) == 3

    def test_context_with_fewer_than_10_important(self):
        mem = TieredMemory()
        for i in range(5):
            mem.mark_important(f"item {i}", reason="r")
        ctx = mem.get_context()
        important_layer = ctx[0]
        assert len(important_layer["entries"]) == 5


# ═══════════════════════════════════════════════
#  Statistics (get_statistics)
# ═══════════════════════════════════════════════

class TestStatistics:
    """Tests for get_statistics."""

    def test_empty_statistics(self):
        mem = TieredMemory(working_limit=10, important_limit=50, summary_limit=20)
        stats = mem.get_statistics()
        assert stats == {
            "working_count": 0,
            "working_limit": 10,
            "important_count": 0,
            "important_limit": 50,
            "summary_count": 0,
            "summary_limit": 20,
        }

    def test_statistics_after_adding_interactions(self):
        mem = TieredMemory(working_limit=5, important_limit=10, summary_limit=5)
        mem.add_interaction("a")
        mem.add_interaction("b")
        stats = mem.get_statistics()
        assert stats["working_count"] == 2
        assert stats["important_count"] == 0
        assert stats["summary_count"] == 0

    def test_statistics_after_marking_important(self):
        mem = TieredMemory()
        mem.mark_important("vuln", reason="r")
        mem.mark_important("cred", reason="r")
        stats = mem.get_statistics()
        assert stats["important_count"] == 2

    def test_statistics_after_auto_summarize(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"e{i}", source="s")
        stats = mem.get_statistics()
        assert stats["working_count"] == 3  # trimmed to last 3
        assert stats["summary_count"] == 1

    def test_statistics_reflects_limits(self):
        mem = TieredMemory(working_limit=7, important_limit=33, summary_limit=11)
        stats = mem.get_statistics()
        assert stats["working_limit"] == 7
        assert stats["important_limit"] == 33
        assert stats["summary_limit"] == 11

    def test_statistics_after_clear(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"e{i}", source="s")
        mem.mark_important("x", reason="r")
        mem.clear()
        stats = mem.get_statistics()
        assert stats["working_count"] == 0
        assert stats["important_count"] == 0
        assert stats["summary_count"] == 0
        # Limits should remain unchanged after clear
        assert stats["working_limit"] == 4


# ═══════════════════════════════════════════════
#  Clear
# ═══════════════════════════════════════════════

class TestClear:
    """Tests for the clear method."""

    def test_clear_empties_all_tiers(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"e{i}", source="s")
        mem.mark_important("vuln", reason="r")
        # At this point we have data in all 3 tiers
        assert len(mem.working_memory) > 0
        assert len(mem.important_memory) > 0
        assert len(mem.summary_memory) > 0
        mem.clear()
        assert len(mem.working_memory) == 0
        assert len(mem.important_memory) == 0
        assert len(mem.summary_memory) == 0

    def test_clear_on_empty_is_safe(self):
        mem = TieredMemory()
        mem.clear()  # should not raise
        assert len(mem.working_memory) == 0
        assert len(mem.important_memory) == 0
        assert len(mem.summary_memory) == 0

    def test_clear_allows_reuse(self):
        mem = TieredMemory()
        mem.add_interaction("before clear")
        mem.mark_important("finding", reason="r")
        mem.clear()
        mem.add_interaction("after clear")
        mem.mark_important("new finding", reason="r2")
        assert len(mem.working_memory) == 1
        assert mem.working_memory[0].content == "after clear"
        assert len(mem.important_memory) == 1
        assert mem.important_memory[0].content == "new finding"

    def test_clear_does_not_affect_limits(self):
        mem = TieredMemory(working_limit=7, important_limit=33, summary_limit=11)
        mem.clear()
        assert mem._working_limit == 7
        assert mem._important_limit == 33
        assert mem._summary_limit == 11


# ═══════════════════════════════════════════════
#  Integration / Cross-tier Scenarios
# ═══════════════════════════════════════════════

class TestIntegration:
    """Tests that exercise multiple tiers together."""

    def test_full_lifecycle(self):
        """Simulate a realistic sequence: interactions → overflow → mark important → context."""
        mem = TieredMemory(working_limit=5, important_limit=3, summary_limit=2)

        # Phase 1: Add interactions until overflow
        for i in range(6):
            mem.add_interaction(f"scan step {i}", source="nmap", category="scan")

        # Should have triggered auto_summarize
        assert len(mem.summary_memory) >= 1
        assert len(mem.working_memory) == 3

        # Phase 2: Mark important findings
        mem.mark_important("SQLi at /login", reason="injection point", importance="critical")
        mem.mark_important("open port 22", reason="SSH access", importance="normal")

        # Phase 3: Get context
        ctx = mem.get_context()
        layers = {c["layer"] for c in ctx}
        assert "summary" in layers
        assert "important" in layers
        assert "working" in layers

        # Phase 4: Statistics should reflect current state
        stats = mem.get_statistics()
        assert stats["working_count"] == 3
        assert stats["important_count"] == 2
        assert stats["summary_count"] >= 1

    def test_add_interaction_does_not_affect_important(self):
        mem = TieredMemory()
        mem.add_interaction("interaction data")
        assert len(mem.important_memory) == 0

    def test_mark_important_does_not_affect_working(self):
        mem = TieredMemory()
        mem.mark_important("critical finding", reason="r")
        assert len(mem.working_memory) == 0

    def test_auto_summarize_does_not_affect_important(self):
        mem = TieredMemory(working_limit=4)
        mem.mark_important("pre-existing", reason="r")
        for i in range(5):
            mem.add_interaction(f"e{i}", source="s")
        # auto_summarize was triggered; important_memory should be untouched
        assert len(mem.important_memory) == 1
        assert mem.important_memory[0].content == "pre-existing"

    def test_large_scale_operations(self):
        """Stress test with many operations to ensure no crashes or unexpected state."""
        mem = TieredMemory(working_limit=5, important_limit=10, summary_limit=5)
        for i in range(100):
            mem.add_interaction(f"interaction {i}", source=f"tool{i % 3}")
        for i in range(30):
            importance = ["critical", "high", "normal", "low"][i % 4]
            mem.mark_important(f"finding {i}", reason=f"r{i}", importance=importance)

        assert len(mem.working_memory) <= 5
        assert len(mem.important_memory) <= 10
        assert len(mem.summary_memory) <= 5

        stats = mem.get_statistics()
        assert stats["working_count"] == len(mem.working_memory)
        assert stats["important_count"] == len(mem.important_memory)
        assert stats["summary_count"] == len(mem.summary_memory)

        ctx = mem.get_context()
        assert len(ctx) >= 1

    def test_context_after_clear_is_empty(self):
        mem = TieredMemory(working_limit=4)
        for i in range(5):
            mem.add_interaction(f"e{i}", source="s")
        mem.mark_important("item", reason="r")
        mem.clear()
        ctx = mem.get_context()
        assert ctx == []
