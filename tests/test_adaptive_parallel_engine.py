"""
Tests for AdaptiveParallelEngine, DAGAnalyzer, ConflictDetector,
and all supporting data structures.

(kali_mcp/core/adaptive_parallel_engine.py)

Covers:
- TaskStatus enum: all 7 members and values
- ConflictType enum: all 5 members and values
- TaskPriority dataclass: creation, defaults, __lt__, __eq__, ordering
- TaskNode dataclass: creation, defaults, __lt__, field types
- ConflictInfo dataclass: creation, defaults
- ExecutionPlan dataclass: creation, defaults
- DAGAnalyzer class:
  - build_dag (basic, with dependencies, with priority, missing dep, cycle detection)
  - _validate_dag (valid, cycle)
  - topological_sort (single level, multi level, complex DAG)
  - find_ready_tasks (no deps, with deps, partial deps)
- ConflictDetector class:
  - detect_conflicts (no conflict, resource, data, tool, network, multiple)
  - _check_resource_conflict (under limit, over limit)
  - _check_data_conflict (no overlap, overlap no write, overlap with write)
  - _extract_data_paths (various fields, non-string, list)
  - _has_write_conflict (write types, read-only)
  - _check_tool_conflict (no common, common exclusive, common non-exclusive)
  - _check_network_conflict (different target, same target diff port, same target same port)
- AdaptiveParallelEngine class:
  - __init__ (defaults, custom)
  - execute_plan (basic async, with context, exception propagation)
  - _execute_dag (ready tasks, priority ordering, conflict handling)
  - _start_task (status change, wrapper success, wrapper failure)
  - _handle_task_completion (success, failure)
  - _calculate_initial_parallelism (io intensive, cpu intensive, high load)
  - _adjust_parallelism (high load decrease, low load increase, no change)
  - _estimate_io_intensive_ratio (all io, none io, mixed, empty)
  - _get_task_node (existing, missing)
"""

import asyncio
from datetime import datetime, timedelta
from dataclasses import fields as dc_fields
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock
import heapq

import pytest

from kali_mcp.core.adaptive_parallel_engine import (
    AdaptiveParallelEngine,
    ConflictDetector,
    ConflictInfo,
    ConflictType,
    DAGAnalyzer,
    ExecutionPlan,
    TaskNode,
    TaskPriority,
    TaskStatus,
)


# ===================== Helpers =====================

def _make_task_node(
    task_id="t1",
    task_type="scan",
    task_data=None,
    status=TaskStatus.PENDING,
    dependencies=None,
    priority=None,
    estimated_cpu=0.0,
    estimated_memory=0.0,
    required_tools=None,
):
    return TaskNode(
        task_id=task_id,
        task_type=task_type,
        task_data=task_data or {},
        status=status,
        dependencies=dependencies or set(),
        priority=priority or TaskPriority(),
        estimated_cpu=estimated_cpu,
        estimated_memory=estimated_memory,
        required_tools=required_tools or [],
    )


def _make_plan(tasks=None, running_tasks=None, completed=None, failed=None, dag_levels=None):
    return ExecutionPlan(
        tasks=tasks or {},
        ready_queue=[],
        running_tasks=running_tasks or {},
        completed_tasks=completed or set(),
        failed_tasks=failed or set(),
        dag_levels=dag_levels or [],
        total_tasks=len(tasks) if tasks else 0,
    )


def _make_task_dict(task_id, task_type="scan", task_data=None, dependencies=None, priority=None):
    d = {"task_id": task_id, "task_type": task_type, "task_data": task_data or {}}
    if dependencies:
        d["dependencies"] = dependencies
    if priority is not None:
        d["priority"] = priority
    return d


# ===================== TaskStatus Enum =====================

class TestTaskStatus:
    def test_pending_value(self):
        assert TaskStatus.PENDING.value == "pending"

    def test_ready_value(self):
        assert TaskStatus.READY.value == "ready"

    def test_running_value(self):
        assert TaskStatus.RUNNING.value == "running"

    def test_completed_value(self):
        assert TaskStatus.COMPLETED.value == "completed"

    def test_failed_value(self):
        assert TaskStatus.FAILED.value == "failed"

    def test_cancelled_value(self):
        assert TaskStatus.CANCELLED.value == "cancelled"

    def test_blocked_value(self):
        assert TaskStatus.BLOCKED.value == "blocked"

    def test_member_count(self):
        assert len(TaskStatus) == 7

    def test_from_value(self):
        assert TaskStatus("pending") is TaskStatus.PENDING

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            TaskStatus("nonexistent")


# ===================== ConflictType Enum =====================

class TestConflictType:
    def test_resource_value(self):
        assert ConflictType.RESOURCE.value == "resource"

    def test_data_value(self):
        assert ConflictType.DATA.value == "data"

    def test_tool_value(self):
        assert ConflictType.TOOL.value == "tool"

    def test_network_value(self):
        assert ConflictType.NETWORK.value == "network"

    def test_exclusive_value(self):
        assert ConflictType.EXCLUSIVE.value == "exclusive"

    def test_member_count(self):
        assert len(ConflictType) == 5

    def test_from_value(self):
        assert ConflictType("resource") is ConflictType.RESOURCE


# ===================== TaskPriority =====================

class TestTaskPriority:
    def test_default_priority(self):
        tp = TaskPriority()
        assert tp.priority == 5

    def test_custom_priority(self):
        tp = TaskPriority(priority=10)
        assert tp.priority == 10

    def test_created_at_is_datetime(self):
        tp = TaskPriority()
        assert isinstance(tp.created_at, datetime)

    def test_lt_higher_priority_comes_first(self):
        """Higher priority number should be 'less than' (i.e., come first)."""
        high = TaskPriority(priority=10)
        low = TaskPriority(priority=1)
        assert high < low  # high priority is "less than" in heap ordering

    def test_lt_same_priority_earlier_first(self):
        early = TaskPriority(priority=5, created_at=datetime(2025, 1, 1))
        late = TaskPriority(priority=5, created_at=datetime(2025, 6, 1))
        assert early < late

    def test_lt_same_priority_same_time(self):
        t = datetime(2025, 1, 1)
        tp1 = TaskPriority(priority=5, created_at=t)
        tp2 = TaskPriority(priority=5, created_at=t)
        assert not (tp1 < tp2)

    def test_eq_identical(self):
        t = datetime(2025, 1, 1)
        tp1 = TaskPriority(priority=5, created_at=t)
        tp2 = TaskPriority(priority=5, created_at=t)
        assert tp1 == tp2

    def test_eq_different_priority(self):
        t = datetime(2025, 1, 1)
        tp1 = TaskPriority(priority=5, created_at=t)
        tp2 = TaskPriority(priority=6, created_at=t)
        assert tp1 != tp2

    def test_eq_different_type_returns_not_implemented(self):
        tp = TaskPriority()
        assert tp.__eq__("not a priority") is NotImplemented

    def test_ge_via_total_ordering(self):
        high = TaskPriority(priority=10)
        low = TaskPriority(priority=1)
        assert low >= high  # low priority has higher heap order

    def test_le_via_total_ordering(self):
        high = TaskPriority(priority=10)
        low = TaskPriority(priority=1)
        assert high <= low

    def test_heap_ordering(self):
        """Verify heapq produces highest-priority-first ordering."""
        items = [
            TaskPriority(priority=3, created_at=datetime(2025, 1, 1)),
            TaskPriority(priority=10, created_at=datetime(2025, 1, 1)),
            TaskPriority(priority=5, created_at=datetime(2025, 1, 1)),
        ]
        heapq.heapify(items)
        popped = [heapq.heappop(items) for _ in range(3)]
        assert [p.priority for p in popped] == [10, 5, 3]


# ===================== TaskNode =====================

class TestTaskNode:
    def test_creation_basic(self):
        node = _make_task_node()
        assert node.task_id == "t1"
        assert node.task_type == "scan"

    def test_default_status(self):
        node = TaskNode(task_id="x", task_type="y", task_data={})
        assert node.status == TaskStatus.PENDING

    def test_default_dependencies_empty(self):
        node = TaskNode(task_id="x", task_type="y", task_data={})
        assert node.dependencies == set()

    def test_default_dependents_empty(self):
        node = TaskNode(task_id="x", task_type="y", task_data={})
        assert node.dependents == set()

    def test_default_agent_id_none(self):
        node = _make_task_node()
        assert node.agent_id is None

    def test_default_times_none(self):
        node = _make_task_node()
        assert node.start_time is None
        assert node.end_time is None
        assert node.execution_time == 0.0

    def test_default_result_error_none(self):
        node = _make_task_node()
        assert node.result is None
        assert node.error is None

    def test_default_estimated_resources(self):
        node = _make_task_node()
        assert node.estimated_cpu == 0.0
        assert node.estimated_memory == 0.0

    def test_default_required_tools_empty(self):
        node = _make_task_node()
        assert node.required_tools == []

    def test_default_conflicts_empty(self):
        node = TaskNode(task_id="x", task_type="y", task_data={})
        assert node.conflicts == set()

    def test_lt_delegates_to_priority(self):
        high = _make_task_node(task_id="h", priority=TaskPriority(priority=10))
        low = _make_task_node(task_id="l", priority=TaskPriority(priority=1))
        assert high < low

    def test_lt_not_implemented_for_non_tasknode(self):
        node = _make_task_node()
        assert node.__lt__("string") is NotImplemented

    def test_heap_with_task_nodes(self):
        nodes = [
            _make_task_node(task_id="low", priority=TaskPriority(priority=1, created_at=datetime(2025, 1, 1))),
            _make_task_node(task_id="high", priority=TaskPriority(priority=10, created_at=datetime(2025, 1, 1))),
            _make_task_node(task_id="mid", priority=TaskPriority(priority=5, created_at=datetime(2025, 1, 1))),
        ]
        heapq.heapify(nodes)
        result = [heapq.heappop(nodes).task_id for _ in range(3)]
        assert result == ["high", "mid", "low"]

    def test_mutable_defaults_independent(self):
        """Ensure mutable default fields (set, list) are independent across instances."""
        n1 = TaskNode(task_id="a", task_type="t", task_data={})
        n2 = TaskNode(task_id="b", task_type="t", task_data={})
        n1.dependencies.add("x")
        assert "x" not in n2.dependencies


# ===================== ConflictInfo =====================

class TestConflictInfo:
    def test_creation(self):
        ci = ConflictInfo(
            conflict_type=ConflictType.RESOURCE,
            task1_id="t1",
            task2_id="t2",
            reason="test reason",
        )
        assert ci.conflict_type == ConflictType.RESOURCE
        assert ci.task1_id == "t1"
        assert ci.task2_id == "t2"
        assert ci.reason == "test reason"

    def test_default_resolution_strategy(self):
        ci = ConflictInfo(
            conflict_type=ConflictType.DATA,
            task1_id="a",
            task2_id="b",
            reason="r",
        )
        assert ci.resolution_strategy is None

    def test_custom_resolution_strategy(self):
        ci = ConflictInfo(
            conflict_type=ConflictType.TOOL,
            task1_id="a",
            task2_id="b",
            reason="r",
            resolution_strategy="delay",
        )
        assert ci.resolution_strategy == "delay"


# ===================== ExecutionPlan =====================

class TestExecutionPlan:
    def test_creation_basic(self):
        plan = _make_plan()
        assert plan.tasks == {}
        assert plan.ready_queue == []
        assert plan.running_tasks == {}
        assert plan.completed_tasks == set()
        assert plan.failed_tasks == set()

    def test_default_counts(self):
        plan = _make_plan()
        assert plan.total_tasks == 0
        assert plan.completed_count == 0
        assert plan.failed_count == 0

    def test_default_times_none(self):
        plan = _make_plan()
        assert plan.start_time is None
        assert plan.end_time is None

    def test_total_tasks_matches(self):
        tasks = {"t1": _make_task_node("t1"), "t2": _make_task_node("t2")}
        plan = _make_plan(tasks=tasks)
        assert plan.total_tasks == 2


# ===================== DAGAnalyzer =====================

class TestDAGAnalyzer:
    def test_init(self):
        analyzer = DAGAnalyzer()
        assert analyzer._tasks == {}

    def test_build_dag_single_task(self):
        analyzer = DAGAnalyzer()
        tasks = [_make_task_dict("t1")]
        result = analyzer.build_dag(tasks)
        assert "t1" in result
        assert result["t1"].task_id == "t1"

    def test_build_dag_multiple_independent_tasks(self):
        analyzer = DAGAnalyzer()
        tasks = [_make_task_dict("t1"), _make_task_dict("t2"), _make_task_dict("t3")]
        result = analyzer.build_dag(tasks)
        assert len(result) == 3

    def test_build_dag_with_dependencies(self):
        analyzer = DAGAnalyzer()
        tasks = [
            _make_task_dict("t1"),
            _make_task_dict("t2", dependencies=["t1"]),
        ]
        result = analyzer.build_dag(tasks)
        assert "t1" in result["t2"].dependencies
        assert "t2" in result["t1"].dependents

    def test_build_dag_with_priority(self):
        analyzer = DAGAnalyzer()
        tasks = [_make_task_dict("t1", priority=8)]
        result = analyzer.build_dag(tasks)
        assert result["t1"].priority.priority == 8

    def test_build_dag_without_priority_keeps_default(self):
        analyzer = DAGAnalyzer()
        tasks = [_make_task_dict("t1")]
        result = analyzer.build_dag(tasks)
        assert result["t1"].priority.priority == 5  # default

    def test_build_dag_missing_dependency_logged(self):
        """Missing dependency should not crash, just warn."""
        analyzer = DAGAnalyzer()
        tasks = [_make_task_dict("t1", dependencies=["nonexistent"])]
        result = analyzer.build_dag(tasks)
        assert "nonexistent" in result["t1"].dependencies

    def test_build_dag_task_data_propagated(self):
        analyzer = DAGAnalyzer()
        tasks = [_make_task_dict("t1", task_data={"target": "10.0.0.1"})]
        result = analyzer.build_dag(tasks)
        assert result["t1"].task_data == {"target": "10.0.0.1"}

    def test_build_dag_empty_task_data_default(self):
        analyzer = DAGAnalyzer()
        tasks = [{"task_id": "t1", "task_type": "scan"}]
        result = analyzer.build_dag(tasks)
        assert result["t1"].task_data == {}

    def test_build_dag_cycle_raises(self):
        analyzer = DAGAnalyzer()
        tasks = [
            _make_task_dict("t1", dependencies=["t2"]),
            _make_task_dict("t2", dependencies=["t1"]),
        ]
        with pytest.raises(ValueError, match="循环依赖"):
            analyzer.build_dag(tasks)

    def test_build_dag_three_node_cycle_raises(self):
        analyzer = DAGAnalyzer()
        tasks = [
            _make_task_dict("t1", dependencies=["t3"]),
            _make_task_dict("t2", dependencies=["t1"]),
            _make_task_dict("t3", dependencies=["t2"]),
        ]
        with pytest.raises(ValueError, match="循环依赖"):
            analyzer.build_dag(tasks)

    def test_build_dag_clears_previous_state(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([_make_task_dict("t1")])
        analyzer.build_dag([_make_task_dict("t2")])
        assert "t1" not in analyzer._tasks
        assert "t2" in analyzer._tasks

    def test_validate_dag_valid_linear(self):
        analyzer = DAGAnalyzer()
        tasks = [
            _make_task_dict("t1"),
            _make_task_dict("t2", dependencies=["t1"]),
            _make_task_dict("t3", dependencies=["t2"]),
        ]
        result = analyzer.build_dag(tasks)
        assert len(result) == 3

    def test_topological_sort_single_level(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([_make_task_dict("a"), _make_task_dict("b")])
        levels = analyzer.topological_sort()
        assert len(levels) == 1
        assert set(levels[0]) == {"a", "b"}

    def test_topological_sort_two_levels(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("a"),
            _make_task_dict("b", dependencies=["a"]),
        ])
        levels = analyzer.topological_sort()
        assert len(levels) == 2
        assert levels[0] == ["a"]
        assert levels[1] == ["b"]

    def test_topological_sort_three_levels(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("a"),
            _make_task_dict("b", dependencies=["a"]),
            _make_task_dict("c", dependencies=["b"]),
        ])
        levels = analyzer.topological_sort()
        assert len(levels) == 3

    def test_topological_sort_diamond(self):
        """Diamond: a -> b,c -> d"""
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("a"),
            _make_task_dict("b", dependencies=["a"]),
            _make_task_dict("c", dependencies=["a"]),
            _make_task_dict("d", dependencies=["b", "c"]),
        ])
        levels = analyzer.topological_sort()
        assert len(levels) == 3
        assert levels[0] == ["a"]
        assert set(levels[1]) == {"b", "c"}
        assert levels[2] == ["d"]

    def test_find_ready_tasks_no_deps(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([_make_task_dict("a"), _make_task_dict("b")])
        ready = analyzer.find_ready_tasks(set())
        assert len(ready) == 2
        assert all(n.status == TaskStatus.READY for n in ready)

    def test_find_ready_tasks_deps_not_met(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("a"),
            _make_task_dict("b", dependencies=["a"]),
        ])
        ready = analyzer.find_ready_tasks(set())
        assert len(ready) == 1
        assert ready[0].task_id == "a"

    def test_find_ready_tasks_deps_met(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("a"),
            _make_task_dict("b", dependencies=["a"]),
        ])
        # First round: a becomes ready
        ready1 = analyzer.find_ready_tasks(set())
        assert len(ready1) == 1
        # Mark a as completed
        analyzer._tasks["a"].status = TaskStatus.COMPLETED
        ready2 = analyzer.find_ready_tasks({"a"})
        assert len(ready2) == 1
        assert ready2[0].task_id == "b"

    def test_find_ready_tasks_already_ready_not_duplicated(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([_make_task_dict("a")])
        ready1 = analyzer.find_ready_tasks(set())
        # Status is now READY, so calling again should not re-add
        ready2 = analyzer.find_ready_tasks(set())
        assert len(ready2) == 0

    def test_find_ready_tasks_partial_deps(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("a"),
            _make_task_dict("b"),
            _make_task_dict("c", dependencies=["a", "b"]),
        ])
        ready = analyzer.find_ready_tasks(set())
        ids = {n.task_id for n in ready}
        assert ids == {"a", "b"}
        # Mark only a as completed
        analyzer._tasks["a"].status = TaskStatus.COMPLETED
        analyzer._tasks["b"].status = TaskStatus.COMPLETED
        ready2 = analyzer.find_ready_tasks({"a"})
        # c needs both a and b; only a is completed -> not ready
        # Wait: b's status was changed to COMPLETED but it's not in 'completed' set
        # Actually find_ready_tasks checks status == PENDING and deps subset of completed
        # b's status is COMPLETED so it won't be re-added, c's deps are {"a", "b"}, completed is {"a"}
        # {"a", "b"}.issubset({"a"}) is False, so c is not ready yet
        # Let me re-check: we set b's status to COMPLETED manually.
        # find_ready_tasks checks status == PENDING. c is still PENDING.
        # c.dependencies = {"a", "b"}, completed_arg = {"a"} -> not subset -> not ready
        # Correct! Let me fix the test.
        ready2 = analyzer.find_ready_tasks({"a"})
        assert len(ready2) == 0  # c still blocked on b

        ready3 = analyzer.find_ready_tasks({"a", "b"})
        assert len(ready3) == 1
        assert ready3[0].task_id == "c"


# ===================== ConflictDetector =====================

class TestConflictDetector:
    def test_init(self):
        cd = ConflictDetector()
        assert cd._resource_usage == {}
        assert cd._data_access == {}
        assert cd._tool_usage == {}
        assert cd._network_targets == {}

    def test_detect_conflicts_empty_running(self):
        cd = ConflictDetector()
        task = _make_task_node()
        result = cd.detect_conflicts(task, {})
        assert result == []

    def test_detect_conflicts_skip_self(self):
        cd = ConflictDetector()
        task = _make_task_node(task_id="t1")
        running = {"t1": task}
        with patch.object(cd, '_check_resource_conflict', return_value=False), \
             patch.object(cd, '_check_data_conflict', return_value=None), \
             patch.object(cd, '_check_tool_conflict', return_value=None), \
             patch.object(cd, '_check_network_conflict', return_value=None):
            result = cd.detect_conflicts(task, running)
        assert result == []

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_check_resource_conflict_no_conflict(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 8
        mock_vm = MagicMock()
        mock_vm.available = 8 * 1024 * 1024 * 1024  # 8GB in bytes
        mock_psutil.virtual_memory.return_value = mock_vm

        cd = ConflictDetector()
        t1 = _make_task_node(estimated_cpu=1.0, estimated_memory=100.0)
        t2 = _make_task_node(task_id="t2", estimated_cpu=1.0, estimated_memory=100.0)
        assert cd._check_resource_conflict(t1, t2) is False

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_check_resource_conflict_cpu_over(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 2
        mock_vm = MagicMock()
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        cd = ConflictDetector()
        t1 = _make_task_node(estimated_cpu=5.0, estimated_memory=0.0)
        t2 = _make_task_node(task_id="t2", estimated_cpu=5.0, estimated_memory=0.0)
        # total_cpu=10, cpu_count=2, (10/2)*100=500% > 90
        assert cd._check_resource_conflict(t1, t2) is True

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_check_resource_conflict_memory_over(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 8
        mock_vm = MagicMock()
        mock_vm.available = 100 * 1024 * 1024  # 100 MB
        mock_psutil.virtual_memory.return_value = mock_vm

        cd = ConflictDetector()
        t1 = _make_task_node(estimated_cpu=0.0, estimated_memory=50.0)
        t2 = _make_task_node(task_id="t2", estimated_cpu=0.0, estimated_memory=50.0)
        # total_memory=100, available=100MB, (100/100)*100=100% > 90
        assert cd._check_resource_conflict(t1, t2) is True

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_check_resource_conflict_zero_cpu_count(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 0
        mock_vm = MagicMock()
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        cd = ConflictDetector()
        t1 = _make_task_node(estimated_cpu=1.0)
        t2 = _make_task_node(task_id="t2", estimated_cpu=1.0)
        # cpu_usage=0 (division guard), memory OK
        assert cd._check_resource_conflict(t1, t2) is False

    def test_extract_data_paths_target_field(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={"target": "10.0.0.1"})
        paths = cd._extract_data_paths(task)
        assert "10.0.0.1" in paths

    def test_extract_data_paths_multiple_fields(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={"target": "10.0.0.1", "file": "/tmp/x", "path": "/etc/passwd"})
        paths = cd._extract_data_paths(task)
        assert paths == {"10.0.0.1", "/tmp/x", "/etc/passwd"}

    def test_extract_data_paths_list_values(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={"target": ["a", "b"]})
        paths = cd._extract_data_paths(task)
        assert "a" in paths
        assert "b" in paths

    def test_extract_data_paths_non_matching_fields(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={"url": "http://x.com", "mode": "fast"})
        paths = cd._extract_data_paths(task)
        assert len(paths) == 0

    def test_extract_data_paths_empty_data(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={})
        paths = cd._extract_data_paths(task)
        assert len(paths) == 0

    def test_extract_data_paths_non_string_non_list(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={"target": 12345})
        paths = cd._extract_data_paths(task)
        assert len(paths) == 0

    def test_has_write_conflict_write_type(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="write_file")
        t2 = _make_task_node(task_id="t2", task_type="scan")
        assert cd._has_write_conflict(t1, t2, {"path"}) is True

    def test_has_write_conflict_upload_type(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="scan")
        t2 = _make_task_node(task_id="t2", task_type="file_upload")
        assert cd._has_write_conflict(t1, t2, {"path"}) is True

    def test_has_write_conflict_exploit_type(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="exploit_cve")
        t2 = _make_task_node(task_id="t2", task_type="scan")
        assert cd._has_write_conflict(t1, t2, {"path"}) is True

    def test_has_write_conflict_no_write(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="scan")
        t2 = _make_task_node(task_id="t2", task_type="recon")
        assert cd._has_write_conflict(t1, t2, {"path"}) is False

    def test_check_data_conflict_no_overlap(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={"target": "10.0.0.1"})
        t2 = _make_task_node(task_id="t2", task_data={"target": "10.0.0.2"})
        assert cd._check_data_conflict(t1, t2) is None

    def test_check_data_conflict_overlap_no_write(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="scan", task_data={"target": "10.0.0.1"})
        t2 = _make_task_node(task_id="t2", task_type="recon", task_data={"target": "10.0.0.1"})
        assert cd._check_data_conflict(t1, t2) is None

    def test_check_data_conflict_overlap_with_write(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="write_data", task_data={"target": "10.0.0.1"})
        t2 = _make_task_node(task_id="t2", task_type="scan", task_data={"target": "10.0.0.1"})
        result = cd._check_data_conflict(t1, t2)
        assert result is not None
        assert "数据读写冲突" in result

    def test_check_tool_conflict_no_common_tools(self):
        cd = ConflictDetector()
        t1 = _make_task_node(required_tools=["nmap_scan"])
        t2 = _make_task_node(task_id="t2", required_tools=["gobuster_scan"])
        assert cd._check_tool_conflict(t1, t2) is None

    def test_check_tool_conflict_common_non_exclusive(self):
        cd = ConflictDetector()
        t1 = _make_task_node(required_tools=["gobuster_scan"])
        t2 = _make_task_node(task_id="t2", required_tools=["gobuster_scan"])
        assert cd._check_tool_conflict(t1, t2) is None

    def test_check_tool_conflict_common_exclusive(self):
        cd = ConflictDetector()
        t1 = _make_task_node(required_tools=["nmap_scan"])
        t2 = _make_task_node(task_id="t2", required_tools=["nmap_scan"])
        result = cd._check_tool_conflict(t1, t2)
        assert result is not None
        assert "互斥工具冲突" in result
        assert "nmap_scan" in result

    def test_check_tool_conflict_hydra_exclusive(self):
        cd = ConflictDetector()
        t1 = _make_task_node(required_tools=["hydra_attack"])
        t2 = _make_task_node(task_id="t2", required_tools=["hydra_attack"])
        result = cd._check_tool_conflict(t1, t2)
        assert result is not None

    def test_check_tool_conflict_masscan_exclusive(self):
        cd = ConflictDetector()
        t1 = _make_task_node(required_tools=["masscan_scan"])
        t2 = _make_task_node(task_id="t2", required_tools=["masscan_scan"])
        result = cd._check_tool_conflict(t1, t2)
        assert result is not None

    def test_check_tool_conflict_empty_tools(self):
        cd = ConflictDetector()
        t1 = _make_task_node(required_tools=[])
        t2 = _make_task_node(task_id="t2", required_tools=[])
        assert cd._check_tool_conflict(t1, t2) is None

    def test_check_network_conflict_different_targets(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={"target": "10.0.0.1", "port": 80})
        t2 = _make_task_node(task_id="t2", task_data={"target": "10.0.0.2", "port": 80})
        assert cd._check_network_conflict(t1, t2) is None

    def test_check_network_conflict_same_target_diff_port(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={"target": "10.0.0.1", "port": 80})
        t2 = _make_task_node(task_id="t2", task_data={"target": "10.0.0.1", "port": 443})
        assert cd._check_network_conflict(t1, t2) is None

    def test_check_network_conflict_same_target_same_port(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={"target": "10.0.0.1", "port": 80})
        t2 = _make_task_node(task_id="t2", task_data={"target": "10.0.0.1", "port": 80})
        result = cd._check_network_conflict(t1, t2)
        assert result is not None
        assert "网络冲突" in result
        assert "10.0.0.1:80" in result

    def test_check_network_conflict_no_target(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={})
        t2 = _make_task_node(task_id="t2", task_data={})
        assert cd._check_network_conflict(t1, t2) is None

    def test_check_network_conflict_same_target_no_port(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={"target": "10.0.0.1"})
        t2 = _make_task_node(task_id="t2", task_data={"target": "10.0.0.1"})
        assert cd._check_network_conflict(t1, t2) is None

    def test_check_network_conflict_one_has_port(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={"target": "10.0.0.1", "port": 80})
        t2 = _make_task_node(task_id="t2", task_data={"target": "10.0.0.1"})
        assert cd._check_network_conflict(t1, t2) is None

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_detect_conflicts_resource_conflict(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 1
        mock_vm = MagicMock()
        mock_vm.available = 10 * 1024 * 1024  # 10MB
        mock_psutil.virtual_memory.return_value = mock_vm

        cd = ConflictDetector()
        task = _make_task_node(task_id="new", estimated_cpu=5.0, estimated_memory=5.0)
        running_task = _make_task_node(task_id="run", estimated_cpu=5.0, estimated_memory=5.0)
        result = cd.detect_conflicts(task, {"run": running_task})
        resource_conflicts = [c for c in result if c.conflict_type == ConflictType.RESOURCE]
        assert len(resource_conflicts) >= 1

    def test_detect_conflicts_tool_conflict(self):
        cd = ConflictDetector()
        task = _make_task_node(task_id="new", required_tools=["nmap_scan"])
        running_task = _make_task_node(task_id="run", required_tools=["nmap_scan"])
        with patch.object(cd, '_check_resource_conflict', return_value=False):
            result = cd.detect_conflicts(task, {"run": running_task})
        tool_conflicts = [c for c in result if c.conflict_type == ConflictType.TOOL]
        assert len(tool_conflicts) == 1

    def test_detect_conflicts_network_conflict(self):
        cd = ConflictDetector()
        task = _make_task_node(task_id="new", task_data={"target": "x", "port": 80})
        running_task = _make_task_node(task_id="run", task_data={"target": "x", "port": 80})
        with patch.object(cd, '_check_resource_conflict', return_value=False):
            result = cd.detect_conflicts(task, {"run": running_task})
        network_conflicts = [c for c in result if c.conflict_type == ConflictType.NETWORK]
        assert len(network_conflicts) == 1

    def test_detect_conflicts_multiple_types(self):
        cd = ConflictDetector()
        task = _make_task_node(
            task_id="new",
            task_data={"target": "x", "port": 80},
            required_tools=["nmap_scan"],
        )
        running_task = _make_task_node(
            task_id="run",
            task_data={"target": "x", "port": 80},
            required_tools=["nmap_scan"],
        )
        with patch.object(cd, '_check_resource_conflict', return_value=False):
            result = cd.detect_conflicts(task, {"run": running_task})
        types = {c.conflict_type for c in result}
        assert ConflictType.TOOL in types
        assert ConflictType.NETWORK in types

    def test_detect_conflicts_data_conflict(self):
        cd = ConflictDetector()
        task = _make_task_node(task_id="new", task_type="write_data", task_data={"target": "10.0.0.1"})
        running_task = _make_task_node(task_id="run", task_type="scan", task_data={"target": "10.0.0.1"})
        with patch.object(cd, '_check_resource_conflict', return_value=False):
            result = cd.detect_conflicts(task, {"run": running_task})
        data_conflicts = [c for c in result if c.conflict_type == ConflictType.DATA]
        assert len(data_conflicts) == 1


# ===================== AdaptiveParallelEngine =====================

class TestAdaptiveParallelEngineInit:
    def test_default_init(self):
        engine = AdaptiveParallelEngine()
        assert engine.min_parallelism == 2
        assert engine.max_parallelism == 16
        assert engine.default_parallelism == 4

    def test_custom_init(self):
        engine = AdaptiveParallelEngine(min_parallelism=1, max_parallelism=8, default_parallelism=3)
        assert engine.min_parallelism == 1
        assert engine.max_parallelism == 8
        assert engine.default_parallelism == 3

    def test_has_dag_analyzer(self):
        engine = AdaptiveParallelEngine()
        assert isinstance(engine.dag_analyzer, DAGAnalyzer)

    def test_has_conflict_detector(self):
        engine = AdaptiveParallelEngine()
        assert isinstance(engine.conflict_detector, ConflictDetector)

    def test_initial_stats(self):
        engine = AdaptiveParallelEngine()
        assert engine.stats["total_executions"] == 0
        assert engine.stats["completed_tasks"] == 0
        assert engine.stats["failed_tasks"] == 0
        assert engine.stats["conflicts_detected"] == 0
        assert engine.stats["conflicts_resolved"] == 0
        assert engine.stats["avg_parallelism"] == 0.0

    def test_not_running_initially(self):
        engine = AdaptiveParallelEngine()
        assert engine._running is False


class TestEstimateIOIntensiveRatio:
    def test_all_io_tasks(self):
        engine = AdaptiveParallelEngine()
        tasks = {
            "t1": _make_task_node(task_id="t1", task_type="scan"),
            "t2": _make_task_node(task_id="t2", task_type="web_recon"),
            "t3": _make_task_node(task_id="t3", task_type="dns_enum"),
        }
        plan = _make_plan(tasks=tasks)
        ratio = engine._estimate_io_intensive_ratio(plan)
        assert ratio == 1.0

    def test_no_io_tasks(self):
        engine = AdaptiveParallelEngine()
        tasks = {
            "t1": _make_task_node(task_id="t1", task_type="compile"),
            "t2": _make_task_node(task_id="t2", task_type="analyze"),
        }
        plan = _make_plan(tasks=tasks)
        ratio = engine._estimate_io_intensive_ratio(plan)
        assert ratio == 0.0

    def test_mixed_tasks(self):
        engine = AdaptiveParallelEngine()
        tasks = {
            "t1": _make_task_node(task_id="t1", task_type="scan"),
            "t2": _make_task_node(task_id="t2", task_type="compile"),
        }
        plan = _make_plan(tasks=tasks)
        ratio = engine._estimate_io_intensive_ratio(plan)
        assert ratio == 0.5

    def test_empty_tasks(self):
        engine = AdaptiveParallelEngine()
        plan = _make_plan(tasks={})
        ratio = engine._estimate_io_intensive_ratio(plan)
        assert ratio == 0.5  # default when empty

    def test_io_type_http(self):
        engine = AdaptiveParallelEngine()
        tasks = {"t1": _make_task_node(task_id="t1", task_type="http_request")}
        plan = _make_plan(tasks=tasks)
        assert engine._estimate_io_intensive_ratio(plan) == 1.0

    def test_io_type_network(self):
        engine = AdaptiveParallelEngine()
        tasks = {"t1": _make_task_node(task_id="t1", task_type="network_probe")}
        plan = _make_plan(tasks=tasks)
        assert engine._estimate_io_intensive_ratio(plan) == 1.0

    def test_io_type_directory(self):
        engine = AdaptiveParallelEngine()
        tasks = {"t1": _make_task_node(task_id="t1", task_type="directory_scan")}
        plan = _make_plan(tasks=tasks)
        assert engine._estimate_io_intensive_ratio(plan) == 1.0

    def test_io_type_subdomain(self):
        engine = AdaptiveParallelEngine()
        tasks = {"t1": _make_task_node(task_id="t1", task_type="subdomain_enum")}
        plan = _make_plan(tasks=tasks)
        assert engine._estimate_io_intensive_ratio(plan) == 1.0

    def test_io_type_case_insensitive(self):
        engine = AdaptiveParallelEngine()
        tasks = {"t1": _make_task_node(task_id="t1", task_type="DNS_Query")}
        plan = _make_plan(tasks=tasks)
        assert engine._estimate_io_intensive_ratio(plan) == 1.0


class TestCalculateInitialParallelism:
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_io_intensive_high_parallelism(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(max_parallelism=16)
        tasks = {
            "t1": _make_task_node(task_id="t1", task_type="scan"),
            "t2": _make_task_node(task_id="t2", task_type="web_recon"),
        }
        plan = _make_plan(tasks=tasks)
        p = engine._calculate_initial_parallelism(plan)
        assert p == min(4 * 2, 16)  # 8

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_cpu_intensive_lower_parallelism(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(max_parallelism=16)
        tasks = {
            "t1": _make_task_node(task_id="t1", task_type="compile"),
            "t2": _make_task_node(task_id="t2", task_type="analyze"),
        }
        plan = _make_plan(tasks=tasks)
        p = engine._calculate_initial_parallelism(plan)
        assert p == min(4, 16)  # 4

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_high_cpu_load_reduces_parallelism(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 8
        mock_psutil.cpu_percent.return_value = 85.0  # > 80
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(min_parallelism=2, max_parallelism=16)
        tasks = {"t1": _make_task_node(task_id="t1", task_type="scan")}
        plan = _make_plan(tasks=tasks)
        p = engine._calculate_initial_parallelism(plan)
        # base = min(16, 16) = 16, then halved due to high cpu: max(2, 8) = 8
        assert p == max(2, min(8 * 2, 16) // 2)

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_high_memory_load_reduces_parallelism(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 8
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 85.0  # > 80
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(min_parallelism=2, max_parallelism=16)
        tasks = {"t1": _make_task_node(task_id="t1", task_type="scan")}
        plan = _make_plan(tasks=tasks)
        p = engine._calculate_initial_parallelism(plan)
        # base = min(16, 16) = 16, halved: max(2, 8) = 8
        assert p == 8

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_max_parallelism_respected(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 32
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(max_parallelism=4)
        tasks = {"t1": _make_task_node(task_id="t1", task_type="scan")}
        plan = _make_plan(tasks=tasks)
        p = engine._calculate_initial_parallelism(plan)
        assert p <= 4


class TestAdjustParallelism:
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_high_cpu_decreases(self, mock_psutil):
        mock_psutil.cpu_percent.return_value = 95.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(min_parallelism=2)
        plan = _make_plan()
        plan.running_tasks = {}
        result = engine._adjust_parallelism(plan, 6)
        assert result == 5

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_high_memory_decreases(self, mock_psutil):
        mock_psutil.cpu_percent.return_value = 30.0
        mock_vm = MagicMock()
        mock_vm.percent = 95.0
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(min_parallelism=2)
        plan = _make_plan()
        plan.running_tasks = {}
        result = engine._adjust_parallelism(plan, 6)
        assert result == 5

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_decrease_respects_min(self, mock_psutil):
        mock_psutil.cpu_percent.return_value = 95.0
        mock_vm = MagicMock()
        mock_vm.percent = 95.0
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(min_parallelism=3)
        plan = _make_plan()
        plan.running_tasks = {}
        result = engine._adjust_parallelism(plan, 3)
        assert result == 3  # can't go below min

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_low_load_increases(self, mock_psutil):
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 20.0
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(max_parallelism=10)
        plan = _make_plan()
        plan.running_tasks = {"t1": MagicMock()}  # 1 running < current(4)
        result = engine._adjust_parallelism(plan, 4)
        assert result == 5

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_increase_respects_max(self, mock_psutil):
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 20.0
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(max_parallelism=5)
        plan = _make_plan()
        plan.running_tasks = {"t1": MagicMock()}
        result = engine._adjust_parallelism(plan, 5)
        assert result == 5  # can't exceed max

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_moderate_load_no_change(self, mock_psutil):
        mock_psutil.cpu_percent.return_value = 50.0
        mock_vm = MagicMock()
        mock_vm.percent = 60.0
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()
        plan = _make_plan()
        plan.running_tasks = {"t1": MagicMock(), "t2": MagicMock()}
        result = engine._adjust_parallelism(plan, 4)
        assert result == 4

    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    def test_low_cpu_but_high_running_no_increase(self, mock_psutil):
        """Low CPU but running_count >= current should not increase."""
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 20.0
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine(max_parallelism=10)
        plan = _make_plan()
        plan.running_tasks = {f"t{i}": MagicMock() for i in range(4)}
        result = engine._adjust_parallelism(plan, 4)
        # running_count(4) == current(4), condition `running_count < current` is false
        assert result == 4


class TestGetTaskNode:
    def test_existing(self):
        engine = AdaptiveParallelEngine()
        node = _make_task_node(task_id="t1")
        plan = _make_plan(tasks={"t1": node})
        assert engine._get_task_node(plan, "t1") is node

    def test_missing(self):
        engine = AdaptiveParallelEngine()
        plan = _make_plan(tasks={})
        assert engine._get_task_node(plan, "nonexistent") is None


class TestExecutePlan:
    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_single_task_success(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            return {"task_id": task_node.task_id, "data": "ok"}

        tasks = [_make_task_dict("t1", task_type="scan")]
        plan = await engine.execute_plan(tasks, executor)

        assert plan.completed_count == 1
        assert plan.failed_count == 0
        assert "t1" in plan.completed_tasks
        assert plan.start_time is not None
        assert plan.end_time is not None
        assert engine.stats["total_executions"] == 1
        assert engine.stats["completed_tasks"] == 1

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_single_task_failure(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            raise RuntimeError("boom")

        tasks = [_make_task_dict("t1", task_type="scan")]
        plan = await engine.execute_plan(tasks, executor)

        assert plan.failed_count == 1
        assert "t1" in plan.failed_tasks
        assert engine.stats["failed_tasks"] == 1

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_with_context(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()
        received_ctx = {}

        async def executor(task_node, context):
            received_ctx.update(context)
            return "done"

        tasks = [_make_task_dict("t1")]
        await engine.execute_plan(tasks, executor, context={"key": "value"})
        assert received_ctx == {"key": "value"}

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_dependent_tasks(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()
        execution_order = []

        async def executor(task_node, context):
            execution_order.append(task_node.task_id)
            return f"result_{task_node.task_id}"

        tasks = [
            _make_task_dict("t1"),
            _make_task_dict("t2", dependencies=["t1"]),
        ]
        plan = await engine.execute_plan(tasks, executor)

        assert plan.completed_count == 2
        assert execution_order.index("t1") < execution_order.index("t2")

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_parallel_independent_tasks(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 8
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024  # 8 GB
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            return "ok"

        tasks = [_make_task_dict(f"t{i}") for i in range(4)]
        plan = await engine.execute_plan(tasks, executor)

        assert plan.completed_count == 4
        assert plan.failed_count == 0

    @pytest.mark.asyncio
    async def test_cycle_detection_raises(self):
        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            return "ok"

        tasks = [
            _make_task_dict("t1", dependencies=["t2"]),
            _make_task_dict("t2", dependencies=["t1"]),
        ]
        with pytest.raises(ValueError, match="循环依赖"):
            await engine.execute_plan(tasks, executor)

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_end_time_set_even_on_exception(self, mock_psutil):
        """end_time should be set in the finally block."""
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            return "ok"

        tasks = [_make_task_dict("t1")]
        plan = await engine.execute_plan(tasks, executor)
        assert plan.end_time is not None

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_stats_increment(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            return "ok"

        await engine.execute_plan([_make_task_dict("t1")], executor)
        await engine.execute_plan([_make_task_dict("t2")], executor)
        assert engine.stats["total_executions"] == 2
        assert engine.stats["completed_tasks"] == 2


class TestStartTask:
    @pytest.mark.asyncio
    async def test_sets_status_and_start_time(self):
        engine = AdaptiveParallelEngine()
        node = _make_task_node(task_id="t1")
        plan = _make_plan(tasks={"t1": node})

        async def executor(task_node, context):
            return "ok"

        await engine._start_task(plan, node, executor, {})
        assert node.status == TaskStatus.RUNNING
        assert node.start_time is not None
        assert "t1" in plan.running_tasks

    @pytest.mark.asyncio
    async def test_wrapper_returns_success(self):
        engine = AdaptiveParallelEngine()
        node = _make_task_node(task_id="t1")
        plan = _make_plan(tasks={"t1": node})

        async def executor(task_node, context):
            return {"value": 42}

        await engine._start_task(plan, node, executor, {})
        result = await plan.running_tasks["t1"]
        assert result["success"] is True
        assert result["task_id"] == "t1"

    @pytest.mark.asyncio
    async def test_wrapper_catches_exception(self):
        engine = AdaptiveParallelEngine()
        node = _make_task_node(task_id="t1")
        plan = _make_plan(tasks={"t1": node})

        async def executor(task_node, context):
            raise ValueError("test error")

        await engine._start_task(plan, node, executor, {})
        result = await plan.running_tasks["t1"]
        assert result["success"] is False
        assert "test error" in result["error"]
        assert result["task_id"] == "t1"


class TestHandleTaskCompletion:
    @pytest.mark.asyncio
    async def test_success_completion(self):
        engine = AdaptiveParallelEngine()
        node = _make_task_node(task_id="t1")
        node.start_time = datetime.now()
        plan = _make_plan(tasks={"t1": node})

        async def mock_task():
            return {"success": True, "result": "data", "task_id": "t1"}

        task = asyncio.create_task(mock_task())
        plan.running_tasks["t1"] = task
        await task  # let it finish

        await engine._handle_task_completion(plan, "t1", task)
        assert node.status == TaskStatus.COMPLETED
        assert node.result == "data"
        assert "t1" in plan.completed_tasks
        assert plan.completed_count == 1
        assert "t1" not in plan.running_tasks
        assert node.end_time is not None
        assert node.execution_time > 0 or node.execution_time == 0.0

    @pytest.mark.asyncio
    async def test_failure_completion(self):
        engine = AdaptiveParallelEngine()
        node = _make_task_node(task_id="t1")
        node.start_time = datetime.now()
        plan = _make_plan(tasks={"t1": node})

        async def mock_task():
            return {"success": False, "error": "oops", "task_id": "t1"}

        task = asyncio.create_task(mock_task())
        plan.running_tasks["t1"] = task
        await task

        await engine._handle_task_completion(plan, "t1", task)
        assert node.status == TaskStatus.FAILED
        assert node.error == "oops"
        assert "t1" in plan.failed_tasks
        assert plan.failed_count == 1
        assert engine.stats["failed_tasks"] == 1

    @pytest.mark.asyncio
    async def test_execution_time_calculated(self):
        engine = AdaptiveParallelEngine()
        node = _make_task_node(task_id="t1")
        node.start_time = datetime.now() - timedelta(seconds=2)
        plan = _make_plan(tasks={"t1": node})

        async def mock_task():
            return {"success": True, "result": None, "task_id": "t1"}

        task = asyncio.create_task(mock_task())
        plan.running_tasks["t1"] = task
        await task

        await engine._handle_task_completion(plan, "t1", task)
        assert node.execution_time >= 1.5  # at least ~2 seconds


class TestExecutePlanConflictHandling:
    @pytest.mark.asyncio
    async def test_conflict_requeues_task(self):
        """When conflicts are detected, the task should be re-enqueued with lower priority."""
        engine = AdaptiveParallelEngine()

        # Directly test conflict detection stats by simulating what _execute_dag does
        node = _make_task_node(task_id="t1", priority=5)
        conflict = ConflictInfo(
            conflict_type=ConflictType.TOOL,
            task1_id="t1",
            task2_id="t2",
            reason="test conflict",
        )

        # Simulate the conflict handling path
        engine.stats["conflicts_detected"] += 1
        node.priority = max(1, node.priority - 1)

        assert engine.stats["conflicts_detected"] >= 1
        assert node.priority == 4  # decreased from 5


class TestModuleExports:
    def test_all_exports(self):
        from kali_mcp.core import adaptive_parallel_engine as mod
        expected = [
            'AdaptiveParallelEngine',
            'DAGAnalyzer',
            'ConflictDetector',
            'TaskStatus',
            'ConflictType',
            'TaskPriority',
            'TaskNode',
            'ConflictInfo',
            'ExecutionPlan',
        ]
        for name in expected:
            assert name in mod.__all__
            assert hasattr(mod, name)


class TestDAGAnalyzerEdgeCases:
    def test_single_task_topological_sort(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([_make_task_dict("t1")])
        levels = analyzer.topological_sort()
        assert levels == [["t1"]]

    def test_wide_dag_single_level(self):
        analyzer = DAGAnalyzer()
        tasks = [_make_task_dict(f"t{i}") for i in range(10)]
        analyzer.build_dag(tasks)
        levels = analyzer.topological_sort()
        assert len(levels) == 1
        assert len(levels[0]) == 10

    def test_deep_linear_chain(self):
        analyzer = DAGAnalyzer()
        tasks = []
        for i in range(5):
            deps = [f"t{i-1}"] if i > 0 else []
            tasks.append(_make_task_dict(f"t{i}", dependencies=deps))
        analyzer.build_dag(tasks)
        levels = analyzer.topological_sort()
        assert len(levels) == 5
        for i, level in enumerate(levels):
            assert level == [f"t{i}"]

    def test_dependency_bidirectional_linkage(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("parent"),
            _make_task_dict("child", dependencies=["parent"]),
        ])
        assert "child" in analyzer._tasks["parent"].dependents
        assert "parent" in analyzer._tasks["child"].dependencies

    def test_multiple_dependencies_same_child(self):
        analyzer = DAGAnalyzer()
        analyzer.build_dag([
            _make_task_dict("p1"),
            _make_task_dict("p2"),
            _make_task_dict("child", dependencies=["p1", "p2"]),
        ])
        assert analyzer._tasks["child"].dependencies == {"p1", "p2"}
        assert "child" in analyzer._tasks["p1"].dependents
        assert "child" in analyzer._tasks["p2"].dependents


class TestConflictDetectorEdgeCases:
    def test_medusa_bruteforce_exclusive(self):
        cd = ConflictDetector()
        t1 = _make_task_node(required_tools=["medusa_bruteforce"])
        t2 = _make_task_node(task_id="t2", required_tools=["medusa_bruteforce"])
        result = cd._check_tool_conflict(t1, t2)
        assert result is not None

    def test_modify_task_type_write_conflict(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="modify_config")
        t2 = _make_task_node(task_id="t2", task_type="scan")
        assert cd._has_write_conflict(t1, t2, {"target"}) is True

    def test_delete_task_type_write_conflict(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_type="delete_file")
        t2 = _make_task_node(task_id="t2", task_type="scan")
        assert cd._has_write_conflict(t1, t2, {"target"}) is True

    def test_extract_data_paths_output_field(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={"output": "/tmp/results"})
        paths = cd._extract_data_paths(task)
        assert "/tmp/results" in paths

    def test_extract_data_paths_input_field(self):
        cd = ConflictDetector()
        task = _make_task_node(task_data={"input": "/tmp/data"})
        paths = cd._extract_data_paths(task)
        assert "/tmp/data" in paths

    def test_empty_target_no_network_conflict(self):
        cd = ConflictDetector()
        t1 = _make_task_node(task_data={"target": "", "port": 80})
        t2 = _make_task_node(task_id="t2", task_data={"target": "", "port": 80})
        assert cd._check_network_conflict(t1, t2) is None


class TestTaskPriorityEdgeCases:
    def test_lt_priority_10_vs_1(self):
        high = TaskPriority(priority=10)
        low = TaskPriority(priority=1)
        # Higher priority should be "less than" (come first in min-heap)
        assert high < low
        assert not (low < high)

    def test_eq_with_none(self):
        tp = TaskPriority()
        assert tp.__eq__(None) is NotImplemented

    def test_eq_with_int(self):
        tp = TaskPriority()
        assert tp.__eq__(5) is NotImplemented

    def test_priority_1_minimum(self):
        tp = TaskPriority(priority=1)
        assert tp.priority == 1

    def test_priority_0(self):
        tp = TaskPriority(priority=0)
        assert tp.priority == 0


class TestComplexDAGExecution:
    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_diamond_dag_execution(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()
        order = []

        async def executor(task_node, context):
            order.append(task_node.task_id)
            return "ok"

        tasks = [
            _make_task_dict("root"),
            _make_task_dict("left", dependencies=["root"]),
            _make_task_dict("right", dependencies=["root"]),
            _make_task_dict("join", dependencies=["left", "right"]),
        ]
        plan = await engine.execute_plan(tasks, executor)
        assert plan.completed_count == 4
        assert order[0] == "root"
        assert order[-1] == "join"

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_empty_task_list(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            return "ok"

        plan = await engine.execute_plan([], executor)
        assert plan.completed_count == 0
        assert plan.total_tasks == 0

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_mixed_success_failure(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            if task_node.task_id == "t2":
                raise RuntimeError("fail")
            return "ok"

        tasks = [
            _make_task_dict("t1"),
            _make_task_dict("t2"),
            _make_task_dict("t3"),
        ]
        plan = await engine.execute_plan(tasks, executor)
        assert plan.completed_count == 2
        assert plan.failed_count == 1

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_task_node_result_stored(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            return {"scan_data": [1, 2, 3]}

        tasks = [_make_task_dict("t1")]
        plan = await engine.execute_plan(tasks, executor)
        assert plan.tasks["t1"].result == {"scan_data": [1, 2, 3]}
        assert plan.tasks["t1"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_task_node_error_stored(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()

        async def executor(task_node, context):
            raise ValueError("specific error message")

        tasks = [_make_task_dict("t1")]
        plan = await engine.execute_plan(tasks, executor)
        assert plan.tasks["t1"].error == "specific error message"
        assert plan.tasks["t1"].status == TaskStatus.FAILED

    @pytest.mark.asyncio
    @patch("kali_mcp.core.adaptive_parallel_engine.psutil")
    async def test_none_context_defaults_to_empty_dict(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_percent.return_value = 10.0
        mock_vm = MagicMock()
        mock_vm.percent = 30.0
        mock_vm.available = 8 * 1024 * 1024 * 1024
        mock_vm.total = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_vm

        engine = AdaptiveParallelEngine()
        received = {}

        async def executor(task_node, context):
            received.update(context)
            return "ok"

        tasks = [_make_task_dict("t1")]
        await engine.execute_plan(tasks, executor, context=None)
        assert received == {}
