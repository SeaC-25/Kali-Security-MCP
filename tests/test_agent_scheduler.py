"""
Tests for AgentScheduler, SchedulingStrategy, AssignmentStatus,
ScheduledTask, SchedulingStatistics, SchedulingDecision
(kali_mcp/core/agent_scheduler.py)

Covers:
- SchedulingStrategy enum: all 5 members and values
- AssignmentStatus enum: all 4 members and values
- ScheduledTask dataclass: creation, defaults, ordering
- SchedulingStatistics dataclass: creation, defaults, mutable defaults, success_rate property
- SchedulingDecision dataclass: creation, defaults
- AgentScheduler class:
  - __init__ with different strategies
  - schedule_task (all paths)
  - recommend_agent (dispatches to each strategy)
  - schedule_batch (priority sorting)
  - schedule_task_graph (phases / dependencies)
  - mark_task_complete (success / failure / missing / duration calc)
  - get_pending_tasks / get_running_tasks / get_statistics
  - _adaptive_schedule (load filtering, scoring, no capable, all overloaded)
  - _least_loaded_schedule (no capable, empty load, normal)
  - _priority_schedule (high priority filtering, no capable)
  - _capability_schedule (no capable, normal)
  - _round_robin_schedule (match, no match)
  - _get_available_agents (with / without is_available)
  - _calculate_agent_score (load_report variations, tool match, partial match, success_rate)
  - _get_execution_phases (topological sort)
  - _update_statistics (load, utilization, avg exec time)
  - _agent_supported_tools (get_supported_tools, capabilities list, capabilities object, fallback)
  - _agent_can_handle_tool (exact match, prefix match, no match)
  - _get_agent_load (sync, async, None, no report_load)
  - _fallback_load_report (normal / overloaded)
  - _agent_max_concurrency (list caps, single cap, no caps)
  - _as_float (number, string, invalid)
  - _as_int (number, bool, string, invalid)
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock

import pytest

from kali_mcp.core.agent_scheduler import (
    AgentScheduler,
    AssignmentStatus,
    ScheduledTask,
    SchedulingDecision,
    SchedulingStatistics,
    SchedulingStrategy,
)
from kali_mcp.core.agent_registry import LoadReport
from kali_mcp.core.task_decomposer import Task, TaskCategory, TaskGraph


# ===================== Helpers =====================

def _make_load_report(agent_id="a1", current_tasks=0, cpu_usage=0.0, memory_usage_mb=0.0):
    return LoadReport(
        agent_id=agent_id,
        current_tasks=current_tasks,
        cpu_usage=cpu_usage,
        memory_usage_mb=memory_usage_mb,
    )


class _Cap:
    """Minimal capability with supported_tools and max_concurrent_tasks."""
    def __init__(self, tools=None, max_concurrent=5):
        self.supported_tools = tools or []
        self.max_concurrent_tasks = max_concurrent


def _make_agent(
    agent_id="agent-1",
    supported_tools=None,
    cpu_usage=0.0,
    current_tasks=0,
    is_available=True,
    report_load_raises=False,
    report_load_returns_none=False,
    has_report_load=True,
    use_get_supported_tools=True,
    capabilities=None,
    success_rate=0.0,
    max_concurrent=5,
    report_load_async=False,
):
    """Build a mock agent compatible with AgentScheduler's expectations."""
    agent = MagicMock()
    agent.agent_id = agent_id

    tools = supported_tools or []

    if use_get_supported_tools:
        agent.get_supported_tools = MagicMock(return_value=tools)
    else:
        del agent.get_supported_tools
        if capabilities is not None:
            agent.capabilities = capabilities
        else:
            cap = _Cap(tools=tools, max_concurrent=max_concurrent)
            agent.capabilities = cap

    if capabilities is not None and use_get_supported_tools:
        agent.capabilities = capabilities

    lr = _make_load_report(agent_id=agent_id, cpu_usage=cpu_usage, current_tasks=current_tasks)

    if not has_report_load:
        del agent.report_load
    elif report_load_raises:
        agent.report_load = MagicMock(side_effect=RuntimeError("boom"))
    elif report_load_returns_none:
        agent.report_load = MagicMock(return_value=None)
    elif report_load_async:
        async def _async_load():
            return lr
        agent.report_load = MagicMock(return_value=_async_load())
    else:
        agent.report_load = MagicMock(return_value=lr)

    if is_available is not None:
        agent.is_available = MagicMock(return_value=is_available)
    else:
        del agent.is_available

    perf = MagicMock()
    perf.success_rate = success_rate
    agent.performance_metrics = perf

    return agent


def _make_task(task_id="t1", tool_name="nmap", priority=5, deps=None):
    return Task(
        task_id=task_id,
        name=f"Task {task_id}",
        category=TaskCategory.SCANNING,
        tool_name=tool_name,
        parameters={"target": "127.0.0.1"},
        dependencies=deps or [],
        priority=priority,
    )


def _make_registry(agents=None):
    registry = MagicMock()
    registry.list_all = MagicMock(return_value=agents or [])
    return registry


def _run(coro):
    """Run an async coroutine synchronously."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        raise RuntimeError("Cannot use _run inside a running event loop")
    return asyncio.new_event_loop().run_until_complete(coro)


# ===================== SchedulingStrategy Enum =====================

class TestSchedulingStrategy:
    def test_round_robin_value(self):
        assert SchedulingStrategy.ROUND_ROBIN.value == "round_robin"

    def test_least_loaded_value(self):
        assert SchedulingStrategy.LEAST_LOADED.value == "least_loaded"

    def test_priority_based_value(self):
        assert SchedulingStrategy.PRIORITY_BASED.value == "priority_based"

    def test_capability_match_value(self):
        assert SchedulingStrategy.CAPABILITY_MATCH.value == "capability_match"

    def test_adaptive_value(self):
        assert SchedulingStrategy.ADAPTIVE.value == "adaptive"

    def test_member_count(self):
        assert len(SchedulingStrategy) == 5

    def test_from_value(self):
        assert SchedulingStrategy("round_robin") is SchedulingStrategy.ROUND_ROBIN

    def test_invalid_value(self):
        with pytest.raises(ValueError):
            SchedulingStrategy("nonexistent")

    def test_all_are_enum(self):
        for member in SchedulingStrategy:
            assert isinstance(member, SchedulingStrategy)


# ===================== AssignmentStatus Enum =====================

class TestAssignmentStatus:
    def test_assigned_value(self):
        assert AssignmentStatus.ASSIGNED.value == "assigned"

    def test_pending_value(self):
        assert AssignmentStatus.PENDING.value == "pending"

    def test_failed_value(self):
        assert AssignmentStatus.FAILED.value == "failed"

    def test_cancelled_value(self):
        assert AssignmentStatus.CANCELLED.value == "cancelled"

    def test_member_count(self):
        assert len(AssignmentStatus) == 4

    def test_from_value(self):
        assert AssignmentStatus("failed") is AssignmentStatus.FAILED


# ===================== ScheduledTask Dataclass =====================

class TestScheduledTask:
    def test_creation_minimal(self):
        task = _make_task()
        st = ScheduledTask(priority=5, created_at=datetime.now(), task=task)
        assert st.priority == 5
        assert st.assigned_agent is None
        assert st.status == AssignmentStatus.PENDING
        assert st.scheduled_at is None
        assert st.started_at is None
        assert st.completed_at is None

    def test_creation_full(self):
        task = _make_task()
        agent = _make_agent()
        now = datetime.now()
        st = ScheduledTask(
            priority=8,
            created_at=now,
            task=task,
            assigned_agent=agent,
            status=AssignmentStatus.ASSIGNED,
            scheduled_at=now,
            started_at=now,
            completed_at=now,
        )
        assert st.status == AssignmentStatus.ASSIGNED
        assert st.assigned_agent is agent
        assert st.scheduled_at == now

    def test_ordering_by_priority(self):
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2")
        now = datetime.now()
        st1 = ScheduledTask(priority=3, created_at=now, task=t1)
        st2 = ScheduledTask(priority=7, created_at=now, task=t2)
        assert st1 < st2

    def test_ordering_same_priority_by_time(self):
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2")
        earlier = datetime(2024, 1, 1)
        later = datetime(2024, 6, 1)
        st1 = ScheduledTask(priority=5, created_at=earlier, task=t1)
        st2 = ScheduledTask(priority=5, created_at=later, task=t2)
        assert st1 < st2

    def test_equality(self):
        task = _make_task()
        now = datetime.now()
        st1 = ScheduledTask(priority=5, created_at=now, task=task)
        st2 = ScheduledTask(priority=5, created_at=now, task=task)
        assert st1 == st2


# ===================== SchedulingStatistics Dataclass =====================

class TestSchedulingStatistics:
    def test_defaults(self):
        stats = SchedulingStatistics()
        assert stats.total_assignments == 0
        assert stats.successful_assignments == 0
        assert stats.failed_assignments == 0
        assert stats.total_execution_time == 0.0
        assert stats.avg_execution_time == 0.0
        assert stats.current_load == 0.0
        assert stats.peak_load == 0.0
        assert stats.agent_utilization == {}

    def test_mutable_default_isolation(self):
        s1 = SchedulingStatistics()
        s2 = SchedulingStatistics()
        s1.agent_utilization["a1"] = 0.5
        assert "a1" not in s2.agent_utilization

    def test_success_rate_zero_total(self):
        stats = SchedulingStatistics()
        assert stats.success_rate == 0.0

    def test_success_rate_all_successful(self):
        stats = SchedulingStatistics(total_assignments=10, successful_assignments=10)
        assert stats.success_rate == 1.0

    def test_success_rate_partial(self):
        stats = SchedulingStatistics(total_assignments=10, successful_assignments=7)
        assert abs(stats.success_rate - 0.7) < 1e-9

    def test_success_rate_none_successful(self):
        stats = SchedulingStatistics(total_assignments=5, successful_assignments=0)
        assert stats.success_rate == 0.0

    def test_custom_values(self):
        stats = SchedulingStatistics(
            total_assignments=100,
            successful_assignments=90,
            failed_assignments=10,
            total_execution_time=500.0,
            avg_execution_time=5.0,
            current_load=0.5,
            peak_load=0.8,
        )
        assert stats.total_assignments == 100
        assert stats.peak_load == 0.8


# ===================== SchedulingDecision Dataclass =====================

class TestSchedulingDecision:
    def test_creation(self):
        task = _make_task()
        agent = _make_agent()
        d = SchedulingDecision(
            task=task,
            selected_agent=agent,
            strategy=SchedulingStrategy.ADAPTIVE,
            confidence=0.9,
            reasoning=["test"],
        )
        assert d.task is task
        assert d.selected_agent is agent
        assert d.strategy == SchedulingStrategy.ADAPTIVE
        assert d.confidence == 0.9
        assert d.estimated_duration is None

    def test_creation_no_agent(self):
        task = _make_task()
        d = SchedulingDecision(
            task=task,
            selected_agent=None,
            strategy=SchedulingStrategy.ROUND_ROBIN,
            confidence=0.0,
            reasoning=[],
        )
        assert d.selected_agent is None

    def test_estimated_duration(self):
        task = _make_task()
        d = SchedulingDecision(
            task=task,
            selected_agent=None,
            strategy=SchedulingStrategy.LEAST_LOADED,
            confidence=0.5,
            reasoning=[],
            estimated_duration=120,
        )
        assert d.estimated_duration == 120


# ===================== AgentScheduler Init =====================

class TestAgentSchedulerInit:
    def test_default_strategy(self):
        registry = _make_registry()
        scheduler = AgentScheduler(registry)
        assert scheduler.strategy == SchedulingStrategy.ADAPTIVE
        assert len(scheduler.pending_tasks) == 0
        assert scheduler.running_tasks == {}
        assert scheduler.completed_tasks == []
        assert scheduler.history == []

    def test_custom_strategy(self):
        registry = _make_registry()
        scheduler = AgentScheduler(registry, strategy=SchedulingStrategy.ROUND_ROBIN)
        assert scheduler.strategy == SchedulingStrategy.ROUND_ROBIN

    def test_stats_initialized(self):
        registry = _make_registry()
        scheduler = AgentScheduler(registry)
        assert isinstance(scheduler.stats, SchedulingStatistics)
        assert scheduler.stats.total_assignments == 0

    def test_all_strategies(self):
        registry = _make_registry()
        for strategy in SchedulingStrategy:
            s = AgentScheduler(registry, strategy=strategy)
            assert s.strategy == strategy


# ===================== _as_float =====================

class TestAsFloat:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_int_input(self):
        assert self._sched()._as_float(5, 0.0) == 5.0

    def test_float_input(self):
        assert self._sched()._as_float(3.14, 0.0) == 3.14

    def test_string_numeric(self):
        assert self._sched()._as_float("2.5", 0.0) == 2.5

    def test_string_invalid(self):
        assert self._sched()._as_float("abc", 99.0) == 99.0

    def test_none(self):
        assert self._sched()._as_float(None, 42.0) == 42.0

    def test_bool_true(self):
        assert self._sched()._as_float(True, 0.0) == 1.0

    def test_bool_false(self):
        assert self._sched()._as_float(False, 0.0) == 0.0

    def test_zero(self):
        assert self._sched()._as_float(0, 99.0) == 0.0

    def test_negative(self):
        assert self._sched()._as_float(-3.5, 0.0) == -3.5

    def test_list_invalid(self):
        assert self._sched()._as_float([1, 2], 7.0) == 7.0


# ===================== _as_int =====================

class TestAsInt:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_int_input(self):
        assert self._sched()._as_int(5, 0) == 5

    def test_float_input(self):
        assert self._sched()._as_int(3.7, 0) == 3

    def test_string_numeric(self):
        assert self._sched()._as_int("10", 0) == 10

    def test_string_invalid(self):
        assert self._sched()._as_int("abc", 99) == 99

    def test_none(self):
        assert self._sched()._as_int(None, 42) == 42

    def test_bool_true(self):
        assert self._sched()._as_int(True, 0) == 1

    def test_bool_false(self):
        assert self._sched()._as_int(False, 0) == 0

    def test_zero(self):
        assert self._sched()._as_int(0, 99) == 0

    def test_negative(self):
        assert self._sched()._as_int(-5, 0) == -5

    def test_list_invalid(self):
        assert self._sched()._as_int([1], 7) == 7


# ===================== _agent_supported_tools =====================

class TestAgentSupportedTools:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_via_get_supported_tools_list(self):
        agent = _make_agent(supported_tools=["nmap", "gobuster"])
        result = self._sched()._agent_supported_tools(agent)
        assert result == {"nmap", "gobuster"}

    def test_via_get_supported_tools_set(self):
        agent = MagicMock()
        agent.get_supported_tools = MagicMock(return_value={"nmap", "nikto"})
        result = self._sched()._agent_supported_tools(agent)
        assert result == {"nmap", "nikto"}

    def test_via_get_supported_tools_tuple(self):
        agent = MagicMock()
        agent.get_supported_tools = MagicMock(return_value=("nmap",))
        result = self._sched()._agent_supported_tools(agent)
        assert result == {"nmap"}

    def test_via_capabilities_list(self):
        cap1 = _Cap(tools=["nmap", "nikto"])
        cap2 = _Cap(tools=["sqlmap"])
        agent = _make_agent(use_get_supported_tools=False, capabilities=[cap1, cap2])
        result = self._sched()._agent_supported_tools(agent)
        assert result == {"nmap", "nikto", "sqlmap"}

    def test_via_capabilities_object(self):
        cap = _Cap(tools=["nmap", "gobuster"])
        agent = MagicMock(spec=[])
        agent.capabilities = cap
        result = self._sched()._agent_supported_tools(agent)
        assert result == {"nmap", "gobuster"}

    def test_no_tools_returns_empty(self):
        agent = MagicMock(spec=[])
        agent.capabilities = None
        result = self._sched()._agent_supported_tools(agent)
        assert result == set()

    def test_get_supported_tools_raises(self):
        agent = MagicMock()
        agent.get_supported_tools = MagicMock(side_effect=RuntimeError("oops"))
        agent.capabilities = None
        result = self._sched()._agent_supported_tools(agent)
        assert result == set()

    def test_get_supported_tools_returns_non_iterable(self):
        agent = MagicMock()
        agent.get_supported_tools = MagicMock(return_value=42)
        agent.capabilities = None
        result = self._sched()._agent_supported_tools(agent)
        assert result == set()

    def test_capabilities_list_with_tools_attr(self):
        """Test capabilities with .tools instead of .supported_tools."""
        cap = MagicMock(spec=[])
        cap.supported_tools = None
        cap.tools = ["nmap"]
        agent = _make_agent(use_get_supported_tools=False, capabilities=[cap])
        result = self._sched()._agent_supported_tools(agent)
        assert result == {"nmap"}


# ===================== _agent_can_handle_tool =====================

class TestAgentCanHandleTool:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_exact_match(self):
        agent = _make_agent(supported_tools=["nmap", "gobuster"])
        assert self._sched()._agent_can_handle_tool(agent, "nmap") is True

    def test_prefix_match(self):
        agent = _make_agent(supported_tools=["nmap"])
        assert self._sched()._agent_can_handle_tool(agent, "nmap_scan") is True

    def test_no_match(self):
        agent = _make_agent(supported_tools=["gobuster"])
        assert self._sched()._agent_can_handle_tool(agent, "nmap") is False

    def test_empty_tools(self):
        agent = _make_agent(supported_tools=[])
        assert self._sched()._agent_can_handle_tool(agent, "nmap") is False


# ===================== _get_agent_load =====================

class TestGetAgentLoad:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_sync_report_load(self):
        agent = _make_agent(cpu_usage=0.3, current_tasks=2)
        result = _run(self._sched()._get_agent_load(agent))
        assert result.cpu_usage == 0.3
        assert result.current_tasks == 2

    def test_async_report_load(self):
        agent = _make_agent(cpu_usage=0.5, current_tasks=3, report_load_async=True)
        result = _run(self._sched()._get_agent_load(agent))
        assert result.cpu_usage == 0.5

    def test_report_load_returns_none(self):
        agent = _make_agent(report_load_returns_none=True)
        result = _run(self._sched()._get_agent_load(agent))
        assert result.agent_id == agent.agent_id

    def test_no_report_load_method(self):
        agent = _make_agent(has_report_load=False)
        result = _run(self._sched()._get_agent_load(agent))
        assert result.agent_id == agent.agent_id


# ===================== _fallback_load_report =====================

class TestFallbackLoadReport:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_normal(self):
        r = self._sched()._fallback_load_report("a1", current_tasks=2)
        assert r.agent_id == "a1"
        assert r.current_tasks == 2
        assert r.cpu_usage == 0.0

    def test_overloaded(self):
        r = self._sched()._fallback_load_report("a1", current_tasks=999)
        assert r.cpu_usage == 1.0

    def test_default_tasks(self):
        r = self._sched()._fallback_load_report("a1")
        assert r.current_tasks == 0
        assert r.cpu_usage == 0.0


# ===================== _agent_max_concurrency =====================

class TestAgentMaxConcurrency:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_list_capabilities(self):
        cap1 = _Cap(max_concurrent=5)
        cap2 = _Cap(max_concurrent=3)
        agent = MagicMock()
        agent.capabilities = [cap1, cap2]
        assert self._sched()._agent_max_concurrency(agent) == 8

    def test_single_capability(self):
        cap = _Cap(max_concurrent=10)
        agent = MagicMock()
        agent.capabilities = cap
        assert self._sched()._agent_max_concurrency(agent) == 10

    def test_no_capabilities(self):
        agent = MagicMock()
        agent.capabilities = None
        assert self._sched()._agent_max_concurrency(agent) == 0

    def test_list_with_zero_concurrent(self):
        cap = _Cap(max_concurrent=0)
        agent = MagicMock()
        agent.capabilities = [cap]
        assert self._sched()._agent_max_concurrency(agent) == 0


# ===================== _calculate_agent_score =====================

class TestCalculateAgentScore:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_full_score_with_tool_match_and_low_load(self):
        agent = _make_agent(supported_tools=["nmap"], success_rate=1.0)
        task = _make_task(tool_name="nmap")
        lr = _make_load_report(cpu_usage=0.0, current_tasks=0)
        score = self._sched()._calculate_agent_score(agent, task, lr)
        # load=40, capability=30, success=20, idle=10 = 100
        assert score == 100.0

    def test_no_load_report(self):
        agent = _make_agent(supported_tools=["nmap"], success_rate=0.0)
        task = _make_task(tool_name="nmap")
        score = self._sched()._calculate_agent_score(agent, task, None)
        # load=20 (default), capability=30, success=10 (default), idle=0 = 60
        assert score == 60.0

    def test_partial_tool_match(self):
        agent = _make_agent(supported_tools=["nmap"])
        task = _make_task(tool_name="nmap_scan")
        lr = _make_load_report(cpu_usage=0.5, current_tasks=2)
        score = self._sched()._calculate_agent_score(agent, task, lr)
        # load=(1-0.5)*40=20, capability=15 (prefix), success=10, idle=5 (tasks<3)
        assert score == 50.0

    def test_no_tool_match(self):
        agent = _make_agent(supported_tools=["gobuster"])
        task = _make_task(tool_name="nmap")
        lr = _make_load_report(cpu_usage=0.0, current_tasks=0)
        score = self._sched()._calculate_agent_score(agent, task, lr)
        # load=40, capability=0, success=10, idle=10 = 60
        assert score == 60.0

    def test_high_load_low_score(self):
        agent = _make_agent(supported_tools=["nmap"], success_rate=0.5)
        task = _make_task(tool_name="nmap")
        lr = _make_load_report(cpu_usage=0.9, current_tasks=5)
        score = self._sched()._calculate_agent_score(agent, task, lr)
        # load=(1-0.9)*40=4, capability=30, success=0.5*20=10, idle=0
        assert score == 44.0

    def test_idle_bonus_zero_tasks(self):
        agent = _make_agent(supported_tools=["nmap"])
        task = _make_task(tool_name="nmap")
        lr = _make_load_report(cpu_usage=0.0, current_tasks=0)
        score = self._sched()._calculate_agent_score(agent, task, lr)
        assert score >= 80  # Should include idle bonus 10

    def test_idle_bonus_few_tasks(self):
        agent = _make_agent(supported_tools=["nmap"])
        task = _make_task(tool_name="nmap")
        lr = _make_load_report(cpu_usage=0.0, current_tasks=2)
        score = self._sched()._calculate_agent_score(agent, task, lr)
        # load=40, capability=30, success=10, idle=5 = 85
        assert score == 85.0

    def test_no_idle_bonus_many_tasks(self):
        agent = _make_agent(supported_tools=["nmap"])
        task = _make_task(tool_name="nmap")
        lr = _make_load_report(cpu_usage=0.0, current_tasks=5)
        score = self._sched()._calculate_agent_score(agent, task, lr)
        # load=40, capability=30, success=10, idle=0 = 80
        assert score == 80.0


# ===================== _get_available_agents =====================

class TestGetAvailableAgents:
    def test_all_available(self):
        a1 = _make_agent(agent_id="a1", is_available=True)
        a2 = _make_agent(agent_id="a2", is_available=True)
        registry = _make_registry([a1, a2])
        scheduler = AgentScheduler(registry)
        result = scheduler._get_available_agents()
        assert len(result) == 2

    def test_some_unavailable(self):
        a1 = _make_agent(agent_id="a1", is_available=True)
        a2 = _make_agent(agent_id="a2", is_available=False)
        registry = _make_registry([a1, a2])
        scheduler = AgentScheduler(registry)
        result = scheduler._get_available_agents()
        assert len(result) == 1
        assert result[0].agent_id == "a1"

    def test_no_is_available_method(self):
        a1 = _make_agent(agent_id="a1", is_available=None)
        registry = _make_registry([a1])
        scheduler = AgentScheduler(registry)
        result = scheduler._get_available_agents()
        assert len(result) == 1

    def test_is_available_raises(self):
        a1 = _make_agent(agent_id="a1")
        a1.is_available = MagicMock(side_effect=RuntimeError("fail"))
        registry = _make_registry([a1])
        scheduler = AgentScheduler(registry)
        result = scheduler._get_available_agents()
        assert len(result) == 0

    def test_empty_registry(self):
        registry = _make_registry([])
        scheduler = AgentScheduler(registry)
        result = scheduler._get_available_agents()
        assert result == []


# ===================== _get_execution_phases =====================

class TestGetExecutionPhases:
    def _sched(self):
        return AgentScheduler(_make_registry())

    def test_no_deps(self):
        tg = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2")
        tg.add_task(t1)
        tg.add_task(t2)
        phases = self._sched()._get_execution_phases(tg)
        assert len(phases) == 1
        assert set(phases[0]) == {"t1", "t2"}

    def test_linear_deps(self):
        tg = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2", deps=["t1"])
        t3 = _make_task(task_id="t3", deps=["t2"])
        tg.add_task(t1)
        tg.add_task(t2)
        tg.add_task(t3)
        phases = self._sched()._get_execution_phases(tg)
        assert len(phases) == 3
        assert phases[0] == ["t1"]
        assert phases[1] == ["t2"]
        assert phases[2] == ["t3"]

    def test_diamond_deps(self):
        tg = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2", deps=["t1"])
        t3 = _make_task(task_id="t3", deps=["t1"])
        t4 = _make_task(task_id="t4", deps=["t2", "t3"])
        tg.add_task(t1)
        tg.add_task(t2)
        tg.add_task(t3)
        tg.add_task(t4)
        phases = self._sched()._get_execution_phases(tg)
        assert len(phases) == 3
        assert phases[0] == ["t1"]
        assert set(phases[1]) == {"t2", "t3"}
        assert phases[2] == ["t4"]

    def test_empty_graph(self):
        tg = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        phases = self._sched()._get_execution_phases(tg)
        assert phases == []


# ===================== _update_statistics =====================

class TestUpdateStatistics:
    def test_avg_execution_time(self):
        registry = _make_registry([_make_agent()])
        scheduler = AgentScheduler(registry)
        scheduler.stats.total_execution_time = 100.0
        task = _make_task()
        st = ScheduledTask(priority=5, created_at=datetime.now(), task=task)
        scheduler.completed_tasks.append(st)
        scheduler._update_statistics()
        assert scheduler.stats.avg_execution_time == 100.0

    def test_current_load(self):
        agents = [_make_agent(agent_id=f"a{i}") for i in range(2)]
        registry = _make_registry(agents)
        scheduler = AgentScheduler(registry)
        task = _make_task()
        st = ScheduledTask(
            priority=5, created_at=datetime.now(), task=task,
            assigned_agent=agents[0], status=AssignmentStatus.ASSIGNED,
        )
        scheduler.running_tasks["t1"] = st
        scheduler._update_statistics()
        # 2 agents * 10 = 20 capacity, 1 running = 0.05
        assert scheduler.stats.current_load == pytest.approx(0.05)

    def test_peak_load_tracking(self):
        agents = [_make_agent(agent_id="a1")]
        registry = _make_registry(agents)
        scheduler = AgentScheduler(registry)
        task = _make_task()
        for i in range(5):
            st = ScheduledTask(
                priority=5, created_at=datetime.now(), task=_make_task(task_id=f"t{i}"),
                assigned_agent=agents[0], status=AssignmentStatus.ASSIGNED,
            )
            scheduler.running_tasks[f"t{i}"] = st
        scheduler._update_statistics()
        assert scheduler.stats.peak_load == 0.5

    def test_agent_utilization(self):
        cap = _Cap(max_concurrent=10)
        agent = _make_agent(agent_id="a1", capabilities=cap)
        # Need capabilities set on agent properly for _agent_max_concurrency
        agent.capabilities = cap
        registry = _make_registry([agent])
        scheduler = AgentScheduler(registry)
        task = _make_task()
        st = ScheduledTask(
            priority=5, created_at=datetime.now(), task=task,
            assigned_agent=agent, status=AssignmentStatus.ASSIGNED,
        )
        scheduler.running_tasks["t1"] = st
        scheduler._update_statistics()
        assert scheduler.stats.agent_utilization.get("a1", 0) == pytest.approx(0.1)

    def test_no_completed_tasks(self):
        registry = _make_registry([_make_agent()])
        scheduler = AgentScheduler(registry)
        scheduler._update_statistics()
        assert scheduler.stats.avg_execution_time == 0.0


# ===================== mark_task_complete =====================

class TestMarkTaskComplete:
    def test_success(self):
        registry = _make_registry([_make_agent()])
        scheduler = AgentScheduler(registry)
        task = _make_task(task_id="t1")
        now = datetime.now()
        st = ScheduledTask(
            priority=5, created_at=now, task=task,
            status=AssignmentStatus.ASSIGNED, started_at=now,
        )
        scheduler.running_tasks["t1"] = st
        scheduler.mark_task_complete("t1", success=True)
        assert "t1" not in scheduler.running_tasks
        assert len(scheduler.completed_tasks) == 1
        assert scheduler.completed_tasks[0].status == AssignmentStatus.ASSIGNED

    def test_failure(self):
        registry = _make_registry([_make_agent()])
        scheduler = AgentScheduler(registry)
        task = _make_task(task_id="t1")
        now = datetime.now()
        st = ScheduledTask(
            priority=5, created_at=now, task=task,
            status=AssignmentStatus.ASSIGNED, started_at=now,
        )
        scheduler.running_tasks["t1"] = st
        scheduler.mark_task_complete("t1", success=False)
        assert scheduler.completed_tasks[0].status == AssignmentStatus.FAILED

    def test_missing_task(self):
        registry = _make_registry([_make_agent()])
        scheduler = AgentScheduler(registry)
        scheduler.mark_task_complete("nonexistent")
        assert len(scheduler.completed_tasks) == 0

    def test_duration_calculation(self):
        registry = _make_registry([_make_agent()])
        scheduler = AgentScheduler(registry)
        task = _make_task(task_id="t1")
        started = datetime(2024, 1, 1, 12, 0, 0)
        st = ScheduledTask(
            priority=5, created_at=started, task=task,
            status=AssignmentStatus.ASSIGNED, started_at=started,
        )
        scheduler.running_tasks["t1"] = st
        scheduler.mark_task_complete("t1")
        # completed_at is set to datetime.now(), which is after started
        assert scheduler.stats.total_execution_time > 0

    def test_no_started_at_no_duration(self):
        registry = _make_registry([_make_agent()])
        scheduler = AgentScheduler(registry)
        task = _make_task(task_id="t1")
        st = ScheduledTask(
            priority=5, created_at=datetime.now(), task=task,
            status=AssignmentStatus.ASSIGNED,
            started_at=None,  # no started_at
        )
        scheduler.running_tasks["t1"] = st
        scheduler.mark_task_complete("t1")
        # Should NOT add to total_execution_time because started_at is None
        # completed_at is set, but started_at is None
        assert scheduler.stats.total_execution_time == 0.0


# ===================== get_pending_tasks / get_running_tasks =====================

class TestGetTasks:
    def test_get_pending_tasks_empty(self):
        scheduler = AgentScheduler(_make_registry())
        assert scheduler.get_pending_tasks() == []

    def test_get_pending_tasks_with_items(self):
        scheduler = AgentScheduler(_make_registry())
        task = _make_task()
        st = ScheduledTask(priority=5, created_at=datetime.now(), task=task)
        scheduler.pending_tasks.append(st)
        result = scheduler.get_pending_tasks()
        assert len(result) == 1
        assert result[0] is st

    def test_get_running_tasks_empty(self):
        scheduler = AgentScheduler(_make_registry())
        assert scheduler.get_running_tasks() == []

    def test_get_running_tasks_with_items(self):
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(task_id="t1")
        st = ScheduledTask(priority=5, created_at=datetime.now(), task=task)
        scheduler.running_tasks["t1"] = st
        result = scheduler.get_running_tasks()
        assert len(result) == 1

    def test_get_statistics_returns_stats(self):
        scheduler = AgentScheduler(_make_registry([_make_agent()]))
        stats = scheduler.get_statistics()
        assert isinstance(stats, SchedulingStatistics)


# ===================== Scheduling strategies (async) =====================

class TestRoundRobinSchedule:
    def test_match_found(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._round_robin_schedule(task, [agent]))
        assert decision.selected_agent is agent
        assert decision.strategy == SchedulingStrategy.ROUND_ROBIN
        assert decision.confidence == 0.7

    def test_no_match(self):
        agent = _make_agent(supported_tools=["gobuster"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._round_robin_schedule(task, [agent]))
        assert decision.selected_agent is None
        assert decision.confidence == 0.0

    def test_empty_agents(self):
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._round_robin_schedule(task, []))
        assert decision.selected_agent is None

    def test_first_capable_selected(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["gobuster"])
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"])
        a3 = _make_agent(agent_id="a3", supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._round_robin_schedule(task, [a1, a2, a3]))
        assert decision.selected_agent.agent_id == "a2"


class TestLeastLoadedSchedule:
    def test_selects_least_loaded(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], current_tasks=5)
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"], current_tasks=1)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._least_loaded_schedule(task, [a1, a2]))
        assert decision.selected_agent.agent_id == "a2"

    def test_no_capable_agents(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["gobuster"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._least_loaded_schedule(task, [a1]))
        assert decision.selected_agent is None

    def test_empty_agents(self):
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._least_loaded_schedule(task, []))
        assert decision.selected_agent is None

    def test_confidence_is_0_8(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._least_loaded_schedule(task, [a1]))
        assert decision.confidence == 0.8

    def test_report_load_exception_handled(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], report_load_raises=True)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        # Should not raise, load defaults to 999
        decision = _run(scheduler._least_loaded_schedule(task, [a1]))
        assert decision.selected_agent is not None


class TestPrioritySchedule:
    def test_high_priority_task(self):
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.1)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap", priority=9)
        decision = _run(scheduler._priority_schedule(task, [agent]))
        assert decision.selected_agent is not None
        assert decision.confidence == 0.9

    def test_high_priority_task_high_load_filtered(self):
        # priority >= 8 and cpu_usage >= 0.7 => skip
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.8)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap", priority=8)
        decision = _run(scheduler._priority_schedule(task, [agent]))
        assert decision.selected_agent is None
        assert decision.confidence == 0.0

    def test_low_priority_not_filtered(self):
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.8)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap", priority=5)
        decision = _run(scheduler._priority_schedule(task, [agent]))
        assert decision.selected_agent is not None

    def test_no_capable_agents(self):
        agent = _make_agent(agent_id="a1", supported_tools=["gobuster"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap", priority=5)
        decision = _run(scheduler._priority_schedule(task, [agent]))
        assert decision.selected_agent is None

    def test_priority_bonus_in_scoring(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.1)
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"], cpu_usage=0.1)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap", priority=9)
        decision = _run(scheduler._priority_schedule(task, [a1, a2]))
        assert decision.selected_agent is not None


class TestCapabilitySchedule:
    def test_selects_best_match(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.5, success_rate=0.5)
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"], cpu_usage=0.0, success_rate=1.0)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._capability_schedule(task, [a1, a2]))
        assert decision.selected_agent.agent_id == "a2"

    def test_no_capable(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["gobuster"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._capability_schedule(task, [a1]))
        assert decision.selected_agent is None
        assert decision.confidence == 0.0

    def test_confidence_when_selected(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._capability_schedule(task, [a1]))
        assert decision.confidence == 0.9


class TestAdaptiveSchedule:
    def test_selects_best_score(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.5, success_rate=0.5)
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"], cpu_usage=0.0, success_rate=1.0)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._adaptive_schedule(task, [a1, a2]))
        assert decision.selected_agent.agent_id == "a2"
        assert decision.strategy == SchedulingStrategy.ADAPTIVE

    def test_no_capable_agents(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["gobuster"])
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._adaptive_schedule(task, [a1]))
        assert decision.selected_agent is None
        assert decision.confidence == 0.0

    def test_all_overloaded(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.9)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._adaptive_schedule(task, [a1]))
        assert decision.selected_agent is None
        assert "负载过高" in decision.reasoning[0]

    def test_load_exception_uses_fallback(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], report_load_raises=True)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        # report_load raises → fallback with current_tasks=999 → cpu_usage=1.0 → filtered
        decision = _run(scheduler._adaptive_schedule(task, [a1]))
        assert decision.selected_agent is None

    def test_confidence_clamped(self):
        # Score of 100 → confidence = min(100/100, 1.0) = 1.0
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"],
                           cpu_usage=0.0, current_tasks=0, success_rate=1.0)
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._adaptive_schedule(task, [agent]))
        assert decision.confidence <= 1.0

    def test_empty_agents(self):
        scheduler = AgentScheduler(_make_registry())
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler._adaptive_schedule(task, []))
        assert decision.selected_agent is None


# ===================== recommend_agent dispatch =====================

class TestRecommendAgent:
    def test_dispatches_adaptive(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ADAPTIVE)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.recommend_agent(task, [agent]))
        assert decision.strategy == SchedulingStrategy.ADAPTIVE

    def test_dispatches_least_loaded(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.LEAST_LOADED)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.recommend_agent(task, [agent]))
        assert decision.strategy == SchedulingStrategy.LEAST_LOADED

    def test_dispatches_priority_based(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.PRIORITY_BASED)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.recommend_agent(task, [agent]))
        assert decision.strategy == SchedulingStrategy.PRIORITY_BASED

    def test_dispatches_capability_match(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.CAPABILITY_MATCH)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.recommend_agent(task, [agent]))
        assert decision.strategy == SchedulingStrategy.CAPABILITY_MATCH

    def test_dispatches_round_robin(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.recommend_agent(task, [agent]))
        assert decision.strategy == SchedulingStrategy.ROUND_ROBIN

    def test_recommend_uses_registry_when_no_agents(self):
        agent = _make_agent(supported_tools=["nmap"])
        registry = _make_registry([agent])
        scheduler = AgentScheduler(registry, strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.recommend_agent(task, None))
        assert decision.selected_agent is not None

    def test_recommend_no_side_effects(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(tool_name="nmap")
        _run(scheduler.recommend_agent(task, [agent]))
        assert scheduler.stats.total_assignments == 0
        assert len(scheduler.history) == 0
        assert len(scheduler.running_tasks) == 0


# ===================== schedule_task =====================

class TestScheduleTask:
    def test_successful_assignment(self):
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry([agent]), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(task_id="t1", tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, [agent]))
        assert decision.selected_agent is agent
        assert "t1" in scheduler.running_tasks
        assert scheduler.stats.total_assignments == 1
        assert scheduler.stats.successful_assignments == 1
        assert len(scheduler.history) == 1

    def test_failed_assignment(self):
        agent = _make_agent(agent_id="a1", supported_tools=["gobuster"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(task_id="t1", tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, [agent]))
        assert decision.selected_agent is None
        assert "t1" not in scheduler.running_tasks
        assert scheduler.stats.failed_assignments == 1

    def test_uses_registry_when_no_agents_provided(self):
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"])
        registry = _make_registry([agent])
        scheduler = AgentScheduler(registry, strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.schedule_task(task))
        assert decision.selected_agent is not None

    def test_reasoning_populated(self):
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, [agent]))
        assert len(decision.reasoning) > 0


# ===================== schedule_batch =====================

class TestScheduleBatch:
    def test_sorts_by_priority(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        t1 = _make_task(task_id="t1", tool_name="nmap", priority=3)
        t2 = _make_task(task_id="t2", tool_name="nmap", priority=9)
        t3 = _make_task(task_id="t3", tool_name="nmap", priority=6)
        decisions = _run(scheduler.schedule_batch([t1, t2, t3], [agent]))
        assert len(decisions) == 3
        # All should succeed
        assert all(d.selected_agent is not None for d in decisions)

    def test_empty_tasks(self):
        scheduler = AgentScheduler(_make_registry())
        decisions = _run(scheduler.schedule_batch([], []))
        assert decisions == []

    def test_mixed_success_failure(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        t1 = _make_task(task_id="t1", tool_name="nmap", priority=5)
        t2 = _make_task(task_id="t2", tool_name="sqlmap", priority=5)
        decisions = _run(scheduler.schedule_batch([t1, t2], [agent]))
        successes = [d for d in decisions if d.selected_agent is not None]
        failures = [d for d in decisions if d.selected_agent is None]
        assert len(successes) == 1
        assert len(failures) == 1


# ===================== schedule_task_graph =====================

class TestScheduleTaskGraph:
    def test_basic_graph(self):
        agent = _make_agent(supported_tools=["nmap", "sqlmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        tg = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = _make_task(task_id="t1", tool_name="nmap")
        t2 = _make_task(task_id="t2", tool_name="sqlmap", deps=["t1"])
        tg.add_task(t1)
        tg.add_task(t2)
        decisions = _run(scheduler.schedule_task_graph(tg, [agent]))
        assert "t1" in decisions
        assert "t2" in decisions

    def test_empty_graph(self):
        scheduler = AgentScheduler(_make_registry())
        tg = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        decisions = _run(scheduler.schedule_task_graph(tg))
        assert decisions == {}


# ===================== Integration-like tests =====================

class TestSchedulerIntegration:
    def test_full_lifecycle(self):
        """Schedule → mark complete → check stats."""
        agent = _make_agent(agent_id="a1", supported_tools=["nmap"])
        registry = _make_registry([agent])
        scheduler = AgentScheduler(registry, strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(task_id="t1", tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, [agent]))
        assert decision.selected_agent is not None
        # Simulate start
        scheduler.running_tasks["t1"].started_at = datetime.now()
        scheduler.mark_task_complete("t1", success=True)
        assert len(scheduler.completed_tasks) == 1
        assert len(scheduler.running_tasks) == 0
        stats = scheduler.get_statistics()
        assert stats.total_assignments == 1
        assert stats.successful_assignments == 1

    def test_multiple_tasks_different_tools(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"])
        a2 = _make_agent(agent_id="a2", supported_tools=["sqlmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        t1 = _make_task(task_id="t1", tool_name="nmap")
        t2 = _make_task(task_id="t2", tool_name="sqlmap")
        d1 = _run(scheduler.schedule_task(t1, [a1, a2]))
        d2 = _run(scheduler.schedule_task(t2, [a1, a2]))
        assert d1.selected_agent.agent_id == "a1"
        assert d2.selected_agent.agent_id == "a2"

    def test_schedule_with_adaptive_and_multiple_agents(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"],
                        cpu_usage=0.7, current_tasks=5, success_rate=0.5)
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"],
                        cpu_usage=0.1, current_tasks=0, success_rate=0.9)
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ADAPTIVE)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, [a1, a2]))
        # a2 should win: lower load, higher success rate, idle
        assert decision.selected_agent.agent_id == "a2"

    def test_adaptive_with_only_overloaded_agents(self):
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], cpu_usage=0.9)
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"], cpu_usage=0.95)
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ADAPTIVE)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, [a1, a2]))
        assert decision.selected_agent is None
        assert scheduler.stats.failed_assignments == 1


# ===================== Edge cases =====================

class TestEdgeCases:
    def test_schedule_same_task_twice(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(task_id="t1", tool_name="nmap")
        _run(scheduler.schedule_task(task, [agent]))
        # Scheduling same task_id again overwrites
        _run(scheduler.schedule_task(task, [agent]))
        assert scheduler.stats.total_assignments == 2

    def test_mark_complete_then_schedule_same_id(self):
        agent = _make_agent(supported_tools=["nmap"])
        registry = _make_registry([agent])
        scheduler = AgentScheduler(registry, strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(task_id="t1", tool_name="nmap")
        _run(scheduler.schedule_task(task, [agent]))
        scheduler.running_tasks["t1"].started_at = datetime.now()
        scheduler.mark_task_complete("t1")
        # Re-schedule
        _run(scheduler.schedule_task(task, [agent]))
        assert "t1" in scheduler.running_tasks

    def test_agent_with_no_tools(self):
        agent = _make_agent(supported_tools=[])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ROUND_ROBIN)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, [agent]))
        assert decision.selected_agent is None

    def test_task_priority_zero(self):
        agent = _make_agent(supported_tools=["nmap"])
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.PRIORITY_BASED)
        task = _make_task(tool_name="nmap", priority=0)
        decision = _run(scheduler.schedule_task(task, [agent]))
        assert decision.selected_agent is not None

    def test_task_priority_ten(self):
        agent = _make_agent(supported_tools=["nmap"], cpu_usage=0.1)
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.PRIORITY_BASED)
        task = _make_task(tool_name="nmap", priority=10)
        decision = _run(scheduler.schedule_task(task, [agent]))
        assert decision.selected_agent is not None

    def test_many_agents_adaptive(self):
        agents = [
            _make_agent(agent_id=f"a{i}", supported_tools=["nmap"],
                       cpu_usage=i * 0.1, current_tasks=i, success_rate=1.0 - i * 0.1)
            for i in range(8)
        ]
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.ADAPTIVE)
        task = _make_task(tool_name="nmap")
        decision = _run(scheduler.schedule_task(task, agents))
        # a0 should win (lowest load, highest success rate)
        assert decision.selected_agent.agent_id == "a0"

    def test_least_loaded_with_exception_all_agents(self):
        """All agents raise on report_load."""
        a1 = _make_agent(agent_id="a1", supported_tools=["nmap"], report_load_raises=True)
        a2 = _make_agent(agent_id="a2", supported_tools=["nmap"], report_load_raises=True)
        scheduler = AgentScheduler(_make_registry(), strategy=SchedulingStrategy.LEAST_LOADED)
        task = _make_task(tool_name="nmap")
        # load defaults to 999, but least_loaded still picks one
        decision = _run(scheduler.schedule_task(task, [a1, a2]))
        assert decision.selected_agent is not None

    def test_empty_agents_all_strategies(self):
        for strategy in SchedulingStrategy:
            scheduler = AgentScheduler(_make_registry(), strategy=strategy)
            task = _make_task(tool_name="nmap")
            decision = _run(scheduler.schedule_task(task, []))
            assert decision.selected_agent is None
