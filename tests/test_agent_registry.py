"""
Tests for AgentRegistry, AgentState, AgentInfo, SelectionCriteria
(kali_mcp/core/agent_registry.py)

Covers:
- Fallback imports: stub LoadReport dataclass and AgentStatus enum
- AgentState enum: 9 states
- AgentInfo dataclass: creation and defaults
- SelectionCriteria dataclass: creation and defaults
- AgentRegistry class: registration, unregistration, querying,
  capability/tool indexing, agent selection/scoring, heartbeat,
  health checking, metrics, state management, dunder methods
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from kali_mcp.core.agent_registry import (
    AgentInfo,
    AgentRegistry,
    AgentState,
    LoadReport,
    SelectionCriteria,
)


# ===================== Mock Helpers =====================


def _make_load_report(load_pct: float = 0.0, **kwargs):
    """Create a LoadReport with sensible defaults."""
    defaults = dict(
        agent_id="mock",
        current_tasks=0,
        cpu_usage=0.0,
        memory_usage_mb=0.0,
        load_percentage=load_pct,
        available_capacity=10,
        status="ok",
    )
    defaults.update(kwargs)
    return LoadReport(**defaults)


class _Capability:
    """Minimal capability object with a .name and optional .supported_tools."""

    def __init__(self, name: str, tools: Optional[List[str]] = None):
        self.name = name
        self.supported_tools = tools or []


def make_agent(
    agent_id: str = "agent-1",
    name: str = "TestAgent",
    capabilities: Optional[List[_Capability]] = None,
    tools: Optional[List[str]] = None,
    load_pct: float = 0.0,
    use_get_capabilities: bool = True,
    use_get_supported_tools: bool = False,
    is_available: Optional[bool] = None,
    mesh_bus_supported: bool = False,
    report_load_raises: bool = False,
    get_perf_metrics: Optional[Dict] = None,
):
    """Build a mock agent with the attributes AgentRegistry inspects."""
    agent = MagicMock()
    agent.agent_id = agent_id
    agent.name = name

    caps = capabilities or [_Capability("general")]

    if use_get_capabilities:
        agent.get_capabilities = MagicMock(return_value=caps)
    else:
        del agent.get_capabilities  # force fallback to agent.capabilities
        agent.capabilities = caps

    if use_get_supported_tools and tools:
        agent.get_supported_tools = MagicMock(return_value=tools)
    elif tools:
        # put tools on the capabilities so the fallback path picks them up
        for cap in caps:
            cap.supported_tools = tools
        agent.get_supported_tools = MagicMock(return_value=tools)
    else:
        agent.get_supported_tools = MagicMock(return_value=[])

    if report_load_raises:
        agent.report_load = MagicMock(side_effect=RuntimeError("no load"))
    else:
        agent.report_load = MagicMock(return_value=_make_load_report(load_pct, agent_id=agent_id))

    if is_available is not None:
        agent.is_available = MagicMock(return_value=is_available)
    else:
        # no is_available attr — will still pass through get_available_agents
        del agent.is_available

    agent.get_status_summary = MagicMock(return_value={"mesh_bus_supported": mesh_bus_supported})
    agent.get_performance_metrics = MagicMock(return_value=get_perf_metrics or {})

    return agent


# ===================== Fallback Imports =====================


class TestFallbackImports:
    """Ensure either real or stub versions of LoadReport/AgentStatus are available."""

    def test_load_report_is_available(self):
        assert LoadReport is not None

    def test_load_report_can_be_instantiated(self):
        lr = LoadReport(agent_id="x")
        assert lr.agent_id == "x"
        assert lr.current_tasks == 0
        assert lr.cpu_usage == 0.0
        assert lr.memory_usage_mb == 0.0
        assert lr.load_percentage == 0.0
        assert lr.available_capacity == 0
        assert lr.status == "unknown"

    def test_load_report_custom_values(self):
        lr = LoadReport(agent_id="y", current_tasks=5, cpu_usage=75.0, load_percentage=60.0,
                        memory_usage_mb=512.0, available_capacity=3, status="busy")
        assert lr.current_tasks == 5
        assert lr.load_percentage == 60.0
        assert lr.status == "busy"

    def test_agent_status_is_importable(self):
        from kali_mcp.core.agent_registry import AgentStatus  # noqa: F811
        assert AgentStatus is not None

    def test_agent_status_has_idle(self):
        from kali_mcp.core.agent_registry import AgentStatus  # noqa: F811
        assert hasattr(AgentStatus, "IDLE")


# ===================== AgentState Enum =====================


class TestAgentState:
    """Verify all nine states and their string values."""

    EXPECTED = {
        "STARTING": "starting",
        "ACTIVE": "active",
        "BUSY": "busy",
        "IDLE": "idle",
        "OVERLOADED": "overloaded",
        "UNRESPONSIVE": "unresponsive",
        "STOPPING": "stopping",
        "STOPPED": "stopped",
        "ERROR": "error",
    }

    def test_state_count(self):
        assert len(AgentState) == 9

    @pytest.mark.parametrize("member,value", EXPECTED.items())
    def test_state_value(self, member, value):
        assert AgentState[member].value == value

    def test_states_are_unique(self):
        values = [s.value for s in AgentState]
        assert len(values) == len(set(values))

    def test_state_is_enum(self):
        from enum import Enum
        assert issubclass(AgentState, Enum)


# ===================== AgentInfo Dataclass =====================


class TestAgentInfo:
    def test_required_fields(self):
        now = datetime.now()
        info = AgentInfo(
            agent_id="a1", name="Agent1", state=AgentState.IDLE,
            capabilities=["scan"], supported_tools=["nmap"],
            registered_at=now, last_heartbeat=now,
        )
        assert info.agent_id == "a1"
        assert info.state == AgentState.IDLE
        assert info.capabilities == ["scan"]

    def test_default_optional_fields(self):
        now = datetime.now()
        info = AgentInfo(
            agent_id="a2", name="Agent2", state=AgentState.ACTIVE,
            capabilities=[], supported_tools=[],
            registered_at=now, last_heartbeat=now,
        )
        assert info.heartbeat_count == 0
        assert info.total_tasks == 0
        assert info.completed_tasks == 0
        assert info.failed_tasks == 0
        assert info.avg_task_duration == 0.0
        assert info.last_error is None
        assert info.metadata == {}

    def test_metadata_default_factory(self):
        now = datetime.now()
        info1 = AgentInfo("i1", "n1", AgentState.IDLE, [], [], now, now)
        info2 = AgentInfo("i2", "n2", AgentState.IDLE, [], [], now, now)
        info1.metadata["key"] = "val"
        assert "key" not in info2.metadata  # independent dicts

    def test_custom_values(self):
        now = datetime.now()
        info = AgentInfo(
            agent_id="a3", name="Agent3", state=AgentState.BUSY,
            capabilities=["web", "network"], supported_tools=["nmap", "nikto"],
            registered_at=now, last_heartbeat=now,
            heartbeat_count=10, total_tasks=50, completed_tasks=45,
            failed_tasks=5, avg_task_duration=12.5, last_error="timeout",
            metadata={"version": "2.0"},
        )
        assert info.total_tasks == 50
        assert info.avg_task_duration == 12.5
        assert info.metadata["version"] == "2.0"


# ===================== SelectionCriteria Dataclass =====================


class TestSelectionCriteria:
    def test_defaults(self):
        sc = SelectionCriteria()
        assert sc.capability is None
        assert sc.min_success_rate == 0.0
        assert sc.max_load_percentage == 100.0
        assert sc.prefer_idle is False
        assert sc.allow_overloaded is False
        assert sc.require_mesh_bus is False
        assert sc.tags is None

    def test_custom_values(self):
        sc = SelectionCriteria(
            capability="scan", min_success_rate=0.8,
            max_load_percentage=70.0, prefer_idle=True,
            allow_overloaded=True, require_mesh_bus=True,
            tags={"tag1", "tag2"},
        )
        assert sc.capability == "scan"
        assert sc.min_success_rate == 0.8
        assert sc.tags == {"tag1", "tag2"}


# ===================== AgentRegistry — Init =====================


class TestRegistryInit:
    def test_empty_state(self):
        reg = AgentRegistry()
        assert len(reg) == 0
        assert reg.get_all_agents() == []
        assert reg.list_agent_ids() == []

    def test_default_heartbeat_timeout(self):
        reg = AgentRegistry()
        assert reg.heartbeat_timeout == 60.0

    def test_custom_heartbeat_timeout(self):
        reg = AgentRegistry(heartbeat_timeout=120.0)
        assert reg.heartbeat_timeout == 120.0

    def test_initial_stats(self):
        reg = AgentRegistry()
        for key in ["total_registered", "total_unregistered", "total_heartbeats",
                     "failed_heartbeats", "selections", "selection_failures"]:
            assert reg.stats[key] == 0

    def test_lock_is_rlock(self):
        from threading import RLock
        reg = AgentRegistry()
        assert isinstance(reg._lock, type(RLock()))

    def test_repr_empty(self):
        reg = AgentRegistry()
        r = repr(reg)
        assert "AgentRegistry" in r
        assert "agents=0" in r
        assert "capabilities=0" in r


# ===================== AgentRegistry — Registration =====================


class TestRegistryRegister:
    def test_register_simple_agent(self):
        reg = AgentRegistry()
        agent = make_agent(agent_id="a1")
        assert reg.register_agent(agent) is True
        assert len(reg) == 1
        assert "a1" in reg

    def test_register_returns_false_without_agent_id(self):
        reg = AgentRegistry()
        obj = MagicMock(spec=[])  # no attributes at all
        assert reg.register_agent(obj) is False
        assert len(reg) == 0

    def test_register_increments_stats(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("x"))
        assert reg.stats["total_registered"] == 1

    def test_register_duplicate_replaces(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("dup", capabilities=[_Capability("cap1")]))
        reg.register_agent(make_agent("dup", capabilities=[_Capability("cap2")]))
        assert len(reg) == 1
        info = reg.get_agent_info("dup")
        assert "cap2" in info.capabilities

    def test_register_sets_state_starting(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        info = reg.get_agent_info("a1")
        assert info.state == AgentState.STARTING

    def test_register_uses_agent_name(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", name="MyName"))
        info = reg.get_agent_info("a1")
        assert info.name == "MyName"

    def test_register_extracts_capabilities_via_get_capabilities(self):
        reg = AgentRegistry()
        caps = [_Capability("scan"), _Capability("exploit")]
        reg.register_agent(make_agent("a1", capabilities=caps))
        info = reg.get_agent_info("a1")
        assert "scan" in info.capabilities
        assert "exploit" in info.capabilities

    def test_register_fallback_to_agent_capabilities_attr(self):
        reg = AgentRegistry()
        caps = [_Capability("fb_cap")]
        agent = make_agent("a1", capabilities=caps, use_get_capabilities=False)
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert "fb_cap" in info.capabilities

    def test_register_defaults_to_general_capability(self):
        """When capability objects have no .name, defaults to ['general']."""
        reg = AgentRegistry()
        agent = make_agent("a1")
        # Override: capabilities with no .name attribute
        nameless = MagicMock(spec=[])  # no name attr
        agent.get_capabilities = MagicMock(return_value=[nameless])
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert info.capabilities == ["general"]

    def test_register_get_capabilities_returns_tuple(self):
        reg = AgentRegistry()
        caps = (_Capability("tcp"),)
        agent = make_agent("a1")
        agent.get_capabilities = MagicMock(return_value=caps)
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert "tcp" in info.capabilities

    def test_register_get_capabilities_raises_falls_back(self):
        reg = AgentRegistry()
        agent = make_agent("a1", capabilities=[_Capability("fallback")])
        agent.get_capabilities = MagicMock(side_effect=RuntimeError("boom"))
        # fallback path reads agent.capabilities
        agent.capabilities = [_Capability("fallback")]
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert "fallback" in info.capabilities

    def test_register_builds_capability_index(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("web")]))
        reg.register_agent(make_agent("a2", capabilities=[_Capability("web"), _Capability("network")]))
        assert reg.find_agents_by_capability("web") != []
        assert len(reg.find_agents_by_capability("web")) == 2
        assert len(reg.find_agents_by_capability("network")) == 1

    def test_register_builds_tool_index(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", tools=["nmap", "nikto"]))
        assert len(reg.find_agents_by_tool("nmap")) == 1

    def test_register_extracts_tools_via_get_supported_tools(self):
        reg = AgentRegistry()
        agent = make_agent("a1", tools=["hydra"], use_get_supported_tools=True)
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert "hydra" in info.supported_tools

    def test_register_extracts_tools_from_capabilities_fallback(self):
        """When get_supported_tools returns empty, tools are read from capability objects."""
        reg = AgentRegistry()
        cap = _Capability("scan", tools=["masscan"])
        agent = make_agent("a1", capabilities=[cap])
        agent.get_supported_tools = MagicMock(return_value=[])
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert "masscan" in info.supported_tools

    def test_register_deduplicates_tools(self):
        reg = AgentRegistry()
        cap = _Capability("scan", tools=["nmap", "nmap", "nikto"])
        agent = make_agent("a1", capabilities=[cap])
        agent.get_supported_tools = MagicMock(return_value=[])
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert info.supported_tools.count("nmap") == 1


# ===================== AgentRegistry — Unregistration =====================


class TestRegistryUnregister:
    def test_unregister_existing(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert reg.unregister_agent("a1") is True
        assert len(reg) == 0
        assert "a1" not in reg

    def test_unregister_nonexistent(self):
        reg = AgentRegistry()
        assert reg.unregister_agent("no_such") is False

    def test_unregister_updates_stats(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.unregister_agent("a1")
        assert reg.stats["total_unregistered"] == 1

    def test_unregister_clears_capability_index(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")]))
        reg.unregister_agent("a1")
        assert reg.find_agents_by_capability("scan") == []
        assert "scan" not in reg.get_all_capabilities()

    def test_unregister_clears_tool_index(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", tools=["nmap"]))
        reg.unregister_agent("a1")
        assert reg.find_agents_by_tool("nmap") == []
        assert "nmap" not in reg.get_all_tools()

    def test_unregister_preserves_other_agents_in_index(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")]))
        reg.register_agent(make_agent("a2", capabilities=[_Capability("scan")]))
        reg.unregister_agent("a1")
        assert len(reg.find_agents_by_capability("scan")) == 1

    def test_unregister_after_double_register(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.register_agent(make_agent("a1"))  # re-register
        reg.unregister_agent("a1")
        assert len(reg) == 0


# ===================== AgentRegistry — Get / List =====================


class TestRegistryGetAndList:
    def test_get_agent_existing(self):
        reg = AgentRegistry()
        agent = make_agent("a1")
        reg.register_agent(agent)
        assert reg.get_agent("a1") is agent

    def test_get_agent_missing(self):
        reg = AgentRegistry()
        assert reg.get_agent("nope") is None

    def test_get_all_agents(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.register_agent(make_agent("a2"))
        assert len(reg.get_all_agents()) == 2

    def test_list_all_is_alias(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert reg.list_all() == reg.get_all_agents()

    def test_list_agent_ids(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.register_agent(make_agent("a2"))
        ids = reg.list_agent_ids()
        assert "a1" in ids
        assert "a2" in ids

    def test_get_available_agents_all_available(self):
        reg = AgentRegistry()
        # Agents without is_available are included
        reg.register_agent(make_agent("a1"))
        reg.register_agent(make_agent("a2"))
        assert len(reg.get_available_agents()) == 2

    def test_get_available_agents_filters_unavailable(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", is_available=True))
        reg.register_agent(make_agent("a2", is_available=False))
        avail = reg.get_available_agents()
        ids = [a.agent_id for a in avail]
        assert "a1" in ids
        assert "a2" not in ids

    def test_get_available_agents_is_available_raises(self):
        reg = AgentRegistry()
        agent = make_agent("a1")
        agent.is_available = MagicMock(side_effect=RuntimeError("err"))
        reg.register_agent(agent)
        # Agent with is_available raising exception is excluded
        assert len(reg.get_available_agents()) == 0


# ===================== AgentRegistry — Capability/Tool Queries =====================


class TestCapabilityToolQueries:
    def test_find_agents_by_capability(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("web")]))
        agents = reg.find_agents_by_capability("web")
        assert len(agents) == 1
        assert agents[0].agent_id == "a1"

    def test_find_agents_by_capability_missing(self):
        reg = AgentRegistry()
        assert reg.find_agents_by_capability("nonexistent") == []

    def test_find_agents_by_tool(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", tools=["sqlmap"]))
        agents = reg.find_agents_by_tool("sqlmap")
        assert len(agents) == 1

    def test_find_agents_by_tool_missing(self):
        reg = AgentRegistry()
        assert reg.find_agents_by_tool("nonexistent") == []

    def test_find_capable_agents_delegates(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("recon")]))
        agents = reg.find_capable_agents("recon")
        assert len(agents) == 1

    def test_get_all_capabilities(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("web"), _Capability("net")]))
        caps = reg.get_all_capabilities()
        assert "web" in caps
        assert "net" in caps

    def test_get_all_capabilities_empty(self):
        reg = AgentRegistry()
        assert reg.get_all_capabilities() == set()

    def test_get_all_tools(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", tools=["nmap", "nikto"]))
        tools = reg.get_all_tools()
        assert "nmap" in tools
        assert "nikto" in tools

    def test_get_all_tools_empty(self):
        reg = AgentRegistry()
        assert reg.get_all_tools() == set()

    def test_get_capability_summary(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")]))
        reg.register_agent(make_agent("a2", capabilities=[_Capability("scan"), _Capability("exploit")]))
        summary = reg.get_capability_summary()
        assert summary["scan"] == 2
        assert summary["exploit"] == 1

    def test_get_capability_summary_empty(self):
        reg = AgentRegistry()
        assert reg.get_capability_summary() == {}


# ===================== AgentRegistry — Agent Selection / Scoring =====================


class TestFindBestAgent:
    def test_find_best_returns_none_for_no_candidates(self):
        reg = AgentRegistry()
        assert reg.find_best_agent("nonexistent") is None

    def test_find_best_increments_selection_failures(self):
        reg = AgentRegistry()
        reg.find_best_agent("nonexistent")
        assert reg.stats["selection_failures"] >= 1

    def test_find_best_single_candidate(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=10.0))
        # heartbeat so it moves out of STARTING
        reg.heartbeat("a1")
        best = reg.find_best_agent("scan")
        assert best is not None
        assert best.agent_id == "a1"

    def test_find_best_prefers_lower_load(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("heavy", capabilities=[_Capability("scan")], load_pct=80.0))
        reg.register_agent(make_agent("light", capabilities=[_Capability("scan")], load_pct=10.0))
        reg.heartbeat("heavy")
        reg.heartbeat("light")
        best = reg.find_best_agent("scan")
        assert best.agent_id == "light"

    def test_find_best_increments_selections(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0))
        reg.heartbeat("a1")
        reg.find_best_agent("scan")
        assert reg.stats["selections"] >= 1

    def test_find_best_filters_stopped_agents(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0))
        reg.set_agent_state("a1", AgentState.STOPPED)
        assert reg.find_best_agent("scan") is None

    def test_find_best_filters_error_agents(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0))
        reg.set_agent_state("a1", AgentState.ERROR)
        assert reg.find_best_agent("scan") is None

    def test_find_best_filters_unresponsive(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0))
        reg.set_agent_state("a1", AgentState.UNRESPONSIVE)
        assert reg.find_best_agent("scan") is None

    def test_find_best_filters_overloaded_by_default(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0))
        reg.set_agent_state("a1", AgentState.OVERLOADED)
        assert reg.find_best_agent("scan") is None

    def test_find_best_allows_overloaded_when_criteria_says_so(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0))
        reg.set_agent_state("a1", AgentState.OVERLOADED)
        criteria = SelectionCriteria(allow_overloaded=True)
        best = reg.find_best_agent("scan", criteria)
        assert best is not None

    def test_find_best_respects_min_success_rate(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0))
        reg.heartbeat("a1")
        # Give it tasks with low success rate
        info = reg.get_agent_info("a1")
        info.total_tasks = 10
        info.completed_tasks = 3  # 30%
        info.failed_tasks = 7
        criteria = SelectionCriteria(min_success_rate=0.5)
        assert reg.find_best_agent("scan", criteria) is None

    def test_find_best_respects_max_load_percentage(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=80.0))
        reg.heartbeat("a1")
        criteria = SelectionCriteria(max_load_percentage=50.0)
        assert reg.find_best_agent("scan", criteria) is None

    def test_find_best_prefer_idle(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("active_a", capabilities=[_Capability("scan")], load_pct=10.0))
        reg.register_agent(make_agent("idle_a", capabilities=[_Capability("scan")], load_pct=10.0))
        reg.heartbeat("active_a")
        reg.heartbeat("idle_a")
        reg.set_agent_state("idle_a", AgentState.IDLE)
        criteria = SelectionCriteria(prefer_idle=True)
        best = reg.find_best_agent("scan", criteria)
        assert best.agent_id == "idle_a"

    def test_find_best_report_load_raises_skips_agent(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], report_load_raises=True))
        reg.heartbeat("a1")
        # filter calls report_load, which raises => agent filtered out
        assert reg.find_best_agent("scan") is None

    def test_find_best_require_mesh_bus(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0,
                                       mesh_bus_supported=False))
        reg.heartbeat("a1")
        criteria = SelectionCriteria(require_mesh_bus=True)
        assert reg.find_best_agent("scan", criteria) is None

    def test_find_best_require_mesh_bus_passes(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0,
                                       mesh_bus_supported=True))
        reg.heartbeat("a1")
        criteria = SelectionCriteria(require_mesh_bus=True)
        assert reg.find_best_agent("scan", criteria) is not None


class TestAgentScoring:
    """Tests for _calculate_agent_score logic."""

    def _score(self, reg, agent, criteria=None):
        return reg._calculate_agent_score(agent, criteria or SelectionCriteria())

    def test_score_zero_for_unknown_agent(self):
        reg = AgentRegistry()
        agent = make_agent("unknown")
        assert self._score(reg, agent) == 0.0

    def test_load_score_component_full_capacity(self):
        reg = AgentRegistry()
        agent = make_agent("a1", load_pct=0.0)
        reg.register_agent(agent)
        score = self._score(reg, agent)
        # load_score = 40 * (1 - 0/100) = 40
        assert score >= 40.0

    def test_load_score_component_full_load(self):
        reg = AgentRegistry()
        agent = make_agent("a1", load_pct=100.0)
        reg.register_agent(agent)
        score = self._score(reg, agent)
        # load_score = 40*(1-100/100) = 0
        # success_score = 15 (new agent default), idle bonus = 0 (STARTING), task bonus = 0
        assert score == pytest.approx(15.0, abs=1.0)

    def test_load_score_report_raises_gives_default(self):
        reg = AgentRegistry()
        agent = make_agent("a1", report_load_raises=True)
        reg.register_agent(agent)
        score = self._score(reg, agent)
        # load_score fallback = 20, success = 15, state bonus = 0, task bonus = 0
        assert score == pytest.approx(35.0, abs=1.0)

    def test_success_rate_score(self):
        reg = AgentRegistry()
        agent = make_agent("a1", load_pct=0.0)
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        info.total_tasks = 10
        info.completed_tasks = 10
        score = self._score(reg, agent)
        # load=40, success=30*1.0=30, state=0 (STARTING), task=min(10,10*0.5)=5
        assert score == pytest.approx(75.0, abs=1.0)

    def test_new_agent_gets_default_success_score(self):
        reg = AgentRegistry()
        agent = make_agent("a1", load_pct=0.0)
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert info.total_tasks == 0
        score = self._score(reg, agent)
        # success = 15 for new agent
        assert score >= 15.0

    def test_idle_state_gives_20_bonus(self):
        reg = AgentRegistry()
        agent = make_agent("a1", load_pct=0.0)
        reg.register_agent(agent)
        reg.set_agent_state("a1", AgentState.IDLE)
        score = self._score(reg, agent)
        # load=40, success=15, idle=20, tasks=0 => 75
        assert score == pytest.approx(75.0, abs=1.0)

    def test_active_state_gives_10_bonus(self):
        reg = AgentRegistry()
        agent = make_agent("a1", load_pct=0.0)
        reg.register_agent(agent)
        reg.set_agent_state("a1", AgentState.ACTIVE)
        score = self._score(reg, agent)
        # load=40, success=15, active=10, tasks=0 => 65
        assert score == pytest.approx(65.0, abs=1.0)

    def test_completed_tasks_bonus_capped_at_10(self):
        reg = AgentRegistry()
        agent = make_agent("a1", load_pct=0.0)
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        info.total_tasks = 100
        info.completed_tasks = 100
        score = self._score(reg, agent)
        # task_bonus = min(10, 100*0.5) = 10
        # load=40, success=30, state=0, tasks=10 => 80
        assert score == pytest.approx(80.0, abs=1.0)

    def test_rank_and_select_returns_none_for_empty(self):
        reg = AgentRegistry()
        assert reg._rank_and_select_agent([], SelectionCriteria()) is None

    def test_rank_and_select_picks_highest_score(self):
        reg = AgentRegistry()
        a1 = make_agent("a1", load_pct=80.0, capabilities=[_Capability("scan")])
        a2 = make_agent("a2", load_pct=10.0, capabilities=[_Capability("scan")])
        reg.register_agent(a1)
        reg.register_agent(a2)
        best = reg._rank_and_select_agent([a1, a2], SelectionCriteria())
        assert best.agent_id == "a2"


# ===================== AgentRegistry — Heartbeat =====================


class TestHeartbeat:
    def test_heartbeat_registered_agent(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert reg.heartbeat("a1") is True

    def test_heartbeat_unregistered_agent(self):
        reg = AgentRegistry()
        assert reg.heartbeat("unknown") is False

    def test_heartbeat_increments_count(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.heartbeat("a1")
        reg.heartbeat("a1")
        info = reg.get_agent_info("a1")
        assert info.heartbeat_count == 2

    def test_heartbeat_updates_last_heartbeat_time(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        before = reg.get_agent_info("a1").last_heartbeat
        time.sleep(0.01)
        reg.heartbeat("a1")
        after = reg.get_agent_info("a1").last_heartbeat
        assert after > before

    def test_heartbeat_transitions_starting_to_active(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert reg.get_agent_info("a1").state == AgentState.STARTING
        reg.heartbeat("a1")
        assert reg.get_agent_info("a1").state == AgentState.ACTIVE

    def test_heartbeat_transitions_unresponsive_to_active(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.set_agent_state("a1", AgentState.UNRESPONSIVE)
        reg.heartbeat("a1")
        assert reg.get_agent_info("a1").state == AgentState.ACTIVE

    def test_heartbeat_does_not_change_idle_to_active(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.set_agent_state("a1", AgentState.IDLE)
        reg.heartbeat("a1")
        assert reg.get_agent_info("a1").state == AgentState.IDLE

    def test_heartbeat_does_not_change_busy_to_active(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.set_agent_state("a1", AgentState.BUSY)
        reg.heartbeat("a1")
        assert reg.get_agent_info("a1").state == AgentState.BUSY

    def test_heartbeat_increments_stats(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.heartbeat("a1")
        assert reg.stats["total_heartbeats"] == 1


# ===================== AgentRegistry — Health Check =====================


class TestHealthCheck:
    def test_check_agent_health_healthy(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.heartbeat("a1")
        assert reg.check_agent_health("a1") is True

    def test_check_agent_health_unregistered(self):
        reg = AgentRegistry()
        assert reg.check_agent_health("nobody") is False

    def test_check_agent_health_timeout(self):
        reg = AgentRegistry(heartbeat_timeout=0.01)
        reg.register_agent(make_agent("a1"))
        time.sleep(0.02)
        assert reg.check_agent_health("a1") is False
        info = reg.get_agent_info("a1")
        assert info.state == AgentState.UNRESPONSIVE

    def test_check_agent_health_timeout_increments_stats(self):
        reg = AgentRegistry(heartbeat_timeout=0.01)
        reg.register_agent(make_agent("a1"))
        time.sleep(0.02)
        reg.check_agent_health("a1")
        assert reg.stats["failed_heartbeats"] >= 1

    def test_health_check_batch(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.register_agent(make_agent("a2"))
        reg.heartbeat("a1")
        reg.heartbeat("a2")
        results = reg.health_check()
        assert results["a1"] is True
        assert results["a2"] is True

    def test_health_check_batch_mixed(self):
        reg = AgentRegistry(heartbeat_timeout=0.01)
        reg.register_agent(make_agent("healthy"))
        reg.register_agent(make_agent("stale"))
        reg.heartbeat("healthy")
        reg.heartbeat("stale")
        time.sleep(0.02)
        reg.heartbeat("healthy")  # refresh healthy
        results = reg.health_check()
        assert results["healthy"] is True
        assert results["stale"] is False

    def test_health_check_empty_registry(self):
        reg = AgentRegistry()
        assert reg.health_check() == {}


# ===================== AgentRegistry — Agent Info / Status =====================


class TestAgentInfoAndStatus:
    def test_get_agent_info_existing(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        info = reg.get_agent_info("a1")
        assert info is not None
        assert isinstance(info, AgentInfo)

    def test_get_agent_info_missing(self):
        reg = AgentRegistry()
        assert reg.get_agent_info("nope") is None

    def test_get_agent_status_existing(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", load_pct=20.0, get_perf_metrics={"rps": 10}))
        reg.heartbeat("a1")
        status = reg.get_agent_status("a1")
        assert status is not None
        assert status["agent_id"] == "a1"
        assert "load" in status
        assert "performance" in status
        assert "heartbeat" in status

    def test_get_agent_status_missing(self):
        reg = AgentRegistry()
        assert reg.get_agent_status("nope") is None

    def test_get_agent_status_report_load_raises(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", report_load_raises=True))
        # report_load raises, get_agent_status returns None
        status = reg.get_agent_status("a1")
        assert status is None

    def test_get_agent_status_contains_load_details(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", load_pct=35.0))
        status = reg.get_agent_status("a1")
        assert status["load"]["load_percentage"] == 35.0

    def test_get_agent_status_success_rate_format(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        info = reg.get_agent_info("a1")
        info.total_tasks = 10
        info.completed_tasks = 7
        status = reg.get_agent_status("a1")
        assert status["performance"]["success_rate"] == "70.0%"

    def test_get_agent_status_success_rate_zero_tasks(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        status = reg.get_agent_status("a1")
        assert status["performance"]["success_rate"] == "0.0%"


# ===================== AgentRegistry — Registry Stats / Cluster Summary =====================


class TestRegistryStats:
    def test_get_registry_stats_empty(self):
        reg = AgentRegistry()
        stats = reg.get_registry_stats()
        assert stats["total_agents"] == 0
        assert stats["total_capabilities"] == 0
        assert stats["total_tools"] == 0
        assert stats["state_distribution"] == {}
        assert stats["monitoring_running"] is False

    def test_get_registry_stats_with_agents(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("web")], tools=["nmap"]))
        reg.register_agent(make_agent("a2", capabilities=[_Capability("web"), _Capability("net")]))
        stats = reg.get_registry_stats()
        assert stats["total_agents"] == 2
        assert stats["total_capabilities"] == 2  # web, net
        assert stats["total_tools"] >= 1
        assert stats["stats"]["total_registered"] == 2

    def test_get_registry_stats_state_distribution(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.register_agent(make_agent("a2"))
        reg.set_agent_state("a2", AgentState.IDLE)
        stats = reg.get_registry_stats()
        dist = stats["state_distribution"]
        assert dist.get("starting", 0) == 1
        assert dist.get("idle", 0) == 1


class TestClusterSummary:
    def test_cluster_summary_empty(self):
        reg = AgentRegistry()
        summary = reg.get_cluster_summary()
        assert summary["cluster_size"] == 0
        assert summary["agents"] == []
        assert "timestamp" in summary

    def test_cluster_summary_with_agents(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", load_pct=10.0, capabilities=[_Capability("scan")]))
        reg.heartbeat("a1")
        summary = reg.get_cluster_summary()
        assert summary["cluster_size"] == 1
        agent_entry = summary["agents"][0]
        assert agent_entry["agent_id"] == "a1"
        assert agent_entry["load_percentage"] == 10.0
        assert "healthy" in agent_entry

    def test_cluster_summary_report_load_raises_uses_zero(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", report_load_raises=True))
        summary = reg.get_cluster_summary()
        agent_entry = summary["agents"][0]
        assert agent_entry["load_percentage"] == 0
        assert agent_entry["available_capacity"] == 0


# ===================== AgentRegistry — Update Metrics =====================


class TestUpdateMetrics:
    def test_update_metrics_completed(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.update_agent_metrics("a1", task_completed=True, task_duration=5.0)
        info = reg.get_agent_info("a1")
        assert info.total_tasks == 1
        assert info.completed_tasks == 1
        assert info.failed_tasks == 0
        assert info.avg_task_duration == 5.0

    def test_update_metrics_failed(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.update_agent_metrics("a1", task_completed=False, task_duration=2.0)
        info = reg.get_agent_info("a1")
        assert info.total_tasks == 1
        assert info.completed_tasks == 0
        assert info.failed_tasks == 1

    def test_update_metrics_ema(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.update_agent_metrics("a1", task_completed=True, task_duration=10.0)
        assert reg.get_agent_info("a1").avg_task_duration == 10.0
        reg.update_agent_metrics("a1", task_completed=True, task_duration=20.0)
        # EMA: 10.0 * 0.9 + 20.0 * 0.1 = 9.0 + 2.0 = 11.0
        assert reg.get_agent_info("a1").avg_task_duration == pytest.approx(11.0)

    def test_update_metrics_first_task_sets_duration_directly(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.update_agent_metrics("a1", task_completed=True, task_duration=7.5)
        assert reg.get_agent_info("a1").avg_task_duration == 7.5

    def test_update_metrics_unknown_agent_is_noop(self):
        reg = AgentRegistry()
        # Should not raise
        reg.update_agent_metrics("nobody", task_completed=True, task_duration=1.0)

    def test_update_metrics_accumulation(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        for i in range(5):
            reg.update_agent_metrics("a1", task_completed=True, task_duration=1.0)
        for i in range(3):
            reg.update_agent_metrics("a1", task_completed=False, task_duration=1.0)
        info = reg.get_agent_info("a1")
        assert info.total_tasks == 8
        assert info.completed_tasks == 5
        assert info.failed_tasks == 3


# ===================== AgentRegistry — Set Agent State =====================


class TestSetAgentState:
    def test_set_state_success(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert reg.set_agent_state("a1", AgentState.BUSY) is True
        assert reg.get_agent_info("a1").state == AgentState.BUSY

    def test_set_state_nonexistent(self):
        reg = AgentRegistry()
        assert reg.set_agent_state("nobody", AgentState.ACTIVE) is False

    @pytest.mark.parametrize("state", list(AgentState))
    def test_set_every_state(self, state):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert reg.set_agent_state("a1", state) is True
        assert reg.get_agent_info("a1").state == state


# ===================== AgentRegistry — Dunder Methods =====================


class TestDunderMethods:
    def test_len_empty(self):
        reg = AgentRegistry()
        assert len(reg) == 0

    def test_len_after_register(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.register_agent(make_agent("a2"))
        assert len(reg) == 2

    def test_len_after_unregister(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.unregister_agent("a1")
        assert len(reg) == 0

    def test_contains_true(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert "a1" in reg

    def test_contains_false(self):
        reg = AgentRegistry()
        assert "a1" not in reg

    def test_repr_with_agents(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("web"), _Capability("net")]))
        r = repr(reg)
        assert "agents=1" in r
        assert "capabilities=2" in r


# ===================== AgentRegistry — Thread Safety =====================


class TestThreadSafety:
    """Verify that concurrent operations do not corrupt state."""

    def test_concurrent_register_unregister(self):
        import threading

        reg = AgentRegistry()
        errors = []

        def register_batch(start, count):
            try:
                for i in range(start, start + count):
                    reg.register_agent(make_agent(f"agent-{i}"))
            except Exception as e:
                errors.append(e)

        def unregister_batch(start, count):
            try:
                for i in range(start, start + count):
                    reg.unregister_agent(f"agent-{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for batch_start in range(0, 50, 10):
            t = threading.Thread(target=register_batch, args=(batch_start, 10))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(reg) == 50

        threads2 = []
        for batch_start in range(0, 50, 10):
            t = threading.Thread(target=unregister_batch, args=(batch_start, 10))
            threads2.append(t)

        for t in threads2:
            t.start()
        for t in threads2:
            t.join()

        assert not errors
        assert len(reg) == 0

    def test_concurrent_heartbeats(self):
        import threading

        reg = AgentRegistry()
        for i in range(10):
            reg.register_agent(make_agent(f"a-{i}"))

        errors = []

        def heartbeat_loop(agent_id, n):
            try:
                for _ in range(n):
                    reg.heartbeat(agent_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=heartbeat_loop, args=(f"a-{i}", 20)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        total_hb = sum(reg.get_agent_info(f"a-{i}").heartbeat_count for i in range(10))
        assert total_hb == 200


# ===================== Edge Cases =====================


class TestEdgeCases:
    def test_register_agent_without_name_uses_id(self):
        reg = AgentRegistry()
        agent = MagicMock()
        agent.agent_id = "anon"
        del agent.name  # no .name attribute
        agent.get_capabilities = MagicMock(return_value=[])
        agent.get_supported_tools = MagicMock(return_value=[])
        agent.report_load = MagicMock(return_value=_make_load_report())
        reg.register_agent(agent)
        info = reg.get_agent_info("anon")
        assert info.name == "anon"

    def test_register_agent_capabilities_single_non_list(self):
        """When fallback capabilities is a single non-list truthy value, wrap it."""
        reg = AgentRegistry()
        agent = MagicMock()
        agent.agent_id = "single"
        agent.name = "Single"
        del agent.get_capabilities  # force fallback
        agent.capabilities = "single_cap"  # truthy non-list
        agent.get_supported_tools = MagicMock(return_value=[])
        agent.report_load = MagicMock(return_value=_make_load_report())
        reg.register_agent(agent)
        # The code wraps non-list truthy fallback into [fallback_caps]
        # But "single_cap" string has no .name attribute → defaults to ["general"]
        info = reg.get_agent_info("single")
        assert "general" in info.capabilities

    def test_large_registry(self):
        reg = AgentRegistry()
        n = 200
        for i in range(n):
            reg.register_agent(make_agent(f"agent-{i}", capabilities=[_Capability("gen")]))
        assert len(reg) == n
        agents = reg.find_agents_by_capability("gen")
        assert len(agents) == n

    def test_multiple_capabilities_multiple_agents(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("web"), _Capability("scan")]))
        reg.register_agent(make_agent("a2", capabilities=[_Capability("scan"), _Capability("exploit")]))
        reg.register_agent(make_agent("a3", capabilities=[_Capability("exploit")]))

        assert len(reg.find_agents_by_capability("web")) == 1
        assert len(reg.find_agents_by_capability("scan")) == 2
        assert len(reg.find_agents_by_capability("exploit")) == 2

    def test_unregister_cleans_shared_capability_partially(self):
        """Unregistering one agent from a shared capability removes only that agent."""
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("shared")]))
        reg.register_agent(make_agent("a2", capabilities=[_Capability("shared")]))
        reg.unregister_agent("a1")
        agents = reg.find_agents_by_capability("shared")
        assert len(agents) == 1
        assert agents[0].agent_id == "a2"

    def test_register_agent_with_tools_attribute_on_capability(self):
        """Capability with .tools instead of .supported_tools."""
        reg = AgentRegistry()
        cap = MagicMock()
        cap.name = "net"
        cap.supported_tools = None
        cap.tools = ["traceroute", "ping"]
        agent = make_agent("a1", capabilities=[cap])
        agent.get_capabilities = MagicMock(return_value=[cap])
        agent.get_supported_tools = MagicMock(return_value=[])
        reg.register_agent(agent)
        info = reg.get_agent_info("a1")
        assert "traceroute" in info.supported_tools
        assert "ping" in info.supported_tools

    def test_stats_copy_in_get_registry_stats(self):
        """The stats dict returned should be a copy, not a reference."""
        reg = AgentRegistry()
        stats = reg.get_registry_stats()
        stats["stats"]["total_registered"] = 999
        assert reg.stats["total_registered"] == 0

    def test_heartbeat_then_health_check_resets_unresponsive(self):
        """After going unresponsive from timeout, a heartbeat revives the agent."""
        reg = AgentRegistry(heartbeat_timeout=0.01)
        reg.register_agent(make_agent("a1"))
        reg.heartbeat("a1")
        time.sleep(0.02)
        assert reg.check_agent_health("a1") is False
        assert reg.get_agent_info("a1").state == AgentState.UNRESPONSIVE
        # Now send heartbeat — should revive
        reg.heartbeat("a1")
        assert reg.get_agent_info("a1").state == AgentState.ACTIVE

    def test_set_state_preserves_other_info(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        reg.update_agent_metrics("a1", True, 5.0)
        reg.set_agent_state("a1", AgentState.BUSY)
        info = reg.get_agent_info("a1")
        assert info.state == AgentState.BUSY
        assert info.total_tasks == 1

    def test_double_unregister(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1"))
        assert reg.unregister_agent("a1") is True
        assert reg.unregister_agent("a1") is False

    def test_get_capability_summary_after_unregister(self):
        reg = AgentRegistry()
        reg.register_agent(make_agent("a1", capabilities=[_Capability("web")]))
        reg.unregister_agent("a1")
        summary = reg.get_capability_summary()
        assert "web" not in summary


# ===================== Filter Agents (internal method) =====================


class TestFilterAgents:
    def test_filter_excludes_no_info(self):
        reg = AgentRegistry()
        agent = make_agent("orphan")
        # Don't register — no info exists
        filtered = reg._filter_agents([agent], SelectionCriteria())
        assert len(filtered) == 0

    def test_filter_excludes_stopped(self):
        reg = AgentRegistry()
        agent = make_agent("a1", capabilities=[_Capability("scan")], load_pct=5.0)
        reg.register_agent(agent)
        for state in [AgentState.STOPPED, AgentState.ERROR, AgentState.UNRESPONSIVE]:
            reg.set_agent_state("a1", state)
            filtered = reg._filter_agents([agent], SelectionCriteria())
            assert len(filtered) == 0, f"Should have excluded state {state}"

    def test_filter_idle_agent_inserted_first_when_prefer_idle(self):
        reg = AgentRegistry()
        a1 = make_agent("active_a", capabilities=[_Capability("scan")], load_pct=5.0)
        a2 = make_agent("idle_a", capabilities=[_Capability("scan")], load_pct=5.0)
        reg.register_agent(a1)
        reg.register_agent(a2)
        reg.set_agent_state("active_a", AgentState.ACTIVE)
        reg.set_agent_state("idle_a", AgentState.IDLE)
        criteria = SelectionCriteria(prefer_idle=True)
        filtered = reg._filter_agents([a1, a2], criteria)
        assert filtered[0].agent_id == "idle_a"
