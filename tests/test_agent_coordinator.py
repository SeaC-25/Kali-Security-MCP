"""
Tests for CoordinatorAgent, CoordinatorState, CoordinatorExecutionPlan,
ExecutionSession, and helper methods.

Covers:
- CoordinatorState enum: all 9 members and values
- CoordinatorExecutionPlan dataclass: creation, defaults, properties
- ExecutionSession dataclass: creation, defaults, mutable default isolation
- CoordinatorAgent class: initialization, session management, statistics,
  process_request flow, _create_execution_plan, _execute_plan,
  _execute_single_task, _topological_sort, _infer_strategy_mode,
  _attach_strategy_constraint, _is_strategy_constrained_task,
  _select_stage_candidate_agents, make_decision, generate_report
"""

import asyncio
import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from unittest.mock import (
    AsyncMock,
    MagicMock,
    PropertyMock,
    patch,
    call,
)

import pytest

from kali_mcp.core.agent_coordinator import (
    CoordinatorAgent,
    CoordinatorExecutionPlan,
    CoordinatorState,
    ExecutionSession,
)
from kali_mcp.core.intent_analyzer import (
    AttackIntent,
    IntentAnalysis,
    TargetInfo,
    TargetType,
)
from kali_mcp.core.task_decomposer import (
    ExecutionPlan as DecomposerExecutionPlan,
    Task,
    TaskCategory,
    TaskGraph,
    TaskStatus,
)
from kali_mcp.core.agent_scheduler import (
    SchedulingDecision,
    SchedulingStatistics,
    SchedulingStrategy,
)
from kali_mcp.core.hybrid_decision_engine import (
    Decision,
    DecisionContext,
    DecisionLevel,
    DecisionOption,
    DecisionType,
    StrategicDecision,
    TacticalDecision,
)
from kali_mcp.core.result_aggregator import (
    AgentResult,
    AggregatedResult,
    Finding,
    ResultSeverity,
    ResultType,
)


# ===================== Helpers =====================

def _make_intent(
    intent: AttackIntent = AttackIntent.RECONNAISSANCE,
    user_input: str = "scan target",
    targets: Optional[List[TargetInfo]] = None,
    constraints: Optional[List] = None,
    confidence: float = 0.8,
) -> IntentAnalysis:
    if targets is None:
        targets = [
            TargetInfo(
                original="http://example.com",
                type=TargetType.URL,
                value="http://example.com",
            )
        ]
    return IntentAnalysis(
        user_input=user_input,
        intent=intent,
        targets=targets,
        constraints=constraints or [],
        priority=5,
        confidence=confidence,
    )


def _make_task(
    task_id: str = "task-1",
    name: str = "Test Task",
    category: TaskCategory = TaskCategory.SCANNING,
    tool_name: str = "nmap_scan",
    parameters: Optional[Dict] = None,
    dependencies: Optional[List[str]] = None,
    priority: int = 5,
) -> Task:
    if parameters is None:
        parameters = {"target": "10.0.0.1"}
    return Task(
        task_id=task_id,
        name=name,
        category=category,
        tool_name=tool_name,
        parameters=parameters,
        dependencies=dependencies or [],
        priority=priority,
    )


def _make_task_graph(tasks: Optional[List[Task]] = None) -> TaskGraph:
    tg = TaskGraph(tasks={})
    for t in (tasks or []):
        tg.add_task(t)
    return tg


def _make_decomposer_plan(
    task_graph: Optional[TaskGraph] = None,
    estimated_duration: int = 300,
) -> DecomposerExecutionPlan:
    tg = task_graph or _make_task_graph([_make_task()])
    return DecomposerExecutionPlan(
        task_graph=tg,
        phases=[list(tg.tasks.keys())],
        estimated_duration=estimated_duration,
        metadata={},
    )


def _make_decision_option(desc: str = "option") -> DecisionOption:
    return DecisionOption(
        option_id="opt-1",
        description=desc,
        actions=["action1"],
        expected_benefit=0.7,
        expected_cost=0.3,
        risk_level=0.2,
        confidence=0.8,
    )


def _make_strategic_decision() -> StrategicDecision:
    ctx = DecisionContext()
    return StrategicDecision(
        decision_id="dec-1",
        decision_type=DecisionType.ATTACK_PATH,
        decision_level=DecisionLevel.STRATEGIC,
        context=ctx,
        selected_option=_make_decision_option("strategic opt"),
        attack_strategy="full_recon",
    )


def _make_tactical_decision() -> TacticalDecision:
    ctx = DecisionContext()
    return TacticalDecision(
        decision_id="dec-2",
        decision_type=DecisionType.TOOL_SELECTION,
        decision_level=DecisionLevel.TACTICAL,
        context=ctx,
        selected_option=_make_decision_option("tactical opt"),
    )


def _make_agent_result(
    agent_id: str = "agent-1",
    task_id: str = "task-1",
    success: bool = True,
    execution_time: float = 1.5,
) -> AgentResult:
    return AgentResult(
        agent_id=agent_id,
        task_id=task_id,
        tool_name="nmap_scan",
        target="10.0.0.1",
        success=success,
        execution_time=execution_time,
        output="scan results",
    )


def _make_aggregated_result(
    intent: Optional[IntentAnalysis] = None,
    results: Optional[List[AgentResult]] = None,
) -> AggregatedResult:
    return AggregatedResult(
        intent_analysis=intent or _make_intent(),
        agent_results=results or [],
        unique_findings=[],
        extracted_flags=[],
    )


def _make_scheduling_decision(
    task: Optional[Task] = None,
    agent: Optional[Any] = None,
    confidence: float = 0.9,
) -> SchedulingDecision:
    return SchedulingDecision(
        task=task or _make_task(),
        selected_agent=agent,
        strategy=SchedulingStrategy.ADAPTIVE,
        confidence=confidence,
        reasoning=["matched"],
    )


def _make_scheduling_stats(**kwargs) -> SchedulingStatistics:
    defaults = dict(
        total_assignments=10,
        successful_assignments=8,
        failed_assignments=2,
        total_execution_time=100.0,
        avg_execution_time=10.0,
        current_load=0.5,
        peak_load=0.8,
    )
    defaults.update(kwargs)
    return SchedulingStatistics(**defaults)


def _make_mock_agent(agent_id: str = "agent-1"):
    agent = MagicMock()
    agent.agent_id = agent_id
    agent.execute_task = AsyncMock(return_value=_make_agent_result(agent_id=agent_id))
    return agent


def _make_mock_registry(agents=None):
    registry = MagicMock()
    agents = agents or []
    registry.get_all_agents.return_value = agents
    registry.get_available_agents.return_value = agents
    registry.get_agent.side_effect = lambda aid: next(
        (a for a in agents if getattr(a, "agent_id", None) == aid), None
    )
    registry.get_capability_summary.return_value = {}
    return registry


# ===================== CoordinatorState Tests =====================


class TestCoordinatorState:
    def test_idle_value(self):
        assert CoordinatorState.IDLE.value == "idle"

    def test_analyzing_value(self):
        assert CoordinatorState.ANALYZING.value == "analyzing"

    def test_decomposing_value(self):
        assert CoordinatorState.DECOMPOSING.value == "decomposing"

    def test_scheduling_value(self):
        assert CoordinatorState.SCHEDULING.value == "scheduling"

    def test_executing_value(self):
        assert CoordinatorState.EXECUTING.value == "executing"

    def test_aggregating_value(self):
        assert CoordinatorState.AGGREGATING.value == "aggregating"

    def test_deciding_value(self):
        assert CoordinatorState.DECIDING.value == "deciding"

    def test_completed_value(self):
        assert CoordinatorState.COMPLETED.value == "completed"

    def test_failed_value(self):
        assert CoordinatorState.FAILED.value == "failed"

    def test_all_members_count(self):
        assert len(CoordinatorState) == 9

    def test_from_value(self):
        assert CoordinatorState("idle") is CoordinatorState.IDLE
        assert CoordinatorState("failed") is CoordinatorState.FAILED

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            CoordinatorState("nonexistent")

    def test_members_are_unique(self):
        values = [s.value for s in CoordinatorState]
        assert len(values) == len(set(values))


# ===================== CoordinatorExecutionPlan Tests =====================


class TestCoordinatorExecutionPlan:
    def test_creation(self):
        intent = _make_intent()
        dp = _make_decomposer_plan()
        plan = CoordinatorExecutionPlan(
            plan_id="plan-1",
            intent_analysis=intent,
            decomposer_plan=dp,
            scheduling_decisions=[],
        )
        assert plan.plan_id == "plan-1"
        assert plan.intent_analysis is intent
        assert plan.decomposer_plan is dp
        assert plan.scheduling_decisions == []

    def test_required_agents_default(self):
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
        )
        assert isinstance(plan.required_agents, set)
        assert len(plan.required_agents) == 0

    def test_required_agents_mutable_isolation(self):
        p1 = CoordinatorExecutionPlan(
            plan_id="p1",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
        )
        p2 = CoordinatorExecutionPlan(
            plan_id="p2",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
        )
        p1.required_agents.add("x")
        assert "x" not in p2.required_agents

    def test_created_at_default(self):
        before = datetime.now()
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
        )
        after = datetime.now()
        assert before <= plan.created_at <= after

    def test_task_graph_property(self):
        tg = _make_task_graph([_make_task()])
        dp = _make_decomposer_plan(task_graph=tg)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[],
        )
        assert plan.task_graph is tg

    def test_estimated_duration_property(self):
        dp = _make_decomposer_plan(estimated_duration=600)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[],
        )
        assert plan.estimated_duration == 600

    def test_scheduling_decisions_list_isolation(self):
        p1 = CoordinatorExecutionPlan(
            plan_id="p1",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
        )
        p2 = CoordinatorExecutionPlan(
            plan_id="p2",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
        )
        # These are explicitly passed, not default_factory, so same ref is expected.
        # But plan-level test: they should at least be lists.
        assert isinstance(p1.scheduling_decisions, list)
        assert isinstance(p2.scheduling_decisions, list)


# ===================== ExecutionSession Tests =====================


class TestExecutionSession:
    def test_creation_required_fields(self):
        s = ExecutionSession(
            session_id="s1",
            user_input="scan 10.0.0.1",
            state=CoordinatorState.IDLE,
        )
        assert s.session_id == "s1"
        assert s.user_input == "scan 10.0.0.1"
        assert s.state is CoordinatorState.IDLE

    def test_optional_defaults(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        assert s.plan is None
        assert s.aggregated_result is None
        assert s.completed_at is None
        assert s.error is None
        assert s.total_tasks == 0
        assert s.completed_tasks == 0
        assert s.failed_tasks == 0

    def test_decisions_default_empty_list(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        assert isinstance(s.decisions, list)
        assert len(s.decisions) == 0

    def test_agent_results_default_empty_list(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        assert isinstance(s.agent_results, list)
        assert len(s.agent_results) == 0

    def test_mutable_defaults_isolation(self):
        s1 = ExecutionSession(
            session_id="s1", user_input="x", state=CoordinatorState.IDLE
        )
        s2 = ExecutionSession(
            session_id="s2", user_input="y", state=CoordinatorState.IDLE
        )
        s1.decisions.append("d")
        assert "d" not in s2.decisions
        s1.agent_results.append("r")
        assert "r" not in s2.agent_results

    def test_started_at_default(self):
        before = datetime.now()
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        after = datetime.now()
        assert before <= s.started_at <= after

    def test_state_assignment(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        s.state = CoordinatorState.EXECUTING
        assert s.state is CoordinatorState.EXECUTING

    def test_statistics_fields_mutate(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        s.total_tasks = 5
        s.completed_tasks = 3
        s.failed_tasks = 1
        assert s.total_tasks == 5
        assert s.completed_tasks == 3
        assert s.failed_tasks == 1


# ===================== CoordinatorAgent Init Tests =====================


class TestCoordinatorAgentInit:
    @patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner")
    @patch("kali_mcp.core.agent_coordinator.ResultAggregator")
    @patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine")
    @patch("kali_mcp.core.agent_coordinator.AgentScheduler")
    @patch("kali_mcp.core.agent_coordinator.TaskDecomposer")
    @patch("kali_mcp.core.agent_coordinator.IntentAnalyzer")
    def test_init_default_strategy(
        self, MockIA, MockTD, MockAS, MockHDE, MockRA, MockPCP
    ):
        registry = _make_mock_registry()
        coord = CoordinatorAgent(registry)
        assert coord.agent_registry is registry
        MockAS.assert_called_once_with(registry, SchedulingStrategy.ADAPTIVE)

    @patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner")
    @patch("kali_mcp.core.agent_coordinator.ResultAggregator")
    @patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine")
    @patch("kali_mcp.core.agent_coordinator.AgentScheduler")
    @patch("kali_mcp.core.agent_coordinator.TaskDecomposer")
    @patch("kali_mcp.core.agent_coordinator.IntentAnalyzer")
    def test_init_custom_strategy(
        self, MockIA, MockTD, MockAS, MockHDE, MockRA, MockPCP
    ):
        registry = _make_mock_registry()
        coord = CoordinatorAgent(registry, SchedulingStrategy.ROUND_ROBIN)
        MockAS.assert_called_once_with(registry, SchedulingStrategy.ROUND_ROBIN)

    @patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner")
    @patch("kali_mcp.core.agent_coordinator.ResultAggregator")
    @patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine")
    @patch("kali_mcp.core.agent_coordinator.AgentScheduler")
    @patch("kali_mcp.core.agent_coordinator.TaskDecomposer")
    @patch("kali_mcp.core.agent_coordinator.IntentAnalyzer")
    def test_init_state(
        self, MockIA, MockTD, MockAS, MockHDE, MockRA, MockPCP
    ):
        registry = _make_mock_registry()
        coord = CoordinatorAgent(registry)
        assert coord.sessions == {}
        assert coord.current_session_id is None
        assert coord.total_sessions == 0
        assert coord.successful_sessions == 0


# ===================== Session Management Tests =====================


class TestSessionManagement:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    def test_get_session_none_when_empty(self):
        coord = self._make_coordinator()
        assert coord.get_session("nonexistent") is None

    def test_get_session_returns_session(self):
        coord = self._make_coordinator()
        session = ExecutionSession(
            session_id="s1", user_input="test", state=CoordinatorState.IDLE
        )
        coord.sessions["s1"] = session
        assert coord.get_session("s1") is session

    def test_get_current_session_none_when_no_current(self):
        coord = self._make_coordinator()
        assert coord.get_current_session() is None

    def test_get_current_session_returns_current(self):
        coord = self._make_coordinator()
        session = ExecutionSession(
            session_id="s2", user_input="test", state=CoordinatorState.IDLE
        )
        coord.sessions["s2"] = session
        coord.current_session_id = "s2"
        assert coord.get_current_session() is session

    def test_get_current_session_id_not_in_sessions(self):
        coord = self._make_coordinator()
        coord.current_session_id = "missing"
        assert coord.get_current_session() is None


# ===================== _infer_strategy_mode Tests =====================


class TestInferStrategyMode:
    def test_ctf_solving(self):
        intent = _make_intent(intent=AttackIntent.CTF_SOLVING)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "ctf"

    def test_reconnaissance(self):
        intent = _make_intent(intent=AttackIntent.RECONNAISSANCE)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "recon"

    def test_coverage_analysis(self):
        intent = _make_intent(intent=AttackIntent.COVERAGE_ANALYSIS)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "recon"

    def test_exploitation(self):
        intent = _make_intent(intent=AttackIntent.EXPLOITATION)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"

    def test_full_compromise(self):
        intent = _make_intent(intent=AttackIntent.FULL_COMPROMISE)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"

    def test_apt_simulation(self):
        intent = _make_intent(intent=AttackIntent.APT_SIMULATION)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"

    def test_lateral_movement(self):
        intent = _make_intent(intent=AttackIntent.LATERAL_MOVEMENT)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"

    def test_vulnerability_scanning_defaults_pentest(self):
        intent = _make_intent(intent=AttackIntent.VULNERABILITY_SCANNING)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"

    def test_privilege_escalation_defaults_pentest(self):
        intent = _make_intent(intent=AttackIntent.PRIVILEGE_ESCALATION)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"

    def test_data_exfiltration_defaults_pentest(self):
        intent = _make_intent(intent=AttackIntent.DATA_EXFILTRATION)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"

    def test_persistence_defaults_pentest(self):
        intent = _make_intent(intent=AttackIntent.PERSISTENCE)
        assert CoordinatorAgent._infer_strategy_mode(intent) == "pentest"


# ===================== _is_strategy_constrained_task Tests =====================


class TestIsStrategyConstrainedTask:
    def test_with_strategy_stage_index(self):
        task = _make_task(parameters={"strategy_stage_index": 0, "target": "x"})
        assert CoordinatorAgent._is_strategy_constrained_task(task) is True

    def test_without_strategy_stage_index(self):
        task = _make_task(parameters={"target": "x"})
        assert CoordinatorAgent._is_strategy_constrained_task(task) is False

    def test_empty_parameters(self):
        task = _make_task(parameters={})
        assert CoordinatorAgent._is_strategy_constrained_task(task) is False


# ===================== _select_stage_candidate_agents Tests =====================


class TestSelectStageCandidateAgents:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    def test_non_strategy_constrained_returns_all(self):
        coord = self._make_coordinator()
        agents = [_make_mock_agent("a1"), _make_mock_agent("a2")]
        task = _make_task(parameters={"target": "x"})
        result = coord._select_stage_candidate_agents(task, agents)
        assert result is agents

    def test_strategy_constrained_with_preferred(self):
        coord = self._make_coordinator()
        a1 = _make_mock_agent("a1")
        a2 = _make_mock_agent("a2")
        a3 = _make_mock_agent("a3")
        agents = [a1, a2, a3]
        task = _make_task(
            parameters={
                "strategy_stage_index": 0,
                "strategy_preferred_agents": ["a2", "a3"],
                "target": "x",
            }
        )
        result = coord._select_stage_candidate_agents(task, agents)
        ids = [a.agent_id for a in result]
        assert "a2" in ids
        assert "a3" in ids
        assert "a1" not in ids

    def test_strategy_constrained_no_preferred(self):
        coord = self._make_coordinator()
        agents = [_make_mock_agent("a1")]
        task = _make_task(parameters={"strategy_stage_index": 0, "target": "x"})
        result = coord._select_stage_candidate_agents(task, agents)
        assert result is agents

    def test_strategy_constrained_empty_preferred_list(self):
        coord = self._make_coordinator()
        agents = [_make_mock_agent("a1")]
        task = _make_task(
            parameters={
                "strategy_stage_index": 0,
                "strategy_preferred_agents": [],
                "target": "x",
            }
        )
        result = coord._select_stage_candidate_agents(task, agents)
        assert result is agents

    def test_strategy_constrained_preferred_not_list(self):
        coord = self._make_coordinator()
        agents = [_make_mock_agent("a1")]
        task = _make_task(
            parameters={
                "strategy_stage_index": 0,
                "strategy_preferred_agents": "not_a_list",
                "target": "x",
            }
        )
        result = coord._select_stage_candidate_agents(task, agents)
        assert result is agents

    def test_strategy_constrained_preferred_no_match(self):
        coord = self._make_coordinator()
        agents = [_make_mock_agent("a1")]
        task = _make_task(
            parameters={
                "strategy_stage_index": 0,
                "strategy_preferred_agents": ["nonexistent"],
                "target": "x",
            }
        )
        result = coord._select_stage_candidate_agents(task, agents)
        assert result == []


# ===================== _topological_sort Tests =====================


class TestTopologicalSort:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    def test_single_task(self):
        coord = self._make_coordinator()
        t1 = _make_task(task_id="t1")
        tg = _make_task_graph([t1])
        result = coord._topological_sort(tg)
        assert result == ["t1"]

    def test_linear_dependencies(self):
        coord = self._make_coordinator()
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2", dependencies=["t1"])
        t3 = _make_task(task_id="t3", dependencies=["t2"])
        tg = _make_task_graph([t1, t2, t3])
        result = coord._topological_sort(tg)
        assert result.index("t1") < result.index("t2")
        assert result.index("t2") < result.index("t3")

    def test_diamond_dependencies(self):
        coord = self._make_coordinator()
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2", dependencies=["t1"])
        t3 = _make_task(task_id="t3", dependencies=["t1"])
        t4 = _make_task(task_id="t4", dependencies=["t2", "t3"])
        tg = _make_task_graph([t1, t2, t3, t4])
        result = coord._topological_sort(tg)
        assert result.index("t1") < result.index("t2")
        assert result.index("t1") < result.index("t3")
        assert result.index("t2") < result.index("t4")
        assert result.index("t3") < result.index("t4")

    def test_no_dependencies_all_present(self):
        coord = self._make_coordinator()
        tasks = [_make_task(task_id=f"t{i}") for i in range(5)]
        tg = _make_task_graph(tasks)
        result = coord._topological_sort(tg)
        assert set(result) == {f"t{i}" for i in range(5)}

    def test_circular_dependency_raises(self):
        coord = self._make_coordinator()
        t1 = _make_task(task_id="t1", dependencies=["t2"])
        t2 = _make_task(task_id="t2", dependencies=["t1"])
        tg = _make_task_graph([t1, t2])
        with pytest.raises(ValueError, match="循环依赖"):
            coord._topological_sort(tg)

    def test_self_loop_raises(self):
        coord = self._make_coordinator()
        t1 = _make_task(task_id="t1", dependencies=["t1"])
        tg = _make_task_graph([t1])
        with pytest.raises(ValueError, match="循环依赖"):
            coord._topological_sort(tg)

    def test_empty_graph(self):
        coord = self._make_coordinator()
        tg = _make_task_graph([])
        result = coord._topological_sort(tg)
        assert result == []


# ===================== _attach_strategy_constraint Tests =====================


class TestAttachStrategyConstraint:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner") as MockPCP:
            coord = CoordinatorAgent(_make_mock_registry())
            # The planner mock was already set
            return coord

    def test_appends_strategy_constraint(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {"stages": []}
        intent = _make_intent(constraints=[])
        result = coord._attach_strategy_constraint(intent)
        assert any(
            isinstance(c, dict) and c.get("type") == "execution_strategy"
            for c in result.constraints
        )

    def test_removes_old_execution_strategy(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {"stages": []}
        old_constraint = {"type": "execution_strategy", "source": "old"}
        intent = _make_intent(constraints=[old_constraint])
        result = coord._attach_strategy_constraint(intent)
        strategies = [
            c for c in result.constraints
            if isinstance(c, dict) and c.get("type") == "execution_strategy"
        ]
        assert len(strategies) == 1
        assert strategies[0]["source"] == "coordinator"

    def test_removes_strategy_blueprint_constraint(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        old = {"type": "strategy_blueprint", "data": "x"}
        intent = _make_intent(constraints=[old, "keep_me"])
        result = coord._attach_strategy_constraint(intent)
        assert "keep_me" in result.constraints
        assert old not in result.constraints

    def test_removes_pentest_strategy_constraint(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        old = {"type": "pentest_strategy", "data": "x"}
        intent = _make_intent(constraints=[old])
        result = coord._attach_strategy_constraint(intent)
        non_exec = [
            c for c in result.constraints
            if isinstance(c, dict) and c.get("type") == "pentest_strategy"
        ]
        assert len(non_exec) == 0

    def test_preserves_non_strategy_constraints(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        keep = {"type": "scope", "value": "internal"}
        intent = _make_intent(constraints=[keep, "string_constraint"])
        result = coord._attach_strategy_constraint(intent)
        assert keep in result.constraints
        assert "string_constraint" in result.constraints

    def test_uses_first_target_value(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        target1 = TargetInfo(
            original="http://t1.com", type=TargetType.URL, value="http://t1.com"
        )
        target2 = TargetInfo(
            original="http://t2.com", type=TargetType.URL, value="http://t2.com"
        )
        intent = _make_intent(targets=[target1, target2])
        coord._attach_strategy_constraint(intent)
        call_args = coord.strategy_planner.build_strategy.call_args
        assert call_args.kwargs.get("target") == "http://t1.com" or \
               call_args[1].get("target") == "http://t1.com" or \
               (len(call_args[0]) > 0 and call_args[0][0] == "http://t1.com")

    def test_no_targets_uses_user_input(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        intent = _make_intent(targets=[], user_input="scan 192.168.1.1")
        coord._attach_strategy_constraint(intent)
        call_args = coord.strategy_planner.build_strategy.call_args
        # The target should be derived from user_input
        assert "scan 192.168.1.1" in str(call_args)

    def test_no_targets_no_input_uses_unknown(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        intent = _make_intent(targets=[], user_input="")
        coord._attach_strategy_constraint(intent)
        call_args = coord.strategy_planner.build_strategy.call_args
        assert "unknown-target" in str(call_args)

    def test_none_constraints_handled(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        intent = _make_intent(constraints=None)
        intent.constraints = None
        result = coord._attach_strategy_constraint(intent)
        assert isinstance(result.constraints, list)

    def test_case_insensitive_type_filtering(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        old = {"type": "Execution_Strategy", "source": "old"}
        intent = _make_intent(constraints=[old])
        result = coord._attach_strategy_constraint(intent)
        exec_strats = [
            c for c in result.constraints
            if isinstance(c, dict) and str(c.get("type", "")).lower() == "execution_strategy"
        ]
        # Should have exactly 1 (the new one from coordinator)
        assert len(exec_strats) == 1
        assert exec_strats[0]["source"] == "coordinator"


# ===================== _execute_single_task Tests =====================


class TestExecuteSingleTask:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry(agents or []))

    @pytest.mark.asyncio
    async def test_agent_not_found_raises(self):
        coord = self._make_coordinator()
        task = _make_task()
        with pytest.raises(ValueError, match="不存在"):
            await coord._execute_single_task(task, "nonexistent")

    @pytest.mark.asyncio
    async def test_successful_execution(self):
        agent = _make_mock_agent("a1")
        expected_result = _make_agent_result(agent_id="a1")
        agent.execute_task = AsyncMock(return_value=expected_result)
        coord = self._make_coordinator([agent])
        task = _make_task()
        result = await coord._execute_single_task(task, "a1")
        assert result.agent_id == "a1"
        assert result.success is True
        assert result.execution_time >= 0

    @pytest.mark.asyncio
    async def test_execution_failure_returns_error_result(self):
        agent = _make_mock_agent("a1")
        agent.execute_task = AsyncMock(side_effect=RuntimeError("tool crash"))
        coord = self._make_coordinator([agent])
        task = _make_task()
        result = await coord._execute_single_task(task, "a1")
        assert result.success is False
        assert "tool crash" in result.errors[0]
        assert result.agent_id == "a1"

    @pytest.mark.asyncio
    async def test_execution_sets_time(self):
        agent = _make_mock_agent("a1")
        result = _make_agent_result(agent_id="a1")
        result.execution_time = 0
        agent.execute_task = AsyncMock(return_value=result)
        coord = self._make_coordinator([agent])
        task = _make_task()
        returned = await coord._execute_single_task(task, "a1")
        assert returned.execution_time >= 0


# ===================== _execute_plan Tests =====================


class TestExecutePlan:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler") as MockAS, \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            coord = CoordinatorAgent(_make_mock_registry(agents or []))
            coord.agent_scheduler.mark_task_complete = MagicMock()
            return coord

    @pytest.mark.asyncio
    async def test_no_decision_produces_failure_result(self):
        coord = self._make_coordinator()
        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[],  # no decisions
        )
        results = await coord._execute_plan(plan)
        assert len(results) == 1
        assert results[0].success is False
        assert "coordinator" == results[0].agent_id

    @pytest.mark.asyncio
    async def test_decision_no_agent_produces_failure(self):
        coord = self._make_coordinator()
        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        dec = _make_scheduling_decision(task=task, agent=None)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec],
        )
        results = await coord._execute_plan(plan)
        assert len(results) == 1
        assert results[0].success is False

    @pytest.mark.asyncio
    async def test_successful_plan_execution(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        dec = _make_scheduling_decision(task=task, agent=agent)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec],
        )
        results = await coord._execute_plan(plan)
        assert len(results) == 1
        assert results[0].success is True
        coord.agent_scheduler.mark_task_complete.assert_called_once()

    @pytest.mark.asyncio
    async def test_execution_exception_handled(self):
        agent = _make_mock_agent("a1")
        agent.execute_task = AsyncMock(side_effect=RuntimeError("boom"))
        coord = self._make_coordinator([agent])
        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        dec = _make_scheduling_decision(task=task, agent=agent)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec],
        )
        results = await coord._execute_plan(plan)
        assert len(results) == 1
        assert results[0].success is False
        assert "boom" in results[0].errors[0]

    @pytest.mark.asyncio
    async def test_decision_reasoning_in_failure_message(self):
        coord = self._make_coordinator()
        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        dec = _make_scheduling_decision(task=task, agent=None)
        dec.reasoning = ["no capable agent", "all busy"]
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec],
        )
        results = await coord._execute_plan(plan)
        assert "no capable agent" in results[0].errors[0]
        assert "all busy" in results[0].errors[0]


# ===================== _create_execution_plan Tests =====================


class TestCreateExecutionPlan:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry(agents or []))

    @pytest.mark.asyncio
    async def test_creates_plan_with_id(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        coord.agent_scheduler.schedule_task = AsyncMock(
            return_value=_make_scheduling_decision(agent=agent)
        )
        intent = _make_intent()
        dp = _make_decomposer_plan()
        plan = await coord._create_execution_plan(intent, dp)
        assert plan.plan_id.startswith("plan_")
        assert plan.intent_analysis is intent
        assert plan.decomposer_plan is dp

    @pytest.mark.asyncio
    async def test_fallback_assignment(self):
        agent = _make_mock_agent("fallback")
        coord = self._make_coordinator([agent])
        # schedule_task returns no selected agent
        dec_no_agent = _make_scheduling_decision(agent=None)
        coord.agent_scheduler.schedule_task = AsyncMock(return_value=dec_no_agent)
        coord.agent_scheduler.strategy = SchedulingStrategy.ADAPTIVE
        intent = _make_intent()
        task = _make_task(parameters={"target": "x"})  # No strategy_stage_index
        dp = _make_decomposer_plan(task_graph=_make_task_graph([task]))
        plan = await coord._create_execution_plan(intent, dp)
        # Should have fallback agent
        assert any(
            d.selected_agent is not None for d in plan.scheduling_decisions
        )

    @pytest.mark.asyncio
    async def test_strategy_constrained_no_fallback(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        dec_no_agent = _make_scheduling_decision(agent=None)
        coord.agent_scheduler.schedule_task = AsyncMock(return_value=dec_no_agent)
        coord.agent_scheduler.strategy = SchedulingStrategy.ADAPTIVE
        intent = _make_intent()
        # Task IS strategy-constrained
        task = _make_task(
            parameters={"strategy_stage_index": 0, "target": "x"}
        )
        dp = _make_decomposer_plan(task_graph=_make_task_graph([task]))
        plan = await coord._create_execution_plan(intent, dp)
        # Should NOT get fallback for strategy-constrained tasks
        for d in plan.scheduling_decisions:
            if d.task.task_id == task.task_id:
                assert d.selected_agent is None

    @pytest.mark.asyncio
    async def test_required_agents_populated(self):
        a1 = _make_mock_agent("a1")
        a2 = _make_mock_agent("a2")
        coord = self._make_coordinator([a1, a2])
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2")
        tg = _make_task_graph([t1, t2])
        dp = _make_decomposer_plan(task_graph=tg)
        coord.agent_scheduler.schedule_task = AsyncMock(
            side_effect=[
                _make_scheduling_decision(task=t1, agent=a1),
                _make_scheduling_decision(task=t2, agent=a2),
            ]
        )
        intent = _make_intent()
        plan = await coord._create_execution_plan(intent, dp)
        assert "a1" in plan.required_agents
        assert "a2" in plan.required_agents

    @pytest.mark.asyncio
    async def test_tasks_sorted_by_stage_and_priority(self):
        coord = self._make_coordinator([_make_mock_agent("a1")])
        t1 = _make_task(
            task_id="t1",
            priority=3,
            parameters={"strategy_stage_index": 1, "target": "x"},
        )
        t2 = _make_task(
            task_id="t2",
            priority=9,
            parameters={"strategy_stage_index": 0, "target": "x"},
        )
        tg = _make_task_graph([t1, t2])
        dp = _make_decomposer_plan(task_graph=tg)
        call_order = []
        async def track_schedule(task, agents):
            call_order.append(task.task_id)
            return _make_scheduling_decision(task=task, agent=_make_mock_agent("a1"))
        coord.agent_scheduler.schedule_task = track_schedule
        await coord._create_execution_plan(_make_intent(), dp)
        # t2 has stage_index 0, t1 has stage_index 1, so t2 first
        assert call_order[0] == "t2"
        assert call_order[1] == "t1"


# ===================== get_statistics Tests =====================


class TestGetStatistics:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry([_make_mock_agent()]))

    def test_returns_dict_with_sections(self):
        coord = self._make_coordinator()
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        assert "coordinator" in stats
        assert "scheduler" in stats
        assert "decision_engine" in stats
        assert "agent_registry" in stats

    def test_coordinator_stats_zero_sessions(self):
        coord = self._make_coordinator()
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        assert stats["coordinator"]["total_sessions"] == 0
        assert stats["coordinator"]["success_rate"] == 0

    def test_coordinator_stats_with_sessions(self):
        coord = self._make_coordinator()
        coord.total_sessions = 10
        coord.successful_sessions = 7
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        assert stats["coordinator"]["success_rate"] == 0.7

    def test_active_sessions_counted(self):
        coord = self._make_coordinator()
        coord.sessions["s1"] = ExecutionSession(
            session_id="s1", user_input="x", state=CoordinatorState.EXECUTING
        )
        coord.sessions["s2"] = ExecutionSession(
            session_id="s2", user_input="y", state=CoordinatorState.COMPLETED
        )
        coord.sessions["s3"] = ExecutionSession(
            session_id="s3", user_input="z", state=CoordinatorState.FAILED
        )
        coord.sessions["s4"] = ExecutionSession(
            session_id="s4", user_input="w", state=CoordinatorState.ANALYZING
        )
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        # s1 and s4 are active (not completed/failed)
        assert stats["coordinator"]["active_sessions"] == 2


# ===================== generate_report Tests =====================


class TestGenerateReport:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    @pytest.mark.asyncio
    async def test_nonexistent_session_raises(self):
        coord = self._make_coordinator()
        with pytest.raises(ValueError, match="不存在"):
            await coord.generate_report("no-such-session")

    @pytest.mark.asyncio
    async def test_no_aggregated_result_raises(self):
        coord = self._make_coordinator()
        session = ExecutionSession(
            session_id="s1", user_input="x", state=CoordinatorState.EXECUTING
        )
        coord.sessions["s1"] = session
        with pytest.raises(ValueError, match="尚未完成"):
            await coord.generate_report("s1")

    @pytest.mark.asyncio
    async def test_successful_report_generation(self):
        coord = self._make_coordinator()
        session = ExecutionSession(
            session_id="s1", user_input="x", state=CoordinatorState.COMPLETED
        )
        session.aggregated_result = _make_aggregated_result()
        coord.sessions["s1"] = session
        coord.result_aggregator.generate_report.return_value = "# Report"
        report = await coord.generate_report("s1", "markdown")
        coord.result_aggregator.generate_report.assert_called_once_with(
            session.aggregated_result, "markdown"
        )
        assert report == "# Report"

    @pytest.mark.asyncio
    async def test_report_default_format(self):
        coord = self._make_coordinator()
        session = ExecutionSession(
            session_id="s1", user_input="x", state=CoordinatorState.COMPLETED
        )
        session.aggregated_result = _make_aggregated_result()
        coord.sessions["s1"] = session
        coord.result_aggregator.generate_report.return_value = "report"
        await coord.generate_report("s1")
        call_args = coord.result_aggregator.generate_report.call_args
        assert call_args[0][1] == "markdown"


# ===================== make_decision Tests =====================


class TestMakeDecision:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    @pytest.mark.asyncio
    async def test_delegates_to_engine(self):
        coord = self._make_coordinator()
        ctx = DecisionContext()
        expected = [_make_strategic_decision()]
        coord.decision_engine.make_hybrid_decision = AsyncMock(return_value=expected)
        result = await coord.make_decision(ctx)
        assert result is expected
        coord.decision_engine.make_hybrid_decision.assert_called_once_with(ctx)


# ===================== process_request Tests =====================


class TestProcessRequest:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            coord = CoordinatorAgent(_make_mock_registry(agents or []))
            return coord

    @pytest.mark.asyncio
    async def test_creates_new_session_when_none_provided(self):
        coord = self._make_coordinator()
        intent = _make_intent()
        coord.intent_analyzer.analyze.return_value = intent
        # Make everything fail early to test session creation
        coord.task_decomposer.decompose.side_effect = RuntimeError("test")
        coord.strategy_planner.build_strategy.return_value = {}
        session = await coord.process_request("scan target")
        assert session.session_id.startswith("session_")
        assert session.state is CoordinatorState.FAILED
        assert coord.total_sessions == 1

    @pytest.mark.asyncio
    async def test_uses_provided_session_id(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.return_value = _make_intent()
        coord.task_decomposer.decompose.side_effect = RuntimeError("test")
        coord.strategy_planner.build_strategy.return_value = {}
        session = await coord.process_request("scan", session_id="my-session")
        assert session.session_id == "my-session"
        assert "my-session" in coord.sessions

    @pytest.mark.asyncio
    async def test_reuses_existing_session(self):
        coord = self._make_coordinator()
        existing = ExecutionSession(
            session_id="existing", user_input="old", state=CoordinatorState.IDLE
        )
        coord.sessions["existing"] = existing
        coord.intent_analyzer.analyze.return_value = _make_intent()
        coord.task_decomposer.decompose.side_effect = RuntimeError("test")
        coord.strategy_planner.build_strategy.return_value = {}
        session = await coord.process_request("new input", session_id="existing")
        assert session is existing

    @pytest.mark.asyncio
    async def test_creates_session_for_unknown_id(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.return_value = _make_intent()
        coord.task_decomposer.decompose.side_effect = RuntimeError("test")
        coord.strategy_planner.build_strategy.return_value = {}
        session = await coord.process_request("scan", session_id="new-id")
        assert session.session_id == "new-id"
        assert "new-id" in coord.sessions

    @pytest.mark.asyncio
    async def test_failure_sets_state_and_error(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.return_value = _make_intent()
        coord.task_decomposer.decompose.side_effect = RuntimeError("decompose fail")
        coord.strategy_planner.build_strategy.return_value = {}
        session = await coord.process_request("scan target")
        assert session.state is CoordinatorState.FAILED
        assert "decompose fail" in session.error
        assert session.completed_at is not None

    @pytest.mark.asyncio
    async def test_successful_flow(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])

        # Setup mocks for complete flow
        intent = _make_intent()
        coord.intent_analyzer.analyze.return_value = intent
        coord.strategy_planner.build_strategy.return_value = {"stages": []}

        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        coord.task_decomposer.decompose.return_value = dp

        dec = _make_scheduling_decision(task=task, agent=agent)
        coord.agent_scheduler.schedule_task = AsyncMock(return_value=dec)
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.agent_scheduler.mark_task_complete = MagicMock()

        strategic = _make_strategic_decision()
        tactical = _make_tactical_decision()
        coord.decision_engine.make_strategic_decision = AsyncMock(
            return_value=strategic
        )
        coord.decision_engine.make_tactical_decision = AsyncMock(
            return_value=tactical
        )
        coord.decision_engine.make_hybrid_decision = AsyncMock(return_value=[])

        agg = _make_aggregated_result(intent=intent)
        coord.result_aggregator.aggregate_results = AsyncMock(return_value=agg)

        session = await coord.process_request("scan target")
        assert session.state is CoordinatorState.COMPLETED
        assert session.completed_at is not None
        assert coord.successful_sessions == 1
        assert coord.total_sessions == 1
        assert session.aggregated_result is agg
        assert len(session.decisions) >= 2  # strategic + tactical

    @pytest.mark.asyncio
    async def test_total_sessions_increments_on_failure(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.side_effect = RuntimeError("fail")
        session = await coord.process_request("scan")
        assert coord.total_sessions == 1
        assert coord.successful_sessions == 0

    @pytest.mark.asyncio
    async def test_current_session_id_updated(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.side_effect = RuntimeError("fail")
        session = await coord.process_request("scan")
        assert coord.current_session_id == session.session_id


# ===================== Edge Case / Integration Tests =====================


class TestEdgeCases:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry(agents or []))

    def test_topological_sort_three_node_cycle(self):
        coord = self._make_coordinator()
        t1 = _make_task(task_id="t1", dependencies=["t3"])
        t2 = _make_task(task_id="t2", dependencies=["t1"])
        t3 = _make_task(task_id="t3", dependencies=["t2"])
        tg = _make_task_graph([t1, t2, t3])
        with pytest.raises(ValueError, match="循环依赖"):
            coord._topological_sort(tg)

    @pytest.mark.asyncio
    async def test_execute_plan_empty_graph(self):
        coord = self._make_coordinator()
        tg = _make_task_graph([])
        dp = _make_decomposer_plan(task_graph=tg)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[],
        )
        results = await coord._execute_plan(plan)
        assert results == []

    @pytest.mark.asyncio
    async def test_execute_plan_multi_tasks_with_deps(self):
        a1 = _make_mock_agent("a1")
        coord = self._make_coordinator([a1])
        coord.agent_scheduler.mark_task_complete = MagicMock()
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2", dependencies=["t1"])
        tg = _make_task_graph([t1, t2])
        dp = _make_decomposer_plan(task_graph=tg)
        dec1 = _make_scheduling_decision(task=t1, agent=a1)
        dec2 = _make_scheduling_decision(task=t2, agent=a1)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec1, dec2],
        )
        results = await coord._execute_plan(plan)
        assert len(results) == 2

    def test_infer_strategy_mode_is_static(self):
        # Verify it's a static method
        assert isinstance(
            CoordinatorAgent.__dict__["_infer_strategy_mode"], staticmethod
        )

    def test_is_strategy_constrained_is_static(self):
        assert isinstance(
            CoordinatorAgent.__dict__["_is_strategy_constrained_task"], staticmethod
        )

    @pytest.mark.asyncio
    async def test_process_request_multiple_sessions(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.side_effect = RuntimeError("fail")
        s1 = await coord.process_request("scan1", session_id="s1")
        s2 = await coord.process_request("scan2", session_id="s2")
        assert "s1" in coord.sessions
        assert "s2" in coord.sessions
        assert coord.total_sessions == 2

    def test_strategy_mode_all_attack_intents_covered(self):
        """All AttackIntent values should produce a string mode."""
        for intent_val in AttackIntent:
            ia = _make_intent(intent=intent_val)
            result = CoordinatorAgent._infer_strategy_mode(ia)
            assert isinstance(result, str)
            assert result in {"ctf", "recon", "pentest"}

    @pytest.mark.asyncio
    async def test_fallback_no_available_agents(self):
        coord = self._make_coordinator([])  # no agents
        dec_no_agent = _make_scheduling_decision(agent=None)
        coord.agent_scheduler.schedule_task = AsyncMock(return_value=dec_no_agent)
        coord.agent_scheduler.strategy = SchedulingStrategy.ADAPTIVE
        task = _make_task(parameters={"target": "x"})
        dp = _make_decomposer_plan(task_graph=_make_task_graph([task]))
        plan = await coord._create_execution_plan(_make_intent(), dp)
        # No available agents means no fallback
        for d in plan.scheduling_decisions:
            assert d.selected_agent is None

    def test_get_statistics_scheduler_fields(self):
        coord = self._make_coordinator()
        stats = _make_scheduling_stats(
            total_assignments=20,
            successful_assignments=15,
            failed_assignments=5,
        )
        coord.agent_scheduler.get_statistics.return_value = stats
        coord.decision_engine.get_statistics.return_value = {"decisions": 0}
        result = coord.get_statistics()
        assert result["scheduler"]["total_assignments"] == 20
        assert result["scheduler"]["successful_assignments"] == 15
        assert result["scheduler"]["failed_assignments"] == 5

    @pytest.mark.asyncio
    async def test_execute_single_task_target_from_params(self):
        agent = _make_mock_agent("a1")
        agent.execute_task = AsyncMock(side_effect=RuntimeError("err"))
        coord = self._make_coordinator([agent])
        task = _make_task(parameters={"target": "special_target"})
        result = await coord._execute_single_task(task, "a1")
        assert result.target == "special_target"

    @pytest.mark.asyncio
    async def test_execute_single_task_missing_target_param(self):
        agent = _make_mock_agent("a1")
        agent.execute_task = AsyncMock(side_effect=RuntimeError("err"))
        coord = self._make_coordinator([agent])
        task = _make_task(parameters={})
        result = await coord._execute_single_task(task, "a1")
        assert result.target == ""

    def test_attach_strategy_calls_infer_mode(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        intent = _make_intent(intent=AttackIntent.CTF_SOLVING)
        coord._attach_strategy_constraint(intent)
        call_kwargs = coord.strategy_planner.build_strategy.call_args
        # mode should be "ctf"
        assert "ctf" in str(call_kwargs)

    @pytest.mark.asyncio
    async def test_process_request_hybrid_decisions_appended(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        intent = _make_intent()
        coord.intent_analyzer.analyze.return_value = intent
        coord.strategy_planner.build_strategy.return_value = {}
        task = _make_task()
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        coord.task_decomposer.decompose.return_value = dp
        coord.agent_scheduler.schedule_task = AsyncMock(
            return_value=_make_scheduling_decision(task=task, agent=agent)
        )
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.agent_scheduler.mark_task_complete = MagicMock()
        coord.decision_engine.make_strategic_decision = AsyncMock(
            return_value=_make_strategic_decision()
        )
        coord.decision_engine.make_tactical_decision = AsyncMock(
            return_value=_make_tactical_decision()
        )
        hybrid_decs = [_make_strategic_decision(), _make_tactical_decision()]
        coord.decision_engine.make_hybrid_decision = AsyncMock(
            return_value=hybrid_decs
        )
        coord.result_aggregator.aggregate_results = AsyncMock(
            return_value=_make_aggregated_result()
        )
        session = await coord.process_request("scan")
        # strategic + tactical + 2 hybrid = 4
        assert len(session.decisions) == 4


# ===================== Sorting in _create_execution_plan =====================


class TestPlanSorting:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry(agents or []))

    @pytest.mark.asyncio
    async def test_sort_by_priority_desc(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        # Two tasks with same stage but different priorities
        t1 = _make_task(task_id="low", priority=2, parameters={"target": "x"})
        t2 = _make_task(task_id="high", priority=9, parameters={"target": "x"})
        tg = _make_task_graph([t1, t2])
        dp = _make_decomposer_plan(task_graph=tg)
        call_order = []
        async def track(task, agents_list):
            call_order.append(task.task_id)
            return _make_scheduling_decision(task=task, agent=agent)
        coord.agent_scheduler.schedule_task = track
        await coord._create_execution_plan(_make_intent(), dp)
        # Higher priority (9) should come first (sorted by -priority)
        assert call_order[0] == "high"

    @pytest.mark.asyncio
    async def test_sort_by_category_tiebreaker(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        # Same stage and priority, different categories
        t1 = _make_task(
            task_id="scan_task",
            priority=5,
            category=TaskCategory.SCANNING,
            parameters={"target": "x"},
        )
        t2 = _make_task(
            task_id="recon_task",
            priority=5,
            category=TaskCategory.RECONNAISSANCE,
            parameters={"target": "x"},
        )
        tg = _make_task_graph([t1, t2])
        dp = _make_decomposer_plan(task_graph=tg)
        call_order = []
        async def track(task, agents_list):
            call_order.append(task.task_id)
            return _make_scheduling_decision(task=task, agent=agent)
        coord.agent_scheduler.schedule_task = track
        await coord._create_execution_plan(_make_intent(), dp)
        # Category value is used as final tiebreaker
        assert len(call_order) == 2


# ===================== Additional Coverage Tests =====================


class TestCoordinatorStateMembership:
    """Ensure enum members have correct identity semantics."""

    def test_identity_comparison(self):
        assert CoordinatorState.IDLE is CoordinatorState.IDLE
        assert CoordinatorState.IDLE is not CoordinatorState.FAILED

    def test_equality_with_same_member(self):
        assert CoordinatorState.EXECUTING == CoordinatorState.EXECUTING

    def test_inequality_with_different_member(self):
        assert CoordinatorState.COMPLETED != CoordinatorState.FAILED

    def test_name_attribute(self):
        assert CoordinatorState.ANALYZING.name == "ANALYZING"
        assert CoordinatorState.SCHEDULING.name == "SCHEDULING"

    def test_iteration(self):
        states = list(CoordinatorState)
        assert len(states) == 9
        assert CoordinatorState.IDLE in states

    def test_repr_contains_name(self):
        r = repr(CoordinatorState.DECIDING)
        assert "DECIDING" in r


class TestExecutionSessionAdvanced:
    def test_error_assignment(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        s.error = "something went wrong"
        assert s.error == "something went wrong"

    def test_completed_at_assignment(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        now = datetime.now()
        s.completed_at = now
        assert s.completed_at == now

    def test_plan_assignment(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
        )
        s.plan = plan
        assert s.plan is plan

    def test_aggregated_result_assignment(self):
        s = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.IDLE
        )
        agg = _make_aggregated_result()
        s.aggregated_result = agg
        assert s.aggregated_result is agg


class TestCoordinatorExecutionPlanAdvanced:
    def test_required_agents_with_values(self):
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
            required_agents={"agent-a", "agent-b"},
        )
        assert "agent-a" in plan.required_agents
        assert "agent-b" in plan.required_agents

    def test_custom_created_at(self):
        custom_time = datetime(2025, 1, 1)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=_make_decomposer_plan(),
            scheduling_decisions=[],
            created_at=custom_time,
        )
        assert plan.created_at == custom_time

    def test_task_graph_delegates_to_decomposer(self):
        """Verify property is a true delegation."""
        dp = _make_decomposer_plan()
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[],
        )
        assert plan.task_graph is dp.task_graph
        assert plan.estimated_duration is dp.estimated_duration


class TestTopologicalSortAdvanced:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    def test_wide_fan_out(self):
        """One root with many children."""
        coord = self._make_coordinator()
        root = _make_task(task_id="root")
        children = [
            _make_task(task_id=f"child_{i}", dependencies=["root"])
            for i in range(10)
        ]
        tg = _make_task_graph([root] + children)
        result = coord._topological_sort(tg)
        assert result[0] == "root"
        assert len(result) == 11

    def test_wide_fan_in(self):
        """Many roots into one sink."""
        coord = self._make_coordinator()
        roots = [_make_task(task_id=f"root_{i}") for i in range(5)]
        sink = _make_task(
            task_id="sink",
            dependencies=[f"root_{i}" for i in range(5)],
        )
        tg = _make_task_graph(roots + [sink])
        result = coord._topological_sort(tg)
        assert result[-1] == "sink"
        assert len(result) == 6

    def test_two_independent_chains(self):
        coord = self._make_coordinator()
        t1 = _make_task(task_id="a1")
        t2 = _make_task(task_id="a2", dependencies=["a1"])
        t3 = _make_task(task_id="b1")
        t4 = _make_task(task_id="b2", dependencies=["b1"])
        tg = _make_task_graph([t1, t2, t3, t4])
        result = coord._topological_sort(tg)
        assert result.index("a1") < result.index("a2")
        assert result.index("b1") < result.index("b2")
        assert len(result) == 4


class TestAttachStrategyConstraintAdvanced:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    def test_non_dict_constraints_preserved(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        intent = _make_intent(constraints=["string1", 42, None])
        result = coord._attach_strategy_constraint(intent)
        assert "string1" in result.constraints
        assert 42 in result.constraints
        assert None in result.constraints

    def test_dict_without_type_preserved(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        keep = {"key": "value"}
        intent = _make_intent(constraints=[keep])
        result = coord._attach_strategy_constraint(intent)
        assert keep in result.constraints

    def test_strategy_source_is_coordinator(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {"plan": "x"}
        intent = _make_intent()
        result = coord._attach_strategy_constraint(intent)
        exec_strats = [
            c for c in result.constraints
            if isinstance(c, dict) and c.get("type") == "execution_strategy"
        ]
        assert len(exec_strats) == 1
        assert exec_strats[0]["source"] == "coordinator"
        assert exec_strats[0]["strategy"] == {"plan": "x"}

    def test_calls_build_strategy_with_has_source_false(self):
        coord = self._make_coordinator()
        coord.strategy_planner.build_strategy.return_value = {}
        intent = _make_intent()
        coord._attach_strategy_constraint(intent)
        call_kwargs = coord.strategy_planner.build_strategy.call_args
        assert call_kwargs.kwargs.get("has_source") is False


class TestExecutePlanAdvanced:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            coord = CoordinatorAgent(_make_mock_registry(agents or []))
            coord.agent_scheduler.mark_task_complete = MagicMock()
            return coord

    @pytest.mark.asyncio
    async def test_mixed_success_and_failure(self):
        a1 = _make_mock_agent("a1")
        a2 = _make_mock_agent("a2")
        a2.execute_task = AsyncMock(side_effect=RuntimeError("fail"))
        coord = self._make_coordinator([a1, a2])

        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2")
        tg = _make_task_graph([t1, t2])
        dp = _make_decomposer_plan(task_graph=tg)

        dec1 = _make_scheduling_decision(task=t1, agent=a1)
        dec2 = _make_scheduling_decision(task=t2, agent=a2)

        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec1, dec2],
        )
        results = await coord._execute_plan(plan)
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]
        assert len(successes) == 1
        assert len(failures) == 1

    @pytest.mark.asyncio
    async def test_marks_task_complete_on_success(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        dec = _make_scheduling_decision(task=task, agent=agent)
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec],
        )
        await coord._execute_plan(plan)
        coord.agent_scheduler.mark_task_complete.assert_called_once_with(
            "t1", success=True
        )

    @pytest.mark.asyncio
    async def test_no_decision_default_reason(self):
        coord = self._make_coordinator()
        task = _make_task(task_id="t1")
        tg = _make_task_graph([task])
        dp = _make_decomposer_plan(task_graph=tg)
        # Decision with no agent and empty reasoning
        dec = _make_scheduling_decision(task=task, agent=None)
        dec.reasoning = []
        plan = CoordinatorExecutionPlan(
            plan_id="p",
            intent_analysis=_make_intent(),
            decomposer_plan=dp,
            scheduling_decisions=[dec],
        )
        results = await coord._execute_plan(plan)
        assert "无可用Agent" in results[0].errors[0]


class TestGetStatisticsAdvanced:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry([_make_mock_agent()]))

    def test_agent_registry_total_agents(self):
        coord = self._make_coordinator()
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        assert "total_agents" in stats["agent_registry"]

    def test_agent_registry_available_agents(self):
        coord = self._make_coordinator()
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        assert "available_agents" in stats["agent_registry"]

    def test_scheduler_avg_execution_time(self):
        coord = self._make_coordinator()
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats(
            avg_execution_time=5.5
        )
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        assert stats["scheduler"]["avg_execution_time"] == 5.5

    def test_all_sessions_completed_or_failed_zero_active(self):
        coord = self._make_coordinator()
        coord.sessions["s1"] = ExecutionSession(
            session_id="s1", user_input="x", state=CoordinatorState.COMPLETED
        )
        coord.sessions["s2"] = ExecutionSession(
            session_id="s2", user_input="x", state=CoordinatorState.FAILED
        )
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.decision_engine.get_statistics.return_value = {}
        stats = coord.get_statistics()
        assert stats["coordinator"]["active_sessions"] == 0

    def test_decision_engine_stats_passthrough(self):
        coord = self._make_coordinator()
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        engine_stats = {"total_decisions": 42, "accuracy": 0.95}
        coord.decision_engine.get_statistics.return_value = engine_stats
        stats = coord.get_statistics()
        assert stats["decision_engine"] == engine_stats


class TestProcessRequestAdvanced:
    def _make_coordinator(self, agents=None):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry(agents or []))

    @pytest.mark.asyncio
    async def test_session_state_transitions_on_failure(self):
        """Verify final state is FAILED when intent analysis fails."""
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.side_effect = ValueError("bad input")
        session = await coord.process_request("invalid")
        assert session.state is CoordinatorState.FAILED
        assert "bad input" in session.error

    @pytest.mark.asyncio
    async def test_session_user_input_stored(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.side_effect = RuntimeError("fail")
        session = await coord.process_request("my special input")
        assert session.user_input == "my special input"

    @pytest.mark.asyncio
    async def test_successful_sessions_not_incremented_on_failure(self):
        coord = self._make_coordinator()
        coord.intent_analyzer.analyze.side_effect = RuntimeError("fail")
        await coord.process_request("scan")
        assert coord.successful_sessions == 0

    @pytest.mark.asyncio
    async def test_session_total_tasks_set_in_success_flow(self):
        agent = _make_mock_agent("a1")
        coord = self._make_coordinator([agent])
        intent = _make_intent()
        coord.intent_analyzer.analyze.return_value = intent
        coord.strategy_planner.build_strategy.return_value = {}
        t1 = _make_task(task_id="t1")
        t2 = _make_task(task_id="t2")
        tg = _make_task_graph([t1, t2])
        dp = _make_decomposer_plan(task_graph=tg)
        coord.task_decomposer.decompose.return_value = dp
        coord.agent_scheduler.schedule_task = AsyncMock(
            return_value=_make_scheduling_decision(agent=agent)
        )
        coord.agent_scheduler.get_statistics.return_value = _make_scheduling_stats()
        coord.agent_scheduler.mark_task_complete = MagicMock()
        coord.decision_engine.make_strategic_decision = AsyncMock(
            return_value=_make_strategic_decision()
        )
        coord.decision_engine.make_tactical_decision = AsyncMock(
            return_value=_make_tactical_decision()
        )
        coord.decision_engine.make_hybrid_decision = AsyncMock(return_value=[])
        coord.result_aggregator.aggregate_results = AsyncMock(
            return_value=_make_aggregated_result()
        )
        session = await coord.process_request("scan")
        assert session.total_tasks == 2


class TestSelectStageCandidateAgentsAdvanced:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    def test_preferred_with_none_entries_skipped(self):
        coord = self._make_coordinator()
        a1 = _make_mock_agent("a1")
        agents = [a1]
        task = _make_task(
            parameters={
                "strategy_stage_index": 0,
                "strategy_preferred_agents": [None, "", "a1"],
                "target": "x",
            }
        )
        result = coord._select_stage_candidate_agents(task, agents)
        # None and "" should be filtered, "a1" should match
        ids = [a.agent_id for a in result]
        assert "a1" in ids

    def test_empty_available_agents(self):
        coord = self._make_coordinator()
        task = _make_task(
            parameters={
                "strategy_stage_index": 0,
                "strategy_preferred_agents": ["a1"],
                "target": "x",
            }
        )
        result = coord._select_stage_candidate_agents(task, [])
        assert result == []

    def test_agent_without_agent_id_attr(self):
        coord = self._make_coordinator()
        # Agent without agent_id attribute
        fake_agent = MagicMock(spec=[])
        agents = [fake_agent]
        task = _make_task(
            parameters={
                "strategy_stage_index": 0,
                "strategy_preferred_agents": ["a1"],
                "target": "x",
            }
        )
        result = coord._select_stage_candidate_agents(task, agents)
        # getattr(agent, "agent_id", "") returns "" which won't match "a1"
        assert result == []


class TestMakeDecisionAdvanced:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    @pytest.mark.asyncio
    async def test_returns_list(self):
        coord = self._make_coordinator()
        ctx = DecisionContext()
        coord.decision_engine.make_hybrid_decision = AsyncMock(return_value=[])
        result = await coord.make_decision(ctx)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_propagates_exception(self):
        coord = self._make_coordinator()
        ctx = DecisionContext()
        coord.decision_engine.make_hybrid_decision = AsyncMock(
            side_effect=RuntimeError("engine fail")
        )
        with pytest.raises(RuntimeError, match="engine fail"):
            await coord.make_decision(ctx)


class TestGenerateReportAdvanced:
    def _make_coordinator(self):
        with patch("kali_mcp.core.agent_coordinator.IntentAnalyzer"), \
             patch("kali_mcp.core.agent_coordinator.TaskDecomposer"), \
             patch("kali_mcp.core.agent_coordinator.AgentScheduler"), \
             patch("kali_mcp.core.agent_coordinator.HybridDecisionEngine"), \
             patch("kali_mcp.core.agent_coordinator.ResultAggregator"), \
             patch("kali_mcp.core.agent_coordinator.PentestCapabilityPlanner"):
            return CoordinatorAgent(_make_mock_registry())

    @pytest.mark.asyncio
    async def test_json_format(self):
        coord = self._make_coordinator()
        session = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.COMPLETED
        )
        session.aggregated_result = _make_aggregated_result()
        coord.sessions["s"] = session
        coord.result_aggregator.generate_report.return_value = '{"report": true}'
        report = await coord.generate_report("s", "json")
        coord.result_aggregator.generate_report.assert_called_once_with(
            session.aggregated_result, "json"
        )
        assert report == '{"report": true}'

    @pytest.mark.asyncio
    async def test_html_format(self):
        coord = self._make_coordinator()
        session = ExecutionSession(
            session_id="s", user_input="x", state=CoordinatorState.COMPLETED
        )
        session.aggregated_result = _make_aggregated_result()
        coord.sessions["s"] = session
        coord.result_aggregator.generate_report.return_value = "<h1>Report</h1>"
        report = await coord.generate_report("s", "html")
        assert report == "<h1>Report</h1>"
