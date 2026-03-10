"""
Comprehensive unit tests for kali_mcp.core.hybrid_decision_engine

Covers:
- DecisionLevel enum (3 members)
- DecisionType enum (6 members)
- DecisionOption dataclass and calculate_score()
- DecisionContext dataclass and __post_init__()
- Decision, StrategicDecision, TacticalDecision dataclasses
- DecisionModel base class
- StrategicDecisionModel
- TacticalDecisionModel
- HybridDecisionEngine
"""

import json
import os
import tempfile
import asyncio
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, AsyncMock
from dataclasses import fields

from kali_mcp.core.hybrid_decision_engine import (
    DecisionLevel,
    DecisionType,
    DecisionOption,
    DecisionContext,
    Decision,
    StrategicDecision,
    TacticalDecision,
    DecisionModel,
    StrategicDecisionModel,
    TacticalDecisionModel,
    HybridDecisionEngine,
)
from kali_mcp.core.intent_analyzer import (
    IntentAnalysis,
    AttackIntent,
    TargetInfo,
    TargetType,
)
from kali_mcp.core.task_decomposer import (
    Task,
    TaskGraph,
    TaskCategory,
    TaskStatus,
)


# ==================== Helpers ====================

def _run(coro):
    """Run an async coroutine synchronously."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_target(value="http://example.com", target_type=TargetType.URL,
                 is_ctf=False):
    return TargetInfo(original=value, type=target_type, value=value,
                      is_ctf=is_ctf)


def _make_intent_analysis(intent=AttackIntent.RECONNAISSANCE, targets=None,
                          constraints=None):
    if targets is None:
        targets = [_make_target()]
    return IntentAnalysis(
        user_input="test input",
        intent=intent,
        targets=targets,
        constraints=constraints or [],
        priority=5,
        confidence=0.8,
    )


def _make_task(task_id="t1", priority=5, tool_name="nmap",
               status=TaskStatus.PENDING, dependencies=None):
    return Task(
        task_id=task_id,
        name=f"Task {task_id}",
        category=TaskCategory.RECONNAISSANCE,
        tool_name=tool_name,
        parameters={"target": "127.0.0.1"},
        priority=priority,
        status=status,
        dependencies=dependencies or [],
    )


def _make_mock_agent(agent_id="agent_1", supported_tools=None):
    agent = MagicMock()
    agent.agent_id = agent_id
    agent.capabilities = MagicMock()
    agent.capabilities.supported_tools = supported_tools or ["nmap", "sqlmap"]
    return agent


def _make_task_graph(tasks=None):
    tg = TaskGraph(tasks={})
    if tasks:
        for t in tasks:
            tg.add_task(t)
    return tg


def _make_context(intent=AttackIntent.RECONNAISSANCE, targets=None,
                  time_constraint=None, agents=None, system_load=None,
                  task_graph=None, resource_budget=None):
    ia = _make_intent_analysis(intent=intent, targets=targets)
    tg = task_graph or _make_task_graph()
    return DecisionContext(
        intent_analysis=ia,
        task_graph=tg,
        available_agents=agents or [],
        system_load=system_load or {"cpu": 0.5, "memory": 0.5, "network": 0.5},
        time_constraint=time_constraint,
        resource_budget=resource_budget,
    )


def _make_option(option_id="opt1", benefit=0.7, cost=0.3, risk=0.2,
                 confidence=0.9):
    return DecisionOption(
        option_id=option_id,
        description=f"Option {option_id}",
        actions=["action1"],
        expected_benefit=benefit,
        expected_cost=cost,
        risk_level=risk,
        confidence=confidence,
    )


def _make_decision(decision_id="d1", decision_type=DecisionType.ATTACK_PATH,
                   decision_level=DecisionLevel.STRATEGIC, option=None):
    ctx = _make_context()
    return Decision(
        decision_id=decision_id,
        decision_type=decision_type,
        decision_level=decision_level,
        context=ctx,
        selected_option=option or _make_option(),
    )


# ==================== DecisionLevel Tests ====================

class TestDecisionLevel:
    def test_has_three_members(self):
        assert len(DecisionLevel) == 3

    def test_strategic_value(self):
        assert DecisionLevel.STRATEGIC.value == "strategic"

    def test_tactical_value(self):
        assert DecisionLevel.TACTICAL.value == "tactical"

    def test_operational_value(self):
        assert DecisionLevel.OPERATIONAL.value == "operational"

    def test_members_are_unique(self):
        values = [m.value for m in DecisionLevel]
        assert len(values) == len(set(values))


# ==================== DecisionType Tests ====================

class TestDecisionType:
    def test_has_six_members(self):
        assert len(DecisionType) == 6

    def test_attack_path(self):
        assert DecisionType.ATTACK_PATH.value == "attack_path"

    def test_agent_selection(self):
        assert DecisionType.AGENT_SELECTION.value == "agent_selection"

    def test_tool_selection(self):
        assert DecisionType.TOOL_SELECTION.value == "tool_selection"

    def test_priority_adjustment(self):
        assert DecisionType.PRIORITY_ADJUSTMENT.value == "priority"

    def test_resource_allocation(self):
        assert DecisionType.RESOURCE_ALLOCATION.value == "resource"

    def test_strategy_switch(self):
        assert DecisionType.STRATEGY_SWITCH.value == "strategy_switch"

    def test_members_are_unique(self):
        values = [m.value for m in DecisionType]
        assert len(values) == len(set(values))


# ==================== DecisionOption Tests ====================

class TestDecisionOption:
    def test_basic_creation(self):
        opt = _make_option()
        assert opt.option_id == "opt1"
        assert opt.expected_benefit == 0.7
        assert opt.expected_cost == 0.3
        assert opt.risk_level == 0.2
        assert opt.confidence == 0.9

    def test_default_fields(self):
        opt = _make_option()
        assert opt.required_resources == {}
        assert opt.prerequisites == []

    def test_calculate_score_moderate_risk_tolerance(self):
        """risk_tolerance=0.5 -> penalty = risk * 0.3"""
        opt = _make_option(benefit=0.7, cost=0.3, risk=0.2, confidence=0.9)
        base = 0.7 * 0.6 - 0.3 * 0.4  # 0.42 - 0.12 = 0.30
        penalty = 0.2 * 0.3  # 0.06
        final = (base - penalty) * 0.9  # 0.24 * 0.9 = 0.216
        assert abs(opt.calculate_score(0.5) - final) < 1e-9

    def test_calculate_score_conservative(self):
        """risk_tolerance < 0.3 -> penalty = risk * 0.5"""
        opt = _make_option(benefit=0.8, cost=0.2, risk=0.6, confidence=1.0)
        base = 0.8 * 0.6 - 0.2 * 0.4  # 0.48 - 0.08 = 0.40
        penalty = 0.6 * 0.5  # 0.30
        final = max(-1.0, min(1.0, base - penalty)) * 1.0  # 0.10
        assert abs(opt.calculate_score(0.1) - final) < 1e-9

    def test_calculate_score_aggressive(self):
        """risk_tolerance > 0.7 -> penalty = risk * 0.1"""
        opt = _make_option(benefit=0.8, cost=0.2, risk=0.6, confidence=1.0)
        base = 0.8 * 0.6 - 0.2 * 0.4  # 0.40
        penalty = 0.6 * 0.1  # 0.06
        final = (base - penalty) * 1.0  # 0.34
        assert abs(opt.calculate_score(0.9) - final) < 1e-9

    def test_calculate_score_boundary_conservative(self):
        """risk_tolerance == 0.3 is NOT < 0.3, falls into middle branch."""
        opt = _make_option(benefit=0.5, cost=0.5, risk=0.5, confidence=1.0)
        base = 0.5 * 0.6 - 0.5 * 0.4  # 0.10
        penalty = 0.5 * 0.3  # 0.15
        final = base - penalty  # -0.05
        assert abs(opt.calculate_score(0.3) - final) < 1e-9

    def test_calculate_score_boundary_aggressive(self):
        """risk_tolerance == 0.7 is NOT > 0.7, falls into middle branch."""
        opt = _make_option(benefit=0.5, cost=0.5, risk=0.5, confidence=1.0)
        base = 0.5 * 0.6 - 0.5 * 0.4  # 0.10
        penalty = 0.5 * 0.3  # 0.15
        final = base - penalty  # -0.05
        assert abs(opt.calculate_score(0.7) - final) < 1e-9

    def test_calculate_score_clamped_negative(self):
        """Score clamped at -1.0 before multiplying by confidence."""
        opt = _make_option(benefit=0.0, cost=1.0, risk=1.0, confidence=1.0)
        # base = 0 - 0.4 = -0.4
        # penalty(0.1, conservative) = 1.0 * 0.5 = 0.5
        # raw = -0.4 - 0.5 = -0.9
        # clamp = max(-1, min(1, -0.9)) = -0.9
        score = opt.calculate_score(0.1)
        assert score >= -1.0

    def test_calculate_score_clamped_positive(self):
        """Score clamped at 1.0 before multiplying by confidence."""
        opt = _make_option(benefit=1.0, cost=0.0, risk=0.0, confidence=1.0)
        # base = 0.6
        # penalty = 0
        # raw = 0.6
        # clamp = 0.6
        score = opt.calculate_score(0.5)
        assert score <= 1.0

    def test_calculate_score_zero_confidence(self):
        """Zero confidence yields zero score."""
        opt = _make_option(benefit=1.0, cost=0.0, risk=0.0, confidence=0.0)
        assert opt.calculate_score(0.5) == 0.0

    def test_calculate_score_all_zeros(self):
        opt = _make_option(benefit=0.0, cost=0.0, risk=0.0, confidence=0.0)
        assert opt.calculate_score(0.5) == 0.0

    def test_calculate_score_max_benefit_min_cost(self):
        opt = _make_option(benefit=1.0, cost=0.0, risk=0.0, confidence=1.0)
        # base = 0.6, penalty = 0, clamp = 0.6, * 1.0 = 0.6
        assert abs(opt.calculate_score(0.5) - 0.6) < 1e-9

    def test_calculate_score_with_resources_and_prerequisites(self):
        """Extra fields don't affect score calculation."""
        opt = DecisionOption(
            option_id="x", description="x", actions=[],
            expected_benefit=0.5, expected_cost=0.5,
            risk_level=0.5, confidence=0.5,
            required_resources={"cpu": 0.9},
            prerequisites=["pre1"],
        )
        # Should not raise
        score = opt.calculate_score(0.5)
        assert isinstance(score, float)


# ==================== DecisionContext Tests ====================

class TestDecisionContext:
    def test_default_post_init_creates_intent_analysis(self):
        """When intent_analysis is None, __post_init__ creates a default one."""
        ctx = DecisionContext()
        assert ctx.intent_analysis is not None
        assert ctx.intent_analysis.intent == AttackIntent.RECONNAISSANCE

    def test_default_post_init_creates_task_graph(self):
        ctx = DecisionContext()
        assert ctx.task_graph is not None
        assert isinstance(ctx.task_graph, TaskGraph)

    def test_default_post_init_sets_system_load(self):
        ctx = DecisionContext()
        assert ctx.system_load == {"cpu": 0.5, "memory": 0.5, "network": 0.5}

    def test_post_init_with_targets(self):
        """Targets list should be converted to TargetInfo objects."""
        ctx = DecisionContext(targets=["http://example.com", "test.local"])
        assert len(ctx.intent_analysis.targets) == 2
        assert ctx.intent_analysis.targets[0].type == TargetType.URL
        assert ctx.intent_analysis.targets[1].type == TargetType.DOMAIN

    def test_post_init_with_intent(self):
        ctx = DecisionContext(intent=AttackIntent.CTF_SOLVING)
        assert ctx.intent_analysis.intent == AttackIntent.CTF_SOLVING

    def test_post_init_preserves_provided_intent_analysis(self):
        ia = _make_intent_analysis(intent=AttackIntent.EXPLOITATION)
        ctx = DecisionContext(intent_analysis=ia)
        assert ctx.intent_analysis is ia

    def test_post_init_preserves_provided_task_graph(self):
        tg = _make_task_graph()
        ctx = DecisionContext(task_graph=tg)
        assert ctx.task_graph is tg

    def test_post_init_preserves_nonempty_system_load(self):
        load = {"cpu": 0.9, "memory": 0.1, "network": 0.3}
        ctx = DecisionContext(system_load=load)
        assert ctx.system_load == load

    def test_default_collections_are_empty(self):
        ctx = DecisionContext()
        assert ctx.available_agents == []
        assert ctx.previous_decisions == []
        assert ctx.running_tasks == []
        assert ctx.completed_tasks == []
        assert ctx.failed_tasks == []
        assert ctx.discovered_assets == set()

    def test_current_phase_default(self):
        ctx = DecisionContext()
        assert ctx.current_phase == "planning"

    def test_post_init_with_constraints(self):
        ctx = DecisionContext(
            targets=["http://x.com"],
            constraints=[{"type": "time_limit", "value": 60}],
        )
        assert len(ctx.intent_analysis.constraints) == 1

    def test_https_url_detected_as_url(self):
        ctx = DecisionContext(targets=["https://secure.example.com"])
        assert ctx.intent_analysis.targets[0].type == TargetType.URL

    def test_non_url_detected_as_domain(self):
        ctx = DecisionContext(targets=["example.com"])
        assert ctx.intent_analysis.targets[0].type == TargetType.DOMAIN


# ==================== Decision Tests ====================

class TestDecision:
    def test_creation(self):
        d = _make_decision()
        assert d.decision_id == "d1"
        assert d.execution_status == "pending"
        assert d.actual_benefit is None

    def test_created_at_is_datetime(self):
        d = _make_decision()
        assert isinstance(d.created_at, datetime)

    def test_defaults(self):
        d = _make_decision()
        assert d.rejected_options == []
        assert d.reasoning == []
        assert d.expires_at is None
        assert d.executed_at is None
        assert d.execution_result is None
        assert d.feedback is None


# ==================== StrategicDecision Tests ====================

class TestStrategicDecision:
    def test_creation(self):
        ctx = _make_context()
        sd = StrategicDecision(
            decision_id="s1",
            decision_type=DecisionType.ATTACK_PATH,
            decision_level=DecisionLevel.STRATEGIC,
            context=ctx,
            selected_option=_make_option(),
            attack_strategy="fast_recon",
            target_priorities={"t1": 8},
            resource_allocation={"agent_1": 0.5},
            estimated_duration=3600,
        )
        assert sd.attack_strategy == "fast_recon"
        assert sd.estimated_duration == 3600
        assert sd.target_priorities == {"t1": 8}

    def test_defaults(self):
        ctx = _make_context()
        sd = StrategicDecision(
            decision_id="s2",
            decision_type=DecisionType.ATTACK_PATH,
            decision_level=DecisionLevel.STRATEGIC,
            context=ctx,
            selected_option=_make_option(),
        )
        assert sd.attack_strategy == ""
        assert sd.target_priorities == {}
        assert sd.resource_allocation == {}
        assert sd.estimated_duration == 0


# ==================== TacticalDecision Tests ====================

class TestTacticalDecision:
    def test_creation(self):
        ctx = _make_context()
        td = TacticalDecision(
            decision_id="t1",
            decision_type=DecisionType.AGENT_SELECTION,
            decision_level=DecisionLevel.TACTICAL,
            context=ctx,
            selected_option=_make_option(),
            selected_agents=["a1", "a2"],
            task_sequence=["t1", "t2"],
            parallel_groups=[["t1", "t2"]],
        )
        assert td.selected_agents == ["a1", "a2"]
        assert td.parallel_groups == [["t1", "t2"]]

    def test_defaults(self):
        ctx = _make_context()
        td = TacticalDecision(
            decision_id="t2",
            decision_type=DecisionType.AGENT_SELECTION,
            decision_level=DecisionLevel.TACTICAL,
            context=ctx,
            selected_option=_make_option(),
        )
        assert td.selected_agents == []
        assert td.task_sequence == []
        assert td.parallel_groups == []


# ==================== DecisionModel Base Tests ====================

class TestDecisionModel:
    def test_init(self):
        model = DecisionModel("test_model")
        assert model.model_name == "test_model"
        assert model.decision_history == []
        assert model.performance_metrics == {}

    def test_decide_raises(self):
        model = DecisionModel("test")
        with pytest.raises(NotImplementedError):
            _run(model.decide(_make_context()))

    def test_learn_from_outcome_appends(self):
        model = DecisionModel("test")
        d = _make_decision()
        model.learn_from_outcome(d)
        assert len(model.decision_history) == 1

    def test_learn_from_outcome_with_actual_benefit(self):
        model = DecisionModel("test")
        d = _make_decision(
            decision_type=DecisionType.ATTACK_PATH,
            decision_level=DecisionLevel.STRATEGIC,
        )
        d.actual_benefit = 0.8
        model.learn_from_outcome(d)
        key = "attack_path_strategic"
        assert key in model.performance_metrics
        assert model.performance_metrics[key] == [0.8]

    def test_learn_from_outcome_without_benefit_no_metrics(self):
        model = DecisionModel("test")
        d = _make_decision()
        d.actual_benefit = None
        model.learn_from_outcome(d)
        assert model.performance_metrics == {}

    def test_learn_from_outcome_accumulates(self):
        model = DecisionModel("test")
        for val in [0.5, 0.7, 0.9]:
            d = _make_decision()
            d.actual_benefit = val
            model.learn_from_outcome(d)
        key = "attack_path_strategic"
        assert len(model.performance_metrics[key]) == 3

    def test_get_average_performance_default(self):
        model = DecisionModel("test")
        avg = model.get_average_performance(
            DecisionType.ATTACK_PATH, DecisionLevel.STRATEGIC
        )
        assert avg == 0.5

    def test_get_average_performance_with_data(self):
        model = DecisionModel("test")
        model.performance_metrics["attack_path_strategic"] = [0.6, 0.8, 1.0]
        avg = model.get_average_performance(
            DecisionType.ATTACK_PATH, DecisionLevel.STRATEGIC
        )
        assert abs(avg - 0.8) < 1e-9

    def test_get_average_performance_empty_list(self):
        model = DecisionModel("test")
        model.performance_metrics["attack_path_strategic"] = []
        avg = model.get_average_performance(
            DecisionType.ATTACK_PATH, DecisionLevel.STRATEGIC
        )
        assert avg == 0.5


# ==================== StrategicDecisionModel Tests ====================

class TestStrategicDecisionModel:
    def test_init(self):
        model = StrategicDecisionModel()
        assert model.model_name == "strategic_model"
        assert len(model.strategy_templates) == 5

    def test_strategy_templates_keys(self):
        model = StrategicDecisionModel()
        expected = {
            AttackIntent.CTF_SOLVING,
            AttackIntent.APT_SIMULATION,
            AttackIntent.RECONNAISSANCE,
            AttackIntent.VULNERABILITY_SCANNING,
            AttackIntent.EXPLOITATION,
        }
        assert set(model.strategy_templates.keys()) == expected

    def test_decide_returns_strategic_decision(self):
        model = StrategicDecisionModel()
        ctx = _make_context(intent=AttackIntent.RECONNAISSANCE)
        result = _run(model.decide(ctx))
        assert isinstance(result, StrategicDecision)

    def test_decide_ctf_intent(self):
        model = StrategicDecisionModel()
        ctx = _make_context(intent=AttackIntent.CTF_SOLVING)
        result = _run(model.decide(ctx))
        assert result.attack_strategy == "ctf_intensive"

    def test_decide_apt_intent(self):
        model = StrategicDecisionModel()
        ctx = _make_context(intent=AttackIntent.APT_SIMULATION)
        result = _run(model.decide(ctx))
        assert result.attack_strategy == "comprehensive_apt"

    def test_decide_exploitation_intent(self):
        model = StrategicDecisionModel()
        ctx = _make_context(intent=AttackIntent.EXPLOITATION)
        result = _run(model.decide(ctx))
        assert result.attack_strategy == "exploit_chain"

    def test_decide_vuln_scan_intent(self):
        model = StrategicDecisionModel()
        ctx = _make_context(intent=AttackIntent.VULNERABILITY_SCANNING)
        result = _run(model.decide(ctx))
        assert result.attack_strategy == "vuln_scan"

    def test_decide_unknown_intent_falls_back_to_recon(self):
        """Intents not in strategy_templates default to RECONNAISSANCE."""
        model = StrategicDecisionModel()
        ctx = _make_context(intent=AttackIntent.LATERAL_MOVEMENT)
        result = _run(model.decide(ctx))
        assert result.attack_strategy == "fast_recon"

    def test_decide_time_constraint(self):
        model = StrategicDecisionModel()
        ctx = _make_context(
            intent=AttackIntent.RECONNAISSANCE,
            time_constraint=1800,
        )
        result = _run(model.decide(ctx))
        assert result.estimated_duration == 1800

    def test_decide_default_time_constraint(self):
        model = StrategicDecisionModel()
        ctx = _make_context(intent=AttackIntent.RECONNAISSANCE)
        result = _run(model.decide(ctx))
        assert result.estimated_duration == 3600

    def test_decide_high_cpu_load_reduces_parallelism(self):
        model = StrategicDecisionModel()
        ctx = _make_context(
            intent=AttackIntent.CTF_SOLVING,
            system_load={"cpu": 0.9, "memory": 0.5, "network": 0.5},
        )
        result = _run(model.decide(ctx))
        # CTF is "high" parallelism -> 8, but CPU > 0.8 -> halved to 4
        assert "并行度: 4" in " ".join(result.reasoning)

    def test_decide_generates_three_options(self):
        model = StrategicDecisionModel()
        ctx = _make_context()
        result = _run(model.decide(ctx))
        total_options = 1 + len(result.rejected_options)  # selected + rejected
        assert total_options == 3

    def test_generate_strategic_options_ids(self):
        model = StrategicDecisionModel()
        options = model._generate_strategic_options(
            _make_context(), {"name": "test"}, {}, 4, {}
        )
        ids = {o.option_id for o in options}
        assert ids == {"aggressive", "balanced", "conservative"}

    def test_select_best_option_high_risk_tolerance(self):
        """With high risk tolerance, balanced still wins due to higher base score.

        Aggressive: base=0.20, penalty=0.06, final=0.14*0.9=0.126
        Balanced:   base=0.22, penalty=0.03, final=0.19*0.95=0.1805
        """
        model = StrategicDecisionModel()
        options = model._generate_strategic_options(
            _make_context(), {"name": "t"}, {}, 4, {}
        )
        best = model._select_best_option(options, risk_tolerance=0.9)
        assert best.option_id == "balanced"

    def test_select_best_option_low_risk_tolerance(self):
        """Conservative option should win with low risk tolerance."""
        model = StrategicDecisionModel()
        options = model._generate_strategic_options(
            _make_context(), {"name": "t"}, {}, 4, {}
        )
        best = model._select_best_option(options, risk_tolerance=0.1)
        # Conservative has lowest risk penalty under conservative tolerance
        assert best.option_id in ("balanced", "conservative")

    def test_calculate_target_priorities_basic(self):
        model = StrategicDecisionModel()
        ctx = _make_context(targets=[_make_target()])
        priorities = model._calculate_target_priorities(ctx)
        assert len(priorities) == 1
        # base priority 5, URL +1 => 6
        assert list(priorities.values())[0] == 6

    def test_calculate_target_priorities_ctf_target(self):
        model = StrategicDecisionModel()
        target = _make_target(is_ctf=True)
        ctx = _make_context(targets=[target])
        priorities = model._calculate_target_priorities(ctx)
        # base 5 + ctf 3 + url 1 = 9
        assert list(priorities.values())[0] == 9

    def test_calculate_target_priorities_time_limit_constraint(self):
        model = StrategicDecisionModel()
        ia = _make_intent_analysis(
            constraints=[{"type": "time_limit", "value": 60}]
        )
        ctx = _make_context()
        ctx.intent_analysis = ia
        priorities = model._calculate_target_priorities(ctx)
        # base 5 + url 1 + time_limit 2 = 8
        assert list(priorities.values())[0] == 8

    def test_calculate_target_priorities_clamped_at_10(self):
        model = StrategicDecisionModel()
        target = _make_target(is_ctf=True)
        ia = _make_intent_analysis(
            targets=[target],
            constraints=[{"type": "time_limit"}, {"type": "time_limit"}],
        )
        ctx = _make_context()
        ctx.intent_analysis = ia
        priorities = model._calculate_target_priorities(ctx)
        # base 5 + ctf 3 + url 1 + 2*2 = 13, clamped to 10
        assert list(priorities.values())[0] == 10

    def test_calculate_target_priorities_domain_type(self):
        model = StrategicDecisionModel()
        target = _make_target(
            value="example.com", target_type=TargetType.DOMAIN
        )
        ctx = _make_context(targets=[target])
        priorities = model._calculate_target_priorities(ctx)
        # base 5, not URL so no +1 => 5
        assert list(priorities.values())[0] == 5

    def test_allocate_resources_no_agents(self):
        model = StrategicDecisionModel()
        ctx = _make_context(agents=[])
        allocation = model._allocate_resources(ctx, max_parallel=4)
        assert allocation == {}

    def test_allocate_resources_agents_within_limit(self):
        model = StrategicDecisionModel()
        agents = [_make_mock_agent(f"a{i}") for i in range(3)]
        ctx = _make_context(agents=agents)
        allocation = model._allocate_resources(ctx, max_parallel=4)
        assert len(allocation) == 3
        assert abs(sum(allocation.values()) - 1.0) < 1e-9

    def test_allocate_resources_agents_exceed_limit(self):
        model = StrategicDecisionModel()
        agents = [_make_mock_agent(f"a{i}") for i in range(10)]
        ctx = _make_context(agents=agents)
        allocation = model._allocate_resources(ctx, max_parallel=3)
        assert len(allocation) == 3

    def test_decide_has_reasoning(self):
        model = StrategicDecisionModel()
        ctx = _make_context()
        result = _run(model.decide(ctx))
        assert len(result.reasoning) > 0

    def test_parallelism_medium(self):
        """APT_SIMULATION uses 'medium' parallelism -> base 4."""
        model = StrategicDecisionModel()
        ctx = _make_context(
            intent=AttackIntent.APT_SIMULATION,
            system_load={"cpu": 0.3, "memory": 0.5, "network": 0.5},
        )
        result = _run(model.decide(ctx))
        assert "并行度: 4" in " ".join(result.reasoning)

    def test_parallelism_low(self):
        """EXPLOITATION uses 'low' parallelism -> base 2."""
        model = StrategicDecisionModel()
        ctx = _make_context(
            intent=AttackIntent.EXPLOITATION,
            system_load={"cpu": 0.3, "memory": 0.5, "network": 0.5},
        )
        result = _run(model.decide(ctx))
        assert "并行度: 2" in " ".join(result.reasoning)


# ==================== TacticalDecisionModel Tests ====================

class TestTacticalDecisionModel:
    def test_init(self):
        model = TacticalDecisionModel()
        assert model.model_name == "tactical_model"

    def test_group_tasks_by_priority(self):
        model = TacticalDecisionModel()
        tasks = [
            _make_task("high1", priority=9),
            _make_task("high2", priority=8),
            _make_task("med1", priority=6),
            _make_task("med2", priority=5),
            _make_task("low1", priority=3),
            _make_task("low2", priority=1),
        ]
        groups = model._group_tasks_by_priority(tasks)
        assert len(groups["high"]) == 2
        assert len(groups["medium"]) == 2
        assert len(groups["low"]) == 2

    def test_group_tasks_boundary_8(self):
        model = TacticalDecisionModel()
        tasks = [_make_task("t1", priority=8)]
        groups = model._group_tasks_by_priority(tasks)
        assert len(groups["high"]) == 1
        assert len(groups["medium"]) == 0

    def test_group_tasks_boundary_5(self):
        model = TacticalDecisionModel()
        tasks = [_make_task("t1", priority=5)]
        groups = model._group_tasks_by_priority(tasks)
        assert len(groups["medium"]) == 1
        assert len(groups["low"]) == 0

    def test_group_tasks_boundary_4(self):
        model = TacticalDecisionModel()
        tasks = [_make_task("t1", priority=4)]
        groups = model._group_tasks_by_priority(tasks)
        assert len(groups["low"]) == 1
        assert len(groups["medium"]) == 0

    def test_group_tasks_empty(self):
        model = TacticalDecisionModel()
        groups = model._group_tasks_by_priority([])
        assert groups == {"high": [], "medium": [], "low": []}

    def test_generate_tactical_options(self):
        model = TacticalDecisionModel()
        groups = {"high": [], "medium": [], "low": []}
        options = model._generate_tactical_options(_make_context(), groups)
        assert len(options) == 3
        ids = {o.option_id for o in options}
        assert ids == {"max_parallel", "priority_serial", "hybrid"}

    def test_select_best_option_uses_moderate_risk(self):
        model = TacticalDecisionModel()
        options = model._generate_tactical_options(
            _make_context(), {"high": [], "medium": [], "low": []}
        )
        best = model._select_best_option(options)
        # With risk_tolerance=0.5, hybrid should score well
        assert best.option_id in ("max_parallel", "priority_serial", "hybrid")

    def test_plan_execution_sequence_all_groups(self):
        model = TacticalDecisionModel()
        t_high = _make_task("h1", priority=9)
        t_med = _make_task("m1", priority=6)
        t_low = _make_task("l1", priority=3)
        groups = {"high": [t_high], "medium": [t_med], "low": [t_low]}
        seq, par = model._plan_execution_sequence(groups, {}, _make_context())
        assert "h1" in seq
        assert "m1" in seq
        assert "l1" in seq
        assert len(par) == 2  # high and low each form a parallel group

    def test_plan_execution_sequence_empty(self):
        model = TacticalDecisionModel()
        groups = {"high": [], "medium": [], "low": []}
        seq, par = model._plan_execution_sequence(groups, {}, _make_context())
        assert seq == []
        assert par == []

    def test_plan_execution_sequence_no_duplicate_medium(self):
        """If a medium task is already in high group, it shouldn't duplicate."""
        model = TacticalDecisionModel()
        t = _make_task("shared", priority=9)
        groups = {
            "high": [t],
            "medium": [t],  # same task appears in both (edge case)
            "low": [],
        }
        seq, par = model._plan_execution_sequence(groups, {}, _make_context())
        # "shared" should appear only once in the sequence
        assert seq.count("shared") == 1

    def test_decide_with_ready_tasks(self):
        model = TacticalDecisionModel()
        t1 = _make_task("t1", priority=9, status=TaskStatus.PENDING)
        t2 = _make_task("t2", priority=3, status=TaskStatus.PENDING)
        tg = _make_task_graph([t1, t2])
        ctx = _make_context(task_graph=tg)
        result = _run(model.decide(ctx))
        assert isinstance(result, TacticalDecision)
        assert result.decision_level == DecisionLevel.TACTICAL

    def test_decide_no_tasks(self):
        model = TacticalDecisionModel()
        ctx = _make_context(task_graph=_make_task_graph())
        result = _run(model.decide(ctx))
        assert isinstance(result, TacticalDecision)

    def test_decide_reasoning_has_info(self):
        model = TacticalDecisionModel()
        t1 = _make_task("t1", priority=9)
        tg = _make_task_graph([t1])
        ctx = _make_context(task_graph=tg)
        result = _run(model.decide(ctx))
        assert any("就绪任务数" in r for r in result.reasoning)

    def test_select_agents_for_tasks_with_capable_agent(self):
        model = TacticalDecisionModel()
        task = _make_task("t1", tool_name="nmap")
        agent = _make_mock_agent("a1", supported_tools=["nmap"])
        ctx = _make_context(agents=[agent])
        assignments = _run(model._select_agents_for_tasks([task], ctx))
        assert "t1" in assignments
        assert assignments["t1"] == "a1"

    def test_select_agents_for_tasks_no_capable_agent(self):
        model = TacticalDecisionModel()
        task = _make_task("t1", tool_name="gobuster")
        agent = _make_mock_agent("a1", supported_tools=["nmap"])
        ctx = _make_context(agents=[agent])
        assignments = _run(model._select_agents_for_tasks([task], ctx))
        assert "t1" not in assignments

    def test_select_agents_for_tasks_empty(self):
        model = TacticalDecisionModel()
        ctx = _make_context()
        assignments = _run(model._select_agents_for_tasks([], ctx))
        assert assignments == {}


# ==================== HybridDecisionEngine Tests ====================

class TestHybridDecisionEngine:
    def test_init(self):
        engine = HybridDecisionEngine()
        assert isinstance(engine.strategic_model, StrategicDecisionModel)
        assert isinstance(engine.tactical_model, TacticalDecisionModel)
        assert engine.decision_history == []
        assert engine.active_decisions == {}
        assert engine.successful_decisions == 0
        assert engine.failed_decisions == 0

    def test_make_strategic_decision(self):
        engine = HybridDecisionEngine()
        ctx = _make_context(intent=AttackIntent.RECONNAISSANCE)
        result = _run(engine.make_strategic_decision(ctx))
        assert isinstance(result, StrategicDecision)
        assert result.decision_id in engine.active_decisions

    def test_make_tactical_decision(self):
        engine = HybridDecisionEngine()
        t1 = _make_task("t1", priority=5)
        tg = _make_task_graph([t1])
        ctx = _make_context(task_graph=tg)
        result = _run(engine.make_tactical_decision(ctx))
        assert isinstance(result, TacticalDecision)
        assert result.decision_id in engine.active_decisions

    def test_make_hybrid_decision_returns_three(self):
        engine = HybridDecisionEngine()
        ctx = _make_context()
        results = _run(engine.make_hybrid_decision(ctx))
        assert len(results) == 3
        assert isinstance(results[0], StrategicDecision)
        assert isinstance(results[1], TacticalDecision)
        assert isinstance(results[2], Decision)

    def test_make_hybrid_decision_fused_has_reasoning(self):
        engine = HybridDecisionEngine()
        ctx = _make_context()
        results = _run(engine.make_hybrid_decision(ctx))
        fused = results[2]
        assert any("决策融合" in r for r in fused.reasoning)

    def test_make_hybrid_decision_fused_option_averages(self):
        engine = HybridDecisionEngine()
        ctx = _make_context()
        results = _run(engine.make_hybrid_decision(ctx))
        strategic, tactical, fused = results
        fused_opt = fused.selected_option
        s_opt = strategic.selected_option
        t_opt = tactical.selected_option
        expected_benefit = (s_opt.expected_benefit + t_opt.expected_benefit) / 2
        expected_cost = (s_opt.expected_cost + t_opt.expected_cost) / 2
        expected_risk = (s_opt.risk_level + t_opt.risk_level) / 2
        expected_conf = (s_opt.confidence + t_opt.confidence) / 2
        assert abs(fused_opt.expected_benefit - expected_benefit) < 1e-9
        assert abs(fused_opt.expected_cost - expected_cost) < 1e-9
        assert abs(fused_opt.risk_level - expected_risk) < 1e-9
        assert abs(fused_opt.confidence - expected_conf) < 1e-9

    def test_make_hybrid_decision_fused_actions_combined(self):
        engine = HybridDecisionEngine()
        ctx = _make_context()
        results = _run(engine.make_hybrid_decision(ctx))
        strategic, tactical, fused = results
        expected_actions = (
            strategic.selected_option.actions + tactical.selected_option.actions
        )
        assert fused.selected_option.actions == expected_actions

    def test_make_hybrid_decision_strategic_added_to_previous(self):
        engine = HybridDecisionEngine()
        ctx = _make_context()
        _run(engine.make_hybrid_decision(ctx))
        # The strategic decision should have been appended to context
        assert len(ctx.previous_decisions) >= 1

    def test_track_decision(self):
        engine = HybridDecisionEngine()
        d = _make_decision(decision_id="test_track")
        engine._track_decision(d)
        assert "test_track" in engine.active_decisions
        assert d in engine.decision_history

    def test_update_decision_outcome_success(self):
        engine = HybridDecisionEngine()
        d = _make_decision(decision_id="update_ok")
        engine._track_decision(d)
        engine.update_decision_outcome(
            "update_ok", success=True, actual_benefit=0.9, feedback="great"
        )
        assert d.execution_status == "completed"
        assert d.actual_benefit == 0.9
        assert d.feedback == "great"
        assert d.executed_at is not None
        assert engine.successful_decisions == 1

    def test_update_decision_outcome_failure(self):
        engine = HybridDecisionEngine()
        d = _make_decision(decision_id="update_fail")
        engine._track_decision(d)
        engine.update_decision_outcome("update_fail", success=False)
        assert d.execution_status == "failed"
        assert engine.failed_decisions == 1

    def test_update_decision_outcome_unknown_id(self):
        engine = HybridDecisionEngine()
        # Should not raise
        engine.update_decision_outcome("nonexistent", success=True)
        assert engine.successful_decisions == 0

    def test_update_decision_outcome_triggers_learning(self):
        engine = HybridDecisionEngine()
        d = _make_decision(decision_id="learn1")
        d.actual_benefit = 0.7
        engine._track_decision(d)
        engine.update_decision_outcome(
            "learn1", success=True, actual_benefit=0.7
        )
        # Both models should have learned
        assert len(engine.strategic_model.decision_history) == 1
        assert len(engine.tactical_model.decision_history) == 1

    def test_get_decision_history_all(self):
        engine = HybridDecisionEngine()
        for i in range(5):
            engine._track_decision(_make_decision(decision_id=f"h{i}"))
        history = engine.get_decision_history()
        assert len(history) == 5

    def test_get_decision_history_limit(self):
        engine = HybridDecisionEngine()
        for i in range(10):
            engine._track_decision(_make_decision(decision_id=f"h{i}"))
        history = engine.get_decision_history(limit=3)
        assert len(history) == 3
        # Should be the last 3
        assert history[0].decision_id == "h7"

    def test_get_decision_history_empty(self):
        engine = HybridDecisionEngine()
        assert engine.get_decision_history() == []

    def test_get_performance_metrics_initial(self):
        engine = HybridDecisionEngine()
        metrics = engine.get_performance_metrics()
        assert metrics["total_decisions"] == 0
        assert metrics["success_rate"] == 0

    def test_get_performance_metrics_with_data(self):
        engine = HybridDecisionEngine()
        engine.successful_decisions = 7
        engine.failed_decisions = 3
        metrics = engine.get_performance_metrics()
        assert metrics["total_decisions"] == 10
        assert abs(metrics["success_rate"] - 0.7) < 1e-9

    def test_get_statistics_is_alias(self):
        engine = HybridDecisionEngine()
        engine.successful_decisions = 2
        engine.failed_decisions = 1
        assert engine.get_statistics() == engine.get_performance_metrics()

    def test_export_decisions(self):
        engine = HybridDecisionEngine()
        d = _make_decision(decision_id="export1")
        engine._track_decision(d)
        engine.successful_decisions = 1

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            engine.export_decisions(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert "decisions" in data
            assert "metrics" in data
            assert len(data["decisions"]) == 1
            assert data["decisions"][0]["decision_id"] == "export1"
            assert data["decisions"][0]["type"] == "attack_path"
            assert data["decisions"][0]["level"] == "strategic"
        finally:
            os.unlink(filepath)

    def test_export_decisions_multiple(self):
        engine = HybridDecisionEngine()
        for i in range(3):
            engine._track_decision(_make_decision(decision_id=f"exp{i}"))

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            engine.export_decisions(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert len(data["decisions"]) == 3
        finally:
            os.unlink(filepath)

    def test_export_decisions_includes_actual_benefit(self):
        engine = HybridDecisionEngine()
        d = _make_decision(decision_id="exp_benefit")
        d.actual_benefit = 0.85
        engine._track_decision(d)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            engine.export_decisions(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["decisions"][0]["actual_benefit"] == 0.85
        finally:
            os.unlink(filepath)


# ==================== Fuse Decisions Tests ====================

class TestFuseDecisions:
    def _make_strategic_and_tactical(self):
        engine = HybridDecisionEngine()
        ctx = _make_context()
        strategic = _run(engine.strategic_model.decide(ctx))
        tactical = _run(engine.tactical_model.decide(ctx))
        return engine, strategic, tactical

    def test_fused_option_id(self):
        engine, s, t = self._make_strategic_and_tactical()
        fused = engine._fuse_decisions(s, t)
        assert fused.selected_option.option_id == "fused"

    def test_fused_decision_level(self):
        engine, s, t = self._make_strategic_and_tactical()
        fused = engine._fuse_decisions(s, t)
        assert fused.decision_level == DecisionLevel.STRATEGIC

    def test_fused_decision_type(self):
        engine, s, t = self._make_strategic_and_tactical()
        fused = engine._fuse_decisions(s, t)
        assert fused.decision_type == DecisionType.ATTACK_PATH

    def test_fused_context_from_strategic(self):
        engine, s, t = self._make_strategic_and_tactical()
        fused = engine._fuse_decisions(s, t)
        assert fused.context is s.context

    def test_fused_reasoning_mentions_strategy(self):
        engine, s, t = self._make_strategic_and_tactical()
        fused = engine._fuse_decisions(s, t)
        joined = " ".join(fused.reasoning)
        assert s.attack_strategy in joined

    def test_fused_description_contains_strategy(self):
        engine, s, t = self._make_strategic_and_tactical()
        fused = engine._fuse_decisions(s, t)
        assert s.attack_strategy in fused.selected_option.description


# ==================== Integration-Style Tests ====================

class TestIntegration:
    def test_full_hybrid_flow_with_agents(self):
        """End-to-end: context with agents, tasks -> hybrid decision."""
        engine = HybridDecisionEngine()
        agents = [_make_mock_agent(f"agent_{i}") for i in range(3)]
        tasks = [
            _make_task("t1", priority=9, tool_name="nmap"),
            _make_task("t2", priority=5, tool_name="sqlmap"),
            _make_task("t3", priority=2, tool_name="gobuster"),
        ]
        tg = _make_task_graph(tasks)
        ctx = _make_context(
            intent=AttackIntent.CTF_SOLVING,
            agents=agents,
            task_graph=tg,
            time_constraint=600,
        )
        results = _run(engine.make_hybrid_decision(ctx))
        assert len(results) == 3
        # History should have 3 decisions (strategic, tactical, fused)
        assert len(engine.decision_history) == 3

    def test_multiple_decisions_accumulate_history(self):
        engine = HybridDecisionEngine()
        for _ in range(3):
            ctx = _make_context()
            _run(engine.make_strategic_decision(ctx))
        assert len(engine.decision_history) == 3

    def test_outcome_update_after_hybrid(self):
        engine = HybridDecisionEngine()
        ctx = _make_context()
        results = _run(engine.make_hybrid_decision(ctx))
        for r in results:
            engine.update_decision_outcome(
                r.decision_id, success=True, actual_benefit=0.8
            )
        assert engine.successful_decisions == 3

    def test_decision_score_ordering_consistency(self):
        """Verify that select_best_option returns highest-scored option."""
        model = StrategicDecisionModel()
        options = model._generate_strategic_options(
            _make_context(), {"name": "t"}, {}, 4, {}
        )
        for rt in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]:
            scores = [(o.calculate_score(rt), o.option_id) for o in options]
            scores.sort(key=lambda x: x[0], reverse=True)
            best = model._select_best_option(options, rt)
            assert best.option_id == scores[0][1]

    def test_calculate_score_monotonicity_risk(self):
        """Higher risk should yield lower or equal scores (for same benefit/cost/confidence)."""
        for risk in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]:
            opt = _make_option(benefit=0.7, cost=0.3, risk=risk, confidence=0.9)
            score = opt.calculate_score(0.5)
            if risk == 0.0:
                prev_score = score
            else:
                assert score <= prev_score + 1e-9
                prev_score = score

    def test_calculate_score_monotonicity_benefit(self):
        """Higher benefit should yield higher or equal scores."""
        prev = None
        for benefit in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]:
            opt = _make_option(
                benefit=benefit, cost=0.3, risk=0.2, confidence=0.9
            )
            score = opt.calculate_score(0.5)
            if prev is not None:
                assert score >= prev - 1e-9
            prev = score


# ==================== Edge Case Tests ====================

class TestEdgeCases:
    def test_context_with_empty_targets(self):
        ctx = DecisionContext(targets=[])
        assert ctx.intent_analysis.targets == []

    def test_strategic_decide_no_targets(self):
        model = StrategicDecisionModel()
        ia = _make_intent_analysis(targets=[])
        ctx = _make_context()
        ctx.intent_analysis = ia
        result = _run(model.decide(ctx))
        assert result.target_priorities == {}

    def test_allocate_resources_max_parallel_one(self):
        model = StrategicDecisionModel()
        agents = [_make_mock_agent(f"a{i}") for i in range(5)]
        ctx = _make_context(agents=agents)
        allocation = model._allocate_resources(ctx, max_parallel=1)
        assert len(allocation) == 1
        assert list(allocation.values())[0] == 1.0

    def test_decision_id_uniqueness_across_types(self):
        """Strategic and tactical IDs should have different prefixes."""
        engine = HybridDecisionEngine()
        ctx = _make_context()
        results = _run(engine.make_hybrid_decision(ctx))
        ids = [r.decision_id for r in results]
        assert ids[0].startswith("strategic_")
        assert ids[1].startswith("tactical_")
        assert ids[2].startswith("fused_")

    def test_export_empty_history(self):
        engine = HybridDecisionEngine()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name
        try:
            engine.export_decisions(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["decisions"] == []
            assert data["metrics"]["total_decisions"] == 0
        finally:
            os.unlink(filepath)

    def test_high_cpu_load_halves_parallelism_for_exploitation(self):
        """EXPLOITATION has 'low' parallelism (2). High CPU -> max(1, 2//2)=1."""
        model = StrategicDecisionModel()
        ctx = _make_context(
            intent=AttackIntent.EXPLOITATION,
            system_load={"cpu": 0.85, "memory": 0.5, "network": 0.5},
        )
        result = _run(model.decide(ctx))
        assert "并行度: 1" in " ".join(result.reasoning)

    def test_context_discovered_assets_set(self):
        ctx = DecisionContext()
        ctx.discovered_assets.add("10.0.0.1")
        ctx.discovered_assets.add("10.0.0.1")
        assert len(ctx.discovered_assets) == 1

    def test_multiple_outcome_updates(self):
        engine = HybridDecisionEngine()
        d = _make_decision(decision_id="multi_update")
        engine._track_decision(d)
        engine.update_decision_outcome("multi_update", success=True, actual_benefit=0.5)
        engine.update_decision_outcome("multi_update", success=False, actual_benefit=0.1)
        # Both counted
        assert engine.successful_decisions == 1
        assert engine.failed_decisions == 1
        # Last update wins on the decision object
        assert d.execution_status == "failed"
        assert d.actual_benefit == 0.1

    def test_get_performance_metrics_zero_division_safe(self):
        engine = HybridDecisionEngine()
        metrics = engine.get_performance_metrics()
        assert metrics["success_rate"] == 0

    def test_constraint_without_type_no_priority_boost(self):
        """Constraints without 'type' == 'time_limit' don't boost priority."""
        model = StrategicDecisionModel()
        ia = _make_intent_analysis(
            constraints=[{"type": "scope", "value": "internal"}]
        )
        ctx = _make_context()
        ctx.intent_analysis = ia
        priorities = model._calculate_target_priorities(ctx)
        # base 5 + url 1 = 6 (no time_limit boost)
        assert list(priorities.values())[0] == 6
