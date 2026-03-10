"""
Tests for TaskDecomposer (kali_mcp/core/task_decomposer.py)

Covers:
- Enums: TaskCategory, TaskStatus
- Dataclasses: Task, TaskGraph, ExecutionPlan, StrategyTemplate
- TaskGraph operations: add_task, get_ready_tasks, validate (cycles, missing deps)
- ExecutionPlan: get_phase_tasks
- StrategyTemplate: matches
- TaskDecomposer: __init__, decompose, template selection, strategy blueprint extraction,
  stage category inference, task graph building, dependency resolution, parameter building,
  execution phase calculation, duration estimation
"""

import pytest
from datetime import datetime
from typing import List

from kali_mcp.core.task_decomposer import (
    TaskCategory,
    TaskStatus,
    Task,
    TaskGraph,
    ExecutionPlan,
    StrategyTemplate,
    TaskDecomposer,
)
from kali_mcp.core.intent_analyzer import (
    IntentAnalysis,
    AttackIntent,
    TargetInfo,
    TargetType,
)


# ===================== Fixtures =====================


@pytest.fixture
def decomposer():
    return TaskDecomposer()


@pytest.fixture
def url_target():
    return TargetInfo(
        original="http://example.com",
        type=TargetType.URL,
        value="http://example.com",
        protocol="http",
    )


@pytest.fixture
def ip_target():
    return TargetInfo(
        original="192.168.1.100",
        type=TargetType.IP_ADDRESS,
        value="192.168.1.100",
        port=8080,
    )


@pytest.fixture
def ip_target_no_port():
    return TargetInfo(
        original="10.0.0.1",
        type=TargetType.IP_ADDRESS,
        value="10.0.0.1",
    )


@pytest.fixture
def domain_target():
    return TargetInfo(
        original="example.com",
        type=TargetType.DOMAIN,
        value="example.com",
    )


@pytest.fixture
def recon_intent(url_target):
    return IntentAnalysis(
        user_input="scan http://example.com",
        intent=AttackIntent.RECONNAISSANCE,
        targets=[url_target],
        constraints=[],
    )


@pytest.fixture
def ctf_intent(url_target):
    return IntentAnalysis(
        user_input="solve CTF at http://example.com",
        intent=AttackIntent.CTF_SOLVING,
        targets=[url_target],
        constraints=[],
    )


@pytest.fixture
def exploit_intent(ip_target):
    return IntentAnalysis(
        user_input="exploit 192.168.1.100",
        intent=AttackIntent.EXPLOITATION,
        targets=[ip_target],
        constraints=[],
    )


@pytest.fixture
def apt_intent(url_target):
    return IntentAnalysis(
        user_input="APT simulation on http://example.com",
        intent=AttackIntent.APT_SIMULATION,
        targets=[url_target],
        constraints=[],
    )


@pytest.fixture
def vuln_scan_intent(url_target):
    return IntentAnalysis(
        user_input="vulnerability scan http://example.com",
        intent=AttackIntent.VULNERABILITY_SCANNING,
        targets=[url_target],
        constraints=[],
    )


@pytest.fixture
def multi_target_intent(url_target, ip_target):
    return IntentAnalysis(
        user_input="scan http://example.com and 192.168.1.100",
        intent=AttackIntent.RECONNAISSANCE,
        targets=[url_target, ip_target],
        constraints=[],
    )


def make_task(task_id, name="test", category=TaskCategory.SCANNING,
              tool_name="nmap", parameters=None, dependencies=None,
              priority=5, status=TaskStatus.PENDING, estimated_duration=None):
    return Task(
        task_id=task_id,
        name=name,
        category=category,
        tool_name=tool_name,
        parameters=parameters or {},
        dependencies=dependencies or [],
        priority=priority,
        status=status,
        estimated_duration=estimated_duration,
    )


# ===================== TaskCategory Enum =====================


class TestTaskCategory:
    def test_reconnaissance_value(self):
        assert TaskCategory.RECONNAISSANCE.value == "recon"

    def test_scanning_value(self):
        assert TaskCategory.SCANNING.value == "scan"

    def test_vulnerability_scanning_same_as_scanning(self):
        """VULNERABILITY_SCANNING and SCANNING share the same value 'scan'."""
        assert TaskCategory.VULNERABILITY_SCANNING.value == "scan"
        assert TaskCategory.SCANNING.value == TaskCategory.VULNERABILITY_SCANNING.value

    def test_exploitation_value(self):
        assert TaskCategory.EXPLOITATION.value == "exploit"

    def test_post_exploitation_value(self):
        assert TaskCategory.POST_EXPLOITATION.value == "post_exploit"

    def test_reporting_value(self):
        assert TaskCategory.REPORTING.value == "report"

    def test_construct_from_value(self):
        """TaskCategory('recon') should yield RECONNAISSANCE."""
        assert TaskCategory("recon") == TaskCategory.RECONNAISSANCE

    def test_construct_scan_yields_scanning(self):
        """TaskCategory('scan') returns the first member with that value (SCANNING)."""
        cat = TaskCategory("scan")
        assert cat.value == "scan"


# ===================== TaskStatus Enum =====================


class TestTaskStatus:
    def test_all_values(self):
        expected = {"pending", "ready", "running", "completed", "failed", "skipped"}
        actual = {s.value for s in TaskStatus}
        assert actual == expected

    def test_pending(self):
        assert TaskStatus.PENDING.value == "pending"

    def test_ready(self):
        assert TaskStatus.READY.value == "ready"

    def test_running(self):
        assert TaskStatus.RUNNING.value == "running"

    def test_completed(self):
        assert TaskStatus.COMPLETED.value == "completed"

    def test_failed(self):
        assert TaskStatus.FAILED.value == "failed"

    def test_skipped(self):
        assert TaskStatus.SKIPPED.value == "skipped"


# ===================== Task Dataclass =====================


class TestTask:
    def test_minimal_creation(self):
        t = Task(
            task_id="t1",
            name="port scan",
            category=TaskCategory.RECONNAISSANCE,
            tool_name="nmap_scan",
            parameters={"target": "10.0.0.1"},
        )
        assert t.task_id == "t1"
        assert t.name == "port scan"
        assert t.category == TaskCategory.RECONNAISSANCE
        assert t.tool_name == "nmap_scan"
        assert t.parameters == {"target": "10.0.0.1"}

    def test_defaults(self):
        t = make_task("t0")
        assert t.dependencies == []
        assert t.priority == 5
        assert t.estimated_duration is None
        assert t.description is None
        assert t.tags == set()
        assert t.status == TaskStatus.PENDING
        assert t.result is None
        assert t.error is None

    def test_custom_fields(self):
        t = Task(
            task_id="t2",
            name="vuln scan",
            category=TaskCategory.SCANNING,
            tool_name="nuclei",
            parameters={},
            dependencies=["t1"],
            priority=9,
            estimated_duration=120,
            description="run nuclei scan",
            tags={"web", "vuln"},
            status=TaskStatus.RUNNING,
            result={"vulns": 3},
            error=None,
        )
        assert t.dependencies == ["t1"]
        assert t.priority == 9
        assert t.estimated_duration == 120
        assert t.description == "run nuclei scan"
        assert t.tags == {"web", "vuln"}
        assert t.status == TaskStatus.RUNNING
        assert t.result == {"vulns": 3}

    def test_mutable_defaults_are_independent(self):
        t1 = make_task("a")
        t2 = make_task("b")
        t1.dependencies.append("x")
        assert "x" not in t2.dependencies

        t1.tags.add("special")
        assert "special" not in t2.tags


# ===================== TaskGraph =====================


class TestTaskGraph:
    def test_add_single_task(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t = make_task("t1")
        g.add_task(t)

        assert "t1" in g.tasks
        assert "t1" in g.adjacency_list
        assert "t1" in g.reverse_adjacency
        assert g.adjacency_list["t1"] == set()
        assert g.reverse_adjacency["t1"] == set()

    def test_add_task_with_dependency(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = make_task("t1")
        t2 = make_task("t2", dependencies=["t1"])
        g.add_task(t1)
        g.add_task(t2)

        assert "t2" in g.adjacency_list["t1"]   # t1 → t2
        assert "t1" in g.reverse_adjacency["t2"]  # t2 depends on t1

    def test_add_task_dependency_before_dep_added(self):
        """Adding a task whose dependency hasn't been added yet should still create entries."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t2 = make_task("t2", dependencies=["t1"])
        g.add_task(t2)

        # adjacency for t1 should exist even though t1 is not in tasks
        assert "t1" in g.adjacency_list
        assert "t2" in g.adjacency_list["t1"]

    def test_add_multiple_dependencies(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = make_task("t1")
        t2 = make_task("t2")
        t3 = make_task("t3", dependencies=["t1", "t2"])
        g.add_task(t1)
        g.add_task(t2)
        g.add_task(t3)

        assert "t3" in g.adjacency_list["t1"]
        assert "t3" in g.adjacency_list["t2"]
        assert g.reverse_adjacency["t3"] == {"t1", "t2"}

    # ---------- get_ready_tasks ----------

    def test_get_ready_tasks_no_deps(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2"))

        ready = g.get_ready_tasks()
        ready_ids = {t.task_id for t in ready}
        assert ready_ids == {"t1", "t2"}

    def test_get_ready_tasks_with_completed_dep(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", status=TaskStatus.COMPLETED))
        g.add_task(make_task("t2", dependencies=["t1"]))

        ready = g.get_ready_tasks()
        ready_ids = {t.task_id for t in ready}
        assert ready_ids == {"t2"}

    def test_get_ready_tasks_with_pending_dep(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2", dependencies=["t1"]))

        ready = g.get_ready_tasks()
        ready_ids = {t.task_id for t in ready}
        # t2 not ready because t1 is still PENDING
        assert ready_ids == {"t1"}

    def test_get_ready_tasks_excludes_non_pending(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", status=TaskStatus.RUNNING))
        g.add_task(make_task("t2", status=TaskStatus.COMPLETED))
        g.add_task(make_task("t3", status=TaskStatus.FAILED))
        g.add_task(make_task("t4"))

        ready = g.get_ready_tasks()
        ready_ids = {t.task_id for t in ready}
        assert ready_ids == {"t4"}

    def test_get_ready_tasks_missing_dep_in_graph(self):
        """If dependency is not in tasks dict, it's skipped in the completeness check."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t = make_task("t2", dependencies=["nonexistent"])
        g.add_task(t)

        ready = g.get_ready_tasks()
        # Since nonexistent is not in tasks, the `if dep_id in self.tasks` filter skips it,
        # so all() returns True on the empty filtered list → t2 is ready
        ready_ids = {t.task_id for t in ready}
        assert "t2" in ready_ids

    def test_get_ready_tasks_empty_graph(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        assert g.get_ready_tasks() == []

    def test_get_ready_tasks_chain(self):
        """In a chain t1→t2→t3, only t1 should be ready when all are PENDING."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2", dependencies=["t1"]))
        g.add_task(make_task("t3", dependencies=["t2"]))

        ready = g.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].task_id == "t1"

    # ---------- validate ----------

    def test_validate_valid_graph(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2", dependencies=["t1"]))
        g.add_task(make_task("t3", dependencies=["t1"]))
        g.add_task(make_task("t4", dependencies=["t2", "t3"]))

        valid, errors = g.validate()
        assert valid is True
        assert errors == []

    def test_validate_empty_graph(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        valid, errors = g.validate()
        assert valid is True
        assert errors == []

    def test_validate_missing_dependency(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t = make_task("t1", dependencies=["missing_dep"])
        g.add_task(t)

        valid, errors = g.validate()
        assert valid is False
        assert len(errors) >= 1
        assert any("missing_dep" in e for e in errors)

    def test_validate_cycle_self_loop(self):
        """Detect a self-referencing cycle via adjacency_list."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t = make_task("t1", dependencies=["t1"])
        g.add_task(t)

        valid, errors = g.validate()
        assert valid is False
        assert any("循环" in e or "t1" in e for e in errors)

    def test_validate_cycle_two_nodes(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = make_task("t1", dependencies=["t2"])
        t2 = make_task("t2", dependencies=["t1"])
        g.add_task(t1)
        g.add_task(t2)

        valid, errors = g.validate()
        assert valid is False

    def test_validate_cycle_three_nodes(self):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = make_task("t1", dependencies=["t3"])
        t2 = make_task("t2", dependencies=["t1"])
        t3 = make_task("t3", dependencies=["t2"])
        g.add_task(t1)
        g.add_task(t2)
        g.add_task(t3)

        valid, errors = g.validate()
        assert valid is False

    def test_validate_no_cycle_diamond(self):
        """Diamond DAG: t1→t2, t1→t3, t2→t4, t3→t4 is valid."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2", dependencies=["t1"]))
        g.add_task(make_task("t3", dependencies=["t1"]))
        g.add_task(make_task("t4", dependencies=["t2", "t3"]))

        valid, errors = g.validate()
        assert valid is True

    def test_validate_multiple_errors(self):
        """Graph with both missing dep and cycle should report both."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        t1 = make_task("t1", dependencies=["t2"])
        t2 = make_task("t2", dependencies=["t1"])
        # t3 depends on a task not in graph
        t3 = make_task("t3", dependencies=["nonexistent"])
        g.add_task(t1)
        g.add_task(t2)
        g.add_task(t3)

        valid, errors = g.validate()
        assert valid is False
        assert len(errors) >= 2


# ===================== ExecutionPlan =====================


class TestExecutionPlan:
    def _make_plan(self, tasks: List[Task], phases: List[List[str]]):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        for t in tasks:
            g.add_task(t)
        return ExecutionPlan(
            task_graph=g,
            phases=phases,
            estimated_duration=100,
            metadata={"strategy": "test"},
        )

    def test_get_phase_tasks_valid(self):
        t1 = make_task("t1")
        t2 = make_task("t2")
        t3 = make_task("t3")
        plan = self._make_plan([t1, t2, t3], [["t1", "t2"], ["t3"]])

        phase0 = plan.get_phase_tasks(0)
        assert len(phase0) == 2
        assert {t.task_id for t in phase0} == {"t1", "t2"}

        phase1 = plan.get_phase_tasks(1)
        assert len(phase1) == 1
        assert phase1[0].task_id == "t3"

    def test_get_phase_tasks_out_of_range(self):
        t1 = make_task("t1")
        plan = self._make_plan([t1], [["t1"]])
        assert plan.get_phase_tasks(5) == []
        assert plan.get_phase_tasks(1) == []

    def test_get_phase_tasks_missing_task_id(self):
        """If a phase references a task_id not in the graph, it's filtered out."""
        t1 = make_task("t1")
        plan = self._make_plan([t1], [["t1", "ghost"]])

        phase0 = plan.get_phase_tasks(0)
        assert len(phase0) == 1
        assert phase0[0].task_id == "t1"

    def test_get_phase_tasks_empty_phases(self):
        plan = self._make_plan([], [])
        assert plan.get_phase_tasks(0) == []


# ===================== StrategyTemplate =====================


class TestStrategyTemplate:
    def test_matches_true(self):
        st = StrategyTemplate(
            name="test",
            description="test strategy",
            required_intents={AttackIntent.RECONNAISSANCE, AttackIntent.CTF_SOLVING},
            task_template=[],
        )
        assert st.matches(AttackIntent.RECONNAISSANCE) is True
        assert st.matches(AttackIntent.CTF_SOLVING) is True

    def test_matches_false(self):
        st = StrategyTemplate(
            name="test",
            description="test strategy",
            required_intents={AttackIntent.RECONNAISSANCE},
            task_template=[],
        )
        assert st.matches(AttackIntent.EXPLOITATION) is False

    def test_matches_empty_intents(self):
        st = StrategyTemplate(
            name="empty",
            description="no intents",
            required_intents=set(),
            task_template=[],
        )
        assert st.matches(AttackIntent.RECONNAISSANCE) is False


# ===================== TaskDecomposer Init =====================


class TestTaskDecomposerInit:
    def test_strategy_templates_loaded(self, decomposer):
        templates = decomposer._strategy_templates
        assert len(templates) == 5

    def test_template_names(self, decomposer):
        names = {t.name for t in decomposer._strategy_templates}
        assert names == {
            "ctf_intensive",
            "comprehensive_apt",
            "fast_recon",
            "vuln_scan",
            "exploit_chain",
        }

    def test_ctf_template_matches_ctf(self, decomposer):
        ctf_template = next(t for t in decomposer._strategy_templates if t.name == "ctf_intensive")
        assert ctf_template.matches(AttackIntent.CTF_SOLVING)

    def test_apt_template_matches_apt_and_full_compromise(self, decomposer):
        apt_template = next(t for t in decomposer._strategy_templates if t.name == "comprehensive_apt")
        assert apt_template.matches(AttackIntent.APT_SIMULATION)
        assert apt_template.matches(AttackIntent.FULL_COMPROMISE)

    def test_exploit_template(self, decomposer):
        exploit_template = next(t for t in decomposer._strategy_templates if t.name == "exploit_chain")
        assert exploit_template.matches(AttackIntent.EXPLOITATION)

    def test_vuln_scan_template(self, decomposer):
        vuln_template = next(t for t in decomposer._strategy_templates if t.name == "vuln_scan")
        assert vuln_template.matches(AttackIntent.VULNERABILITY_SCANNING)

    def test_fast_recon_template(self, decomposer):
        recon_template = next(t for t in decomposer._strategy_templates if t.name == "fast_recon")
        assert recon_template.matches(AttackIntent.RECONNAISSANCE)


# ===================== _select_template =====================


class TestSelectTemplate:
    def test_selects_ctf_for_ctf_intent(self, decomposer):
        t = decomposer._select_template(AttackIntent.CTF_SOLVING)
        assert t.name == "ctf_intensive"

    def test_selects_recon_for_recon_intent(self, decomposer):
        t = decomposer._select_template(AttackIntent.RECONNAISSANCE)
        assert t.name == "fast_recon"

    def test_selects_exploit_for_exploitation(self, decomposer):
        t = decomposer._select_template(AttackIntent.EXPLOITATION)
        assert t.name == "exploit_chain"

    def test_selects_vuln_scan(self, decomposer):
        t = decomposer._select_template(AttackIntent.VULNERABILITY_SCANNING)
        assert t.name == "vuln_scan"

    def test_selects_apt_for_apt_simulation(self, decomposer):
        t = decomposer._select_template(AttackIntent.APT_SIMULATION)
        assert t.name == "comprehensive_apt"

    def test_selects_apt_for_full_compromise(self, decomposer):
        t = decomposer._select_template(AttackIntent.FULL_COMPROMISE)
        assert t.name == "comprehensive_apt"

    def test_default_fallback_for_unknown_intent(self, decomposer):
        """Intents not matched by any template should fall back to first template."""
        t = decomposer._select_template(AttackIntent.DATA_EXFILTRATION)
        # first template is ctf_intensive (index 0)
        assert t == decomposer._strategy_templates[0]

    def test_default_fallback_privilege_escalation(self, decomposer):
        t = decomposer._select_template(AttackIntent.PRIVILEGE_ESCALATION)
        assert t == decomposer._strategy_templates[0]


# ===================== _extract_strategy_blueprint =====================


class TestExtractStrategyBlueprint:
    def test_returns_none_no_constraints(self, url_target):
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is None

    def test_returns_none_no_matching_type(self, url_target):
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "time_limit", "value": 30}],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is None

    def test_extracts_execution_strategy(self, url_target):
        strategy = {"stages": [{"id": "recon", "tools": ["nmap"]}], "name": "my_strat"}
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is strategy

    def test_extracts_strategy_blueprint_type(self, url_target):
        strategy = {"stages": [{"id": "scan"}]}
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "strategy_blueprint", "strategy": strategy}],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is strategy

    def test_extracts_pentest_strategy_type(self, url_target):
        strategy = {"stages": [{"id": "exploit"}]}
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "pentest_strategy", "strategy": strategy}],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is strategy

    def test_case_insensitive_type(self, url_target):
        strategy = {"stages": [{"id": "s1"}]}
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "Execution_Strategy", "strategy": strategy}],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is strategy

    def test_rejects_strategy_without_stages_list(self, url_target):
        # strategy is a dict but stages is not a list
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": {"stages": "not-a-list"}}],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is None

    def test_rejects_strategy_not_dict(self, url_target):
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": "just-a-string"}],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is None

    def test_skips_non_dict_constraints(self, url_target):
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=["not-a-dict", 42, None],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is None

    def test_first_matching_constraint_wins(self, url_target):
        s1 = {"stages": [{"id": "first"}]}
        s2 = {"stages": [{"id": "second"}]}
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[
                {"type": "execution_strategy", "strategy": s1},
                {"type": "pentest_strategy", "strategy": s2},
            ],
        )
        result = TaskDecomposer._extract_strategy_blueprint(intent)
        assert result is s1


# ===================== _infer_stage_category =====================


class TestInferStageCategory:
    @pytest.mark.parametrize("stage_id,expected", [
        ("recon_phase", TaskCategory.RECONNAISSANCE),
        ("network_mapping", TaskCategory.RECONNAISSANCE),
        ("attack_surface", TaskCategory.RECONNAISSANCE),
        ("RECON", TaskCategory.RECONNAISSANCE),
        ("exploit_vuln", TaskCategory.EXPLOITATION),
        ("flag_extraction", TaskCategory.EXPLOITATION),
        ("pivot_internal", TaskCategory.EXPLOITATION),
        ("lateral_movement", TaskCategory.EXPLOITATION),
        ("final_report", TaskCategory.REPORTING),
        ("fix_issues", TaskCategory.REPORTING),
        ("remediation_plan", TaskCategory.REPORTING),
        ("vuln_scan", TaskCategory.SCANNING),
        ("directory_brute", TaskCategory.SCANNING),
        ("unknown_phase", TaskCategory.SCANNING),
        ("", TaskCategory.SCANNING),
    ])
    def test_stage_category_inference(self, stage_id, expected):
        result = TaskDecomposer._infer_stage_category(stage_id)
        assert result == expected

    def test_none_input(self):
        result = TaskDecomposer._infer_stage_category(None)
        assert result == TaskCategory.SCANNING


# ===================== _build_task_parameters =====================


class TestBuildTaskParameters:
    def test_url_target_params(self, decomposer, url_target, recon_intent):
        template = {"tool": "whatweb", "parameters": {"extra": "val"}}
        params = decomposer._build_task_parameters(template, url_target, recon_intent)

        assert params["target"] == "http://example.com"
        assert params["url"] == "http://example.com"
        assert params["extra"] == "val"

    def test_ip_target_with_port(self, decomposer, ip_target, exploit_intent):
        template = {"tool": "nmap", "parameters": {}}
        params = decomposer._build_task_parameters(template, ip_target, exploit_intent)

        assert params["target"] == "192.168.1.100:8080"

    def test_ip_target_no_port(self, decomposer, ip_target_no_port):
        intent = IntentAnalysis(
            user_input="scan",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[ip_target_no_port],
            constraints=[],
        )
        template = {"tool": "nmap", "parameters": {}}
        params = decomposer._build_task_parameters(template, ip_target_no_port, intent)

        assert params["target"] == "10.0.0.1"
        assert "url" not in params
        assert "domain" not in params

    def test_domain_target_params(self, decomposer, domain_target):
        intent = IntentAnalysis(
            user_input="scan",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[domain_target],
            constraints=[],
        )
        template = {"tool": "subfinder", "parameters": {}}
        params = decomposer._build_task_parameters(template, domain_target, intent)

        assert params["target"] == "example.com"
        assert params["domain"] == "example.com"

    def test_template_params_merged(self, decomposer, url_target, recon_intent):
        template = {"tool": "nmap", "parameters": {"scan_type": "-sV", "ports": "1-1000"}}
        params = decomposer._build_task_parameters(template, url_target, recon_intent)

        assert params["scan_type"] == "-sV"
        assert params["ports"] == "1-1000"

    def test_template_params_override_base(self, decomposer, url_target, recon_intent):
        """Template parameters override the base 'target' if they include one."""
        template = {"tool": "nmap", "parameters": {"target": "overridden"}}
        params = decomposer._build_task_parameters(template, url_target, recon_intent)

        assert params["target"] == "overridden"

    def test_time_limit_constraint_adds_timeout(self, decomposer, url_target):
        intent = IntentAnalysis(
            user_input="quick scan",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "time_limit", "value": 60}],
        )
        template = {"tool": "nmap", "parameters": {}}
        params = decomposer._build_task_parameters(template, url_target, intent)

        assert params["timeout"] == 30

    def test_no_time_limit_no_timeout(self, decomposer, url_target, recon_intent):
        template = {"tool": "nmap", "parameters": {}}
        params = decomposer._build_task_parameters(template, url_target, recon_intent)

        assert "timeout" not in params

    def test_no_template_parameters_key(self, decomposer, url_target, recon_intent):
        template = {"tool": "nmap"}  # no "parameters" key
        params = decomposer._build_task_parameters(template, url_target, recon_intent)

        assert params["target"] == "http://example.com"


# ===================== _generate_tasks_for_target =====================


class TestGenerateTasksForTarget:
    def test_creates_correct_number_of_tasks(self, decomposer, url_target, ctf_intent):
        template = decomposer._select_template(AttackIntent.CTF_SOLVING)
        tasks = decomposer._generate_tasks_for_target(url_target, 0, ctf_intent, template)

        assert len(tasks) == len(template.task_template)

    def test_task_ids_follow_pattern(self, decomposer, url_target, ctf_intent):
        template = decomposer._select_template(AttackIntent.CTF_SOLVING)
        tasks = decomposer._generate_tasks_for_target(url_target, 0, ctf_intent, template)

        for i, t in enumerate(tasks):
            assert t.task_id == f"url_0_{i}"

    def test_task_ids_with_different_target_idx(self, decomposer, ip_target, exploit_intent):
        template = decomposer._select_template(AttackIntent.EXPLOITATION)
        tasks = decomposer._generate_tasks_for_target(ip_target, 3, exploit_intent, template)

        for i, t in enumerate(tasks):
            assert t.task_id == f"ip_3_{i}"

    def test_integer_dependencies_resolved(self, decomposer, url_target, ctf_intent):
        """CTF template has integer dependencies like [0], [1], [2] — they should be resolved to task IDs."""
        template = decomposer._select_template(AttackIntent.CTF_SOLVING)
        tasks = decomposer._generate_tasks_for_target(url_target, 0, ctf_intent, template)

        # Second task (whatweb) depends on first (masscan) → dep [0] → "url_0_0"
        assert "url_0_0" in tasks[1].dependencies

        # Third task (gobuster) depends on second → dep [1] → "url_0_1"
        assert "url_0_1" in tasks[2].dependencies

    def test_string_dependencies_kept(self, decomposer, url_target):
        custom_template = StrategyTemplate(
            name="custom",
            description="test",
            required_intents={AttackIntent.RECONNAISSANCE},
            task_template=[
                {"tool": "nmap", "category": "recon"},
                {"tool": "nuclei", "category": "scan", "dependencies": ["external_task"]},
            ],
        )
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[],
        )
        tasks = decomposer._generate_tasks_for_target(url_target, 0, intent, custom_template)

        assert "external_task" in tasks[1].dependencies

    def test_no_dependencies(self, decomposer, url_target, recon_intent):
        """fast_recon template tasks 0 and 1 have no dependencies."""
        template = decomposer._select_template(AttackIntent.RECONNAISSANCE)
        tasks = decomposer._generate_tasks_for_target(url_target, 0, recon_intent, template)

        assert tasks[0].dependencies == []
        assert tasks[1].dependencies == []  # subfinder has no dep in fast_recon

    def test_task_tags_as_set(self, decomposer, url_target, ctf_intent):
        template = decomposer._select_template(AttackIntent.CTF_SOLVING)
        tasks = decomposer._generate_tasks_for_target(url_target, 0, ctf_intent, template)

        # First task should have tags ["quick", "recon"] → set
        assert tasks[0].tags == {"quick", "recon"}

    def test_task_priority_from_template(self, decomposer, url_target, ctf_intent):
        template = decomposer._select_template(AttackIntent.CTF_SOLVING)
        tasks = decomposer._generate_tasks_for_target(url_target, 0, ctf_intent, template)

        # First task (masscan) has priority 9
        assert tasks[0].priority == 9

    def test_task_estimated_duration(self, decomposer, url_target, ctf_intent):
        template = decomposer._select_template(AttackIntent.CTF_SOLVING)
        tasks = decomposer._generate_tasks_for_target(url_target, 0, ctf_intent, template)

        # First task (masscan) has duration 30
        assert tasks[0].estimated_duration == 30

    def test_default_task_name_when_not_specified(self, decomposer, url_target):
        custom_template = StrategyTemplate(
            name="custom",
            description="test",
            required_intents={AttackIntent.RECONNAISSANCE},
            task_template=[
                {"tool": "nmap", "category": "recon"},
            ],
        )
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[],
        )
        tasks = decomposer._generate_tasks_for_target(url_target, 0, intent, custom_template)

        # Default name format: f"{task_template['tool']} on {target.value}"
        assert "nmap" in tasks[0].name
        assert "http://example.com" in tasks[0].name


# ===================== _build_task_graph =====================


class TestBuildTaskGraph:
    def test_single_target(self, decomposer, recon_intent):
        template = decomposer._select_template(AttackIntent.RECONNAISSANCE)
        graph = decomposer._build_task_graph(recon_intent, template)

        assert len(graph.tasks) == len(template.task_template)

    def test_multi_target(self, decomposer, multi_target_intent):
        template = decomposer._select_template(AttackIntent.RECONNAISSANCE)
        graph = decomposer._build_task_graph(multi_target_intent, template)

        # fast_recon has 3 tasks per target, 2 targets = 6 tasks
        assert len(graph.tasks) == 6

    def test_graph_validates(self, decomposer, recon_intent):
        template = decomposer._select_template(AttackIntent.RECONNAISSANCE)
        graph = decomposer._build_task_graph(recon_intent, template)

        valid, errors = graph.validate()
        assert valid is True, f"Graph validation failed: {errors}"


# ===================== _calculate_execution_phases =====================


class TestCalculateExecutionPhases:
    def test_independent_tasks_single_phase(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2"))
        g.add_task(make_task("t3"))

        phases = decomposer._calculate_execution_phases(g)
        assert len(phases) == 1
        assert set(phases[0]) == {"t1", "t2", "t3"}

    def test_linear_chain(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2", dependencies=["t1"]))
        g.add_task(make_task("t3", dependencies=["t2"]))

        phases = decomposer._calculate_execution_phases(g)
        assert len(phases) == 3
        assert phases[0] == ["t1"]
        assert phases[1] == ["t2"]
        assert phases[2] == ["t3"]

    def test_diamond_dag(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2", dependencies=["t1"]))
        g.add_task(make_task("t3", dependencies=["t1"]))
        g.add_task(make_task("t4", dependencies=["t2", "t3"]))

        phases = decomposer._calculate_execution_phases(g)
        assert len(phases) == 3
        assert phases[0] == ["t1"]
        assert set(phases[1]) == {"t2", "t3"}
        assert phases[2] == ["t4"]

    def test_empty_graph(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        phases = decomposer._calculate_execution_phases(g)
        assert phases == []

    def test_phases_are_sorted(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("c"))
        g.add_task(make_task("a"))
        g.add_task(make_task("b"))

        phases = decomposer._calculate_execution_phases(g)
        assert len(phases) == 1
        assert phases[0] == ["a", "b", "c"]  # sorted

    def test_wide_fan_out(self, decomposer):
        """One root with many parallel children → 2 phases."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("root"))
        for i in range(5):
            g.add_task(make_task(f"child_{i}", dependencies=["root"]))

        phases = decomposer._calculate_execution_phases(g)
        assert len(phases) == 2
        assert phases[0] == ["root"]
        assert len(phases[1]) == 5


# ===================== _estimate_total_duration =====================


class TestEstimateTotalDuration:
    def test_with_explicit_durations(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", estimated_duration=100))
        g.add_task(make_task("t2", estimated_duration=200))

        total = decomposer._estimate_total_duration(g)
        assert total == 300

    def test_default_recon_duration(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", category=TaskCategory.RECONNAISSANCE))

        total = decomposer._estimate_total_duration(g)
        assert total == 60

    def test_default_scanning_duration(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", category=TaskCategory.SCANNING))

        total = decomposer._estimate_total_duration(g)
        assert total == 120

    def test_default_exploitation_duration(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", category=TaskCategory.EXPLOITATION))

        total = decomposer._estimate_total_duration(g)
        assert total == 300

    def test_default_post_exploitation_duration(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", category=TaskCategory.POST_EXPLOITATION))

        total = decomposer._estimate_total_duration(g)
        assert total == 180

    def test_default_reporting_duration(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", category=TaskCategory.REPORTING))

        total = decomposer._estimate_total_duration(g)
        assert total == 30

    def test_mixed_explicit_and_default(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", category=TaskCategory.RECONNAISSANCE, estimated_duration=10))
        g.add_task(make_task("t2", category=TaskCategory.EXPLOITATION))

        total = decomposer._estimate_total_duration(g)
        assert total == 310  # 10 (explicit) + 300 (default exploit)

    def test_empty_graph_zero_duration(self, decomposer):
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        assert decomposer._estimate_total_duration(g) == 0

    def test_vulnerability_scanning_uses_scan_default(self, decomposer):
        """VULNERABILITY_SCANNING has the same value as SCANNING, so it should use 120."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1", category=TaskCategory.VULNERABILITY_SCANNING))

        total = decomposer._estimate_total_duration(g)
        assert total == 120


# ===================== decompose (Integration) =====================


class TestDecompose:
    def test_recon_decompose(self, decomposer, recon_intent):
        plan = decomposer.decompose(recon_intent)

        assert isinstance(plan, ExecutionPlan)
        assert len(plan.task_graph.tasks) > 0
        assert len(plan.phases) > 0
        assert plan.estimated_duration > 0
        assert plan.metadata["strategy"] == "fast_recon"
        assert plan.metadata["strategy_mode"] == "template"
        assert plan.metadata["intent"] == "reconnaissance"
        assert plan.metadata["target_count"] == 1
        assert "created_at" in plan.metadata

    def test_ctf_decompose(self, decomposer, ctf_intent):
        plan = decomposer.decompose(ctf_intent)

        assert plan.metadata["strategy"] == "ctf_intensive"
        assert plan.metadata["intent"] == "ctf_solving"
        # CTF template has 5 tasks
        assert len(plan.task_graph.tasks) == 5

    def test_exploit_decompose(self, decomposer, exploit_intent):
        plan = decomposer.decompose(exploit_intent)

        assert plan.metadata["strategy"] == "exploit_chain"
        assert len(plan.task_graph.tasks) == 3  # exploit_chain has 3 tasks

    def test_apt_decompose(self, decomposer, apt_intent):
        plan = decomposer.decompose(apt_intent)

        assert plan.metadata["strategy"] == "comprehensive_apt"
        # comprehensive_apt has 6 tasks per target
        assert len(plan.task_graph.tasks) == 6

    def test_vuln_scan_decompose(self, decomposer, vuln_scan_intent):
        plan = decomposer.decompose(vuln_scan_intent)

        assert plan.metadata["strategy"] == "vuln_scan"
        assert len(plan.task_graph.tasks) == 3

    def test_multi_target_decompose(self, decomposer, multi_target_intent):
        plan = decomposer.decompose(multi_target_intent)

        assert plan.metadata["target_count"] == 2
        # fast_recon template has 3 tasks × 2 targets = 6
        assert len(plan.task_graph.tasks) == 6

    def test_graph_validates_after_decompose(self, decomposer, recon_intent):
        plan = decomposer.decompose(recon_intent)
        valid, errors = plan.task_graph.validate()
        assert valid is True, f"Validation errors: {errors}"

    def test_phases_cover_all_tasks(self, decomposer, ctf_intent):
        plan = decomposer.decompose(ctf_intent)

        phase_task_ids = set()
        for phase in plan.phases:
            phase_task_ids.update(phase)

        all_task_ids = set(plan.task_graph.tasks.keys())
        assert phase_task_ids == all_task_ids

    def test_decompose_with_time_constraint(self, decomposer, url_target):
        intent = IntentAnalysis(
            user_input="fast scan",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "time_limit", "value": 60}],
        )
        plan = decomposer.decompose(intent)

        # All tasks should have timeout=30 due to time_limit constraint
        for task in plan.task_graph.tasks.values():
            assert task.parameters.get("timeout") == 30

    def test_decompose_with_strategy_blueprint(self, decomposer, url_target):
        """When a strategy blueprint is provided via constraints, it drives task generation."""
        strategy = {
            "name": "custom_strategy",
            "stages": [
                {
                    "id": "recon_stage",
                    "name": "Reconnaissance",
                    "recommended_tools": ["nmap_scan"],
                    "agents": ["ReconAgent"],
                    "gate_requirements": {},
                },
                {
                    "id": "exploit_stage",
                    "name": "Exploitation",
                    "recommended_tools": ["sqlmap_scan", "nuclei_scan"],
                    "agents": [],
                    "gate_requirements": {},
                },
            ],
        }
        intent = IntentAnalysis(
            user_input="test with blueprint",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        assert plan.metadata["strategy_mode"] == "planner_driven"
        # Stage 0 has 1 tool, stage 1 has 2 tools → 3 tasks total
        assert len(plan.task_graph.tasks) == 3

    def test_decompose_strategy_blueprint_stage_dependencies(self, decomposer, url_target):
        """Tasks in stage N+1 should depend on tasks from stage N."""
        strategy = {
            "stages": [
                {"id": "s0", "name": "Stage 0", "recommended_tools": ["nmap"]},
                {"id": "s1", "name": "Stage 1", "recommended_tools": ["gobuster"]},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        tasks_list = list(plan.task_graph.tasks.values())
        # Stage 1 task should depend on stage 0 task
        stage1_tasks = [t for t in tasks_list if "s1" in t.task_id]
        stage0_tasks = [t for t in tasks_list if "s0" in t.task_id]

        assert len(stage1_tasks) > 0
        assert len(stage0_tasks) > 0

        for s1_task in stage1_tasks:
            for s0_task in stage0_tasks:
                assert s0_task.task_id in s1_task.dependencies

    def test_decompose_strategy_blueprint_metadata(self, decomposer, url_target):
        strategy = {
            "name": "named_strategy",
            "profile": {"mode": "aggressive"},
            "stages": [
                {"id": "s0", "recommended_tools": ["nmap"]},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        # profile.mode should be used as strategy name when available
        assert plan.metadata["strategy"] == "aggressive"

    def test_decompose_strategy_blueprint_fallback_name(self, decomposer, url_target):
        strategy = {
            "name": "my_plan",
            "stages": [
                {"id": "s0", "recommended_tools": ["nmap"]},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        assert plan.metadata["strategy"] == "my_plan"

    def test_decompose_strategy_blueprint_no_tools_uses_manual(self, decomposer, url_target):
        """When a stage has no recommended or backup tools, 'manual_validation' is used."""
        strategy = {
            "stages": [
                {"id": "s0", "name": "Empty Stage"},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        tasks = list(plan.task_graph.tasks.values())
        assert len(tasks) == 1
        assert tasks[0].tool_name == "manual_validation"

    def test_decompose_strategy_blueprint_backup_tools(self, decomposer, url_target):
        """Backup tools should be appended after recommended tools, deduped."""
        strategy = {
            "stages": [
                {
                    "id": "s0",
                    "name": "Mixed",
                    "recommended_tools": ["nmap", "whatweb"],
                    "backup_tools": ["whatweb", "nikto"],  # whatweb is dup
                },
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        tool_names = [t.tool_name for t in plan.task_graph.tasks.values()]
        assert tool_names == ["nmap", "whatweb", "nikto"]  # deduped, order preserved

    def test_decompose_strategy_blueprint_tags(self, decomposer, url_target):
        """Strategy-driven tasks should have 'strategy_driven' and stage_id as tags."""
        strategy = {
            "stages": [
                {"id": "recon_phase", "recommended_tools": ["nmap"]},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        task = list(plan.task_graph.tasks.values())[0]
        assert "strategy_driven" in task.tags
        assert "recon_phase" in task.tags

    def test_no_targets_empty_plan(self, decomposer):
        intent = IntentAnalysis(
            user_input="empty",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[],
            constraints=[],
        )
        plan = decomposer.decompose(intent)
        assert len(plan.task_graph.tasks) == 0
        assert plan.phases == []
        assert plan.estimated_duration == 0

    def test_unknown_intent_uses_fallback(self, decomposer, url_target):
        """An intent not matched by any template uses the first template as fallback."""
        intent = IntentAnalysis(
            user_input="exfiltrate data",
            intent=AttackIntent.DATA_EXFILTRATION,
            targets=[url_target],
            constraints=[],
        )
        plan = decomposer.decompose(intent)

        # Fallback is first template (ctf_intensive), which has 5 tasks
        assert plan.metadata["strategy"] == "ctf_intensive"
        assert len(plan.task_graph.tasks) == 5


# ===================== Strategy-driven multi-target =====================


class TestStrategyBlueprintMultiTarget:
    def test_multi_target_strategy_blueprint(self, decomposer, url_target, ip_target):
        strategy = {
            "stages": [
                {"id": "s0", "name": "Scan", "recommended_tools": ["nmap"]},
                {"id": "s1", "name": "Exploit", "recommended_tools": ["sqlmap"]},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target, ip_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        # 2 stages × 1 tool × 2 targets = 4 tasks
        assert len(plan.task_graph.tasks) == 4

    def test_multi_target_independent_chains(self, decomposer, url_target, ip_target):
        """Each target's stage chain should be independent."""
        strategy = {
            "stages": [
                {"id": "s0", "recommended_tools": ["nmap"]},
                {"id": "s1", "recommended_tools": ["gobuster"]},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target, ip_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        # Target 0's s1 task should depend on target 0's s0 task, not target 1's
        for task in plan.task_graph.tasks.values():
            for dep in task.dependencies:
                # All deps should share the same target prefix
                task_prefix = task.task_id.rsplit("_s", 1)[0]
                dep_prefix = dep.rsplit("_s", 1)[0]
                assert task_prefix == dep_prefix


# ===================== Edge cases =====================


class TestEdgeCases:
    def test_strategy_blueprint_stage_with_objective(self, decomposer, url_target):
        """Stage objective should be used as task description."""
        strategy = {
            "stages": [
                {
                    "id": "s0",
                    "name": "Recon",
                    "objective": "Gather initial information",
                    "recommended_tools": ["nmap"],
                },
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        task = list(plan.task_graph.tasks.values())[0]
        assert task.description == "Gather initial information"

    def test_strategy_stage_category_mapping(self, decomposer, url_target):
        """Verify that stage_id based category inference is applied in blueprint mode."""
        strategy = {
            "stages": [
                {"id": "recon_init", "recommended_tools": ["nmap"]},
                {"id": "exploit_rce", "recommended_tools": ["sqlmap"]},
                {"id": "report_final", "recommended_tools": ["custom_report"]},
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        tasks = list(plan.task_graph.tasks.values())
        categories = [t.category for t in tasks]
        assert TaskCategory.RECONNAISSANCE in categories
        assert TaskCategory.EXPLOITATION in categories
        assert TaskCategory.REPORTING in categories

    def test_task_graph_ready_after_marking_complete(self):
        """Simulate progressing through a chain by marking tasks complete."""
        g = TaskGraph(tasks={}, adjacency_list={}, reverse_adjacency={})
        g.add_task(make_task("t1"))
        g.add_task(make_task("t2", dependencies=["t1"]))
        g.add_task(make_task("t3", dependencies=["t2"]))

        # Initially only t1 is ready
        ready = g.get_ready_tasks()
        assert [t.task_id for t in ready] == ["t1"]

        # Complete t1
        g.tasks["t1"].status = TaskStatus.COMPLETED
        ready = g.get_ready_tasks()
        assert [t.task_id for t in ready] == ["t2"]

        # Complete t2
        g.tasks["t2"].status = TaskStatus.COMPLETED
        ready = g.get_ready_tasks()
        assert [t.task_id for t in ready] == ["t3"]

        # Complete t3
        g.tasks["t3"].status = TaskStatus.COMPLETED
        ready = g.get_ready_tasks()
        assert ready == []

    def test_strategy_blueprint_priority_calculation(self, decomposer, url_target):
        """Verify priority: max(1, 10 - stage_idx - (1 if backup))."""
        strategy = {
            "stages": [
                {
                    "id": "s0",
                    "recommended_tools": ["primary"],
                    "backup_tools": ["backup"],
                },
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        tasks = list(plan.task_graph.tasks.values())
        primary_task = next(t for t in tasks if t.tool_name == "primary")
        backup_task = next(t for t in tasks if t.tool_name == "backup")

        # stage_idx=0: primary → max(1, 10-0-0) = 10, backup → max(1, 10-0-1) = 9
        assert primary_task.priority == 10
        assert backup_task.priority == 9

    def test_strategy_blueprint_parameters_include_metadata(self, decomposer, url_target):
        """Strategy-driven tasks should have strategy metadata in parameters."""
        strategy = {
            "stages": [
                {
                    "id": "my_stage",
                    "name": "My Stage",
                    "recommended_tools": ["nmap"],
                    "agents": ["ReconAgent"],
                    "gate_requirements": {"min_findings": 1},
                },
            ],
        }
        intent = IntentAnalysis(
            user_input="test",
            intent=AttackIntent.RECONNAISSANCE,
            targets=[url_target],
            constraints=[{"type": "execution_strategy", "strategy": strategy}],
        )
        plan = decomposer.decompose(intent)

        task = list(plan.task_graph.tasks.values())[0]
        assert task.parameters["strategy_stage_id"] == "my_stage"
        assert task.parameters["strategy_stage_name"] == "My Stage"
        assert task.parameters["strategy_stage_index"] == 0
        assert "nmap" in task.parameters["strategy_allowed_tools"]
        assert "ReconAgent" in task.parameters["strategy_preferred_agents"]
        assert task.parameters["strategy_gate_requirements"] == {"min_findings": 1}
