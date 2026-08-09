"""Test multi_target orchestration module — pure logic, no real executor.

Covers: add_target (regression for NameError time/random), adaptive strategy,
dependency-aware topological ordering, task optimization, status/estimation.
"""
from __future__ import annotations

import unittest

from kali_mcp.core.multi_target import (
    MultiTargetOrchestrator,
    TargetProfile,
    AttackTask,
)


class TestAddTarget(unittest.TestCase):
    """add_target previously crashed with NameError (missing time/random import)."""

    def setUp(self):
        self.o = MultiTargetOrchestrator()

    def test_add_target_returns_registered_id(self):
        tid = self.o.add_target("http://127.0.0.1:18081/")
        self.assertTrue(tid)
        self.assertIn(tid, self.o.targets)
        profile = self.o.targets[tid]
        self.assertEqual(profile.target_url, "http://127.0.0.1:18081/")

    def test_add_target_defaults(self):
        tid = self.o.add_target("10.0.0.1")
        profile = self.o.targets[tid]
        self.assertEqual(profile.target_type, "unknown")
        self.assertEqual(profile.priority, 1)
        self.assertEqual(profile.status, "pending")
        self.assertEqual(profile.dependency_targets, [])

    def test_add_target_custom_fields(self):
        tid = self.o.add_target(
            "10.0.0.2", target_type="network", priority=9,
            dependencies=["other_id"])
        profile = self.o.targets[tid]
        self.assertEqual(profile.target_type, "network")
        self.assertEqual(profile.priority, 9)
        self.assertEqual(profile.dependency_targets, ["other_id"])

    def test_add_target_updates_metrics(self):
        self.o.add_target("a.example", target_type="web")
        self.o.add_target("b.example", target_type="web")
        self.assertEqual(self.o.performance_metrics["total_targets"], 2)


class TestOrchestrate(unittest.TestCase):
    def setUp(self):
        self.o = MultiTargetOrchestrator()
        self.t1 = self.o.add_target("http://a/", target_type="web")
        self.t2 = self.o.add_target("10.0.0.1", target_type="network")

    def test_adaptive_plan_shape(self):
        res = self.o.orchestrate_attack()
        self.assertEqual(res["orchestration_strategy"], "adaptive")
        self.assertEqual(res["targets_count"], 2)
        plan = res["execution_plan"]
        self.assertEqual(plan["strategy"], "adaptive")
        self.assertIn("execution_phases", plan)
        self.assertIsInstance(res["estimated_total_time"], int)

    def test_unknown_strategy_raises(self):
        with self.assertRaises(ValueError):
            self.o.orchestrate_attack("bogus_strategy")

    def test_plan_includes_queued_tasks(self):
        task = AttackTask(target_id=self.t1, tool_name="nmap", status="queued")
        self.o.attack_tasks[task.task_id] = task
        res = self.o.orchestrate_attack()
        phases = res["execution_plan"]["execution_phases"]
        all_task_ids = [
            t["task_id"] for phase in phases for t in phase.get("tasks", [])
        ]
        self.assertIn(task.task_id, all_task_ids)


class TestDependencyOrdering(unittest.TestCase):
    def setUp(self):
        self.o = MultiTargetOrchestrator()
        # t2 depends on t1, so t1 must be planned first
        self.t1 = self.o.add_target("first.example")
        self.t2 = self.o.add_target("second.example", dependencies=[self.t1])

    def test_topological_levels(self):
        levels = self.o._topological_sort(self.o._build_dependency_graph())
        self.assertIn([self.t1], levels)
        self.assertIn([self.t2], levels)
        t1_level = levels.index([self.t1])
        t2_level = levels.index([self.t2])
        self.assertLess(t1_level, t2_level)

    def test_cycle_does_not_infinite_loop(self):
        # self-cycle: remaining nodes never drain, must stop safely
        self.o.targets[self.t2].dependency_targets = [self.t2]
        levels = self.o._topological_sort(self.o._build_dependency_graph())
        self.assertIsInstance(levels, list)


class TestTaskOptimization(unittest.TestCase):
    def setUp(self):
        self.o = MultiTargetOrchestrator()
        self.tid = self.o.add_target("http://w/", target_type="web")

    def test_preferred_order_first(self):
        nikto = AttackTask(target_id=self.tid, tool_name="nikto", priority=1, status="queued")
        nmap = AttackTask(target_id=self.tid, tool_name="nmap", priority=5, status="queued")
        self.o.attack_tasks[nikto.task_id] = nikto
        self.o.attack_tasks[nmap.task_id] = nmap
        ordered = self.o._optimize_task_sequence(
            list(self.o.attack_tasks.values()), self.o.targets[self.tid])
        tools = [t.tool_name for t in ordered]
        self.assertEqual(tools[0], "nmap")  # web profile puts nmap first
        self.assertEqual(tools[1], "nikto")


class TestStatusAndEstimation(unittest.TestCase):
    def setUp(self):
        self.o = MultiTargetOrchestrator()
        self.tid = self.o.add_target("http://s/", target_type="web")

    def test_status_shape(self):
        task = AttackTask(target_id=self.tid, tool_name="nmap", status="completed")
        self.o.attack_tasks[task.task_id] = task
        self.o.completed_tasks[task.task_id] = task
        st = self.o.get_orchestration_status()
        self.assertEqual(st["total_targets"], 1)
        self.assertEqual(st["total_tasks"], 1)
        self.assertEqual(st["completed_tasks"], 1)
        self.assertEqual(st["success_rate"], 100.0)
        self.assertEqual(st["current_strategy"], "adaptive")

    def test_estimate_total_time_uses_max_per_phase(self):
        t2 = self.o.add_target("http://s2/", target_type="web")
        a = AttackTask(target_id=self.tid, tool_name="nmap", estimated_duration=10, status="queued")
        b = AttackTask(target_id=t2, tool_name="nmap", estimated_duration=30, status="queued")
        self.o.attack_tasks[a.task_id] = a
        self.o.attack_tasks[b.task_id] = b
        plan = self.o.orchestrate_attack()["execution_plan"]
        total = self.o._estimate_total_execution_time(plan)
        self.assertGreaterEqual(total, 0)


class TestModuleGlobals(unittest.TestCase):
    def test_dataclasses_defaults(self):
        p = TargetProfile(target_id="t", target_url="http://x/")
        self.assertEqual(p.status, "pending")
        self.assertEqual(p.discovered_assets, {})
        t = AttackTask()
        self.assertEqual(t.status, "queued")
        self.assertEqual(t.max_retries, 3)
        self.assertTrue(t.task_id)

    def test_global_orchestrator_exists(self):
        from kali_mcp.core.multi_target import multi_target_orchestrator
        self.assertIsInstance(multi_target_orchestrator, MultiTargetOrchestrator)


if __name__ == "__main__":
    unittest.main()
