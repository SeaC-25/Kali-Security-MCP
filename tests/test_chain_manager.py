"""Test ChainManager (SQLite attack-chain lifecycle) — uses tmp db, no home pollution."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from kali_mcp.core.chain_manager import ChainManager
from kali_mcp.core.chain_models import AttackChain, ChainStep


class TestChainManagerCRUD(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp.name) / "chains.db")
        self.cm = ChainManager(db_path=self.db_path)

    def tearDown(self):
        self._tmp.cleanup()

    def _make_chain(self, title="测试链"):
        return AttackChain(title=title, description="desc", impact_level="high")

    def test_create_and_get_by_id_roundtrip(self):
        chain = self._make_chain()
        chain.steps = [
            ChainStep(title="探测", precondition="", action="nmap -sV"),
            ChainStep(title="验证", precondition="探测完成", action="curl /x"),
        ]
        cid = self.cm.create_chain(chain)
        loaded = self.cm.get_by_id(cid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.title, "测试链")
        self.assertEqual(loaded.impact_level, "high")
        self.assertEqual(len(loaded.steps), 2)
        self.assertEqual(loaded.steps[0].title, "探测")
        self.assertEqual(loaded.steps[1].precondition, "探测完成")

    def test_get_by_id_missing_returns_none(self):
        self.assertIsNone(self.cm.get_by_id("NO_SUCH_CHAIN"))

    def test_get_all_and_status_filter(self):
        c1 = self._make_chain(title="A")
        c2 = self._make_chain(title="B")
        c3 = self._make_chain(title="C")
        self.cm.create_chain(c1)
        self.cm.create_chain(c2)
        self.cm.create_chain(c3)
        self.assertEqual(len(self.cm.get_all()), 3)
        self.cm.update_status(c2.chain_id, "confirmed")
        self.assertEqual(len(self.cm.get_all(status="confirmed")), 1)
        self.assertEqual(len(self.cm.get_all(status="draft")), 2)

    def test_add_step_appends_with_order(self):
        chain = self._make_chain()
        cid = self.cm.create_chain(chain)
        self.assertTrue(self.cm.add_step(cid, ChainStep(title="第一步")))
        self.assertTrue(self.cm.add_step(cid, ChainStep(title="第二步")))
        loaded = self.cm.get_by_id(cid)
        self.assertEqual([s.order for s in loaded.steps], [1, 2])

    def test_add_step_missing_chain_fails(self):
        self.assertFalse(self.cm.add_step("NOPE", ChainStep(title="x")))

    def test_update_status(self):
        chain = self._make_chain()
        cid = self.cm.create_chain(chain)
        self.assertTrue(self.cm.update_status(cid, "executed"))
        self.assertEqual(self.cm.get_by_id(cid).status, "executed")
        self.assertFalse(self.cm.update_status("NOPE", "executed"))


class TestFeasibility(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cm = ChainManager(db_path=str(Path(self._tmp.name) / "chains.db"))

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_chain_score_zero(self):
        res = self.cm.analyze_feasibility("NOPE")
        self.assertEqual(res["score"], 0)
        self.assertIn("攻击链不存在", res["reason"])

    def test_chain_without_steps_low_score(self):
        cid = self.cm.create_chain(AttackChain(title="空链"))
        res = self.cm.analyze_feasibility(cid)
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["recommendation"], "不建议执行")

    def test_rich_chain_scores_high(self):
        chain = AttackChain(title="富链")
        for i in range(4):
            chain.steps.append(ChainStep(
                title=f"步骤{i}", precondition=f"前置{i}" if i > 0 else ""))
        chain.fragments = ["f1", "f2", "f3"]
        cid = self.cm.create_chain(chain)
        res = self.cm.analyze_feasibility(cid)
        # 40 (steps) + 30 (evidence) + coherence
        self.assertGreaterEqual(res["score"], 60)
        self.assertEqual(res["recommendation"], "可执行")
        # score persisted back
        self.assertEqual(self.cm.get_by_id(cid).feasibility_score, res["score"])


class TestStatistics(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cm = ChainManager(db_path=str(Path(self._tmp.name) / "chains.db"))

    def tearDown(self):
        self._tmp.cleanup()

    def test_statistics_empty(self):
        st = self.cm.get_statistics()
        self.assertEqual(st["total"], 0)
        self.assertEqual(st["draft"], 0)
        self.assertEqual(st["by_status"], {})

    def test_statistics_grouped(self):
        for i in range(3):
            cid = self.cm.create_chain(AttackChain(title=f"c{i}"))
            self.cm.update_status(cid, "confirmed" if i % 2 else "executed")
        st = self.cm.get_statistics()
        self.assertEqual(st["total"], 3)
        self.assertEqual(st["executed"], 2)
        self.assertEqual(st["confirmed"], 1)
        self.assertEqual(st["draft"], 0)


if __name__ == "__main__":
    unittest.main()
