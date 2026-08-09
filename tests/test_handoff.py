"""Test handoff compile + continue — pure logic, no real executor."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from kali_mcp.core.handoff import compile_handoff, continue_from_handoff, load_handoff, _TERMINAL_STATUSES


class TestCompileHandoff(unittest.TestCase):
    """compile_handoff reads workspace state and writes JSON+md."""

    def setUp(self):
        self.tid = "hnd_" + str(id(self))
        from kali_mcp.core.task_workspace import get_workspace
        self.ws = get_workspace(self.tid, create=True)

    def tearDown(self):
        import shutil
        if self.ws.root.exists():
            shutil.rmtree(str(self.ws.root))

    def test_compile_basic_shape(self):
        result = compile_handoff(self.tid)
        self.assertIn("task_id", result)
        self.assertIn("compiled_at", result)
        self.assertIn("verified_count", result)
        self.assertIn("handoff_json", result)
        self.assertIn("progress_md", result)
        self.assertEqual(result.get("task_id"), self.tid)

    def test_handoff_json_written(self):
        result = compile_handoff(self.tid)
        path = Path(result["handoff_json"])
        self.assertTrue(path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["task_id"], self.tid)

    def test_progress_md_written(self):
        result = compile_handoff(self.tid)
        path = Path(result["progress_md"])
        self.assertTrue(path.exists())
        text = path.read_text(encoding="utf-8")
        self.assertIn(self.tid, text)
        self.assertIn("Next actions", text)
        self.assertIn("Verified", text)

    def test_compile_with_findings(self):
        from kali_mcp.core.findings_store import upsert_finding
        upsert_finding(self.tid, {"title": "test1", "status": "verified", "source": "playbook",
                                   "target": "http://x/"})
        upsert_finding(self.tid, {"title": "test2", "status": "candidate", "source": "insight",
                                   "target": "http://x/"})
        result = compile_handoff(self.tid)
        self.assertEqual(result["verified_count"], 1)
        self.assertEqual(result["candidate_count"], 1)
        self.assertIn("test1", result["verified_titles"])


class TestContinueFromHandoff(unittest.TestCase):
    """Continue logic: terminal tasks preserve status, non-terminal transition correctly."""

    def setUp(self):
        self.tid = "cnt_" + str(id(self))
        from kali_mcp.core.task_workspace import get_workspace
        self.ws = get_workspace(self.tid, create=True)

    def tearDown(self):
        # Also clean the "<tid>_missing" variant created by test_load_handoff_compiles_if_missing.
        import shutil
        for root in (self.ws.root, self.ws.root.with_name(self.ws.root.name + "_missing")):
            if root.exists():
                shutil.rmtree(str(root))

    def _set_meta(self, phase="RECON", status="open"):
        self.ws.write_meta({"task_id": self.tid, "phase": phase, "status": status,
                            "targets": ["http://x/"], "depth": "quick",
                            "created_at": "2026-01-01T00:00:00",
                            "updated_at": "2026-01-01T00:00:00"})

    def test_continue_terminal_keeps_status(self):
        self._set_meta(phase="REPORT", status="chain_done")
        result = continue_from_handoff(self.tid, update_status=True)
        after = self.ws.read_meta()
        self.assertEqual(after.get("status"), "chain_done")
        self.assertNotEqual(result.get("status"), "resumed")

    def test_continue_non_terminal_returns_resume(self):
        self._set_meta(phase="RECON", status="open")
        from kali_mcp.core.target_graph import get_graph
        g = get_graph(self.tid)
        g.upsert_node("host", "x", confidence=0.5, next_checks=["http_probe"])
        g.save()
        result = continue_from_handoff(self.tid)
        after = self.ws.read_meta()
        self.assertEqual(after.get("status"), "resumed")

    def test_continue_with_update_status_false(self):
        self._set_meta(phase="REPORT", status="chain_done")
        result = continue_from_handoff(self.tid, update_status=False)
        after = self.ws.read_meta()
        self.assertEqual(after.get("status"), "chain_done")

    def test_load_handoff_compiles_if_missing(self):
        result = load_handoff(self.tid + "_missing")
        self.assertIn("task_id", result)
        self.assertEqual(result.get("task_id"), self.tid + "_missing")

    def test_terminal_statuses_defined(self):
        for s in ("chain_done", "playbook_done", "goal_done", "closed", "done", "report_done"):
            self.assertIn(s, _TERMINAL_STATUSES)
