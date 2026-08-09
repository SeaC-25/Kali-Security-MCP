"""Test chain.py error logging paths — observer/handoff failures must not crash chain."""
from __future__ import annotations

import shutil
import unittest
from unittest.mock import MagicMock, patch


class TestChainErrorHandling(unittest.TestCase):
    """Verify that observer/handoff failures are logged (not silently swallowed)."""

    def setUp(self):
        self.tid = "chain_err_" + str(id(self))
        from kali_mcp.core.task_workspace import get_workspace
        self.ws = get_workspace(self.tid, create=True)

    def tearDown(self):
        # Every chain_err_* test dir (incl. _h/_wt variants) must be removed:
        # these are probe/debug artifacts and must not leak into workspace/tasks.
        from kali_mcp.core.task_workspace import tasks_root
        for p in tasks_root().glob("chain_err_*"):
            if p.is_dir():
                shutil.rmtree(str(p))

    def _fake_pb(self, name, task_id, target, executor, depth="quick", **kwargs):
        return {"ok": True, "playbook": name, "depth": depth}

    def _fake_report(self, *a, **kw):
        return {
            "ok": True,
            "markdown_path": f"/tmp/{self.tid}/report.md",
            "paths": {"markdown": f"/tmp/{self.tid}/report.md"},
        }

    def test_observer_failure_does_not_crash_chain(self):
        """When observer.apply_observer_hints raises, chain should still complete."""
        from kali_mcp.core.playbooks.chain import run_surface_chain

        ex = MagicMock()
        with patch("kali_mcp.core.playbooks.run_playbook", side_effect=self._fake_pb), patch(
            "kali_mcp.core.playbooks.list_playbooks", return_value=["web_surface"]
        ), patch(
            "kali_mcp.core.playbooks.chain.compile_handoff", return_value={}
        ), patch(
            "kali_mcp.core.playbooks.chain.continue_from_handoff", return_value={"ok": True}
        ), patch(
            "kali_mcp.core.observer.apply_observer_hints",
            side_effect=RuntimeError("simulated observer crash"),
        ), patch(
            "kali_mcp.core.insight_bridge.propose_insights",
            return_value={"ok": True, "created_count": 0, "skipped": True},
        ), patch(
            "kali_mcp.core.report_export.export_task_report", side_effect=self._fake_report
        ):
            out = run_surface_chain(
                self.tid, "http://lab.local/", ex, depth="quick", playbooks=["web_surface"]
            )

        self.assertTrue(out.get("ok"), msg=f"Chain crashed on observer error: {out}")
        self.assertIn("steps", out)

    def test_final_handoff_failure_logged_not_crash(self):
        """The final (try-guarded) handoff compile failure must not crash chain."""
        from kali_mcp.core.playbooks.chain import run_surface_chain

        ex = MagicMock()
        with patch("kali_mcp.core.playbooks.run_playbook", side_effect=self._fake_pb), patch(
            "kali_mcp.core.playbooks.list_playbooks", return_value=["web_surface"]
        ), patch(
            # first call (line 208) returns normally; second call (final, guarded) raises
            "kali_mcp.core.playbooks.chain.compile_handoff",
            side_effect=[{"handoff_json": "/tmp/h.json", "progress_md": "/tmp/p.md"}, OSError("final handoff crash")],
        ), patch(
            "kali_mcp.core.playbooks.chain.continue_from_handoff", return_value={"ok": True}
        ), patch(
            "kali_mcp.core.observer.apply_observer_hints",
            return_value={"duplicate_count": 0, "suggestions": []},
        ), patch(
            "kali_mcp.core.insight_bridge.propose_insights",
            return_value={"ok": True, "created_count": 0, "skipped": True},
        ), patch(
            "kali_mcp.core.report_export.export_task_report", side_effect=self._fake_report
        ):
            out = run_surface_chain(
                self.tid + "_h", "http://lab.local/", ex, depth="quick", playbooks=["web_surface"]
            )

        self.assertTrue(out.get("ok"), msg=f"Chain crashed on final handoff error: {out}")
        self.assertIn("steps", out)

    def test_chain_wall_clock_timeout_aborts(self):
        """KALI_MCP_CHAIN_TIMEOUT_S=short should abort after playbook completes."""
        import os
        from kali_mcp.core.playbooks.chain import run_surface_chain

        os.environ["KALI_MCP_CHAIN_TIMEOUT_S"] = "3600"  # generous so it won't false-positive abort

        ex = MagicMock()
        with patch("kali_mcp.core.playbooks.run_playbook", side_effect=self._fake_pb), patch(
            "kali_mcp.core.playbooks.list_playbooks", return_value=["web_surface", "api_surface"]
        ), patch(
            "kali_mcp.core.playbooks.chain.compile_handoff", return_value={}
        ), patch(
            "kali_mcp.core.playbooks.chain.continue_from_handoff", return_value={"ok": True}
        ), patch(
            "kali_mcp.core.observer.apply_observer_hints",
            return_value={"duplicate_count": 0, "suggestions": []},
        ), patch(
            "kali_mcp.core.insight_bridge.propose_insights",
            return_value={"ok": True, "created_count": 0, "skipped": True},
        ), patch(
            "kali_mcp.core.report_export.export_task_report", side_effect=self._fake_report
        ):
            out = run_surface_chain(
                self.tid + "_wt", "http://lab.local/", ex, depth="quick", playbooks=["web_surface"]
            )
        # Under normal mock speed this should not trip 3600s timeout
        self.assertTrue(out.get("ok"), msg=f"Chain failed: {out}")
        # Status should NOT be wall_clock_timeout with 3600s limit
        self.assertNotEqual(out.get("status"), "wall_clock_timeout")
