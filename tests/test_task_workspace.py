"""Test task_workspace: paths, create, meta read/write."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from kali_mcp.core.task_workspace import (
    TaskWorkspace,
    get_workspace,
    list_tasks,
    normalize_task_id,
    utc_now_iso,
    workspace_root,
    tasks_root,
)


class TestWorkspacePaths(unittest.TestCase):
    """Path resolution and id normalization."""

    def test_workspace_root_default(self):
        root = workspace_root()
        self.assertIsInstance(root, Path)
        self.assertTrue(root.exists())

    def test_tasks_root(self):
        root = tasks_root()
        self.assertTrue(root.exists())
        self.assertEqual(root.name, "tasks")

    def test_normalize_valid(self):
        self.assertEqual(normalize_task_id("abc123"), "abc123")
        self.assertEqual(normalize_task_id("  abc_123  "), "abc_123")

    def test_normalize_empty_generates_uuid(self):
        tid = normalize_task_id(None)
        self.assertTrue(tid.startswith("task_"))
        self.assertEqual(len(tid), 17)

    def test_normalize_too_long_truncates_to_64(self):
        long_name = "a" * 100
        result = normalize_task_id(long_name)
        self.assertLessEqual(len(result), 64)

    def test_utc_now_iso_format(self):
        s = utc_now_iso()
        self.assertIn("T", s)


class TestTaskWorkspace(unittest.TestCase):
    """Create, read, update workspace directories and metadata."""

    def setUp(self):
        self.tid = "wst_" + str(id(self))
        self.ws = get_workspace(self.tid, create=True)

    def tearDown(self):
        import shutil
        if self.ws.root.exists():
            shutil.rmtree(str(self.ws.root))

    def test_ensure_creates_directories(self):
        ws = TaskWorkspace("new_dir_test_" + str(id(self))).ensure()
        self.assertTrue(ws.graph_dir.exists())
        self.assertTrue(ws.evidence_dir.exists())
        self.assertTrue(ws.logs_dir.exists())
        self.assertTrue(ws.findings_dir.exists())
        self.assertTrue(ws.handoff_dir.exists())
        self.assertTrue(ws.report_dir.exists())
        import shutil
        shutil.rmtree(str(ws.root))

    def test_meta_path(self):
        self.assertTrue(self.ws.meta_path.exists())

    def test_read_meta_defaults(self):
        meta = self.ws.read_meta()
        self.assertEqual(meta.get("task_id"), self.tid)
        self.assertEqual(meta.get("phase"), "RECON")
        self.assertEqual(meta.get("status"), "open")

    def test_update_meta(self):
        self.ws.update_meta(phase="REPORT", status="chain_done")
        meta = self.ws.read_meta()
        self.assertEqual(meta.get("phase"), "REPORT")
        self.assertEqual(meta.get("status"), "chain_done")

    def test_update_meta_always_sets_task_id(self):
        self.ws.update_meta(targets=["http://x/"])
        meta = self.ws.read_meta()
        self.assertEqual(meta.get("task_id"), self.tid)

    def test_write_meta_sets_updated_at(self):
        self.ws.write_meta({"task_id": self.tid, "phase": "RECON", "status": "open"})
        meta = self.ws.read_meta()
        self.assertIn("updated_at", meta)

    def test_graph_path_property(self):
        self.assertEqual(self.ws.graph_path, self.ws.graph_dir / "graph.json")

    def test_actions_log_path_property(self):
        self.assertEqual(self.ws.actions_log_path, self.ws.logs_dir / "actions.jsonl")

    def test_findings_path_property(self):
        self.assertEqual(self.ws.findings_path, self.ws.findings_dir / "findings.json")

    def test_list_tasks_includes_this(self):
        all_tasks = list_tasks()
        self.assertIn(self.tid, all_tasks)

    def test_read_meta_missing_returns_empty(self):
        ws2 = TaskWorkspace("nonexistent_" + str(id(self)))
        meta = ws2.read_meta()
        self.assertEqual(meta, {})
