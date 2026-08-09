#!/usr/bin/env python3
"""Task workspace paths and bootstrap for P0 harness."""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def workspace_root() -> Path:
    raw = os.getenv("KALI_MCP_WORKSPACE", "").strip()
    if raw:
        root = Path(raw).expanduser().resolve()
    else:
        # kali_mcp/core -> repo root
        root = Path(__file__).resolve().parents[2] / "workspace"
    root.mkdir(parents=True, exist_ok=True)
    return root


def tasks_root() -> Path:
    path = workspace_root() / "tasks"
    path.mkdir(parents=True, exist_ok=True)
    return path


def normalize_task_id(task_id: Optional[str] = None) -> str:
    if task_id and _TASK_ID_RE.match(task_id.strip()):
        return task_id.strip()
    return f"task_{uuid.uuid4().hex[:12]}"


class TaskWorkspace:
    """Per-task directory layout."""

    def __init__(self, task_id: str):
        self.task_id = normalize_task_id(task_id)
        self.root = tasks_root() / self.task_id
        self.graph_dir = self.root / "graph"
        self.evidence_dir = self.root / "evidence"
        self.logs_dir = self.root / "logs"
        self.findings_dir = self.root / "findings"
        self.handoff_dir = self.root / "handoff"
        self.report_dir = self.root / "report"
        self.meta_path = self.root / "task.json"

    def ensure(self) -> "TaskWorkspace":
        for d in (
            self.root,
            self.graph_dir,
            self.evidence_dir,
            self.logs_dir,
            self.findings_dir,
            self.handoff_dir,
            self.report_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
        if not self.meta_path.exists():
            self.write_meta(
                {
                    "task_id": self.task_id,
                    "created_at": utc_now_iso(),
                    "updated_at": utc_now_iso(),
                    "phase": "RECON",
                    "status": "open",
                    "targets": [],
                    "depth": "standard",
                }
            )
        return self

    def write_meta(self, data: Dict[str, Any]) -> None:
        data = dict(data)
        data["updated_at"] = utc_now_iso()
        self.meta_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def read_meta(self) -> Dict[str, Any]:
        if not self.meta_path.exists():
            return {}
        return json.loads(self.meta_path.read_text(encoding="utf-8"))

    def update_meta(self, **kwargs: Any) -> Dict[str, Any]:
        meta = self.read_meta()
        meta.update(kwargs)
        meta["task_id"] = self.task_id
        self.write_meta(meta)
        return meta

    @property
    def graph_path(self) -> Path:
        return self.graph_dir / "graph.json"

    @property
    def actions_log_path(self) -> Path:
        return self.logs_dir / "actions.jsonl"

    @property
    def findings_path(self) -> Path:
        return self.findings_dir / "findings.json"


def list_tasks() -> List[str]:
    root = tasks_root()
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def get_workspace(task_id: Optional[str] = None, create: bool = True) -> TaskWorkspace:
    ws = TaskWorkspace(normalize_task_id(task_id))
    if create:
        ws.ensure()
    return ws
