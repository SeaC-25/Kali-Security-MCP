#!/usr/bin/env python3
"""Lightweight action log (what/when) — does not block execution.

Single write path for harness telemetry. Schema is fixed; extra is optional.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from kali_mcp.core.task_workspace import get_workspace, utc_now_iso

# Canonical event fields written by log_action (extra is optional add-on).
ACTION_EVENT_FIELDS: Tuple[str, ...] = (
    "ts",
    "task_id",
    "phase",
    "target",
    "tool",
    "args_digest",
    "exit",
    "duration_ms",
    "evidence_path",
    "finding_ids",
    "source",
)


def _digest(args: Any) -> str:
    try:
        raw = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        raw = str(args)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def log_action(
    task_id: str,
    *,
    phase: str = "",
    target: str = "",
    tool: str = "",
    args: Any = None,
    exit_code: Any = None,
    duration_ms: Optional[float] = None,
    evidence_path: str = "",
    finding_ids: Optional[List[str]] = None,
    source: str = "playbook",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    record: Dict[str, Any] = {
        "ts": utc_now_iso(),
        "task_id": ws.task_id,
        "phase": phase,
        "target": target,
        "tool": tool,
        "args_digest": _digest(args),
        "exit": exit_code,
        "duration_ms": duration_ms,
        "evidence_path": evidence_path,
        "finding_ids": list(finding_ids or []),
        "source": source,
    }
    if extra:
        record["extra"] = extra
    path = ws.actions_log_path
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def read_actions(task_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    ws = get_workspace(task_id, create=True)
    path = ws.actions_log_path
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    items = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except Exception:
            continue
    return items


def task_timeline(
    task_id: str,
    *,
    limit: int = 200,
    tools: Optional[Sequence[str]] = None,
    sources: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Read-only timeline over action_log (no new write path)."""
    if not task_id:
        return {"ok": False, "error": "task_id required", "events": [], "count": 0}
    events = read_actions(task_id, limit=max(1, int(limit or 200)))
    tool_set = {str(t).strip() for t in (tools or []) if str(t).strip()} or None
    source_set = {str(s).strip() for s in (sources or []) if str(s).strip()} or None
    if tool_set:
        events = [e for e in events if str(e.get("tool") or "") in tool_set]
    if source_set:
        events = [e for e in events if str(e.get("source") or "") in source_set]

    duration_sum = 0.0
    duration_known = 0
    by_tool: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    for e in events:
        d = e.get("duration_ms")
        if isinstance(d, (int, float)):
            duration_sum += float(d)
            duration_known += 1
        t = str(e.get("tool") or "") or "?"
        by_tool[t] = by_tool.get(t, 0) + 1
        s = str(e.get("source") or "") or "?"
        by_source[s] = by_source.get(s, 0) + 1

    return {
        "ok": True,
        "task_id": task_id,
        "count": len(events),
        "events": events,
        "duration_ms_sum": round(duration_sum, 3),
        "duration_ms_known_count": duration_known,
        "by_tool": by_tool,
        "by_source": by_source,
        "schema_fields": list(ACTION_EVENT_FIELDS),
        "note": "read-only over logs/actions.jsonl; measured duration_ms only when writers set it",
    }
