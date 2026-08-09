#!/usr/bin/env python3
"""
K4 thin task board: file-backed multi-agent coordination, no LLM dependency.

Port of SpringInFer's substrate/agents/board.py semantics to a JSON-file store
(``<repo root>/data/taskboard.json``) with no KG, no mailbox polling and no
cluster classes. Design rules inherited from the SpringInFer board:

  - Claims carry leases (600s) so crashed workers do not permanently lock work.
  - Expired leases are reverted to open lazily on any read.
  - Concurrency is capped: at most ``env_cap`` (3) claimed tasks at once.
  - task_complete() requires the full result envelope (orchestrate 11-stage
    contract); the task is NOT completed when keys are missing.
  - File writes are atomic (temp file + os.replace); a threading.Lock keeps
    in-process access serialized.

Every tool returns a dict (or list) and never raises; failures are surfaced as
``{"error": "..."}``.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

BOARD_FILE: Path = _REPO_ROOT / "data" / "taskboard.json"

ROLES = ("strategist", "scout", "exploiter", "verifier", "general")
TASK_STATUSES = ("open", "claimed", "done", "failed", "cancelled")
TASK_KINDS = (
    "recon",
    "hypothesize",
    "exploit",
    "verify",
    "submit",
    "close",
    "consolidate",
    "other",
)

# 11 orchestrate stages mapped onto the canonical 8 kinds. task_create()
# accepts any of these as `kind`; the stored `kind` is the resolved canonical
# one, `stage` keeps the caller-facing name verbatim so board_snapshot() can
# report a per-stage distribution.
STAGE_KIND_ALIASES = {
    "intake": "recon",
    "context": "recon",
    "candidates": "hypothesize",
    "review": "hypothesize",
    "plan": "hypothesize",
    "execute": "exploit",
    "integrate": "verify",
    "check": "verify",
    "optimize": "exploit",
    "package": "close",
    "done": "close",
}

# Required result envelope for task_complete() (orchestrate 11-stage
# contract). Every key MUST be present; evidence/artifacts/risks/unresolved
# may be empty lists but cannot be omitted.
RESULT_ENVELOPE_KEYS = (
    "summary",
    "evidence",
    "artifacts",
    "risks",
    "unresolved",
    "recommended_next_action",
)

# Canonical kind -> owning role. Kinds not listed default to strategist.
KIND_ROLE = {
    "recon": "scout",
    "exploit": "exploiter",
    "verify": "verifier",
    "submit": "verifier",
}

# Platform constraint: max concurrent claimed tasks (env slots).
MAX_ACTIVE_ENVS = 3
DEFAULT_LEASE_SEC = 600

_LOCK = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_s() -> str:
    return _now().isoformat()


def _uid(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _parse_ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _default_board() -> Dict[str, Any]:
    return {"env_cap": MAX_ACTIVE_ENVS, "agents": {}, "tasks": {}}


def _read_board_unlocked() -> Dict[str, Any]:
    """Load the board JSON (starting fresh when missing/corrupt)."""
    if not BOARD_FILE.exists():
        return _default_board()
    try:
        with open(BOARD_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return _default_board()
    if not isinstance(data, dict):
        return _default_board()
    data.setdefault("env_cap", MAX_ACTIVE_ENVS)
    data.setdefault("agents", {})
    data.setdefault("tasks", {})
    return data


def _write_board_unlocked(data: Dict[str, Any]) -> None:
    """Atomically persist the board (temp file + os.replace)."""
    BOARD_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".taskboard.", suffix=".tmp", dir=BOARD_FILE.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, BOARD_FILE)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _sweep_expired(data: Dict[str, Any]) -> bool:
    """Revert claimed tasks with an expired lease back to open. Returns True
    when anything changed."""
    now = _now()
    changed = False
    for task in list(data.get("tasks", {}).values()):
        if task.get("status") != "claimed":
            continue
        until = _parse_ts(task.get("lease_until"))
        if until is not None and until >= now:
            continue
        agent_id = task.get("assignee")
        task["status"] = "open"
        task["assignee"] = None
        task["lease_until"] = None
        if agent_id:
            agent = data.get("agents", {}).get(agent_id)
            if agent:
                agent["status"] = "idle"
                agent["last_seen"] = _now_s()
        changed = True
    return changed


def _board_locked() -> Dict[str, Any]:
    """Load the board and persist any lease sweep. Caller MUST hold _LOCK."""
    data = _read_board_unlocked()
    if _sweep_expired(data):
        _write_board_unlocked(data)
    return data


def _eligible_kinds(role: str) -> tuple:
    """Kinds a role may claim. general claims anything; others claim the kinds
    whose KIND_ROLE matches."""
    if role == "general":
        return TASK_KINDS
    return tuple(k for k in TASK_KINDS if KIND_ROLE.get(k, "strategist") == role)


def _sort_key(task: Dict[str, Any]) -> tuple:
    """Priority DESC, then created_at ASC (SpringInFer claim ordering)."""
    ts = _parse_ts(task.get("created_at")) or _now()
    return (task.get("priority", 0), -ts.timestamp())


def task_create(title: str, kind: str = "other", priority: int = 50) -> Dict[str, Any]:
    """Create an open task on the board.

    Args:
        title: Task title.
        kind: Canonical kind or an orchestrate stage alias (e.g. "execute").
        priority: Higher priority is claimed first (default 50).

    Returns:
        The created task dict.
    """
    raw = ((kind or "other").strip().lower()) or "other"
    canonical = STAGE_KIND_ALIASES.get(raw, raw)
    if canonical not in TASK_KINDS:
        return {
            "error": "invalid_kind",
            "kind": kind,
            "allowed": list(TASK_KINDS),
            "stage_aliases": list(STAGE_KIND_ALIASES),
        }
    task = {
        "id": _uid("tsk_"),
        "title": title,
        "kind": canonical,
        "stage": raw,
        "status": "open",
        "priority": int(priority),
        "assignee": None,
        "lease_until": None,
        "created_at": _now_s(),
        "result": None,
    }
    with _LOCK:
        data = _board_locked()
        data["tasks"][task["id"]] = task
        _write_board_unlocked(data)
    return task


def task_claim(role: str = "general", agent_id: str = "") -> Dict[str, Any]:
    """Claim the best-priority open task matching ``role``.

    Args:
        role: One of ROLES; the task's kind must map to this role (general
            claims anything). Best priority first, oldest created first.
        agent_id: Claiming agent; auto-generated when empty.

    Returns:
        The claimed task dict (status='claimed', assignee and lease set), or
        ``{"error": "max_active_envs"}`` when the env-slot cap is reached.
    """
    role = ((role or "general").strip().lower()) or "general"
    if role not in ROLES:
        return {"error": "invalid_role", "role": role, "roles": list(ROLES)}
    agent = agent_id or _uid(f"{role[:3]}_")
    with _LOCK:
        data = _board_locked()
        claimed_count = sum(
            1 for t in data["tasks"].values() if t.get("status") == "claimed"
        )
        env_cap = int(data.get("env_cap", MAX_ACTIVE_ENVS))
        if claimed_count >= env_cap:
            return {
                "error": "max_active_envs",
                "max": env_cap,
                "claimed": claimed_count,
            }
        kinds = _eligible_kinds(role)
        candidates = [
            t
            for t in data["tasks"].values()
            if t.get("status") == "open" and t.get("kind") in kinds
        ]
        if not candidates:
            return {"error": "no_open_task", "role": role, "kinds": list(kinds)}
        candidates.sort(key=_sort_key, reverse=True)
        best = candidates[0]
        best["status"] = "claimed"
        best["assignee"] = agent
        best["lease_until"] = (_now() + timedelta(seconds=DEFAULT_LEASE_SEC)).isoformat()
        agent_rec = data["agents"].setdefault(
            agent, {"agent_id": agent, "role": role, "status": "idle", "last_seen": ""}
        )
        agent_rec["role"] = role
        agent_rec["status"] = "busy"
        agent_rec["last_seen"] = _now_s()
        _write_board_unlocked(data)
    claimed = dict(best)
    claimed["agent_id"] = agent
    return claimed


def task_complete(task_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Complete a task. The result envelope is REQUIRED: summary plus the five
    supporting keys must all be present (evidence/artifacts/risks/unresolved
    may be empty lists). Missing keys reject the completion.

    Args:
        task_id: Task id.
        result: Result envelope with every RESULT_ENVELOPE_KEYS key.

    Returns:
        The completed task dict (status='done'), or an error dict listing
        missing envelope fields.
    """
    envelope = dict(result or {})
    missing = [k for k in RESULT_ENVELOPE_KEYS if k not in envelope]
    if missing:
        return {
            "error": "result_envelope_incomplete",
            "task_id": task_id,
            "missing_fields": missing,
            "required": list(RESULT_ENVELOPE_KEYS),
        }
    with _LOCK:
        data = _board_locked()
        task = data["tasks"].get(task_id)
        if not task:
            return {"error": "task_not_found", "task_id": task_id}
        if task.get("status") not in ("claimed", "open"):
            return {
                "error": "bad_status",
                "task_id": task_id,
                "status": task.get("status"),
            }
        task["status"] = "done"
        task["result"] = envelope
        task["lease_until"] = None
        agent_id = task.get("assignee")
        if agent_id:
            agent = data["agents"].get(agent_id)
            if agent:
                agent["status"] = "idle"
                agent["last_seen"] = _now_s()
        _write_board_unlocked(data)
    return task


def task_renew(task_id: str, agent_id: str) -> Dict[str, Any]:
    """Extend a claimed task's lease (only the assignee may renew).

    Args:
        task_id: Task id.
        agent_id: Claiming agent id.

    Returns:
        The task dict with an extended lease, or an error dict.
    """
    with _LOCK:
        data = _board_locked()
        task = data["tasks"].get(task_id)
        if not task:
            return {"error": "task_not_found", "task_id": task_id}
        if task.get("status") != "claimed" or task.get("assignee") != agent_id:
            return {
                "error": "cannot_renew",
                "task_id": task_id,
                "agent_id": agent_id,
                "status": task.get("status"),
            }
        task["lease_until"] = (_now() + timedelta(seconds=DEFAULT_LEASE_SEC)).isoformat()
        agent = data["agents"].get(agent_id)
        if agent:
            agent["status"] = "busy"
            agent["last_seen"] = _now_s()
        _write_board_unlocked(data)
    return task


def task_list(status: Optional[str] = None) -> List[Dict[str, Any]]:
    """List tasks, optionally filtered by status. Expired leases are swept
    first (lazy expiry).

    Args:
        status: Optional status filter (open/claimed/done/...).

    Returns:
        Tasks ordered by priority DESC, then created_at ASC.
    """
    with _LOCK:
        data = _board_locked()
        tasks = [dict(t) for t in data["tasks"].values()]
    if status:
        tasks = [t for t in tasks if t.get("status") == status]
    tasks.sort(key=_sort_key, reverse=True)
    return tasks


def board_snapshot() -> Dict[str, Any]:
    """Return a compact board overview (agents, open/claimed tasks, stage
    distribution). Expired leases are swept first.

    Returns:
        {"agents": [...], "open_tasks": [...], "claimed_tasks": [...],
         "active_env_count": n, "max_active_envs": cap,
         "stage_distribution": {...}}
    """
    with _LOCK:
        data = _board_locked()
        agents = sorted(
            data["agents"].values(),
            key=lambda a: (a.get("role", ""), a.get("agent_id", "")),
        )
        tasks = [dict(t) for t in data["tasks"].values()]
        env_cap = int(data.get("env_cap", MAX_ACTIVE_ENVS))
    tasks.sort(key=_sort_key, reverse=True)
    open_tasks = [t for t in tasks if t.get("status") == "open"]
    claimed_tasks = [t for t in tasks if t.get("status") == "claimed"]
    stage_distribution: Dict[str, int] = {}
    for t in tasks:
        stage = t.get("stage") or t.get("kind") or "unspecified"
        stage_distribution[stage] = stage_distribution.get(stage, 0) + 1
    return {
        "agents": agents,
        "open_tasks": open_tasks,
        "claimed_tasks": claimed_tasks,
        "active_env_count": len(claimed_tasks),
        "max_active_envs": env_cap,
        "stage_distribution": stage_distribution,
    }


def register_board_tools(mcp: Any, *args: Any, **kwargs: Any) -> None:
    """Register the K4 thin task-board tools on a FastMCP instance."""
    mcp.tool()(task_create)
    mcp.tool()(task_claim)
    mcp.tool()(task_complete)
    mcp.tool()(task_renew)
    mcp.tool()(task_list)
    mcp.tool()(board_snapshot)
