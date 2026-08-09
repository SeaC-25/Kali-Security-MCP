#!/usr/bin/env python3
"""Task handoff / progress compiler for resume without full rescan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from kali_mcp.core.action_log import read_actions
from kali_mcp.core.findings_store import list_findings
from kali_mcp.core.target_graph import get_graph
from kali_mcp.core.task_workspace import get_workspace, utc_now_iso


def compile_handoff(task_id: str) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    graph = get_graph(ws.task_id, reload=True)
    findings = list_findings(ws.task_id)
    actions = read_actions(ws.task_id, limit=100)
    meta = ws.read_meta()
    next_actions = graph.next_actions(limit=30)
    dead = [n.to_dict() for n in graph.nodes.values() if n.dead_reason]
    verified = [f for f in findings if f.get("status") == "verified"]
    candidates = [f for f in findings if f.get("status") == "candidate"]

    done_tools = []
    for a in actions:
        t = a.get("tool")
        if t and t not in done_tools:
            done_tools.append(t)

    payload = {
        "task_id": ws.task_id,
        "compiled_at": utc_now_iso(),
        "phase": meta.get("phase"),
        "status": meta.get("status"),
        "targets": meta.get("targets") or [],
        "depth": meta.get("depth"),
        "graph_summary": graph.summary(),
        "done_tools": done_tools,
        "actions_count": len(actions),
        "verified_count": len(verified),
        "candidate_count": len(candidates),
        "verified_titles": [f.get("title") for f in verified],
        "candidate_titles": [f.get("title") for f in candidates],
        "dead_nodes": [{"id": d.get("id"), "value": d.get("value"), "reason": d.get("dead_reason")} for d in dead[:50]],
        "next_actions": next_actions,
        "do_not_rescan": [
            {"tool": a.get("tool"), "target": a.get("target"), "args_digest": a.get("args_digest")}
            for a in actions
            if a.get("tool") and a.get("exit") in (0, "0", None)
        ][-50:],
    }

    json_path = ws.handoff_dir / "handoff.json"
    md_path = ws.handoff_dir / "progress.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        f"# Handoff {ws.task_id}",
        "",
        f"- compiled_at: {payload['compiled_at']}",
        f"- phase: {payload['phase']}",
        f"- status: {payload['status']}",
        f"- targets: {', '.join(payload['targets']) if payload['targets'] else '(none)'}",
        f"- depth: {payload['depth']}",
        f"- graph: {payload['graph_summary']}",
        f"- verified: {payload['verified_count']} | candidates: {payload['candidate_count']}",
        f"- done_tools: {', '.join(done_tools) if done_tools else '(none)'}",
        "",
        "## Next actions",
    ]
    for item in next_actions[:20]:
        lines.append(f"- [{item.get('node_type')}] {item.get('value')} -> {item.get('action')}")
    if not next_actions:
        lines.append("- (empty)")
    lines.extend(["", "## Verified"])
    for t in payload["verified_titles"] or ["(none)"]:
        lines.append(f"- {t}")
    lines.extend(["", "## Dead / skip"])
    for d in payload["dead_nodes"][:20] or [{"value": "(none)", "reason": ""}]:
        lines.append(f"- {d.get('value')} ({d.get('reason')})")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    payload["handoff_json"] = str(json_path)
    payload["progress_md"] = str(md_path)
    return payload


def load_handoff(task_id: str) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    path = ws.handoff_dir / "handoff.json"
    if not path.exists():
        return compile_handoff(task_id)
    return json.loads(path.read_text(encoding="utf-8"))


_TERMINAL_STATUSES = frozenset(
    {
        "chain_done",
        "playbook_done",
        "goal_done",
        "closed",
        "done",
        "report_done",
    }
)


def continue_from_handoff(task_id: str, *, update_status: bool = True) -> Dict[str, Any]:
    """Return resume plan without forcing rescan of completed probes.

    Does not force status=resumed when update_status=False, when the task is
    already terminal with nothing left to run, or when next_actions is empty.
    """
    payload = load_handoff(task_id)
    ws = get_workspace(task_id, create=True)
    before = dict(ws.read_meta() or {})
    # Live graph must include insight residual queue for resume planning.
    # Default next_actions() hides source=insight; that made terminal+insight look empty.
    next_actions = list(payload.get("next_actions") or [])
    try:
        live_next = get_graph(ws.task_id, reload=True).next_actions(
            limit=30, include_insights=True
        )
        if live_next is not None:
            next_actions = list(live_next)
    except Exception:
        pass

    status_now = str(before.get("status") or "")
    terminal = status_now in _TERMINAL_STATUSES
    mutated = False
    meta = before

    def _insight_only(actions: List[Any]) -> bool:
        if not actions:
            return False
        for a in actions:
            if not isinstance(a, dict):
                return False
            act = str(a.get("action") or "")
            src = str(a.get("source") or "")
            if act.startswith("insight_") or src == "insight":
                continue
            return False
        return True

    if update_status and next_actions:
        # Terminal chain_done + only residual insight_verify: keep terminal meta
        if terminal and _insight_only(next_actions):
            meta = before
            mutated = False
        else:
            phase = before.get("phase") or payload.get("phase") or meta_phase_safe(ws)
            meta = ws.update_meta(status="resumed", phase=phase)
            mutated = True
    # empty next_actions or update_status=False: never clobber terminal meta

    return {
        "ok": True,
        "task_id": ws.task_id,
        "meta": meta,
        "resume": {
            "next_actions": next_actions,
            "do_not_rescan_count": len(payload.get("do_not_rescan") or []),
            "verified_count": payload.get("verified_count", 0),
            "candidate_count": payload.get("candidate_count", 0),
            "graph_summary": payload.get("graph_summary"),
            "handoff_json": payload.get("handoff_json"),
            "progress_md": payload.get("progress_md"),
            "mutated_meta": mutated,
            "insight_residual_only": bool(next_actions) and _insight_only(next_actions),
        },
    }


def meta_phase_safe(ws) -> str:
    return (ws.read_meta() or {}).get("phase") or "RECON"
