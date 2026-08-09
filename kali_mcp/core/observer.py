#!/usr/bin/env python3
"""Observer side-channel: detect loops / duplicates; advise only (no hard block)."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from kali_mcp.core.action_log import log_action, read_actions
from kali_mcp.core.target_graph import get_graph


def _key(tool: str, target: str, args_digest: str) -> Tuple[str, str, str]:
    return (
        (tool or "").strip().lower(),
        (target or "").strip().lower(),
        (args_digest or "").strip().lower(),
    )


_META_TOOLS = frozenset({
    "observer_analyze",
    "propose_insights",
    "compile_handoff",
    "continue_from_handoff",
    "run_surface_chain",
    "start_task",
    "log_action",
})


def analyze_actions(
    task_id: str,
    *,
    limit: int = 500,
    duplicate_threshold: int = 2,
    empty_streak_threshold: int = 3,
) -> Dict[str, Any]:
    """Scan action log for repeats and empty-result streaks.

    Returns suggestions only — never blocks execution.
    Meta/internal tools (observer_analyze etc.) are excluded from duplicate detection.
    """
    actions = read_actions(task_id, limit=int(limit or 500))
    counts: Counter = Counter()
    by_tool_target: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    empty_streak = 0
    max_empty_streak = 0
    suggestions: List[Dict[str, Any]] = []

    for a in actions:
        tool = str(a.get("tool") or "")
        target = str(a.get("target") or "")
        digest = str(a.get("args_digest") or "")
        k = _key(tool, target, digest)
        # Skip internal/meta tools — they are not "scans" to be deduplicated
        if tool.lower() in _META_TOOLS:
            continue
        counts[k] += 1
        by_tool_target[(k[0], k[1])].append(a)

        exit_code = a.get("exit")
        # treat non-zero exit or explicit empty marker as empty-ish
        is_empty = False
        if exit_code not in (0, "0", None, ""):
            is_empty = True
        extra = a.get("extra") or {}
        if isinstance(extra, dict) and extra.get("empty_result"):
            is_empty = True
        if is_empty:
            empty_streak += 1
            max_empty_streak = max(max_empty_streak, empty_streak)
        else:
            empty_streak = 0

    duplicates: List[Dict[str, Any]] = []
    for (tool, target, digest), n in counts.items():
        if not tool:
            continue
        if n >= int(duplicate_threshold or 2):
            item = {
                "kind": "duplicate_call",
                "tool": tool,
                "target": target,
                "args_digest": digest,
                "count": n,
                "advice": "skip_or_cache",
                "message": f"same tool+target+args repeated {n} times; prefer skip/cache",
            }
            duplicates.append(item)
            suggestions.append(item)

    if max_empty_streak >= int(empty_streak_threshold or 3):
        suggestions.append(
            {
                "kind": "empty_streak",
                "count": max_empty_streak,
                "advice": "slow_down_or_mark_dead",
                "message": f"empty/failed streak reached {max_empty_streak}; consider dead_reason or phase advance",
            }
        )

    # WAF / full-block heuristic from action extra notes
    waf_hits = 0
    for a in actions:
        extra = a.get("extra") or {}
        blob = " ".join(
            str(x)
            for x in (
                a.get("tool"),
                extra.get("note"),
                extra.get("signal"),
                extra.get("status_hint"),
            )
            if x
        ).lower()
        if any(t in blob for t in ("waf", "403", "blocked", "cloudflare")):
            waf_hits += 1
    if waf_hits >= 3:
        suggestions.append(
            {
                "kind": "waf_or_block",
                "count": waf_hits,
                "advice": "mark_dead_or_change_path",
                "message": f"detected {waf_hits} WAF/403-like signals; mark node dead or switch surface",
            }
        )

    return {
        "task_id": task_id,
        "actions_scanned": len(actions),
        "duplicate_count": len(duplicates),
        "max_empty_streak": max_empty_streak,
        "duplicates": duplicates[:50],
        "suggestions": suggestions[:50],
        "should_slow_down": bool(suggestions),
    }


def apply_observer_hints(
    task_id: str,
    *,
    auto_mark_dead: bool = False,
    reason_prefix: str = "observer",
) -> Dict[str, Any]:
    """Write observer suggestions to log; optionally mark graph nodes dead.

    Default: log only (no hard block). auto_mark_dead is opt-in.
    """
    report = analyze_actions(task_id)
    graph = get_graph(task_id, reload=True)
    marked: List[str] = []

    if auto_mark_dead:
        for dup in report.get("duplicates") or []:
            target = (dup.get("target") or "").strip()
            if not target:
                continue
            for node in list(graph.nodes.values()):
                if node.dead_reason:
                    continue
                if node.value == target or target in (node.value or ""):
                    graph.mark_dead(node.id, f"{reason_prefix}:duplicate:{dup.get('tool')}")
                    marked.append(node.id)
        if marked:
            graph.save()

    log_action(
        task_id,
        phase="OBSERVE",
        target="",
        tool="observer_analyze",
        args={
            "duplicate_count": report.get("duplicate_count"),
            "suggestions": len(report.get("suggestions") or []),
            "auto_mark_dead": auto_mark_dead,
        },
        exit_code=0,
        source="observer",
        extra={"suggestions": report.get("suggestions") or [], "marked_dead": marked},
    )
    report["marked_dead"] = marked
    report["ok"] = True
    return report
