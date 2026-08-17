#!/usr/bin/env python3
"""Sequential surface playbook chain (no run_goal mega-package)."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Sequence

from kali_mcp.core.action_log import log_action, read_actions
from kali_mcp.core.findings_store import list_findings
from kali_mcp.core.handoff import compile_handoff, continue_from_handoff
from kali_mcp.core.target_graph import get_graph
from kali_mcp.core.task_workspace import get_workspace

logger = logging.getLogger(__name__)

# Wall-clock timeout for run_surface_chain (0 = unlimited, seconds). Set via env.
_CHAIN_TIMEOUT_S: int = 0
_raw = os.environ.get("KALI_MCP_CHAIN_TIMEOUT_S", "0")
if _raw and _raw.strip():
    try:
        _val = int(_raw.strip())
        _CHAIN_TIMEOUT_S = _val if _val >= 0 else 0
    except (ValueError, TypeError):
        logger.debug("Invalid KALI_MCP_CHAIN_TIMEOUT_S=%r, using 0 (unlimited)", _raw)
        _CHAIN_TIMEOUT_S = 0

# Fixed order for surface assessment; still not a run_goal mega-package.
DEFAULT_SURFACE_ORDER: List[str] = [
    "web_surface",
    "api_surface",
    "auth_surface",
    "svc_surface",
    "internal_lateral",
    "stealth",
]

DEFAULT_DEPTHS: Dict[str, str] = {
    "web_surface": "standard",
    "api_surface": "quick",
    "auth_surface": "quick",
    "svc_surface": "quick",
    "internal_lateral": "quick",
    "stealth": "quick",
}


def _parse_order(playbooks: Optional[str | Sequence[str]]) -> List[str]:
    if playbooks is None or playbooks == "":
        return list(DEFAULT_SURFACE_ORDER)
    if isinstance(playbooks, str):
        parts = [p.strip().lower() for p in playbooks.replace(",", " ").split() if p.strip()]
        return parts or list(DEFAULT_SURFACE_ORDER)
    return [str(p).strip().lower() for p in playbooks if str(p).strip()]


def _resolve_depths(
    depth: str,
    order: Sequence[str],
    depth_overrides: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Map each playbook to a depth.

    - depth=mixed|default|chain: use DEFAULT_DEPTHS (web=standard, others=quick)
    - depth=quick|standard|thorough: apply same depth to all playbooks
    - depth_overrides: per-playbook overrides (wins)
    """
    base = (depth or "mixed").strip().lower()
    out: Dict[str, str] = {}
    for pb in order:
        if base in ("mixed", "default", "chain", ""):
            out[pb] = DEFAULT_DEPTHS.get(pb, "quick")
        else:
            out[pb] = base
    if depth_overrides:
        for k, v in depth_overrides.items():
            key = str(k).strip().lower()
            if key in out and v:
                out[key] = str(v).strip().lower()
    return out


def run_surface_chain(
    task_id: str,
    target: str,
    executor,
    depth: str = "mixed",
    playbooks: Optional[str | Sequence[str]] = None,
    depth_overrides: Optional[Dict[str, str]] = None,
    stop_on_error: bool = False,
    seed_task: bool = True,
) -> Dict[str, Any]:
    """Run surface playbooks sequentially on one target under an existing/new task.

    Does NOT reintroduce run_goal. Call after start_task or with seed_task=True.
    """
    # Lazy import avoids circular import with playbooks/__init__.py
    from kali_mcp.core.playbooks import list_playbooks, run_playbook

    if not task_id:
        return {"ok": False, "error": "task_id required"}
    if not target or not str(target).strip():
        return {"ok": False, "error": "target required"}

    target = str(target).strip()
    order = _parse_order(playbooks)
    available = set(list_playbooks())
    depths = _resolve_depths(depth, order, depth_overrides)

    ws = get_workspace(task_id, create=True)
    if seed_task:
        meta_targets = list(ws.read_meta().get("targets") or [])
        if target not in meta_targets:
            meta_targets.append(target)
        graph = get_graph(ws.task_id)
        if "://" in target:
            graph.upsert_node(
                "url",
                target,
                confidence=0.9,
                next_checks=["fingerprint", "shallow_dir", "nuclei_subset"],
            )
            host = target.split("://", 1)[-1].split("/")[0].split(":")[0]
            if host:
                graph.upsert_node("host", host, confidence=0.9, next_checks=["http_probe"])
        else:
            graph.upsert_node("host", target, confidence=0.9, next_checks=["http_probe"])
        graph.save()
        ws.update_meta(
            targets=meta_targets,
            depth=depth or "mixed",
            phase="RECON",
            status="chain_running",
            notes="run_surface_chain sequential (no run_goal)",
        )

    chain_t0 = time.perf_counter()
    log_action(
        ws.task_id,
        phase="RECON",
        target=target,
        tool="run_surface_chain",
        args={"order": order, "depths": depths, "stop_on_error": stop_on_error},
        source="harness",
        extra={"event": "chain_start"},
    )

    steps: List[Dict[str, Any]] = []
    aborted = False
    for pb in order:
        if pb not in available:
            steps.append(
                {
                    "playbook": pb,
                    "depth": depths.get(pb),
                    "ok": False,
                    "error": "not registered",
                    "skipped": False,
                    "duration_ms": 0.0,
                }
            )
            if stop_on_error:
                aborted = True
                break
            continue
        pb_depth = depths.get(pb, "quick")
        step_t0 = time.perf_counter()
        try:
            out = run_playbook(pb, ws.task_id, target, executor, depth=pb_depth)
        except Exception as e:
            out = {"ok": False, "error": str(e)}
        step_ms = round((time.perf_counter() - step_t0) * 1000.0, 3)
        findings = list_findings(ws.task_id)
        verified = [f for f in findings if f.get("status") == "verified"]
        # Auto-run Observer after each step to surface duplicates/loops early
        observer_hints: Dict[str, Any] = {}
        try:
            from kali_mcp.core.observer import apply_observer_hints
            observer_hints = apply_observer_hints(ws.task_id, auto_mark_dead=False)
        except Exception as _ex:
            logger.debug("Observer hint failed for %s step %s: %s", ws.task_id, pb, _ex)
            observer_hints["_error"] = str(_ex)[:200]
        step = {
            "playbook": pb,
            "depth": pb_depth,
            "ok": bool(out.get("ok")),
            "findings_total_after": len(findings),
            "verified_after": len(verified),
            "error": out.get("error"),
            "skipped": False,
            "duration_ms": step_ms,
            "observer": {
                "duplicate_count": observer_hints.get("duplicate_count", 0),
                "suggestions_count": len(observer_hints.get("suggestions") or []),
            },
        }
        steps.append(step)
        log_action(
            ws.task_id,
            phase="RECON",
            target=target,
            tool="run_surface_chain_step",
            args={"playbook": pb, "depth": pb_depth},
            exit_code=0 if step["ok"] else 1,
            duration_ms=step_ms,
            source="harness",
            extra={
                "event": "chain_step",
                "playbook": pb,
                "depth": pb_depth,
                "ok": step["ok"],
                "error": step.get("error"),
            },
        )
        if stop_on_error and not step["ok"]:
            aborted = True
            break
        # wall-clock timeout: if KALI_MCP_CHAIN_TIMEOUT_S > 0 and elapsed exceeds, abort
        if _CHAIN_TIMEOUT_S > 0:
            elapsed = time.perf_counter() - chain_t0
            if elapsed > _CHAIN_TIMEOUT_S:
                logger.debug("Chain wall-clock timeout after %ss (limit %ss)", round(elapsed, 2), _CHAIN_TIMEOUT_S)
                aborted = "wall_clock_timeout"
                break

    findings = list_findings(ws.task_id)
    graph = get_graph(ws.task_id, reload=True)
    try:
        handoff = compile_handoff(ws.task_id)
    except Exception as _hc:
        logger.debug("Handoff compile for %s after chain: %s", ws.task_id, _hc)
        handoff = {}
    by_status: Dict[str, int] = {}
    for f in findings:
        s = f.get("status") or "?"
        by_status[s] = by_status.get(s, 0) + 1

    # Final observer pass on completed chain
    observer_final: Dict[str, Any] = {}
    try:
        from kali_mcp.core.observer import apply_observer_hints
        observer_final = apply_observer_hints(ws.task_id, auto_mark_dead=False)
    except Exception as _ex2:
        logger.debug("Final observer pass failed for %s: %s", ws.task_id, _ex2)
    insights_result: Dict[str, Any] = {}
    try:
        from kali_mcp.core.insight_bridge import propose_insights
        insights_result = propose_insights(ws.task_id)
    except Exception as e:
        insights_result = {"ok": False, "skipped": True, "error": str(e)[:200], "created_count": 0}

    # Auto export report.md (export_task_report returns markdown_path / paths.markdown)
    report_md_path: str = ""
    report_export_err: str = ""
    export_ms = 0.0
    try:
        from kali_mcp.core.report_export import export_task_report
        export_t0 = time.perf_counter()
        rout = export_task_report(ws.task_id, formats=["json", "markdown"])
        export_ms = round((time.perf_counter() - export_t0) * 1000.0, 3)
        paths_obj = rout.get("paths") if isinstance(rout, dict) else None
        paths: Dict[str, Any] = paths_obj if isinstance(paths_obj, dict) else {}
        report_md_path = (
            str((rout or {}).get("markdown_path") or "")
            or str(paths.get("markdown") or "")
            or ""
        )
        if not report_md_path and not (rout or {}).get("ok"):
            report_export_err = str((rout or {}).get("error") or "export_failed")[:200]
        log_action(
            ws.task_id,
            phase="REPORT",
            target=target,
            tool="export_task_report",
            args={"formats": ["json", "markdown"]},
            exit_code=0 if (rout or {}).get("ok") else 1,
            duration_ms=export_ms,
            evidence_path=report_md_path or "",
            source="harness",
            extra={
                "event": "export",
                "ok": bool((rout or {}).get("ok")),
                "error": report_export_err or None,
            },
        )
    except Exception as e:
        report_export_err = str(e)[:200]
        log_action(
            ws.task_id,
            phase="REPORT",
            target=target,
            tool="export_task_report",
            args={"formats": ["json", "markdown"]},
            exit_code=1,
            duration_ms=export_ms,
            source="harness",
            extra={"event": "export", "ok": False, "error": report_export_err},
        )

    all_ok = bool(steps) and all(s.get("ok") for s in steps) and not aborted
    status = "chain_done" if all_ok else ("chain_aborted" if aborted else "chain_partial")
    if isinstance(aborted, str) and aborted.startswith("wall_clock"):
        status = aborted
    elapsed_ms = round((time.perf_counter() - chain_t0) * 1000.0, 3)
    log_action(
        ws.task_id,
        phase="REPORT" if all_ok or not aborted else "RECON",
        target=target,
        tool="run_surface_chain",
        args={"order": order, "status": status, "steps": len(steps)},
        exit_code=0 if all_ok else 1,
        duration_ms=elapsed_ms,
        source="harness",
        extra={
            "event": "chain_end",
            "status": status,
            "aborted": aborted,
            "step_count": len(steps),
            "export_ms": export_ms,
        },
    )

    summary: Dict[str, Any] = {
        "ok": all_ok,
        "task_id": ws.task_id,
        "target": target,
        "mode": "surface_chain",
        "order": order,
        "depths": depths,
        "steps": steps,
        "aborted": aborted,
        "elapsed_ms": elapsed_ms,
        "by_status": by_status,
        "findings": [
            {
                "finding_id": f.get("finding_id") or f.get("id"),
                "title": f.get("title"),
                "status": f.get("status"),
            }
            for f in findings
        ],
        "graph_summary": graph.summary(),
        "next_actions": graph.next_actions(limit=15),
        "actions_count": len(read_actions(ws.task_id)),
        "handoff_json": handoff.get("handoff_json"),
        "progress_md": handoff.get("progress_md"),
        # read-only continue check — do not mutate meta to "resumed" mid-finalization
        "continue_ok": continue_from_handoff(ws.task_id, update_status=False).get("ok"),
        "observer": {
            "duplicate_count": observer_final.get("duplicate_count", 0),
            "suggestions_count": len(observer_final.get("suggestions") or []),
            "suggestions": (observer_final.get("suggestions") or [])[:10],
        },
        "insights": {
            # success path omits skipped; default False so created>0 is not shown as skipped
            "skipped": bool(insights_result.get("skipped", False)),
            "created_count": int(insights_result.get("created_count") or 0),
            "reason": insights_result.get("reason"),
            "error": insights_result.get("error"),
        },
        "report_md": report_md_path or None,
        "report_export_error": report_export_err or None,
    }

    report = ws.report_dir / "chain_summary.json"
    report.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    final_phase = "REPORT" if all_ok or not aborted else (ws.read_meta() or {}).get("phase") or "RECON"
    ws.update_meta(
        status=status,
        phase=final_phase,
        report_path=str(report),
    )
    # Terminal success: wipe residual next_checks (seed recon + insight_verify).
    # Candidates stay in findings; optional follow-up is explicit verify, not sticky queue.
    if all_ok and not aborted:
        try:
            g_clear = get_graph(ws.task_id, reload=True)
            cleared = 0
            for node in list(g_clear.nodes.values()):
                if node.next_checks:
                    node.next_checks = []
                    cleared += 1
                # prevent default recon refill (no next_checks + no last_tool => defaults)
                node.meta = dict(node.meta or {})
                if not node.meta.get("last_tool"):
                    node.meta["last_tool"] = "surface_chain"
            if cleared:
                g_clear.save()
            else:
                # still save last_tool stamps if any node lacked them
                g_clear.save()
            summary["graph_summary"] = g_clear.summary()
            summary["next_actions"] = g_clear.next_actions(limit=15, include_insights=True)
        except Exception as _ex:
            logger.debug("Graph final cleanup for %s: %s", ws.task_id, _ex)

    # refresh handoff after terminal meta so continue does not reload stale phase
    try:
        handoff2 = compile_handoff(ws.task_id)
        summary["handoff_json"] = handoff2.get("handoff_json")
        summary["progress_md"] = handoff2.get("progress_md")
    except Exception as _ex3:
        logger.debug("Handoff compile for %s after terminal: %s", ws.task_id, _ex3)

    # 终态自动清理（task 级）：REPORT 阶段完成后自动删除 workspace 痕迹。
    # 默认开启；KALI_MCP_AUTO_WIPE=0 关闭；KALI_MCP_KEEP_REPORT=1 保留 report/。
    # 清理前已导出任务摘要（report/chain_summary.json + summary 返回字段），
    # 调用方（harness/agent）从返回值取摘要，workspace 本身删除不可恢复。
    if all_ok and not aborted and os.environ.get("KALI_MCP_AUTO_WIPE") != "0":
        try:
            from kali_mcp.core.trace_wipe import wipe_task_traces

            wipe = wipe_task_traces(ws.task_id)
            summary["auto_wipe"] = {
                "enabled": True,
                "scope": "task",
                "task_id": ws.task_id,
                "deleted": wipe.get("deleted", []),
                "size_freed": wipe.get("size_freed", 0),
                "kept_report": wipe.get("kept_report", False),
                "error": wipe.get("error"),
            }
            logger.info(
                "[chain] 终态自动清理 task %s 完成（freed=%sB）",
                ws.task_id, wipe.get("size_freed", 0),
            )
        except Exception as _wipe_ex:  # noqa: BLE001 —— 清理失败不阻断返回
            logger.warning("[chain] 终态自动清理 %s 失败: %s", ws.task_id, _wipe_ex)
            summary["auto_wipe"] = {
                "enabled": True,
                "scope": "task",
                "task_id": ws.task_id,
                "error": str(_wipe_ex)[:200],
            }
    else:
        summary["auto_wipe"] = {"enabled": False, "reason": "not terminal or KALI_MCP_AUTO_WIPE=0"}
    summary["report_path"] = str(report)
    summary["status"] = status
    summary["phase"] = final_phase
    return summary
