#!/usr/bin/env python3
"""P0 harness MCP tools: task/graph/playbook/verify (lean surface)."""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Phase4 multi-target quotas (env-tunable; hard caps prevent runaway fan-out)
_DEFAULT_MULTI_MAX_TARGETS = 20
_DEFAULT_MULTI_MAX_WORKERS = 4
_HARD_MULTI_MAX_TARGETS = 50
_HARD_MULTI_MAX_WORKERS = 8


def _env_int(name: str, default: int, *, lo: int = 1, hi: int = 64) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, val))


def _legacy_playbooks_enabled() -> bool:
    """playbooks 是否注册为 MCP 工具（ARCH_DESIGN §9）。

    默认 **不注册**（预定义 playbook 已移出主路径，战术内容向量化进 KB）；
    仅当环境变量 `K4_LEGACY_PLAYBOOKS=1` 时显式开启，作为过渡期兼容。
    """
    return os.environ.get("K4_LEGACY_PLAYBOOKS") == "1"


def multi_chain_quotas() -> Dict[str, int]:
    """Return effective multi-target quotas for run_surface_chain_multi."""
    max_targets = _env_int(
        "KALI_MCP_MULTI_MAX_TARGETS",
        _DEFAULT_MULTI_MAX_TARGETS,
        lo=1,
        hi=_HARD_MULTI_MAX_TARGETS,
    )
    max_workers = _env_int(
        "KALI_MCP_MULTI_MAX_WORKERS",
        _DEFAULT_MULTI_MAX_WORKERS,
        lo=1,
        hi=_HARD_MULTI_MAX_WORKERS,
    )
    return {"max_targets": max_targets, "max_workers": max_workers}


def clamp_multi_workers(requested: int, target_count: int) -> Tuple[int, Dict[str, int]]:
    """Clamp parallel workers by env quota and target count."""
    q = multi_chain_quotas()
    req = max(1, int(requested or 1))
    workers = max(1, min(req, q["max_workers"], max(1, target_count)))
    return workers, q


def register_harness_tools(mcp, executor):
    """Register orchestration tools for autonomous assessment."""

    @mcp.tool()
    def start_task(
        targets: str = "",
        task_id: str = "",
        depth: str = "standard",
        notes: str = "",
    ) -> Dict[str, Any]:
        """Create/open a task workspace and seed target graph nodes.

        Args:
            targets: Comma/space separated hosts or URLs
            task_id: Optional task id
            depth: quick|standard|thorough
            notes: free text
        """
        from kali_mcp.core.action_log import log_action
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace

        ws = get_workspace(task_id or None, create=True)
        raw = (targets or "").replace(",", " ").split()
        target_list = [t.strip() for t in raw if t.strip()]
        graph = get_graph(ws.task_id)
        for t in target_list:
            if "://" in t:
                graph.upsert_node("url", t, confidence=0.9, next_checks=["fingerprint", "shallow_dir", "nuclei_subset"])
                host = t.split("://", 1)[-1].split("/")[0].split(":")[0]
                if host:
                    graph.upsert_node("host", host, confidence=0.9, next_checks=["http_probe"])
            else:
                graph.upsert_node("host", t, confidence=0.9, next_checks=["http_probe"])
        graph.save()
        meta = ws.update_meta(
            phase="RECON",
            status="open",
            depth=depth or "standard",
            targets=target_list,
            notes=notes or "",
        )
        log_action(
            ws.task_id,
            phase="RECON",
            target=",".join(target_list),
            tool="start_task",
            args={"targets": target_list, "depth": depth},
            source="harness",
        )
        return {
            "ok": True,
            "task_id": ws.task_id,
            "meta": meta,
            "graph_summary": graph.summary(),
            "next_actions": graph.next_actions(limit=20),
        }

    @mcp.tool()
    def get_task(task_id: str) -> Dict[str, Any]:
        """Get task meta, graph summary, findings counts and recent actions."""
        from kali_mcp.core.action_log import read_actions
        from kali_mcp.core.findings_store import list_findings
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        ws = get_workspace(task_id, create=True)
        graph = get_graph(ws.task_id)
        findings = list_findings(ws.task_id)
        by_status: Dict[str, int] = {}
        for f in findings:
            s = f.get("status") or "candidate"
            by_status[s] = by_status.get(s, 0) + 1
        return {
            "ok": True,
            "task_id": ws.task_id,
            "meta": ws.read_meta(),
            "graph_summary": graph.summary(),
            "findings_by_status": by_status,
            "recent_actions": read_actions(ws.task_id, limit=30),
            "next_actions": graph.next_actions(limit=20),
        }

    @mcp.tool()
    def graph_upsert(
        task_id: str,
        node_type: str,
        value: str,
        confidence: float = 0.5,
        next_checks: str = "",
        meta_json: str = "",
        source: str = "manual",
    ) -> Dict[str, Any]:
        """Upsert a graph node. next_checks is comma-separated. meta_json is optional JSON object."""
        from kali_mcp.core.target_graph import get_graph

        if not task_id or not value:
            return {"ok": False, "error": "task_id and value required"}
        checks = [x.strip() for x in (next_checks or "").split(",") if x.strip()]
        meta = {}
        if meta_json:
            try:
                meta = json.loads(meta_json)
            except Exception as e:
                return {"ok": False, "error": f"meta_json invalid: {e}"}
        graph = get_graph(task_id)
        node = graph.upsert_node(
            node_type or "host",
            value,
            confidence=float(confidence or 0.5),
            next_checks=checks,
            meta=meta if isinstance(meta, dict) else {},
            source=source or "manual",
        )
        graph.save()
        return {"ok": True, "node": node.to_dict(), "graph_summary": graph.summary()}

    @mcp.tool()
    def graph_query(task_id: str, node_type: str = "", alive_only: bool = True, limit: int = 100) -> Dict[str, Any]:
        """Query graph nodes."""
        from kali_mcp.core.target_graph import get_graph

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        graph = get_graph(task_id)
        nodes = graph.query(node_type=node_type or None, alive_only=bool(alive_only), limit=int(limit or 100))
        return {"ok": True, "task_id": graph.task_id, "count": len(nodes), "nodes": nodes}

    @mcp.tool()
    def graph_next_actions(task_id: str, limit: int = 20, include_insights: bool = False) -> Dict[str, Any]:
        """List next actions from graph (optionally include insight-sourced checks)."""
        from kali_mcp.core.target_graph import get_graph

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        graph = get_graph(task_id)
        actions = graph.next_actions(limit=int(limit or 20), include_insights=bool(include_insights))
        return {"ok": True, "task_id": graph.task_id, "actions": actions}

    @mcp.tool()
    def graph_mark_dead(task_id: str, node_id: str, reason: str = "dead") -> Dict[str, Any]:
        """Mark a graph node dead so it stops generating next actions."""
        from kali_mcp.core.target_graph import get_graph

        if not task_id or not node_id:
            return {"ok": False, "error": "task_id and node_id required"}
        graph = get_graph(task_id)
        node = graph.mark_dead(node_id, reason or "dead")
        if not node:
            return {"ok": False, "error": "node not found"}
        graph.save()
        return {"ok": True, "node": node.to_dict()}

    # ---- playbook 注册表（ARCH_DESIGN §9）----
    # 预定义 playbook 已移出主路径：run_playbook / run_surface_chain 默认
    # **不注册**（K4_LEGACY_PLAYBOOKS=1 显式开启过渡）。playbook 战术内容
    # 已向量化进 KB 作参考；核心实现保留在 kali_mcp/core/playbooks/。
    # run_surface_chain_multi（多目标配额扇出工具）独立于 playbook 注册表保留。
    if _legacy_playbooks_enabled():

        @mcp.tool()
        def run_playbook(
            task_id: str,
            playbook: str = "web_surface",
            target: str = "",
            depth: str = "standard",
        ) -> Dict[str, Any]:
            """Run a named playbook (web_surface | api_surface | auth_surface | svc_surface).

            @legacy（ARCH_DESIGN §9）：预定义 playbook 已移出主路径，本工具仅在
            K4_LEGACY_PLAYBOOKS=1 时注册，作为过渡期兼容。
            """
            from kali_mcp.core.playbooks import list_playbooks, run_playbook as _run

            if not task_id:
                return {"ok": False, "error": "task_id required"}
            if not target:
                return {"ok": False, "error": "target required", "available_playbooks": list_playbooks()}
            try:
                return _run(playbook or "web_surface", task_id, target, executor, depth=depth or "standard")
            except Exception as e:
                logger.exception("run_playbook failed")
                return {"ok": False, "error": str(e), "available_playbooks": list_playbooks()}

        @mcp.tool()
        def run_surface_chain(
            task_id: str,
            target: str = "",
            depth: str = "mixed",
            playbooks: str = "",
            stop_on_error: bool = False,
        ) -> Dict[str, Any]:
            """Sequentially run surface playbooks after start_task (no run_goal).

            Default order: web_surface(standard) → api_surface(quick) → auth_surface(quick) → svc_surface(quick).
            depth=mixed keeps that mix; depth=quick|standard|thorough applies to all.
            playbooks: optional comma/space list to subset/reorder (must be registered playbooks).

            @legacy（ARCH_DESIGN §9）：预定义 playbook 已移出主路径，本工具仅在
            K4_LEGACY_PLAYBOOKS=1 时注册，作为过渡期兼容。
            """
            from kali_mcp.core.playbooks import list_playbooks, run_surface_chain as _chain

            if not task_id:
                return {"ok": False, "error": "task_id required"}
            if not target:
                return {
                    "ok": False,
                    "error": "target required",
                    "available_playbooks": list_playbooks(),
                    "default_order": ["web_surface", "api_surface", "auth_surface", "svc_surface"],
                }
            try:
                return _chain(
                    task_id=task_id,
                    target=target,
                    executor=executor,
                    depth=depth or "mixed",
                    playbooks=playbooks or None,
                    stop_on_error=bool(stop_on_error),
                    seed_task=True,
                )
            except Exception as e:
                logger.exception("run_surface_chain failed")
                return {"ok": False, "error": str(e), "available_playbooks": list_playbooks()}

    @mcp.tool()
    def verify_finding(
        task_id: str,
        finding_id: str,
        reproduce_cmd: str = "",
        expected_signal: str = "",
    ) -> Dict[str, Any]:
        """Verify a candidate finding by replaying command and matching expected_signal."""
        from kali_mcp.core.verifier import verify_finding as _verify

        if not task_id or not finding_id:
            return {"ok": False, "error": "task_id and finding_id required"}
        return _verify(
            task_id,
            finding_id,
            executor=executor,
            reproduce_cmd=reproduce_cmd or None,
            expected_signal=expected_signal if expected_signal != "" else None,
        )

    @mcp.tool()
    def export_task_summary(task_id: str, format: str = "both") -> Dict[str, Any]:
        """Export task report: JSON + Markdown primary; optional docx (python-docx).

        Args:
            task_id: task id
            format: json | markdown | docx | both | all (default both = json+markdown).
                    Raw evidence stays on disk (no redaction).
        """
        from kali_mcp.core.evidence_store import save_json_evidence
        from kali_mcp.core.report_export import export_task_report

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        fmt = (format or "both").strip().lower()
        if fmt in ("md", "markdown"):
            formats = ["markdown"]
        elif fmt == "json":
            formats = ["json"]
        elif fmt == "docx":
            formats = ["docx"]
        elif fmt in ("all", "full"):
            formats = ["json", "markdown", "docx"]
        elif fmt in ("md+docx", "markdown+docx"):
            formats = ["markdown", "docx"]
        else:
            formats = ["json", "markdown"]
        out = export_task_report(task_id, formats=formats)
        if not out.get("ok"):
            return out
        # keep evidence snapshot of structured summary for replay
        try:
            payload_meta = {
                "paths": out.get("paths"),
                "verified_count": out.get("verified_count"),
                "candidate_count": out.get("candidate_count"),
                "exported_at": out.get("exported_at"),
            }
            evidence = save_json_evidence(
                task_id, "task_summary", payload_meta, meta={"kind": "export"}
            )
            out["evidence_path"] = evidence.get("path")
        except Exception as e:
            logger.warning("export evidence snapshot failed: %s", e)
            out["evidence_path"] = ""
        return out

    @mcp.tool()
    def compile_task_handoff(task_id: str) -> Dict[str, Any]:
        """Compile handoff/progress for resume (do-not-rescan + next_actions)."""
        from kali_mcp.core.handoff import compile_handoff

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        payload = compile_handoff(task_id)
        return {"ok": True, **payload}

    @mcp.tool()
    def continue_from_handoff(task_id: str) -> Dict[str, Any]:
        """Resume plan from last handoff without forcing full rescan."""
        from kali_mcp.core.handoff import continue_from_handoff as _cont

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        return _cont(task_id)

    @mcp.tool()
    def observe_task(task_id: str, auto_mark_dead: bool = False) -> Dict[str, Any]:
        """Observer side-channel: detect duplicate tool calls / empty streaks; advise only by default."""
        from kali_mcp.core.observer import apply_observer_hints

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        return apply_observer_hints(task_id, auto_mark_dead=bool(auto_mark_dead))

    @mcp.tool()
    def propose_insights(
        task_id: str,
        force: bool = False,
        max_per_phase: int = 0,
        enqueue_verify: bool = False,
    ) -> Dict[str, Any]:
        """Insight branch: produce graph-bound Hypothesis candidates only (never drives executor).

        enqueue_verify=False by default so terminal chain_done stays clean;
        set true only when you want sticky insight_verify next_checks on bound nodes.
        """
        from kali_mcp.core.insight_bridge import propose_insights as _propose

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        kwargs: Dict[str, Any] = {
            "force": bool(force),
            "enqueue_verify": bool(enqueue_verify),
        }
        if max_per_phase and int(max_per_phase) > 0:
            kwargs["max_per_phase"] = int(max_per_phase)
        return _propose(task_id, **kwargs)

    @mcp.tool()
    def attack_coverage(task_id: str) -> Dict[str, Any]:
        """ATT&CK technique label coverage for task findings (report appendix; not a runtime driver)."""
        from kali_mcp.core.attack_coverage import task_attack_coverage

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        return task_attack_coverage(task_id)

    @mcp.tool()
    def task_status(task_id: str = "") -> Dict[str, Any]:
        """Real-time task dashboard: phase, graph size, verified count, recent actions, report paths.

        Omit task_id to list all active tasks.
        """
        from kali_mcp.core.action_log import read_actions
        from kali_mcp.core.findings_store import list_findings
        from kali_mcp.core.target_graph import get_graph
        from kali_mcp.core.task_workspace import get_workspace, list_tasks

        if not task_id:
            tasks = list_tasks()
            summaries = []
            for tid in tasks[-20:]:
                try:
                    ws = get_workspace(tid, create=False)
                    meta = ws.read_meta()
                    findings = list_findings(tid)
                    by_status: Dict[str, int] = {}
                    for f in findings:
                        s = f.get("status") or "?"
                        by_status[s] = by_status.get(s, 0) + 1
                    summaries.append({
                        "task_id": tid,
                        "phase": meta.get("phase"),
                        "status": meta.get("status"),
                        "targets": meta.get("targets") or [],
                        "depth": meta.get("depth"),
                        "verified": by_status.get("verified", 0),
                        "candidate": by_status.get("candidate", 0),
                        "updated_at": meta.get("updated_at"),
                    })
                except Exception:
                    summaries.append({"task_id": tid, "error": "unreadable"})
            return {"ok": True, "tasks": summaries, "total": len(tasks)}

        ws = get_workspace(task_id, create=True)
        meta = ws.read_meta()
        graph = get_graph(ws.task_id, reload=True)
        findings = list_findings(ws.task_id)
        actions = read_actions(ws.task_id, limit=10)
        by_status: Dict[str, int] = {}
        for f in findings:
            s = f.get("status") or "?"
            by_status[s] = by_status.get(s, 0) + 1
        report_path = ws.report_dir / "report.md"
        summary_path = ws.report_dir / "summary.json"
        chain_path = ws.report_dir / "chain_summary.json"
        return {
            "ok": True,
            "task_id": ws.task_id,
            "phase": meta.get("phase"),
            "status": meta.get("status"),
            "targets": meta.get("targets") or [],
            "depth": meta.get("depth"),
            "graph": graph.summary(),
            "next_actions_count": len(graph.next_actions(limit=50)),
            "next_actions": graph.next_actions(limit=10),
            "findings_by_status": by_status,
            "findings_total": len(findings),
            "recent_actions": actions,
            "report_md": str(report_path) if report_path.exists() else None,
            "summary_json": str(summary_path) if summary_path.exists() else None,
            "chain_summary": str(chain_path) if chain_path.exists() else None,
            "handoff": str(ws.handoff_dir / "handoff.json") if (ws.handoff_dir / "handoff.json").exists() else None,
            "updated_at": meta.get("updated_at"),
        }

    @mcp.tool()
    def task_timeline(task_id: str, limit: int = 200, tools: str = "", sources: str = "") -> Dict[str, Any]:
        """Read-only action_log timeline (what/when). No new write path.

        Args:
            task_id: task id
            limit: max events (tail)
            tools: optional comma/space tool filter
            sources: optional comma/space source filter
        """
        from kali_mcp.core.action_log import task_timeline as _timeline

        if not task_id:
            return {"ok": False, "error": "task_id required"}
        tool_list = [x.strip() for x in (tools or "").replace(",", " ").split() if x.strip()] or None
        source_list = [x.strip() for x in (sources or "").replace(",", " ").split() if x.strip()] or None
        return _timeline(
            task_id,
            limit=int(limit or 200),
            tools=tool_list,
            sources=source_list,
        )

    @mcp.tool()
    def run_surface_chain_multi(
        targets: str,
        task_id: str = "",
        depth: str = "mixed",
        playbooks: str = "",
        stop_on_error: bool = False,
        parallel: bool = False,
        max_workers: int = 2,
    ) -> Dict[str, Any]:
        """Run surface chain on multiple targets.

        sequential (default): same task_id, targets one after another.
        parallel=True: each target gets its own task_id ({base}-{i}) to avoid graph races;
        wall-clock elapsed_sec is always returned (measured only).

        Quotas (Phase4):
          - KALI_MCP_MULTI_MAX_TARGETS (default 20, hard max 50)
          - KALI_MCP_MULTI_MAX_WORKERS (default 4, hard max 8)
        Exceeding max_targets returns ok=false without starting work.
        """
        import time
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from kali_mcp.core.playbooks.chain import run_surface_chain
        from kali_mcp.core.task_workspace import get_workspace, normalize_task_id

        raw = (targets or "").replace(",", " ").split()
        target_list = [t.strip() for t in raw if t.strip()]
        if not target_list:
            return {"ok": False, "error": "targets required"}

        quotas = multi_chain_quotas()
        if len(target_list) > quotas["max_targets"]:
            return {
                "ok": False,
                "error": (
                    f"targets count {len(target_list)} exceeds multi max_targets "
                    f"{quotas['max_targets']} (set KALI_MCP_MULTI_MAX_TARGETS, hard max "
                    f"{_HARD_MULTI_MAX_TARGETS})"
                ),
                "quota": quotas,
                "targets_count": len(target_list),
                "targets": target_list[:20],
            }

        base_tid = task_id or normalize_task_id(None)
        workers, quotas = clamp_multi_workers(int(max_workers or 2), len(target_list))
        t0 = time.perf_counter()
        results: List[Dict[str, Any]] = []

        def _one(idx: int, t: str, tid: str, seed: bool) -> Dict[str, Any]:
            try:
                out = run_surface_chain(
                    task_id=tid,
                    target=t,
                    executor=executor,
                    depth=depth or "mixed",
                    playbooks=playbooks or None,
                    stop_on_error=stop_on_error,
                    seed_task=seed,
                )
            except Exception as e:
                out = {"ok": False, "target": t, "task_id": tid, "error": str(e)[:300]}
            by = out.get("by_status") or {}
            return {
                "target": t,
                "task_id": out.get("task_id") or tid,
                "ok": out.get("ok"),
                "error": out.get("error"),
                "verified": by.get("verified", 0) if isinstance(by, dict) else 0,
                "findings_total": out.get("findings_total") or 0,
            }

        if parallel and len(target_list) > 1:
            mode = "parallel"
            futures = {}
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for i, t in enumerate(target_list):
                    tid_i = f"{base_tid}-{i + 1}"
                    fut = pool.submit(_one, i, t, tid_i, True)
                    futures[fut] = i
                ordered: List[Optional[Dict[str, Any]]] = [None] * len(target_list)
                for fut in as_completed(futures):
                    idx = futures[fut]
                    try:
                        ordered[idx] = fut.result()
                    except Exception as e:
                        ordered[idx] = {
                            "target": target_list[idx],
                            "task_id": f"{base_tid}-{idx + 1}",
                            "ok": False,
                            "error": str(e)[:300],
                            "verified": 0,
                            "findings_total": 0,
                        }
                results = [r for r in ordered if r is not None]
        else:
            mode = "sequential"
            for i, t in enumerate(target_list):
                results.append(_one(i, t, base_tid, seed=(i == 0)))

        elapsed = round(time.perf_counter() - t0, 3)

        # combined summary: sequential → shared task; parallel → base task may be empty
        summary_tid = base_tid if mode == "sequential" else (results[0].get("task_id") if results else base_tid)
        from kali_mcp.core.findings_store import list_findings
        from kali_mcp.core.target_graph import get_graph

        combined_by_status: Dict[str, int] = {}
        combined_graph: Dict[str, Any] = {}
        next_actions: List[Dict[str, Any]] = []
        if mode == "sequential":
            ws = get_workspace(base_tid, create=True)
            findings = list_findings(base_tid)
            for f in findings:
                s = f.get("status") or "?"
                combined_by_status[s] = combined_by_status.get(s, 0) + 1
            g = get_graph(base_tid, reload=True)
            combined_graph = g.summary()
            next_actions = g.next_actions(limit=10)
        else:
            for r in results:
                tid_r = str(r.get("task_id") or "")
                if not tid_r:
                    continue
                try:
                    for f in list_findings(tid_r):
                        s = f.get("status") or "?"
                        combined_by_status[s] = combined_by_status.get(s, 0) + 1
                except Exception:
                    pass
            combined_graph = {"mode": "parallel", "task_ids": [r.get("task_id") for r in results]}

        return {
            "ok": all(r.get("ok") for r in results) if results else False,
            "task_id": base_tid if mode == "sequential" else base_tid,
            "mode": mode,
            "parallel": mode == "parallel",
            "max_workers": workers if mode == "parallel" else 1,
            "quota": quotas,
            "elapsed_sec": elapsed,
            "targets": target_list,
            "per_target": results,
            "combined_by_status": combined_by_status,
            "combined_graph": combined_graph,
            "next_actions": next_actions,
            "summary_task_id": summary_tid,
        }

    logger.info(
        "harness tools registered (start_task/graph/%srun_playbook/%srun_surface_chain/"
        "run_surface_chain_multi/verify/export_task_summary/handoff/observe/"
        "propose_insights/attack_coverage/task_status/task_timeline)"
        % (
            "" if _legacy_playbooks_enabled() else "NO-",
            "" if _legacy_playbooks_enabled() else "NO-",
        )
    )
