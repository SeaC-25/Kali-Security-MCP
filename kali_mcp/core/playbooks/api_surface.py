#!/usr/bin/env python3
"""api_surface: probe common API routes; register + auto-verify candidates."""

from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from kali_mcp.core.action_log import log_action
from kali_mcp.core.evidence_store import save_evidence
from kali_mcp.core.findings_store import list_findings
from kali_mcp.core.handoff import compile_handoff
from kali_mcp.core.target_graph import get_graph
from kali_mcp.core.task_context import clear_active_task, set_active_task
from kali_mcp.core.task_workspace import get_workspace
from kali_mcp.core.verifier import register_candidate, verify_finding

COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/actuator",
    "/actuator/health",
    "/health",
    "/docs",
    "/redoc",
]


def _unique_paths(paths: List[str]) -> List[str]:
    """Drop trailing-slash duplicates while preserving first-seen order."""
    seen = set()
    out: List[str] = []
    for p in paths:
        key = (p or "").rstrip("/") or "/"
        if key in seen:
            continue
        seen.add(key)
        out.append(key if key != "/" else p)
    return out


def _base(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = f"http://{u}"
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def run_api_surface(
    task_id: str,
    target: str,
    executor: Any,
    depth: str = "standard",
    **kwargs: Any,
) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    base = _base(target)
    if not base:
        return {"ok": False, "error": "target required"}

    set_active_task(ws.task_id)
    try:
        graph = get_graph(ws.task_id)
        graph.upsert_node(
            "url",
            base + "/",
            confidence=0.8,
            meta={"playbook": "api_surface"},
            source="playbook",
        )
        graph.save()
        ws.update_meta(phase="RECON", status="running")

        paths = list(COMMON_API_PATHS)
        d = (depth or "standard").lower()
        if d == "quick":
            paths = paths[:8]
        elif d == "thorough":
            paths = paths + [
                "/api/users",
                "/api/admin",
                "/api/config",
                "/.well-known/openid-configuration",
            ]
        paths = _unique_paths(paths)

        hits: List[Dict[str, Any]] = []
        steps: List[Dict[str, Any]] = []
        for path in paths:
            # probe canonical path only (no /api + /api/ double hit)
            full = urljoin(base + "/", path.lstrip("/"))
            start = time.time()
            # body + status in one shot to avoid double noise
            cmd = (
                f'curl -sS --noproxy "*" -L -w "\\n__HTTP_CODE__:%{{http_code}}" "{full}"'
            )
            result = executor.execute_command(cmd)
            duration_ms = round((time.time() - start) * 1000, 2)
            raw_out = result.get("output") or ""
            code = ""
            body = raw_out
            if "__HTTP_CODE__:" in raw_out:
                body, _, tail = raw_out.rpartition("__HTTP_CODE__:")
                code = (tail or "").strip().split()[0] if tail else ""
            body = body.strip()
            evidence = save_evidence(
                ws.task_id,
                name=f"api_probe_{path.replace('/', '_') or 'root'}",
                content=f"status={code}\nurl={full}\n{body[:4000]}",
                meta={"path": path, "status": code, "url": full},
            )
            log_action(
                ws.task_id,
                phase="RECON",
                target=full,
                tool="curl_api_probe",
                args={"path": path},
                exit_code=result.get("return_code"),
                duration_ms=duration_ms,
                evidence_path=evidence["path"],
                source="playbook",
                extra={"playbook": "api_surface", "status": code},
            )
            steps.append(
                {
                    "path": path,
                    "url": full,
                    "status": code,
                    "duration_ms": duration_ms,
                    "success": bool(result.get("success")),
                }
            )
            # interesting: 2xx/3xx/auth walls
            if code not in {"200", "201", "204", "301", "302", "401", "403"}:
                continue
            graph.upsert_node(
                "path",
                full,
                confidence=0.75,
                evidence_path=evidence["path"],
                next_checks=["verify_finding"],
                meta={"status": code, "playbook": "api_surface"},
                source="playbook",
            )
            hits.append({"url": full, "status": code})
            body_l = body.lower()
            content_hit = any(
                k in body_l
                for k in (
                    "swagger",
                    "openapi",
                    "graphql",
                    "api",
                    "json",
                    "health",
                    "status",
                    "ok",
                    "html",
                )
            )
            if code in {"200", "201"} or content_hit or code in {"401", "403"}:
                register_candidate(
                    ws.task_id,
                    title=f"api_endpoint:{full}",
                    target=full,
                    severity="medium" if str(code).startswith("2") else "low",
                    reproduce_cmd=f'curl -sS --noproxy "*" -L "{full}"',
                    expected_signal="re:(?i)(api|json|swagger|openapi|graphql|health|status|ok|html|200|401|403)",
                    source="playbook",
                    technique_ids=["T1595"],
                    evidence_paths=[evidence["path"]],
                    meta={"status": code, "playbook": "api_surface"},
                )

        graph.save()

        auto_verified: List[Dict[str, Any]] = []
        for f in list_findings(ws.task_id, status="candidate"):
            if "api_endpoint:" not in str(f.get("title") or ""):
                continue
            vr = verify_finding(
                ws.task_id,
                str(f.get("finding_id")),
                executor=executor,
                reproduce_cmd=f.get("reproduce_cmd"),
                expected_signal=f.get("expected_signal"),
                phase="VERIFY",
            )
            auto_verified.append(
                {
                    "finding_id": f.get("finding_id"),
                    "title": f.get("title"),
                    "status": vr.get("status"),
                    "ok": vr.get("ok"),
                }
            )

        # clear verify queue on resolved path nodes
        remaining = {
            str(f.get("target") or "").rstrip("/")
            for f in list_findings(ws.task_id, status="candidate")
            if "api_endpoint:" in str(f.get("title") or "")
        }
        for node in list(graph.nodes.values()):
            if node.type != "path":
                continue
            nv = (node.value or "").rstrip("/")
            if "verify_finding" in (node.next_checks or []) and nv not in remaining:
                node.next_checks = [
                    c for c in node.next_checks if c != "verify_finding"
                ]
                node.meta["last_tool"] = "api_surface"
        graph.save()

        handoff = compile_handoff(ws.task_id)
        ws.update_meta(phase="EVIDENCE", status="playbook_done")
        findings = list_findings(ws.task_id)
        report_path = ""
        try:
            import json as _json

            payload = {
                "task_id": ws.task_id,
                "playbook": "api_surface",
                "target": base,
                "depth": d,
                "hits": hits,
                "steps": steps,
                "auto_verified": auto_verified,
                "findings": findings,
                "graph_summary": graph.summary(),
                "handoff_json": handoff.get("handoff_json"),
            }
            report_path = str(ws.report_dir / "api_surface_summary.json")
            (ws.report_dir / "api_surface_summary.json").write_text(
                _json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            report_path = ""

        return {
            "ok": True,
            "playbook": "api_surface",
            "task_id": ws.task_id,
            "target": base,
            "depth": d,
            "hits": hits,
            "steps": steps,
            "auto_verified": auto_verified,
            "findings": findings,
            "findings_total": len(findings),
            "graph_summary": graph.summary(),
            "next_actions": graph.next_actions(limit=15),
            "handoff_json": handoff.get("handoff_json"),
            "progress_md": handoff.get("progress_md"),
            "report_path": report_path,
        }
    finally:
        clear_active_task()
