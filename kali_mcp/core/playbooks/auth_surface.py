#!/usr/bin/env python3
"""auth_surface: discover login-like entrypoints; register + auto-verify."""

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

AUTH_PATHS = [
    "/login",
    "/admin/login",
    "/user/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/wp-login.php",
    "/admin",
    "/console",
    "/oauth/authorize",
    "/sso/login",
]


def _unique_paths(paths: List[str]) -> List[str]:
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


def _looks_like_login(body: str) -> bool:
    low = (body or "").lower()
    if len(low.strip()) < 20:
        return False
    has_password = any(
        k in low
        for k in (
            "password",
            'type="password"',
            "type='password'",
            'name="password"',
            "name='password'",
            "密码",
        )
    )
    has_login_ctx = any(
        k in low
        for k in (
            "login",
            "signin",
            "sign in",
            "username",
            "user name",
            "csrf",
            "otp",
            "用户名",
            "登录",
            "验证码",
        )
    )
    return has_password and has_login_ctx


def run_auth_surface(
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
            meta={"playbook": "auth_surface"},
            source="playbook",
        )
        graph.save()
        ws.update_meta(phase="RECON", status="running")

        paths = list(AUTH_PATHS)
        d = (depth or "standard").lower()
        if d == "quick":
            paths = paths[:8]
        elif d == "thorough":
            paths = paths + ["/portal/login", "/manage/login", "/backend/login"]
        paths = _unique_paths(paths)

        hits: List[Dict[str, Any]] = []
        steps: List[Dict[str, Any]] = []
        for path in paths:
            # probe canonical path only (no /login + /login/ double hit)
            full = urljoin(base + "/", path.lstrip("/"))
            start = time.time()
            result = executor.execute_command(
                f'curl -sS --noproxy "*" -L -w "\\n__HTTP_CODE__:%{{http_code}}" "{full}"'
            )
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
                name=f"auth_probe_{path.replace('/', '_') or 'root'}",
                content=f"status={code}\nurl={full}\n{body[:4000]}",
                meta={"path": path, "status": code, "url": full},
            )
            log_action(
                ws.task_id,
                phase="RECON",
                target=full,
                tool="curl_auth_probe",
                args={"path": path},
                exit_code=result.get("return_code"),
                duration_ms=duration_ms,
                evidence_path=evidence["path"],
                source="playbook",
                extra={"playbook": "auth_surface", "status": code},
            )
            hit = _looks_like_login(body) and code in {
                "200",
                "201",
                "401",
                "403",
                "301",
                "302",
            }
            steps.append(
                {
                    "path": path,
                    "url": full,
                    "status": code,
                    "duration_ms": duration_ms,
                    "hit": hit,
                    "success": bool(result.get("success")),
                }
            )
            if not hit:
                continue
            graph.upsert_node(
                "path",
                full,
                confidence=0.7,
                evidence_path=evidence["path"],
                next_checks=["verify_finding"],
                meta={"status": code, "playbook": "auth_surface"},
                source="playbook",
            )
            hits.append({"url": full, "status": code})
            register_candidate(
                ws.task_id,
                title=f"auth_entry:{full}",
                target=full,
                severity="medium",
                reproduce_cmd=f'curl -sS --noproxy "*" -L "{full}"',
                expected_signal="re:(?i)(password|username|login|sign.?in|csrf|密码|用户名|登录)",
                source="playbook",
                technique_ids=["T1078"],
                evidence_paths=[evidence["path"]],
                meta={"status": code, "playbook": "auth_surface"},
            )

        graph.save()

        auto_verified: List[Dict[str, Any]] = []
        for f in list_findings(ws.task_id, status="candidate"):
            if "auth_entry:" not in str(f.get("title") or ""):
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

        remaining = {
            str(f.get("target") or "").rstrip("/")
            for f in list_findings(ws.task_id, status="candidate")
            if "auth_entry:" in str(f.get("title") or "")
        }
        for node in list(graph.nodes.values()):
            if node.type != "path":
                continue
            nv = (node.value or "").rstrip("/")
            if "verify_finding" in (node.next_checks or []) and nv not in remaining:
                node.next_checks = [
                    c for c in node.next_checks if c != "verify_finding"
                ]
                node.meta["last_tool"] = "auth_surface"
        graph.save()

        handoff = compile_handoff(ws.task_id)
        ws.update_meta(phase="EVIDENCE", status="playbook_done")
        findings = list_findings(ws.task_id)
        report_path = ""
        try:
            import json as _json

            payload = {
                "task_id": ws.task_id,
                "playbook": "auth_surface",
                "target": base,
                "depth": d,
                "hits": hits,
                "steps": steps,
                "auto_verified": auto_verified,
                "findings": findings,
                "graph_summary": graph.summary(),
                "handoff_json": handoff.get("handoff_json"),
            }
            report_path = str(ws.report_dir / "auth_surface_summary.json")
            (ws.report_dir / "auth_surface_summary.json").write_text(
                _json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            report_path = ""

        return {
            "ok": True,
            "playbook": "auth_surface",
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
