#!/usr/bin/env python3
"""web_surface playbook: probe -> fingerprint -> shallow dir -> nuclei subset."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from kali_mcp.core.action_log import log_action
from kali_mcp.core.evidence_store import save_evidence
from kali_mcp.core.findings_store import list_findings
from kali_mcp.core.target_graph import get_graph
from kali_mcp.core.task_workspace import get_workspace
from kali_mcp.core.verifier import register_candidate

DEPTH_PROFILE = {
    "quick": {
        "httpx": True,
        "whatweb": True,
        "gobuster": False,
        "nuclei": True,
        "nuclei_severity": "critical,high",
    },
    "standard": {
        "httpx": True,
        "whatweb": True,
        "gobuster": True,
        "nuclei": True,
        "nuclei_severity": "critical,high",
    },
    "thorough": {
        "httpx": True,
        "whatweb": True,
        "gobuster": True,
        "nuclei": True,
        "nuclei_severity": "critical,high,medium",
    },
}


def _normalize_url(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        return f"http://{t}"
    return t


def _extract_gobuster_paths(raw: str, base_url: str) -> List[str]:
    """Parse gobuster-style lines into path/URL list."""
    import re

    paths: List[str] = []
    base = (base_url or "").rstrip("/")
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("=") or "Progress:" in line:
            continue
        # Status: 200 - /admin/  or  /admin (Status: 200)
        m = re.search(r"(/[^\s]*)\s*\(Status:\s*(\d{3})\)", line, re.I)
        if not m:
            m2 = re.search(r"Status:\s*(\d{3}).*?(/[^\s]*)", line, re.I)
            if m2:
                code, path = m2.group(1), m2.group(2)
            else:
                continue
        else:
            path, code = m.group(1), m.group(2)
        if code.startswith(("4", "5")) and code not in {"401", "403"}:
            continue
        full = path if path.startswith("http") else f"{base}{path}"
        if full not in paths:
            paths.append(full)
    return paths[:100]


def _run_tool(executor, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
    # nuclei 无模板目录时会挂死等下载：主路径统一先探测模板，缺失则跳过
    if tool_name == "nuclei":
        # nuclei -version 首次运行会慢(配置初始化)，直接检查模板目录存在性
        probe_cmd = ("(test -d ~/nuclei-templates -o -d /root/nuclei-templates -o -d /home/zss/nuclei-templates "
                     "-o -d ~/.local/nuclei-templates -o -d /home/zss/.local/nuclei-templates"
                     ") && echo HAS_TMPL || echo NO_TMPL")
        if hasattr(executor, "_run_tool_command"):
            probe = executor._run_tool_command(probe_cmd, timeout=15)
        elif hasattr(executor, "execute_command"):
            probe = executor.execute_command(probe_cmd, timeout=15)
        else:
            probe = {"output": ""}
        if "HAS_TMPL" not in (probe.get("output") or ""):
            return {
                "success": True,
                "output": "[nuclei skipped: no templates installed; run 'nuclei -update-templates' on the backend]",
                "error": "",
                "return_code": 0,
                "skipped": "no_nuclei_templates",
            }
        # 全模板扫描对单目标过慢（>55s）：默认限定常用模板子集
        if not data.get("templates") and not data.get("templates_suffix"):
            base = "/home/zss/.local/nuclei-templates"
            data = dict(data)
            data["templates_suffix"] = (
                f" -t {base}/http/misconfiguration/,"
                f"{base}/http/exposures/,"
                f"{base}/http/technologies/"
            )
    if hasattr(executor, "execute_tool_with_data"):
        return executor.execute_tool_with_data(tool_name, data)
    # fallback: build simple commands for dry environments
    target = data.get("target") or data.get("url") or ""
    if tool_name == "httpx":
        # fallback only when execute_tool_with_data unavailable
        from kali_mcp.core.tool_registry import build_command

        built = build_command("fastsec", {"fingerprint": target.split("//")[-1].split("/")[0]})
        cmd = built or f"fastsec -fingerprint {target.split('//')[-1].split('/')[0]}"
    elif tool_name == "whatweb":
        # fastsec fingerprint/cms 替代 whatweb -a 1
        host = target.split("//")[-1].split("/")[0]
        cmd = f"fastsec -cms {target} -delay-min 10 -delay-max 30"
    elif tool_name == "gobuster":
        # fastsec -dir 替代 gobuster dir（自动加载 data/dir 4707 字典）
        cmd = f"fastsec -dir {target} -delay-min 10 -delay-max 30"
    elif tool_name == "nuclei":
        # fastsec -d 模板目录 替代 nuclei（3-gate 零误报确认）
        sev = data.get("severity", "critical,high")
        tpl_dir = data.get("templates_dir", "~/nuclei-templates")
        cmd = f"fastsec -u {target} -d {tpl_dir} -delay-min 10 -delay-max 30"
    else:
        return {"success": False, "error": f"unsupported tool {tool_name}", "output": "", "return_code": -1}
    return executor.execute_command(cmd)


def run_web_surface(
    task_id: str,
    target: str,
    executor: Any,
    depth: str = "standard",
    **kwargs: Any,
) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    url = _normalize_url(target)
    if not url:
        return {"ok": False, "error": "target required"}

    profile = DEPTH_PROFILE.get((depth or "standard").lower(), DEPTH_PROFILE["standard"])
    graph = get_graph(ws.task_id)
    host = urlparse(url).hostname or url
    graph.upsert_node("host", host, confidence=0.9, next_checks=["http_probe"])
    graph.upsert_node(
        "url",
        url,
        confidence=0.9,
        next_checks=["fingerprint", "shallow_dir", "nuclei_subset"],
        meta={"playbook": "web_surface"},
    )
    graph.save()
    ws.update_meta(phase="RECON", status="running", depth=depth, targets=list(dict.fromkeys((ws.read_meta().get("targets") or []) + [url])))

    steps: List[Dict[str, Any]] = []
    candidates_before = {f["finding_id"] for f in list_findings(ws.task_id)}

    from kali_mcp.core.task_context import clear_active_task, set_active_task

    set_active_task(ws.task_id)
    try:
        return _run_web_surface_body(
            ws=ws,
            url=url,
            host=host,
            graph=graph,
            profile=profile,
            executor=executor,
            depth=depth,
            kwargs=kwargs,
            steps=steps,
            candidates_before=candidates_before,
        )
    finally:
        clear_active_task()


def _run_web_surface_body(
    *,
    ws,
    url: str,
    host: str,
    graph,
    profile: Dict[str, Any],
    executor: Any,
    depth: str,
    kwargs: Dict[str, Any],
    steps: List[Dict[str, Any]],
    candidates_before: set,
) -> Dict[str, Any]:
    def _step(tool: str, data: Dict[str, Any], phase: str) -> Dict[str, Any]:
        start = time.time()
        payload = dict(data)
        payload.setdefault("task_id", ws.task_id)
        payload.setdefault("phase", phase)
        result = _run_tool(executor, tool, payload)
        duration_ms = round((time.time() - start) * 1000, 2)
        err_part = result.get("error") or ""
        raw = (result.get("output") or "") + (("\n" + err_part) if err_part else "")
        evidence_path = result.get("evidence_path")
        if not evidence_path:
            evidence = save_evidence(
                ws.task_id,
                name=f"web_surface_{tool}",
                content=raw,
                meta={"tool": tool, "data": data, "return_code": result.get("return_code")},
            )
            evidence_path = evidence["path"]
        parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {
            "tool_name": tool,
            "success": bool(result.get("success")),
            "summary": (result.get("output") or "")[:300],
            "structured_data": {},
            "confidence": 0.5 if result.get("success") else 0.2,
            "severity": "info",
        }
        if not isinstance(parsed, dict):
            parsed = {
                "tool_name": tool,
                "success": bool(result.get("success")),
                "summary": str(parsed)[:300],
                "structured_data": {},
                "confidence": 0.2,
                "severity": "info",
            }
        # gobuster path extraction fallback when parser is thin
        if tool == "gobuster" and result.get("success"):
            paths = _extract_gobuster_paths(raw, url)
            if paths:
                sd = dict(parsed.get("structured_data") or {})
                sd["paths"] = paths
                parsed["structured_data"] = sd
        ingest = result.get("graph_ingest")
        if not isinstance(ingest, dict):
            ingest = graph.ingest_parsed(tool, parsed, target=url, evidence_path=evidence_path)
        # ensure action log even if executor hook already logged (source playbook)
        log_action(
            ws.task_id,
            phase=phase,
            target=url,
            tool=tool,
            args=data,
            exit_code=result.get("return_code"),
            duration_ms=duration_ms,
            evidence_path=str(evidence_path),
            source="playbook",
            extra={"playbook": "web_surface"},
        )
        step = {
            "tool": tool,
            "success": bool(result.get("success")),
            "duration_ms": duration_ms,
            "evidence_path": evidence_path,
            "summary": (parsed.get("summary") or "")[:300],
            "graph_nodes_touched": (ingest or {}).get("nodes_touched", 0),
        }
        steps.append(step)
        return step

    # 1) live / http probe — httpx 在 Kali 上可能是 Python CLI (无 -u)，统一用 curl 探测
    if profile.get("httpx"):
        _step("curl", {"url": url, "target": url, "headers": {"User-Agent": "kali-mcp-probe"}, "timeout": 8}, "RECON")
    else:
        _step("whatweb", {"target": url, "url": url}, "RECON")

    ws.update_meta(phase="FINGERPRINT")
    # 2) fingerprint
    if profile.get("whatweb"):
        _step("whatweb", {"target": url, "url": url}, "FINGERPRINT")

    # 3) shallow dir
    if profile.get("gobuster"):
        ws.update_meta(phase="RECON")
        _step(
            "gobuster",
            {
                "target": url,
                "url": url,
                "wordlist": kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                "threads": kwargs.get("threads", 20),
            },
            "RECON",
        )

    # 4) nuclei subset
    if profile.get("nuclei"):
        ws.update_meta(phase="VERIFY")
        nuclei_step = _step(
            "nuclei",
            {
                "target": url,
                "url": url,
                "severity": profile.get("nuclei_severity", "critical,high"),
            },
            "VERIFY",
        )
        # if nuclei text mentions [critical]/[high] without structured findings, create candidate
        if nuclei_step.get("success") and nuclei_step.get("summary"):
            text = nuclei_step["summary"]
            if "[" in text and "]" in text:
                register_candidate(
                    ws.task_id,
                    title=f"nuclei_hit:{url}",
                    target=url,
                    severity="high",
                    reproduce_cmd=f"nuclei -u {url} -severity {profile.get('nuclei_severity', 'critical,high')} -silent",
                    expected_signal="[",
                    source="playbook",
                    technique_ids=["T1190"],
                    evidence_paths=[nuclei_step.get("evidence_path") or ""],
                    meta={"playbook": "web_surface"},
                )

    # clear satisfied next_checks after playbook steps; leave verify queue only
    # compare with normalized values — graph stores trailing-slash-collapsed urls/paths
    from kali_mcp.core.target_graph import _normalize_node_value

    url_key = _normalize_node_value("url", url)
    host_key = (host or "").strip().lower()
    has_candidates = any(f.get("status") == "candidate" for f in list_findings(ws.task_id))
    for node in graph.nodes.values():
        node.meta["last_tool"] = node.meta.get("last_tool") or "web_surface"
        if node.type == "url" and _normalize_node_value("url", node.value) == url_key:
            node.next_checks = ["verify_candidates"] if has_candidates else []
        elif node.type == "host" and (node.value or "").strip().lower() == host_key:
            node.next_checks = []
        elif node.type == "path":
            node.next_checks = ["verify_finding"] if has_candidates and any(
                k in (node.value or "").lower() for k in ("/admin", "/api", "/backup", "/.git")
            ) else []
        elif node.type == "tech":
            node.next_checks = []
    graph.save()

    # interesting paths as candidates (admin/api style) — upsert dedupes by title+target
    for node in list(graph.nodes.values()):
        if node.type != "path":
            continue
        val = (node.value or "").lower()
        if any(k in val for k in ("/admin", "/api", "/backup", "/.git", "/config", "/console")):
            path_url = node.value
            # directory-style targets need trailing slash for SimpleHTTP/many servers
            if path_url.rstrip("/").endswith(("/admin", "/api", "/console", "/backup")) and not path_url.endswith("/"):
                path_url = path_url + "/"
            register_candidate(
                ws.task_id,
                title=f"interesting_path:{node.value}",
                target=path_url,
                severity="medium",
                reproduce_cmd=f'curl -s --noproxy "*" -L "{path_url}"',
                expected_signal="re:(?i)(200|admin|api|flag|status|ok|html)",
                source="playbook",
                technique_ids=["T1595"],
                evidence_paths=list(node.evidence_paths or []),
                meta={"playbook": "web_surface", "path": node.value},
            )

    # auto-verify high-value candidates (status 200 style signals)
    from kali_mcp.core.verifier import verify_finding as _verify

    auto_verified: List[Dict[str, Any]] = []
    for f in list_findings(ws.task_id, status="candidate"):
        title = str(f.get("title") or "")
        target_f = str(f.get("target") or "")
        high = any(k in (title + target_f).lower() for k in ("/admin", "/api", "admin_panel", "/.git", "/console"))
        if not high:
            continue
        if not f.get("reproduce_cmd"):
            continue
        try:
            vr = _verify(
                ws.task_id,
                str(f.get("finding_id")),
                executor=executor,
                reproduce_cmd=f.get("reproduce_cmd"),
                expected_signal=f.get("expected_signal") or "200",
                phase="VERIFY",
            )
            auto_verified.append(
                {
                    "finding_id": f.get("finding_id"),
                    "title": title,
                    "status": vr.get("status"),
                    "ok": vr.get("ok"),
                }
            )
        except Exception as exc:
            auto_verified.append(
                {"finding_id": f.get("finding_id"), "title": title, "status": "error", "ok": False, "error": str(exc)[:120]}
            )

    # refresh next_checks after auto verify
    remaining = [x for x in list_findings(ws.task_id) if x.get("status") == "candidate"]
    for node in graph.nodes.values():
        if node.type == "url" and _normalize_node_value("url", node.value) == url_key:
            node.next_checks = ["verify_candidates"] if remaining else []
        elif node.type == "path":
            nv = _normalize_node_value("path", node.value)
            still = any(
                nv
                and nv in _normalize_node_value("path", str(f.get("target") or ""))
                and f.get("status") == "candidate"
                for f in remaining
            ) or any(
                (node.value or "") in str(f.get("target") or "") and f.get("status") == "candidate"
                for f in remaining
            )
            node.next_checks = ["verify_finding"] if still else []
    graph.save()

    findings = list_findings(ws.task_id)
    new_findings = [f for f in findings if f.get("finding_id") not in candidates_before]
    from kali_mcp.core.handoff import compile_handoff

    handoff = compile_handoff(ws.task_id)
    ws.update_meta(phase="EVIDENCE", status="playbook_done")

    report_path = ""
    try:
        import json as _json

        summary_payload = {
            "task_id": ws.task_id,
            "playbook": "web_surface",
            "target": url,
            "depth": depth,
            "meta": ws.read_meta(),
            "graph_summary": graph.summary(),
            "findings": findings,
            "auto_verified": auto_verified,
            "steps": steps,
            "next_actions": graph.next_actions(limit=15),
            "handoff_json": handoff.get("handoff_json"),
            "progress_md": handoff.get("progress_md"),
        }
        report_path = str(ws.report_dir / "summary.json")
        (ws.report_dir / "summary.json").write_text(
            _json.dumps(summary_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        report_path = ""

    return {
        "ok": True,
        "playbook": "web_surface",
        "task_id": ws.task_id,
        "target": url,
        "depth": depth,
        "steps": steps,
        "graph_summary": graph.summary(),
        "findings_total": len(findings),
        "findings_new": len(new_findings),
        "findings": findings,
        "auto_verified": auto_verified,
        "next_actions": graph.next_actions(limit=15),
        "handoff_json": handoff.get("handoff_json"),
        "progress_md": handoff.get("progress_md"),
        "report_path": report_path,
    }
