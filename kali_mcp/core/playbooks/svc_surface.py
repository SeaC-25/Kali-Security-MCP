#!/usr/bin/env python3
"""svc_surface: host port/service fingerprint via nmap; register open ports."""

from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import urlparse

from kali_mcp.core.action_log import log_action
from kali_mcp.core.evidence_store import save_evidence
from kali_mcp.core.findings_store import list_findings
from kali_mcp.core.handoff import compile_handoff
from kali_mcp.core.target_graph import get_graph
from kali_mcp.core.task_context import clear_active_task, set_active_task
from kali_mcp.core.task_workspace import get_workspace
from kali_mcp.core.verifier import register_candidate, verify_finding


def _host_from_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return urlparse(t).hostname or ""
    return t.split("/")[0].split(":")[0]


def run_svc_surface(
    task_id: str,
    target: str,
    executor: Any,
    depth: str = "standard",
    **kwargs: Any,
) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    host = _host_from_target(target)
    if not host:
        return {"ok": False, "error": "host/target required"}

    set_active_task(ws.task_id)
    try:
        graph = get_graph(ws.task_id)
        graph.upsert_node(
            "host",
            host,
            confidence=0.9,
            next_checks=["service_fingerprint"],
            meta={"playbook": "svc_surface"},
            source="playbook",
        )
        graph.save()
        ws.update_meta(phase="RECON", status="running")

        d = (depth or "standard").lower()
        if d == "quick":
            ports = "22,80,443,8080,8443,3306,6379"
            scan_type = "-sV -T4 --open"
        elif d == "thorough":
            ports = "1-10000"
            scan_type = "-sV -sC -T4 --open"
        else:
            ports = (
                "21,22,23,25,53,80,110,135,139,143,443,445,993,995,"
                "1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017"
            )
            scan_type = "-sV -T4 --open"

        data = {
            "target": host,
            "ports": ports,
            "scan_type": scan_type,
            "task_id": ws.task_id,
            "phase": "RECON",
        }
        start = time.time()
        if hasattr(executor, "execute_tool_with_data"):
            result = executor.execute_tool_with_data("nmap", data)
        else:
            result = executor.execute_command(f"nmap {scan_type} -p {ports} {host}")
        duration_ms = round((time.time() - start) * 1000, 2)
        err = result.get("error") or ""
        raw = (result.get("output") or "") + (("\n" + err) if err else "")
        evidence = save_evidence(
            ws.task_id,
            name="svc_nmap",
            content=raw,
            meta={
                "host": host,
                "ports": ports,
                "return_code": result.get("return_code"),
            },
        )
        parsed = (
            result.get("parsed")
            if isinstance(result.get("parsed"), dict)
            else {
                "tool_name": "nmap",
                "success": bool(result.get("success")),
                "summary": (result.get("output") or "")[:300],
                "structured_data": {},
                "confidence": 0.6 if result.get("success") else 0.2,
                "severity": "info",
            }
        )
        ingest = result.get("graph_ingest")
        if not isinstance(ingest, dict):
            ingest = graph.ingest_parsed(
                "nmap",
                parsed,
                target=host,
                evidence_path=evidence["path"],
            )
        log_action(
            ws.task_id,
            phase="RECON",
            target=host,
            tool="nmap",
            args=data,
            exit_code=result.get("return_code"),
            duration_ms=duration_ms,
            evidence_path=evidence["path"],
            source="playbook",
            extra={"playbook": "svc_surface"},
        )

        open_ports: List[Dict[str, str]] = []
        ports_data = (parsed.get("structured_data") or {}).get("ports") or []
        for item in ports_data[:40]:
            if isinstance(item, dict):
                port = str(item.get("port") or item.get("number") or "")
                service = str(item.get("service") or item.get("name") or "")
            else:
                port, service = str(item), ""
            if not port:
                continue
            open_ports.append({"port": port, "service": service or "unknown"})
            register_candidate(
                ws.task_id,
                title=f"open_port:{host}:{port}/{service or 'unknown'}",
                target=f"{host}:{port}",
                severity="info",
                reproduce_cmd=f"nmap -sV -p {port} {host}",
                expected_signal=port,
                source="playbook",
                technique_ids=["T1046"],
                evidence_paths=[evidence["path"]],
                meta={"playbook": "svc_surface", "service": service},
            )

        # if parser thin, fallback parse open lines from raw nmap text
        if not open_ports and result.get("success"):
            import re

            for line in raw.splitlines():
                m = re.search(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line.strip())
                if not m:
                    continue
                port, _proto, service = m.group(1), m.group(2), m.group(3)
                open_ports.append({"port": port, "service": service})
                register_candidate(
                    ws.task_id,
                    title=f"open_port:{host}:{port}/{service}",
                    target=f"{host}:{port}",
                    severity="info",
                    reproduce_cmd=f"nmap -sV -p {port} {host}",
                    expected_signal=port,
                    source="playbook",
                    technique_ids=["T1046"],
                    evidence_paths=[evidence["path"]],
                    meta={"playbook": "svc_surface", "service": service},
                )

        for node in list(graph.nodes.values()):
            if node.type == "host" and node.value == host:
                node.next_checks = []
                node.meta["last_tool"] = "nmap"
            if node.type in {"port", "service"} and str(node.value or "").startswith(host):
                node.next_checks = []
                node.meta["last_tool"] = "nmap"
                node.meta["fingerprinted"] = True
        graph.save()

        auto_verified: List[Dict[str, Any]] = []
        for f in list_findings(ws.task_id, status="candidate"):
            if not str(f.get("title") or "").startswith("open_port:"):
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

        handoff = compile_handoff(ws.task_id)
        ws.update_meta(phase="FINGERPRINT", status="playbook_done")
        findings = list_findings(ws.task_id)
        report_path = ""
        try:
            import json as _json

            payload = {
                "task_id": ws.task_id,
                "playbook": "svc_surface",
                "target": host,
                "depth": d,
                "open_ports": open_ports,
                "duration_ms": duration_ms,
                "summary": (parsed.get("summary") or "")[:300],
                "auto_verified": auto_verified,
                "findings": findings,
                "graph_summary": graph.summary(),
                "handoff_json": handoff.get("handoff_json"),
            }
            report_path = str(ws.report_dir / "svc_surface_summary.json")
            (ws.report_dir / "svc_surface_summary.json").write_text(
                _json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            report_path = ""

        return {
            "ok": True,
            "playbook": "svc_surface",
            "task_id": ws.task_id,
            "target": host,
            "depth": d,
            "duration_ms": duration_ms,
            "summary": (parsed.get("summary") or "")[:300],
            "open_ports": open_ports,
            "graph_nodes_touched": (ingest or {}).get("nodes_touched", 0),
            "evidence_path": evidence["path"],
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
