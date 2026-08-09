#!/usr/bin/env python3
"""Finding verifier: candidate must pass replay signal to become verified."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional

from kali_mcp.core.action_log import log_action
from kali_mcp.core.evidence_store import save_evidence
from kali_mcp.core.findings_store import get_finding, set_status, upsert_finding
from kali_mcp.core.target_graph import get_graph


def _match_signal(text: str, expected_signal: str) -> bool:
    signal = (expected_signal or "").strip()
    if not signal:
        # no signal => treat non-empty successful output as weak pass only if caller sets allow_empty_signal
        return False
    body = text or ""
    if signal.startswith("re:"):
        try:
            return re.search(signal[3:], body, re.IGNORECASE | re.MULTILINE) is not None
        except re.error:
            return signal[3:] in body
    if signal.startswith("status:"):
        # e.g. status:200
        return signal.split(":", 1)[-1].strip() in body
    return signal.lower() in body.lower()


def verify_finding(
    task_id: str,
    finding_id: str,
    executor: Any = None,
    *,
    reproduce_cmd: Optional[str] = None,
    expected_signal: Optional[str] = None,
    phase: str = "VERIFY",
) -> Dict[str, Any]:
    """
    Replay minimal command and gate status.

    If executor is None and no command can run, status becomes blocked with reason.
    """
    item = get_finding(task_id, finding_id)
    if not item:
        return {"ok": False, "error": f"finding not found: {finding_id}"}

    cmd = (reproduce_cmd or item.get("reproduce_cmd") or "").strip()
    signal = (expected_signal if expected_signal is not None else item.get("expected_signal") or "").strip()
    target = str(item.get("target") or item.get("asset") or "")

    if not cmd:
        updated = set_status(
            task_id,
            finding_id,
            "blocked",
            block_reason="missing reproduce_cmd",
        )
        return {"ok": False, "status": "blocked", "finding": updated, "error": "missing reproduce_cmd"}

    if executor is None:
        updated = set_status(
            task_id,
            finding_id,
            "blocked",
            block_reason="no executor",
            reproduce_cmd=cmd,
            expected_signal=signal,
        )
        return {"ok": False, "status": "blocked", "finding": updated, "error": "no executor provided"}

    start = time.time()
    try:
        result = executor.execute_command(cmd)
    except Exception as exc:
        result = {"success": False, "output": "", "error": str(exc), "return_code": -1, "command": cmd}
    duration_ms = round((time.time() - start) * 1000, 2)

    raw = (result.get("output") or "") + "\n" + (result.get("error") or "")
    evidence = save_evidence(
        task_id,
        name=f"verify_{finding_id}",
        content=raw,
        meta={
            "finding_id": finding_id,
            "command": cmd,
            "expected_signal": signal,
            "return_code": result.get("return_code"),
            "success": result.get("success"),
        },
    )

    matched = _match_signal(raw, signal) if signal else bool(result.get("success") and (result.get("output") or "").strip())
    if matched:
        status = "verified"
    elif result.get("success") is False and not matched:
        status = "false_positive" if signal else "blocked"
    else:
        status = "false_positive"

    paths = list(item.get("evidence_paths") or [])
    if evidence["path"] not in paths:
        paths.append(evidence["path"])

    updated = set_status(
        task_id,
        finding_id,
        status,
        reproduce_cmd=cmd,
        expected_signal=signal,
        evidence_paths=paths,
        last_verify={
            "matched": matched,
            "return_code": result.get("return_code"),
            "duration_ms": duration_ms,
            "evidence_path": evidence["path"],
        },
    )

    log_action(
        task_id,
        phase=phase,
        target=target,
        tool="verify_finding",
        args={"finding_id": finding_id, "cmd": cmd, "signal": signal},
        exit_code=result.get("return_code"),
        duration_ms=duration_ms,
        evidence_path=evidence["path"],
        finding_ids=[finding_id],
        source="verify",
        extra={"status": status, "matched": matched},
    )

    # reflect on graph: finding nodes + path/url nodes bound to this target
    try:
        graph = get_graph(task_id)
        title = str(item.get("title") or "")
        target_norm = (target or "").rstrip("/")
        changed = False
        for node in list(graph.nodes.values()):
            bound = False
            if node.type == "finding" and (
                node.id == finding_id or node.value == title or node.meta.get("finding_id") == finding_id
            ):
                bound = True
            elif node.type in {"path", "url"} and target_norm:
                nv = (node.value or "").rstrip("/")
                if nv == target_norm or node.meta.get("finding_id") == finding_id:
                    bound = True
                # title embeds url: auth_entry:http://...
                elif title.endswith(node.value or "") or (node.value and node.value in title):
                    bound = True
            if not bound:
                continue
            changed = True
            node.meta["status"] = status
            if evidence["path"] not in node.evidence_paths:
                node.evidence_paths.append(evidence["path"])
            if status in {"false_positive", "blocked"}:
                node.dead_reason = status
                node.next_checks = []
            elif status == "verified":
                node.dead_reason = None
                node.next_checks = [c for c in node.next_checks if c not in {"verify_finding", "verify_candidates"}]
        if changed:
            graph.save()
    except Exception:
        pass

    return {
        "ok": status == "verified",
        "status": status,
        "matched": matched,
        "finding": updated,
        "evidence_path": evidence["path"],
        "duration_ms": duration_ms,
    }


def register_candidate(
    task_id: str,
    *,
    title: str,
    target: str = "",
    severity: str = "info",
    reproduce_cmd: str = "",
    expected_signal: str = "",
    source: str = "scan",
    technique_ids: Optional[list] = None,
    evidence_paths: Optional[list] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finding = {
        "title": title,
        "target": target,
        "severity": severity,
        "status": "candidate",
        "reproduce_cmd": reproduce_cmd,
        "expected_signal": expected_signal,
        "source": source,
        "technique_ids": list(technique_ids or []),
        "evidence_paths": list(evidence_paths or []),
        "meta": meta or {},
    }
    return upsert_finding(task_id, finding)
