#!/usr/bin/env python3
"""Lab e2e acceptance checklist (machine-readable).

Checks lab reachability, optional pytest, runs surface chain (or dry steps),
and writes JSON under doc/lab-acceptance/.

Forbidden: task_id == rpt_probe (and similar probe aliases).
Does NOT reintroduce run_goal or drive_executor.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_LAB = os.environ.get("LAB_URL", "http://127.0.0.1:18081/")
# Shared non-delivery rules (single source of truth, also used by the isolation tool).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from non_delivery_rules import NON_DELIVERY_EXACT, is_non_delivery  # noqa: E402

ACCEPT_DIR = ROOT / "doc" / "lab-acceptance"


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _clear_proxy_env() -> None:
    for k in (
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
    ):
        os.environ.pop(k, None)
    os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
    os.environ.setdefault("no_proxy", "127.0.0.1,localhost")


def check_lab(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """HTTP GET lab root; also try common paths used by acceptance."""
    paths = ["/", "/login", "/admin", "/api/health", "/console"]
    base = url.rstrip("/")
    checks: Dict[str, Any] = {}
    ok_all = True
    err: Optional[str] = None
    for p in paths:
        full = base + p if p != "/" else base + "/"
        try:
            req = urllib.request.Request(full, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = int(getattr(resp, "status", 0) or resp.getcode())
            checks[p] = code
            if code >= 400:
                ok_all = False
        except Exception as e:  # noqa: BLE001 — surface as checklist field
            checks[p] = None
            ok_all = False
            err = str(e)[:200]
    # TCP port listen hint
    listen = False
    try:
        u = urlparse(url if "://" in url else f"http://{url}")
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout):
            listen = True
    except OSError:
        listen = False
        ok_all = False
    return {
        "ok": ok_all and listen,
        "url": url,
        "listen": listen,
        "checks": checks,
        "error": err,
    }


def ensure_lab(url: str) -> Dict[str, Any]:
    """If lab not up, try start_lab.sh once (Unix)."""
    probe = check_lab(url)
    if probe.get("ok"):
        return {"started": False, "probe": probe}
    start_sh = ROOT / "utils" / "lab" / "start_lab.sh"
    if not start_sh.is_file() or os.name == "nt":
        return {"started": False, "probe": probe, "note": "lab down; start_lab skipped on this host"}
    try:
        subprocess.run(
            ["bash", str(start_sh)],
            cwd=str(start_sh.parent),
            check=False,
            timeout=30,
            capture_output=True,
            text=True,
        )
        time.sleep(0.8)
    except Exception as e:  # noqa: BLE001
        return {"started": False, "probe": probe, "start_error": str(e)[:200]}
    probe2 = check_lab(url)
    return {"started": True, "probe": probe2}


def validate_task_id(task_id: str) -> Optional[str]:
    tid = (task_id or "").strip()
    if not tid:
        return "empty task_id"
    if is_non_delivery(tid):
        return f"forbidden task_id={tid!r} (do not use probe/debug ids for acceptance)"
    return None


def run_pytest_harness(run: bool) -> Dict[str, Any]:
    cmd = [sys.executable, "-m", "pytest", "tests/test_p0_harness.py", "-q"]
    if not run:
        return {
            "ran": False,
            "command": " ".join(cmd),
            "hint": "pass --pytest to execute",
        }
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        p = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        out = (p.stdout or "") + (p.stderr or "")
        return {
            "ran": True,
            "command": " ".join(cmd),
            "exit_code": p.returncode,
            "ok": p.returncode == 0,
            "tail": out[-2000:],
        }
    except Exception as e:  # noqa: BLE001
        return {"ran": True, "ok": False, "error": str(e)[:300], "command": " ".join(cmd)}


def run_chain(task_id: str, target: str, depth: str = "mixed") -> Dict[str, Any]:
    from kali_mcp.core.local_executor import LocalCommandExecutor
    from kali_mcp.core.handoff import continue_from_handoff
    from kali_mcp.core.playbooks import run_surface_chain
    from kali_mcp.core.task_workspace import TaskWorkspace

    ex = LocalCommandExecutor(timeout=180)
    summary = run_surface_chain(
        task_id=task_id,
        target=target,
        executor=ex,
        depth=depth,
        seed_task=True,
    )
    ws = TaskWorkspace(task_id)
    meta_before = dict(ws.read_meta() or {})
    cont = continue_from_handoff(task_id, update_status=True)
    meta_after = dict(ws.read_meta() or {})
    status_before = meta_before.get("status")
    status_after = meta_after.get("status")
    phase_after = meta_after.get("phase")
    # Idempotent continue: must not clobber chain_done -> resumed
    continue_idempotent = True
    if status_before in ("chain_done", "chain_partial", "chain_aborted"):
        if status_after == "resumed":
            continue_idempotent = False
        if status_before == "chain_done" and status_after != "chain_done":
            continue_idempotent = False

    report_md = summary.get("report_md") or ""
    report_md_exists = bool(report_md) and Path(str(report_md)).is_file()
    if not report_md_exists:
        alt = ws.report_dir / "report.md"
        if alt.is_file():
            report_md = str(alt)
            report_md_exists = True

    steps = summary.get("steps") or []
    surfaces = [s.get("pb") or s.get("playbook") for s in steps]
    four_ok = (
        len(steps) >= 4
        and all(s.get("ok") for s in steps)
        and set(surfaces) >= {"web_surface", "api_surface", "auth_surface", "svc_surface"}
    )

    # insight sticky: default enqueue_verify=False → no insight_verify in next_actions
    next_actions = summary.get("next_actions") or []
    insight_sticky = any(
        str(a.get("action") or "").startswith("insight_verify:") for a in next_actions
    )
    # also check live graph after continue
    try:
        from kali_mcp.core.target_graph import get_graph

        g = get_graph(task_id, reload=True)
        live_next = g.next_actions(limit=30, include_insights=True)
        insight_sticky = insight_sticky or any(
            str(a.get("action") or "").startswith("insight_verify:") for a in live_next
        )
        next_count_with_insights = len(live_next)
    except Exception:  # noqa: BLE001
        live_next = next_actions
        next_count_with_insights = len(next_actions)

    by_status = summary.get("by_status") or {}
    verified = int(by_status.get("verified") or 0)

    acceptance = {
        "task_id": task_id,
        "target": target,
        "depth": depth,
        "chain_ok": bool(summary.get("ok")),
        "four_surfaces_ok": four_ok,
        "surfaces": surfaces,
        "steps": [
            {
                "pb": s.get("pb") or s.get("playbook"),
                "ok": s.get("ok"),
                "verified": s.get("verified"),
            }
            for s in steps
        ],
        "verified": verified,
        "by_status": by_status,
        "report_md": report_md or None,
        "report_md_exists": report_md_exists,
        "status": status_after,
        "phase": phase_after,
        "chain_done_and_report": status_after == "chain_done" and phase_after == "REPORT",
        "continue_ok": bool(cont.get("ok")),
        "continue_idempotent": continue_idempotent,
        "mutated_to_resumed": status_after == "resumed",
        "insight_sticky": insight_sticky,
        "insight_default_not_sticky": not insight_sticky,
        "next_count_with_insights": next_count_with_insights,
        "insights": summary.get("insights"),
        "actions_count": summary.get("actions_count"),
        "elapsed_ms": summary.get("elapsed_ms"),
        "continue_result": {
            "ok": cont.get("ok"),
            "status": cont.get("status"),
            "phase": cont.get("phase"),
        },
        "meta_before_continue": {"status": status_before, "phase": meta_before.get("phase")},
        "meta_after_continue": {"status": status_after, "phase": phase_after},
    }
    gates = [
        acceptance["chain_ok"],
        acceptance["four_surfaces_ok"],
        acceptance["report_md_exists"],
        acceptance["chain_done_and_report"],
        acceptance["continue_idempotent"],
        acceptance["insight_default_not_sticky"],
        verified > 0,
    ]
    acceptance["acceptance_ok"] = all(gates)
    acceptance["gates"] = {
        "chain_ok": acceptance["chain_ok"],
        "four_surfaces_ok": acceptance["four_surfaces_ok"],
        "report_md_exists": acceptance["report_md_exists"],
        "chain_done_and_report": acceptance["chain_done_and_report"],
        "continue_idempotent": acceptance["continue_idempotent"],
        "insight_default_not_sticky": acceptance["insight_default_not_sticky"],
        "verified_gt_0": verified > 0,
    }
    return acceptance


def fixed_steps_text() -> List[str]:
    return [
        "1. Ensure lab listens: curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/",
        "2. If down: bash utils/lab/start_lab.sh",
        "3. Export: PYTHONPATH=$PWD KALI_MCP_WORKSPACE=$PWD/workspace KALI_MCP_HTTPX_BIN=/home/zss/go/bin/httpx; clear proxies",
        "4. New task_id (NEVER rpt_probe), e.g. lab_reg_YYYYMMDD",
        "5. python utils/lab/run_chain.py http://127.0.0.1:18081/ <task_id>  # depth=mixed",
        "6. Assert: four surfaces ok, verified>0, report.md, status=chain_done phase=REPORT",
        "7. continue_from_handoff: must NOT write status=resumed; insight_verify not sticky by default",
        "8. pytest tests/test_p0_harness.py -q",
        "9. Write JSON summary under doc/lab-acceptance/",
    ]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Lab e2e acceptance checklist")
    parser.add_argument("--target", default=DEFAULT_LAB, help="lab URL")
    parser.add_argument(
        "--task-id",
        default="",
        help="task id for chain run (required with --run-chain; forbidden: rpt_probe)",
    )
    parser.add_argument("--depth", default="mixed", help="chain depth (default mixed)")
    parser.add_argument("--run-chain", action="store_true", help="execute run_surface_chain")
    parser.add_argument("--pytest", action="store_true", help="run tests/test_p0_harness.py -q")
    parser.add_argument("--ensure-lab", action="store_true", help="try start_lab.sh if down")
    parser.add_argument(
        "--out",
        default="",
        help="output JSON path (default doc/lab-acceptance/e2e_<task|stamp>.json)",
    )
    args = parser.parse_args(argv)

    _clear_proxy_env()
    os.environ.setdefault("KALI_MCP_WORKSPACE", str(ROOT / "workspace"))
    if str(ROOT) not in os.environ.get("PYTHONPATH", ""):
        os.environ["PYTHONPATH"] = str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")

    doc: Dict[str, Any] = {
        "schema": "lab_e2e_acceptance_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "root": str(ROOT),
        "forbidden": {
            "task_ids": sorted(NON_DELIVERY_EXACT),
            "note": "Do not use probe/debug task ids for acceptance deliverables",
            "no_run_goal": True,
            "no_drive_executor": True,
        },
        "fixed_steps": fixed_steps_text(),
    }

    if args.ensure_lab:
        doc["ensure_lab"] = ensure_lab(args.target)
        lab = doc["ensure_lab"].get("probe") or check_lab(args.target)
    else:
        lab = check_lab(args.target)
    doc["lab"] = lab

    doc["pytest"] = run_pytest_harness(bool(args.pytest))

    chain_block: Dict[str, Any]
    if args.run_chain:
        tid = (args.task_id or "").strip()
        bad = validate_task_id(tid)
        if bad:
            chain_block = {"ran": False, "error": bad, "acceptance_ok": False}
            doc["chain"] = chain_block
            ACCEPT_DIR.mkdir(parents=True, exist_ok=True)
            out_path = Path(args.out) if args.out else ACCEPT_DIR / f"e2e_error_{_utc_stamp()}.json"
            out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(doc, ensure_ascii=False, indent=2))
            print("OUT", out_path, file=sys.stderr)
            return 2
        try:
            chain_block = run_chain(tid, args.target, depth=args.depth)
            chain_block["ran"] = True
        except Exception as e:  # noqa: BLE001
            chain_block = {"ran": True, "error": str(e)[:500], "acceptance_ok": False}
        doc["chain"] = chain_block
    else:
        doc["chain"] = {
            "ran": False,
            "hint": "pass --run-chain --task-id <new_id> to execute",
            "example": f"python utils/lab/e2e_checklist.py --ensure-lab --run-chain --task-id lab_reg_{datetime.now().strftime('%Y%m%d')} --target {args.target}",
        }

    # overall
    overall_ok = bool(lab.get("ok"))
    if args.run_chain:
        overall_ok = overall_ok and bool((doc.get("chain") or {}).get("acceptance_ok"))
    if args.pytest:
        overall_ok = overall_ok and bool((doc.get("pytest") or {}).get("ok"))
    doc["overall_ok"] = overall_ok

    ACCEPT_DIR.mkdir(parents=True, exist_ok=True)
    if args.out:
        out_path = Path(args.out)
    else:
        suffix = (args.task_id or "checklist").strip() or "checklist"
        if args.run_chain and args.task_id:
            out_path = ACCEPT_DIR / f"{args.task_id}_acceptance.json"
        else:
            out_path = ACCEPT_DIR / f"e2e_{suffix}_{_utc_stamp()}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(doc, ensure_ascii=False, indent=2))
    print("OUT", out_path, file=sys.stderr)
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
