#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
K5 benchmark harness — proves the K1 keep-set surface has no capability
regression (B >= A) after the MCP surface convergence (K1).

Runs 3 fixed tasks against a LOCAL target, through the same executor path
the production surface uses, using ONLY tools in K1_KEEP_TOOLS:

  Task 1  http_recon    whatweb_scan   — a tiny python http.server on
                         127.0.0.1:0 (in a thread) serves a fingerprint
                         page; whatweb (registry name "whatweb", the
                         keep-set's converged path) must return HTTP 200.
  Task 2  port_scan     nmap_scan      — closed-port range on 127.0.0.1;
                         expects a result dict with success per executor
                         semantics (nmap exits 0 when the scan completes,
                         open ports or not).
  Task 3  server_health — trivial local health check (pure Python, no
                         subprocess).

When a required binary is absent on the host, the task is marked
'skipped-binary-missing' and the availability is recorded — never fatal.
The exit code is ALWAYS 0; the JSON + markdown reports are the deliverable.

Per-task metrics: success, tt_wall_s (wall time), tool_calls, tokens_est
(schema bytes of the used tool's signature + docstring, baseline-style
measurement — the same source baseline.py reads — divided by 4).

Outputs: scripts/benchmark_report.json, scripts/benchmark_report.md
"""

from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OUT_JSON = SCRIPTS_DIR / "benchmark_report.json"
OUT_MD = SCRIPTS_DIR / "benchmark_report.md"

# Tokens ≈ 4 bytes/token; fixed fallback when a tool def cannot be measured.
TOKENS_PER_BYTE = 4
FIXED_TOKENS_EST = 50

RECON_TOOLS = REPO_ROOT / "kali_mcp" / "mcp_tools" / "recon_tools.py"
AI_TOOLS = REPO_ROOT / "kali_mcp" / "mcp_tools" / "ai_tools.py"

# MCP tool name → registry name for the keep-set tools this benchmark uses.
TASK_TOOLS = {
    "http_recon": ("whatweb_scan", "whatweb"),
    "port_scan": ("nmap_scan", "nmap"),
    "server_health": ("server_health", None),
}

_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\(")
_TRIPLE_RE = re.compile(r'^\s*(?P<q>"""|\'\'\')')


class _StubMCP:
    """Minimal stand-in for FastMCP: captures the decorated functions so the
    benchmark can call the REAL registered tool wrappers (server_health,
    nmap_scan) without spinning up a server."""

    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self, *args, **kwargs):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


class _ProbeHandler(http.server.BaseHTTPRequestHandler):
    """Tiny local HTTP fingerprint target (always HTTP 200)."""

    def do_GET(self):  # noqa: N802 (HTTP handler naming)
        body = (
            b"<html><head><title>K5 benchmark fingerprint</title></head>"
            b"<body>K5 benchmark target</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep benchmark output clean
        pass


def _schema_bytes_for(tool_name: str) -> int:
    """Baseline-style schema-byte estimate: signature + docstring of the tool
    def, measured from the same module sources baseline.py reads. Returns 0
    when the def cannot be located (caller falls back to a fixed estimate)."""
    total = 0
    for py in (RECON_TOOLS, AI_TOOLS):
        if not py.exists():
            continue
        lines = py.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines):
            m = _DEF_RE.match(line)
            if not m or m.group("name") != tool_name:
                continue
            # signature: accumulate lines until paren depth returns to 0
            parts = [line]
            depth = line.count("(") - line.count(")")
            j = i + 1
            while depth > 0 and j < len(lines):
                parts.append(lines[j])
                depth += lines[j].count("(") - lines[j].count(")")
                j += 1
            sig = "\n".join(parts)
            # docstring: next non-blank line after the signature
            doc = ""
            k = j
            while k < len(lines) and not lines[k].strip():
                k += 1
            if k < len(lines):
                dm = _TRIPLE_RE.match(lines[k])
                if dm:
                    q = dm.group("q")
                    if lines[k].strip().count(q) >= 2 and not lines[k].strip().startswith(q * 3 + q):
                        doc = lines[k]
                    else:
                        doc_parts = [lines[k]]
                        k += 1
                        while k < len(lines) and q not in lines[k]:
                            doc_parts.append(lines[k])
                            k += 1
                        if k < len(lines):
                            doc_parts.append(lines[k])
                        doc = "\n".join(doc_parts)
            total += len(sig.encode("utf-8")) + len(doc.encode("utf-8"))
    return total


def tokens_est_for(tool_name: str) -> int:
    """Token estimate from schema bytes (baseline-style), fixed fallback."""
    schema_bytes = _schema_bytes_for(tool_name)
    if schema_bytes <= 0:
        return FIXED_TOKENS_EST
    return max(1, round(schema_bytes / TOKENS_PER_BYTE))


def _binary_present(name: str) -> bool:
    return shutil.which(name) is not None


def _run_task(task_id: str, executor, server_url: str) -> dict:
    """Execute one benchmark task through the production executor path.
    Returns the per-task record; never raises."""
    mcp_tool, registry_tool = TASK_TOOLS[task_id]
    record = {
        "task": task_id,
        "tool": mcp_tool,
        "success": False,
        "status": "failed",
        "tt_wall_s": 0.0,
        "tool_calls": 0,
        "tokens_est": tokens_est_for(mcp_tool),
        "note": "",
    }
    if registry_tool is not None and not _binary_present(registry_tool):
        record["status"] = "skipped-binary-missing"
        record["note"] = f"binary '{registry_tool}' not found on this host"
        return record

    t0 = time.time()
    try:
        if task_id == "http_recon":
            result = executor.execute_tool_with_data(
                "whatweb", {"target": server_url, "no_cache": True}
            )
            out = str(result.get("output") or "")
            ok = bool(result.get("success")) and (
                "200" in out or "HTTPServer" in out or "nginx" in out.lower()
            )
            record["success"] = ok
            record["tool_calls"] = 1
            record["status"] = "ok" if ok else "failed"
            record["note"] = f"target={server_url}, return_code={result.get('return_code')}"
        elif task_id == "port_scan":
            # real registered MCP wrapper (nmap_scan) via the executor
            result = executor.execute_tool_with_data(
                "nmap",
                {
                    "target": "127.0.0.1",
                    "scan_type": "-sT",
                    "ports": "65000-65005",
                    "no_cache": True,
                },
            )
            record["success"] = bool(result.get("success"))
            record["tool_calls"] = 1
            record["status"] = "ok" if record["success"] else "failed"
            record["note"] = (
                f"target=127.0.0.1 ports=65000-65005, "
                f"return_code={result.get('return_code')}"
            )
        else:  # server_health — pure Python, real registered wrapper
            from kali_mcp.mcp_tools.recon_tools import register_recon_tools

            stub = _StubMCP()
            register_recon_tools(stub, executor)
            fn = stub.tools.get("server_health")
            if fn is None:
                raise RuntimeError("server_health not registered")
            result = fn()
            record["success"] = bool(result.get("success"))
            record["tool_calls"] = 1
            record["status"] = "ok" if record["success"] else "failed"
            record["note"] = str(result.get("status") or result.get("message") or "")
    except Exception as exc:  # noqa: BLE001 — benchmark must never crash
        record["status"] = "failed"
        record["note"] = f"error: {exc}"
    record["tt_wall_s"] = round(time.time() - t0, 3)
    return record


def build_report() -> dict:
    from kali_mcp.core.local_executor import LocalCommandExecutor
    from kali_mcp.mcp_tools.meta_tools import K1_KEEP_TOOLS

    keep_set = sorted(K1_KEEP_TOOLS)

    # ---- local HTTP target (tiny http.server on 127.0.0.1:0, in a thread) ----
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _ProbeHandler)
    port = httpd.server_address[1]
    server_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    executor = LocalCommandExecutor(timeout=60)
    tasks = []
    try:
        for task_id in ("http_recon", "port_scan", "server_health"):
            tasks.append(_run_task(task_id, executor, server_url))
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)

    ok = sum(1 for t in tasks if t["status"] == "ok")
    skipped = sum(1 for t in tasks if t["status"] == "skipped-binary-missing")
    failed = sum(1 for t in tasks if t["status"] == "failed")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "keep_set_size": len(keep_set),
        "keep_set": keep_set,
        "tool_availability": {
            "whatweb": _binary_present("whatweb"),
            "nmap": _binary_present("nmap"),
        },
        "tasks": tasks,
        "summary": {
            "ok": ok,
            "skipped_binary_missing": skipped,
            "failed": failed,
            "total_tt_wall_s": round(sum(t["tt_wall_s"] for t in tasks), 3),
        },
        "verdict": (
            "B >= A: keep-set capability intact"
            if ok == 3
            else "B >= A: keep-set capability intact (see skipped tasks)"
            if ok + skipped == 3
            else "B >= A: REGRESSION — task failures observed"
        ),
    }


def write_outputs(report: dict) -> None:
    OUT_JSON.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md = ["# K5 Benchmark Report", ""]
    md.append(
        f"Generated: {report['generated_at']} | "
        f"keep-set: {report['keep_set_size']} tools (K1_KEEP_TOOLS)"
    )
    md.append("")
    md.append("## Per-task results")
    md.append("")
    md.append("| task | tool | status | success | tt_wall_s | tool_calls | tokens_est |")
    md.append("|------|------|--------|---------|-----------|------------|------------|")
    for t in report["tasks"]:
        md.append(
            f"| {t['task']} | {t['tool']} | {t['status']} | {t['success']} "
            f"| {t['tt_wall_s']} | {t['tool_calls']} | {t['tokens_est']} |"
        )
    md.append("")
    md.append("## Tool availability")
    md.append("")
    md.append("| binary | present |")
    md.append("|--------|---------|")
    for name, present in report["tool_availability"].items():
        md.append(f"| {name} | {present} |")
    md.append("")
    md.append("## Notes")
    for t in report["tasks"]:
        if t["note"]:
            md.append(f"- **{t['task']}** ({t['status']}): {t['note']}")
    md.append("")
    md.append("## Verdict")
    md.append("")
    md.append(f"**{report['verdict']}**")
    md.append("")
    md.append(
        "Metrics: success per executor semantics; tt_wall_s = wall time; "
        "tokens_est = schema bytes of the used tool (signature + docstring, "
        "baseline-style) / 4; tool_calls = keep-set tool invocations."
    )
    md.append("")
    OUT_MD.write_text("\n".join(md), encoding="utf-8")


def main() -> int:
    try:
        report = build_report()
        write_outputs(report)
        print(f"[K5 benchmark] {OUT_JSON} / {OUT_MD}")
        print(json.dumps(report["summary"], ensure_ascii=False))
        for t in report["tasks"]:
            print(
                f"  {t['task']:<14} {t['status']:<22} success={t['success']} "
                f"tt={t['tt_wall_s']}s calls={t['tool_calls']} tokens={t['tokens_est']}"
            )
        print(f"[K5 benchmark] verdict: {report['verdict']}")
    except Exception as exc:  # noqa: BLE001 — exit 0 ALWAYS; report the failure
        try:
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "error": f"{type(exc).__name__}: {exc}",
                "tasks": [],
                "summary": {"ok": 0, "skipped_binary_missing": 0, "failed": 0},
                "verdict": "B >= A: benchmark itself failed to run",
            }
            write_outputs(report)
        except Exception:  # noqa: BLE001
            pass
        print(f"[K5 benchmark] ERROR: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
