#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali MCP baseline measurement (K0-1).

Idempotent, stdlib-only snapshot of the Kali MCP server surface:
  1. registered tool count (kali_mcp/mcp_tools/*.py, @mcp.tool() decorators)
  2. schema byte estimate (signature + docstring per tool, best-effort regex)
  3. instructions block byte length (FastMCP(instructions=...) in mcp_server.py)
  4. timeout inventory (EXEC_CONFIG in kali_mcp/core/shell_utils.py)
  5. LLM-key dependency files (anthropic/openai/api_key references)
  6. backend reachability (nmap on PATH)

Writes scripts/baseline_report.json and scripts/baseline_report.md, prints a
compact summary table. Always exits 0 (measurement, not a gate).
"""

import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
MCP_TOOLS_DIR = REPO_ROOT / "kali_mcp" / "mcp_tools"
MCP_SERVER = REPO_ROOT / "mcp_server.py"
SHELL_UTILS = REPO_ROOT / "kali_mcp" / "core" / "shell_utils.py"
KALI_MCP = REPO_ROOT / "kali_mcp"
OUT_JSON = SCRIPTS_DIR / "baseline_report.json"
OUT_MD = SCRIPTS_DIR / "baseline_report.md"

DECORATOR_RE = re.compile(r"^[ \t]*@mcp\.tool\s*\(\s*\)[ \t\r]*$", re.M)
DEF_RE = re.compile(r"^(?P<indent>\s*)(?:async\s+)?def\s+(?P<name>\w+)\s*\(")
TRIPLE_DOC_RE = re.compile(r"^\s*(?P<quote>\"\"\"|''')")
ENV_INT_RE = re.compile(
    r'^[ \t]*"(?P<key>\w+)"\s*:\s*int\(os\.environ\.get\(\s*'
    r'"(?P<env>[A-Z0-9_]+)"\s*,\s*"(?P<default>\d+)"\s*\)\s*\)'
)
PLAIN_INT_RE = re.compile(r'^[ \t]*"(?P<key>\w+)"\s*:\s*(?P<value>\d+)\s*,?$')
TIMEOUT_ENTRY_RE = re.compile(r'^[ \t]*"(?P<tool>\w+)"\s*:\s*(?P<secs>\d+)\s*,?$')
LLM_REF_RE = re.compile(r"anthropic|openai|api_key", re.IGNORECASE)


def read_text(path):
    return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------- tools / schema

def parse_signature(lines, start):
    """Collect the def line(s) of a (possibly multi-line) signature.

    Returns (signature_text, index_of_last_signature_line).
    """
    parts = []
    depth = 0
    i = start
    while i < len(lines):
        line = lines[i]
        parts.append(line)
        depth += line.count("(") - line.count(")")
        if depth <= 0 and line.rstrip().endswith(":"):
            break
        i += 1
    return "\n".join(parts), i


def parse_docstring(lines, after):
    """Best-effort docstring right after a signature (triple- or single-quoted)."""
    j = after + 1
    while j < len(lines) and not lines[j].strip():
        j += 1
    if j >= len(lines):
        return "", j
    stripped = lines[j].strip()
    m = TRIPLE_DOC_RE.match(stripped)
    if m:
        quote = m.group("quote")
        parts = [lines[j]]
        if stripped.count(quote) >= 2:  # opener and closer on one line
            return "\n".join(parts), j
        k = j + 1
        while k < len(lines):
            parts.append(lines[k])
            if quote in lines[k]:
                return "\n".join(parts), k
            k += 1
        return "\n".join(parts), k
    if stripped.startswith('"') or stripped.startswith("'"):
        return lines[j], j
    return "", j


def analyze_tools():
    """Count @mcp.tool() decorators and estimate schema bytes per module."""
    tools = []  # {module, name, signature_bytes, docstring_bytes, schema_bytes}
    module_totals = {}
    for py in sorted(MCP_TOOLS_DIR.glob("*.py")):
        source = read_text(py)
        lines = source.splitlines()
        module_bytes = 0
        module_tools = 0
        for dm in DECORATOR_RE.finditer(source):
            line_no = source[: dm.start()].count("\n")
            # find the def line that follows the decorator
            i = line_no + 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            if i >= len(lines):
                continue
            defm = DEF_RE.match(lines[i])
            if not defm:
                continue
            name = defm.group("name")
            sig_text, sig_end = parse_signature(lines, i)
            doc_text, _ = parse_docstring(lines, sig_end)
            sig_bytes = len(sig_text.encode("utf-8"))
            doc_bytes = len(doc_text.encode("utf-8"))
            schema_bytes = sig_bytes + doc_bytes
            module_bytes += schema_bytes
            module_tools += 1
            tools.append(
                {
                    "module": py.name,
                    "name": name,
                    "signature_bytes": sig_bytes,
                    "docstring_bytes": doc_bytes,
                    "schema_bytes": schema_bytes,
                }
            )
        module_totals[py.name] = {
            "tool_count": module_tools,
            "schema_bytes": module_bytes,
        }
    total_bytes = sum(t["schema_bytes"] for t in tools)
    return tools, module_totals, total_bytes


# -------------------------------------------------------------- instructions block

def instructions_bytes():
    source = read_text(MCP_SERVER)
    m = re.search(r'instructions\s*=\s*"""(.*?)"""', source, re.S)
    if not m:
        return None
    content = m.group(1)
    return {
        "chars": len(content),
        "bytes": len(content.encode("utf-8")),
        "lines": len(content.splitlines()),
    }


# -------------------------------------------------------------- timeout inventory

def extract_braced_block(source, key):
    """Return the text inside { ... } following '<key>: {', or None."""
    m = re.search(r'"%s"\s*:\s*\{' % key, source)
    if not m:
        return None
    depth = 0
    for i in range(m.end() - 1, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[m.end():i]
    return None


def timeout_inventory():
    source = read_text(SHELL_UTILS)
    m = re.search(r"EXEC_CONFIG\s*=\s*\{", source)
    if not m:
        return {"error": "EXEC_CONFIG not found"}
    depth = 0
    end = None
    for i in range(m.end() - 1, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return {"error": "EXEC_CONFIG not terminated"}
    block = source[m.end():end]
    scalars = {}
    in_nested = 0
    for line in block.splitlines():
        if in_nested:
            in_nested += line.count("{") - line.count("}")
            continue
        if '"tool_timeouts"' in line and "{" in line:
            in_nested = 1
            continue
        em = ENV_INT_RE.match(line)
        if em:
            scalars[em.group("key")] = {
                "default": int(em.group("default")),
                "env_var": em.group("env"),
            }
            continue
        pm = PLAIN_INT_RE.match(line)
        if pm:
            scalars[pm.group("key")] = {"value": int(pm.group("value"))}
    tool_block = extract_braced_block(block, "tool_timeouts")
    tool_timeouts = {}
    if tool_block:
        for line in tool_block.splitlines():
            tm = TIMEOUT_ENTRY_RE.match(line)
            if tm:
                tool_timeouts[tm.group("tool")] = int(tm.group("secs"))
    numeric = []
    for v in scalars.values():
        numeric.append(v.get("default", v.get("value")))
    numeric.extend(tool_timeouts.values())
    return {
        "default_timeout": scalars.get("default_timeout"),
        "retry_count": scalars.get("retry_count"),
        "retry_delay": scalars.get("retry_delay"),
        "other_scalars": {k: v for k, v in sorted(scalars.items())
                          if k not in ("default_timeout", "retry_count", "retry_delay")},
        "tool_timeouts": dict(sorted(tool_timeouts.items())),
        "max_tool_timeout": max(tool_timeouts.values()) if tool_timeouts else None,
        "max_config_value": max(numeric) if numeric else None,
        "tool_timeout_count": len(tool_timeouts),
    }


# -------------------------------------------------------------- llm-key deps

def llm_key_dependency_files():
    hits = []
    for py in sorted(KALI_MCP.rglob("*.py")):
        if LLM_REF_RE.search(read_text(py)):
            hits.append(py.relative_to(REPO_ROOT).as_posix())
    return hits


# -------------------------------------------------------------- backend reachability

def backend_reachability():
    check_cmd = "where nmap" if os.name == "nt" else "which nmap"
    path = shutil.which("nmap")
    return {
        "check_command": check_cmd,
        "nmap_found": path is not None,
        "nmap_path": path,
    }


# -------------------------------------------------------------- report assembly

def build_report():
    tools, module_totals, total_schema_bytes = analyze_tools()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repo_root": REPO_ROOT.as_posix(),
        "tool_count": len(tools),
        "modules": len(module_totals),
        "module_breakdown": dict(sorted(module_totals.items())),
        "schema_byte_estimate": {
            "total_bytes": total_schema_bytes,
            "tools_measured": len(tools),
            "per_module": {k: v["schema_bytes"]
                           for k, v in sorted(module_totals.items())},
        },
        "instructions_block": instructions_bytes(),
        "timeout_inventory": timeout_inventory(),
        "llm_key_dependency_files": llm_key_dependency_files(),
        "backend_reachability": backend_reachability(),
    }
    return report, tools


def write_outputs(report, tools):
    json_payload = dict(report)
    json_payload["tools"] = tools
    OUT_JSON.write_text(
        json.dumps(json_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    tb = report["schema_byte_estimate"]["total_bytes"]
    inst = report["instructions_block"]
    inst_str = f"{inst['bytes']} bytes" if inst else "not found"
    ti = report["timeout_inventory"]
    nmap = report["backend_reachability"]

    md = [
        "# Kali MCP Baseline Report",
        "",
        f"- Generated (UTC): {report['generated_at']}",
        f"- Repo root: `{report['repo_root']}`",
        "",
        "## Registered tools",
        "",
        f"- Tool count (`@mcp.tool()` in `kali_mcp/mcp_tools/*.py`): **{report['tool_count']}**",
        f"- Schema byte estimate (signature + docstring): **{tb}** bytes across {len(tools)} tools",
        "",
        "### Per-module breakdown",
        "",
        "| Module | Tools | Schema bytes |",
        "|---|---|---|",
    ]
    for mod, info in sorted(report["module_breakdown"].items()):
        md.append(f"| {mod} | {info['tool_count']} | {info['schema_bytes']} |")
    md += [
        "",
        "## Instructions block",
        "",
        f"- `instructions=\"...\"` in `mcp_server.py`: **{inst_str}**"
        + (f" ({inst['chars']} chars, {inst['lines']} lines)" if inst else ""),
        "",
        "## Timeout inventory (`EXEC_CONFIG` in `kali_mcp/core/shell_utils.py`)",
        "",
        "| Setting | Value |",
        "|---|---|",
    ]
    if "error" in ti:
        md.append(f"| error | {ti['error']} |")
    else:
        md.append(f"| default_timeout | {ti['default_timeout']} |")
        md.append(f"| retry_count | {ti['retry_count']} |")
        md.append(f"| retry_delay | {ti['retry_delay']} |")
        md.append(f"| tool_timeouts entries | {ti['tool_timeout_count']} |")
        md.append(f"| max tool timeout | {ti['max_tool_timeout']}s |")
        md.append(f"| max config value | {ti['max_config_value']}s |")
        md += ["", "### Tool timeouts", "", "| Tool | Seconds |", "|---|---|"]
        for tool, secs in ti["tool_timeouts"].items():
            md.append(f"| {tool} | {secs} |")
    md += [
        "",
        "## LLM-key dependency files",
        "",
        f"- Files referencing `anthropic`/`openai`/`api_key`: **{len(report['llm_key_dependency_files'])}**",
    ]
    for f in report["llm_key_dependency_files"]:
        md.append(f"- `{f}`")
    md += [
        "",
        "## Backend reachability",
        "",
        f"- Check: `{nmap['check_command']}`",
        f"- nmap: **{'found' if nmap['nmap_found'] else 'not-found'}**"
        + (f" at `{nmap['nmap_path']}`" if nmap["nmap_path"] else ""),
        "",
    ]
    OUT_MD.write_text("\n".join(md), encoding="utf-8")


def print_summary(report):
    ti = report["timeout_inventory"]
    nmap = report["backend_reachability"]
    print("Kali MCP baseline")
    print(f"  tools:            {report['tool_count']} (@mcp.tool() in {report['modules']} modules)")
    print(f"  schema bytes:     {report['schema_byte_estimate']['total_bytes']} (signature+docstring)")
    inst = report["instructions_block"]
    print(f"  instructions:     {inst['bytes']} bytes" if inst else "  instructions:     not found")
    if "error" not in ti:
        print(f"  timeouts:         default={ti['default_timeout']['default']}s "
              f"retry={ti['retry_count']['default']}x/{ti['retry_delay']['default']}s "
              f"tools={ti['tool_timeout_count']} max={ti['max_tool_timeout']}s")
    else:
        print(f"  timeouts:         error: {ti['error']}")
    print(f"  llm-key files:    {len(report['llm_key_dependency_files'])}")
    print(f"  nmap:             {'found: ' + str(nmap['nmap_path']) if nmap['nmap_found'] else 'not-found'}")


def main():
    try:
        report, tools = build_report()
        write_outputs(report, tools)
        print_summary(report)
    except Exception as exc:  # measurement never gates: always exit 0
        print(f"baseline error: {exc!r}", file=sys.stderr)
        OUT_JSON.write_text(
            json.dumps({"error": str(exc), "generated_at":
                        datetime.now(timezone.utc).isoformat(timespec="seconds")},
                       indent=2),
            encoding="utf-8",
        )
        OUT_MD.write_text(f"# Kali MCP Baseline Report\n\nError: {exc}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
