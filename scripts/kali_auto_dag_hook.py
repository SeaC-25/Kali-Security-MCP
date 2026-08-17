#!/usr/bin/env python3
"""Kali MCP 自动集成 hook：工具调用后自动建 DAG 节点 + 提炼证据（LLM 透明）。

用途：harness（Claude Code PostToolUse / Codex / OpenCode / Pi）在子代理每次
MCP 工具调用后自动执行本脚本，实现"零提示自动集成"——不靠提示词提示才调 DAG。

行为（对扫描/枚举类工具）：
1. 自动 `dag_apply(op="add_node", node_type="attack_action", ...)` 建节点；
2. 有原始输出时自动 `extract_findings(agent_id, tool_name, output, target)` 提炼证据，
   并把 findings 数量写入节点 meta（evidence 只来自确定性正则解析器）；
3. 输出统一附加块 `[AUTO-DAG] 已记录节点 <id>（findings=N）`，主 agent 可见但无需指示。

输入（stdin JSON，兼容 Claude Code PostToolUse 格式）：
  {"tool_name": "fastsec_scan", "tool_input": {"url"/"target"/"host": ...},
   "tool_response": "..." | {"content"/"output": "..."}, "agent_id"?: "..."}
若拿不到原始 output（hook 机制限制）→ 只建节点（半自动兜底），提炼交给
子代理正文"自动集成约束"节（extract_findings 由子代理调）。

用法：
  py -3 scripts/kali_auto_dag_hook.py < hook_payload.json
退出码恒 0（hook 失败不阻断 harness 主流程）。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO))

# 工具名 → 解析器归属 agent（确定性映射；未命中 → recon_agent）
TOOL_TO_AGENT = {
    "nmap_scan": "recon_agent",
    "masscan_scan": "recon_agent",
    "fastsec_scan": "web_vuln_agent",
    "fastsec_port_scan": "recon_agent",
    "fastsec_dir_scan": "web_recon_agent",
    "fastsec_cms_scan": "web_recon_agent",
    "fastsec_sqli_scan": "web_vuln_agent",
    "fastsec_xss_scan": "web_vuln_agent",
    "fastsec_brute": "auth_agent",
    "fastsec_osint": "subdomain_agent",
    "fastsec_fingerprint": "web_recon_agent",
    "fastsec_template_scan": "vuln_scanner_agent",
    "fastsec_crack": "auth_agent",
    "fastsec_kerberos": "lateral_agent",
    "fastsec_diff": "web_vuln_agent",
    "fastsec_orchestrate": "recon_agent",
    "fastsec_seq": "web_vuln_agent",
    "fastsec_audit": "code_audit_agent",
    "fastsec_file": "forensics_agent",
    "fastsec_user": "subdomain_agent",
    "fastsec_shell": "exploit_agent",
    "fastsec_sam": "forensics_agent",
    "fastsec_smb": "lateral_agent",
    "fastsec_dump": "web_vuln_agent",
    "whatweb_scan": "web_recon_agent",
    "httpx_probe": "web_recon_agent",
    "gobuster_scan": "web_recon_agent",
    "subfinder_scan": "subdomain_agent",
    "nuclei_scan": "vuln_scanner_agent",
    "nikto_scan": "vuln_scanner_agent",
    "sqlmap_scan": "web_vuln_agent",
    "metasploit_run": "exploit_agent",
    "john_crack": "auth_agent",
    "hashcat_crack": "auth_agent",
    "enum4linux_scan": "network_vuln_agent",
    "smb_scan": "network_vuln_agent",
    "kali_run": "recon_agent",
}

# 触发自动集成的工具面（扫描/枚举类；观测类工具不触发）
AUTO_TRIGGER_TOOLS = {
    "nmap_scan", "masscan_scan", "fastsec_scan", "whatweb_scan", "httpx_probe",
    "gobuster_scan", "dirb_scan", "ffuf_scan", "feroxbuster_scan", "wfuzz_scan",
    "subfinder_scan", "amass_scan", "nuclei_scan", "nikto_scan", "sqlmap_scan",
    "metasploit_run", "john_crack", "hashcat_crack", "enum4linux_scan",
    "smb_scan", "rustscan_scan", "naabu_scan", "kerbrute_attack", "nxc_attack",
    "kali_run",
    # fastsec 全能力独立工具面（kb/soceng/shell 为本地生成/查询，不触发扫描 hook）
    "fastsec_port_scan", "fastsec_dir_scan", "fastsec_cms_scan",
    "fastsec_sqli_scan", "fastsec_xss_scan", "fastsec_brute",
    "fastsec_osint", "fastsec_fingerprint", "fastsec_template_scan",
    "fastsec_crack", "fastsec_kerberos", "fastsec_diff",
    "fastsec_orchestrate", "fastsec_seq", "fastsec_audit",
    "fastsec_file", "fastsec_user", "fastsec_sam",
    "fastsec_smb", "fastsec_dump",
}


def _pick_target(tool_input: dict) -> str:
    for k in ("target", "url", "host", "domain", "RHOSTS", "ip"):
        v = tool_input.get(k)
        if v:
            return str(v)
    return ""


def _extract_output(tool_response) -> str:
    if tool_response is None:
        return ""
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        for k in ("output", "content", "stdout", "text", "result"):
            v = tool_response.get(k)
            if isinstance(v, str):
                return v
            if isinstance(v, list):
                parts = [str(x.get("text", "")) if isinstance(x, dict) else str(x)
                         for x in v]
                return "\n".join(parts)
    return str(tool_response)


def main() -> int:
    try:
        raw = sys.stdin.read() or "{}"
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}

    tool_name = str(payload.get("tool_name") or payload.get("tool") or "")
    if not tool_name or tool_name not in AUTO_TRIGGER_TOOLS:
        return 0  # 非扫描/枚举工具，不触发

    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    target = _pick_target(tool_input) or str(payload.get("target") or "")
    agent_id = str(payload.get("agent_id") or TOOL_TO_AGENT.get(tool_name, "recon_agent"))
    session_id = str(tool_input.get("task_id") or payload.get("session_id") or "auto")
    output = _extract_output(payload.get("tool_response"))

    try:
        from kali_mcp.mcp_tools.kg_dag_tools import _dag_service, _run_async
        from kali_mcp.mcp_tools.extract_findings_tools import extract_findings_impl

        dag = _dag_service()
        node_id = f"{tool_name}_{abs(hash((tool_name, target, session_id))) % 10**8:x}"
        if dag is not None:
            _run_async(dag.apply("add_node", {
                "node": {
                    "node_id": node_id,
                    "node_type": "attack_action",
                    "session_id": session_id,
                    "label": f"{tool_name} {target}",
                    "meta": {
                        "agent_role": agent_id,
                        "tool": tool_name,
                        "target": target,
                        "output_preview": output[:300],
                        "hook_auto": True,
                    },
                }
            }))
            # 命中 → 沉积信息素（成功信号 0.9）；未命中仅建节点
            # （信息素沉积走 coordinator/子代理的 dag_apply(deposit) 带真实 edge_ids）
            findings = []
            if output.strip():
                try:
                    res = extract_findings_impl(agent_id, tool_name, output, target)
                    findings = res.get("findings") or []
                except Exception:
                    findings = []

        else:
            findings = []

        # 统一附加块：主 agent 可见但无需指示
        print(json.dumps({
            "hook": "kali_auto_dag",
            "tool_name": tool_name,
            "node_id": node_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "findings_count": len(findings),
            "note": "[AUTO-DAG] 已记录节点 " + node_id +
                    (f"，提炼 {len(findings)} 条证据" if findings else "（无输出，未提炼）"),
        }, ensure_ascii=False))
    except Exception as e:  # noqa: BLE001 —— hook 失败不阻断 harness
        print(json.dumps({"hook": "kali_auto_dag", "error": str(e)[:200]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
