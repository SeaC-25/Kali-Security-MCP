#!/usr/bin/env python3
"""
K1 meta surface: kali_run 通用执行工具 (converged MCP surface fallback).

The MCP tool surface was converged from 192 tools down to a ~26-tool keep-set
(see K1_KEEP_TOOLS). Archived tool modules remain on disk but are UNREGISTERED;
their commands are still buildable through kali_mcp.core.tool_registry.
kali_run is the meta fallback: it builds + executes ANY recognised tool name
(keep-set or archived, registry key or alias) without re-expanding the MCP
surface.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from kali_mcp.core.tool_registry import (
    ALLOWED_TOOLS,
    build_command,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# K1 keep-set: tools that stay natively registered on the MCP surface.
# Every other recognised tool is archived (module file kept, unregistered)
# and remains reachable through kali_run.
# ---------------------------------------------------------------------------
K1_KEEP_TOOLS = frozenset({
    # recon (recon_tools.py — whole module kept)
    # fastsec 已替代: gobuster/nikto/sqlmap/hydra/whatweb/subfinder/ffuf/nuclei
    "nmap_scan", "metasploit_run", "john_crack", "enum4linux_scan",
    "server_health",
    # recon / web (ai_tools.py — pruned to these)
    # password (ai_tools.py)
    "hashcat_crack",
    # exploit (ai_tools.py)
    # pwn (pwn_tools.py — pruned)
    "quick_pwn_check",
    # intel (code_audit_tools.py — pruned)
    "comprehensive_recon",
    # harness (harness_tools.py — pruned; exact names for the plan's
    # start_task/add_target/task_status/run_chain/verify_target bucket —
    # add_target has no harness equivalent, run_chain/verify_target map to
    # run_surface_chain/verify_finding)
    "start_task", "task_status", "run_surface_chain", "verify_finding",
    # session (session_tools.py — pruned; create_session/list_sessions map
    # to start_attack_session/list_attack_sessions)
    "start_attack_session", "list_attack_sessions",
    # K4 thin task board (board_tools.py)
    "task_create", "task_claim", "task_complete", "task_renew",
    "task_list", "board_snapshot",
    # meta
    "kali_run",
    # K2 async surface
    "scan_start", "scan_collect", "scan_wait", "scan_jobs",
    # 高性能/内网横向（2026-08 增强）
    "rustscan_scan", "naabu_scan", "kerbrute_attack", "nxc_attack",
    "evil_winrm_attack", "GetUserSPNs_scan", "secretsdump_scan",
    "psexec_attack", "smbexec_attack", "GetNPUsers_scan",
    "fastsec_scan",
    # fastsec 全能力独立工具面（24 个模式，薄包装 execute_tool_with_data("fastsec")）
    "fastsec_port_scan", "fastsec_dir_scan", "fastsec_cms_scan",
    "fastsec_sqli_scan", "fastsec_xss_scan", "fastsec_brute",
    "fastsec_osint", "fastsec_fingerprint", "fastsec_template_scan",
    "fastsec_crack", "fastsec_kerberos", "fastsec_diff",
    "fastsec_soceng", "fastsec_orchestrate", "fastsec_seq",
    "fastsec_audit", "fastsec_file", "fastsec_user",
    "fastsec_shell", "fastsec_sam", "fastsec_smb",
    "fastsec_dump", "fastsec_kb",
    # K3 orchestrate workflow
    "wf_init", "wf_transition", "wf_record_result", "wf_record_issue",
    "wf_status", "wf_pack_turn",
    # 多智能体集群入口（原生子代理架构：编排移入 harness 侧，MCP 不再暴露）
    # 向量库检索 + 蚁群 DAG 读写/观测（能力工具，独立构造服务）
    "kb_search", "dag_status", "dag_apply", "dag_recommend",
    # 证据提炼（复用 17 agent 确定性解析器）
    "extract_findings",
    # 痕迹清理（三粒度：task/session/global，雁过无痕）
    "wipe_traces",
})

# ---------------------------------------------------------------------------
# MCP tool names (registered surface) → registry / executor tool names.
# kali_run accepts either spelling; registry keys and aliases (e.g.
# "aircrack-ng") are used directly without mapping.
# ---------------------------------------------------------------------------
_MCP_TO_REGISTRY: Dict[str, str] = {
    # keep-set (recon / web / password / exploit)
    "nmap_scan": "nmap",
                                        "john_crack": "john",
    "hashcat_crack": "hashcat",
    "metasploit_run": "metasploit",
        "enum4linux_scan": "enum4linux",
    # fastsec 自研引擎（单二进制，AI 原生扫描）
    "fastsec_scan": "fastsec",
    # archived aliases (ai_tools / misc / pentagi / apt surface)
    "aircrack_attack": "aircrack-ng",
    "reaver_attack": "reaver",
    "bettercap_attack": "bettercap",
                "httpx_probe": "httpx",
    "recon_ng_run": "recon-ng",
    "netdiscover_scan": "netdiscover",
        "arp_scan": "arp-scan",
    "fping_scan": "fping",
    "binwalk_analysis": "binwalk",
    "bandit_scan": "bandit",
    "semgrep_scan": "semgrep",
    "shellcheck_scan": "shellcheck",
        "amass_scan": "amass",
                    "sublist3r_scan": "sublist3r",
                            "bully_attack": "bully",
    "pixiewps_attack": "pixiewps",
    "yersinia_attack": "yersinia",
}


def register_meta_tools(mcp, executor):
    """Register the K1 meta surface (kali_run)."""

    @mcp.tool()
    def kali_run(tool_name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute ANY tool by name through the command registry (meta fallback).

        The MCP surface is converged: ~26 tools are natively registered and the
        rest are archived but remain executable here. Accepts registry keys,
        aliases and MCP-style tool names (e.g. "nmap_scan", "aircrack-ng",
        "sqlmap"). The whitelist is ALLOWED_TOOLS (registry-supported names);
        keep-set names map onto it via the MCP→registry index, so native tools
        stay reachable through this fallback as well.

        Args:
            tool_name: Tool name (registry key, alias, or MCP tool name).
            params: Tool parameter dict, same shape as the native tool's args.

        Returns:
            Execution result (same shape as native tools).
        """
        name = (tool_name or "").strip()
        if not name:
            return {"success": False, "error": "tool_name required", "tool_name": name}

        # MCP-style name → registry name (identity for registry keys/aliases)
        registry_name = _MCP_TO_REGISTRY.get(name, name)
        if registry_name not in ALLOWED_TOOLS:
            return {
                "success": False,
                "error": f"工具 '{name}' 不在白名单中 (ALLOWED_TOOLS)，拒绝执行",
                "tool_name": name,
            }

        data = dict(params or {})
        cmd = build_command(registry_name, data)
        if not cmd:
            return {
                "success": False,
                "error": f"工具 '{name}' 无法构建命令，请检查参数",
                "tool_name": name,
            }

        logger.info("[kali_run] %s → %s", name, cmd)
        # 与原生工具一致：走 execute_tool_with_data 获得 ssh 后端路由 / 结果缓存 / 输出解析。
        # 直接 execute_command 会把命令丢到本地 subprocess，绕过已配置的 ssh 后端
        # （harness 档位下归档工具的唯一入口，nmap/fastsec 等在 Windows 主机上全部不可用）。
        return executor.execute_tool_with_data(registry_name, data)
