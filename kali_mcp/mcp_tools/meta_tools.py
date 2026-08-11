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
    "nmap_scan", "gobuster_scan", "nikto_scan", "sqlmap_scan",
    "metasploit_run", "hydra_attack", "john_crack", "enum4linux_scan",
    "server_health",
    # recon / web (ai_tools.py — pruned to these)
    "whatweb_scan", "subfinder_scan", "masscan_fast_scan", "ffuf_scan",
    "nuclei_scan",
    # password (ai_tools.py)
    "hashcat_crack",
    # exploit (ai_tools.py)
    "searchsploit_search",
    # pwn (pwn_tools.py — pruned)
    "quick_pwn_check", "pwnpasi_auto_pwn",
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
    # K3 orchestrate workflow
    "wf_init", "wf_transition", "wf_record_result", "wf_record_issue",
    "wf_status", "wf_pack_turn",
})

# ---------------------------------------------------------------------------
# MCP tool names (registered surface) → registry / executor tool names.
# kali_run accepts either spelling; registry keys and aliases (e.g.
# "aircrack-ng") are used directly without mapping.
# ---------------------------------------------------------------------------
_MCP_TO_REGISTRY: Dict[str, str] = {
    # keep-set (recon / web / password / exploit)
    "nmap_scan": "nmap",
    "gobuster_scan": "gobuster",
    "nikto_scan": "nikto",
    "sqlmap_scan": "sqlmap",
    "whatweb_scan": "whatweb",
    "subfinder_scan": "subfinder",
    "masscan_fast_scan": "masscan",
    "ffuf_scan": "ffuf",
    "nuclei_scan": "nuclei",
    "hydra_attack": "hydra",
    "john_crack": "john",
    "hashcat_crack": "hashcat",
    "metasploit_run": "metasploit",
    "searchsploit_search": "searchsploit",
    "enum4linux_scan": "enum4linux",
    # archived aliases (ai_tools / misc / pentagi / apt surface)
    "aircrack_attack": "aircrack-ng",
    "reaver_attack": "reaver",
    "bettercap_attack": "bettercap",
    "wpscan_scan": "wpscan",
    "theharvester_osint": "theharvester",
    "sherlock_search": "sherlock",
    "httpx_probe": "httpx",
    "recon_ng_run": "recon-ng",
    "netdiscover_scan": "netdiscover",
    "dnsrecon_scan": "dnsrecon",
    "arp_scan": "arp-scan",
    "fping_scan": "fping",
    "binwalk_analysis": "binwalk",
    "bandit_scan": "bandit",
    "semgrep_scan": "semgrep",
    "shellcheck_scan": "shellcheck",
    "joomscan_scan": "joomscan",
    "amass_scan": "amass",
    "dirb_scan": "dirb",
    "feroxbuster_scan": "feroxbuster",
    "wfuzz_scan": "wfuzz",
    "dnsenum_scan": "dnsenum",
    "sublist3r_scan": "sublist3r",
    "fierce_scan": "fierce",
    "medusa_attack": "medusa",
    "ncrack_attack": "ncrack",
    "brutespray_attack": "brutespray",
    "crowbar_attack": "crowbar",
    "patator_attack": "patator",
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
        return executor.execute_command(cmd)
