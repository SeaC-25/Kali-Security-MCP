#!/usr/bin/env python3
"""
K2: 异步重型工具 MCP 面 — scan_start / scan_collect / scan_wait / scan_jobs。

重活工具（nmap/sqlmap/hydra/nuclei 等）通过 AsyncJobBridge 在后台线程执行，
立即返回 job_id；模型在等待期可调用其它工具（K2-1 异步化）。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from kali_mcp.core.async_bridge import AsyncJobBridge

logger = logging.getLogger(__name__)

# 异步化的重活工具白名单（K2-1: nmap/masscan/sqlmap/hydra/nikto/nuclei/gobuster/amass）
HEAVY_TOOLS = {
    "nmap", "masscan", "sqlmap", "hydra", "nikto",
    "nuclei", "gobuster", "amass",
}


def register_async_tools(mcp, executor) -> None:
    """Register the K2 async surface (scan_start/scan_collect/scan_wait/scan_jobs)."""
    bridge = AsyncJobBridge(executor=executor)

    @mcp.tool()
    def scan_start(tool_name: str, params: Optional[Dict[str, Any]] = None,
                   timeout: Optional[int] = None) -> Dict[str, Any]:
        """Start a heavy scan in background; returns job_id immediately.

        Heavy tools: nmap/masscan/sqlmap/hydra/nikto/nuclei/gobuster/amass.
        Poll with scan_collect(job_id) or block with scan_wait(job_id, timeout_s).
        """
        name = (tool_name or "").strip()
        if name not in HEAVY_TOOLS:
            return {
                "success": False,
                "error": f"'{name}' 不在异步化白名单（{sorted(HEAVY_TOOLS)}）；轻量工具直接调用同步版本",
                "tool_name": name,
            }
        data = dict(params or {})
        if timeout:
            data["timeout"] = timeout  # 传给执行器工具级超时
        return bridge.start(name, data)

    @mcp.tool()
    def scan_collect(job_id: str) -> Dict[str, Any]:
        """Poll an async scan job; returns running/done/expired/not_found + result."""
        return bridge.collect(job_id)

    @mcp.tool()
    def scan_wait(job_id: str, timeout_s: float = 60.0) -> Dict[str, Any]:
        """Block until an async scan job finishes or timeout_s elapses."""
        return bridge.wait(job_id, timeout_s)

    @mcp.tool()
    def scan_jobs() -> Dict[str, Any]:
        """List currently running async scan jobs."""
        return bridge.jobs()
