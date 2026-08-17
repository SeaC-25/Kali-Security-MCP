#!/usr/bin/env python3
"""extract_findings 能力工具：复用 17 个 Python agent 的确定性解析器提炼证据。

原生子代理架构下，harness 侧子代理每次扫描/枚举工具调用后，由 hook 自动调本工具
把原始工具输出提炼为结构化 Finding（title/severity/confidence/evidence）——证据只
来自确定性正则解析器（_parse_tool_output），禁止 LLM 自编。

实现：懒加载 AGENT_CLASS map（17 个 agent 类），`cls()` 全空构造（agent __init__
全参数可空，解析器仅引用 self.agent_id + 入参），调 `_parse_tool_output` 后用
`LLMAgentBase._finding_to_dict` 序列化，每条补 source=agent_id。
单 agent 构造失败 → 该 agent 返回空 findings（不阻塞其余），并报告 error。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 17 个权威 agent_id（与 agents/*/*_agent.py 的 self.agent_id 一致）
AGENT_IDS = [
    "recon_agent", "subdomain_agent", "web_recon_agent",
    "vuln_scanner_agent", "web_vuln_agent", "auth_agent",
    "network_vuln_agent", "vuln_verifier_agent",
    "exploit_agent", "privilege_agent", "lateral_agent",
    "pwn_agent", "crypto_agent", "forensics_agent",
    "code_audit_agent", "source_code_agent", "code_analyze_agent",
]

_AGENT_CLASS: Optional[Dict[str, Any]] = None


def _agent_classes() -> Dict[str, Any]:
    """懒加载 agent_id → 类 map。构造/导入失败的单 agent 记录 error 不阻塞其余。"""
    global _AGENT_CLASS
    if _AGENT_CLASS is not None:
        return _AGENT_CLASS
    classes: Dict[str, Any] = {}
    specs = [
        ("recon_agent", "kali_mcp.agents.information_gathering.recon_agent", "ReconAgent"),
        ("subdomain_agent", "kali_mcp.agents.information_gathering.subdomain_agent", "SubdomainAgent"),
        ("web_recon_agent", "kali_mcp.agents.information_gathering.web_recon_agent", "WebReconAgent"),
        ("vuln_scanner_agent", "kali_mcp.agents.vulnerability_discovery.vuln_scanner_agent", "VulnScannerAgent"),
        ("web_vuln_agent", "kali_mcp.agents.vulnerability_discovery.web_vuln_agent", "WebVulnAgent"),
        ("auth_agent", "kali_mcp.agents.vulnerability_discovery.auth_agent", "AuthAgent"),
        ("network_vuln_agent", "kali_mcp.agents.vulnerability_discovery.network_vuln_agent", "NetworkVulnAgent"),
        ("vuln_verifier_agent", "kali_mcp.agents.vulnerability_discovery.vuln_verifier_agent", "VulnVerifierAgent"),
        ("exploit_agent", "kali_mcp.agents.exploitation.exploit_agent", "ExploitAgent"),
        ("privilege_agent", "kali_mcp.agents.exploitation.privilege_agent", "PrivilegeAgent"),
        ("lateral_agent", "kali_mcp.agents.exploitation.lateral_agent", "LateralAgent"),
        ("pwn_agent", "kali_mcp.agents.specialized.pwn_agent", "PwnAgent"),
        ("crypto_agent", "kali_mcp.agents.specialized.crypto_agent", "CryptoAgent"),
        ("forensics_agent", "kali_mcp.agents.specialized.forensics_agent", "ForensicsAgent"),
        ("code_audit_agent", "kali_mcp.agents.specialized.code_audit_agent", "CodeAuditAgent"),
        ("source_code_agent", "kali_mcp.agents.specialized.source_code_agent", "SourceCodeAgent"),
        ("code_analyze_agent", "kali_mcp.agents.specialized.code_analyze_agent", "CodeAnalyzeAgent"),
    ]
    for agent_id, module_path, cls_name in specs:
        try:
            mod = __import__(module_path, fromlist=[cls_name])
            classes[agent_id] = getattr(mod, cls_name)
        except Exception as e:  # noqa: BLE001 —— 单 agent 失败不阻塞其余
            logger.warning("[extract_findings] %s 导入失败: %s", agent_id, e)
    _AGENT_CLASS = classes
    return classes


def extract_findings_impl(
    agent_id: str,
    tool_name: str,
    output: str,
    target: str,
) -> Dict[str, Any]:
    """提炼工具输出为结构化 Finding 列表（复用 agent 解析器）。

    Returns:
        {agent_id, tool_name, target, findings:[{type, severity, title, description,
         evidence, confidence, source}], error?}
    """
    cls = _agent_classes().get(agent_id)
    if cls is None:
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "target": target,
            "findings": [],
            "error": f"unknown agent_id {agent_id!r}（合法: {AGENT_IDS}）",
        }
    try:
        agent = cls()  # 全空构造：解析器仅依赖 self.agent_id + 入参
    except Exception as e:  # noqa: BLE001 —— 构造失败不阻塞其他 agent
        logger.warning("[extract_findings] %s 构造失败: %s", agent_id, e)
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "target": target,
            "findings": [],
            "error": f"agent 构造失败: {e}",
        }
    try:
        findings = agent._parse_tool_output(tool_name, output, target)
        out = []
        for f in findings or []:
            d = agent._finding_to_dict(f)
            d["source"] = agent_id  # 覆盖解析器写死的 self.agent_id
            out.append(d)
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "target": target,
            "findings": out,
        }
    except Exception as e:  # noqa: BLE001 —— 解析失败返回空 + 错误信息
        logger.warning("[extract_findings] %s 解析 %s 失败: %s", agent_id, tool_name, e)
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "target": target,
            "findings": [],
            "error": str(e),
        }


def register_extract_findings_tools(mcp, executor):
    """注册证据提炼工具（harness 档位）。"""

    @mcp.tool()
    def extract_findings(
        agent_id: str,
        tool_name: str,
        output: str,
        target: str = "",
    ) -> Dict[str, Any]:
        """把工具原始输出提炼为结构化 Finding 证据（确定性正则，LLM 透明）。

        每次扫描/枚举工具调用后自动调用：hook 或子代理把 tool_name + 原始 output
        交给本工具，返回 {findings: [{type, severity, title, description, evidence,
        confidence, source}]}。evidence 只来自真实工具输出的正则匹配，
        禁止 LLM 自编证据。

        Args:
            agent_id: 解析器归属（17 个专业 agent，如 recon_agent/web_vuln_agent）
            tool_name: 调用的 MCP 工具名（如 fastsec_scan/nmap_scan/kali_run）
            output: 工具原始输出文本
            target: 测试目标（IP/域名/URL）

        Returns:
            {agent_id, tool_name, target, findings:[...], [error]}
        """
        return extract_findings_impl(agent_id, tool_name, output, target)
