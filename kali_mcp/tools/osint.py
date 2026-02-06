#!/usr/bin/env python3
"""
OSINT开源情报工具模块

包含信息收集和OSINT工具:
- subfinder_scan: 子域名发现
- theharvester_osint: 邮箱/域名收集
- dnsrecon_scan: DNS枚举
- sherlock_search: 用户名搜索
- amass_enum: 高级子域名枚举
"""

import asyncio
import re
import json
import logging
from typing import Dict, List, Optional, Any

from .base import (
    BaseTool,
    ToolResult,
    ToolCategory,
    RiskLevel,
    Finding,
    tool,
    get_registry
)
from ..core.executor import get_executor, ExecutionResult
from ..core.cache import get_tool_cache

logger = logging.getLogger(__name__)


@tool(
    name="subfinder_scan",
    category=ToolCategory.OSINT,
    description="Subfinder子域名发现 - 快速被动子域名枚举",
    risk_level=RiskLevel.INFO,
    timeout=300
)
class SubfinderScan(BaseTool):
    """Subfinder扫描工具"""

    async def execute(
        self,
        domain: str,
        sources: str = "",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Subfinder扫描

        Args:
            domain: 目标域名
            sources: 数据源
            additional_args: 额外参数
        """
        cache = get_tool_cache()
        cache_params = {"sources": sources}
        hit, cached = cache.get("subfinder_scan", domain, cache_params)
        if hit:
            result = ToolResult(**cached)
            result.cache_hit = True
            return result

        cmd_parts = ["subfinder", "-d", domain, "-silent"]

        if sources:
            cmd_parts.extend(["-sources", sources])

        if additional_args:
            cmd_parts.append(additional_args)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="subfinder_scan",
            target=domain,
            raw_output=exec_result.stdout
        )

        # 解析子域名
        for line in exec_result.stdout.strip().split('\n'):
            subdomain = line.strip()
            if subdomain and '.' in subdomain:
                result.add_finding(
                    finding_type="subdomain",
                    value=subdomain,
                    severity="info"
                )

        subdomains = [f.value for f in result.findings if f.finding_type == "subdomain"]
        if subdomains:
            result.summary = f"发现 {len(subdomains)} 个子域名"
            result.suggest_next_step("对发现的子域名进行端口扫描", "nmap_scan")
            result.suggest_next_step("使用 httpx 探测存活", "httpx_probe")

            # 缓存结果
            cache.set("subfinder_scan", domain, result.to_dict(), cache_params)
        else:
            result.summary = "未发现子域名"

        return result


@tool(
    name="theharvester_osint",
    category=ToolCategory.OSINT,
    description="theHarvester信息收集 - 邮箱、子域名、IP收集",
    risk_level=RiskLevel.INFO,
    timeout=300
)
class TheHarvesterOsint(BaseTool):
    """theHarvester工具"""

    async def execute(
        self,
        domain: str,
        sources: str = "google,bing,yahoo",
        limit: str = "500",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """执行theHarvester收集"""
        cmd = f"theHarvester -d {domain} -b {sources} -l {limit} {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="theharvester_osint",
            target=domain,
            raw_output=exec_result.stdout
        )

        # 解析邮箱
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        for match in re.finditer(email_pattern, exec_result.stdout):
            email = match.group(0)
            if domain.lower() in email.lower():
                result.add_finding(
                    finding_type="email",
                    value=email,
                    severity="low"
                )

        # 解析主机
        host_pattern = r'(\S+\.' + re.escape(domain) + r')'
        for match in re.finditer(host_pattern, exec_result.stdout, re.IGNORECASE):
            result.add_finding(
                finding_type="subdomain",
                value=match.group(1),
                severity="info"
            )

        emails = [f for f in result.findings if f.finding_type == "email"]
        subdomains = [f for f in result.findings if f.finding_type == "subdomain"]

        parts = []
        if emails:
            parts.append(f"{len(emails)}个邮箱")
        if subdomains:
            parts.append(f"{len(subdomains)}个子域名")

        result.summary = f"收集到: {', '.join(parts)}" if parts else "未收集到信息"

        return result


@tool(
    name="dnsrecon_scan",
    category=ToolCategory.OSINT,
    description="DNSrecon DNS枚举 - 全面的DNS信息收集",
    risk_level=RiskLevel.INFO,
    timeout=300
)
class DnsreconScan(BaseTool):
    """DNSrecon扫描工具"""

    async def execute(
        self,
        domain: str,
        scan_type: str = "-t std",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """执行DNSrecon扫描"""
        cmd = f"dnsrecon -d {domain} {scan_type} {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="dnsrecon_scan",
            target=domain,
            raw_output=exec_result.stdout
        )

        # 解析DNS记录
        record_patterns = [
            (r'A\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)', 'A'),
            (r'AAAA\s+(\S+)\s+(\S+)', 'AAAA'),
            (r'MX\s+(\S+)\s+(\S+)', 'MX'),
            (r'NS\s+(\S+)', 'NS'),
            (r'TXT\s+(\S+)', 'TXT'),
        ]

        for pattern, record_type in record_patterns:
            for match in re.finditer(pattern, exec_result.stdout):
                result.add_finding(
                    finding_type="dns_record",
                    value=match.group(0),
                    severity="info",
                    record_type=record_type
                )

        records = result.findings
        result.summary = f"发现 {len(records)} 条DNS记录" if records else "未发现DNS记录"

        return result


@tool(
    name="sherlock_search",
    category=ToolCategory.OSINT,
    description="Sherlock用户名搜索 - 跨平台社交账号查找",
    risk_level=RiskLevel.INFO,
    timeout=300
)
class SherlockSearch(BaseTool):
    """Sherlock搜索工具"""

    async def execute(
        self,
        username: str,
        sites: str = "",
        output_format: str = "json",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Sherlock搜索

        Args:
            username: 要搜索的用户名
            sites: 指定搜索的站点
            output_format: 输出格式
            additional_args: 额外参数
        """
        cmd_parts = ["sherlock", username]

        if sites:
            cmd_parts.extend(["--site", sites])

        cmd_parts.extend(["--print-found"])

        if additional_args:
            cmd_parts.append(additional_args)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="sherlock_search",
            target=username,
            raw_output=exec_result.stdout
        )

        # 解析发现的账号
        url_pattern = r'(https?://\S+)'
        for match in re.finditer(url_pattern, exec_result.stdout):
            url = match.group(1)
            result.add_finding(
                finding_type="social_account",
                value=url,
                severity="info"
            )

        accounts = [f for f in result.findings if f.finding_type == "social_account"]
        result.summary = f"发现 {len(accounts)} 个社交账号" if accounts else "未发现社交账号"

        return result


@tool(
    name="amass_enum",
    category=ToolCategory.OSINT,
    description="Amass子域名枚举 - 高级资产发现工具",
    risk_level=RiskLevel.INFO,
    timeout=600
)
class AmassEnum(BaseTool):
    """Amass枚举工具"""

    async def execute(
        self,
        domain: str,
        mode: str = "enum",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """执行Amass枚举"""
        cmd = f"amass {mode} -d {domain} -passive {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="amass_enum",
            target=domain,
            raw_output=exec_result.stdout
        )

        # 解析子域名
        for line in exec_result.stdout.strip().split('\n'):
            subdomain = line.strip()
            if subdomain and domain in subdomain:
                result.add_finding(
                    finding_type="subdomain",
                    value=subdomain,
                    severity="info"
                )

        subdomains = [f for f in result.findings if f.finding_type == "subdomain"]
        result.summary = f"发现 {len(subdomains)} 个子域名" if subdomains else "未发现子域名"

        return result


__all__ = [
    "SubfinderScan",
    "TheHarvesterOsint",
    "DnsreconScan",
    "SherlockSearch",
    "AmassEnum",
]
