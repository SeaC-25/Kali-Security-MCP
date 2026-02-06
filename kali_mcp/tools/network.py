#!/usr/bin/env python3
"""
网络侦察工具模块

包含网络扫描、端口发现、服务识别等工具:
- nmap_scan: Nmap端口扫描
- masscan_fast_scan: Masscan高速扫描
- arp_scan: ARP网络发现
- fping_scan: ICMP主机发现
- netdiscover_scan: 网络发现
- zmap_scan: Zmap大规模扫描
"""

import asyncio
import re
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
    name="nmap_scan",
    category=ToolCategory.NETWORK,
    description="Nmap网络扫描器 - 端口扫描、服务识别、版本检测",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class NmapScan(BaseTool):
    """Nmap扫描工具"""

    async def execute(
        self,
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = "",
        intelligent_optimization: bool = True,
        target_type: str = "unknown",
        time_constraint: str = "quick",
        stealth_mode: bool = False,
        **kwargs
    ) -> ToolResult:
        """
        执行Nmap扫描

        Args:
            target: 目标IP或主机名
            scan_type: 扫描类型 (-sS, -sV, -sC等)
            ports: 端口范围 (如 "1-1000" 或 "80,443,8080")
            additional_args: 额外参数
            intelligent_optimization: 是否启用智能优化
            target_type: 目标类型 (web, network, database)
            time_constraint: 时间约束 (quick, standard, thorough)
            stealth_mode: 隐蔽模式

        Returns:
            ToolResult
        """
        # 检查缓存
        cache = get_tool_cache()
        cache_params = {"scan_type": scan_type, "ports": ports, "args": additional_args}
        hit, cached = cache.get("nmap_scan", target, cache_params)
        if hit:
            result = ToolResult(**cached)
            result.cache_hit = True
            return result

        # 构建命令
        cmd = self._build_command(
            target, scan_type, ports, additional_args,
            intelligent_optimization, target_type, time_constraint, stealth_mode
        )

        # 执行扫描
        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        # 解析结果
        result = self._parse_output(target, exec_result)

        # 缓存结果
        if result.success:
            cache.set("nmap_scan", target, result.to_dict(), cache_params)

        return result

    def _build_command(
        self,
        target: str,
        scan_type: str,
        ports: str,
        additional_args: str,
        intelligent_optimization: bool,
        target_type: str,
        time_constraint: str,
        stealth_mode: bool
    ) -> str:
        """构建Nmap命令"""
        cmd_parts = ["nmap"]

        # 扫描类型
        cmd_parts.append(scan_type)

        # 端口设置
        if ports:
            cmd_parts.append(f"-p {ports}")
        elif time_constraint == "quick":
            cmd_parts.append("-p 21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389,5432,8080")

        # 时序优化
        if time_constraint == "quick":
            cmd_parts.append("-T4")
            cmd_parts.append("--max-retries 1")
            cmd_parts.append("--host-timeout 30s")
        elif time_constraint == "thorough":
            cmd_parts.append("-T3")
        else:
            cmd_parts.append("-T4")

        # 隐蔽模式
        if stealth_mode:
            cmd_parts.append("-T2")
            cmd_parts.append("--scan-delay 1s")

        # 额外参数
        if additional_args:
            cmd_parts.append(additional_args)

        # 目标
        cmd_parts.append(target)

        return " ".join(cmd_parts)

    def _parse_output(self, target: str, exec_result: ExecutionResult) -> ToolResult:
        """解析Nmap输出"""
        result = ToolResult(
            success=exec_result.success,
            tool_name="nmap_scan",
            target=target,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        output = exec_result.stdout

        # 解析开放端口
        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?'
        for match in re.finditer(port_pattern, output):
            port = match.group(1)
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5) or ""

            if state == "open":
                result.add_finding(
                    finding_type="port",
                    value=f"{port}/{protocol}",
                    severity="info",
                    service=service,
                    version=version.strip()
                )

                # 添加服务发现
                result.add_finding(
                    finding_type="service",
                    value=service,
                    severity="info",
                    port=port,
                    protocol=protocol,
                    version=version.strip()
                )

        # 生成摘要
        ports = result.get_ports()
        if ports:
            result.summary = f"发现 {len(ports)} 个开放端口: {', '.join(ports[:5])}"
            if len(ports) > 5:
                result.summary += f" 等"

            # 推荐下一步
            for port_str in ports:
                port = port_str.split('/')[0]
                if port in ['80', '443', '8080', '8443']:
                    result.suggest_next_step("发现Web端口，建议扫描目录", "gobuster_scan")
                elif port == '22':
                    result.suggest_next_step("发现SSH服务，可尝试弱口令", "hydra_attack")
                elif port in ['3306', '5432', '1433']:
                    result.suggest_next_step("发现数据库端口，可尝试SQL注入", "sqlmap_scan")
        else:
            result.summary = "未发现开放端口"

        # 检测Flag
        flags = result.extract_flags(output)
        result.flags_found.extend(flags)

        return result


@tool(
    name="masscan_fast_scan",
    category=ToolCategory.NETWORK,
    description="Masscan高速端口扫描器 - 大规模网络快速扫描",
    risk_level=RiskLevel.MEDIUM,
    timeout=120
)
class MasscanFastScan(BaseTool):
    """Masscan高速扫描工具"""

    async def execute(
        self,
        target: str,
        ports: str = "80,443,22,21,25,53,110,143,993,995,8080,8443",
        rate: str = "10000",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Masscan快速扫描

        Args:
            target: 目标IP或网段
            ports: 要扫描的端口
            rate: 扫描速率(每秒包数)
            additional_args: 额外参数
        """
        cmd = f"masscan {target} -p {ports} --rate={rate} {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="masscan_fast_scan",
            target=target,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析结果
        port_pattern = r'Discovered open port (\d+)/(tcp|udp) on ([\d.]+)'
        for match in re.finditer(port_pattern, exec_result.stdout):
            port = match.group(1)
            protocol = match.group(2)
            ip = match.group(3)

            result.add_finding(
                finding_type="port",
                value=f"{port}/{protocol}",
                severity="info",
                ip=ip
            )

        ports_found = result.get_ports()
        if ports_found:
            result.summary = f"快速扫描发现 {len(ports_found)} 个开放端口"
            result.suggest_next_step("建议使用nmap进行详细服务识别", "nmap_scan")
        else:
            result.summary = "快速扫描未发现开放端口"

        return result


@tool(
    name="arp_scan",
    category=ToolCategory.NETWORK,
    description="ARP扫描器 - 本地网络主机发现",
    risk_level=RiskLevel.INFO,
    timeout=60
)
class ArpScan(BaseTool):
    """ARP扫描工具"""

    async def execute(
        self,
        interface: str = "",
        network: str = "--local",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行ARP扫描

        Args:
            interface: 网络接口
            network: 网络范围或--local
            additional_args: 额外参数
        """
        cmd_parts = ["arp-scan"]

        if interface:
            cmd_parts.append(f"-I {interface}")

        cmd_parts.append(network)

        if additional_args:
            cmd_parts.append(additional_args)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="arp_scan",
            target=network,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析结果
        host_pattern = r'([\d.]+)\s+([\w:]+)\s+(.+)'
        for match in re.finditer(host_pattern, exec_result.stdout):
            ip = match.group(1)
            mac = match.group(2)
            vendor = match.group(3).strip()

            result.add_finding(
                finding_type="host",
                value=ip,
                severity="info",
                mac=mac,
                vendor=vendor
            )

        hosts_found = [f.value for f in result.findings if f.finding_type == "host"]
        if hosts_found:
            result.summary = f"发现 {len(hosts_found)} 个活跃主机"
            result.suggest_next_step("对发现的主机进行端口扫描", "nmap_scan")
        else:
            result.summary = "未发现活跃主机"

        return result


@tool(
    name="fping_scan",
    category=ToolCategory.NETWORK,
    description="Fping批量主机探测 - 快速ICMP存活检测",
    risk_level=RiskLevel.INFO,
    timeout=60
)
class FpingScan(BaseTool):
    """Fping扫描工具"""

    async def execute(
        self,
        targets: str,
        count: str = "3",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Fping扫描

        Args:
            targets: 目标主机或网段
            count: ping次数
            additional_args: 额外参数
        """
        cmd = f"fping -c {count} -g {targets} {additional_args} 2>&1"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=True,  # fping总是有输出
            tool_name="fping_scan",
            target=targets,
            raw_output=exec_result.stdout
        )

        # 解析存活主机
        alive_pattern = r'([\d.]+)\s*:\s*\[\d+\],\s*\d+ bytes'
        for match in re.finditer(alive_pattern, exec_result.stdout):
            ip = match.group(1)
            result.add_finding(
                finding_type="host",
                value=ip,
                severity="info"
            )

        hosts_found = [f.value for f in result.findings if f.finding_type == "host"]
        if hosts_found:
            result.summary = f"发现 {len(hosts_found)} 个存活主机"
        else:
            result.summary = "未发现存活主机"

        return result


@tool(
    name="netdiscover_scan",
    category=ToolCategory.NETWORK,
    description="Netdiscover网络发现工具 - ARP被动/主动扫描",
    risk_level=RiskLevel.INFO,
    timeout=60
)
class NetdiscoverScan(BaseTool):
    """Netdiscover扫描工具"""

    async def execute(
        self,
        interface: str = "",
        range_ip: str = "",
        passive: bool = False,
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Netdiscover扫描

        Args:
            interface: 网络接口
            range_ip: IP范围
            passive: 被动模式
            additional_args: 额外参数
        """
        cmd_parts = ["netdiscover", "-P"]  # -P 以可解析格式输出

        if interface:
            cmd_parts.append(f"-i {interface}")

        if range_ip:
            cmd_parts.append(f"-r {range_ip}")

        if passive:
            cmd_parts.append("-p")

        if additional_args:
            cmd_parts.append(additional_args)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="netdiscover_scan",
            target=range_ip or "local",
            raw_output=exec_result.stdout
        )

        # 解析结果
        for line in exec_result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                result.add_finding(
                    finding_type="host",
                    value=parts[0],
                    severity="info",
                    mac=parts[1] if len(parts) > 1 else "",
                    vendor=" ".join(parts[2:]) if len(parts) > 2 else ""
                )

        hosts = [f.value for f in result.findings if f.finding_type == "host"]
        result.summary = f"发现 {len(hosts)} 个主机" if hosts else "未发现主机"

        return result


@tool(
    name="zmap_scan",
    category=ToolCategory.NETWORK,
    description="Zmap网络扫描器 - 互联网级别高速扫描",
    risk_level=RiskLevel.HIGH,
    timeout=180
)
class ZmapScan(BaseTool):
    """Zmap扫描工具"""
    requires_root = True

    async def execute(
        self,
        target: str,
        port: str = "80",
        rate: str = "10000",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Zmap扫描

        Args:
            target: 目标网络或IP范围
            port: 要扫描的端口
            rate: 扫描速率
            additional_args: 额外参数
        """
        cmd = f"zmap -p {port} -r {rate} {target} {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="zmap_scan",
            target=target,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析结果 - Zmap输出IP列表
        for line in exec_result.stdout.strip().split('\n'):
            ip = line.strip()
            if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                result.add_finding(
                    finding_type="host",
                    value=ip,
                    severity="info",
                    port=port
                )

        hosts = [f.value for f in result.findings if f.finding_type == "host"]
        result.summary = f"发现 {len(hosts)} 个主机开放端口 {port}" if hosts else f"未发现开放端口 {port} 的主机"

        return result


# 导出所有工具类
__all__ = [
    "NmapScan",
    "MasscanFastScan",
    "ArpScan",
    "FpingScan",
    "NetdiscoverScan",
    "ZmapScan",
]
