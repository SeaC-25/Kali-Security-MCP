#!/usr/bin/env python3
"""
健康检查模块

检查系统和工具的健康状态:
- 工具可用性检查
- 系统资源检查
- 服务状态检查
"""

import asyncio
import logging
import shutil
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """健康状态"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ToolHealth:
    """工具健康状态"""
    tool_name: str
    available: bool
    version: str = ""
    path: str = ""
    last_check: Optional[datetime] = None
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "available": self.available,
            "version": self.version,
            "path": self.path,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "error": self.error
        }


@dataclass
class SystemHealth:
    """系统健康状态"""
    status: HealthStatus
    cpu_usage: float = 0
    memory_usage: float = 0
    disk_usage: float = 0
    tools_available: int = 0
    tools_missing: int = 0
    last_check: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "disk_usage": self.disk_usage,
            "tools_available": self.tools_available,
            "tools_missing": self.tools_missing,
            "last_check": self.last_check.isoformat() if self.last_check else None
        }


class HealthChecker:
    """健康检查器"""

    # 核心工具列表
    CORE_TOOLS = [
        "nmap", "masscan", "gobuster", "nikto", "sqlmap",
        "hydra", "john", "hashcat", "nuclei", "ffuf",
        "whatweb", "wpscan", "searchsploit", "enum4linux",
        "subfinder", "amass", "dnsrecon", "theharvester",
        "binwalk", "checksec", "r2", "objdump"
    ]

    # 可选工具列表
    OPTIONAL_TOOLS = [
        "feroxbuster", "wfuzz", "medusa", "ncrack",
        "aircrack-ng", "reaver", "bettercap", "ettercap",
        "responder", "sherlock", "ghidra"
    ]

    def __init__(self):
        """初始化健康检查器"""
        self.tool_status: Dict[str, ToolHealth] = {}
        self.system_health: Optional[SystemHealth] = None
        self._last_full_check: Optional[datetime] = None
        logger.info("HealthChecker 初始化完成")

    async def check_tool(self, tool_name: str) -> ToolHealth:
        """
        检查单个工具

        Args:
            tool_name: 工具名称

        Returns:
            工具健康状态
        """
        health = ToolHealth(
            tool_name=tool_name,
            available=False,
            last_check=datetime.now()
        )

        # 检查工具是否存在
        tool_path = shutil.which(tool_name)
        if tool_path:
            health.available = True
            health.path = tool_path

            # 尝试获取版本
            try:
                version = await self._get_tool_version(tool_name)
                health.version = version
            except Exception as e:
                health.version = "unknown"
                logger.debug(f"无法获取 {tool_name} 版本: {e}")
        else:
            health.error = f"{tool_name} 未找到"

        self.tool_status[tool_name] = health
        return health

    async def _get_tool_version(self, tool_name: str) -> str:
        """获取工具版本"""
        version_args = {
            "nmap": ["-V"],
            "masscan": ["--version"],
            "gobuster": ["version"],
            "nikto": ["-Version"],
            "sqlmap": ["--version"],
            "hydra": ["-h"],
            "john": ["--version"],
            "nuclei": ["-version"],
            "ffuf": ["-V"],
            "whatweb": ["--version"],
        }

        args = version_args.get(tool_name, ["--version"])

        try:
            proc = await asyncio.create_subprocess_exec(
                tool_name, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode() or stderr.decode()

            # 提取第一行作为版本
            lines = output.strip().split('\n')
            if lines:
                return lines[0][:50]  # 限制长度
        except Exception:
            pass

        return "unknown"

    async def check_all_tools(self) -> Dict[str, ToolHealth]:
        """
        检查所有工具

        Returns:
            所有工具的健康状态
        """
        all_tools = self.CORE_TOOLS + self.OPTIONAL_TOOLS

        # 并行检查
        tasks = [self.check_tool(tool) for tool in all_tools]
        await asyncio.gather(*tasks, return_exceptions=True)

        self._last_full_check = datetime.now()
        return self.tool_status

    def check_system_resources(self) -> Dict[str, float]:
        """
        检查系统资源

        Returns:
            资源使用情况
        """
        resources = {
            "cpu_usage": 0,
            "memory_usage": 0,
            "disk_usage": 0
        }

        try:
            # CPU使用率
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
                cpu_count = os.cpu_count() or 1
                resources["cpu_usage"] = min(100, (load / cpu_count) * 100)
        except Exception:
            pass

        try:
            # 内存使用率
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = int(parts[1].strip().split()[0])
                        meminfo[key] = value

                total = meminfo.get('MemTotal', 1)
                available = meminfo.get('MemAvailable', 0)
                resources["memory_usage"] = ((total - available) / total) * 100
        except Exception:
            pass

        try:
            # 磁盘使用率
            statvfs = os.statvfs('/')
            total = statvfs.f_blocks * statvfs.f_frsize
            free = statvfs.f_bfree * statvfs.f_frsize
            resources["disk_usage"] = ((total - free) / total) * 100
        except Exception:
            pass

        return resources

    async def get_system_health(self) -> SystemHealth:
        """
        获取系统健康状态

        Returns:
            系统健康状态
        """
        # 检查资源
        resources = self.check_system_resources()

        # 统计工具状态
        available = sum(1 for h in self.tool_status.values() if h.available)
        missing = len(self.CORE_TOOLS) - sum(
            1 for t in self.CORE_TOOLS
            if self.tool_status.get(t, ToolHealth(t, False)).available
        )

        # 判断健康状态
        if missing > len(self.CORE_TOOLS) * 0.3:
            status = HealthStatus.UNHEALTHY
        elif missing > 0 or resources["memory_usage"] > 90:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        self.system_health = SystemHealth(
            status=status,
            cpu_usage=resources["cpu_usage"],
            memory_usage=resources["memory_usage"],
            disk_usage=resources["disk_usage"],
            tools_available=available,
            tools_missing=missing,
            last_check=datetime.now()
        )

        return self.system_health

    async def full_health_check(self) -> Dict[str, Any]:
        """
        执行完整健康检查

        Returns:
            完整健康报告
        """
        # 检查所有工具
        await self.check_all_tools()

        # 获取系统健康
        system_health = await self.get_system_health()

        # 生成报告
        report = {
            "status": system_health.status.value,
            "timestamp": datetime.now().isoformat(),
            "system": system_health.to_dict(),
            "core_tools": {
                tool: self.tool_status.get(tool, ToolHealth(tool, False)).to_dict()
                for tool in self.CORE_TOOLS
            },
            "optional_tools": {
                tool: self.tool_status.get(tool, ToolHealth(tool, False)).to_dict()
                for tool in self.OPTIONAL_TOOLS
            },
            "summary": {
                "core_available": sum(
                    1 for t in self.CORE_TOOLS
                    if self.tool_status.get(t, ToolHealth(t, False)).available
                ),
                "core_total": len(self.CORE_TOOLS),
                "optional_available": sum(
                    1 for t in self.OPTIONAL_TOOLS
                    if self.tool_status.get(t, ToolHealth(t, False)).available
                ),
                "optional_total": len(self.OPTIONAL_TOOLS)
            }
        }

        return report

    def get_missing_tools(self) -> List[str]:
        """获取缺失的核心工具"""
        missing = []
        for tool in self.CORE_TOOLS:
            health = self.tool_status.get(tool)
            if not health or not health.available:
                missing.append(tool)
        return missing

    def get_quick_status(self) -> Dict[str, Any]:
        """
        获取快速状态（不执行检查）

        Returns:
            当前缓存的状态
        """
        return {
            "status": self.system_health.status.value if self.system_health else "unknown",
            "last_check": self._last_full_check.isoformat() if self._last_full_check else None,
            "tools_checked": len(self.tool_status),
            "tools_available": sum(1 for h in self.tool_status.values() if h.available)
        }


# 全局实例
_global_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """获取全局健康检查器"""
    global _global_checker
    if _global_checker is None:
        _global_checker = HealthChecker()
    return _global_checker
