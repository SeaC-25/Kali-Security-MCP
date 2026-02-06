#!/usr/bin/env python3
"""
Web安全工具模块

包含Web应用安全测试工具:
- gobuster_scan: 目录扫描
- nikto_scan: Web服务器扫描
- sqlmap_scan: SQL注入检测
- nuclei_scan: 漏洞扫描
- whatweb_scan: 技术识别
- ffuf_scan: 模糊测试
- feroxbuster_scan: 目录枚举
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
    name="gobuster_scan",
    category=ToolCategory.WEB,
    description="Gobuster目录扫描器 - 目录/DNS/虚拟主机枚举",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class GobusterScan(BaseTool):
    """Gobuster扫描工具"""

    async def execute(
        self,
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
        intelligent_optimization: bool = True,
        target_type: str = "web",
        time_constraint: str = "quick",
        stealth_mode: bool = False,
        **kwargs
    ) -> ToolResult:
        """
        执行Gobuster扫描

        Args:
            url: 目标URL
            mode: 扫描模式 (dir, dns, fuzz, vhost)
            wordlist: 字典文件路径
            additional_args: 额外参数
        """
        # 检查缓存
        cache = get_tool_cache()
        cache_params = {"mode": mode, "wordlist": wordlist}
        hit, cached = cache.get("gobuster_scan", url, cache_params)
        if hit:
            result = ToolResult(**cached)
            result.cache_hit = True
            return result

        # 构建命令
        cmd = self._build_command(url, mode, wordlist, additional_args, time_constraint, stealth_mode)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = self._parse_output(url, mode, exec_result)

        if result.success:
            cache.set("gobuster_scan", url, result.to_dict(), cache_params)

        return result

    def _build_command(
        self,
        url: str,
        mode: str,
        wordlist: str,
        additional_args: str,
        time_constraint: str,
        stealth_mode: bool
    ) -> str:
        """构建Gobuster命令"""
        cmd_parts = ["gobuster", mode, "-u", url, "-w", wordlist]

        # 线程设置
        if time_constraint == "quick":
            cmd_parts.extend(["-t", "50"])
            if mode == "dir":
                wordlist = "/usr/share/wordlists/dirb/small.txt"
        else:
            cmd_parts.extend(["-t", "20"])

        # 隐蔽模式
        if stealth_mode:
            cmd_parts.extend(["-t", "5", "--delay", "500ms"])

        # 静默模式
        cmd_parts.append("-q")

        if additional_args:
            cmd_parts.append(additional_args)

        return " ".join(cmd_parts)

    def _parse_output(self, url: str, mode: str, exec_result: ExecutionResult) -> ToolResult:
        """解析Gobuster输出"""
        result = ToolResult(
            success=exec_result.success,
            tool_name="gobuster_scan",
            target=url,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析发现的目录/文件
        for line in exec_result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue

            # 提取路径和状态码
            match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
            if match:
                path = match.group(1)
                status = match.group(2)

                # 根据状态码设置严重程度
                severity = "info"
                if status in ["200", "301", "302"]:
                    severity = "low"
                if "/admin" in path.lower() or "/login" in path.lower():
                    severity = "medium"

                result.add_finding(
                    finding_type="directory",
                    value=path,
                    severity=severity,
                    status_code=status
                )

        dirs = [f.value for f in result.findings if f.finding_type == "directory"]
        if dirs:
            result.summary = f"发现 {len(dirs)} 个目录/文件"

            # 推荐下一步
            for d in dirs[:5]:
                if "admin" in d.lower():
                    result.suggest_next_step(f"发现管理目录 {d}，尝试默认凭据", "hydra_attack")
                elif "upload" in d.lower():
                    result.suggest_next_step(f"发现上传功能 {d}，可尝试文件上传绕过")
                elif "api" in d.lower():
                    result.suggest_next_step(f"发现API接口 {d}，可进一步测试", "nuclei_scan")
        else:
            result.summary = "未发现目录"

        # 检测Flag
        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="nikto_scan",
    category=ToolCategory.WEB,
    description="Nikto Web服务器扫描器 - 检测危险文件和配置问题",
    risk_level=RiskLevel.MEDIUM,
    timeout=600
)
class NiktoScan(BaseTool):
    """Nikto扫描工具"""

    async def execute(
        self,
        target: str,
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """执行Nikto扫描"""
        cmd = f"nikto -h {target} -Format txt {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="nikto_scan",
            target=target,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析漏洞发现
        vuln_patterns = [
            (r'OSVDB-\d+', 'vulnerability'),
            (r'CVE-\d+-\d+', 'vulnerability'),
            (r'/\S+\.php', 'file'),
            (r'/\S+\.bak', 'file'),
            (r'/\S+\.old', 'file'),
        ]

        for pattern, finding_type in vuln_patterns:
            for match in re.finditer(pattern, exec_result.stdout):
                result.add_finding(
                    finding_type=finding_type,
                    value=match.group(0),
                    severity="medium"
                )

        vulns = result.get_vulnerabilities()
        if vulns:
            result.summary = f"发现 {len(vulns)} 个潜在漏洞"
            result.suggest_next_step("使用 nuclei_scan 进行深入漏洞扫描", "nuclei_scan")
        else:
            result.summary = "未发现明显漏洞"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="sqlmap_scan",
    category=ToolCategory.WEB,
    description="SQLMap SQL注入扫描器 - 自动化SQL注入检测和利用",
    risk_level=RiskLevel.HIGH,
    timeout=600
)
class SqlmapScan(BaseTool):
    """SQLMap扫描工具"""

    async def execute(
        self,
        url: str,
        data: str = "",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行SQLMap扫描

        Args:
            url: 目标URL
            data: POST数据
            additional_args: 额外参数
        """
        cmd_parts = ["sqlmap", "-u", f'"{url}"', "--batch"]

        if data:
            cmd_parts.extend(["--data", f'"{data}"'])

        # 默认参数
        if not additional_args:
            additional_args = "--level=2 --risk=2"

        cmd_parts.append(additional_args)
        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="sqlmap_scan",
            target=url,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析注入点
        if "is vulnerable" in exec_result.stdout.lower():
            # 提取注入参数
            param_match = re.search(r"Parameter:\s*(\S+)", exec_result.stdout)
            param = param_match.group(1) if param_match else "unknown"

            result.add_finding(
                finding_type="vulnerability",
                value="SQL Injection",
                severity="critical",
                parameter=param
            )

            # 提取数据库类型
            db_match = re.search(r"back-end DBMS:\s*(.+)", exec_result.stdout)
            if db_match:
                result.add_finding(
                    finding_type="database",
                    value=db_match.group(1).strip(),
                    severity="info"
                )

            result.summary = f"发现SQL注入漏洞 (参数: {param})"
            result.suggest_next_step("使用 --dbs 枚举数据库")
            result.suggest_next_step("使用 --dump 导出数据")
        else:
            result.summary = "未发现SQL注入漏洞"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="nuclei_scan",
    category=ToolCategory.WEB,
    description="Nuclei漏洞扫描器 - 基于模板的快速漏洞检测",
    risk_level=RiskLevel.MEDIUM,
    timeout=300
)
class NucleiScan(BaseTool):
    """Nuclei扫描工具"""

    async def execute(
        self,
        target: str,
        templates: str = "",
        severity: str = "critical,high,medium",
        tags: str = "",
        output_format: str = "json",
        **kwargs
    ) -> ToolResult:
        """
        执行Nuclei扫描

        Args:
            target: 目标URL
            templates: 模板路径
            severity: 严重级别过滤
            tags: 标签过滤
            output_format: 输出格式
        """
        cmd_parts = ["nuclei", "-u", target, "-silent"]

        if templates:
            cmd_parts.extend(["-t", templates])

        if severity:
            cmd_parts.extend(["-s", severity])

        if tags:
            cmd_parts.extend(["-tags", tags])

        cmd_parts.extend(["-j"])  # JSON输出

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="nuclei_scan",
            target=target,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析JSON结果
        for line in exec_result.stdout.strip().split('\n'):
            if not line:
                continue
            try:
                finding = json.loads(line)
                result.add_finding(
                    finding_type="vulnerability",
                    value=finding.get("template-id", "unknown"),
                    severity=finding.get("info", {}).get("severity", "info"),
                    name=finding.get("info", {}).get("name", ""),
                    matched_at=finding.get("matched-at", ""),
                    description=finding.get("info", {}).get("description", "")
                )
            except json.JSONDecodeError:
                # 非JSON行，可能是文本格式
                if "critical" in line.lower() or "high" in line.lower():
                    result.add_finding(
                        finding_type="vulnerability",
                        value=line,
                        severity="high"
                    )

        vulns = result.get_vulnerabilities()
        if vulns:
            critical = sum(1 for v in vulns if v.get("severity") == "critical")
            high = sum(1 for v in vulns if v.get("severity") == "high")
            result.summary = f"发现 {len(vulns)} 个漏洞 (严重: {critical}, 高危: {high})"

            if critical > 0:
                result.suggest_next_step("存在严重漏洞，建议使用 searchsploit_search 查找利用代码", "searchsploit_search")
        else:
            result.summary = "未发现漏洞"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="whatweb_scan",
    category=ToolCategory.WEB,
    description="WhatWeb技术识别 - 识别网站使用的技术栈",
    risk_level=RiskLevel.INFO,
    timeout=120
)
class WhatwebScan(BaseTool):
    """WhatWeb扫描工具"""

    async def execute(
        self,
        target: str,
        aggression: str = "1",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """执行WhatWeb扫描"""
        cmd = f"whatweb -a {aggression} {target} {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="whatweb_scan",
            target=target,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析技术栈
        tech_patterns = [
            (r'WordPress', 'CMS'),
            (r'Joomla', 'CMS'),
            (r'Drupal', 'CMS'),
            (r'PHP\[([^\]]+)\]', 'Language'),
            (r'Apache\[([^\]]+)\]', 'Server'),
            (r'nginx\[([^\]]+)\]', 'Server'),
            (r'jQuery\[([^\]]+)\]', 'JavaScript'),
            (r'Bootstrap', 'Framework'),
        ]

        for pattern, tech_type in tech_patterns:
            match = re.search(pattern, exec_result.stdout, re.IGNORECASE)
            if match:
                result.add_finding(
                    finding_type="technology",
                    value=match.group(0),
                    severity="info",
                    type=tech_type
                )

        techs = [f.value for f in result.findings if f.finding_type == "technology"]
        if techs:
            result.summary = f"识别技术栈: {', '.join(techs[:5])}"

            # 根据技术推荐工具
            for tech in techs:
                if "wordpress" in tech.lower():
                    result.suggest_next_step("检测到WordPress，使用WPScan深入扫描", "wpscan_scan")
                elif "joomla" in tech.lower():
                    result.suggest_next_step("检测到Joomla，使用JoomScan扫描", "joomscan_scan")
        else:
            result.summary = "未能识别技术栈"

        return result


@tool(
    name="ffuf_scan",
    category=ToolCategory.WEB,
    description="FFUF模糊测试工具 - 快速Web模糊测试",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class FfufScan(BaseTool):
    """FFUF扫描工具"""

    async def execute(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        mode: str = "FUZZ",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行FFUF扫描

        Args:
            url: 目标URL (需包含FUZZ关键词)
            wordlist: 字典文件
            mode: 模糊测试模式
            additional_args: 额外参数
        """
        # 确保URL包含FUZZ关键词
        if "FUZZ" not in url:
            url = url.rstrip('/') + "/FUZZ"

        cmd = f"ffuf -u {url} -w {wordlist} -mc 200,301,302,403 -o /tmp/ffuf_result.json -of json {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="ffuf_scan",
            target=url,
            raw_output=exec_result.stdout
        )

        # 尝试读取JSON结果
        try:
            read_result = await executor.run_command("cat /tmp/ffuf_result.json")
            if read_result.success:
                data = json.loads(read_result.stdout)
                for res in data.get("results", []):
                    result.add_finding(
                        finding_type="directory",
                        value=res.get("input", {}).get("FUZZ", ""),
                        severity="info",
                        status_code=res.get("status", 0),
                        length=res.get("length", 0)
                    )
        except:
            pass

        dirs = [f.value for f in result.findings if f.finding_type == "directory"]
        result.summary = f"发现 {len(dirs)} 个路径" if dirs else "未发现路径"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="feroxbuster_scan",
    category=ToolCategory.WEB,
    description="Feroxbuster递归目录扫描 - 快速递归内容发现",
    risk_level=RiskLevel.LOW,
    timeout=300
)
class FeroxbusterScan(BaseTool):
    """Feroxbuster扫描工具"""

    async def execute(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        threads: str = "50",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """执行Feroxbuster扫描"""
        cmd = f"feroxbuster -u {url} -w {wordlist} -t {threads} -q {additional_args}"

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="feroxbuster_scan",
            target=url,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析结果
        for line in exec_result.stdout.split('\n'):
            match = re.search(r'(\d{3})\s+\S+\s+\S+\s+(\S+)', line)
            if match:
                status = match.group(1)
                path = match.group(2)
                result.add_finding(
                    finding_type="directory",
                    value=path,
                    severity="info",
                    status_code=status
                )

        dirs = [f.value for f in result.findings if f.finding_type == "directory"]
        result.summary = f"发现 {len(dirs)} 个路径" if dirs else "未发现路径"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="wpscan_scan",
    category=ToolCategory.WEB,
    description="WPScan WordPress扫描器 - WordPress专项安全检测",
    risk_level=RiskLevel.MEDIUM,
    timeout=600
)
class WpscanScan(BaseTool):
    """WPScan工具"""

    async def execute(
        self,
        target: str,
        api_token: str = "",
        additional_args: str = "--enumerate p,t,u",
        **kwargs
    ) -> ToolResult:
        """执行WPScan扫描"""
        cmd_parts = ["wpscan", "--url", target, "--no-banner"]

        if api_token:
            cmd_parts.extend(["--api-token", api_token])

        if additional_args:
            cmd_parts.append(additional_args)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="wpscan_scan",
            target=target,
            raw_output=exec_result.stdout
        )

        if not exec_result.success:
            result.error_message = exec_result.stderr or exec_result.error_message
            return result

        # 解析WordPress版本
        version_match = re.search(r'WordPress version:\s*(\S+)', exec_result.stdout)
        if version_match:
            result.add_finding(
                finding_type="version",
                value=f"WordPress {version_match.group(1)}",
                severity="info"
            )

        # 解析用户
        user_pattern = r'\[\+\]\s*(\w+)'
        users_section = re.search(r'User\(s\) Identified:(.+?)(?:\n\n|\Z)', exec_result.stdout, re.DOTALL)
        if users_section:
            for match in re.finditer(user_pattern, users_section.group(1)):
                result.add_finding(
                    finding_type="user",
                    value=match.group(1),
                    severity="low"
                )

        # 解析漏洞
        if "vulnerability" in exec_result.stdout.lower() or "CVE" in exec_result.stdout:
            cve_pattern = r'CVE-\d+-\d+'
            for match in re.finditer(cve_pattern, exec_result.stdout):
                result.add_finding(
                    finding_type="vulnerability",
                    value=match.group(0),
                    severity="high"
                )

        vulns = result.get_vulnerabilities()
        users = [f.value for f in result.findings if f.finding_type == "user"]

        parts = []
        if vulns:
            parts.append(f"{len(vulns)}个漏洞")
        if users:
            parts.append(f"{len(users)}个用户")

        result.summary = f"发现 {', '.join(parts)}" if parts else "WordPress站点扫描完成"

        if users:
            result.suggest_next_step("发现用户，可尝试密码爆破", "hydra_attack")

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


# 导出所有工具类
__all__ = [
    "GobusterScan",
    "NiktoScan",
    "SqlmapScan",
    "NucleiScan",
    "WhatwebScan",
    "FfufScan",
    "FeroxbusterScan",
    "WpscanScan",
]
