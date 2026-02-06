#!/usr/bin/env python3
"""
密码攻击工具模块

包含密码破解和暴力破解工具:
- hydra_attack: Hydra在线密码破解
- john_crack: John the Ripper离线破解
- hashcat_crack: Hashcat GPU加速破解
- medusa_bruteforce: Medusa暴力破解
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

logger = logging.getLogger(__name__)


@tool(
    name="hydra_attack",
    category=ToolCategory.PASSWORD,
    description="Hydra在线密码破解 - 支持多种协议的暴力破解",
    risk_level=RiskLevel.HIGH,
    timeout=600
)
class HydraAttack(BaseTool):
    """Hydra密码攻击工具"""

    async def execute(
        self,
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "/usr/share/wordlists/rockyou.txt",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Hydra密码攻击

        Args:
            target: 目标主机
            service: 服务类型 (ssh, ftp, http-post-form等)
            username: 单个用户名
            username_file: 用户名字典
            password: 单个密码
            password_file: 密码字典
            additional_args: 额外参数
        """
        cmd_parts = ["hydra"]

        # 用户名设置
        if username:
            cmd_parts.extend(["-l", username])
        elif username_file:
            cmd_parts.extend(["-L", username_file])
        else:
            cmd_parts.extend(["-l", "admin"])  # 默认用户名

        # 密码设置
        if password:
            cmd_parts.extend(["-p", password])
        elif password_file:
            cmd_parts.extend(["-P", password_file])

        # 线程和其他选项
        cmd_parts.extend(["-t", "4", "-f"])  # 4线程，找到即停

        if additional_args:
            cmd_parts.append(additional_args)

        # 目标和服务
        cmd_parts.extend([target, service])

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="hydra_attack",
            target=target,
            raw_output=exec_result.stdout
        )

        # 解析成功的凭据
        cred_pattern = r'\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)'
        for match in re.finditer(cred_pattern, exec_result.stdout):
            port = match.group(1)
            proto = match.group(2)
            host = match.group(3)
            user = match.group(4)
            passwd = match.group(5)

            result.add_finding(
                finding_type="credential",
                value=f"{user}:{passwd}",
                severity="critical",
                host=host,
                port=port,
                protocol=proto
            )

        creds = [f for f in result.findings if f.finding_type == "credential"]
        if creds:
            result.summary = f"成功破解 {len(creds)} 个凭据!"
            result.suggest_next_step("使用获取的凭据尝试登录")
        else:
            result.summary = "未能破解密码"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="john_crack",
    category=ToolCategory.PASSWORD,
    description="John the Ripper离线密码破解 - 支持多种哈希格式",
    risk_level=RiskLevel.LOW,
    timeout=1800
)
class JohnCrack(BaseTool):
    """John the Ripper破解工具"""

    async def execute(
        self,
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = "",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行John破解

        Args:
            hash_file: 哈希文件路径
            wordlist: 字典文件
            format_type: 哈希格式
            additional_args: 额外参数
        """
        cmd_parts = ["john"]

        if wordlist:
            cmd_parts.extend(["--wordlist=" + wordlist])

        if format_type:
            cmd_parts.extend(["--format=" + format_type])

        if additional_args:
            cmd_parts.append(additional_args)

        cmd_parts.append(hash_file)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="john_crack",
            target=hash_file,
            raw_output=exec_result.stdout
        )

        # 获取破解结果
        show_result = await executor.run_command(f"john --show {hash_file}")

        if show_result.success:
            # 解析破解的密码
            for line in show_result.stdout.split('\n'):
                if ':' in line and not line.startswith('0 password'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        result.add_finding(
                            finding_type="credential",
                            value=f"{parts[0]}:{parts[1]}",
                            severity="critical"
                        )

        creds = [f for f in result.findings if f.finding_type == "credential"]
        if creds:
            result.summary = f"破解了 {len(creds)} 个密码"
        else:
            result.summary = "密码破解进行中或未破解成功"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))
        result.flags_found.extend(result.extract_flags(show_result.stdout))

        return result


@tool(
    name="hashcat_crack",
    category=ToolCategory.PASSWORD,
    description="Hashcat GPU加速密码破解 - 高性能哈希破解",
    risk_level=RiskLevel.LOW,
    timeout=3600
)
class HashcatCrack(BaseTool):
    """Hashcat破解工具"""

    async def execute(
        self,
        hash_file: str,
        attack_mode: str = "0",
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        hash_type: str = "",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Hashcat破解

        Args:
            hash_file: 哈希文件
            attack_mode: 攻击模式 (0=字典, 1=组合, 3=暴力)
            wordlist: 字典文件
            hash_type: 哈希类型 (-m参数)
            additional_args: 额外参数
        """
        cmd_parts = ["hashcat", "-a", attack_mode]

        if hash_type:
            cmd_parts.extend(["-m", hash_type])

        cmd_parts.extend(["--force", "-o", "/tmp/hashcat_cracked.txt"])

        if additional_args:
            cmd_parts.append(additional_args)

        cmd_parts.extend([hash_file, wordlist])

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="hashcat_crack",
            target=hash_file,
            raw_output=exec_result.stdout
        )

        # 读取破解结果
        read_result = await executor.run_command("cat /tmp/hashcat_cracked.txt 2>/dev/null")
        if read_result.success and read_result.stdout.strip():
            for line in read_result.stdout.strip().split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    result.add_finding(
                        finding_type="credential",
                        value=line,
                        severity="critical"
                    )

        creds = [f for f in result.findings if f.finding_type == "credential"]
        if creds:
            result.summary = f"破解了 {len(creds)} 个哈希"
        else:
            result.summary = "破解进行中或未成功"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="medusa_bruteforce",
    category=ToolCategory.PASSWORD,
    description="Medusa暴力破解工具 - 并行密码破解",
    risk_level=RiskLevel.HIGH,
    timeout=600
)
class MedusaBruteforce(BaseTool):
    """Medusa暴力破解工具"""

    async def execute(
        self,
        target: str,
        username: str = "",
        password_list: str = "/usr/share/wordlists/rockyou.txt",
        service: str = "ssh",
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """执行Medusa暴力破解"""
        cmd_parts = ["medusa", "-h", target, "-M", service]

        if username:
            cmd_parts.extend(["-u", username])
        else:
            cmd_parts.extend(["-u", "root"])

        cmd_parts.extend(["-P", password_list])

        if additional_args:
            cmd_parts.append(additional_args)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="medusa_bruteforce",
            target=target,
            raw_output=exec_result.stdout
        )

        # 解析成功凭据
        success_pattern = r'SUCCESS \(([^)]+)\)'
        for match in re.finditer(success_pattern, exec_result.stdout):
            result.add_finding(
                finding_type="credential",
                value=match.group(1),
                severity="critical"
            )

        creds = [f for f in result.findings if f.finding_type == "credential"]
        if creds:
            result.summary = f"破解成功! 发现 {len(creds)} 个凭据"
        else:
            result.summary = "暴力破解未成功"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


__all__ = [
    "HydraAttack",
    "JohnCrack",
    "HashcatCrack",
    "MedusaBruteforce",
]
