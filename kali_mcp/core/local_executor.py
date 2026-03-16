#!/usr/bin/env python3
"""
本地命令执行器

从 mcp_server.py 提取:
- LocalCommandExecutor: 本地Kali工具命令执行器
"""

import os
import re
import json
import shlex
import time
import logging
import subprocess
import hashlib
from typing import Dict, Any, Optional, List, Set
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from kali_mcp.security import engagement_manager
except Exception:
    engagement_manager = None

# v6.0: 声明式工具注册表 + 结构化输出解析器
try:
    from kali_mcp.core.tool_registry import (
        build_command as _registry_build_command,
        ALLOWED_TOOLS as _REGISTRY_ALLOWED_TOOLS,
        get_tool_spec,
        get_output_parser_name,
    )
    _HAS_TOOL_REGISTRY = True
except ImportError:
    _HAS_TOOL_REGISTRY = False
    logger.debug("tool_registry 未加载，使用内置 elif 路由")

try:
    from kali_mcp.core.output_parsers import (
        parse_output as _parse_output,
        detect_flags,
        smart_truncate,
    )
    _HAS_OUTPUT_PARSERS = True
except ImportError:
    _HAS_OUTPUT_PARSERS = False
    logger.debug("output_parsers 未加载，使用原始输出")

# v5.1: 可选事件总线 — 不存在时静默降级
_event_bus = None

def set_event_bus(bus):
    """注入全局事件总线实例（由 mcp_server.py 启动时调用）"""
    global _event_bus
    _event_bus = bus


def sanitize_shell_arg(value: str) -> str:
    """使用 shlex.quote() 转义 shell 参数，防止命令注入"""
    if not value:
        return ""
    return shlex.quote(str(value))


def sanitize_shell_fragment(value: str) -> str:
    """
    转义包含多个参数的片段，避免把 '-sV -sC -T3' 当成单个参数。
    """
    if not value:
        return ""
    try:
        tokens = shlex.split(str(value))
    except ValueError:
        tokens = [str(value)]
    return " ".join(shlex.quote(token) for token in tokens if token)

ALLOWED_TOOLS: Set[str] = {
    "nmap", "gobuster", "sqlmap", "nikto", "hydra", "dirb",
    "wfuzz", "ffuf", "feroxbuster", "wafw00f", "whatweb",
    "wpscan", "joomscan", "masscan", "zmap", "arp-scan", "arpscan",
    "fping", "netdiscover", "dnsrecon", "dnsenum", "fierce",
    "dnsmap", "sublist3r", "subfinder", "amass", "john", "hashcat",
    "medusa", "ncrack", "patator", "crowbar", "brutespray",
    "aircrack-ng", "aircrack", "reaver", "bully", "pixiewps",
    "wifiphisher", "bluesnarfer", "btscanner", "ettercap",
    "responder", "bettercap", "dsniff", "ngrep", "tshark",
    "nuclei", "searchsploit", "enum4linux", "theHarvester",
    "sherlock", "recon-ng", "binwalk", "radare2", "r2",
    "slowhttptest", "yersinia", "httpx", "metasploit",
    "msfconsole", "msfvenom",
    "semgrep", "bandit", "flawfinder", "shellcheck",
    # v5.1: 新增基础工具
    "curl", "wget", "nc", "ncat", "netcat",
    "ssh", "scp", "python3", "python",
    "dig", "host", "whois", "traceroute",
    "openssl", "base64", "xxd",
    "grep", "awk", "sed", "jq",
    "steghide", "zsteg", "exiftool", "foremost",
    "volatility", "strings",
}

# v5.1: 可配置执行参数 - 支持环境变量覆盖
EXEC_CONFIG = {
    "default_timeout": int(os.environ.get("KALI_MCP_TIMEOUT", "300")),
    "nuclei_rate_limit": int(os.environ.get("KALI_MCP_NUCLEI_RATE", "150")),
    "nuclei_timeout": int(os.environ.get("KALI_MCP_NUCLEI_TIMEOUT", "15")),
    "retry_count": int(os.environ.get("KALI_MCP_RETRY_COUNT", "2")),
    "retry_delay": int(os.environ.get("KALI_MCP_RETRY_DELAY", "3")),
    # 工具级超时覆盖
    "tool_timeouts": {
        "nmap": 600,
        "masscan": 300,
        "sqlmap": 600,
        "nikto": 300,
        "nuclei": 300,
        "gobuster": 180,
        "ffuf": 180,
        "hydra": 600,
        "wpscan": 300,
    },
}

def validate_tool_name(name: str) -> bool:
    """验证工具名是否在白名单中

    v6.0: 同时检查内置白名单和注册表工具集。
    """
    if name in ALLOWED_TOOLS:
        return True
    if _HAS_TOOL_REGISTRY and name in _REGISTRY_ALLOWED_TOOLS:
        return True
    return False

class LocalCommandExecutor:
    """本地命令执行器 - 直接使用subprocess执行Kali工具"""

    def __init__(self, timeout: int = 300, working_dir: str = None):
        """
        初始化本地命令执行器

        Args:
            timeout: 命令执行超时时间（秒）
            working_dir: 工作目录
        """
        self.timeout = timeout
        self.working_dir = working_dir or os.getcwd()
        logger.info(f"初始化本地命令执行器，工作目录: {self.working_dir}")

    def execute_command(self, command: str, timeout: int = None) -> Dict[str, Any]:
        """
        执行shell命令

        Args:
            command: 要执行的命令
            timeout: 命令超时时间（可选，覆盖默认值）

        Returns:
            执行结果字典
        """
        cmd_timeout = timeout or self.timeout

        # 合规策略 - 授权范围门禁
        if engagement_manager is not None:
            extracted_targets = engagement_manager.extract_targets(command)
            allowed, reason = engagement_manager.validate_targets(extracted_targets)
            if not allowed:
                return {
                    "success": False,
                    "error": f"Scope blocked command: {reason}",
                    "output": "",
                    "return_code": -3,
                    "command": command,
                    "scope": {
                        "targets": extracted_targets,
                        "reason": reason,
                    },
                }

        try:
            logger.debug(f"执行命令: {command}")

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=cmd_timeout,
                cwd=self.working_dir
            )

            success = result.returncode == 0

            return {
                "success": success,
                "output": result.stdout,
                "error": result.stderr if not success else "",
                "return_code": result.returncode,
                "command": command
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"命令执行超时 ({cmd_timeout}秒): {command}")
            return {
                "success": False,
                "error": f"Command timeout after {cmd_timeout} seconds",
                "output": "",
                "return_code": -1,
                "command": command
            }
        except Exception as e:
            logger.error(f"命令执行失败: {command}, 错误: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "return_code": -1,
                "command": command
            }

    def check_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        if not validate_tool_name(tool_name):
            logger.warning(f"工具名不在白名单中: {tool_name}")
            return False
        result = self.execute_command(f"which {sanitize_shell_arg(tool_name)}", timeout=5)
        return result["success"]

    def get_tool_version(self, tool_name: str) -> str:
        """获取工具版本"""
        if not validate_tool_name(tool_name):
            logger.warning(f"工具名不在白名单中: {tool_name}")
            return "Unknown"
        result = self.execute_command(f"{sanitize_shell_arg(tool_name)} --version 2>&1 | head -1", timeout=5)
        return result["output"].strip() if result["success"] else "Unknown"

    def execute_tool_with_data(self, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据工具名称和数据字典执行工具命令

        Args:
            tool_name: 工具名称
            data: 工具参数字典

        Returns:
            执行结果
        """
        # 工具级授权范围门禁
        if engagement_manager is not None:
            allowed_tool, reason_tool = engagement_manager.is_tool_allowed(tool_name)
            if not allowed_tool:
                return {
                    "success": False,
                    "error": f"Tool denied by profile: {reason_tool}",
                    "return_code": -4,
                    "tool_name": tool_name,
                }
            targets = engagement_manager.extract_targets(json.dumps(data or {}, ensure_ascii=False))
            allowed_scope, reason_scope = engagement_manager.validate_targets(targets)
            if not allowed_scope:
                return {
                    "success": False,
                    "error": f"Scope blocked tool call: {reason_scope}",
                    "return_code": -3,
                    "tool_name": tool_name,
                    "scope": {
                        "targets": targets,
                        "reason": reason_scope,
                    },
                }

        command = self._build_tool_command(tool_name, data)
        if not command:
            in_whitelist = tool_name in ALLOWED_TOOLS
            if in_whitelist:
                reason = f"工具 '{tool_name}' 在白名单中但无法构建命令，请检查参数"
            else:
                reason = f"工具 '{tool_name}' 不在白名单中，拒绝执行"
            logger.error(reason)
            return {"success": False, "error": reason, "tool_name": tool_name}

        # v5.1: 工具级超时
        tool_timeout = EXEC_CONFIG["tool_timeouts"].get(tool_name, EXEC_CONFIG["default_timeout"])

        start_time = time.time()
        result = self.execute_command(command, timeout=tool_timeout)
        duration = round(time.time() - start_time, 2)

        result["duration"] = duration
        result["tool_name"] = tool_name

        # v6.0: 结构化输出解析
        if _HAS_OUTPUT_PARSERS:
            try:
                raw_output = result.get("output", "")
                parsed = _parse_output(tool_name, raw_output, result.get("success", False))
                result["parsed"] = parsed.to_dict()
                # 智能截断替代硬截断
                truncated_output, was_truncated = smart_truncate(raw_output)
                if was_truncated:
                    result["output_truncated"] = True
                # Flag 检测
                if parsed.flags_found:
                    result["flags_found"] = parsed.flags_found
                    logger.info(f"🚩 发现 Flag: {parsed.flags_found}")
                # 下一步建议
                if parsed.next_steps:
                    result["next_steps"] = parsed.next_steps
            except Exception as e:
                logger.debug(f"输出解析失败 (非致命): {e}")

        # v5.1: 通过事件总线广播工具执行结果
        if _event_bus is not None:
            try:
                target = data.get("target", data.get("url", data.get("domain", "")))
                # v6.0: 使用智能截断替代硬截断
                event_output = result.get("output", "")
                if _HAS_OUTPUT_PARSERS:
                    event_output, _ = smart_truncate(event_output, 5000)
                else:
                    event_output = event_output[:5000]
                _event_bus.emit("tool.result", {
                    "tool_name": tool_name,
                    "target": target,
                    "success": result.get("success", False),
                    "output": event_output,
                    "duration": duration,
                    "data": {k: v for k, v in data.items() if k != "additional_args"},
                }, source="executor")
            except Exception as e:
                logger.debug(f"EventBus emit failed (non-fatal): {e}")

        return result

    def execute_with_retry(self, tool_name: str, data: Dict[str, Any],
                           retry_count: int = None, retry_delay: int = None) -> Dict[str, Any]:
        """
        带自动重试的工具执行

        失败时自动重试，每次可调整参数（如缩小扫描范围）。

        Args:
            tool_name: 工具名称
            data: 工具参数
            retry_count: 重试次数，默认从 EXEC_CONFIG 读取
            retry_delay: 重试间隔秒数
        """
        max_retries = retry_count if retry_count is not None else EXEC_CONFIG["retry_count"]
        delay = retry_delay if retry_delay is not None else EXEC_CONFIG["retry_delay"]

        last_result = None
        for attempt in range(max_retries + 1):
            result = self.execute_tool_with_data(tool_name, data)
            if result.get("success"):
                return result
            last_result = result

            if attempt < max_retries:
                logger.info(f"工具 {tool_name} 第{attempt+1}次失败，{delay}秒后重试")
                time.sleep(delay)
                # 超时失败时缩小范围
                if "timeout" in str(result.get("error", "")).lower():
                    data = dict(data)  # 不修改原始dict
                    if "additional_args" not in data:
                        data["additional_args"] = ""
                    # 对特定工具添加快速模式参数
                    if tool_name == "nmap" and "-T5" not in data.get("additional_args", ""):
                        data["additional_args"] += " -T5 --max-retries 1"
                    elif tool_name == "gobuster" and "-t" not in data.get("additional_args", ""):
                        data["additional_args"] += " -t 20"

        return last_result

    def _build_tool_command(self, tool_name: str, data: Dict[str, Any]) -> str:
        """构建工具命令

        v6.0: 优先使用声明式工具注册表 (tool_registry)。
        若注册表未加载或注册表返回空字符串，则回退到内置 elif 路由。
        """
        # --- v6.0: 新注册表路径 ---
        if _HAS_TOOL_REGISTRY:
            cmd = _registry_build_command(tool_name, data)
            if cmd:
                return cmd

        # --- 回退: 原始 elif 路由 (向后兼容) ---
        if tool_name == "nmap":
            target = sanitize_shell_arg(data.get("target", ""))
            scan_type = sanitize_shell_fragment(data.get("scan_type", "-sV"))
            ports = sanitize_shell_arg(data.get("ports", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"nmap {scan_type} {target}"
            if data.get("ports", ""):
                cmd += f" -p {ports}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "gobuster":
            url = sanitize_shell_arg(data.get("url", ""))
            mode = sanitize_shell_arg(data.get("mode", "dir"))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
            additional_args = data.get("additional_args", "")
            cmd = f"gobuster {mode} -u {url} -w {wordlist} --no-error -q"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "sqlmap":
            url = sanitize_shell_arg(data.get("url", ""))
            data_param = sanitize_shell_arg(data.get("data", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"sqlmap -u {url} --batch"
            if data.get("data", ""):
                cmd += f" --data={data_param}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "nikto":
            target = sanitize_shell_arg(data.get("target", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"nikto -h {target} -maxtime 240s"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "hydra":
            target = sanitize_shell_arg(data.get("target", ""))
            service = sanitize_shell_arg(data.get("service", ""))
            username = data.get("username", "")
            username_file = data.get("username_file", "")
            password = data.get("password", "")
            password_file = data.get("password_file", "")
            additional_args = data.get("additional_args", "")
            cmd = "hydra"
            if username_file:
                cmd += f" -L {sanitize_shell_arg(username_file)}"
            elif username:
                cmd += f" -l {sanitize_shell_arg(username)}"
            if password_file:
                cmd += f" -P {sanitize_shell_arg(password_file)}"
            elif password:
                cmd += f" -p {sanitize_shell_arg(password)}"
            cmd += f" {target} {service}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "dirb":
            url = sanitize_shell_arg(data.get("url", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
            additional_args = data.get("additional_args", "")
            cmd = f"dirb {url} {wordlist}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        # ==================== Web扫描工具 ====================
        elif tool_name == "wfuzz":
            target = sanitize_shell_arg(data.get("target", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
            additional_args = data.get("additional_args", "-c")
            return f"wfuzz -w {wordlist} {sanitize_shell_fragment(additional_args)} {target}"

        elif tool_name == "ffuf":
            url = sanitize_shell_arg(data.get("url", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
            mode = sanitize_shell_arg(data.get("mode", "FUZZ"))
            additional_args = data.get("additional_args", "")
            cmd = f"ffuf -u {url} -w {wordlist}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "feroxbuster":
            url = sanitize_shell_arg(data.get("url", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
            threads = sanitize_shell_arg(data.get("threads", "50"))
            additional_args = data.get("additional_args", "")
            cmd = f"feroxbuster -u {url} -w {wordlist} -t {threads}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "wafw00f":
            target = sanitize_shell_arg(data.get("target", ""))
            additional_args = data.get("additional_args", "-a")
            return f"wafw00f {target} {sanitize_shell_fragment(additional_args)}"

        elif tool_name == "whatweb":
            target = sanitize_shell_arg(data.get("target", ""))
            aggression = sanitize_shell_arg(data.get("aggression", "1"))
            additional_args = data.get("additional_args", "")
            cmd = f"whatweb -a {aggression} {target}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "wpscan":
            target = sanitize_shell_arg(data.get("target", ""))
            api_token = sanitize_shell_arg(data.get("api_token", ""))
            additional_args = data.get("additional_args", "--enumerate p,t,u")
            cmd = f"wpscan --url {target} --no-update {sanitize_shell_fragment(additional_args)}"
            if data.get("api_token", ""):
                cmd += f" --api-token {api_token}"
            return cmd

        elif tool_name == "joomscan":
            target = sanitize_shell_arg(data.get("target", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"joomscan -u {target}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        # ==================== 端口和网络扫描 ====================
        elif tool_name == "masscan":
            target = sanitize_shell_arg(data.get("target", ""))
            ports = sanitize_shell_arg(data.get("ports", "80,443"))
            rate = sanitize_shell_arg(data.get("rate", "1000"))
            additional_args = data.get("additional_args", "")
            cmd = f"masscan {target} -p{ports} --rate={rate}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "zmap":
            target = sanitize_shell_arg(data.get("target", ""))
            port = sanitize_shell_arg(data.get("port", "80"))
            rate = sanitize_shell_arg(data.get("rate", "10000"))
            additional_args = data.get("additional_args", "")
            cmd = f"zmap -p {port} -r {rate} {target}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "arp-scan" or tool_name == "arpscan":
            interface = sanitize_shell_arg(data.get("interface", ""))
            network = sanitize_shell_arg(data.get("network", "--local"))
            additional_args = data.get("additional_args", "")
            cmd = f"arp-scan {network}"
            if data.get("interface", ""):
                cmd = f"arp-scan -I {interface} {network}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "fping":
            targets = sanitize_shell_arg(data.get("targets", ""))
            count = sanitize_shell_arg(data.get("count", "3"))
            additional_args = data.get("additional_args", "")
            cmd = f"fping -c {count} {targets}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "netdiscover":
            interface = sanitize_shell_arg(data.get("interface", ""))
            range_ip = sanitize_shell_arg(data.get("range_ip", ""))
            passive = data.get("passive", False)
            additional_args = data.get("additional_args", "")
            # -P 打印模式(非交互), -N 不打印表头
            cmd = "netdiscover -P -N"
            if passive:
                cmd += " -p"
            if data.get("interface", ""):
                cmd += f" -i {interface}"
            if data.get("range_ip", ""):
                cmd += f" -r {range_ip}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== DNS工具 ====================
        elif tool_name == "dnsrecon":
            domain = sanitize_shell_arg(data.get("domain", ""))
            scan_type = sanitize_shell_fragment(data.get("scan_type", "-t std"))
            additional_args = data.get("additional_args", "")
            cmd = f"dnsrecon -d {domain} {scan_type}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "dnsenum":
            domain = sanitize_shell_arg(data.get("domain", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"dnsenum {domain}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "fierce":
            domain = sanitize_shell_arg(data.get("domain", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"fierce --domain {domain}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd.strip()

        elif tool_name == "dnsmap":
            domain = sanitize_shell_arg(data.get("domain", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"dnsmap {domain}"
            if data.get("wordlist", ""):
                cmd += f" -w {wordlist}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "sublist3r":
            domain = sanitize_shell_arg(data.get("domain", ""))
            additional_args = data.get("additional_args", "-v")
            return f"sublist3r -d {domain} {sanitize_shell_fragment(additional_args)}"

        elif tool_name == "subfinder":
            domain = sanitize_shell_arg(data.get("domain", ""))
            sources = sanitize_shell_arg(data.get("sources", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"subfinder -d {domain}"
            if data.get("sources", ""):
                cmd += f" -sources {sources}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "amass":
            domain = sanitize_shell_arg(data.get("domain", ""))
            mode = sanitize_shell_arg(data.get("mode", "enum"))
            additional_args = data.get("additional_args", "")
            cmd = f"amass {mode} -d {domain}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        # ==================== 密码破解工具 ====================
        elif tool_name == "john":
            hash_file = sanitize_shell_arg(data.get("hash_file", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
            format_type = sanitize_shell_arg(data.get("format_type", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"john --wordlist={wordlist}"
            if data.get("format_type", ""):
                cmd += f" --format={format_type}"
            cmd += f" {hash_file}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "hashcat":
            hash_file = sanitize_shell_arg(data.get("hash_file", ""))
            attack_mode = sanitize_shell_arg(data.get("attack_mode", "0"))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
            hash_type = sanitize_shell_arg(data.get("hash_type", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"hashcat -a {attack_mode}"
            if data.get("hash_type", ""):
                cmd += f" -m {hash_type}"
            cmd += f" {hash_file} {wordlist}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "medusa":
            target = sanitize_shell_arg(data.get("target", ""))
            username = sanitize_shell_arg(data.get("username", ""))
            password_list = sanitize_shell_arg(data.get("password_list", "/usr/share/wordlists/rockyou.txt"))
            service = sanitize_shell_arg(data.get("service", "ssh"))
            additional_args = data.get("additional_args", "")
            cmd = f"medusa -h {target} -M {service} -P {password_list}"
            if data.get("username", ""):
                cmd += f" -u {username}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "ncrack":
            target = sanitize_shell_arg(data.get("target", ""))
            service = sanitize_shell_arg(data.get("service", "ssh"))
            username_file = sanitize_shell_arg(data.get("username_file", ""))
            password_file = sanitize_shell_arg(data.get("password_file", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"ncrack {target}"
            if data.get("service", ""):
                cmd = f"ncrack {service}://{target}"
            if data.get("username_file", ""):
                cmd += f" -U {username_file}"
            if data.get("password_file", ""):
                cmd += f" -P {password_file}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "patator":
            module = sanitize_shell_arg(data.get("module", "ssh_login"))
            target = sanitize_shell_arg(data.get("target", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"patator {module} host={target}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "crowbar":
            service = sanitize_shell_arg(data.get("service", "ssh"))
            target = sanitize_shell_arg(data.get("target", ""))
            username = sanitize_shell_arg(data.get("username", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"crowbar -b {service} -s {target}"
            if data.get("username", ""):
                cmd += f" -u {username}"
            if data.get("wordlist", ""):
                cmd += f" -C {wordlist}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "brutespray":
            nmap_file = sanitize_shell_arg(data.get("nmap_file", ""))
            username_file = sanitize_shell_arg(data.get("username_file", ""))
            password_file = sanitize_shell_arg(data.get("password_file", ""))
            threads = sanitize_shell_arg(data.get("threads", "5"))
            additional_args = data.get("additional_args", "")
            cmd = f"brutespray -f {nmap_file} -t {threads}"
            if data.get("username_file", ""):
                cmd += f" -U {username_file}"
            if data.get("password_file", ""):
                cmd += f" -P {password_file}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== 无线网络工具 ====================
        elif tool_name == "aircrack-ng" or tool_name == "aircrack":
            capture_file = sanitize_shell_arg(data.get("capture_file", ""))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
            bssid = sanitize_shell_arg(data.get("bssid", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"aircrack-ng -w {wordlist}"
            if data.get("bssid", ""):
                cmd += f" -b {bssid}"
            cmd += f" {capture_file}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "reaver":
            interface = sanitize_shell_arg(data.get("interface", ""))
            bssid = sanitize_shell_arg(data.get("bssid", ""))
            additional_args = data.get("additional_args", "-vv")
            return f"reaver -i {interface} -b {bssid} {sanitize_shell_arg(additional_args)}"

        elif tool_name == "bully":
            interface = sanitize_shell_arg(data.get("interface", ""))
            bssid = sanitize_shell_arg(data.get("bssid", ""))
            additional_args = data.get("additional_args", "-v")
            return f"bully {interface} -b {bssid} {sanitize_shell_arg(additional_args)}"

        elif tool_name == "pixiewps":
            pke = sanitize_shell_arg(data.get("pke", ""))
            pkr = sanitize_shell_arg(data.get("pkr", ""))
            e_hash1 = sanitize_shell_arg(data.get("e_hash1", ""))
            e_hash2 = sanitize_shell_arg(data.get("e_hash2", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"pixiewps -e {pke} -r {pkr} -s {e_hash1} -z {e_hash2}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "wifiphisher":
            interface = sanitize_shell_arg(data.get("interface", ""))
            essid = sanitize_shell_arg(data.get("essid", ""))
            phishing_scenario = sanitize_shell_arg(data.get("phishing_scenario", "firmware-upgrade"))
            additional_args = data.get("additional_args", "")
            cmd = f"wifiphisher -i {interface} -p {phishing_scenario}"
            if data.get("essid", ""):
                cmd += f" -e {essid}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== 蓝牙工具 ====================
        elif tool_name == "bluesnarfer":
            target_mac = sanitize_shell_arg(data.get("target_mac", ""))
            action = sanitize_shell_arg(data.get("action", "info"))
            channel = sanitize_shell_arg(data.get("channel", "1"))
            additional_args = data.get("additional_args", "")
            cmd = f"bluesnarfer -b {target_mac} -C {channel}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "btscanner":
            output_file = sanitize_shell_arg(data.get("output_file", "/tmp/btscanner.xml"))
            additional_args = data.get("additional_args", "")
            cmd = f"btscanner -o {output_file}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== 网络嗅探和MITM工具 ====================
        elif tool_name == "ettercap":
            interface = sanitize_shell_arg(data.get("interface", ""))
            target1 = sanitize_shell_arg(data.get("target1", ""))
            target2 = sanitize_shell_arg(data.get("target2", ""))
            filter_file = sanitize_shell_arg(data.get("filter_file", ""))
            additional_args = data.get("additional_args", "-T")
            cmd = f"ettercap {sanitize_shell_arg(additional_args)} -i {interface}"
            if data.get("target1", "") or data.get("target2", ""):
                cmd += f" -M arp:remote /{target1}// /{target2}//"
            if data.get("filter_file", ""):
                cmd += f" -F {filter_file}"
            return cmd

        elif tool_name == "responder":
            interface = sanitize_shell_arg(data.get("interface", ""))
            analyze_mode = data.get("analyze_mode", False)
            additional_args = data.get("additional_args", "")
            cmd = f"responder -I {interface}"
            if analyze_mode:
                cmd += " -A"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "bettercap":
            interface = sanitize_shell_arg(data.get("interface", ""))
            caplet = sanitize_shell_arg(data.get("caplet", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"bettercap -iface {interface}"
            if data.get("caplet", ""):
                cmd += f" -caplet {caplet}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "dsniff":
            interface = sanitize_shell_arg(data.get("interface", ""))
            filter_expr = sanitize_shell_arg(data.get("filter_expr", ""))
            output_file = sanitize_shell_arg(data.get("output_file", ""))
            additional_args = data.get("additional_args", "")
            cmd = "dsniff"
            if data.get("interface", ""):
                cmd += f" -i {interface}"
            if data.get("filter_expr", ""):
                cmd += f" {filter_expr}"
            if data.get("output_file", ""):
                cmd += f" -w {output_file}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "ngrep":
            pattern = sanitize_shell_arg(data.get("pattern", ""))
            interface = sanitize_shell_arg(data.get("interface", ""))
            filter_expr = sanitize_shell_arg(data.get("filter_expr", ""))
            additional_args = data.get("additional_args", "")
            cmd = "ngrep"
            if data.get("interface", ""):
                cmd += f" -d {interface}"
            if data.get("pattern", ""):
                cmd += f" {pattern}"
            if data.get("filter_expr", ""):
                cmd += f" {filter_expr}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "tshark":
            interface = sanitize_shell_arg(data.get("interface", ""))
            capture_filter = sanitize_shell_arg(data.get("capture_filter", ""))
            display_filter = sanitize_shell_arg(data.get("display_filter", ""))
            output_file = sanitize_shell_arg(data.get("output_file", ""))
            packet_count = sanitize_shell_arg(data.get("packet_count", "100"))
            additional_args = data.get("additional_args", "")
            cmd = f"tshark -c {packet_count}"
            if data.get("interface", ""):
                cmd += f" -i {interface}"
            if data.get("capture_filter", ""):
                cmd += f" -f {capture_filter}"
            if data.get("display_filter", ""):
                cmd += f" -Y {display_filter}"
            if data.get("output_file", ""):
                cmd += f" -w {output_file}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== 漏洞扫描工具 ====================
        elif tool_name == "nuclei":
            target = sanitize_shell_arg(data.get("target", ""))
            templates = sanitize_shell_arg(data.get("templates", ""))
            severity = sanitize_shell_arg(data.get("severity", "critical,high,medium"))
            tags = sanitize_shell_arg(data.get("tags", ""))
            output_format = data.get("output_format", "json")
            additional_args = data.get("additional_args", "")
            # 使用nuclei v3+兼容参数 — 速率和超时从EXEC_CONFIG读取
            rl = EXEC_CONFIG["nuclei_rate_limit"]
            nt = EXEC_CONFIG["nuclei_timeout"]
            cmd = f"nuclei -u {target} -s {severity} -silent -rl {rl} -timeout {nt}"
            if data.get("templates", ""):
                cmd += f" -t {templates}"
            if data.get("tags", ""):
                cmd += f" -tags {tags}"
            if output_format == "json":
                cmd += " -jsonl"  # nuclei v3+ 使用 -jsonl
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "searchsploit":
            term = sanitize_shell_arg(data.get("term", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"searchsploit {term}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        # ==================== 枚举工具 ====================
        elif tool_name == "enum4linux":
            target = sanitize_shell_arg(data.get("target", ""))
            additional_args = data.get("additional_args", "-a")
            return f"enum4linux {sanitize_shell_fragment(additional_args)} {target}"

        elif tool_name == "theharvester":
            domain = sanitize_shell_arg(data.get("domain", ""))
            # 默认使用无需API的免费数据源
            sources = sanitize_shell_arg(data.get("sources", "anubis,crtsh,dnsdumpster,hackertarget,rapiddns"))
            limit = sanitize_shell_arg(data.get("limit", "500"))
            additional_args = data.get("additional_args", "")
            cmd = f"theHarvester -d {domain} -b {sources} -l {limit}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "sherlock":
            username = sanitize_shell_arg(data.get("username", ""))
            sites = sanitize_shell_arg(data.get("sites", ""))
            output_format = data.get("output_format", "json")
            additional_args = data.get("additional_args", "")
            cmd = f"sherlock {username}"
            if data.get("sites", ""):
                cmd += f" --site {sites}"
            if output_format == "json":
                cmd += " --json"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "recon-ng":
            workspace = sanitize_shell_arg(data.get("workspace", "default"))
            module = sanitize_shell_arg(data.get("module", ""))
            additional_args = data.get("additional_args", "")
            # recon-ng 需要 -x 来执行命令后退出，避免进入交互shell
            if data.get("module", ""):
                cmd = f"recon-ng -w {workspace} -m {module} -x {sanitize_shell_arg('run; exit')}"
            else:
                cmd = f"recon-ng -w {workspace} -x {sanitize_shell_arg('show modules; exit')}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== 固件和二进制分析 ====================
        elif tool_name == "binwalk":
            file_path = sanitize_shell_arg(data.get("file_path", ""))
            extract = data.get("extract", False)
            additional_args = data.get("additional_args", "")
            cmd = "binwalk"
            if extract:
                cmd += " -e"
            cmd += f" {file_path}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== 逆向工具 ====================
        elif tool_name == "radare2" or tool_name == "r2":
            binary_path = sanitize_shell_arg(data.get("binary_path", ""))
            additional_args = data.get("additional_args", "")
            # -q 安静模式, -c 执行命令后退出, 避免进入交互式shell
            analysis_cmds = data.get("commands", "aaa;afl;ii;iz")
            cmd = f"r2 -q -e scr.color=0 -c {sanitize_shell_arg(analysis_cmds)} {binary_path}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== DoS测试工具 ====================
        elif tool_name == "slowhttptest":
            target = sanitize_shell_arg(data.get("target", ""))
            attack_type = data.get("attack_type", "slowloris")
            connections = sanitize_shell_arg(data.get("connections", "200"))
            timeout = sanitize_shell_arg(data.get("timeout", "240"))
            additional_args = data.get("additional_args", "")
            type_flag = "-H" if attack_type == "slowloris" else "-B"
            cmd = f"slowhttptest {type_flag} -c {connections} -l {timeout} -u {target}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== 协议攻击工具 ====================
        elif tool_name == "yersinia":
            protocol = sanitize_shell_arg(data.get("protocol", "stp"))
            interface = sanitize_shell_arg(data.get("interface", ""))
            attack_type = sanitize_shell_arg(data.get("attack_type", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"yersinia {protocol}"
            if data.get("interface", ""):
                cmd += f" -i {interface}"
            if data.get("attack_type", ""):
                cmd += f" -attack {attack_type}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== HTTP工具 ====================
        elif tool_name == "httpx":
            targets = sanitize_shell_arg(data.get("targets", ""))
            additional_args = data.get("additional_args", "").replace("-tech-detect", "-td")
            cmd = f"echo {targets} | httpx -silent"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "metasploit":
            module = sanitize_shell_arg(data.get("module", "auxiliary/scanner/http/http_version"))
            options = data.get("options", {})
            script_parts = [f"use {module}"]
            if isinstance(options, dict):
                for key, value in options.items():
                    option_key = sanitize_shell_arg(str(key))
                    option_value = sanitize_shell_arg(str(value))
                    if option_key and option_value:
                        script_parts.append(f"set {option_key} {option_value}")
            script_parts.extend(["run", "exit -y"])
            script = "; ".join(script_parts)
            return f"msfconsole -q -x {sanitize_shell_arg(script)}"

        # ==================== 代码审计工具 ====================
        elif tool_name == "semgrep":
            target_path = sanitize_shell_arg(data.get("target_path", "."))
            config = sanitize_shell_arg(data.get("config", "auto"))
            language = data.get("language", "")
            additional_args = data.get("additional_args", "")
            cmd = f"semgrep --config {config} {target_path} --json"
            if language:
                cmd += f" --lang {sanitize_shell_arg(language)}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "bandit":
            target_path = sanitize_shell_arg(data.get("target_path", "."))
            severity = data.get("severity", "")
            confidence = data.get("confidence", "")
            additional_args = data.get("additional_args", "")
            cmd = f"bandit -r {target_path} -f json"
            if severity:
                cmd += f" -l {'l' * ['low','medium','high'].index(severity.lower()) + 1 if severity.lower() in ['low','medium','high'] else ''}"
            if confidence:
                cmd += f" -i {'i' * ['low','medium','high'].index(confidence.lower()) + 1 if confidence.lower() in ['low','medium','high'] else ''}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "flawfinder":
            target_path = sanitize_shell_arg(data.get("target_path", "."))
            min_level = sanitize_shell_arg(data.get("min_level", "1"))
            additional_args = data.get("additional_args", "")
            cmd = f"flawfinder --columns --context --minlevel={min_level} {target_path}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        elif tool_name == "shellcheck":
            target_path = sanitize_shell_arg(data.get("target_path", ""))
            severity = sanitize_shell_arg(data.get("severity", "warning"))
            additional_args = data.get("additional_args", "")
            cmd = f"shellcheck {target_path} -f json -S {severity}"
            if additional_args:
                cmd += f" {sanitize_shell_arg(additional_args)}"
            return cmd

        # ==================== v5.1: 基础网络工具 ====================
        elif tool_name == "curl":
            url = sanitize_shell_arg(data.get("url", data.get("target", "")))
            method = sanitize_shell_arg(data.get("method", "GET"))
            headers = data.get("headers", {})
            post_data = data.get("data", "")
            additional_args = data.get("additional_args", "")
            cmd = f"curl -s -S -L -m 30 -X {method}"
            if isinstance(headers, dict):
                for k, v in headers.items():
                    cmd += f" -H {sanitize_shell_arg(f'{k}: {v}')}"
            if post_data:
                cmd += f" -d {sanitize_shell_arg(post_data)}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            cmd += f" {url}"
            return cmd

        elif tool_name == "wget":
            url = sanitize_shell_arg(data.get("url", data.get("target", "")))
            output = sanitize_shell_arg(data.get("output", "-"))
            additional_args = data.get("additional_args", "")
            cmd = f"wget -q -O {output} --timeout=30"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            cmd += f" {url}"
            return cmd

        elif tool_name in ("nc", "ncat", "netcat"):
            target = sanitize_shell_arg(data.get("target", ""))
            port = sanitize_shell_arg(data.get("port", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"nc -w 5 -v"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            cmd += f" {target} {port}"
            return cmd

        elif tool_name == "dig":
            domain = sanitize_shell_arg(data.get("domain", data.get("target", "")))
            record_type = sanitize_shell_arg(data.get("record_type", "ANY"))
            server = data.get("server", "")
            additional_args = data.get("additional_args", "")
            cmd = f"dig {domain} {record_type}"
            if server:
                cmd += f" @{sanitize_shell_arg(server)}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "host":
            target = sanitize_shell_arg(data.get("target", data.get("domain", "")))
            additional_args = data.get("additional_args", "")
            cmd = f"host {target}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "whois":
            target = sanitize_shell_arg(data.get("target", data.get("domain", "")))
            additional_args = data.get("additional_args", "")
            cmd = f"whois {target}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "traceroute":
            target = sanitize_shell_arg(data.get("target", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"traceroute -m 20 {target}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "openssl":
            subcmd = sanitize_shell_fragment(data.get("subcmd", "s_client"))
            target = sanitize_shell_arg(data.get("target", ""))
            port = sanitize_shell_arg(data.get("port", "443"))
            additional_args = data.get("additional_args", "")
            cmd = f"echo | openssl {subcmd} -connect {target}:{port} 2>/dev/null"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "strings":
            file_path = sanitize_shell_arg(data.get("file_path", data.get("target", "")))
            additional_args = data.get("additional_args", "")
            cmd = f"strings {file_path}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        # ==================== v5.1: 取证/隐写工具 ====================
        elif tool_name == "steghide":
            action = data.get("action", "info")
            file_path = sanitize_shell_arg(data.get("file_path", data.get("target", "")))
            password = data.get("password", "")
            if action == "extract":
                cmd = f"steghide extract -sf {file_path} -f"
                if password:
                    cmd += f" -p {sanitize_shell_arg(password)}"
                else:
                    cmd += " -p ''"
            else:
                cmd = f"steghide info {file_path} -f"
                if password:
                    cmd += f" -p {sanitize_shell_arg(password)}"
                else:
                    cmd += " -p ''"
            return cmd

        elif tool_name == "zsteg":
            file_path = sanitize_shell_arg(data.get("file_path", data.get("target", "")))
            additional_args = data.get("additional_args", "-a")
            return f"zsteg {sanitize_shell_fragment(additional_args)} {file_path}"

        elif tool_name == "exiftool":
            file_path = sanitize_shell_arg(data.get("file_path", data.get("target", "")))
            additional_args = data.get("additional_args", "")
            cmd = f"exiftool {file_path}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "foremost":
            file_path = sanitize_shell_arg(data.get("file_path", data.get("target", "")))
            output_dir = sanitize_shell_arg(data.get("output_dir", "/tmp/foremost_output"))
            additional_args = data.get("additional_args", "")
            cmd = f"foremost -i {file_path} -o {output_dir}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "volatility":
            dump_path = sanitize_shell_arg(data.get("dump_path", data.get("target", "")))
            profile = sanitize_shell_arg(data.get("profile", ""))
            plugin = sanitize_shell_arg(data.get("plugin", "imageinfo"))
            additional_args = data.get("additional_args", "")
            cmd = f"volatility -f {dump_path}"
            if data.get("profile", ""):
                cmd += f" --profile={profile}"
            cmd += f" {plugin}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        # ==================== v5.2: 补全缺失路由 ====================
        elif tool_name == "aircrack":
            capture_file = sanitize_shell_arg(data.get("capture_file", data.get("target", "")))
            wordlist = sanitize_shell_arg(data.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
            bssid = data.get("bssid", "")
            additional_args = data.get("additional_args", "")
            cmd = f"aircrack-ng -w {wordlist}"
            if bssid:
                cmd += f" -b {sanitize_shell_arg(bssid)}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            cmd += f" {capture_file}"
            return cmd

        elif tool_name in ("nc", "ncat", "netcat"):
            target = sanitize_shell_arg(data.get("target", ""))
            port = data.get("port", "")
            additional_args = data.get("additional_args", "")
            binary = "ncat" if tool_name == "ncat" else "nc"
            cmd = binary
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            if target:
                cmd += f" {target}"
            if port:
                cmd += f" {sanitize_shell_arg(str(port))}"
            return cmd

        elif tool_name == "arpscan":
            # alias for arp-scan
            network = data.get("network", data.get("target", ""))
            interface = data.get("interface", "")
            additional_args = data.get("additional_args", "")
            cmd = "arp-scan"
            if interface:
                cmd += f" -I {sanitize_shell_arg(interface)}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            if network:
                cmd += f" {sanitize_shell_arg(network)}"
            else:
                cmd += " --localnet"
            return cmd

        elif tool_name in ("msfconsole", "metasploit"):
            module = data.get("module", "")
            resource_file = data.get("resource_file", "")
            if resource_file:
                return f"msfconsole -r {sanitize_shell_arg(resource_file)} -q"
            elif module:
                # 构建一次性执行命令
                target = data.get("target", data.get("RHOSTS", ""))
                opts = []
                if target:
                    opts.append(f"set RHOSTS {target}")
                for k, v in data.items():
                    if k.isupper() and k not in ("RHOSTS",):
                        opts.append(f"set {k} {v}")
                opts.append("run")
                opts.append("exit")
                rc_cmds = ";".join(f"echo '{o}'" for o in [f"use {module}"] + opts)
                return f"({rc_cmds}) | msfconsole -q"
            return "msfconsole -q -x 'exit'"

        elif tool_name == "msfvenom":
            payload = data.get("payload", "linux/x64/shell_reverse_tcp")
            lhost = data.get("lhost", data.get("LHOST", ""))
            lport = data.get("lport", data.get("LPORT", "4444"))
            fmt = data.get("format", data.get("f", "elf"))
            output = data.get("output", data.get("o", ""))
            additional_args = data.get("additional_args", "")
            cmd = f"msfvenom -p {sanitize_shell_arg(payload)}"
            if lhost:
                cmd += f" LHOST={sanitize_shell_arg(lhost)}"
            cmd += f" LPORT={sanitize_shell_arg(str(lport))}"
            cmd += f" -f {sanitize_shell_arg(fmt)}"
            if output:
                cmd += f" -o {sanitize_shell_arg(output)}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "r2":
            binary_path = sanitize_shell_arg(data.get("binary_path", data.get("target", "")))
            commands = data.get("commands", "aaa;afl;ii;iz;q")
            return f"r2 -q -c {sanitize_shell_arg(commands)} {binary_path}"

        elif tool_name == "theHarvester":
            domain = sanitize_shell_arg(data.get("domain", data.get("target", "")))
            sources = data.get("sources", "anubis,crtsh,dnsdumpster,hackertarget,rapiddns,urlscan")
            limit = data.get("limit", "100")
            additional_args = data.get("additional_args", "")
            cmd = f"theHarvester -d {domain} -b {sanitize_shell_arg(sources)} -l {sanitize_shell_arg(str(limit))}"
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            return cmd

        elif tool_name == "ssh":
            target = sanitize_shell_arg(data.get("target", ""))
            user = data.get("username", data.get("user", ""))
            port = data.get("port", "22")
            command = data.get("command", "")
            key_file = data.get("key_file", "")
            cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10"
            if key_file:
                cmd += f" -i {sanitize_shell_arg(key_file)}"
            cmd += f" -p {sanitize_shell_arg(str(port))}"
            if user:
                cmd += f" {sanitize_shell_arg(user)}@{target}"
            else:
                cmd += f" {target}"
            if command:
                cmd += f" {sanitize_shell_arg(command)}"
            return cmd

        elif tool_name == "scp":
            source = sanitize_shell_arg(data.get("source", ""))
            dest = sanitize_shell_arg(data.get("dest", data.get("target", "")))
            port = data.get("port", "22")
            key_file = data.get("key_file", "")
            cmd = f"scp -o StrictHostKeyChecking=no -P {sanitize_shell_arg(str(port))}"
            if key_file:
                cmd += f" -i {sanitize_shell_arg(key_file)}"
            cmd += f" {source} {dest}"
            return cmd

        elif tool_name in ("python3", "python"):
            script = data.get("script", data.get("command", ""))
            script_file = data.get("script_file", "")
            if script_file:
                return f"python3 {sanitize_shell_arg(script_file)}"
            elif script:
                return f"python3 -c {sanitize_shell_arg(script)}"
            return "python3 --version"

        elif tool_name == "base64":
            action = data.get("action", "decode")
            input_data = data.get("input", data.get("data", ""))
            if action == "encode":
                return f"echo -n {sanitize_shell_arg(input_data)} | base64"
            else:
                return f"echo -n {sanitize_shell_arg(input_data)} | base64 -d"

        elif tool_name == "xxd":
            file_path = data.get("file_path", data.get("target", ""))
            action = data.get("action", "hex")
            if action == "reverse":
                return f"xxd -r {sanitize_shell_arg(file_path)}"
            else:
                return f"xxd {sanitize_shell_arg(file_path)}"

        elif tool_name == "grep":
            pattern = sanitize_shell_arg(data.get("pattern", ""))
            file_path = data.get("file_path", data.get("target", ""))
            additional_args = data.get("additional_args", "-rn")
            cmd = f"grep {sanitize_shell_fragment(additional_args)} {pattern}"
            if file_path:
                cmd += f" {sanitize_shell_arg(file_path)}"
            return cmd

        elif tool_name == "awk":
            program = sanitize_shell_arg(data.get("program", data.get("command", "{print}")))
            file_path = data.get("file_path", data.get("target", ""))
            cmd = f"awk {program}"
            if file_path:
                cmd += f" {sanitize_shell_arg(file_path)}"
            return cmd

        elif tool_name == "sed":
            expression = sanitize_shell_arg(data.get("expression", data.get("command", "")))
            file_path = data.get("file_path", data.get("target", ""))
            cmd = f"sed {expression}"
            if file_path:
                cmd += f" {sanitize_shell_arg(file_path)}"
            return cmd

        elif tool_name == "jq":
            filter_expr = sanitize_shell_arg(data.get("filter", data.get("command", ".")))
            file_path = data.get("file_path", data.get("target", ""))
            cmd = f"jq {filter_expr}"
            if file_path:
                cmd += f" {sanitize_shell_arg(file_path)}"
            return cmd

        # ==================== v5.2: 通用 catch-all ====================
        # 对于白名单中有但没有专门路由的工具，尝试通用构建
        if tool_name in ALLOWED_TOOLS:
            target = data.get("target", data.get("url", data.get("domain", "")))
            additional_args = data.get("additional_args", "")
            cmd = tool_name
            if additional_args:
                cmd += f" {sanitize_shell_fragment(additional_args)}"
            if target:
                cmd += f" {sanitize_shell_arg(target)}"
            logger.info(f"使用通用路由构建: {tool_name}")
            return cmd

        # 未知工具，返回空字符串并记录详细原因
        logger.warning(f"未知工具名: {tool_name}，不在白名单中，拒绝构建命令")
        return ""
