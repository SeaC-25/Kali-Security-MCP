#!/usr/bin/env python3
"""
Kali 后端解析器：动态检测工具执行后端 (local / ssh / docker)。

替代原先硬编码的远程 Kali API 地址：启动时调用 resolve_backend() 决定
工具执行方式；检测失败不应阻塞服务器启动。
"""

import os
import shutil
import socket
import threading
from pathlib import Path

try:
    import paramiko
    _HAS_PARAMIKO = True
except ImportError:
    paramiko = None
    _HAS_PARAMIKO = False

# 常用安全工具检查清单（本地 PATH 检测用）
DEFAULT_TOOL_CHECKLIST = [
    "nmap",
    "gobuster",
    "ffuf",
    "nikto",
    "nuclei",
    "sqlmap",
    "hydra",
    "masscan",
    "whatweb",
    "httpx",
    "subfinder",
    "amass",
    "wpscan",
    "feroxbuster",
]

# 各工具对应的安装提示（缺失时给出友好建议）
INSTALL_HINTS = {
    "nmap": "sudo apt install nmap",
    "gobuster": "sudo apt install gobuster",
    "ffuf": "sudo apt install ffuf",
    "nikto": "sudo apt install nikto",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "sqlmap": "sudo apt install sqlmap",
    "hydra": "sudo apt install hydra",
    "masscan": "sudo apt install masscan",
    "whatweb": "sudo apt install whatweb",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "sudo apt install amass",
    "wpscan": "sudo apt install wpscan",
    "feroxbuster": "sudo apt install feroxbuster",
}


class BackendResolver:
    """按 local -> ssh -> docker 的检测链解析 Kali 工具执行后端。"""

    def __init__(self, ssh_config_path=None):
        self._ssh_config_path = ssh_config_path or Path.home() / ".ssh" / "config"
        self._ssh_hosts = None   # 惰性缓存：SSH 主机列表
        self._docker_ok = None   # 惰性缓存：docker 是否可用

    # ---------- 检测链 ----------

    def _detect_local_tools(self):
        """(a) 本地：工具是否存在于 PATH。"""
        return [t for t in DEFAULT_TOOL_CHECKLIST if shutil.which(t)]

    def _parse_ssh_config(self):
        """(b) ssh: 尽力解析 ~/.ssh/config，返回主机别名列表；文件缺失/不可读时返回 []。"""
        if self._ssh_hosts is not None:
            return self._ssh_hosts
        hosts = []
        try:
            config = Path(self._ssh_config_path)
            if config.is_file():
                for raw in config.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("Host "):
                        hosts.extend(a for a in line[5:].split() if a not in ("*", "?"))
        except OSError:
            pass
        self._ssh_hosts = hosts
        return hosts

    def _detect_docker(self):
        """(c) docker: 检测 docker 命令是否可用。"""
        if self._docker_ok is None:
            self._docker_ok = shutil.which("docker") is not None
        return self._docker_ok

    # ---------- 对外接口 ----------

    def resolve(self):
        """按 local -> ssh -> docker 优先级返回后端信息 dict。"""
        detected = self._detect_local_tools()
        if detected:
            mode = "local"
            detail = f"本地 PATH 检测到 {len(detected)} 个工具: {', '.join(detected[:8])}"
        else:
            hosts = self._parse_ssh_config()
            if hosts:
                mode = "ssh"
                detail = f"检测到 SSH 主机配置 ({', '.join(hosts[:5])})，允许远程执行模式"
            elif self._detect_docker():
                mode = "docker"
                detail = "检测到 docker，可在容器内执行"
            else:
                mode = "unavailable"
                detail = "未检测到可用执行后端 (local/ssh/docker)"
        return {"mode": mode, "details": detail, "detected_tools": detected}

    def tool_available(self, tool_name):
        """工具是否可用：本地 PATH 命中，或后端为 ssh/docker 时视为可远程执行。"""
        if shutil.which(tool_name):
            return True
        return self.resolve()["mode"] in ("ssh", "docker")

    def tool_missing_message(self, tool_name):
        """生成友好的缺失提示，附带安装建议。"""
        hint = INSTALL_HINTS.get(tool_name, f"sudo apt install {tool_name}")
        mode = self.resolve()["mode"]
        if mode == "ssh":
            hosts = ", ".join(self._parse_ssh_config()[:3])
            return (f"工具 '{tool_name}' 本地未安装，但已配置 SSH 远程执行 "
                    f"(主机: {hosts})，可远程调用或在目标主机上安装 ({hint})")
        if mode == "docker":
            return (f"工具 '{tool_name}' 本地未安装，可通过 docker 容器执行 "
                    f"(docker run --rm kalilinux/kali-rolling {tool_name})，或先在本地安装 ({hint})")
        return f"未检测到工具 '{tool_name}'。请在 Kali 上安装: {hint}"


# 模块级单例 + 便捷函数（供 mcp_server 等启动流程调用）
_resolver = BackendResolver()


def resolve_backend():
    """返回后端信息 dict: {mode: local|ssh|docker|unavailable, details, detected_tools}。"""
    return _resolver.resolve()


def tool_available(tool_name):
    """工具是否可用（本地 which + 可选远程后端）。"""
    return _resolver.tool_available(tool_name)


def tool_missing_message(tool_name):
    """生成工具缺失的友好提示与安装建议。"""
    return _resolver.tool_missing_message(tool_name)


# ---------------------------------------------------------------------------
# SSH 远程执行（细测补接线：探测链之外的真实执行路径）
#   resolve_backend() 只回答"后端在哪"；ssh_execute() 实际把工具命令送过去跑。
#   连接参数来源：~/.ssh/config 的 Host 块 (HostName/User/Port) +
#   KALI_SSH_PASSWORD 环境变量（密码不落盘到 config）。
# ---------------------------------------------------------------------------

_ssh_client = None
_ssh_host_target = None
_ssh_lock = threading.Lock()


def _ssh_parse_target():
    """从 ~/.ssh/config 解析第一个非通配 Host 的连接目标。返回 (host, user, port) 或 None。"""
    import os

    config = Path(os.path.expanduser("~/.ssh/config"))
    if not config.is_file():
        return None
    hostname = user = port = None
    in_host = False
    try:
        for raw in config.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low.startswith("host "):
                # 上一个 Host 块结束：有目标则返回
                if in_host and hostname:
                    return (hostname, user or os.environ.get("USER", "root"), port or 22)
                in_host = not any(a in ("*", "?") for a in line[5:].split())
                hostname = user = port = None
            elif in_host:
                if low.startswith("hostname "):
                    hostname = line.split(None, 1)[1]
                elif low.startswith("user "):
                    user = line.split(None, 1)[1]
                elif low.startswith("port "):
                    try:
                        port = int(line.split(None, 1)[1])
                    except ValueError:
                        port = None
        if in_host and hostname:
            return (hostname, user or os.environ.get("USER", "root"), port or 22)
    except OSError:
        pass
    return None


def ssh_execute(command, timeout: int = 60):
    """通过 SSH 在远程 Kali 后端执行命令。返回 {success, output, error, return_code}。

    - 连接目标从 ~/.ssh/config 解析；密码读 KALI_SSH_PASSWORD 环境变量。
    - paramiko 缺失 / 无目标 / 连接失败 → 返回 error dict（不抛异常，调用方可降级本地）。
    """
    global _ssh_client, _ssh_host_target
    if not _HAS_PARAMIKO:
        return {"success": False, "output": "", "error": "paramiko not installed; cannot execute via ssh backend", "return_code": -1}
    target = _ssh_parse_target()
    if not target:
        return {"success": False, "output": "", "error": "no ssh host configured (~/.ssh/config)", "return_code": -1}
    host, user, port = target
    password = os.environ.get("KALI_SSH_PASSWORD", "")
    try:
        with _ssh_lock:
            return _ssh_execute_locked(host, user, port, password, command, timeout)
    except Exception as e:  # noqa: BLE001
        _ssh_client = None
        _ssh_host_target = None
        err_msg = str(e) or type(e).__name__
        if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in err_msg.lower():
            err_msg = f"ssh command timed out after {timeout}s"
        return {"success": False, "output": "", "error": f"ssh execute failed: {err_msg}", "return_code": -1}


def _ssh_execute_locked(host, user, port, password, command, timeout):
    """实际 ssh 执行（调用方已持 _ssh_lock）。"""
    global _ssh_client, _ssh_host_target
    try:
        if _ssh_client is None or _ssh_host_target != (host, user, port):
            _ssh_client = paramiko.SSHClient()
            _ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            _ssh_client.connect(host, port=port, username=user, password=password, timeout=10, allow_agent=True, look_for_keys=True)
            _ssh_host_target = (host, user, port)
        stdin, stdout, stderr = _ssh_client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        # stderr 无论 rc 都保留（whatweb 等工具 RC=0 时 ERROR 走 stderr，丢弃会丢结果）
        return {
            "success": rc == 0,
            "output": out,
            "error": err,
            "return_code": rc,
        }
    except Exception as e:  # noqa: BLE001
        _ssh_client = None
        _ssh_host_target = None
        err_msg = str(e) or type(e).__name__
        if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in err_msg.lower():
            err_msg = f"ssh command timed out after {timeout}s"
        return {"success": False, "output": "", "error": f"ssh execute failed: {err_msg}", "return_code": -1}
