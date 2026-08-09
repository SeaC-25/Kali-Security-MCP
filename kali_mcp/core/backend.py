#!/usr/bin/env python3
"""
Kali 后端解析器：动态检测工具执行后端 (local / ssh / docker)。

替代原先硬编码的远程 Kali API 地址：启动时调用 resolve_backend() 决定
工具执行方式；检测失败不应阻塞服务器启动。
"""

import shutil
from pathlib import Path

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
