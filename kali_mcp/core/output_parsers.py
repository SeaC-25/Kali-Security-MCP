#!/usr/bin/env python3
"""
结构化输出解析器 — 替代原始 output[:5000] 截断机制

本模块将工具的原始文本输出转化为统一的 ParsedResult 结构，包含:
- 人类可读摘要 (summary)
- 工具特定的结构化数据 (structured_data)
- CTF Flag 自动检测 (flags_found)
- 基于发现的下一步建议 (next_steps)
- 严重性和解析器置信度 (severity / confidence)

设计原则:
1. 每个解析器对畸形/不完整输出保持鲁棒
2. 空输出优雅处理
3. Flag 检测在所有解析器中统一运行
4. next_steps 引用实际 MCP 工具名
5. 完全自包含，仅依赖标准库

使用方法:
    from kali_mcp.core.output_parsers import parse_output

    result = parse_output("nmap", raw_output, return_code=0, data={"target": "10.0.0.1"})
    print(result.summary)
    print(result.structured_data["ports"])
    print(result.flags_found)
    print(result.next_steps)
"""

import re
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ============================================================
# CTF Flag 检测系统
# ============================================================

# 明确的 Flag 格式 — 高置信度，直接匹配
_EXPLICIT_FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'DASCTF\{[^}]+\}'),
    re.compile(r'htb\{[^}]+\}', re.IGNORECASE),
    re.compile(r'picoCTF\{[^}]+\}'),
    re.compile(r'ISCC\{[^}]+\}', re.IGNORECASE),
    re.compile(r'SCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'RCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'GWCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'BUUCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'HCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'CISCN\{[^}]+\}', re.IGNORECASE),
    re.compile(r'VNCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'XYCTF\{[^}]+\}', re.IGNORECASE),
    re.compile(r'MOECTF\{[^}]+\}', re.IGNORECASE),
    # FLAG-xxxx-xxxx 格式 (HackTheBox 旧格式)
    re.compile(r'FLAG-[a-zA-Z0-9]{4,}(?:-[a-zA-Z0-9]{4,})*'),
]

# MD5-like hash — 低置信度，需要上下文确认
# 仅在 flag/key/secret/answer 等关键词附近出现时才视为 Flag
_MD5_PATTERN = re.compile(r'\b([0-9a-f]{32})\b', re.IGNORECASE)
_FLAG_CONTEXT_KEYWORDS = re.compile(
    r'(?:flag|key|secret|answer|password|token|hash|md5)\s*[:=]\s*',
    re.IGNORECASE,
)


def detect_flags(text: str) -> List[str]:
    """
    在任意文本中检测 CTF Flag。

    对明确格式（flag{...}, ctf{...} 等）直接匹配。
    对 MD5 hash 仅在关键词上下文中匹配，避免海量误报。

    Args:
        text: 待检测文本

    Returns:
        去重后的 Flag 列表
    """
    if not text:
        return []

    found: List[str] = []
    seen: set = set()

    # 1. 明确格式
    for pattern in _EXPLICIT_FLAG_PATTERNS:
        for match in pattern.finditer(text):
            flag = match.group(0)
            flag_lower = flag.lower()
            if flag_lower not in seen:
                seen.add(flag_lower)
                found.append(flag)

    # 2. MD5 hash — 仅在上下文关键词附近
    for line in text.split('\n'):
        if _FLAG_CONTEXT_KEYWORDS.search(line):
            for match in _MD5_PATTERN.finditer(line):
                candidate = match.group(1)
                # 排除全0、全f等明显非 Flag 的 hash
                if candidate not in seen and not _is_trivial_hash(candidate):
                    seen.add(candidate)
                    found.append(candidate)

    return found


def _is_trivial_hash(h: str) -> bool:
    """排除明显非 Flag 的 MD5 hash"""
    h_lower = h.lower()
    return (
        h_lower == '0' * 32
        or h_lower == 'f' * 32
        or h_lower == 'd41d8cd98f00b204e9800998ecf8427e'  # empty string MD5
        or len(set(h_lower)) <= 2  # 只有1-2种字符
    )


# ============================================================
# 统一结果数据类
# ============================================================

@dataclass
class ParsedResult:
    """
    统一的工具输出解析结果。

    所有解析器都返回此类型，提供一致的接口给上层消费者。

    Attributes:
        tool_name: 工具名称
        success: 执行是否成功
        summary: 人类可读的 1-2 句摘要
        structured_data: 工具特定的结构化数据
        raw_output: 原始输出（智能截断后的版本）
        flags_found: 检测到的 CTF Flag 列表
        next_steps: 基于发现建议的下一步操作
        severity: 发现的最高严重性 info/low/medium/high/critical
        confidence: 解析器置信度 0.0-1.0
    """
    tool_name: str
    success: bool
    summary: str
    structured_data: Dict[str, Any]
    raw_output: str
    flags_found: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    severity: str = "info"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典，方便 JSON 传输"""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "summary": self.summary,
            "structured_data": self.structured_data,
            "raw_output": self.raw_output,
            "flags_found": self.flags_found,
            "next_steps": self.next_steps,
            "severity": self.severity,
            "confidence": self.confidence,
        }


# ============================================================
# 智能截断
# ============================================================

def smart_truncate(text: str, max_length: int = 5000) -> Tuple[str, bool]:
    """
    智能截断文本：保留头部和尾部信息。

    与简单的 text[:5000] 不同，此方法保留:
    - 前 3000 字符（通常包含关键发现）
    - 后 1500 字符（通常包含摘要/结论）
    - 中间插入截断标记

    Args:
        text: 原始文本
        max_length: 最大长度

    Returns:
        (截断后文本, 是否发生了截断)
    """
    if not text or len(text) <= max_length:
        return text or "", False

    head_size = int(max_length * 0.6)   # 3000
    tail_size = int(max_length * 0.3)   # 1500
    # 剩余空间给截断标记

    truncation_marker = (
        f"\n\n... [截断: 原始输出 {len(text)} 字符, "
        f"已省略中间 {len(text) - head_size - tail_size} 字符] ...\n\n"
    )

    return text[:head_size] + truncation_marker + text[-tail_size:], True


# ============================================================
# 基础解析器
# ============================================================

class BaseOutputParser(ABC):
    """
    输出解析器基类。

    所有工具特定的解析器继承此类，实现 _parse_output 方法。
    基类负责:
    - Flag 检测（对所有工具统一执行）
    - 智能截断
    - 错误处理
    """

    tool_name: str = "unknown"

    def parse(
        self,
        output: str,
        return_code: int,
        data: Optional[Dict[str, Any]] = None,
    ) -> ParsedResult:
        """
        解析工具输出的主入口。

        Args:
            output: 工具的原始 stdout 输出
            return_code: 进程退出码
            data: 工具调用时的参数字典

        Returns:
            统一的 ParsedResult
        """
        data = data or {}
        output = output or ""
        success = return_code == 0

        # Flag 检测 — 在所有输出上运行
        flags = detect_flags(output)

        # 智能截断
        truncated_output, was_truncated = smart_truncate(output)

        try:
            result = self._parse_output(output, return_code, data)
        except Exception as e:
            logger.warning(f"解析器 {self.tool_name} 解析失败: {e}")
            result = ParsedResult(
                tool_name=self.tool_name,
                success=success,
                summary=f"{self.tool_name} 输出解析失败: {str(e)[:100]}",
                structured_data={"parse_error": str(e)},
                raw_output=truncated_output,
                flags_found=flags,
                next_steps=[],
                severity="info",
                confidence=0.0,
            )
            return result

        # 合并 Flag（解析器可能已发现额外的 Flag）
        all_flags = list(dict.fromkeys(flags + result.flags_found))
        result.flags_found = all_flags
        result.raw_output = truncated_output

        # 如果发现 Flag，提升摘要
        if all_flags and "flag" not in result.summary.lower():
            result.summary += f" | 🚩 发现 {len(all_flags)} 个Flag!"

        return result

    @abstractmethod
    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        """子类实现：解析工具特定输出"""
        ...


# ============================================================
# Nmap 解析器
# ============================================================

class NmapParser(BaseOutputParser):
    """
    Nmap 输出解析器。

    解析内容:
    - 开放端口（端口号、协议、状态、服务、版本）
    - OS 检测结果
    - NSE 脚本输出
    - 主机存活状态

    structured_data 格式:
    {
        "ports": [{"port": 80, "protocol": "tcp", "state": "open",
                   "service": "http", "version": "Apache 2.4.41"}],
        "os": "Ubuntu Linux",
        "hostname": "target.com",
        "scripts": {"http-title": "Welcome"},
        "host_up": True
    }
    """

    tool_name = "nmap"

    # 端口行: 80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
    _PORT_RE = re.compile(
        r'(\d+)/(tcp|udp)\s+'
        r'(open|closed|filtered|open\|filtered)\s+'
        r'(\S+)'
        r'(?:\s+(.*))?'
    )
    _OS_RE = re.compile(r'OS details?:\s*(.+)', re.IGNORECASE)
    _HOST_RE = re.compile(r'Nmap scan report for\s+(\S+)(?:\s+\(([^)]+)\))?')
    _SCRIPT_HEADER_RE = re.compile(r'^\|[\s_]+([\w-]+):\s*(.*)')
    _SCRIPT_CONT_RE = re.compile(r'^\|[\s_]+\s+(.*)')

    # 端口到服务映射 — 建议下一步工具
    _PORT_NEXT_STEPS = {
        'http': '发现HTTP服务(端口{port}) → 建议使用 gobuster_scan 扫描目录, nikto_scan 扫描漏洞',
        'https': '发现HTTPS服务(端口{port}) → 建议使用 gobuster_scan 扫描目录, nuclei_web_scan 扫描漏洞',
        'ssh': '发现SSH服务(端口{port}) → 建议使用 hydra_attack 爆破弱密码',
        'ftp': '发现FTP服务(端口{port}) → 检查匿名登录, 建议使用 hydra_attack 爆破',
        'mysql': '发现MySQL服务(端口{port}) → 建议使用 hydra_attack 爆破, 检查空密码',
        'postgresql': '发现PostgreSQL服务(端口{port}) → 建议使用 hydra_attack 爆破',
        'smb': '发现SMB服务(端口{port}) → 建议使用 enum4linux_scan 枚举共享和用户',
        'microsoft-ds': '发现SMB服务(端口{port}) → 建议使用 enum4linux_scan 枚举',
        'netbios-ssn': '发现NetBIOS服务(端口{port}) → 建议使用 enum4linux_scan 枚举',
        'redis': '发现Redis服务(端口{port}) → 检查未授权访问',
        'mongodb': '发现MongoDB服务(端口{port}) → 检查未授权访问',
        'rdp': '发现RDP服务(端口{port}) → 建议使用 hydra_attack 爆破, 检查BlueKeep',
        'ms-wbt-server': '发现RDP服务(端口{port}) → 建议使用 hydra_attack 爆破',
        'telnet': '发现Telnet服务(端口{port}) → 建议使用 hydra_attack 爆破',
        'vnc': '发现VNC服务(端口{port}) → 建议使用 hydra_attack 爆破',
        'smtp': '发现SMTP服务(端口{port}) → 枚举用户, 检查开放中继',
        'pop3': '发现POP3服务(端口{port}) → 建议使用 hydra_attack 爆破',
        'imap': '发现IMAP服务(端口{port}) → 建议使用 hydra_attack 爆破',
        'dns': '发现DNS服务(端口{port}) → 建议使用 dnsrecon_scan 检查区域传送',
        'domain': '发现DNS服务(端口{port}) → 建议使用 dnsrecon_scan 检查区域传送',
        'ldap': '发现LDAP服务(端口{port}) → 检查匿名绑定, 枚举信息',
        'snmp': '发现SNMP服务(端口{port}) → 使用 community string 枚举信息',
    }

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        ports: List[Dict[str, Any]] = []
        os_info = ""
        hostname = ""
        target = data.get("target", "")
        host_up = True
        scripts: Dict[str, str] = {}
        current_script_name = ""
        current_script_value = ""

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary="Nmap 扫描无输出",
                structured_data={"ports": [], "os": "", "hostname": "", "scripts": {}, "host_up": False},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()

            # 主机行
            host_match = self._HOST_RE.search(stripped)
            if host_match:
                hostname = host_match.group(1)
                if host_match.group(2):
                    target = target or host_match.group(2)
                elif not target:
                    target = hostname
                continue

            # 主机存活
            if 'Host is up' in stripped:
                host_up = True
                continue
            if 'Host seems down' in stripped:
                host_up = False
                continue

            # 端口行
            port_match = self._PORT_RE.match(stripped)
            if port_match:
                # 先保存前一个脚本
                if current_script_name:
                    scripts[current_script_name] = current_script_value.strip()
                    current_script_name = ""
                    current_script_value = ""

                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version_raw = (port_match.group(5) or "").strip()

                # 清理 ssl/http → https
                if service.startswith("ssl/"):
                    service = service.replace("ssl/http", "https").replace("ssl/", "")

                # 版本提取
                version = version_raw
                ver_match = re.search(r'([\d.]+(?:p\d+)?)', version_raw)
                if ver_match:
                    version = ver_match.group(1)

                port_entry = {
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version,
                    "version_raw": version_raw,
                }
                ports.append(port_entry)
                continue

            # OS 检测
            os_match = self._OS_RE.search(stripped)
            if os_match:
                os_info = os_match.group(1).strip()
                continue

            # NSE 脚本输出
            script_header = self._SCRIPT_HEADER_RE.match(line)
            if script_header:
                if current_script_name:
                    scripts[current_script_name] = current_script_value.strip()
                current_script_name = script_header.group(1)
                current_script_value = script_header.group(2)
                continue

            script_cont = self._SCRIPT_CONT_RE.match(line)
            if script_cont and current_script_name:
                current_script_value += "\n" + script_cont.group(1)
                continue

        # 保存最后一个脚本
        if current_script_name:
            scripts[current_script_name] = current_script_value.strip()

        # 构建 next_steps
        open_ports = [p for p in ports if p["state"] == "open"]
        next_steps = self._build_next_steps(open_ports)

        # 构建摘要
        if not open_ports:
            summary = f"Nmap 扫描 {target or hostname}: 未发现开放端口"
            if not host_up:
                summary = f"Nmap 扫描 {target or hostname}: 主机似乎不在线"
        else:
            port_desc = ", ".join(
                f"{p['port']}({p['service']})" for p in open_ports[:8]
            )
            extra = f" 等共 {len(open_ports)} 个" if len(open_ports) > 8 else ""
            summary = f"Nmap 扫描 {target or hostname}: 发现 {len(open_ports)} 个开放端口: {port_desc}{extra}"

        # 严重性判断
        severity = "info"
        for p in open_ports:
            svc = p["service"].lower()
            if svc in ("telnet", "ftp", "snmp"):
                severity = "medium"
            if svc in ("redis", "mongodb") and not p.get("version_raw", ""):
                severity = "high"  # 可能未授权访问

        structured_data = {
            "ports": ports,
            "os": os_info,
            "hostname": hostname,
            "scripts": scripts,
            "host_up": host_up,
            "open_port_count": len(open_ports),
        }

        # 通用建议
        if open_ports:
            web_ports = [p for p in open_ports if p["service"] in ("http", "https", "http-proxy", "http-alt")]
            if web_ports:
                next_steps.append(
                    f"发现 {len(web_ports)} 个Web端口 → 建议使用 nuclei_web_scan 进行全面漏洞扫描"
                )

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data=structured_data,
            raw_output="",  # 由基类填充
            next_steps=next_steps,
            severity=severity,
            confidence=0.95 if open_ports else 0.7,
        )

    def _build_next_steps(self, open_ports: List[Dict[str, Any]]) -> List[str]:
        """根据开放端口生成下一步建议"""
        steps: List[str] = []
        seen_services: set = set()

        for p in open_ports:
            service = p["service"].lower()
            # 避免同一服务重复建议
            if service in seen_services:
                continue
            seen_services.add(service)

            template = self._PORT_NEXT_STEPS.get(service)
            if template:
                steps.append(template.format(port=p["port"]))

            # 版本特定建议
            version_raw = p.get("version_raw", "").lower()
            if "apache" in version_raw:
                steps.append(f"Apache 服务(端口{p['port']}) → 建议使用 nuclei_cve_scan 检查已知CVE")
            elif "nginx" in version_raw:
                steps.append(f"Nginx 服务(端口{p['port']}) → 建议使用 nuclei_cve_scan 检查已知CVE")
            elif "openssh" in version_raw:
                ver_match = re.search(r'openssh[_\s]*([\d.]+)', version_raw)
                if ver_match:
                    steps.append(
                        f"OpenSSH {ver_match.group(1)} → 使用 searchsploit_search 检查版本漏洞"
                    )

        return steps


# ============================================================
# Gobuster 解析器
# ============================================================

class GobusterParser(BaseOutputParser):
    """
    Gobuster / 目录扫描输出解析器。

    支持 gobuster dir 模式的标准输出格式:
        /admin                (Status: 200) [Size: 1234]
        /login                (Status: 302) [Size: 0] [--> /auth/login]

    也兼容 ffuf/feroxbuster 的类似输出格式。

    structured_data 格式:
    {
        "paths": [{"path": "/admin", "status": 200, "size": 1234}],
        "interesting": ["/admin", "/.git"],
        "total_found": 15
    }
    """

    tool_name = "gobuster"

    # gobuster: /path (Status: 200) [Size: 1234] [--> redirect]
    _GOBUSTER_RE = re.compile(
        r'(/\S*)\s+\(Status:\s*(\d+)\)'
        r'(?:\s+\[Size:\s*(\d+)\])?'
        r'(?:\s+\[-+>\s*(\S+)\])?'
    )

    # feroxbuster: 200 GET 1234l 5678w 9012c http://target/path
    _FEROX_RE = re.compile(
        r'(\d{3})\s+\S+\s+\d+l\s+\d+w\s+(\d+)c\s+(\S+)'
    )

    # 高价值路径关键词
    _INTERESTING_KEYWORDS = {
        'admin', 'login', 'upload', 'api', 'backup', 'config',
        '.git', '.env', '.svn', '.htaccess', '.htpasswd', '.DS_Store',
        'phpmyadmin', 'wp-admin', 'wp-login', 'console', 'dashboard',
        'panel', 'manager', 'shell', 'cmd', 'exec', 'debug',
        'test', 'dev', 'staging', 'internal', 'secret',
        'database', 'db', 'sql', 'dump', 'export',
        'flag', 'key', 'token', 'password', 'credentials',
        'robots.txt', 'sitemap.xml', 'crossdomain.xml',
        'server-status', 'server-info', '.well-known',
    }

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        paths: List[Dict[str, Any]] = []
        target = data.get("url", data.get("target", ""))

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Gobuster 扫描 {target}: 未发现任何路径",
                structured_data={"paths": [], "interesting": [], "total_found": 0},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.6,
            )

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            # gobuster 标准格式
            match = self._GOBUSTER_RE.search(stripped)
            if match:
                paths.append({
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3)) if match.group(3) else 0,
                    "redirect": match.group(4) or "",
                })
                continue

            # feroxbuster 格式
            match2 = self._FEROX_RE.search(stripped)
            if match2:
                url = match2.group(3)
                # 从 URL 中提取路径
                path = "/" + url.split("/", 3)[-1] if "/" in url[8:] else "/"
                paths.append({
                    "path": path,
                    "status": int(match2.group(1)),
                    "size": int(match2.group(2)),
                    "redirect": "",
                })

        # 识别高价值路径
        interesting = self._find_interesting(paths)

        # 构建 next_steps
        next_steps = self._build_next_steps(paths, interesting, target)

        # 摘要
        if not paths:
            summary = f"Gobuster 扫描 {target}: 未发现路径"
        else:
            status_200 = [p for p in paths if p["status"] == 200]
            summary = (
                f"Gobuster 扫描 {target}: 发现 {len(paths)} 个路径 "
                f"(其中 {len(status_200)} 个状态200)"
            )
            if interesting:
                summary += f", {len(interesting)} 个高价值路径: {', '.join(interesting[:5])}"

        # 严重性
        severity = "info"
        for path in interesting:
            pl = path.lower()
            if any(kw in pl for kw in ('.git', '.env', '.htpasswd', 'backup', 'dump', 'database', 'flag')):
                severity = "high"
                break
            if any(kw in pl for kw in ('admin', 'panel', 'console', 'phpmyadmin', 'debug')):
                severity = "medium"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "paths": paths,
                "interesting": interesting,
                "total_found": len(paths),
            },
            raw_output="",
            next_steps=next_steps,
            severity=severity,
            confidence=0.9 if paths else 0.6,
        )

    def _find_interesting(self, paths: List[Dict[str, Any]]) -> List[str]:
        """识别高价值路径"""
        interesting: List[str] = []
        for p in paths:
            path_lower = p["path"].lower()
            # 状态码 200/301/302/403 的路径都可能有价值
            if p["status"] in (200, 301, 302, 403):
                if any(kw in path_lower for kw in self._INTERESTING_KEYWORDS):
                    interesting.append(p["path"])
        return interesting

    def _build_next_steps(
        self,
        paths: List[Dict[str, Any]],
        interesting: List[str],
        target: str,
    ) -> List[str]:
        """根据发现的路径生成建议"""
        steps: List[str] = []

        int_lower = {p.lower() for p in interesting}

        if any('.git' in p for p in int_lower):
            steps.append("发现 .git 目录 → 尝试 git 信息泄露 (git-dumper)")

        if any('.env' in p for p in int_lower):
            steps.append("发现 .env 文件 → 直接访问获取敏感配置信息")

        if any(kw in p for p in int_lower for kw in ('admin', 'panel', 'dashboard', 'console')):
            steps.append(
                "发现管理后台 → 建议使用 hydra_attack 爆破登录, "
                "或使用 intelligent_sql_injection_payloads 测试SQL注入"
            )

        if any(kw in p for p in int_lower for kw in ('login', 'signin', 'auth')):
            steps.append(
                "发现登录页面 → 建议使用 intelligent_sql_injection_payloads 测试注入, "
                "hydra_attack 爆破凭据"
            )

        if any(kw in p for p in int_lower for kw in ('upload', 'file', 'attach')):
            steps.append("发现文件上传功能 → 测试文件上传绕过获取 Webshell")

        if any(kw in p for p in int_lower for kw in ('api', 'graphql', 'swagger', 'docs')):
            steps.append("发现 API 端点 → 建议进一步探测 API 接口和认证绕过")

        if any(kw in p for p in int_lower for kw in ('backup', 'dump', 'export', 'database')):
            steps.append("发现备份/导出路径 → 直接下载检查敏感数据泄露")

        if any('phpmyadmin' in p for p in int_lower):
            steps.append(
                "发现 phpMyAdmin → 建议使用 hydra_attack 爆破, 默认凭据 root/空密码"
            )

        # 通用建议
        php_paths = [p for p in paths if p["status"] == 200 and '.php' in p["path"].lower()]
        if php_paths:
            steps.append(
                f"发现 {len(php_paths)} 个PHP页面 → 建议使用 sqlmap_scan 测试SQL注入"
            )

        if len(paths) > 0 and not steps:
            steps.append(
                f"发现 {len(paths)} 个路径 → 建议使用 nuclei_web_scan 对目标进行漏洞扫描"
            )

        return steps


# ============================================================
# Nuclei 解析器
# ============================================================

class NucleiParser(BaseOutputParser):
    """
    Nuclei 输出解析器。

    支持两种格式:
    1. 文本格式: [severity] [template-id] [protocol] url
    2. JSONL 格式: 每行一个 JSON 对象

    structured_data 格式:
    {
        "vulnerabilities": [
            {"id": "CVE-2021-44228", "severity": "critical", "name": "Log4Shell",
             "url": "http://target/path", "matched": "..."}
        ],
        "stats": {"critical": 0, "high": 1, "medium": 3, "low": 0, "info": 5}
    }
    """

    tool_name = "nuclei"

    # 文本格式: [severity] [template-id] [protocol] url [additional info]
    _TEXT_RE = re.compile(
        r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)'
        r'(?:\s+\[([^\]]*)\])?'
    )

    _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        vulns: List[Dict[str, Any]] = []
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        target = data.get("target", "")

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Nuclei 扫描 {target}: 未发现漏洞",
                structured_data={"vulnerabilities": [], "stats": stats},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.7,
            )

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            vuln = None

            # 尝试 JSONL 格式
            if stripped.startswith('{'):
                vuln = self._parse_json_line(stripped)
            else:
                # 文本格式
                vuln = self._parse_text_line(stripped)

            if vuln:
                vulns.append(vuln)
                sev = vuln.get("severity", "info").lower()
                if sev in stats:
                    stats[sev] += 1

        # 确定最高严重性
        max_severity = "info"
        for sev in ("critical", "high", "medium", "low", "info"):
            if stats.get(sev, 0) > 0:
                max_severity = sev
                break

        # next_steps
        next_steps = self._build_next_steps(vulns)

        # 摘要
        if not vulns:
            summary = f"Nuclei 扫描 {target}: 未发现漏洞"
        else:
            parts = []
            for sev in ("critical", "high", "medium", "low", "info"):
                count = stats.get(sev, 0)
                if count > 0:
                    parts.append(f"{count} {sev}")
            summary = f"Nuclei 扫描 {target}: 发现 {len(vulns)} 个漏洞 ({', '.join(parts)})"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "vulnerabilities": vulns,
                "stats": stats,
            },
            raw_output="",
            next_steps=next_steps,
            severity=max_severity,
            confidence=0.95 if vulns else 0.7,
        )

    def _parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """解析 JSONL 格式的一行"""
        try:
            obj = json.loads(line)
            info = obj.get("info", {})
            classification = info.get("classification", {})

            # CVE ID 可能在多处
            cve_id = ""
            cve_ids = classification.get("cve-id", [])
            if isinstance(cve_ids, list) and cve_ids:
                cve_id = cve_ids[0]
            elif isinstance(cve_ids, str):
                cve_id = cve_ids

            return {
                "id": obj.get("template-id", obj.get("templateID", "")),
                "severity": info.get("severity", "info").lower(),
                "name": info.get("name", ""),
                "url": obj.get("matched-at", obj.get("host", "")),
                "matched": obj.get("matcher-name", ""),
                "cve_id": cve_id,
                "description": info.get("description", ""),
                "extracted_results": obj.get("extracted-results", []),
                "curl_command": obj.get("curl-command", ""),
            }
        except (json.JSONDecodeError, TypeError, AttributeError):
            return None

    def _parse_text_line(self, line: str) -> Optional[Dict[str, Any]]:
        """解析文本格式的一行"""
        match = self._TEXT_RE.match(line)
        if not match:
            return None

        severity = match.group(1).lower()
        template_id = match.group(2)
        url = match.group(4)
        extra = match.group(5) or ""

        # 提取 CVE
        cve_match = re.search(r'(CVE-\d{4}-\d+)', template_id, re.IGNORECASE)
        cve_id = cve_match.group(1) if cve_match else ""

        return {
            "id": template_id,
            "severity": severity,
            "name": template_id,
            "url": url,
            "matched": extra,
            "cve_id": cve_id,
            "description": "",
            "extracted_results": [],
            "curl_command": "",
        }

    def _build_next_steps(self, vulns: List[Dict[str, Any]]) -> List[str]:
        """根据漏洞发现生成建议"""
        steps: List[str] = []

        cve_vulns = [v for v in vulns if v.get("cve_id")]
        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
        high_vulns = [v for v in vulns if v.get("severity") == "high"]

        if critical_vulns:
            for v in critical_vulns[:3]:
                steps.append(
                    f"🔴 严重漏洞 {v['id']} → 建议使用 searchsploit_search 搜索利用代码, "
                    f"或使用 metasploit_run 尝试利用"
                )

        if high_vulns:
            for v in high_vulns[:3]:
                steps.append(
                    f"🟠 高危漏洞 {v['id']} → 建议使用 searchsploit_search 搜索exploit"
                )

        if cve_vulns and not steps:
            cve_list = [v["cve_id"] for v in cve_vulns[:5]]
            steps.append(
                f"发现 {len(cve_vulns)} 个CVE: {', '.join(cve_list)} → "
                f"建议使用 searchsploit_search 搜索利用方法"
            )

        sql_vulns = [v for v in vulns if 'sql' in v.get("id", "").lower()]
        if sql_vulns:
            steps.append("发现SQL注入相关漏洞 → 建议使用 sqlmap_scan 深入利用")

        xss_vulns = [v for v in vulns if 'xss' in v.get("id", "").lower()]
        if xss_vulns:
            steps.append("发现XSS相关漏洞 → 建议使用 intelligent_xss_payloads 生成利用载荷")

        if not steps and vulns:
            steps.append(
                f"发现 {len(vulns)} 个问题 → 建议进一步手动验证高优先级漏洞"
            )

        return steps


# ============================================================
# SQLMap 解析器
# ============================================================

class SqlmapParser(BaseOutputParser):
    """
    SQLMap 输出解析器。

    解析内容:
    - 注入点和注入类型
    - 数据库类型
    - 数据库/表/列枚举
    - 数据转储

    structured_data 格式:
    {
        "injectable": True,
        "parameter": "id",
        "db_type": "MySQL",
        "injection_types": ["boolean-blind", "time-blind"],
        "databases": ["mydb", "information_schema"],
        "tables": {"mydb": ["users", "posts"]},
        "data": {},
        "banner": "5.7.32-0ubuntu0.18.04.1"
    }
    """

    tool_name = "sqlmap"

    _DBMS_RE = re.compile(r'back-end DBMS:\s*(.+)', re.IGNORECASE)
    _PARAM_RE = re.compile(r"Parameter:\s+['\"]?(\w+)['\"]?", re.IGNORECASE)
    _BANNER_RE = re.compile(r'banner:\s*[\'"](.+)[\'"]', re.IGNORECASE)
    _INJECTION_TYPES = [
        "boolean-based", "time-based", "UNION query",
        "error-based", "stacked queries", "inline query",
    ]

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("url", data.get("target", ""))
        injectable = False
        parameter = ""
        db_type = ""
        injection_types: List[str] = []
        databases: List[str] = []
        tables: Dict[str, List[str]] = {}
        dumped_data: Dict[str, Any] = {}
        banner = ""

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"SQLMap 扫描 {target}: 无输出",
                structured_data={
                    "injectable": False, "parameter": "", "db_type": "",
                    "injection_types": [], "databases": [], "tables": {},
                    "data": {}, "banner": "",
                },
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        # 状态变量
        in_db_list = False
        in_table_list = False
        current_db = ""
        in_data_dump = False
        dump_table_name = ""
        dump_columns: List[str] = []
        dump_rows: List[Dict[str, str]] = []

        for line in output.split('\n'):
            stripped = line.strip()
            ll = stripped.lower()

            # 检测注入 — 排除否定
            if 'is vulnerable' in ll or ('injectable' in ll and 'not' not in ll):
                injectable = True

            # 注入类型
            for inj_type in self._INJECTION_TYPES:
                if inj_type.lower() in ll and inj_type not in injection_types:
                    injection_types.append(inj_type)
                    injectable = True

            # 参数
            param_match = self._PARAM_RE.search(stripped)
            if param_match and not parameter:
                parameter = param_match.group(1)

            # 数据库类型
            dbms_match = self._DBMS_RE.search(stripped)
            if dbms_match:
                db_type = dbms_match.group(1).strip()

            # Banner
            banner_match = self._BANNER_RE.search(stripped)
            if banner_match:
                banner = banner_match.group(1)

            # 数据库列表
            if 'available databases' in ll:
                in_db_list = True
                in_table_list = False
                continue

            if in_db_list:
                db_match = re.match(r'^\[\*\]\s+(\S+)', stripped)
                if db_match:
                    db_name = db_match.group(1)
                    if db_name not in databases:
                        databases.append(db_name)
                elif stripped and not stripped.startswith('['):
                    in_db_list = False

            # 表列表: Database: xxx, Table: yyy 或 [*] 格式
            if 'database:' in ll and 'table' not in ll:
                db_match = re.search(r'Database:\s*(\S+)', stripped, re.IGNORECASE)
                if db_match:
                    current_db = db_match.group(1)
                    in_table_list = True
                    in_db_list = False
                    if current_db not in tables:
                        tables[current_db] = []
                    continue

            if in_table_list and current_db:
                table_match = re.match(r'^\[\*\]\s+(\S+)', stripped)
                if table_match:
                    table_name = table_match.group(1)
                    if table_name not in tables.get(current_db, []):
                        tables.setdefault(current_db, []).append(table_name)
                elif stripped and not stripped.startswith('[') and not stripped.startswith('+'):
                    in_table_list = False

            # 数据转储检测 (简化处理 — 只检测是否有数据输出)
            if 'dumped to' in ll or 'fetched data' in ll:
                in_data_dump = True

        # 构建 next_steps
        next_steps: List[str] = []

        if injectable:
            if not databases:
                next_steps.append(
                    f"参数 '{parameter}' 存在SQL注入 → 建议使用 sqlmap_scan 加 --dbs 枚举数据库"
                )
            elif not tables:
                for db in databases[:3]:
                    next_steps.append(
                        f"发现数据库 '{db}' → 建议使用 sqlmap_scan 加 -D {db} --tables 枚举表"
                    )
            else:
                for db, tbl_list in list(tables.items())[:2]:
                    for tbl in tbl_list[:3]:
                        next_steps.append(
                            f"发现表 {db}.{tbl} → 建议使用 sqlmap_scan 加 "
                            f"-D {db} -T {tbl} --dump 导出数据"
                        )
            if db_type and 'mysql' in db_type.lower():
                next_steps.append("MySQL数据库 → 可尝试 --os-shell 获取系统权限")
        else:
            next_steps.append(
                "未发现SQL注入 → 建议尝试其他参数或使用 --level 5 --risk 3 深入测试"
            )

        # 摘要
        if injectable:
            summary = (
                f"SQLMap 扫描 {target}: 发现SQL注入! 参数: {parameter}, "
                f"类型: {', '.join(injection_types) or '未知'}, "
                f"数据库: {db_type or '未知'}"
            )
            if databases:
                summary += f", {len(databases)} 个数据库"
            severity = "critical"
        else:
            summary = f"SQLMap 扫描 {target}: 未发现SQL注入"
            severity = "info"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "injectable": injectable,
                "parameter": parameter,
                "db_type": db_type,
                "injection_types": injection_types,
                "databases": databases,
                "tables": tables,
                "data": dumped_data,
                "banner": banner,
            },
            raw_output="",
            next_steps=next_steps,
            severity=severity,
            confidence=0.95 if injectable else 0.7,
        )


# ============================================================
# Subfinder 解析器
# ============================================================

class SubfinderParser(BaseOutputParser):
    """
    Subfinder / 子域名枚举输出解析器。

    subfinder 输出格式: 每行一个子域名
        sub1.example.com
        sub2.example.com
        *.example.com  (通配符检测)

    structured_data 格式:
    {
        "subdomains": ["sub1.example.com", "sub2.example.com"],
        "count": 15,
        "wildcard_detected": False,
        "unique_prefixes": ["sub1", "sub2"]
    }
    """

    tool_name = "subfinder"

    _DOMAIN_RE = re.compile(r'^([a-zA-Z0-9*][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$')

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("domain", data.get("target", ""))
        subdomains: List[str] = []
        wildcard_detected = False

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Subfinder 扫描 {target}: 未发现子域名",
                structured_data={
                    "subdomains": [], "count": 0,
                    "wildcard_detected": False, "unique_prefixes": [],
                },
                raw_output="",
                next_steps=["未发现子域名 → 建议使用 amass_enum 或 dnsrecon_scan 进行更深入枚举"],
                severity="info",
                confidence=0.6,
            )

        seen: set = set()
        for line in output.split('\n'):
            domain = line.strip().lower()
            if not domain or domain in seen:
                continue

            # 跳过非域名行（日志、进度等）
            if not self._DOMAIN_RE.match(domain):
                continue

            seen.add(domain)
            subdomains.append(domain)

            if domain.startswith('*.'):
                wildcard_detected = True

        # 提取唯一前缀
        prefixes: List[str] = []
        if target:
            target_lower = target.lower().lstrip('.')
            for sub in subdomains:
                if sub.endswith('.' + target_lower):
                    prefix = sub[:-(len(target_lower) + 1)]
                    if prefix and prefix not in prefixes:
                        prefixes.append(prefix)

        # next_steps
        next_steps: List[str] = []
        if subdomains:
            next_steps.append(
                f"发现 {len(subdomains)} 个子域名 → 建议使用 httpx_probe 探测存活主机和Web服务"
            )
            next_steps.append(
                f"对存活子域名 → 建议使用 nmap_scan 扫描端口, nuclei_web_scan 扫描漏洞"
            )
            if wildcard_detected:
                next_steps.append("检测到通配符DNS记录 → 注意排除误报")

        # 摘要
        summary = f"Subfinder 扫描 {target}: 发现 {len(subdomains)} 个子域名"
        if wildcard_detected:
            summary += " (检测到通配符DNS)"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "subdomains": subdomains,
                "count": len(subdomains),
                "wildcard_detected": wildcard_detected,
                "unique_prefixes": prefixes[:50],  # 限制大小
            },
            raw_output="",
            next_steps=next_steps,
            severity="info",
            confidence=0.9 if subdomains else 0.5,
        )


# ============================================================
# Hydra 解析器
# ============================================================

class HydraParser(BaseOutputParser):
    """
    Hydra 密码爆破输出解析器。

    Hydra 成功格式:
        [22][ssh] host: 10.0.0.1   login: admin   password: password123
        [80][http-get] host: 10.0.0.1   login: admin   password: admin

    structured_data 格式:
    {
        "credentials": [
            {"host": "10.0.0.1", "port": 22, "service": "ssh",
             "login": "admin", "password": "password123"}
        ],
        "found": True,
        "attempts": 1234,
        "target": "10.0.0.1"
    }
    """

    tool_name = "hydra"

    # [port][service] host: x.x.x.x   login: xxx   password: xxx
    _CRED_RE = re.compile(
        r'\[(\d+)\]\[([^\]]+)\]\s+'
        r'host:\s+(\S+)\s+'
        r'login:\s+(\S+)\s+'
        r'password:\s+(\S*)',
        re.IGNORECASE,
    )

    # 尝试次数: 1 of 14344399 [child 0]
    _ATTEMPTS_RE = re.compile(r'(\d+)\s+of\s+(\d+)')

    # 完成摘要: 1 valid password found
    _FOUND_RE = re.compile(r'(\d+)\s+valid\s+password', re.IGNORECASE)

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        service = data.get("service", "")
        credentials: List[Dict[str, Any]] = []
        total_attempts = 0

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Hydra 爆破 {target}: 无输出",
                structured_data={
                    "credentials": [], "found": False,
                    "attempts": 0, "target": target,
                },
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()

            # 凭据匹配
            cred_match = self._CRED_RE.search(stripped)
            if cred_match:
                credentials.append({
                    "host": cred_match.group(3),
                    "port": int(cred_match.group(1)),
                    "service": cred_match.group(2),
                    "login": cred_match.group(4),
                    "password": cred_match.group(5),
                })
                continue

            # 尝试次数
            attempt_match = self._ATTEMPTS_RE.search(stripped)
            if attempt_match:
                total_attempts = max(total_attempts, int(attempt_match.group(2)))

        found = len(credentials) > 0

        # next_steps
        next_steps: List[str] = []
        if found:
            for cred in credentials[:3]:
                svc = cred["service"].lower()
                if 'ssh' in svc:
                    next_steps.append(
                        f"成功爆破 SSH {cred['login']}:{cred['password']} → "
                        f"建议 SSH 登录并检查权限提升"
                    )
                elif 'ftp' in svc:
                    next_steps.append(
                        f"成功爆破 FTP {cred['login']}:{cred['password']} → "
                        f"建议登录检查可上传目录"
                    )
                elif 'http' in svc or 'web' in svc:
                    next_steps.append(
                        f"成功爆破 Web登录 {cred['login']}:{cred['password']} → "
                        f"建议登录后台进一步渗透"
                    )
                elif 'mysql' in svc or 'postgres' in svc:
                    next_steps.append(
                        f"成功爆破 数据库 {cred['login']}:{cred['password']} → "
                        f"建议连接数据库提取数据"
                    )
                else:
                    next_steps.append(
                        f"成功爆破 {svc} {cred['login']}:{cred['password']} → "
                        f"建议登录目标服务"
                    )
        else:
            next_steps.append(
                "未找到有效凭据 → 建议更换字典或使用更大的密码列表重试"
            )

        # 摘要
        if found:
            cred_desc = "; ".join(
                f"{c['login']}:{c['password']}@{c['service']}" for c in credentials[:3]
            )
            summary = f"Hydra 爆破 {target}: 成功! 发现 {len(credentials)} 个凭据: {cred_desc}"
            severity = "critical"
        else:
            summary = f"Hydra 爆破 {target}/{service}: 未找到有效凭据 ({total_attempts} 次尝试)"
            severity = "info"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "credentials": credentials,
                "found": found,
                "attempts": total_attempts,
                "target": target,
            },
            raw_output="",
            next_steps=next_steps,
            severity=severity,
            confidence=0.99 if found else 0.6,
        )


# ============================================================
# Nikto 解析器
# ============================================================

class NiktoParser(BaseOutputParser):
    """
    Nikto Web 服务器扫描输出解析器。

    Nikto 输出格式:
        + OSVDB-3092: /admin/: This might be interesting...
        + /login.php: Admin login page/section found.
        + Server: Apache/2.4.41

    structured_data 格式:
    {
        "findings": [{"id": "OSVDB-3092", "url": "/admin/", "description": "..."}],
        "server": "Apache/2.4.41",
        "total_findings": 12,
        "interesting_findings": 3
    }
    """

    tool_name = "nikto"

    # + OSVDB-xxxx: /path: description
    _FINDING_RE = re.compile(
        r'^\+\s+'
        r'(?:(OSVDB-\d+|CVE-[\d-]+):\s+)?'
        r'(/\S*):\s+'
        r'(.+)'
    )
    # + Server: Apache/2.4.41
    _SERVER_RE = re.compile(r'^\+\s+Server:\s+(.+)', re.IGNORECASE)

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        findings: List[Dict[str, str]] = []
        server = ""

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Nikto 扫描 {target}: 无输出",
                structured_data={
                    "findings": [], "server": "",
                    "total_findings": 0, "interesting_findings": 0,
                },
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()

            # 服务器信息
            server_match = self._SERVER_RE.match(stripped)
            if server_match:
                server = server_match.group(1).strip()
                continue

            # 发现
            finding_match = self._FINDING_RE.match(stripped)
            if finding_match:
                findings.append({
                    "id": finding_match.group(1) or "",
                    "url": finding_match.group(2),
                    "description": finding_match.group(3).strip(),
                })

        # 分类
        interesting = [
            f for f in findings
            if any(kw in f["description"].lower() for kw in
                   ('admin', 'login', 'upload', 'backup', 'config',
                    'interesting', 'dangerous', 'vulnerability', 'disclosure'))
        ]

        # 严重性
        severity = "info"
        if any('cve' in f.get("id", "").lower() for f in findings):
            severity = "high"
        elif interesting:
            severity = "medium"

        # next_steps
        next_steps: List[str] = []
        if findings:
            next_steps.append(
                f"Nikto 发现 {len(findings)} 个问题 → 建议使用 nuclei_web_scan 交叉验证"
            )
        if server:
            next_steps.append(
                f"服务器 {server} → 建议使用 searchsploit_search 检查版本漏洞"
            )

        summary = f"Nikto 扫描 {target}: 发现 {len(findings)} 个问题"
        if server:
            summary += f", 服务器: {server}"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "findings": findings,
                "server": server,
                "total_findings": len(findings),
                "interesting_findings": len(interesting),
            },
            raw_output="",
            next_steps=next_steps,
            severity=severity,
            confidence=0.85 if findings else 0.6,
        )


# ============================================================
# WhatWeb 解析器
# ============================================================

class WhatwebParser(BaseOutputParser):
    """
    WhatWeb 技术栈识别输出解析器。

    structured_data 格式:
    {
        "technologies": [{"name": "Apache", "version": "2.4.41", "category": "server"}],
        "server": "Apache 2.4.41",
        "cms": "WordPress",
        "language": "PHP",
        "framework": ""
    }
    """

    tool_name = "whatweb"

    _TECH_RE = re.compile(r'(\w[\w\s.-]*?)(?:\[([^\]]*)\])?(?:,|$)')

    _SERVER_NAMES = {'apache', 'nginx', 'iis', 'lighttpd', 'litespeed', 'caddy'}
    _CMS_NAMES = {
        'wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'typo3',
        'mediawiki', 'moodle', 'ghost', 'hugo', 'jekyll',
    }
    _LANG_NAMES = {'php', 'python', 'java', 'asp.net', 'ruby', 'perl', 'node.js'}
    _FRAMEWORK_NAMES = {
        'django', 'rails', 'laravel', 'spring', 'flask', 'express',
        'angular', 'react', 'vue', 'symfony', 'codeigniter', 'thinkphp',
    }

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        technologies: List[Dict[str, str]] = []
        server = ""
        cms = ""
        language = ""
        framework = ""

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"WhatWeb 扫描 {target}: 无输出",
                structured_data={
                    "technologies": [], "server": "",
                    "cms": "", "language": "", "framework": "",
                },
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.5,
            )

        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            for match in self._TECH_RE.finditer(stripped):
                name = match.group(1).strip()
                version = match.group(2) or ""

                if not name or name in ('200 OK', '301', '302', '403', '404', 'Country'):
                    continue

                name_lower = name.lower()
                category = "other"

                if name_lower in self._SERVER_NAMES:
                    category = "server"
                    server = f"{name} {version}".strip()
                elif name_lower in self._CMS_NAMES:
                    category = "cms"
                    cms = name
                elif name_lower in self._LANG_NAMES:
                    category = "language"
                    language = name
                elif name_lower in self._FRAMEWORK_NAMES:
                    category = "framework"
                    framework = name
                elif name_lower in ('jquery', 'bootstrap', 'modernizr', 'font-awesome'):
                    category = "js-lib"

                technologies.append({
                    "name": name,
                    "version": version,
                    "category": category,
                })

        # next_steps
        next_steps: List[str] = []
        if cms.lower() == 'wordpress':
            next_steps.append("发现 WordPress → 建议使用 wpscan_scan 深度扫描插件/主题漏洞")
        elif cms.lower() == 'joomla':
            next_steps.append("发现 Joomla → 建议使用 joomscan_scan 深度扫描")

        if server:
            next_steps.append(f"服务器 {server} → 建议使用 searchsploit_search 检查版本漏洞")

        if language.lower() == 'php':
            next_steps.append("PHP 技术栈 → 注意 LFI/RFI/反序列化等漏洞")
        elif 'java' in language.lower() or 'spring' in framework.lower():
            next_steps.append("Java/Spring 技术栈 → 注意 OGNL/SpEL 注入、反序列化漏洞")

        if framework.lower() == 'thinkphp':
            next_steps.append("ThinkPHP 框架 → 建议使用 nuclei_cve_scan 检查已知RCE漏洞")

        summary = f"WhatWeb 扫描 {target}: "
        parts = []
        if server:
            parts.append(f"服务器: {server}")
        if cms:
            parts.append(f"CMS: {cms}")
        if language:
            parts.append(f"语言: {language}")
        if framework:
            parts.append(f"框架: {framework}")
        summary += ", ".join(parts) if parts else f"识别到 {len(technologies)} 项技术"

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "technologies": technologies,
                "server": server,
                "cms": cms,
                "language": language,
                "framework": framework,
            },
            raw_output="",
            next_steps=next_steps,
            severity="info",
            confidence=0.85 if technologies else 0.5,
        )


# ============================================================
# Masscan 解析器
# ============================================================

class MasscanParser(BaseOutputParser):
    """
    Masscan 快速端口扫描输出解析器。

    Masscan 输出格式:
        Discovered open port 80/tcp on 192.168.1.1
        Discovered open port 443/tcp on 192.168.1.1

    structured_data 格式:
    {
        "ports": [{"port": 80, "protocol": "tcp", "host": "192.168.1.1"}],
        "hosts": ["192.168.1.1"],
        "open_port_count": 2
    }
    """

    tool_name = "masscan"

    _PORT_RE = re.compile(
        r'Discovered open port (\d+)/(tcp|udp) on (\S+)'
    )

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        target = data.get("target", "")
        ports: List[Dict[str, Any]] = []
        hosts: set = set()

        if not output.strip():
            return ParsedResult(
                tool_name=self.tool_name,
                success=return_code == 0,
                summary=f"Masscan 扫描 {target}: 未发现开放端口",
                structured_data={"ports": [], "hosts": [], "open_port_count": 0},
                raw_output="",
                next_steps=[],
                severity="info",
                confidence=0.6,
            )

        for line in output.split('\n'):
            match = self._PORT_RE.search(line.strip())
            if match:
                host = match.group(3)
                hosts.add(host)
                ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "host": host,
                })

        # next_steps
        next_steps: List[str] = []
        if ports:
            host_list = sorted(hosts)
            port_str = ",".join(str(p["port"]) for p in sorted(ports, key=lambda x: x["port"]))
            next_steps.append(
                f"发现 {len(ports)} 个开放端口 → 建议使用 nmap_scan -sV "
                f"对这些端口进行服务版本检测"
            )
            web_ports = [p for p in ports if p["port"] in (80, 443, 8080, 8443, 8888)]
            if web_ports:
                next_steps.append(
                    f"发现Web端口 → 建议使用 whatweb_scan 识别技术栈"
                )

        summary = (
            f"Masscan 扫描 {target}: 发现 {len(ports)} 个开放端口 "
            f"在 {len(hosts)} 个主机上"
        )

        return ParsedResult(
            tool_name=self.tool_name,
            success=return_code == 0,
            summary=summary,
            structured_data={
                "ports": ports,
                "hosts": sorted(hosts),
                "open_port_count": len(ports),
            },
            raw_output="",
            next_steps=next_steps,
            severity="info",
            confidence=0.85 if ports else 0.6,
        )


# ============================================================
# 通用解析器 (Fallback)
# ============================================================

class GenericParser(BaseOutputParser):
    """
    通用解析器 — 用于所有没有专用解析器的工具。

    特点:
    - 智能截断（保留头部和尾部，优于简单的 output[:5000]）
    - Flag 自动检测
    - 基本错误行识别
    - 输出统计

    structured_data 格式:
    {
        "output_length": 5000,
        "truncated": True,
        "line_count": 150,
        "error_lines": ["ERROR: connection refused"],
        "warning_lines": ["WARNING: timeout on host 10.0.0.1"]
    }
    """

    tool_name = "generic"

    _ERROR_RE = re.compile(
        r'(?:error|fail|fatal|exception|denied|refused|timeout|unreachable)',
        re.IGNORECASE,
    )
    _WARNING_RE = re.compile(
        r'(?:warn|caution|notice|deprecated|skipping)',
        re.IGNORECASE,
    )

    def _parse_output(
        self,
        output: str,
        return_code: int,
        data: Dict[str, Any],
    ) -> ParsedResult:
        tool_name = data.get("_tool_name", "unknown")
        target = data.get("target", data.get("url", data.get("domain", "")))
        success = return_code == 0

        if not output.strip():
            return ParsedResult(
                tool_name=tool_name,
                success=success,
                summary=f"{tool_name} {'执行成功' if success else '执行失败'}: 无输出",
                structured_data={
                    "output_length": 0, "truncated": False,
                    "line_count": 0, "error_lines": [], "warning_lines": [],
                },
                raw_output="",
                next_steps=[],
                severity="info" if success else "low",
                confidence=0.3,
            )

        lines = output.split('\n')
        line_count = len(lines)

        # 识别错误和警告行
        error_lines: List[str] = []
        warning_lines: List[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if self._ERROR_RE.search(stripped):
                error_lines.append(stripped[:200])  # 限制单行长度
            elif self._WARNING_RE.search(stripped):
                warning_lines.append(stripped[:200])

        # 限制错误/警告数量
        error_lines = error_lines[:20]
        warning_lines = warning_lines[:10]

        was_truncated = len(output) > 5000

        # 摘要
        if success:
            summary = f"{tool_name} 执行成功: {line_count} 行输出"
            if error_lines:
                summary += f", {len(error_lines)} 个错误/警告"
        else:
            if error_lines:
                summary = f"{tool_name} 执行失败: {error_lines[0][:80]}"
            else:
                summary = f"{tool_name} 执行失败 (退出码: {return_code})"

        severity = "info"
        if not success:
            severity = "low"
        if error_lines:
            severity = "low"

        return ParsedResult(
            tool_name=tool_name,
            success=success,
            summary=summary,
            structured_data={
                "output_length": len(output),
                "truncated": was_truncated,
                "line_count": line_count,
                "error_lines": error_lines,
                "warning_lines": warning_lines,
            },
            raw_output="",
            next_steps=[],
            severity=severity,
            confidence=0.3,  # 通用解析器置信度低
        )


# ============================================================
# 解析器注册表和调度器
# ============================================================

# 解析器单例注册表
PARSER_REGISTRY: Dict[str, BaseOutputParser] = {
    # 端口扫描
    "nmap": NmapParser(),
    "masscan": MasscanParser(),
    # 目录扫描
    "gobuster": GobusterParser(),
    "dirb": GobusterParser(),
    "ffuf": GobusterParser(),
    "feroxbuster": GobusterParser(),
    # 漏洞扫描
    "nuclei": NucleiParser(),
    "nikto": NiktoParser(),
    # SQL 注入
    "sqlmap": SqlmapParser(),
    # 子域名枚举
    "subfinder": SubfinderParser(),
    "sublist3r": SubfinderParser(),
    "amass": SubfinderParser(),
    # 密码爆破
    "hydra": HydraParser(),
    # 技术栈识别
    "whatweb": WhatwebParser(),
}

# 通用解析器实例
_GENERIC_PARSER = GenericParser()


def parse_output(
    tool_name: str,
    output: str,
    return_code: int = 0,
    data: Optional[Dict[str, Any]] = None,
) -> ParsedResult:
    """
    解析工具输出的主入口 — 根据工具名自动分发到对应解析器。

    Args:
        tool_name: 工具名称 (nmap, gobuster, nuclei, sqlmap, etc.)
        output: 工具的原始 stdout 输出
        return_code: 进程退出码
        data: 工具调用时的参数字典

    Returns:
        统一的 ParsedResult

    Examples:
        >>> result = parse_output("nmap", nmap_output, 0, {"target": "10.0.0.1"})
        >>> result.structured_data["ports"]
        [{"port": 80, "protocol": "tcp", "state": "open", ...}]

        >>> result = parse_output("gobuster", gobuster_output, 0, {"url": "http://target"})
        >>> result.structured_data["interesting"]
        ["/admin", "/.git"]
    """
    data = data or {}

    # 规范化工具名
    normalized = tool_name.lower().strip()

    parser = PARSER_REGISTRY.get(normalized, _GENERIC_PARSER)

    # 为通用解析器传递工具名
    if parser is _GENERIC_PARSER:
        data = dict(data)
        data["_tool_name"] = tool_name

    try:
        return parser.parse(output, return_code, data)
    except Exception as e:
        logger.error(f"解析器 {normalized} 异常: {e}")
        # 最终兜底 — 即使解析器完全崩溃也返回有用结果
        truncated, _ = smart_truncate(output or "")
        return ParsedResult(
            tool_name=tool_name,
            success=return_code == 0,
            summary=f"{tool_name} 输出解析异常: {str(e)[:100]}",
            structured_data={"parse_error": str(e)},
            raw_output=truncated,
            flags_found=detect_flags(output or ""),
            next_steps=[],
            severity="info",
            confidence=0.0,
        )


def get_parser(tool_name: str) -> BaseOutputParser:
    """
    获取指定工具的解析器实例。

    Args:
        tool_name: 工具名称

    Returns:
        解析器实例（无匹配时返回 GenericParser）
    """
    return PARSER_REGISTRY.get(tool_name.lower().strip(), _GENERIC_PARSER)


def register_parser(tool_name: str, parser: BaseOutputParser) -> None:
    """
    注册自定义解析器。

    Args:
        tool_name: 工具名称
        parser: 解析器实例
    """
    PARSER_REGISTRY[tool_name.lower().strip()] = parser


def list_parsers() -> Dict[str, str]:
    """列出所有已注册的解析器及其类名"""
    return {
        name: type(parser).__name__
        for name, parser in PARSER_REGISTRY.items()
    }
