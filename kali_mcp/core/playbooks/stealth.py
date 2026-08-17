#!/usr/bin/env python3
"""stealth playbook: 反检测/隐身执行链（AI 渗透指纹隐藏）。

核心目标：
1. 隐藏 AI 渗透指纹（User-Agent/Header 随机化、请求节奏、TLS 指纹）
2. 降低被 WAF/EDR 识别的概率
3. 通过代理链/轮换出口执行
4. 日志与痕迹最小化
"""

from __future__ import annotations

import json
import os
import random
import time
from typing import Any, Dict, List, Optional

from kali_mcp.core.action_log import log_action
from kali_mcp.core.evidence_store import save_evidence

# 真实浏览器 User-Agent 池（模拟人工浏览，避免 AI 工具默认指纹）
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

# 请求间隔范围（秒）——模拟人工浏览节奏
REQUEST_DELAY_RANGE = (0.8, 3.5)

# 常见 AI 工具指纹（需要规避的默认特征）
AI_FINGERPRINTS = [
    "python-requests",
    "python-urllib",
    "Go-http-client",
    "axios/",
    "curl/",
    "Wget/",
    "aiohttp",
    "httpx",
]

# 统一速率与痕迹纪律（口头限定：prompt 级纪律条款，机械兜底 = fastsec 内建节流）。
# 供 agent 提示词 / harness 子代理定义复用（web_vuln_agent ROLE_PROMPT 等注入点）。
RATE_DISCIPLINE = """## 速率与痕迹纪律（每次工具调用前必读）
1. 任何扫描/爆破工具调用前，先评估目标业务影响：优先用低并发与默认节流（fastsec 默认 -c 20 / delay 300-800ms 已内建，不要用 -c 覆盖超过默认）。
2. 不需要 -c 50 类激进并发；多目标时用 -c/-delay 参数（fastsec -c 8 --delay-min 500）。
3. 不向生产目标发送对业务有影响的 payload：XSS 用无害 marker（-xss-benign 默认），不跑 alert(1) 集除非显式授权。
4. 验证用最小请求（基线+marker），不留扫描特征参数。
5. 所有请求 UA 用真实浏览器 UA，禁止任何 KaliMCP 品牌 UA（POCScanner/probe 旧标识）。
6. 验证即停，不自动推进：利用到 shell/PoC 存在即回传，不自动后渗透；SQLi/XSS 默认 -danger-level 0（只读探测），写操作（INSERT/UPDATE/DELETE/DROP/--dump）需显式授权与 -danger-level 2。"""


def _random_ua() -> str:
    return random.choice(UA_POOL)


def stealth_headers() -> Dict[str, str]:
    """生成伪装成真实浏览器的请求头。"""
    return {
        "User-Agent": _random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }


def build_stealth_command(tool: str, target: str, extra_args: str = "",
                          use_proxy: bool = True) -> str:
    """为工具命令注入隐身参数（UA 伪装 + 节奏 + 可选代理）。"""
    ua = _random_ua()
    parts = [tool]

    # 按工具注入隐身参数
    if tool in ("curl",):
        parts.append(f"-A '{ua}'")
        parts.append("--compressed")
        parts.append("--http1.1")
        if use_proxy:
            proxy = os.environ.get("PENTEST_PROXY", "")
            if proxy:
                parts.append(f"-x {proxy}")
    elif tool in ("nmap",):
        parts.append("-T3")          # 温和时序，避免 -T5 被 IDS 标记
        parts.append("--randomize-hosts")
        if use_proxy:
            proxy = os.environ.get("PENTEST_SOCKS_PROXY", "")
            if proxy:
                parts.append(f"--proxies {proxy}")
    elif tool in ("nuclei",):
        parts.append(f"-H 'User-Agent: {ua}'")
        parts.append("-rl 10")       # 限速 10 req/s
        parts.append("-delay 500ms")
    elif tool in ("ffuf", "gobuster"):
        parts.append(f"-H 'User-Agent: {ua}'")
        parts.append("-rate 50")     # 限速
    elif tool in ("sqlmap",):
        parts.append(f"--user-agent='{ua}'")
        parts.append("--delay=1")
        parts.append("--random-agent")  # sqlmap 自带随机 UA
        if use_proxy:
            proxy = os.environ.get("PENTEST_PROXY", "")
            if proxy:
                parts.append(f"--proxy={proxy}")
    elif tool in ("fastsec", "fastsec_scan"):
        # fastsec 分支：UA 由 stealth.Client 内建随机真实浏览器 UA（无需 -A）；
        # 这里只加温和节流（不覆盖内建默认的激进并发）
        parts.append("--delay-min 500")
        parts.append("--delay-max 1500")
        parts.append("-c 8")
        if use_proxy:
            proxy = os.environ.get("PENTEST_PROXY", "")
            if proxy:
                parts.append(f"--proxy {proxy}")

    parts.append(target)
    if extra_args:
        parts.append(extra_args)
    return " ".join(parts)


def stealth_sleep():
    """模拟人工浏览节奏的随机延迟。"""
    time.sleep(random.uniform(*REQUEST_DELAY_RANGE))


def run_stealth_scan(executor, target: str, tool: str = "curl",
                     extra_args: str = "", use_proxy: bool = True) -> Dict[str, Any]:
    """以隐身模式执行单工具扫描。

    Args:
        executor: LocalCommandExecutor
        target: 目标 URL/IP
        tool: 工具名（curl/nmap/nuclei/ffuf/gobuster/sqlmap）
        extra_args: 额外参数
        use_proxy: 是否使用配置的代理链
    """
    stealth_sleep()  # 先模拟人工节奏
    cmd = build_stealth_command(tool, target, extra_args, use_proxy)
    result = executor.execute_command(cmd, timeout=120)

    # 审计记录（不含敏感代理细节）
    entry = {
        "phase": "stealth",
        "tool": tool,
        "target": target,
        "success": bool(result.get("success")),
        "ua_masked": True,
        "proxy_used": bool(use_proxy and os.environ.get("PENTEST_PROXY")),
        "output": (result.get("output") or "")[:600],
        "duration": result.get("duration", 0),
    }
    try:
        log_action(str(target), phase="stealth", target=str(target), tool=tool,
                   exit_code=result.get("return_code"),
                   duration_ms=entry["duration"])
    except Exception:
        pass
    try:
        save_evidence(
            str(target), name="stealth_scan",
            content=str(entry), meta={"tool": tool, "success": entry["success"]},
        )
    except Exception:
        pass
    return result


def check_ai_fingerprint(executor, target: str) -> Dict[str, Any]:
    """检查目标是否能识别出 AI 工具指纹（自测）。"""
    results = {}
    for fp in AI_FINGERPRINTS:
        # 用裸 UA 请求，看响应是否被拦截/差异化
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -A '{fp}' {target}"
        r = executor.execute_command(cmd, timeout=30)
        results[fp] = r.get("output", "?")
    return {
        "target": target,
        "fingerprint_probe": results,
        "note": "不同 UA 的 HTTP 状态码差异可提示目标是否做 UA 指纹检测",
    }


def check_brand_ua_clean() -> List[str]:
    """回归测试钩子：扫描本仓库代码面，确认无品牌 UA/特征参数残留。

    返回仍含品牌指纹的文件路径列表（空 = 干净）。
    品牌字符串以拼接形式书写，避免本函数自身被指纹扫描命中。
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    patterns = [
        re.compile("KaliMCP-" + "POCScanner" + r"|kali-mcp" + r"-probe|fastsec" + r"-ai"),
        re.compile("__fastsec" + "_baseline_probe__" + r"|__dir" + r"_probe_404__"),
    ]
    hits = []
    for p in root.rglob("*.py"):
        if "__pycache__" in str(p) or ".venv" in str(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pat in patterns:
            if pat.search(text):
                hits.append(str(p.relative_to(root)))
                break
    return sorted(set(hits))
