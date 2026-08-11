#!/usr/bin/env python3
"""smart_dir.py — 智能目录枚举（目录类升级 D1+D2）。

相对原生 gobuster/ffuf 的升级:
  D1 JS 端点预提取: 拉前端 JS → 正则提取真实 API 路径 → 优先测（跳过纯字典）
  D2 3-gate 通配过滤: 发现的路径基线对比（SPA 全 200 自动过滤，防误报）

用法:
    py smart_dir.py -u http://target
    py smart_dir.py -u http://target -w /usr/share/seclists/Discovery/Web-Content/common.txt
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, List


# D1: 从 JS 提取 API 路径的正则
JS_API_PATTERNS = [
    r'["\'](/api/[^"\']{2,80})["\']',
    r'["\'](/v\d+/[^"\']{2,80})["\']',
    r'["\'](/admin[^"\']{2,60})["\']',
    r'["\'](/user[^"\']{2,60})["\']',
    r'["\'](/manage[^"\']{2,60})["\']',
    r'["\'](/login[^"\']{2,40})["\']',
    r'["\'](/upload[^"\']{2,40})["\']',
    r'["\'](/config[^"\']{2,40})["\']',
    r'["\'](/backup[^"\']{2,40})["\']',
    r'["\'](/\.git[^"\']{2,40})["\']',
]


def extract_js_endpoints(base_url: str) -> List[str]:
    """拉首页 → 找 JS 文件 → 提取 API 路径（D1）。"""
    endpoints = set()
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", "replace")
        # 找 JS 文件
        js_files = re.findall(r'(?:src|href)="([^"]+\.js[^"]*)"', html)
        for js in js_files[:5]:
            js_url = js if js.startswith("http") else base_url.rstrip("/") + ("/" + js.lstrip("/") if not js.startswith("/") else js)
            try:
                req2 = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req2, timeout=15) as resp2:
                    js_content = resp2.read().decode("utf-8", "replace")
                for pat in JS_API_PATTERNS:
                    for m in re.finditer(pat, js_content):
                        p = m.group(1)
                        if p and not p.endswith((".js", ".css", ".png", ".svg")):
                            endpoints.add(p)
            except Exception:
                continue
    except Exception:
        pass
    return sorted(endpoints)


def probe_path(base_url: str, path: str, timeout: int = 10) -> tuple:
    """探测单路径，返回 (status, body_len, body_sample)。"""
    url = base_url.rstrip("/") + ("/" + path.lstrip("/") if not path.startswith("/") else path)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(512).decode("utf-8", "replace")
            return resp.status, len(body), body[:64]
    except urllib.error.HTTPError as e:
        try:
            body = e.read(256).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, len(body), body[:64]
    except Exception:
        return 0, 0, ""


def smart_dir(base_url: str, wordlist: str = "") -> Dict[str, any]:
    """智能目录枚举：JS 端点优先 + 字典补充 + 3-gate 过滤。"""
    print(f"[smart-dir] {base_url}")

    # D1: JS 端点预提取
    js_eps = extract_js_endpoints(base_url)
    print(f"[smart-dir] D1 JS 提取 {len(js_eps)} 个端点")
    for e in js_eps[:10]:
        print(f"  {e}")

    # 合并候选：JS 端点优先 + 字典
    candidates = list(js_eps)
    if wordlist and Path(wordlist).exists():
        dict_paths = [l.strip() for l in open(wordlist, encoding="utf-8", errors="replace")
                      if l.strip() and l.startswith("/")]
        # 字典只取前 200（控制请求量）
        candidates += dict_paths[:200]

    # D2: 3-gate 通配过滤——先测基线（随机路径测默认响应）
    baseline_status, baseline_len, baseline_sample = probe_path(base_url, "/__smart_dir_probe_404__")
    print(f"[smart-dir] 基线(404默认): status={baseline_status} len={baseline_len}")

    findings = []
    for path in candidates[:250]:
        status, blen, sample = probe_path(base_url, path)
        # D2: 与基线对比（状态不同 或 长度差异 >20% = 真路径）
        is_real = False
        if status != baseline_status:
            is_real = True
        elif baseline_len > 0 and abs(blen - baseline_len) > baseline_len * 0.2:
            is_real = True
        if is_real and status in (200, 301, 302, 403):
            findings.append({"path": path, "status": status, "len": blen})
            print(f"  [+] {status} {path} ({blen}B)")

    # 结果入库（资产）
    try:
        out = {"findings": [{
            "task_id": "smart_dir", "title": f"路径 {f['path']} ({f['status']})",
            "target": base_url + f["path"], "severity": "info", "source": "smart_dir",
            "meta": {"status": f["status"], "len": f["len"]},
        } for f in findings]}
        Path("/tmp/smart_dir_findings.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    except Exception:
        pass

    return {"endpoints": js_eps, "findings": findings, "count": len(findings)}


def main():
    ap = argparse.ArgumentParser(description="智能目录枚举")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-w", "--wordlist", default="", help="补充字典")
    args = ap.parse_args()
    r = smart_dir(args.url, args.wordlist)
    print(f"\n[smart-dir] 完成: JS 端点 {len(r['endpoints'])} 确认路径 {r['count']}")


if __name__ == "__main__":
    main()
