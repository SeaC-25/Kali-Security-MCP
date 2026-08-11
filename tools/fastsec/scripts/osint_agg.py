#!/usr/bin/env python3
"""osint_agg.py — OSINT 多源聚合 + 审计结果分级（P3 O1+E1）。

O1: theharvester/sherlock 结果合并去重 → 优先级排序（email→username→domain）
E1: semgrep/bandit 结果分级（规则权重 + 上下文）

用法:
    py osint_agg.py -d example.com -o /tmp/osint.json
    py osint_agg.py --audit-semgrep /path/to/code
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List


# ---- O1: OSINT 多源聚合 ----
def run_theharvester(domain: str) -> List[str]:
    """theharvester 查邮箱/子域/主机。"""
    results = []
    try:
        r = subprocess.run(["theharvester", "-d", domain, "-b", "all", "-l", "50"],
                           capture_output=True, text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        # 邮箱
        results += re.findall(r"[\w.+-]+@[\w.-]+\.\w+", out)
        # 子域/主机
        results += re.findall(r"(?:[\w-]+\.)+" + re.escape(domain), out)
    except Exception:
        pass
    return results


def run_sherlock(username: str) -> List[str]:
    """sherlock 查用户名跨平台存在。"""
    results = []
    try:
        r = subprocess.run(["sherlock", username, "--print-found"], capture_output=True, text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        # [+] Username: xxx [site]
        results += re.findall(r"\[\+\] Username: \S+ \[(\S+)\]", out)
    except Exception:
        pass
    return results


def aggregate(domain: str, usernames: List[str]) -> Dict[str, any]:
    """多源聚合 → 优先级排序。"""
    print(f"[osint] 聚合 {domain}")
    emails = set()
    subdomains = set()
    hosts = set()

    # theharvester
    th = run_theharvester(domain)
    for item in th:
        if "@" in item:
            emails.add(item)
        elif item.endswith(domain):
            subdomains.add(item)
        else:
            hosts.add(item)
    print(f"[osint] theharvester: {len(emails)} 邮箱 {len(subdomains)} 子域")

    # sherlock
    usernames_found = {}
    for u in usernames[:10]:
        sites = run_sherlock(u)
        if sites:
            usernames_found[u] = sites
            print(f"[osint] sherlock: {u} → {sites[:3]}...")

    # 优先级排序: email > username > domain
    priority = sorted(
        [{"type": "email", "value": e} for e in emails] +
        [{"type": "username", "value": u, "sites": s} for u, s in usernames_found.items()] +
        [{"type": "subdomain", "value": s} for s in subdomains],
        key=lambda x: {"email": 0, "username": 1, "subdomain": 2}[x["type"]],
    )

    return {
        "domain": domain,
        "emails": sorted(emails),
        "subdomains": sorted(subdomains),
        "usernames": usernames_found,
        "priority": priority,
    }


# ---- E1: 审计结果分级 ----
SEVERITY_WEIGHT = {"critical": 10, "high": 8, "medium": 5, "low": 2, "error": 8, "warning": 3, "info": 1}
RULE_BOOST = {
    "sql-injection": 3, "command-injection": 3, "path-traversal": 3,
    "hardcoded": 2, "secret": 3, "injection": 2, "eval": 2,
    "deserialization": 3, "ssrf": 3, "xxe": 3,
}


def audit_semgrep(code_dir: str) -> List[Dict]:
    """semgrep 扫描 → 规则权重分级。"""
    findings = []
    try:
        r = subprocess.run(["semgrep", "--json", "-q", str(code_dir)],
                           capture_output=True, text=True, timeout=180)
        out = r.stdout or ""
        try:
            data = json.loads(out)
            for res in data.get("results", []):
                rule = res.get("check_id", "")
                sev = res.get("extra", {}).get("severity", "warning").lower()
                score = SEVERITY_WEIGHT.get(sev, 3)
                # 规则关键词加权
                for kw, boost in RULE_BOOST.items():
                    if kw in rule.lower():
                        score += boost
                findings.append({
                    "rule": rule, "severity": sev, "score": score,
                    "file": res.get("path", ""),
                    "line": res.get("start", {}).get("line", 0),
                })
        except Exception:
            pass
    except Exception:
        pass
    # 按 score 降序
    findings.sort(key=lambda x: -x["score"])
    return findings


def main():
    ap = argparse.ArgumentParser(description="OSINT 聚合 + 审计分级")
    ap.add_argument("-d", "--domain", default="", help="target domain")
    ap.add_argument("-u", "--usernames", default="", help="usernames (comma)")
    ap.add_argument("--audit-semgrep", default="", help="code dir for semgrep audit")
    ap.add_argument("-o", "--output", default="/tmp/osint_agg.json")
    args = ap.parse_args()

    result = {}
    if args.domain:
        users = [u.strip() for u in args.usernames.split(",") if u.strip()]
        result["osint"] = aggregate(args.domain, users)
    if args.audit_semgrep:
        result["audit"] = audit_semgrep(args.audit_semgrep)
        print(f"[audit] semgrep 分级 {len(result['audit'])} 条")
        for f in result["audit"][:10]:
            print(f"  [{f['severity']}/{f['score']}] {f['rule']} {f['file']}:{f['line']}")

    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"[osint] 结果 → {args.output}")


if __name__ == "__main__":
    main()
