#!/usr/bin/env python3
"""auto_orchestrate.py — 扫描自动编排（扫描类升级 N1）。

扫描结果 → 服务指纹 → 自动选后续工具:
  web 服务 → fastsec 扫漏洞 / 目录枚举
  数据库端口 → sqlmap++ 测注入（如有 web 入口）
  内核版本 → searchsploit 查 exploit
  SMB/RDP → nxc/stealth_brute 爆破
  开放端口 → findings 入库（资产复用）

用法:
    py auto_orchestrate.py -t 192.168.1.1
    py auto_orchestrate.py -t 192.168.1.1 -p 80,443,3306,445
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List


# 端口 → 服务映射
PORT_SERVICE = {
    22: "ssh", 21: "ftp", 25: "smtp", 53: "dns", 80: "http", 443: "https",
    445: "smb", 3306: "mysql", 1433: "mssql", 5432: "postgresql",
    6379: "redis", 27017: "mongodb", 3389: "rdp", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
    2375: "docker", 5000: "docker-registry", 9000: "php-fpm",
    11211: "memcached", 5900: "vnc", 5432: "postgresql",
}


def run_scan(target: str, ports: str) -> Dict[str, Any]:
    """rustscan 快速扫描 → 解析开放端口。"""
    # -p 逗号端口 / -r 范围（rustscan 两者不同）
    if ports and "," in ports:
        cmd = ["rustscan", "-a", target, "-p", ports, "--ulimit", "5000", "-g"]
    else:
        cmd = ["rustscan", "-a", target, "-r", ports or "1-65535", "--ulimit", "5000", "-g"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        # rustscan -g 输出: "127.0.0.1 -> [22,8091]"
        ports_found = []
        m = re.search(r"\[([\d,]+)\]", out)
        if m:
            ports_found = [int(x) for x in m.group(1).split(",") if x.strip()]
        return {"ports": sorted(set(ports_found))}
    except Exception as e:
        return {"ports": [], "error": str(e)}


def fingerprint_service(port: int) -> str:
    return PORT_SERVICE.get(port, "unknown")


def orchestrate(target: str, ports: str = "") -> Dict[str, Any]:
    """扫描 → 指纹 → 编排后续工具。"""
    print(f"[orchestrate] 扫描 {target} ...")
    scan = run_scan(target, ports)
    open_ports = scan.get("ports", [])
    print(f"[orchestrate] 开放端口: {open_ports}")

    actions = []
    for p in open_ports:
        svc = fingerprint_service(p)
        action = {"port": p, "service": svc}
        # 服务 → 后续工具编排
        if svc in ("http", "https", "http-alt", "https-alt"):
            url = f"http://{target}:{p}/" if p != 443 else f"https://{target}/"
            action["tool"] = "fastsec"
            action["cmd"] = f"fastsec -u {url} -d ~/fastsec/nuclei-templates/http/cves/ -c 30"
            action["next"] = "漏洞扫描 + 目录枚举"
        elif svc in ("mysql", "mssql", "postgresql", "mongodb", "redis"):
            action["tool"] = "sqlmap++/爆破"
            action["cmd"] = f"nxc {svc} {target} -u admin -p password"
            action["next"] = "数据库爆破"
        elif svc == "ssh":
            action["tool"] = "stealth_brute"
            action["cmd"] = f"python3 ~/fastsec/scripts/stealth_brute.py --target {target} --service ssh -U users.txt -P pass.txt"
            action["next"] = "SSH 爆破"
        elif svc == "smb":
            action["tool"] = "nxc"
            action["cmd"] = f"nxc smb {target} -u users.txt -p pass.txt"
            action["next"] = "SMB 爆破 + 共享枚举"
        elif svc == "rdp":
            action["tool"] = "stealth_brute"
            action["cmd"] = f"python3 ~/fastsec/scripts/stealth_brute.py --target {target} --service rdp -U users.txt -P pass.txt"
            action["next"] = "RDP 爆破"
        else:
            action["tool"] = "nmap -sV"
            action["cmd"] = f"nmap -sV -p {p} {target}"
            action["next"] = "服务版本深查"
        actions.append(action)
        print(f"  {p}/{svc} → {action['tool']}: {action['cmd'][:70]}")

    # 端口入库（资产复用）
    try:
        out = {"task_id": "auto_orchestrate", "findings": [
            {"title": f"开放端口 {p}/{fingerprint_service(p)} {target}",
             "target": target, "severity": "info", "source": "orchestrate",
             "meta": {"port": p, "service": fingerprint_service(p)}}
            for p in open_ports]}
        Path("/tmp/orchestrate_findings.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    except Exception:
        pass

    return {"ports": open_ports, "actions": actions, "count": len(open_ports)}


def main():
    ap = argparse.ArgumentParser(description="扫描自动编排")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("-p", "--ports", default="", help="ports (comma/range), default 1-65535")
    args = ap.parse_args()
    r = orchestrate(args.target, args.ports)
    print(f"\n[orchestrate] 完成: {r['count']} 个服务编排")


if __name__ == "__main__":
    main()
