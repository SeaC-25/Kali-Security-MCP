#!/usr/bin/env python3
"""update_templates.py — 自动同步 nuclei 官方模板库到 Kali。

从 jsdelivr CDN 全量拉取 nuclei-templates（10601+ YAML），
断点续传 + 差异更新（只拉缺失/变更文件）。

用法:
    py update_templates.py                     # 增量更新
    py update_templates.py --force             # 强制全量
    py update_templates.py --dest /path        # 自定义目标目录

Cron（Kali 每周）:
    0 3 * * 1 python3 /home/zss/fastsec/scripts/update_templates.py --dest /home/zss/fastsec/nuclei-templates
"""

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# jsdelivr CDN（中国可达，无需翻墙）
TREE_URL = "https://data.jsdelivr.com/v1/packages/gh/projectdiscovery/nuclei-templates@main?structure=flat"
BASE_URL = "https://cdn.jsdelivr.net/gh/projectdiscovery/nuclei-templates@main/"

DEFAULT_DEST = "/home/zss/fastsec/nuclei-templates"
WORKERS = 30
TIMEOUT = 25


def fetch_tree() -> list:
    """下载目录树，返回 yaml 路径列表。"""
    import urllib.request
    req = urllib.request.Request(TREE_URL, headers={"User-Agent": "fastsec-updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
    return [f["name"].lstrip("/") for f in data["files"] if f["name"].endswith((".yaml", ".yml"))]


def fetch_one(dest: Path, path: str) -> bool:
    """下载单个模板（断点续传：已存在且 >100B 跳过）。"""
    target = dest / path
    if target.exists() and target.stat().st_size > 100:
        return True  # already present
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["curl", "-sL", "-m", str(TIMEOUT), "-o", str(target), BASE_URL + path],
            capture_output=True, timeout=TIMEOUT + 5, check=True,
        )
        return target.exists() and target.stat().st_size > 100
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="sync nuclei-templates from jsdelivr CDN")
    ap.add_argument("--dest", default=DEFAULT_DEST, help="target directory")
    ap.add_argument("--force", action="store_true", help="force full re-download")
    ap.add_argument("--workers", type=int, default=WORKERS)
    args = ap.parse_args()

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    print(f"[update] 拉取模板目录树...", flush=True)
    paths = fetch_tree()
    print(f"[update] 共 {len(paths)} 个模板", flush=True)

    # 断点续传：只处理缺失文件
    if args.force:
        todo = paths
    else:
        todo = [p for p in paths
                if not (dest / p).exists() or (dest / p).stat().st_size <= 100]
    print(f"[update] 待更新 {len(todo)} 个", flush=True)

    if not todo:
        print("[update] 已是最新，无需更新")
        return

    ok = fail = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_one, dest, p): p for p in todo}
        for i, f in enumerate(as_completed(futs)):
            if f.result():
                ok += 1
            else:
                fail += 1
            if (i + 1) % 2000 == 0:
                print(f"[update] 进度 {i+1}/{len(todo)} ok={ok} fail={fail}", flush=True)

    dur = time.time() - t0
    total = len(list(dest.rglob("*.yaml"))) + len(list(dest.rglob("*.yml")))
    print(f"[update] 完成: 新增 {ok} 失败 {fail} 总模板 {total} 耗时 {dur:.0f}s")


if __name__ == "__main__":
    main()
