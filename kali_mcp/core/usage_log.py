#!/usr/bin/env python3
"""
K0-5: 工具使用日志 (usage telemetry)

记录每次工具执行的使用情况到 data/usage.sqlite，供自剪枝 (K5-2) 决策使用。
仅依赖标准库 (sqlite3)。任何写入失败都静默降级 —— 日志绝不影响工具执行。
data/ 目录在 .gitignore 中忽略，运行时自动创建。
"""

import hashlib
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

# 仓库根: kali_mcp/core/usage_log.py -> 上三级
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DATA_DIR = os.path.join(_REPO_ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "usage.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY,
    tool TEXT,
    args_hash TEXT,
    duration_s REAL,
    timed_out INTEGER,
    success INTEGER,
    cache_hit INTEGER,
    target TEXT,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


class UsageLogger:
    """工具使用日志记录器 — 写入失败静默降级，绝不抛出。"""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with self._connect() as conn:
                conn.execute(_SCHEMA)
        except Exception:
            pass  # logging must never break execution

    def _connect(self) -> Optional[sqlite3.Connection]:
        return sqlite3.connect(self.db_path, timeout=5.0)

    @staticmethod
    def hash_params(data: Dict[str, Any]) -> str:
        """sha256(sorted params) 截断 16 字符 — 不存储任何原始参数值。

        仅用于关联同参调用，不记录参数明文。
        """
        try:
            payload = json.dumps(data, sort_keys=True, default=str)
        except Exception:
            payload = str(data)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def record(
        self,
        tool: str,
        args_hash: str,
        duration_s: float,
        timed_out: bool,
        success: bool,
        cache_hit: bool,
        target: str = "",
    ) -> None:
        """记录一次工具使用。任何失败（磁盘/锁/类型）都静默忽略。"""
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO usage "
                    "(tool, args_hash, duration_s, timed_out, success, cache_hit, target) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(tool or "")[:256],
                        str(args_hash or ""),
                        float(duration_s or 0.0),
                        1 if timed_out else 0,
                        1 if success else 0,
                        1 if cache_hit else 0,
                        str(target or "")[:1024],
                    ),
                )
        except Exception:
            pass  # logging must never break execution

    def recent(self, count: int = 50) -> List[Dict[str, Any]]:
        """最近 count 条使用记录（新→旧）。"""
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM usage ORDER BY id DESC LIMIT ?",
                    (int(count),),
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def stats_by_tool(self) -> List[Dict[str, Any]]:
        """按工具聚合统计: tool, calls, avg_duration, timeout_count, success_rate。"""
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """
                    SELECT tool,
                           COUNT(*) AS calls,
                           AVG(duration_s) AS avg_duration,
                           SUM(timed_out) AS timeout_count,
                           AVG(success) AS success_rate
                    FROM usage
                    GROUP BY tool
                    ORDER BY calls DESC
                    """
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
