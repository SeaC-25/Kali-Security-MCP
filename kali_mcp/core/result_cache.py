#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
K2: 结果缓存 — sqlite 持久化

- key = sha256(f"{tool}|{sorted args json}|{target}")[:20]
- TTL 来自 tools_recipes/<tool>.yaml 的 cache_ttl 字段；不可读/缺失时默认 3600s
- 数据落在 data/result_cache.sqlite（gitignored，运行时自动创建）
- 所有 IO/解析失败静默降级 —— 缓存绝不影响工具执行
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# 仓库根: kali_mcp/core/result_cache.py -> 上三级
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DATA_DIR = os.path.join(_REPO_ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "result_cache.sqlite")
RECIPES_DIR = os.path.join(_REPO_ROOT, "tools_recipes")

DEFAULT_TTL = 3600.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    payload TEXT,
    ts REAL,
    ttl REAL
)
"""

try:
    import yaml as _yaml
except Exception:  # pragma: no cover
    _yaml = None

# 控制键不参与缓存键的 args 部分（不影响命令语义，避免同一逻辑调用产生不同键）
_CONTROL_KEYS = frozenset({"no_cache", "skip_cache", "task_id", "phase", "additional_args"})


def _pick_target(data: Dict[str, Any]) -> str:
    for k in ("target", "url", "host", "domain"):
        v = data.get(k)
        if v:
            return str(v)
    return ""


class ResultCache:
    """sqlite 持久化的工具结果缓存（best-effort，任何失败都静默降级）。"""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()
        try:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            conn = sqlite3.connect(db_path, timeout=5.0)
            try:
                conn.execute(_SCHEMA)
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug("result cache init failed (non-fatal): %s", e)

    # ---------- key / ttl ----------
    def _key(self, tool: str, data: Dict[str, Any]) -> str:
        """sha256(f"{tool}|{sorted args json}|{target}") 前 20 位。"""
        args = {
            k: v
            for k, v in (data or {}).items()
            if k not in _CONTROL_KEYS
        }
        args_json = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
        raw = f"{tool}|{args_json}|{_pick_target(data)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def _ttl_for(self, tool: str) -> float:
        """tools_recipes/<tool>.yaml 的 cache_ttl；不可读则默认 3600s。"""
        path = os.path.join(RECIPES_DIR, f"{tool}.yaml")
        try:
            if _yaml is not None and os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as fh:
                    recipe = _yaml.safe_load(fh)
                if isinstance(recipe, dict) and recipe.get("cache_ttl") is not None:
                    return float(recipe["cache_ttl"])
            if os.path.isfile(path):
                # yaml 不可用时回退到原始文本扫描
                with open(path, "r", encoding="utf-8") as fh:
                    m = re.search(
                        r"^\s*cache_ttl\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*$",
                        fh.read(),
                        re.MULTILINE,
                    )
                if m:
                    return float(m.group(1))
        except Exception as e:
            logger.debug("cache ttl lookup failed for %s (non-fatal): %s", tool, e)
        return DEFAULT_TTL

    # ---------- api ----------
    def get(self, tool: str, data: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], bool]:
        """返回 (result|None, hit)。任何异常/过期 -> (None, False)。"""
        key = self._key(tool, data)
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            try:
                row = conn.execute(
                    "SELECT payload, ts, ttl FROM cache WHERE key=?", (key,)
                ).fetchone()
            finally:
                conn.close()
            if row is None:
                return None, False
            payload, ts, ttl = row
            if time.time() - float(ts) > float(ttl):
                self._delete(key)
                return None, False
            return json.loads(payload), True
        except Exception as e:
            logger.debug("result cache get failed (non-fatal): %s", e)
            return None, False

    def set(self, tool: str, data: Dict[str, Any], result: Any) -> bool:
        """存储 {result, ts, ttl}；失败静默返回 False。"""
        key = self._key(tool, data)
        ttl = self._ttl_for(tool)
        if ttl <= 0:
            return False
        try:
            payload = json.dumps(result, ensure_ascii=False, default=str)
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO cache (key, payload, ts, ttl) VALUES (?,?,?,?)",
                    (key, payload, time.time(), ttl),
                )
                conn.commit()
            finally:
                conn.close()
            return True
        except Exception as e:
            logger.debug("result cache set failed (non-fatal): %s", e)
            return False

    def _delete(self, key: str) -> None:
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            try:
                conn.execute("DELETE FROM cache WHERE key=?", (key,))
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass

    def clear(self) -> None:
        """清空全部缓存（重置/测试用）。"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            try:
                conn.execute("DELETE FROM cache")
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug("result cache clear failed (non-fatal): %s", e)


# 模块级单例
result_cache = ResultCache()


def reset_result_cache() -> None:
    """测试用：清空全局缓存实例的内容。"""
    result_cache.clear()
