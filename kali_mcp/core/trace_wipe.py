#!/usr/bin/env python3
"""Kali MCP 自动清理渗透测试痕迹（雁过无痕）。

三级清理粒度（用户决策）：
  - task    : 删除 workspace/tasks/<task_id>/ 整目录（含 evidence/logs/findings/graph/handoff/report）
  - session : 按 session_id 删除 attack_dag.sqlite 中 nodes/edges/pheromone 三表数据 +
              匹配的 workspace/d01_session.json
  - global  : 清空运行时状态（result_cache / async_jobs / taskboard / usage），
              保留知识库 / 模型 / 字典（永不进清理清单）

安全边界：
  - task_id 经 task_workspace.normalize_task_id 白名单校验（防路径穿越）；
    非法 id → 返回错误，不执行任何删除路径。
  - 删除不可恢复（rmtree / DELETE），符合"痕迹不可恢复"语义。
  - global 永不自动触发，需显式 scope="global"。
  - 目标侧清除只输出命令模板（target_manual_cleanup），绝不自动执行。

保留白名单（硬编码，永不进 wipe 清单）：
  data/kb_vectors.db、data/models/、data/wordlists/、tools/fastsec/data/、
  scripts/、tests/。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from kali_mcp.core.task_workspace import tasks_root, normalize_task_id

logger = logging.getLogger(__name__)

# 仓库根: kali_mcp/core/trace_wipe.py -> 上三级
_REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = _REPO_ROOT / "data"
WORKSPACE_DIR = _REPO_ROOT / "workspace"

DAG_DB_PATH = DATA_DIR / "attack_dag.sqlite"
RESULT_CACHE_DB = DATA_DIR / "result_cache.sqlite"
USAGE_DB = DATA_DIR / "usage.sqlite"
ASYNC_JOBS_JSON = DATA_DIR / "async_jobs.json"
TASKBOARD_JSON = DATA_DIR / "taskboard.json"
D01_SESSION_JSON = WORKSPACE_DIR / "d01_session.json"

# 永不进清理清单的保留白名单（相对 data/ 与仓库根）
PROTECTED_DATA = ("kb_vectors.db", "models", "wordlists")
PROTECTED_ROOT = ("tools/fastsec/data", "scripts", "tests")

# 目标侧痕迹（只输出清除命令模板，不自动执行）
TARGET_MANUAL_CLEANUP = [
    "rm -f /tmp/f /tmp/s.go",
    "清理 /tmp/phpctf/* (utils/ctf_mb_search.py 产物)",
]


def _dir_size(path: Path) -> int:
    """目录字节数（best-effort）。"""
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _wipe_dir(path: Path) -> int:
    """删除目录，返回释放字节数；不存在 → 0（幂等）。"""
    if not path.exists():
        return 0
    size = _dir_size(path)
    shutil.rmtree(path, ignore_errors=True)
    return size


def _wipe_sqlite_table(db_path: Path, table: str) -> Dict[str, Any]:
    """清空单表，返回 {table, cleared_rows, error?}；库/表不存在 → 幂等空结果。"""
    if not db_path.exists():
        return {"table": table, "cleared_rows": 0}
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
        try:
            cur = conn.execute(f"DELETE FROM {table}")
            conn.commit()
            return {"table": table, "cleared_rows": int(cur.rowcount)}
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001 —— 清理失败不抛，报告 error
        logger.warning("[trace_wipe] 清空 %s.%s 失败: %s", db_path.name, table, e)
        return {"table": table, "cleared_rows": 0, "error": str(e)}


def _wipe_json_reset(path: Path) -> Dict[str, Any]:
    """把 JSON 状态文件重置为 {}；不存在 → 幂等。"""
    if not path.exists():
        return {"file": str(path), "reset": False}
    try:
        path.write_text("{}", encoding="utf-8")
        return {"file": str(path), "reset": True}
    except Exception as e:  # noqa: BLE001
        logger.warning("[trace_wipe] 重置 %s 失败: %s", path, e)
        return {"file": str(path), "reset": False, "error": str(e)}


# ---------------------------------------------------------------------------
# task 级
# ---------------------------------------------------------------------------

def wipe_task_traces(task_id: str) -> Dict[str, Any]:
    """删除单个任务 workspace 目录（整目录，含 evidence/logs/findings/graph/handoff/report）。

    - task_id 经 normalize_task_id 校验：非法（含路径穿越字符）→ 返回错误不删。
    - 目录不存在 → 幂等返回 deleted: []，不报错。
    - KALI_MCP_KEEP_REPORT=1 时保留 report/ 子目录（其余子目录仍删）。
    """
    if not task_id or not str(task_id).strip():
        return {"scope": "task", "error": "task_id required"}

    # 白名单校验：normalize_task_id 对合法 id 原样返回，非法时生成新 id。
    # 这里显式比对：若被改写 → 非法 id，拒绝删除（防路径穿越）。
    normalized = normalize_task_id(task_id)
    if normalized != task_id.strip():
        return {"scope": "task", "error": f"invalid task_id: {task_id!r}"}

    root = tasks_root() / normalized
    if not root.exists():
        return {"scope": "task", "task_id": normalized, "deleted": [], "size_freed": 0}

    keep_report = os.environ.get("KALI_MCP_KEEP_REPORT") == "1"
    deleted: List[str] = []
    size_freed = 0
    try:
        if keep_report:
            # 保留 report/ 子目录，仅删其余子目录 + task.json
            for child in root.iterdir():
                if child.name == "report":
                    continue
                if child.is_dir():
                    size_freed += _wipe_dir(child)
                else:
                    try:
                        size_freed += child.stat().st_size
                        child.unlink(missing_ok=True)
                    except OSError:
                        pass
                deleted.append(str(child))
            report_dir = root / "report"
            if report_dir.exists():
                deleted.append(str(report_dir) + " (保留)")
        else:
            size_freed = _wipe_dir(root)
            deleted.append(str(root))
        # 目录本身：KEEP_REPORT 时根目录留下（含 report），否则已删
        if not keep_report:
            root.rmdir() if root.exists() and not any(root.iterdir()) else None
    except Exception as e:  # noqa: BLE001 —— ignore_errors 兜底 + 报告
        logger.warning("[trace_wipe] task %s 清理异常: %s", normalized, e)
        return {
            "scope": "task",
            "task_id": normalized,
            "error": str(e),
            "partial": deleted,
            "size_freed": size_freed,
        }

    return {
        "scope": "task",
        "task_id": normalized,
        "deleted": deleted,
        "size_freed": size_freed,
        "kept_report": keep_report,
    }


# ---------------------------------------------------------------------------
# session 级
# ---------------------------------------------------------------------------

def wipe_session_traces(session_id: str) -> Dict[str, Any]:
    """按 session_id 删除攻击 DAG 会话数据 + 匹配的 d01_session.json。

    - DAG：对 nodes/edges/pheromone 三表 DELETE WHERE session_id=?
      （attack_dag.sqlite，各表均有 session_id 列 + 索引）。
    - d01_session.json：live_pentest_d01.py watchdog 产物；若其内容与
      session_id 相关（missions/task 提及）则删除。文件无 session_id 字段时
      由调用方自行判断（默认不删）。
    """
    if not session_id or not str(session_id).strip():
        return {"scope": "session", "error": "session_id required"}
    sid = str(session_id).strip()

    dag_deleted: Dict[str, int] = {}
    files: List[str] = []
    try:
        from kali_mcp.reasoning.attack_dag import DAGService

        # 新方法 wipe_session：走与 _load/_persist 一致路径
        dag = DAGService(db_path=str(DAG_DB_PATH) if DAG_DB_PATH.exists() else None)
        dag_deleted = dag.wipe_session(sid)
    except Exception as e:  # noqa: BLE001 —— DAG 清理失败不阻断其余
        logger.warning("[trace_wipe] session %s DAG 清理失败: %s", sid, e)
        dag_deleted = {"error": str(e)}

    # d01_session.json：内容含 session 线索才删（watchdog 产物，无独立 id）
    if D01_SESSION_JSON.exists():
        try:
            blob = D01_SESSION_JSON.read_text(encoding="utf-8")
            if sid in blob or "task" in json.loads(blob):
                try:
                    D01_SESSION_JSON.unlink(missing_ok=True)
                    files.append(str(D01_SESSION_JSON))
                except OSError as e:
                    logger.warning("[trace_wipe] 删除 %s 失败: %s", D01_SESSION_JSON, e)
        except Exception:
            pass  # 解析失败 → 不删（保守）

    return {
        "scope": "session",
        "session_id": sid,
        "dag_deleted": dag_deleted,
        "files": files,
    }


# ---------------------------------------------------------------------------
# global 级
# ---------------------------------------------------------------------------

def wipe_global_traces() -> Dict[str, Any]:
    """清空全部运行时状态（result_cache / async_jobs / taskboard / usage）。

    保留：data/kb_vectors.db、data/models/、data/wordlists/、tools/fastsec/data/、
    scripts/、tests/（白名单硬编码）。
    """
    db_tables_cleared: List[Dict[str, Any]] = []

    # result_cache.sqlite: cache 表
    db_tables_cleared.append(_wipe_sqlite_table(RESULT_CACHE_DB, "cache"))
    # usage.sqlite: usage 表（不删库，只清数据）
    db_tables_cleared.append(_wipe_sqlite_table(USAGE_DB, "usage"))

    # async_jobs.json / taskboard.json → {}
    json_reset = [
        _wipe_json_reset(ASYNC_JOBS_JSON),
        _wipe_json_reset(TASKBOARD_JSON),
    ]

    return {
        "scope": "global",
        "db_tables_cleared": db_tables_cleared,
        "json_reset": json_reset,
        "protected": list(PROTECTED_DATA) + list(PROTECTED_ROOT),
        "target_manual_cleanup": TARGET_MANUAL_CLEANUP,
    }


# ---------------------------------------------------------------------------
# 入口分发
# ---------------------------------------------------------------------------

def wipe_traces(scope: str = "task", task_id: str = "", session_id: str = "") -> Dict[str, Any]:
    """wipe_traces 入口：按粒度分发清理。

    Args:
        scope: task | session | global
        task_id: scope=task 必填（白名单校验）
        session_id: scope=session 必填
    """
    scope = (scope or "task").strip().lower()
    if scope == "task":
        return wipe_task_traces(task_id)
    if scope == "session":
        return wipe_session_traces(session_id)
    if scope == "global":
        return wipe_global_traces()
    return {
        "error": f"unknown scope {scope!r}",
        "valid_scopes": ["task", "session", "global"],
    }
