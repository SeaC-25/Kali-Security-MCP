#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
K2: 异步作业桥 — 后台线程执行重型工具

- start(): 在 daemon 线程中执行 executor.execute_tool_with_data，立即返回 job_id
- collect(): 查询作业状态 running/done/expired/not_found
- wait(): 轮询直到完成或超时
- jobs(): 当前活跃（running）作业列表
- 作业保存在内存 + data/async_jobs.json 快照（重启后上次遗留的 running 作业
  标记为 expired）；快照读写均为 best-effort，绝不抛出
- TTL 默认 4h（与会话 TTL 一致），start 时惰性清扫
"""

import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 仓库根: kali_mcp/core/async_bridge.py -> 上三级
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DATA_DIR = os.path.join(_REPO_ROOT, "data")
JOBS_PATH = os.path.join(DATA_DIR, "async_jobs.json")

DEFAULT_TTL = 4 * 3600  # 默认 4h，与会话 TTL 一致

STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_EXPIRED = "expired"
STATUS_NOT_FOUND = "not_found"


class AsyncJobBridge:
    """在后台线程执行工具并将结果缓存到作业注册表。"""

    def __init__(self, executor: Any = None, jobs_path: str = JOBS_PATH,
                 ttl: float = DEFAULT_TTL):
        if executor is None:
            from kali_mcp.core.local_executor import LocalCommandExecutor

            executor = LocalCommandExecutor()
        self.executor = executor
        self.jobs_path = jobs_path
        self.ttl = ttl
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._load_snapshot()

    # ---------- 持久化 (best-effort) ----------
    def _load_snapshot(self) -> None:
        """恢复上次进程遗留的作业；running -> expired（进程重启导致）。"""
        try:
            if not os.path.isfile(self.jobs_path):
                return
            with open(self.jobs_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return
            now = time.time()
            with self._lock:
                for job_id, rec in data.items():
                    if not isinstance(rec, dict):
                        continue
                    rec = dict(rec)
                    if rec.get("status") == STATUS_RUNNING:
                        rec["status"] = STATUS_EXPIRED
                        rec["expired"] = True
                        rec["note"] = "job was running when the process restarted"
                    self._jobs[str(job_id)] = rec
                self._sweep(now)
        except Exception as e:
            logger.debug("async jobs snapshot load failed (non-fatal): %s", e)

    def _save_snapshot(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.jobs_path), exist_ok=True)
            with self._lock:
                payload = {jid: dict(rec) for jid, rec in self._jobs.items()}
            with open(self.jobs_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
        except Exception as e:
            logger.debug("async jobs snapshot save failed (non-fatal): %s", e)

    # ---------- 生命周期 ----------
    def start(self, tool_name: str, data: Dict[str, Any],
              job_id: str = None) -> Dict[str, Any]:
        """后台启动工具执行，立即返回 {job_id, status:'running'}。"""
        jid = job_id or uuid.uuid4().hex[:12]
        with self._lock:
            self._sweep(time.time())
            self._jobs[jid] = {
                "job_id": jid,
                "tool": tool_name,
                "target": (
                    data.get("target")
                    or data.get("url")
                    or data.get("host")
                    or data.get("domain")
                    or ""
                ),
                "status": STATUS_RUNNING,
                "started": time.time(),
            }
        self._save_snapshot()
        t = threading.Thread(
            target=self._run,
            args=(jid, tool_name, data),
            daemon=True,
            name=f"async-job-{jid}",
        )
        t.start()
        return {"job_id": jid, "status": STATUS_RUNNING}

    def _run(self, job_id: str, tool_name: str, data: Dict[str, Any]) -> None:
        result: Optional[Dict[str, Any]] = None
        try:
            result = self.executor.execute_tool_with_data(tool_name, data)
        except Exception as e:
            logger.error("async job %s tool %s failed: %s", job_id, tool_name, e)
            result = {"success": False, "error": str(e), "tool_name": tool_name}
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                return
            rec["status"] = STATUS_DONE
            rec["finished"] = time.time()
            rec["result"] = result
        self._save_snapshot()

    def collect(self, job_id: str) -> Dict[str, Any]:
        """返回 {job_id, status, result?}；status: running|done|expired|not_found。"""
        with self._lock:
            rec = self._jobs.get(str(job_id))
            if rec is None:
                return {"job_id": job_id, "status": STATUS_NOT_FOUND}
            out: Dict[str, Any] = {
                "job_id": rec.get("job_id", job_id),
                "status": rec.get("status", STATUS_NOT_FOUND),
            }
            if rec.get("status") == STATUS_DONE:
                out["result"] = rec.get("result")
            return out

    def wait(self, job_id: str, timeout_s: float = 0.0) -> Dict[str, Any]:
        """轮询直到完成/过期/不存在，或超时返回当前状态。"""
        timeout_s = max(0.0, float(timeout_s or 0.0))
        deadline = time.time() + timeout_s
        while True:
            out = self.collect(job_id)
            if out["status"] in (STATUS_DONE, STATUS_EXPIRED, STATUS_NOT_FOUND):
                return out
            if timeout_s <= 0 or time.time() >= deadline:
                return out
            time.sleep(0.1)

    def jobs(self) -> List[Dict[str, Any]]:
        """当前活跃（running）作业列表。"""
        with self._lock:
            self._sweep(time.time())
            return [
                {
                    "job_id": jid,
                    "status": rec.get("status"),
                    "tool": rec.get("tool"),
                    "target": rec.get("target"),
                    "started": rec.get("started"),
                }
                for jid, rec in self._jobs.items()
                if rec.get("status") == STATUS_RUNNING
            ]

    def _sweep(self, now: float) -> None:
        """删除超过 TTL 的作业记录（惰性清理）。"""
        expired = [
            jid
            for jid, rec in self._jobs.items()
            if now - rec.get("started", now) > self.ttl
        ]
        for jid in expired:
            del self._jobs[jid]


# 模块级单例（executor 默认用本地命令执行器）
def _default_executor() -> Any:
    from kali_mcp.core.local_executor import LocalCommandExecutor

    return LocalCommandExecutor()


executor = _default_executor()
async_bridge = AsyncJobBridge(executor)
