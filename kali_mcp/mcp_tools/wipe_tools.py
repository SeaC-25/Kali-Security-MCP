#!/usr/bin/env python3
"""Kali MCP 痕迹清理工具面：wipe_traces（三粒度：task/session/global）。

转发 kali_mcp.core.trace_wipe.wipe_traces。清理不可恢复：
  - task    : 删 workspace/tasks/<id>/ 整目录（KALI_MCP_KEEP_REPORT=1 保留 report/）
  - session : 按 session_id 删 attack_dag.sqlite 三表 + 匹配的 d01_session.json
  - global  : 清空 result_cache/async_jobs/taskboard/usage（保留知识库/模型/字典）
仅本机痕迹；目标侧清除命令模板见返回的 target_manual_cleanup（不自动执行）。
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def register_wipe_tools(mcp, executor):
    """注册痕迹清理 MCP 工具（harness 档位）。"""

    @mcp.tool()
    def wipe_traces(
        scope: str = "task",
        task_id: str = "",
        session_id: str = "",
    ) -> Dict[str, Any]:
        """自动清理渗透测试痕迹（本机；删除不可恢复）。

        三级粒度：
        - scope="task"：删除 workspace/tasks/<task_id>/ 整目录（含 evidence/logs/
          findings/graph/handoff/report）。task_id 经白名单校验，非法值拒绝不删。
          KALI_MCP_KEEP_REPORT=1 时保留 report/ 子目录。
        - scope="session"：按 session_id 删除攻击 DAG（attack_dag.sqlite 的
          nodes/edges/pheromone 三表）+ 匹配的 workspace/d01_session.json。
        - scope="global"：清空运行时状态（result_cache / async_jobs / taskboard /
          usage）。永不自动触发，需显式调用。保留知识库/模型/字典
          （kb_vectors.db / models / wordlists 等白名单）。

        目标侧清除（如 /tmp/f、/tmp/s.go、/tmp/phpctf/*）只输出命令模板
        （target_manual_cleanup），不自动执行——目标侧删除属操作者授权动作。

        Args:
            scope: task | session | global
            task_id: scope=task 必填
            session_id: scope=session 必填

        Returns:
            清理报告（含 deleted/cleared_rows/target_manual_cleanup 等）；失败
            返回 {"error": ...}，不抛异常。
        """
        from kali_mcp.core.trace_wipe import wipe_traces as _wipe

        return _wipe(scope=scope, task_id=task_id, session_id=session_id)
