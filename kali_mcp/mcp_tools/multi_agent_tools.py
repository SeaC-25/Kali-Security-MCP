#!/usr/bin/env python3
"""多智能体集群 MCP 入口（v4.0 legacy cluster 直接暴露）。

harness 档位下 apt/assessment/pwn/advanced_ctf 等走 AgentAdapter 的工具模块
全部被禁用，集群即使启动也没有 MCP 工具能触发。这里提供两个直接入口：
  - agent_run:    自然语言任务 → CoordinatorAgent.process_request()
                  （意图分析 → 任务分解 → 17 智能体并行调度 → 结果聚合）
  - agent_status: 集群健康/统计（agent 列表、能力摘要、调度统计）

集群未初始化（K4_LEGACY_CLUSTER 未开/初始化失败）时 agent_run 返回明确错误，
agent_status 返回初始化状态，方便诊断。
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _run_async(coro, timeout: float = 600.0) -> Any:
    """在同步上下文中运行异步协程（与 AgentAdapter._run_async 同构）。"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures

            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result(timeout=timeout)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _extract_session_result(session: Any) -> Dict[str, Any]:
    """从 ExecutionSession 提取可序列化结果。"""
    state = getattr(session, "state", None)
    state_value = getattr(state, "value", None) if state is not None else None
    if state_value is None:
        state_value = str(state or "unknown")

    summary = ""
    raw = {}
    if state_value == "completed":
        agg = getattr(session, "aggregated_result", None)
        if agg is not None:
            summary = getattr(agg, "summary", "") or str(agg)
            raw = getattr(agg, "raw_results", {}) or {}
    else:
        summary = getattr(session, "error", "") or f"代理执行状态: {state_value}"

    return {
        "state": state_value,
        "summary": summary,
        "raw_results": raw,
        "session_id": getattr(session, "session_id", ""),
    }


def register_multi_agent_tools(mcp, coordinator, agent_registry):
    """注册多智能体集群 MCP 工具。coordinator/agent_registry 为 None 时降级提示。"""

    @mcp.tool()
    def agent_run(
        task_description: str,
        target: str = "",
        session_id: str = "",
    ) -> Dict[str, Any]:
        """将任务交给 17 智能体集群编排执行。

        集群做意图分析 → 任务分解 → 并行调度（recon/scan/exploit/privilege 等
        专业智能体）→ 结果聚合。agent 通过 executor 走 ssh 后端调用真实 Kali 工具。

        Args:
            task_description: 自然语言任务描述（如 "对目标做端口扫描+服务指纹识别，尝试弱口令"）
            target: 授权测试目标（IP/域名/URL），可选，会拼接到任务描述
            session_id: 可选会话 ID（用于续跑/查询同一会话）

        Returns:
            {success, state, summary, raw_results, session_id, via_agent}
        """
        start = time.time()
        if coordinator is None:
            return {
                "success": False,
                "error": "多智能体集群未初始化（需 K4_LEGACY_CLUSTER=1 且初始化成功）",
                "via_agent": False,
            }

        user_input = task_description
        if target:
            user_input = f"{task_description}（目标: {target}）"

        logger.info("[agent_run] 提交集群: %s", user_input)
        try:
            session = _run_async(
                coordinator.process_request(user_input, session_id=session_id or None)
            )
            res = _extract_session_result(session)
            res["success"] = res["state"] == "completed"
            res["via_agent"] = True
            res["execution_time"] = round(time.time() - start, 2)
            logger.info(
                "[agent_run] 完成 session=%s state=%s (%.2fs)",
                res["session_id"], res["state"], res["execution_time"],
            )
            return res
        except Exception as e:  # noqa: BLE001
            logger.warning("[agent_run] 集群执行失败: %s", e)
            return {
                "success": False,
                "error": f"agent_run failed: {e}",
                "via_agent": True,
                "execution_time": round(time.time() - start, 2),
            }

    @mcp.tool()
    def agent_status() -> Dict[str, Any]:
        """多智能体集群健康与统计信息。"""
        if coordinator is None:
            return {"initialized": False, "agents": 0}
        try:
            stats = coordinator.get_statistics()
            agents = agent_registry.list_all() if agent_registry is not None else []
            return {
                "initialized": True,
                "agents": len(agents),
                "agent_ids": [getattr(a, "agent_id", str(a)) for a in agents],
                "capabilities": (
                    agent_registry.get_capability_summary()
                    if agent_registry is not None else {}
                ),
                "statistics": stats,
            }
        except Exception as e:  # noqa: BLE001
            logger.warning("[agent_status] 查询失败: %s", e)
            return {"initialized": True, "error": str(e)}
