#!/usr/bin/env python3
"""多智能体集群 MCP 入口（v4.0 legacy cluster 直接暴露）。

harness 档位下 apt/assessment/pwn/advanced_ctf 等走 AgentAdapter 的工具模块
全部被禁用，集群即使启动也没有 MCP 工具能触发。这里提供直接入口：
  - agent_run:    自然语言任务 → CoordinatorAgent.process_request()
                  （P3 起内部为 **LLM orchestrator**：LLM 顶层规划 →
                  dispatch_mission → 17 智能体 LLM 决策循环 → review 轮 →
                  done → 结果聚合；LLM 不可用时按 coordinator 配置降级）
  - agent_status: 集群健康/统计（agent 列表、能力摘要、调度统计）
  - dag_status:   P4 新增观测工具——攻击 DAG 全局状态（节点/边数、信息素
                  top 路径、前沿候选边），让主 agent 实时看到全局进展（§9）
  - kb_search:    P4 新增观测工具——知识库语义检索（KnowledgeRetriever.retrieve），
                  主 agent 直接查向量化 KB（§7.3/§9）

集群未初始化（K4_LEGACY_CLUSTER 未开/初始化失败）时 agent_run 返回明确错误，
agent_status 返回初始化状态；dag_status/kb_search 容错返回空结构 + 提示，
不抛异常（DAG 未初始化 / 知识库为空均可观测）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

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
        # P3：LLM orchestrator 模式标记（llm | legacy）；LLM 不可用且未回退时 state=failed
        "orchestrator": getattr(session, "orchestrator_mode", "unknown"),
    }


def _dag_status(coordinator, session_id: str = "") -> Dict[str, Any]:
    """dag_status 实现（P4 观测工具，§9）：读攻击 DAG 全局状态。

    - 节点/边数、信息素 top 路径（get_pheromone_view）、前沿候选边（get_frontier）；
    - 容错：coordinator/DAGService 缺失或读取异常 → 返回空结构 + 提示，不抛异常。
    """
    sid = session_id or ""
    dag = getattr(coordinator, "dag_service", None) if coordinator is not None else None
    empty = {
        "session_id": sid,
        "initialized": False,
        "nodes": 0,
        "edges": 0,
        "pheromone_top_paths": [],
        "frontier_candidates": [],
    }
    if dag is None:
        empty["message"] = (
            "DAG 未初始化（集群未启动或 CoordinatorAgent 无 DAGService），"
            "当前无可观测的攻击图进展。"
        )
        return empty
    try:
        nodes = int(dag.node_count(session_id=sid))
        edges = int(dag.edge_count(session_id=sid))
        view = dag.get_pheromone_view(agent_role="", limit=10, session_id=sid)
        frontier = dag.get_frontier(max_hypotheses=10, session_id=sid)
    except Exception as exc:  # noqa: BLE001 —— 观测工具容错，不抛异常
        logger.warning("[dag_status] 读取 DAG 状态失败: %s", exc)
        empty["initialized"] = True
        empty["error"] = str(exc)
        empty["message"] = "DAG 状态读取失败，返回空结构。"
        return empty

    top_paths = view.get("edges", []) if isinstance(view, dict) else []
    frontier_candidates: List[Dict[str, Any]] = []
    for fe in frontier or []:
        try:
            to_dict = getattr(fe, "to_dict", None)
            if callable(to_dict):
                frontier_candidates.append(to_dict())
            # 无 to_dict 的裸对象无法提取结构，跳过（容错，不产生无意义输出）
        except Exception:  # noqa: BLE001
            continue
    result: Dict[str, Any] = {
        "session_id": sid,
        "initialized": True,
        "nodes": nodes,
        "edges": edges,
        "pheromone_top_paths": top_paths,
        "frontier_candidates": frontier_candidates,
    }
    if nodes == 0 and edges == 0:
        result["message"] = (
            "当前会话尚无 DAG 节点（会话可能未开始，或 session_id 与执行会话不匹配）。"
        )
    return result


def _kb_search(
    coordinator,
    query: str,
    top_k: int = 5,
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """kb_search 实现（P4 观测工具，§7.3/§9）：调 KnowledgeRetriever.retrieve。

    - 容错：coordinator/retriever 缺失、库为空或检索异常 → 空 hits + 提示，不抛异常。
    """
    k = max(1, int(top_k) if top_k is not None else 5)
    retriever = getattr(coordinator, "retriever", None) if coordinator is not None else None
    empty = {
        "query": query,
        "top_k": k,
        "initialized": False,
        "hits": [],
        "hit_count": 0,
    }
    if retriever is None:
        empty["message"] = (
            "知识库检索器未初始化（coordinator 未注入 retriever；"
            "KB 索引可能未构建，见 scripts/build_kb_index.py）。"
        )
        return empty
    try:
        hits = retriever.retrieve(query, top_k=k, filters=filters)
    except Exception as exc:  # noqa: BLE001 —— 检索失败降级为空，不阻塞调用方
        logger.warning("[kb_search] KB 检索失败: %s", exc)
        empty["initialized"] = True
        empty["error"] = str(exc)
        empty["message"] = "KB 检索失败，返回空结果。"
        return empty
    out_hits = []
    for h in hits or []:
        out_hits.append({
            "chunk_id": getattr(h, "chunk_id", None),
            "source": getattr(h, "source", ""),
            "section": getattr(h, "section", ""),
            "text": str(getattr(h, "text", "") or "")[:500],
            "score": round(float(getattr(h, "score", 0.0) or 0.0), 4),
            "meta": getattr(h, "meta", {}) or {},
        })
    result: Dict[str, Any] = {
        "query": query,
        "top_k": k,
        "initialized": True,
        "hits": out_hits,
        "hit_count": len(out_hits),
    }
    if not out_hits:
        result["message"] = "知识库为空或没有匹配条目。"
    return result


def register_multi_agent_tools(mcp, coordinator, agent_registry):
    """注册多智能体集群 MCP 工具。coordinator/agent_registry 为 None 时降级提示。"""

    @mcp.tool()
    def agent_run(
        task_description: str,
        target: str = "",
        session_id: str = "",
    ) -> Dict[str, Any]:
        """将任务交给多智能体集群编排执行（LLM orchestrator）。

        P3 语义升级：CoordinatorAgent.process_request 内部由确定性编排
        （意图分析→任务分解→调度）升级为 **LLM orchestrator**——
        LLM 唯一决策者：顶层规划（任务 + KB + DAG/ACO 上下文）→
        dispatch_mission（MissionTicket → 子 agent LLM 决策循环）→
        review 轮（累计结果后 LLM 判定继续/换向/done）→ 结果聚合报告。
        子 agent 通过 executor 走 ssh 后端调用真实 Kali 工具。
        LLM 不可用（无 API Key）：coordinator 配置 legacy_fallback 时走旧确定性路径，
        否则返回明确错误（不空转）。

        Args:
            task_description: 自然语言任务描述（如 "对目标做端口扫描+服务指纹识别，尝试弱口令"）
            target: 授权测试目标（IP/域名/URL），可选，会拼接到任务描述
            session_id: 可选会话 ID（用于续跑/查询同一会话）

        Returns:
            {success, state, summary, raw_results, session_id, orchestrator, via_agent}
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

        logger.info("[agent_run] 提交集群(LLM orchestrator): %s", user_input)
        try:
            session = _run_async(
                coordinator.process_request(user_input, session_id=session_id or None)
            )
            res = _extract_session_result(session)
            res["success"] = res["state"] == "completed"
            res["via_agent"] = True
            res["execution_time"] = round(time.time() - start, 2)
            logger.info(
                "[agent_run] 完成 session=%s state=%s orchestrator=%s (%.2fs)",
                res["session_id"], res["state"], res.get("orchestrator"),
                res["execution_time"],
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

    @mcp.tool()
    def dag_status(session_id: str = "") -> Dict[str, Any]:
        """攻击 DAG 全局状态观测（P4，§9）：让主 agent 实时看到攻击图进展。

        返回当前会话攻击 DAG 的节点数/边数、信息素 top 路径（tau 降序）与
        前沿候选边（hypothesis 决策点的出边）。DAG 未初始化/会话无节点时
        返回空结构 + 提示，不抛异常。

        Args:
            session_id: 可选会话 ID；空 → DAGService 默认会话

        Returns:
            {session_id, initialized, nodes, edges, pheromone_top_paths,
             frontier_candidates, [message|error]}
        """
        return _dag_status(coordinator, session_id or "")

    @mcp.tool()
    def kb_search(
        query: str,
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """知识库语义检索观测（P4，§7.3/§9）：调 KnowledgeRetriever.retrieve。

        向量 + BM25 混合检索（RRF 融合），让主 agent 直接查询向量化知识库。
        知识库为空/检索器未初始化 → 空 hits + 提示，不抛异常。

        Args:
            query: 检索语句（如 "nginx 目录遍历 绕过技巧"）
            top_k: 返回条数（默认 5）
            filters: 可选元数据过滤，如 {"category": "credentials", "tool": "fastsec"}

        Returns:
            {query, top_k, initialized, hits:[{chunk_id, source, section, text,
             score, meta}], hit_count, [message|error]}
        """
        f = filters
        if isinstance(f, str) and f.strip():
            try:
                f = json.loads(f)
            except Exception:  # noqa: BLE001 —— 过滤串解析失败降级为不过滤
                f = None
        return _kb_search(coordinator, query, top_k, f)
