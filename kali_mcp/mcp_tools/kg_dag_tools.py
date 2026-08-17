#!/usr/bin/env python3
"""KG/DAG 能力工具面：dag_apply / dag_recommend / dag_status / kb_search。

原生子代理架构（harness 侧 18 markdown 子代理 + hooks 自动触发）下，MCP 退化为
纯能力层。本模块把 DAG/ACO 读写 + 知识库检索暴露为 MCP 工具，**全部不依赖
coordinator 实例**——直接构造 DAGService / ACOCore / KnowledgeRetriever（服务端
单点逻辑，1318 行图算法不重写，只经 MCP 暴露）。

- dag_apply     : DAGService.apply 包装（add_node/add_edge/update_node/deposit/
                  deposit_path/evaporate 写命令，串行锁 + 落库）
- dag_recommend : ACOCore.recommend_next 包装（候选边 P(e) 评分，供子代理/coordinator
                  选下一步；ACO 只推荐不决策）
- dag_status    : 移植自 multi_agent_tools._dag_status，但 DAGService 自建
- kb_search     : 移植自 multi_agent_tools._kb_search，但 KnowledgeRetriever 自建

容错：构造失败/库空 → 返回原 _dag_status/_kb_search 的容错空结构，不抛异常。
embedding 预加载：kb_search 构造 retriever 时主线程 _embed("warmup")，防 Windows
FastMCP worker 线程惰性加载 torch 卡死（原 mcp_server.py 集群初始化段的迁移）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
DAG_DB_PATH = str(_REPO_ROOT / "data" / "attack_dag.sqlite")


def _run_async(coro, timeout: float = 600.0) -> Any:
    """在同步上下文中运行异步协程（与 AgentAdapter._run_async 同构）。"""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _dag_service() -> Any:
    """构造持久化 DAGService（读 data/attack_dag.sqlite）。构造失败 → None。"""
    try:
        from kali_mcp.reasoning.attack_dag import DAGService

        return DAGService(db_path=DAG_DB_PATH)
    except Exception as e:  # noqa: BLE001 —— 容错
        logger.warning("[kg_dag] DAGService 构造失败: %s", e)
        return None


def _aco(dag) -> Any:
    """绑定 dag 构造 ACO；dag 为 None → None。"""
    if dag is None:
        return None
    try:
        from kali_mcp.reasoning.aco import ACO

        return ACO(dag=dag)
    except Exception as e:  # noqa: BLE001
        logger.warning("[kg_dag] ACO 构造失败: %s", e)
        return None


def _retriever() -> Any:
    """构造 KnowledgeRetriever 并主线程预热 embedding（防 Windows 卡死）。失败 → None。"""
    try:
        from kali_mcp.reasoning.knowledge_retriever import KnowledgeRetriever

        r = KnowledgeRetriever()
        try:
            r._embed("warmup")  # 主线程完成 torch 初始化（约 10-15s）
        except Exception:  # noqa: BLE001 —— 预热失败不阻塞构造
            pass
        return r
    except Exception as e:  # noqa: BLE001 —— 检索器不可用降级为空
        logger.warning("[kg_dag] KnowledgeRetriever 构造失败: %s", e)
        return None


# ---------------------------------------------------------------------------
# dag_status / kb_search 实现（移植自 multi_agent_tools，自建服务）
# ---------------------------------------------------------------------------

def _dag_status_impl(session_id: str = "") -> Dict[str, Any]:
    """dag_status 实现：读攻击 DAG 全局状态（节点/边数、信息素 top 路径、前沿候选边）。"""
    sid = session_id or ""
    dag = _dag_service()
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
            "DAG 未初始化（attack_dag.sqlite 不可用或构造失败），"
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


def _kb_search_impl(
    query: str,
    top_k: int = 5,
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """kb_search 实现：调 KnowledgeRetriever.retrieve（向量 + BM25 混合检索）。"""
    k = max(1, int(top_k) if top_k is not None else 5)
    retriever = _retriever()
    empty = {
        "query": query,
        "top_k": k,
        "initialized": False,
        "hits": [],
        "hit_count": 0,
    }
    if retriever is None:
        empty["message"] = (
            "知识库检索器不可用（KB 索引可能未构建，见 scripts/build_kb_index.py）。"
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


# ---------------------------------------------------------------------------
# MCP 注册
# ---------------------------------------------------------------------------

def register_kg_dag_tools(mcp, executor):
    """注册 KG/DAG 能力工具（harness 档位，不依赖 coordinator 实例）。"""

    @mcp.tool()
    def dag_apply(op: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """攻击 DAG 写命令（DAGService.apply 包装，单一写入者串行落库）。

        供 harness 侧 hooks / 子代理自动建图：每次扫描/枚举工具调用后自动
        add_node(attack_action) + deposit（LLM 透明）。ACO 只推荐不决策。

        Args:
            op: add_node | add_edge | update_node | deposit | deposit_path | evaporate
            payload: 按 op 的 apply 协议
                - add_node: {node: {node_id?, node_type, label, meta?, session_id?}}
                - add_edge: {edge: {source_id, target_id, edge_type, weight?, meta?, session_id?}}
                - update_node: {node_id, meta?, label?, session_id?}
                - deposit: {edge_ids: [...], success_signal, severity?, session_id?}
                - deposit_path: {path: [node_ids...], success_signal?, session_id?}

        Returns:
            {op, node/edge/... , created?, evaporated, ...}；失败返回 {error}，不抛。
        """
        dag = _dag_service()
        if dag is None:
            return {"op": op, "error": "DAGService 不可用（attack_dag.sqlite 构造失败）"}
        try:
            return _run_async(dag.apply(op, payload or {}))
        except Exception as e:  # noqa: BLE001 —— 写失败返回错误结构（DAGError 子类含校验原因）
            return {"op": op, "error": str(e)}

    @mcp.tool()
    def dag_recommend(
        node_id: str,
        agent_role: str = "",
        k: int = 5,
        session_id: str = "",
    ) -> List[Dict[str, Any]]:
        """ACO 下一步路径推荐（recommend_next 包装，P(e) 降序 top-k）。

        供 coordinator/子代理选下一步参考——**仅推荐，不决策**：LLM 可否决。

        Args:
            node_id: 当前节点（攻击路径起点）
            agent_role: 角色过滤相关边类型（如 recon_agent）
            k: 返回条数
            session_id: 会话 ID（空 → 默认会话）

        Returns:
            [{edge_id, edge_type, source_id, target_id, tau, eta, p, components,
              weight}]；DAG/ACO 不可用 → []（不抛）。
        """
        dag = _dag_service()
        aco = _aco(dag)
        if dag is None or aco is None:
            return []
        try:
            scores = aco.recommend_next(
                node_id, agent_role=agent_role, k=k,
                session_id=session_id or None,
            )
            return [s.to_dict() for s in scores or []]
        except Exception as e:  # noqa: BLE001 —— 推荐失败返回空
            logger.warning("[dag_recommend] 推荐失败: %s", e)
            return []

    @mcp.tool()
    def dag_status(session_id: str = "") -> Dict[str, Any]:
        """攻击 DAG 全局状态观测：节点/边数、信息素 top 路径、前沿候选边。

        让主 agent / coordinator 实时看到攻击图进展。DAG 不可用/会话无节点 →
        空结构 + 提示，不抛异常。

        Args:
            session_id: 可选会话 ID；空 → DAGService 默认会话

        Returns:
            {session_id, initialized, nodes, edges, pheromone_top_paths,
             frontier_candidates, [message|error]}
        """
        return _dag_status_impl(session_id or "")

    @mcp.tool()
    def kb_search(
        query: str,
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """知识库语义检索：向量 + BM25 混合检索（RRF 融合）。

        知识库为空/检索器不可用 → 空 hits + 提示，不抛异常。
        首次调用在主线程预热 embedding 模型（约 10-15s，此后秒回）。

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
        return _kb_search_impl(query, top_k, f)
