#!/usr/bin/env python3
"""KG/DAG 观测工具单测（原生子代理架构：kg_dag_tools 独立构造服务）。

覆盖：
- dag_status：节点/边数、信息素 top 路径、前沿候选边；容错（服务不可用、读取
  异常、空 DAG）不抛异常；
- kb_search：调用 KnowledgeRetriever.retrieve 的命中序列化与 filters 透传；
  容错（无 retriever、检索异常、空库）返回空结构 + 提示；
- 注册面：dag_apply/dag_recommend/dag_status/kb_search 经 register_kg_dag_tools
  注册进 MCP；编排面（两个 pure-orchestration 工具）已从 K1 keep-set 移除；
- playbooks 摘除：run_playbook/run_surface_chain 默认不注册，
  K4_LEGACY_PLAYBOOKS=1 时恢复（run_surface_chain_multi 不受影响）。
"""
from __future__ import annotations

import os
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from kali_mcp.mcp_tools.kg_dag_tools import _dag_status_impl, _kb_search_impl
from kali_mcp.reasoning.knowledge_retriever import KbHit


# ---------------- 辅助 ----------------

class _FakeFrontier:
    """模拟 FrontierEdge（仅暴露 to_dict，容错路径要求 callable 判定）。"""

    def __init__(self, edge_id: str, tau: float):
        self.edge_id = edge_id
        self.tau = tau

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge": {"edge_id": self.edge_id, "tau": self.tau},
            "source": {"node_id": "n1"},
            "target": {"node_id": "n2"},
        }


def _mock_dag(node_count: int = 3, edge_count: int = 2, frontier=None):
    dag = MagicMock()
    dag.node_count.return_value = node_count
    dag.edge_count.return_value = edge_count
    dag.get_pheromone_view.return_value = {
        "edges": [
            {"edge_id": "e1", "edge_type": "drives", "source_id": "n1",
             "target_id": "n2", "tau": 0.72, "target_label": "对 /admin 的 SQL 检测"},
        ],
        "stats": {"nodes": node_count, "edges": edge_count},
    }
    dag.get_frontier.return_value = frontier or [_FakeFrontier("e9", 0.5)]
    return dag


def _recording_mcp():
    """与 test_p0_harness 同构的录制型 mcp 装饰器。"""
    mcp = MagicMock()
    calls: Dict[str, Any] = {}

    def _tool():
        def deco(fn):
            calls[fn.__name__] = fn
            return fn

        return deco

    mcp.tool = _tool
    return mcp, calls


# ---------------- dag_status ----------------

class TestDagStatus:
    def test_returns_dag_global_state(self):
        dag = _mock_dag(node_count=5, edge_count=4)

        with patch("kali_mcp.mcp_tools.kg_dag_tools._dag_service", return_value=dag):
            out = _dag_status_impl("s1")

        assert out["initialized"] is True
        assert out["session_id"] == "s1"
        assert out["nodes"] == 5
        assert out["edges"] == 4
        # 信息素 top 路径来自 get_pheromone_view
        assert out["pheromone_top_paths"][0]["edge_id"] == "e1"
        assert out["pheromone_top_paths"][0]["tau"] == 0.72
        # 前沿候选边来自 get_frontier.to_dict()
        assert out["frontier_candidates"][0]["edge"]["edge_id"] == "e9"
        # 读接口按 session_id 过滤
        dag.node_count.assert_called_once_with(session_id="s1")
        dag.get_pheromone_view.assert_called_once_with(
            agent_role="", limit=10, session_id="s1"
        )
        dag.get_frontier.assert_called_once_with(max_hypotheses=10, session_id="s1")

    def test_empty_dag_gets_hint(self):
        dag = _mock_dag(node_count=0, edge_count=0)

        with patch("kali_mcp.mcp_tools.kg_dag_tools._dag_service", return_value=dag):
            out = _dag_status_impl("s-empty")

        assert out["initialized"] is True
        assert out["nodes"] == 0
        assert "message" in out  # 空 DAG 提示，不抛异常

    def test_service_none_is_tolerant(self):
        with patch("kali_mcp.mcp_tools.kg_dag_tools._dag_service", return_value=None):
            out = _dag_status_impl("s-x")

        assert out["initialized"] is False
        assert out["nodes"] == 0
        assert out["frontier_candidates"] == []
        assert "message" in out

    def test_dag_read_error_is_tolerant(self):
        dag = _mock_dag()
        dag.node_count.side_effect = RuntimeError("boom")

        with patch("kali_mcp.mcp_tools.kg_dag_tools._dag_service", return_value=dag):
            out = _dag_status_impl("")

        assert out["initialized"] is True
        assert out["nodes"] == 0
        assert "error" in out
        assert "message" in out

    def test_frontier_item_without_to_dict_is_skipped(self):
        dag = _mock_dag(frontier=[object()])  # 无 to_dict 的裸对象

        with patch("kali_mcp.mcp_tools.kg_dag_tools._dag_service", return_value=dag):
            out = _dag_status_impl("")

        assert out["frontier_candidates"] == []


# ---------------- kb_search ----------------

class TestKbSearch:
    def _hits(self):
        return [
            KbHit(chunk_id=7, source="playbooks/web_surface.py", section="web_surface",
                  text="fastsec 目录枚举常用参数", score=12.5,
                  meta={"category": "playbook_ref", "tool": "fastsec"}),
        ]

    def test_returns_retrieved_hits(self):
        retriever = MagicMock()
        retriever.retrieve.return_value = self._hits()

        with patch("kali_mcp.mcp_tools.kg_dag_tools._retriever", return_value=retriever):
            out = _kb_search_impl("目录枚举 参数", top_k=5)

        assert out["initialized"] is True
        assert out["hit_count"] == 1
        hit = out["hits"][0]
        assert hit["chunk_id"] == 7
        assert hit["source"] == "playbooks/web_surface.py"
        assert hit["score"] == 12.5
        assert hit["meta"]["category"] == "playbook_ref"
        retriever.retrieve.assert_called_once_with("目录枚举 参数", top_k=5, filters=None)

    def test_filters_forwarded(self):
        retriever = MagicMock()
        retriever.retrieve.return_value = []
        filters = {"category": "credentials", "tool": "fastsec"}

        with patch("kali_mcp.mcp_tools.kg_dag_tools._retriever", return_value=retriever):
            _kb_search_impl("弱口令字典", top_k=3, filters=filters)

        retriever.retrieve.assert_called_once_with(
            "弱口令字典", top_k=3, filters=filters
        )

    def test_top_k_clamped_positive(self):
        retriever = MagicMock()
        retriever.retrieve.return_value = []

        with patch("kali_mcp.mcp_tools.kg_dag_tools._retriever", return_value=retriever):
            _kb_search_impl("q", top_k=0)
            _kb_search_impl("q", top_k=-3)

        assert retriever.retrieve.call_args_list[0].kwargs["top_k"] == 1
        assert retriever.retrieve.call_args_list[1].kwargs["top_k"] == 1

    def test_retriever_none_is_tolerant(self):
        with patch("kali_mcp.mcp_tools.kg_dag_tools._retriever", return_value=None):
            out = _kb_search_impl("sql 注入")

        assert out["initialized"] is False
        assert out["hits"] == []
        assert "message" in out

    def test_retrieve_error_is_tolerant(self):
        retriever = MagicMock()
        retriever.retrieve.side_effect = RuntimeError("index corrupt")

        with patch("kali_mcp.mcp_tools.kg_dag_tools._retriever", return_value=retriever):
            out = _kb_search_impl("sql 注入")

        assert out["initialized"] is True
        assert out["hits"] == []
        assert "error" in out
        assert "message" in out

    def test_empty_kb_gets_hint(self):
        retriever = MagicMock()
        retriever.retrieve.return_value = []

        with patch("kali_mcp.mcp_tools.kg_dag_tools._retriever", return_value=retriever):
            out = _kb_search_impl("不存在的内容")

        assert out["initialized"] is True
        assert out["hit_count"] == 0
        assert "message" in out  # 知识库为空提示


# ---------------- 注册面 ----------------

class TestObservabilityToolsRegistration:
    def test_kg_dag_tools_registered(self):
        from kali_mcp.mcp_tools.kg_dag_tools import register_kg_dag_tools

        mcp, calls = _recording_mcp()
        register_kg_dag_tools(mcp, MagicMock())

        assert "dag_apply" in calls
        assert "dag_recommend" in calls
        assert "dag_status" in calls
        assert "kb_search" in calls

    def test_orchestration_removed_from_keep_set(self):
        from kali_mcp.mcp_tools.meta_tools import K1_KEEP_TOOLS

        # 编排面（两个 pure-orchestration 工具）已从 MCP surface 移除
        assert "agent_run" not in K1_KEEP_TOOLS
        assert "agent_status" not in K1_KEEP_TOOLS
        # 能力工具在 keep-set 内（注册后不被 K1 裁剪）
        for t in ("dag_apply", "dag_recommend", "dag_status", "kb_search",
                  "extract_findings", "wipe_traces"):
            assert t in K1_KEEP_TOOLS

    def test_registered_kb_search_end_to_end(self):
        from kali_mcp.mcp_tools.kg_dag_tools import register_kg_dag_tools

        mcp, calls = _recording_mcp()
        retriever = MagicMock()
        retriever.retrieve.return_value = [
            KbHit(chunk_id=1, source="docs/kb/sqli.md", section="sqli",
                  text="SQL 注入检测", score=3.0, meta={"category": "writeup"}),
        ]
        register_kg_dag_tools(mcp, MagicMock())

        with patch("kali_mcp.mcp_tools.kg_dag_tools._retriever", return_value=retriever):
            out = calls["kb_search"]("sql 注入", top_k=2, filters={"category": "writeup"})

        assert out["initialized"] is True
        assert out["hit_count"] == 1
        assert out["hits"][0]["source"] == "docs/kb/sqli.md"
        retriever.retrieve.assert_called_once_with(
            "sql 注入", top_k=2, filters={"category": "writeup"}
        )

    def test_registered_dag_status_end_to_end(self):
        from kali_mcp.mcp_tools.kg_dag_tools import register_kg_dag_tools

        mcp, calls = _recording_mcp()
        dag = _mock_dag(node_count=3, edge_count=2)
        register_kg_dag_tools(mcp, MagicMock())

        with patch("kali_mcp.mcp_tools.kg_dag_tools._dag_service", return_value=dag):
            out = calls["dag_status"]("s-obs")

        assert out["initialized"] is True
        assert out["nodes"] == 3
        assert out["edges"] == 2


# ---------------- playbooks 摘除（§9） ----------------

class TestPlaybooksUnregisteredByDefault:
    def _registered_names(self, env_value: str) -> Dict[str, Any]:
        from kali_mcp.mcp_tools.harness_tools import register_harness_tools

        mcp, calls = _recording_mcp()
        with patch.dict(os.environ, {"K4_LEGACY_PLAYBOOKS": env_value}, clear=False):
            register_harness_tools(mcp, MagicMock())
        return calls

    def test_default_not_registered(self):
        calls = self._registered_names("")  # 默认：开关未开

        assert "task_status" in calls        # 非 playbook 工具照常注册
        assert "run_surface_chain_multi" in calls  # 多目标配额工具不受影响
        assert "run_playbook" not in calls   # playbook 注册表摘除
        assert "run_surface_chain" not in calls

    def test_explicit_off_not_registered(self):
        calls = self._registered_names("0")

        assert "run_playbook" not in calls
        assert "run_surface_chain" not in calls

    def test_env_on_restores(self):
        calls = self._registered_names("1")  # K4_LEGACY_PLAYBOOKS=1 显式开启过渡

        assert "run_playbook" in calls
        assert "run_surface_chain" in calls
        assert "task_status" in calls

    def test_legacy_flag_helper(self):
        from kali_mcp.mcp_tools.harness_tools import _legacy_playbooks_enabled

        with patch.dict(os.environ, {}, clear=True):
            assert _legacy_playbooks_enabled() is False
        with patch.dict(os.environ, {"K4_LEGACY_PLAYBOOKS": "1"}, clear=True):
            assert _legacy_playbooks_enabled() is True
