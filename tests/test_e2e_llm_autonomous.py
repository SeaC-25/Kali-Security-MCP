# -*- coding: utf-8 -*-
"""端到端集成验收：LLM 自主多智能体渗透系统（ARCH_DESIGN §11.1 完整数据流）。

用 StubBrain（mock LLM，无真实 API key）**真实驱动决策循环**（不绕过 LLM 直接调子 agent）：
orchestrator dispatch_mission → MissionTicket → DAG mission 节点 + mission.created →
真实 ReconAgent.llm_drive_mission（LLM 决策循环，done 产出 AgentResult）→
DAG finding/summary 节点 → ACO 信息素沉积（deposit_path 接线）→
SummarizerAgent（订阅 mission.completed）→ SummarySnapshot →
orchestrator review → done → ExecutionSession(state=completed, report 非空)。

同时覆盖降级路径：retriever=None、无 SummarizerAgent、dag_service/aco=None（orchestrator 自建）。

全离线：无真实 LLM、无真实网络攻击、无随机（决策脚本预编；DAG 蒸发 TICK 关闭）。
KB 用真实 data/kb_vectors.db（存在则加载，检索失败/为空静默跳过，不阻塞链路）。
"""
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from kali_mcp.core.agent_coordinator import CoordinatorAgent, CoordinatorState
from kali_mcp.core.agent_registry import AgentRegistry
from kali_mcp.core.event_bus import EventBus
from kali_mcp.core.event_stream import EventManager
from kali_mcp.core.llm_brain import LLMBrain
from kali_mcp.core.result_aggregator import AgentResult, ResultSeverity
from kali_mcp.agents.information_gathering.recon_agent import ReconAgent
from kali_mcp.agents.llm_agent_base import MissionTicket
from kali_mcp.core.summarizer_agent import SummarizerAgent
from kali_mcp.reasoning.attack_dag import DAGService
from kali_mcp.reasoning.aco import ACO, PHEROMONE_INIT

SESSION_ID = "e2e-001"
REQUEST = "对 http://localhost:8000/ 做端口识别"
REPO_ROOT = Path(__file__).resolve().parents[1]


# ==================== mock LLM（stub，驱动真实决策循环） ====================

def _dispatch_decision(agent_role: str, objective: str, priority: int = 8) -> Dict[str, Any]:
    """orchestrator 决策：dispatch_mission（附录 A 协议）。"""
    return {
        "thinking": ["plan"],
        "action": "dispatch_mission",
        "agent_role": agent_role,
        "objective": objective,
        "target": "TARGET_HOST",
        "context_refs": ["dag.node.n1", "kb.chunk.3"],
        "constraints": ["read-only verification"],
        "priority": priority,
        "reason": f"dispatch {agent_role}",
        "plan": ["next hypothesis"],
    }


def _orchestrator_done(summary: str = "assessment complete") -> Dict[str, Any]:
    """orchestrator 决策：done。"""
    return {
        "thinking": ["done"],
        "action": "done",
        "summary": summary,
        "structured_summary": {"findings": [], "next_hypotheses": []},
        "plan": [],
    }


def _orchestrator_review() -> Dict[str, Any]:
    """orchestrator 决策：review（hold，等更多结果）。"""
    return {
        "thinking": ["review"],
        "action": "review",
        "reason": "review collected results",
        "plan": [],
    }


def _agent_done(
    title: str = "开放端口: 80/tcp",
    severity: str = "info",
    confidence: float = 0.95,
    evidence: str = "80/tcp open http",
) -> Dict[str, Any]:
    """子 agent 决策：done（structured_summary 携带 finding）。"""
    return {
        "thinking": ["collected"],
        "action": "done",
        "summary": "端口与服务识别完成",
        "structured_summary": {
            "findings": [
                {"title": title, "severity": severity, "confidence": confidence,
                 "evidence": [evidence]},
            ],
            "next_hypotheses": ["检查 80/tcp 的 HTTP 服务指纹"],
        },
        "plan": [],
    }


class StubBrain(LLMBrain):
    """mock LLM：一套实例同时服务 orchestrator 与子 agent 两个管线。

    - orchestrator：`_invoke_text`（复用 LLMBrain._parse_decision_json 解析管线）；
    - 子 agent：`analyze`（llm_drive_mission 决策循环）。
    两条决策队列相互独立，按脚本顺序弹出；耗尽后回落到 done，绝不阻塞。
    """

    def __init__(
        self,
        orchestrator_script: Optional[List[Any]] = None,
        agent_script: Optional[List[Any]] = None,
    ):
        self._orch = list(orchestrator_script or [])
        self._agent = list(agent_script or [])
        self.orch_calls: List[tuple] = []        # (prompt, messages) 每次 _invoke_text
        self.agent_calls: List[List[Dict[str, str]]] = []   # 每次 analyze 的消息列表
        self.tool_catalog = ""
        self._client = object()                  # available=True

    @property
    def available(self) -> bool:
        return True

    # ---- orchestrator 管线（线程池内调用，仅 pop 列表，线程安全） ----
    def _invoke_text(self, prompt, messages, *, max_tokens=2000, prefer_json=False):
        self.orch_calls.append((prompt, list(messages)))
        if not self._orch:
            return json.dumps(_orchestrator_done("no more orchestrator script"), ensure_ascii=False)
        item = self._orch.pop(0)
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)

    # ---- 子 agent 管线 ----
    def analyze(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        self.agent_calls.append(list(messages))
        if not self._agent:
            return _agent_done(title="开放端口: fallback")
        item = self._agent.pop(0)
        return item if isinstance(item, dict) else json.loads(item)

    def is_policy_refusal(self, text: str) -> bool:
        return False

    def repair_decision(self, raw_text, context_messages=None):
        return None

    def truncate_output(self, output, max_chars: int = 3000) -> str:
        return output


class RecordingACO(ACO):
    """观察 ACO：记录 deposit_path 调用（委托 super，行为不变，只做断言观测）。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.deposit_calls: List[Dict[str, Any]] = []

    async def deposit_path(self, verified_node_id, success_signal=1.0,
                           severity="INFO", session_id=None):
        self.deposit_calls.append({
            "verified_node_id": verified_node_id,
            "success_signal": success_signal,
            "severity": severity,
            "session_id": session_id,
        })
        return await super().deposit_path(
            verified_node_id, success_signal=success_signal,
            severity=severity, session_id=session_id,
        )


def _make_retriever():
    """data/kb_vectors.db 存在 → 加载真实检索器；否则 None（与任务规格一致）。"""
    if not (REPO_ROOT / "data" / "kb_vectors.db").exists():
        return None
    try:
        from kali_mcp.reasoning.knowledge_retriever import KnowledgeRetriever
        return KnowledgeRetriever()
    except Exception:  # noqa: BLE001 —— 构建失败降级为 None
        return None


def _make_components(
    brain: StubBrain,
    *,
    session_id: str = SESSION_ID,
    retriever: Any = None,
    retriever_for_agent: Any = None,
    with_summarizer: bool = True,
    dag: Optional[DAGService] = None,
    aco: Optional[ACO] = None,
    **coord_kw,
) -> dict:
    """构造完整组件：registry + 真实 ReconAgent + bus + DAG + ACO + Summarizer + orchestrator。"""
    registry = AgentRegistry()
    agent = ReconAgent(
        brain=brain, retriever=retriever_for_agent, dag_service=dag,
    )
    registry.register_agent(agent)

    bus = EventBus()
    if dag is None:
        # 蒸发 TICK 关闭（tick 阈值/间隔调大），保证 τ 完全确定
        dag = DAGService(
            bus=bus, session_id=session_id, tick_node_count=1000, tick_interval_sec=1e9,
        )
    if aco is None:
        aco = RecordingACO(dag=dag)

    summarizer = None
    if with_summarizer:
        summarizer = SummarizerAgent(
            bus=bus, event_manager=EventManager(), throttle_seconds=0.0,
        ).subscribe()

    coord_kw.setdefault("results_per_review", 1)
    coord = CoordinatorAgent(
        registry,
        brain=brain,
        dag_service=dag,
        aco=aco,
        retriever=retriever,
        bus=bus,
        **coord_kw,
    )
    if retriever is None:
        # 显式 retriever=None：标记为已尝试（模拟无索引的降级环境），
        # 避免触发惰性构建加载真实 KB（_retrieve_kb 返回空块，链路照常）。
        coord._retriever_attempted = True  # noqa: SLF001 —— 测试注入降级状态
    return {
        "coord": coord, "bus": bus, "dag": dag, "aco": aco,
        "agent": agent, "summarizer": summarizer,
    }


async def _pre_seed_dag(dag: DAGService, session_id: str = SESSION_ID) -> None:
    """预置 DAG：hypothesis → attack_action 前沿边（供 ACO 推荐注入 + τ 断言）。"""
    await dag.apply("add_node", {"node": {
        "node_id": "h1", "node_type": "hypothesis", "session_id": session_id,
        "label": "Web 服务暴露面假设", "meta": {}}})
    await dag.apply("add_node", {"node": {
        "node_id": "a1", "node_type": "attack_action", "session_id": session_id,
        "label": "对 80 端口的服务识别", "meta": {"severity_norm": 0.8}}})
    await dag.apply("add_edge", {"edge": {
        "edge_id": "e1", "edge_type": "drives", "source_id": "h1", "target_id": "a1",
        "session_id": session_id, "tau": PHEROMONE_INIT,
        "meta": {"severity_norm": 0.8, "kb_sim": 0.6, "target_rel": 0.5}, "weight": 1.0}})


def _all_llm_text(brain: StubBrain) -> str:
    """orchestrator 看到的所有 LLM 输入文本。"""
    return " ".join(m["content"] for _, msgs in brain.orch_calls for m in msgs)


# ==================== 端到端主链路（验收标准 1/2） ====================

class TestFullE2ELlmChain:
    async def test_full_chain_mock_llm_drives_end_to_end(self):
        """mock LLM 驱动完整链路：dispatch → 子 agent 执行 → review → done → 报告。

        同时验证：KB（真实索引，存在则注入）、DAG/ACO 上下文注入、LLM 侧目标脱敏、
        SummarizerAgent 事件采集、ACO 沉积接线。
        """
        brain = StubBrain(
            orchestrator_script=[
                _dispatch_decision("recon_agent", "识别目标主机的开放端口与服务"),
                _orchestrator_review(),
                _orchestrator_done("recon 完成，报告已生成"),
            ],
            agent_script=[_agent_done()],
        )
        retriever = _make_retriever()
        c = _make_components(brain, retriever=retriever, retriever_for_agent=retriever)
        coord, bus, dag, aco, agent, summarizer = (
            c["coord"], c["bus"], c["dag"], c["aco"], c["agent"], c["summarizer"],
        )
        await _pre_seed_dag(dag)

        session = await coord.process_request(REQUEST, session_id=SESSION_ID)

        # ---------- orchestrator 状态 ----------
        assert session.state == CoordinatorState.COMPLETED
        assert session.orchestrator_mode == "llm"
        # LLM 决策序列：dispatch_mission → review → done（真实 LLM 循环产出）
        assert [d.get("action") for d in session.llm_decisions] == [
            "dispatch_mission", "review", "done",
        ]
        assert session.review_rounds >= 1
        assert session.error is None

        # ---------- MissionTicket（dispatch 产物） ----------
        assert len(session.missions) == 1
        ticket = session.missions[0]
        assert isinstance(ticket, MissionTicket)
        assert ticket.agent_role == "recon_agent"
        assert ticket.objective == "识别目标主机的开放端口与服务"
        assert ticket.target == "http://localhost:8000/"     # 真实目标（intent 提取）
        assert ticket.priority == 8
        assert ticket.constraints == ["read-only verification"]
        assert ticket.context_refs == ["dag.node.n1", "kb.chunk.3"]
        assert ticket.status == "completed"
        assert ticket.lease_expires_at > 0                    # lease TTL
        assert ticket.result_ref == ticket.mission_id

        # ---------- 子 agent（真实 ReconAgent + LLM 决策循环） ----------
        assert len(session.agent_results) == 1
        result = session.agent_results[0]
        assert isinstance(result, AgentResult)
        assert result.success is True
        assert result.agent_id == "recon_agent"
        assert result.task_id == ticket.mission_id
        assert result.metadata.get("llm_autonomous") is True
        assert result.metadata.get("rounds") == 1              # 首轮即 done
        assert len(brain.agent_calls) == 1                     # 子 agent 真的走了一次 LLM
        sub_first = brain.agent_calls[0][0]["content"]
        assert "ReconAgent" in sub_first                       # 角色 prompt
        assert ticket.objective in sub_first                   # 任务简报
        assert "TARGET_HOST" in sub_first                      # 目标脱敏占位符
        assert "http://localhost:8000/" not in sub_first       # 真实目标不出现在 LLM 侧
        titles = {f.title for f in result.findings}
        assert "开放端口: 80/tcp" in titles                    # structured_summary → Finding

        # ---------- DAG 节点/边 ----------
        mission_node = dag.get_node(ticket.mission_id, session_id=SESSION_ID)
        assert mission_node is not None and mission_node.node_type == "mission"
        assert mission_node.meta.get("status") == "completed"
        finding_node = dag.get_node(f"{ticket.mission_id}__finding", session_id=SESSION_ID)
        assert finding_node is not None and finding_node.node_type == "finding"
        assert "开放端口: 80/tcp" in finding_node.meta.get("titles", [])
        node_types = {
            n.node_type for n in dag._nodes.values()          # noqa: SLF001 —— 测试内省
            if n.session_id == SESSION_ID
        }
        assert {"mission", "finding", "summary"} <= node_types
        assert dag.node_count(session_id=SESSION_ID) >= 5      # h1/a1 + mission/finding/summary
        assert dag.edge_count(session_id=SESSION_ID) == 1      # 预置 e1

        # ---------- ACO：orchestrator 成功即触发沉积接线 ----------
        assert len(aco.deposit_calls) == 1
        deposit = aco.deposit_calls[0]
        assert deposit["verified_node_id"] == f"{ticket.mission_id}__finding"
        assert deposit["session_id"] == SESSION_ID
        # 预置边 τ 信息素有值（TICK 关闭 → 无蒸发干扰）
        assert dag.get_edge("e1").tau == pytest.approx(PHEROMONE_INIT)

        # ---------- ACO 推荐注入 orchestrator 输入（只读推荐，不触发工具） ----------
        all_text = _all_llm_text(brain)
        assert "蚁群推荐" in all_text
        assert "e1" in all_text and "P=" in all_text and "τ=" in all_text
        assert "仅参考，你来决定" in all_text
        assert "攻击图上下文" in all_text
        # KB 真实索引存在 → 命中块注入（仅参考）
        if retriever is not None:
            assert "知识库参考" in all_text

        # ---------- SummarizerAgent（mission.completed 事件 → SummarySnapshot） ----------
        assert summarizer is not None
        snap = summarizer.build_snapshot(SESSION_ID)
        assert snap.session_id == SESSION_ID
        assert len(snap.findings) == 1
        assert snap.findings[0].title == "开放端口: 80/tcp"
        assert "nodes_total" in snap.stats
        assert bus.get_stats()["by_type"]["summary.update"]["emitted"] >= 1
        assert bus.get_stats()["total_errors"] == 0            # 事件处理全程无异常

        # ---------- 聚合 + 最终报告 ----------
        assert session.aggregated_result is not None
        assert len(session.aggregated_result.unique_findings) >= 1
        assert session.report
        assert "安全测试报告" in session.report
        assert "开放端口: 80/tcp" in session.report

        # ---------- ACO 写路径（verifier 回写）：E2E 图上沉积真实生效 ----------
        await dag.apply("add_node", {"node": {
            "node_id": "act_v", "node_type": "attack_action", "session_id": SESSION_ID,
            "label": "验证动作", "meta": {"severity_norm": 0.8}}})
        await dag.apply("add_edge", {"edge": {
            "edge_id": "e_v", "edge_type": "yields", "source_id": "act_v",
            "target_id": f"{ticket.mission_id}__finding", "session_id": SESSION_ID,
            "meta": {"severity_norm": 0.8}}})

        records = await aco.deposit_path(
            f"{ticket.mission_id}__finding", success_signal=0.9, severity="HIGH",
            session_id=SESSION_ID,
        )
        assert records, "E2E 图上的 finding 节点必须有可沉积的入边"
        deposited = {r["edge_id"]: r for r in records}
        assert deposited["e_v"]["new_tau"] == pytest.approx(
            PHEROMONE_INIT + 0.15 * 0.9 * (1 + 0.6)
        )

        # ---------- 关键中间状态摘要（验收标准 2 的报告素材） ----------
        print("\n[E2E] dispatch MissionTicket:",
              f"mission_id={ticket.mission_id} agent={ticket.agent_role} "
              f"objective={ticket.objective!r} target={ticket.target} status={ticket.status}")
        print("[E2E] AgentResult:",
              f"agent={result.agent_id} success={result.success} "
              f"findings={len(result.findings)} rounds={result.metadata.get('rounds')} "
              f"titles={titles}")
        print("[E2E] DAG:",
              f"nodes={dag.node_count(session_id=SESSION_ID)} "
              f"edges={dag.edge_count(session_id=SESSION_ID)} "
              f"types={sorted(node_types)}")
        print("[E2E] ACO:",
              f"deposit_path_calls={len(aco.deposit_calls)} "
              f"e1.tau={dag.get_edge('e1').tau} e_v.tau={deposited['e_v']['new_tau']}")
        print("[E2E] SummarySnapshot:",
              f"findings={len(snap.findings)} title={snap.findings[0].title} "
              f"summary.update_emitted={bus.get_stats()['by_type']['summary.update']['emitted']}")
        print(f"[E2E] report: {session.report.splitlines()[1].strip() if len(session.report.splitlines()) > 1 else session.report[:80]}")


# ==================== 降级路径（组件为 None 不阻断链路） ====================

class TestDegradationPaths:
    async def test_retriever_none_skips_kb_block(self):
        """retriever=None → KB 块整体跳过，链路照常完成。"""
        brain = StubBrain(
            orchestrator_script=[
                _dispatch_decision("recon_agent", "识别目标主机端口"),
                _orchestrator_done(),
            ],
            agent_script=[_agent_done(title="开放端口: 22/tcp", evidence="22/tcp open ssh")],
        )
        c = _make_components(brain, retriever=None, retriever_for_agent=None)
        coord = c["coord"]
        session = await coord.process_request(REQUEST, session_id="e2e-nokb")

        assert session.state == CoordinatorState.COMPLETED
        assert len(session.missions) == 1
        assert session.report and "开放端口: 22/tcp" in session.report
        # KB 块从未注入（retriever=None）
        assert "知识库参考" not in _all_llm_text(brain)
        # 子 agent 侧同样无 KB 块
        assert all("知识库参考" not in m.get("content", "") for msgs in brain.agent_calls for m in msgs)

    async def test_no_summarizer_mission_events_still_fine(self):
        """无 SummarizerAgent 订阅 → mission 事件无消费者，链路不崩、报告照常。"""
        brain = StubBrain(
            orchestrator_script=[
                _dispatch_decision("recon_agent", "识别目标主机端口"),
                _orchestrator_done(),
            ],
            agent_script=[_agent_done()],
        )
        c = _make_components(brain, retriever=None, with_summarizer=False)
        coord, bus = c["coord"], c["bus"]
        session = await coord.process_request(REQUEST, session_id="e2e-nosum")

        assert session.state == CoordinatorState.COMPLETED
        assert len(session.missions) == 1
        assert session.report
        assert bus.get_stats()["total_errors"] == 0

    async def test_dag_aco_none_orchestrator_self_builds(self):
        """dag_service/aco 均 None → orchestrator 自建（__init__ 惰性），链路完成。"""
        brain = StubBrain(
            orchestrator_script=[
                _dispatch_decision("recon_agent", "识别目标主机端口"),
                _orchestrator_done(),
            ],
            agent_script=[_agent_done()],
        )
        registry = AgentRegistry()
        agent = ReconAgent(brain=brain, retriever=None, dag_service=None)  # 子 agent 也不接 DAG
        registry.register_agent(agent)
        coord = CoordinatorAgent(
            registry, brain=brain, retriever=None, results_per_review=1,
        )
        coord._retriever_attempted = True   # noqa: SLF001 —— 显式 None：跳过惰性 KB 构建
        assert coord.dag_service is not None and coord.aco is not None   # 自建成功
        assert coord.aco.dag is coord.dag_service

        session = await coord.process_request(REQUEST, session_id="e2e-nodag")

        assert session.state == CoordinatorState.COMPLETED
        assert len(session.missions) == 1
        assert session.report
        # 自建 DAG 收尾：mission + finding + summary 节点
        sid = session.session_id
        node_types = {n.node_type for n in coord.dag_service._nodes.values()  # noqa: SLF001
                      if n.session_id == sid}
        assert {"mission", "finding", "summary"} <= node_types
