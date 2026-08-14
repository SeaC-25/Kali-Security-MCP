# -*- coding: utf-8 -*-
"""P3 LLM orchestrator 单测（ARCH_DESIGN §2 / §2.2 / §5.5 / §11.3 P3，验收标准 1/2/4）。

用 mock brain（脚本化决策 JSON，复用真实 `LLMBrain._parse_decision_json` 管线）
+ mock 子 agent，验证：
- dispatch_mission → MissionTicket 生成 + DAG mission 节点 + bus.emit("mission.created")
- review 轮收集结果 → LLM 判定继续 dispatch / 换向 / done
- done → 复用 result_aggregator.generate_report 产出报告
- ACO 推荐注入 LLM 输入（recommend_next top-k，只读不触发工具）
- LLM 不可用降级：明确错误（不空转）；legacy_fallback 可选回退
- mission lease TTL 超时回收（mission.failed 事件）

全离线：不触网、不加载真实 LLM / embedding 模型。
"""
import asyncio
import json
from typing import Any, Dict, List

import pytest

from kali_mcp.core.agent_coordinator import CoordinatorAgent, CoordinatorState
from kali_mcp.core.agent_registry import AgentRegistry
from kali_mcp.core.event_bus import EventBus
from kali_mcp.core.llm_brain import LLMBrain
from kali_mcp.core.result_aggregator import AgentResult, Finding, ResultSeverity, ResultType
from kali_mcp.agents.llm_agent_base import MissionTicket
from kali_mcp.reasoning.attack_dag import DAGService
from kali_mcp.reasoning.aco import ACO


def _run(coro):
    """同步测试内运行协程。"""
    return asyncio.run(coro)


# ==================== mocks ====================

def _dispatch_decision(agent_role: str, objective: str, priority: int = 8) -> Dict[str, Any]:
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


def _done_decision(summary: str = "assessment complete") -> Dict[str, Any]:
    return {
        "thinking": ["done"],
        "action": "done",
        "summary": summary,
        "structured_summary": {"findings": [], "next_hypotheses": []},
        "plan": [],
    }


class ScriptedBrain(LLMBrain):
    """脚本化 orchestrator brain：覆盖 _invoke_text，其余复用真实 LLMBrain 管线。"""

    def __init__(self, script: List[Any]):
        self._script = list(script)
        self.calls: List[tuple] = []          # (prompt, messages) 每次 _invoke_text
        self.tool_catalog = ""
        self._client = object()               # available=True

    @property
    def available(self) -> bool:
        return True

    def _invoke_text(self, prompt, messages, *, max_tokens=2000, prefer_json=False):
        self.calls.append((prompt, list(messages)))
        if not self._script:
            return json.dumps(_done_decision("no more script"), ensure_ascii=False)
        item = self._script.pop(0)
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)

    def repair_decision(self, raw_text, context_messages=None):
        return None


class UnavailableBrain(LLMBrain):
    """LLM 不可用（无 API Key 语义）。"""

    def __init__(self):
        self.tool_catalog = ""
        self._client = None


def _mission_result(ticket: MissionTicket, *, success: bool = True,
                    title: str = "", errors: List[str] = None) -> AgentResult:
    title = title or f"{ticket.agent_role} finding"
    return AgentResult(
        agent_id=ticket.agent_role,
        task_id=ticket.mission_id,
        tool_name="llm_mission",
        target=ticket.target,
        success=success,
        execution_time=0.01,
        output="mission ok" if success else "; ".join(errors or []),
        parsed_data={"findings": [] if not success else [{
            "type": "vulnerability", "severity": "high", "title": title,
            "description": "mock", "evidence": ["mock evidence"], "confidence": 0.9,
        }]},
        findings=[] if not success else [Finding(
            finding_type=ResultType.VULNERABILITY, severity=ResultSeverity.HIGH,
            title=title, description="mock", evidence=["mock evidence"],
            source=ticket.agent_role, confidence=0.9,
        )],
        errors=errors or [],
        metadata={"llm_autonomous": True, "mission_id": ticket.mission_id},
    )


class MockMissionAgent:
    """伪 LLM 子 agent：记录 mission 并返回脚本化 AgentResult（§2.2 认领后执行）。"""

    def __init__(self, agent_id: str, result: AgentResult = None, delay: float = 0.0):
        self.agent_id = agent_id
        self.delay = delay
        self.driven: List[MissionTicket] = []
        self._result = result

    def get_supported_tools(self):
        return ["llm_mission"]

    def is_available(self):
        return True

    async def llm_drive_mission(self, ticket: MissionTicket) -> AgentResult:
        self.driven.append(ticket)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self._result if self._result is not None else _mission_result(ticket)


class MockLegacyAgent:
    """legacy 确定性路径的伪 agent（execute_task 接口）。"""

    def __init__(self, agent_id: str = "recon_agent"):
        self.agent_id = agent_id
        self.name = agent_id
        self.executed: List[Any] = []

    def get_supported_tools(self):
        return {"nmap_scan", "masscan_scan", "masscan_fast_scan", "whatweb_scan",
                "gobuster_scan", "nuclei_scan", "httpx_probe", "fastsec_scan",
                "report_generator"}

    def is_available(self):
        return True

    async def execute_task(self, task):
        self.executed.append(task)
        return AgentResult(
            agent_id=self.agent_id,
            task_id=task.task_id,
            tool_name=task.tool_name,
            target=task.parameters.get("target", ""),
            success=True,
            execution_time=0.01,
            output="ok",
            parsed_data={"findings": [{
                "type": "info", "severity": "info", "title": f"{task.tool_name} ok",
                "description": "", "evidence": ["ok"], "confidence": 0.8,
            }]},
            findings=[],
            errors=[],
        )


class NullRetriever:
    """空 KB 检索器：避免测试触发真实 embedding 模型加载/下载。"""

    def retrieve(self, query, top_k=5, filters=None):
        return []


def _make_llm_coordinator(script: List[Any], agents: List[Any], *,
                          session_id: str = "s-test", **kw) -> tuple:
    registry = AgentRegistry()
    for a in agents:
        registry.register_agent(a)
    bus = EventBus()
    bus._captured_events = []          # noqa: SLF001 —— 测试捕获总线事件
    bus.subscribe("*", lambda event: bus._captured_events.append(event), "test-capture")
    dag = DAGService(bus=bus, session_id=session_id)
    aco = ACO(dag=dag)
    brain = ScriptedBrain(script)
    kw.setdefault("retriever", NullRetriever())
    coord = CoordinatorAgent(
        registry, brain=brain, dag_service=dag, aco=aco, bus=bus, **kw
    )
    return coord, bus, dag, brain


def _events_of(bus, event_type: str) -> List[Any]:
    return [e for e in getattr(bus, "_captured_events", []) if e.event_type == event_type]


# ==================== dispatch → ticket + mission.created ====================

class TestDispatch:
    def test_dispatch_generates_ticket_and_emits_mission_created(self):
        """dispatch_mission → MissionTicket + DAG mission 节点 + bus mission.created。"""
        script = [
            _dispatch_decision("recon_agent", "识别开放端口与服务"),
            _done_decision(),
        ]
        agent = MockMissionAgent("recon_agent")
        coord, bus, dag, brain = _make_llm_coordinator(script, [agent], results_per_review=1)

        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id="s-test"))

        assert session.state == CoordinatorState.COMPLETED
        # 1 个 mission 被派发并执行
        assert len(session.missions) == 1
        ticket = session.missions[0]
        assert isinstance(ticket, MissionTicket)
        assert ticket.agent_role == "recon_agent"
        assert ticket.objective == "识别开放端口与服务"
        assert ticket.target == "127.0.0.1"          # 真实目标
        assert ticket.status == "completed"
        assert ticket.lease_expires_at > 0            # lease TTL
        assert ticket.priority == 8
        assert ticket.constraints == ["read-only verification"]
        assert ticket.context_refs == ["dag.node.n1", "kb.chunk.3"]

        # 子 agent 收到真实目标
        assert agent.driven[0].target == "127.0.0.1"

        # mission.created 事件（数据即 MissionTicket）
        created = _events_of(bus, "mission.created")
        assert len(created) == 1
        assert created[0].data.mission_id == ticket.mission_id
        assert len(_events_of(bus, "mission.completed")) == 1

        # DAG mission 节点（mission_id 即节点 id，node_type=mission）
        node = dag.get_node(ticket.mission_id, session_id="s-test")
        assert node is not None and node.node_type == "mission"
        assert node.meta.get("status") == "completed"

        # LLM 侧脱敏：真实目标不出现在任何输入消息里
        all_text = " ".join(m["content"] for _, msgs in brain.calls for m in msgs)
        assert "127.0.0.1" not in all_text
        assert "TARGET_HOST" in all_text

        # done → 报告复用 result_aggregator.generate_report
        assert session.aggregated_result is not None
        assert len(session.aggregated_result.unique_findings) == 1
        assert "安全测试报告" in session.report
        assert "recon_agent finding" in session.report

    def test_review_rounds_collect_results_and_llm_decides(self):
        """review 轮：累计 N 个结果后 LLM 判定继续 dispatch → 换向 → done。"""
        script = [
            _dispatch_decision("recon_agent", "识别开放端口"),
            _dispatch_decision("web_vuln_agent", "验证 /admin 是否存在 SQL 注入点"),
            _done_decision(),
        ]
        agents = [MockMissionAgent("recon_agent"), MockMissionAgent("web_vuln_agent")]
        coord, bus, dag, brain = _make_llm_coordinator(script, agents, results_per_review=1)

        session = _run(coord.process_request("对 127.0.0.1 做渗透测试", session_id="s-test"))

        assert session.state == CoordinatorState.COMPLETED
        assert len(session.missions) == 2
        assert [t.agent_role for t in session.missions] == ["recon_agent", "web_vuln_agent"]
        assert session.review_rounds == 2
        # LLM 决策序列：dispatch → dispatch → done
        assert [d.get("action") for d in session.llm_decisions] == [
            "dispatch_mission", "dispatch_mission", "done"
        ]
        # 2 个 mission 结果全部收集
        assert len(session.agent_results) == 2
        assert all(r.success for r in session.agent_results)
        # 两次派发各发一次事件
        assert len(_events_of(bus, "mission.created")) == 2
        assert len(_events_of(bus, "mission.completed")) == 2
        # review 上下文注入过（含「评审轮」提示）
        assert any(
            "评审轮" in m["content"]
            for _, msgs in brain.calls for m in msgs if m["role"] == "user"
        )
        # 报告包含两个 agent 的 finding（去重后）
        titles = {f.title for f in session.aggregated_result.unique_findings}
        assert "recon_agent finding" in titles
        assert "web_vuln_agent finding" in titles

    def test_done_after_single_dispatch_produces_report(self):
        """results_per_review 未达阈值 → 不触发 review，直接 done 收尾。"""
        script = [_dispatch_decision("recon_agent", "端口扫描"), _done_decision()]
        agent = MockMissionAgent("recon_agent")
        coord, bus, dag, brain = _make_llm_coordinator(script, [agent], results_per_review=5)

        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id="s-test"))

        assert session.state == CoordinatorState.COMPLETED
        assert session.review_rounds == 0
        assert len(session.missions) == 1
        assert session.report and "recon_agent finding" in session.report


# ==================== ACO 推荐注入（只推荐不决策） ====================

class TestAcoInjection:
    def test_aco_recommendations_injected_into_llm_input(self):
        """预置 DAG 边 → recommend_next top-k 注入 LLM 输入（§5.5 格式），不触发工具。"""
        session_id = "s-aco"
        script = [
            _dispatch_decision("recon_agent", "识别开放端口与服务"),
            _done_decision(),
        ]
        registry = AgentRegistry()
        registry.register_agent(MockMissionAgent("recon_agent"))
        bus = EventBus()
        dag = DAGService(bus=bus, session_id=session_id)

        # 预置：hypothesis → attack_action 前沿边（τ=0.7）
        _run(dag.apply("add_node", {"node": {
            "node_id": "h1", "node_type": "hypothesis", "session_id": session_id,
            "label": "SQL 参数检查假设", "meta": {}}}))
        _run(dag.apply("add_node", {"node": {
            "node_id": "a1", "node_type": "attack_action", "session_id": session_id,
            "label": "对 /admin 的 SQL 参数检测", "meta": {"severity_norm": 0.8}}}))
        _run(dag.apply("add_edge", {"edge": {
            "edge_id": "e1", "edge_type": "drives", "source_id": "h1", "target_id": "a1",
            "session_id": session_id, "tau": 0.7, "weight": 1.0, "meta": {}}}))

        aco = ACO(dag=dag)
        brain = ScriptedBrain(script)
        coord = CoordinatorAgent(
            registry, brain=brain, dag_service=dag, aco=aco, bus=bus,
            retriever=NullRetriever(),
            results_per_review=1,
        )
        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id=session_id))

        assert session.state == CoordinatorState.COMPLETED
        # ACO 推荐出现在 LLM 输入（初始规划 + review 上下文）
        all_text = " ".join(m["content"] for _, msgs in brain.calls for m in msgs)
        assert "蚁群推荐" in all_text
        assert "e1" in all_text
        assert "P=" in all_text and "τ=" in all_text
        # ACO 只推荐：orchestrator 决策序列仍为纯 LLM 脚本（无工具触发）
        assert [d.get("action") for d in session.llm_decisions] == [
            "dispatch_mission", "done"
        ]
        # 注入文本格式与 §5.5 一致
        assert "仅参考，你来决定" in all_text


# ==================== mission 超时回收 ====================

class TestMissionTimeout:
    def test_mission_timeout_recycles_and_emits_failed(self):
        """lease TTL 超时 → ticket=expired + mission.failed 事件，orchestrator 继续收尾。"""
        script = [
            _dispatch_decision("recon_agent", "慢扫描"),
            _done_decision(),
        ]
        slow = MockMissionAgent("recon_agent", delay=0.2)
        coord, bus, dag, brain = _make_llm_coordinator(
            script, [slow], results_per_review=99, mission_timeout=0.05,
        )

        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id="s-test"))

        # 超时 → 失败结果（不空转、不崩），会话仍正常收尾
        assert session.state == CoordinatorState.COMPLETED
        assert len(session.missions) == 1
        ticket = session.missions[0]
        assert ticket.status == "expired"
        assert session.agent_results[0].success is False
        assert any("超时" in e for e in session.agent_results[0].errors)
        assert len(_events_of(bus, "mission.failed")) == 1
        # DAG mission 节点状态迁移到 expired
        node = dag.get_node(ticket.mission_id, session_id="s-test")
        assert node is not None and node.meta.get("status") == "expired"


# ==================== LLM 不可用降级 ====================

class TestDegradation:
    def test_llm_unavailable_returns_clear_error(self):
        """LLM 不可用且未开回退 → 明确错误（不空转）。"""
        registry = AgentRegistry()
        coord = CoordinatorAgent(registry, brain=UnavailableBrain(), legacy_fallback=False)

        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id="s-fail"))

        assert session.state == CoordinatorState.FAILED
        assert "LLM orchestrator 不可用" in session.error
        assert session.orchestrator_mode == "llm"
        # 无空转：没有 mission、没有 LLM 调用、立即返回
        assert session.missions == []
        assert session.agent_results == []
        assert coord.total_sessions == 1

    def test_legacy_fallback_path_completes(self):
        """legacy_fallback=True → 走旧确定性路径完成（MockLegacyAgent.execute_task）。"""
        registry = AgentRegistry()
        legacy_agent = MockLegacyAgent("recon_agent")
        registry.register_agent(legacy_agent)
        coord = CoordinatorAgent(
            registry, brain=UnavailableBrain(), legacy_fallback=True,
        )

        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id="s-legacy"))

        assert session.orchestrator_mode == "legacy"
        assert session.state == CoordinatorState.COMPLETED
        assert session.plan is not None
        assert len(session.agent_results) > 0
        assert legacy_agent.executed  # 确实走了 agent 执行
        assert session.aggregated_result is not None
        assert session.report


# ==================== LLM 协议健壮性 ====================

class TestProtocolRobustness:
    def test_unknown_action_gets_correction(self):
        """未知 action → 纠正提示后继续，会话正常完成。"""
        script = [
            {"thinking": [], "action": "fly_to_moon", "reason": "", "plan": []},
            _dispatch_decision("recon_agent", "端口扫描"),
            _done_decision(),
        ]
        agent = MockMissionAgent("recon_agent")
        coord, bus, dag, brain = _make_llm_coordinator(script, [agent], results_per_review=1)

        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id="s-test"))

        assert session.state == CoordinatorState.COMPLETED
        assert [d.get("action") for d in session.llm_decisions] == [
            "fly_to_moon", "dispatch_mission", "done"
        ]
        assert any("Unknown action" in m["content"] for _, msgs in brain.calls for m in msgs)

    def test_duplicate_objective_not_dispatched_twice(self):
        """重复 objective → 提示 LLM 换目标，不重复派发同一任务。"""
        script = [
            _dispatch_decision("recon_agent", "端口扫描"),
            _dispatch_decision("recon_agent", "端口扫描"),   # 重复
            _done_decision(),
        ]
        agent = MockMissionAgent("recon_agent")
        coord, bus, dag, brain = _make_llm_coordinator(script, [agent], results_per_review=5)

        session = _run(coord.process_request("对 127.0.0.1 做端口扫描", session_id="s-test"))

        assert session.state == CoordinatorState.COMPLETED
        assert len(session.missions) == 1          # 只派发 1 次
        assert len(_events_of(bus, "mission.created")) == 1
        # LLM 被提示去重
        assert any("objective 已派发过" in m["content"] for _, msgs in brain.calls for m in msgs)
