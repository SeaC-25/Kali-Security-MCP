# -*- coding: utf-8 -*-
"""P1 子 agent LLM 化单测（ARCH_DESIGN §3.1/§3.2/§3.3，验收标准 1）。

用 mock brain（返回固定决策 JSON）验证决策循环：
- call_tool 正确路由到 _call_tool（原 executor 桥）
- 消息累积（决策 + 工具输出回灌）
- retry / repair 处理（复用 LLMBrain 协议）
- done 产出 AgentResult（含 structured_summary 合并的 findings）
- is_tool_failure_output 过滤（失败输出不产出 finding）
- 降级路由（brain 不可用 → legacy 规则路径）
- KB 每 3 步注入（retriever 可选接入）、run_tool、轮次耗尽兜底

全部离线：不触网、不加载真实 LLM / embedding 模型。
"""
import asyncio
from typing import Any, Dict, List

import pytest

from kali_mcp.agents.information_gathering.recon_agent import ReconAgent
from kali_mcp.agents.vulnerability_discovery.web_vuln_agent import WebVulnAgent
from kali_mcp.agents.exploitation.exploit_agent import ExploitAgent
from kali_mcp.agents.llm_agent_base import LLMAgentBase, MissionTicket
from kali_mcp.core.result_aggregator import AgentResult, Finding, ResultSeverity
from kali_mcp.core.task_decomposer import Task, TaskCategory
from kali_mcp.reasoning.knowledge_retriever import KbHit


def _run(coro):
    """同步测试内运行协程（pytest.ini 已开 asyncio_mode=auto，此助手用于非 async 测试）。"""
    return asyncio.run(coro)


def _done_decision(summary="mission complete", findings=None):
    return {
        "thinking": ["done"],
        "action": "done",
        "summary": summary,
        "structured_summary": {
            "findings": findings if findings is not None else [
                {"title": "开放端口: 80/tcp", "severity": "info", "confidence": 0.95,
                 "evidence": ["80/tcp open http"]},
            ],
            "next_hypotheses": ["检查 /admin 是否存在登录页"],
        },
        "plan": [],
    }


class FakeBrain:
    """实现 LLM 决策循环所需的 LLMBrain 接口子集（analyze/repair/refusal/truncate）。"""

    def __init__(self, decisions: List[Dict[str, Any]], available: bool = True):
        self._decisions = list(decisions)
        self.available = available
        self.analyze_calls: List[List[Dict[str, str]]] = []
        self.repair_calls: List[str] = []

    def analyze(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        self.analyze_calls.append(list(messages))
        if not self._decisions:
            return {"thinking": [], "action": "done", "summary": "no more decisions",
                    "structured_summary": {"findings": [], "next_hypotheses": []}, "plan": []}
        return self._decisions.pop(0)

    def is_policy_refusal(self, text: str) -> bool:
        return "i need to decline" in str(text).lower()

    def repair_decision(self, raw_text: str, context_messages=None) -> Dict[str, Any]:
        self.repair_calls.append(raw_text)
        return _done_decision("repaired by repair_decision")

    def truncate_output(self, output: str, max_chars: int = 3000) -> str:
        return output


class FakeRetriever:
    """固定命中的假 KB 检索器，记录 query。"""

    def __init__(self, hits: List[KbHit]):
        self.hits = hits
        self.queries: List[str] = []

    def retrieve(self, query: str, top_k: int = 5, filters: Dict[str, Any] = None) -> List[KbHit]:
        self.queries.append(query)
        return self.hits


def _hit(text: str, chunk_id: int = 1) -> KbHit:
    return KbHit(chunk_id=chunk_id, source="doc/kb.md", section="port_scan",
                 text=text, score=0.9, meta={"category": "runbook"})


def _ticket(**overrides) -> MissionTicket:
    base = dict(
        mission_id="m-test-1",
        session_id="s-test",
        agent_role="recon_agent",
        objective="识别 localhost 的开放端口与服务",
        target="127.0.0.1",
    )
    base.update(overrides)
    return MissionTicket(**base)


# ==================== done → AgentResult ====================

class TestDone:
    def test_done_produces_agent_result(self):
        """done 决策 → llm_drive_mission 返回 AgentResult，structured_summary 合并进 findings。"""
        agent = ReconAgent(brain=FakeBrain([_done_decision()]))
        result = _run(agent.llm_drive_mission(_ticket()))

        assert isinstance(result, AgentResult)
        assert result.success is True
        assert result.agent_id == "recon_agent"
        assert result.task_id == "m-test-1"
        assert result.output == "mission complete"
        assert result.metadata.get("llm_autonomous") is True
        titles = {f.title for f in result.findings}
        assert "开放端口: 80/tcp" in titles
        assert result.parsed_data.get("next_hypotheses") == ["检查 /admin 是否存在登录页"]

    def test_done_merge_structured_and_regex_findings(self):
        """正则提炼的 finding 与 structured_summary 的 finding 合并、按 title 去重。"""
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            _done_decision(findings=[
                {"title": "开放端口: 22/tcp", "severity": "high", "confidence": 0.8,
                 "evidence": ["22/tcp open ssh OpenSSH 9.0"]},
            ]),
        ])

        async def fake_call_tool(tool_name, parameters):
            return "22/tcp open ssh OpenSSH 9.0\n80/tcp open http nginx"

        agent = ReconAgent(brain=brain)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        result = _run(agent.llm_drive_mission(_ticket()))

        titles = {f.title for f in result.findings}
        # 正则提炼（_parse_recon_output）+ structured_summary
        assert "开放端口: 22/tcp" in titles
        assert "开放端口: 80/tcp" in titles
        # 确定性正则提炼优先：22/tcp 先由正则以 INFO 产出，structured_summary 的 high 被去重
        sev = {f.title: f.severity for f in result.findings}
        assert sev["开放端口: 22/tcp"] is ResultSeverity.INFO


# ==================== call_tool 路由到 _call_tool + 消息累积 ====================

class TestCallTool:
    def test_call_tool_routes_to_call_tool(self):
        """call_tool 决策 → 经 self._call_tool 执行，决策与输出回灌消息列表。"""
        calls: List[tuple] = []
        brain = FakeBrain([
            {"thinking": ["scan"], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1", "scan_type": "-sV"}, "reason": "port scan", "plan": []},
            _done_decision(),
        ])

        async def fake_call_tool(tool_name, parameters):
            calls.append((tool_name, parameters))
            return "22/tcp open ssh OpenSSH 9.0"

        agent = ReconAgent(brain=brain)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        result = _run(agent.llm_drive_mission(_ticket()))

        assert calls == [("nmap_scan", {"target": "127.0.0.1", "scan_type": "-sV"})]
        assert result.success is True
        # 消息累积：第 2 次 analyze 时能看到工具输出
        assert len(brain.analyze_calls) == 2
        round2_msgs = {m["role"]: m["content"] for m in brain.analyze_calls[1]}
        assert "Tool output:" in round2_msgs["user"]
        assert "22/tcp open ssh OpenSSH 9.0" in round2_msgs["user"]
        # execution_log 记录工具调用
        log = result.metadata["execution_log"]
        assert log[0]["tool"] == "nmap_scan"
        assert log[0]["action"] == "call_tool"

    def test_initial_message_contains_role_prompt_and_catalog(self):
        """首条消息 = 角色 prompt + 工具目录 + 任务简报（脱敏管线之后）。"""
        brain = FakeBrain([_done_decision()])
        agent = ReconAgent(brain=brain)
        _run(agent.llm_drive_mission(_ticket()))
        first = brain.analyze_calls[0][0]
        assert first["role"] == "user"
        content = first["content"]
        assert "ReconAgent" in content
        assert "nmap_scan" in content           # 工具目录
        assert "识别 localhost 的开放端口与服务" in content
        assert "TARGET_HOST" in content         # 目标在 LLM 侧脱敏为占位符

    def test_target_sanitization(self):
        """真实域名在 LLM 侧脱敏为 TARGET_HOST，desanitize 在参数里还原。"""
        calls: List[tuple] = []
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "TARGET_HOST"}, "reason": "", "plan": []},
            _done_decision(),
        ])

        async def fake_call_tool(tool_name, parameters):
            calls.append((tool_name, parameters))
            return "port scan ok"

        agent = ReconAgent(brain=brain)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        _run(agent.llm_drive_mission(_ticket(target="example.com")))
        assert calls[0][1]["target"] == "example.com"
        # LLM 看到的消息里没有真实域名
        all_text = " ".join(m["content"] for m in brain.analyze_calls[0])
        assert "example.com" not in all_text
        assert "TARGET_HOST" in all_text

    def test_unknown_action_gets_correction_hint(self):
        """未知 action → 纠正提示，循环继续不崩溃。"""
        brain = FakeBrain([
            {"thinking": [], "action": "fly_to_moon", "reason": "", "plan": []},
            _done_decision(),
        ])
        agent = ReconAgent(brain=brain)
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is True
        assert len(brain.analyze_calls) == 2
        assert "Unknown action" in brain.analyze_calls[1][-1]["content"]


# ==================== retry / repair / refusal ====================

class TestRetry:
    def test_retry_repairs_decision(self):
        """retry → repair_decision 修复成功 → 循环按修复后的决策继续。"""
        brain = FakeBrain([
            {"thinking": [], "action": "retry", "raw_text": "not valid json at all",
             "plan": [], "reason": ""},
            _done_decision(),
        ])
        agent = ReconAgent(brain=brain)
        result = _run(agent.llm_drive_mission(_ticket()))
        assert brain.repair_calls == ["not valid json at all"]
        assert result.success is True
        assert result.output == "repaired by repair_decision"

    def test_retry_without_repair_keeps_going(self):
        """repair 失败 → 提示重试，循环继续。"""
        class NoRepairBrain(FakeBrain):
            def repair_decision(self, raw_text, context_messages=None):
                self.repair_calls.append(raw_text)
                return None

        brain = NoRepairBrain([
            {"thinking": [], "action": "retry", "raw_text": "bad json", "plan": [], "reason": ""},
            _done_decision(),
        ])
        agent = ReconAgent(brain=brain)
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is True
        assert len(brain.analyze_calls) == 2

    def test_refusal_three_times_breaks(self):
        """连续 3 次拒答 → 循环中止并产出失败 AgentResult。"""
        brain = FakeBrain([
            {"thinking": [], "action": "retry", "raw_text": "i need to decline this",
             "plan": [], "reason": ""},
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            _done_decision(),
        ])
        brain.is_policy_refusal = lambda text: True   # 所有决策都判定拒答
        agent = ReconAgent(brain=brain)
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is False
        assert "refused" in result.output.lower() or "refused" in " ".join(result.errors).lower()


# ==================== is_tool_failure_output 过滤 ====================

class TestFailureFilter:
    def test_failure_output_not_extracted_as_finding(self):
        """executor 层失败输出（[错误] 前缀）→ 不产出 finding，循环继续。"""
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            _done_decision(findings=[]),   # 空 structured_summary，隔离失败过滤行为
        ])

        async def failing_call_tool(tool_name, parameters):
            return "[错误] nmap_scan: 拒绝执行（不在白名单）"

        agent = ReconAgent(brain=brain)
        agent._call_tool = failing_call_tool  # type: ignore[method-assign]
        result = _run(agent.llm_drive_mission(_ticket()))
        # 失败输出被过滤：不进 _parse_tool_output，不产出 finding
        assert result.findings == []
        # 但消息仍回灌（LLM 需要知道工具失败以调整策略）
        round2 = {m["role"]: m["content"] for m in brain.analyze_calls[1]}
        assert "[错误]" in round2["user"]

    def test_tool_failure_helper_matches(self):
        """is_tool_failure_output 识别 executor 失败标记（复用 BaseAgentV2 判定）。"""
        agent = ReconAgent()
        assert agent.is_tool_failure_output("[错误] nmap: 拒绝执行")
        assert agent.is_tool_failure_output("[异常] fastsec: boom")
        assert agent.is_tool_failure_output("Command timeout after 300 seconds")
        assert not agent.is_tool_failure_output("22/tcp open ssh")


# ==================== 轮次耗尽 / run_tool / KB 注入 ====================

class TestLoopGuards:
    def test_max_rounds_timeout(self):
        """只给 call_tool 决策 → 轮次耗尽 → 失败 AgentResult（不空转死循环）。"""
        agent = ReconAgent(brain=FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
        ]))
        agent.MAX_LLM_ROUNDS = 3
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is False
        assert any("MAX_LLM_ROUNDS" in e for e in result.errors)
        assert result.metadata["rounds"] == 3

    def test_run_tool_goes_through_executor_bridge(self):
        """run_tool 决策 → 经 executor.execute_command 执行（无 executor 时模拟输出）。"""
        brain = FakeBrain([
            {"thinking": [], "action": "run_tool", "command": "curl -s http://127.0.0.1/",
             "reason": "", "plan": []},
            _done_decision(),
        ])
        agent = ReconAgent(brain=brain)   # executor=None → 模拟输出，仍继续循环
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is True
        assert len(brain.analyze_calls) == 2

    def test_kb_injected_every_3_rounds(self):
        """retriever 注入：第 1 轮与第 3 轮各检索一次；query 变化 → 新块追加进历史。"""
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            _done_decision(findings=[]),
        ])

        async def fake_call_tool(tool_name, parameters):
            return f"round output {len(brain.analyze_calls)}"

        class VaryingRetriever(FakeRetriever):
            def retrieve(self, query, top_k=5, filters=None):
                self.queries.append(query)
                return [_hit(f"参考：{query}", chunk_id=len(self.queries))]

        retriever = VaryingRetriever([])
        agent = ReconAgent(brain=brain, retriever=retriever)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is True

        # 检索节奏：第 1 轮 + 第 3 轮（round_no % 3 == 0），共 2 次
        assert len(retriever.queries) == 2
        # 第 1 轮注入第 1 个 KB 块（消息历史里出现 1 次「知识库参考」）
        assert sum(1 for m in brain.analyze_calls[0] if "知识库参考" in m.get("content", "")) == 1
        # 第 3 轮 query 含新输出尾 → 新块追加 → 历史里出现 2 个 KB 块
        assert sum(1 for m in brain.analyze_calls[2] if "知识库参考" in m.get("content", "")) == 2
        # 第 2 / 4 轮不检索、不追加
        assert sum(1 for m in brain.analyze_calls[1] if "知识库参考" in m.get("content", "")) == 1
        assert sum(1 for m in brain.analyze_calls[3] if "知识库参考" in m.get("content", "")) == 2

    def test_kb_identical_block_not_reinjected(self):
        """命中内容不变 → 相同 KB 块不重复注入（控 token 的 step 缓存语义）。"""
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            _done_decision(findings=[]),
        ])

        async def fake_call_tool(tool_name, parameters):
            return f"round output {len(brain.analyze_calls)}"

        retriever = FakeRetriever([_hit("固定命中内容", chunk_id=1)])   # 每次检索结果相同
        agent = ReconAgent(brain=brain, retriever=retriever)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        _run(agent.llm_drive_mission(_ticket()))

        assert len(retriever.queries) == 2       # 仍按节奏检索
        # 但格式化文本不变 → 只注入 1 次，历史中始终只有 1 个 KB 块
        for i in range(4):
            assert sum(1 for m in brain.analyze_calls[i] if "知识库参考" in m.get("content", "")) == 1

    def test_kb_retriever_failure_silently_skipped(self):
        """retriever 抛异常 → KB 块静默跳过，循环继续（降级安全）。"""
        class BoomRetriever(FakeRetriever):
            def retrieve(self, query, top_k=5, filters=None):
                raise RuntimeError("kb db corrupt")

        brain = FakeBrain([_done_decision()])
        agent = ReconAgent(brain=brain, retriever=BoomRetriever([]))
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is True
        assert not any("知识库参考" in m.get("content", "") for m in brain.analyze_calls[0])


# ==================== 降级路由（brain 不可用 → legacy） ====================

class TestDegradationRouting:
    def test_brain_unavailable_uses_legacy(self):
        """无 brain（无 API key）→ _execute_task_impl 走 legacy 规则路径，产出工具输出字符串。"""
        agent = ReconAgent()   # brain.available=False
        assert agent.brain.available is False
        output = _run(agent._execute_task_impl(
            "nmap_scan", {"target": "127.0.0.1"}, "t-legacy-1"))
        # legacy 路径 → _execute_nmap_scan_impl → _call_tool（executor=None → 模拟输出）
        assert isinstance(output, str)
        assert "模拟输出" in output
        assert "nmap_scan" in output

    def test_llm_flag_ignored_without_brain(self):
        """即使 task_data 开了 llm_autonomous，brain 不可用仍走 legacy（不空转）。"""
        agent = ReconAgent()
        output = _run(agent._execute_task_impl(
            "nmap_scan", {"target": "127.0.0.1", "llm_autonomous": True}, "t-legacy-2"))
        assert isinstance(output, str)
        assert "模拟输出" in output

    def test_llm_routing_with_available_brain(self):
        """brain 可用 + llm_autonomous → 路由到 llm_drive_mission 产出 AgentResult。"""
        agent = ReconAgent(brain=FakeBrain([_done_decision("llm path")]))
        result = _run(agent._execute_task_impl(
            "nmap_scan", {"target": "127.0.0.1", "llm_autonomous": True}, "t-llm-1"))
        assert isinstance(result, AgentResult)
        assert result.output == "llm path"

    def test_legacy_without_flag_with_available_brain(self):
        """brain 可用但未开 llm_autonomous → 仍走 legacy。"""
        agent = ReconAgent(brain=FakeBrain([]))
        output = _run(agent._execute_task_impl(
            "nmap_scan", {"target": "127.0.0.1"}, "t-legacy-3"))
        assert isinstance(output, str)

    def test_execute_task_with_task_obj_llm_path_passthrough(self):
        """Task 对象 + llm_autonomous + brain 可用 → execute_task_with_task_obj 直接透传 AgentResult。"""
        agent = ReconAgent(brain=FakeBrain([_done_decision("task obj llm")]))
        task = Task(
            task_id="t-obj-1",
            name="端口识别",
            category=TaskCategory.RECONNAISSANCE,
            tool_name="nmap_scan",
            parameters={"target": "127.0.0.1", "llm_autonomous": True},
        )
        result = _run(agent.execute_task_with_task_obj(task))
        assert isinstance(result, AgentResult)
        assert result.success is True
        assert result.output == "task obj llm"

    def test_legacy_path_without_llm_flag_through_task_obj(self):
        """无 llm_autonomous → Task 对象路径走 legacy 并产出正则 findings（验收标准 3）。"""
        agent = ReconAgent()   # 无 brain
        task = Task(
            task_id="t-obj-2",
            name="端口识别",
            category=TaskCategory.RECONNAISSANCE,
            tool_name="nmap_scan",
            parameters={"target": "127.0.0.1"},
        )
        result = _run(agent.execute_task_with_task_obj(task))
        assert isinstance(result, AgentResult)
        # executor=None → 模拟输出，非失败标记 → legacy 解析路径成功
        assert result.success is True


# ==================== MissionTicket / DAG 可选接入 ====================

class TestMissionTicketAndDag:
    def test_from_task_compat(self):
        """from_task 兼容构造：缺省字段全部兜底。"""
        ticket = MissionTicket.from_task({"target": "http://example.com:8080/admin"})
        assert ticket.target == "http://example.com:8080/admin"
        assert ticket.mission_id.startswith("mission_")
        assert ticket.priority == 5
        assert ticket.constraints == []
        assert ticket.objective  # 兜底目标陈述非空

    def test_from_task_full_fields(self):
        ticket = MissionTicket.from_task({
            "mission_id": "m-x", "session_id": "s-x", "agent_role": "recon_agent",
            "objective": "obj", "target": "t", "constraints": ["只读"],
            "priority": 9, "context_refs": ["dag.node.n1"],
        })
        assert ticket.mission_id == "m-x"
        assert ticket.constraints == ["只读"]
        assert ticket.priority == 9
        assert ticket.context_refs == ["dag.node.n1"]

    def test_dag_service_records_attack_action(self):
        """dag_service 可用 → 每次 call_tool 记录 attack_action 节点（失败静默跳过）。"""
        from kali_mcp.reasoning.attack_dag import DAGService

        dag = DAGService(db_path=":memory:", session_id="s-test")
        calls: List[tuple] = []
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "nmap_scan",
             "params": {"target": "127.0.0.1"}, "reason": "", "plan": []},
            _done_decision(),
        ])

        async def fake_call_tool(tool_name, parameters):
            calls.append((tool_name, parameters))
            return "22/tcp open ssh"

        agent = ReconAgent(brain=brain, dag_service=dag)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        result = _run(agent.llm_drive_mission(_ticket(session_id="s-test")))
        assert result.success is True
        nodes = dag.get_subgraph("n1", depth=3, session_id="s-test")
        assert dag.node_count(session_id="s-test") == 1
        assert nodes["nodes"][0]["node_type"] == "attack_action"

    def test_dag_none_skipped(self):
        """dag_service=None → DAG 注入与记录块静默跳过，循环正常。"""
        brain = FakeBrain([_done_decision()])
        agent = ReconAgent(brain=brain, dag_service=None)
        result = _run(agent.llm_drive_mission(_ticket()))
        assert result.success is True


# ==================== 三个试点 agent 均可用 ====================

class TestPilotAgents:
    def test_all_three_inherit_llm_agent_base(self):
        assert issubclass(ReconAgent, LLMAgentBase)
        assert issubclass(WebVulnAgent, LLMAgentBase)
        assert issubclass(ExploitAgent, LLMAgentBase)

    def test_all_three_instantiate_without_brain(self):
        """验收标准 2/3：不传 brain（无 API key）构造不报错，可实例化。"""
        for cls in (ReconAgent, WebVulnAgent, ExploitAgent):
            agent = cls()
            assert agent.brain.available is False
            assert cls.ROLE_PROMPT.strip() != ""

    def test_web_vuln_agent_llm_mission(self):
        """WebVulnAgent 走 LLM 路径：call_tool → 正则提炼 SQLi finding。"""
        calls: List[tuple] = []
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "fastsec_scan",
             "params": {"url": "http://127.0.0.1/", "inject": "id"}, "reason": "", "plan": []},
            _done_decision(),
        ])

        async def fake_call_tool(tool_name, parameters):
            calls.append((tool_name, parameters))
            return ("[injector] sqlmap found injectable parameter: id\n"
                    "Parameter: id (GET)\nType: boolean-based blind")

        agent = WebVulnAgent(brain=brain)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        result = _run(agent.llm_drive_mission(MissionTicket(
            mission_id="m-web-1", session_id="s", agent_role="web_vuln_agent",
            objective="检测 SQL 注入", target="http://127.0.0.1/")))
        assert calls[0][0] == "fastsec_scan"
        assert result.success is True

    def test_exploit_agent_llm_mission(self):
        """ExploitAgent 走 LLM 路径：call_tool → fastsec 模板扫描 finding。"""
        brain = FakeBrain([
            {"thinking": [], "action": "call_tool", "tool_name": "fastsec_scan",
             "params": {"url": "http://127.0.0.1/", "templates": "http-core/"}, "reason": "", "plan": []},
            _done_decision(),
        ])

        async def fake_call_tool(tool_name, parameters):
            return "[+] 找到可利用漏洞: nginx version disclosure (http-core)"

        agent = ExploitAgent(brain=brain)
        agent._call_tool = fake_call_tool  # type: ignore[method-assign]
        result = _run(agent.llm_drive_mission(MissionTicket(
            mission_id="m-exp-1", session_id="s", agent_role="exploit_agent",
            objective="搜索可利用漏洞模板", target="http://127.0.0.1/")))
        assert result.success is True
        assert result.metadata["execution_log"][0]["tool"] == "fastsec_scan"

    def test_agent_without_brain_legacy_does_not_raise(self):
        """验收标准 3：无 brain 时三个 agent 的最小 legacy 任务都不报错。"""
        for agent, tool in ((ReconAgent(), "nmap_scan"),
                            (WebVulnAgent(), "fastsec_scan"),
                            (ExploitAgent(), "fastsec_scan")):
            output = _run(agent._execute_task_impl(tool, {"target": "127.0.0.1"}, "t-min"))
            assert isinstance(output, str)
