# -*- coding: utf-8 -*-
"""SummarizerAgent 单测（ARCH_DESIGN §6，P3 阶段，验收标准 1/2/3）。

覆盖：
- fingerprint 去重（同指纹合并 / 异指纹区分）
- confidence 合并（同 fingerprint 保留最高者 + 证据合并）
- 硬过滤（is_tool_failure_output 标记 / executor 拒绝标记）
- 置信度阈值降级（< 0.6 → low_confidence）
- 排序（severity 序 → CVSS 降序 → confidence 降序 → 时间升序）
- 2s 节流（同 session 窗口内多次触发只推一次；flag.found 强制高优推送）
- LLM 三分类（mock brain：confirmed / suspicious / false_positive；降级安全）
- 事件驱动汇总（mission / tool.result / vuln.verified / dag.updated / flag.found）

全部离线：不触网、不加载真实 LLM。
"""
import json
from typing import Any, Dict, List

import pytest

from kali_mcp.core.event_bus import Event, EventBus
from kali_mcp.core.event_stream import EventManager
from kali_mcp.core.result_aggregator import Finding, ResultSeverity, ResultType
from kali_mcp.core.summarizer_agent import (
    CONFIDENCE_THRESHOLD,
    SummarizerAgent,
    SummarySnapshot,
    apply_confidence_threshold,
    deduplicate_findings,
    fingerprint_of,
    hard_filter_findings,
    normalize_findings,
    sort_findings,
)


def mk(
    title: str = "SQL injection",
    severity: ResultSeverity = ResultSeverity.HIGH,
    confidence: float = 0.8,
    evidence: List[str] = None,
    cvss: float = None,
    target: str = "10.0.0.1",
    ftype: ResultType = ResultType.VULNERABILITY,
    seq: int = None,
) -> Finding:
    f = Finding(
        finding_type=ftype,
        severity=severity,
        title=title,
        description=f"desc {title}",
        evidence=evidence or [f"evidence-{title}"],
        source="test",
        confidence=confidence,
        cvss_score=cvss,
    )
    f._target = target
    if seq is not None:
        f._ingest_seq = seq
    return f


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class FakeBrain:
    """实现 _invoke_text / _parse_json_payload 接口子集（LLM 三分类 mock）。"""

    def __init__(self, payload: Dict[str, Any] = None, available: bool = True, raises: bool = False):
        self.payload = payload if payload is not None else {"results": []}
        self.available = available
        self.raises = raises

    def _invoke_text(self, prompt, messages, **kwargs):
        if self.raises:
            raise RuntimeError("llm down")
        return json.dumps(self.payload, ensure_ascii=False)

    @staticmethod
    def _parse_json_payload(text: str) -> Dict[str, Any]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}


def _summary_count(bus: EventBus) -> int:
    return bus.get_stats().get("by_type", {}).get("summary.update", {}).get("emitted", 0)


def _make_agent(bus=None, em=None, brain=None, throttle=2.0, clock=None, **kw) -> SummarizerAgent:
    return SummarizerAgent(
        bus=bus or EventBus(),
        event_manager=em if em is not None else EventManager(),
        brain=brain,
        throttle_seconds=throttle,
        now=clock,
        **kw,
    )


# ==================== fingerprint 去重 ====================

class TestFingerprint:
    def test_same_fingerprint(self):
        a = mk(title="SQLi", evidence=["POST /admin?id=1 error"])
        b = mk(title="SQLi", evidence=["POST /admin?id=1 error"])
        assert fingerprint_of(a) == fingerprint_of(b)

    def test_different_evidence_differs(self):
        a = mk(title="SQLi", evidence=["POST /admin?id=1 error"])
        b = mk(title="SQLi", evidence=["POST /admin?id=2 error"])
        assert fingerprint_of(a) != fingerprint_of(b)

    def test_different_target_differs(self):
        a = mk(title="SQLi", target="10.0.0.1")
        b = mk(title="SQLi", target="10.0.0.2")
        assert fingerprint_of(a) != fingerprint_of(b)

    def test_different_type_differs(self):
        a = mk(title="port", ftype=ResultType.ASSET, evidence=["80/tcp open"])
        b = mk(title="port", ftype=ResultType.VULNERABILITY, evidence=["80/tcp open"])
        assert fingerprint_of(a) != fingerprint_of(b)

    def test_missing_evidence_stable(self):
        a = mk(title="t", evidence=[])
        b = mk(title="t", evidence=[])
        assert fingerprint_of(a) == fingerprint_of(b)


# ==================== confidence 合并 / 批内去重 ====================

class TestDeduplicate:
    def test_keeps_highest_confidence_and_merges_evidence(self):
        # 同 fingerprint（首条 evidence 相同），后续 evidence 合并
        f1 = mk(title="SQLi", confidence=0.4, evidence=["ev-a"], seq=0)
        f2 = mk(title="SQLi", confidence=0.9, evidence=["ev-a", "ev-b"], seq=1)
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].confidence == 0.9
        assert result[0].evidence == ["ev-a", "ev-b"]  # 证据合并、保序

    def test_reversed_input_order(self):
        f1 = mk(title="SQLi", confidence=0.4, evidence=["ev-a"])
        f2 = mk(title="SQLi", confidence=0.9, evidence=["ev-a", "ev-b"])
        result = deduplicate_findings([f2, f1])
        assert len(result) == 1
        assert result[0].confidence == 0.9
        assert set(result[0].evidence) == {"ev-a", "ev-b"}

    def test_evidence_deduped_within_merge(self):
        f1 = mk(title="SQLi", confidence=0.5, evidence=["ev-a"])
        f2 = mk(title="SQLi", confidence=0.9, evidence=["ev-a", "ev-b"])
        result = deduplicate_findings([f1, f2])
        assert result[0].evidence == ["ev-a", "ev-b"]

    def test_distinct_fingerprints_all_kept(self):
        a = mk(title="SQLi", evidence=["a"])
        b = mk(title="XSS", evidence=["b"])
        assert len(deduplicate_findings([a, b])) == 2


# ==================== 硬过滤 ====================

class TestHardFilter:
    def test_drops_failure_prefix_output(self):
        f = mk(title="SQLi", evidence=["[错误] 工具不在白名单"])
        assert hard_filter_findings([f]) == []

    def test_drops_failure_keyword_output(self):
        f = mk(title="SQLi", evidence=["executor: 拒绝执行"])
        assert hard_filter_findings([f]) == []

    def test_drops_timed_out_output(self):
        f = mk(title="SQLi", evidence=["Command timeout after 30s"])
        assert hard_filter_findings([f]) == []

    def test_drops_executor_rejected_marker(self):
        f = mk(title="SQLi")
        f._executor_rejected = True
        assert hard_filter_findings([f]) == []

    def test_keeps_clean_finding(self):
        f = mk(title="SQLi", evidence=["POST /admin?id=1 error"])
        assert hard_filter_findings([f]) == [f]

    def test_failure_in_description_also_dropped(self):
        f = mk(title="SQLi", evidence=["snippet"])
        f.description = "执行失败: 目标不可达"
        assert hard_filter_findings([f]) == []


# ==================== 置信度阈值降级 ====================

class TestConfidenceThreshold:
    def test_below_threshold_marked(self):
        f = mk(confidence=0.5)
        apply_confidence_threshold([f])
        assert getattr(f, "low_confidence", False) is True

    def test_at_threshold_not_marked(self):
        f = mk(confidence=CONFIDENCE_THRESHOLD)
        apply_confidence_threshold([f])
        assert getattr(f, "low_confidence", False) is False

    def test_high_confidence_not_marked(self):
        f = mk(confidence=0.95)
        apply_confidence_threshold([f])
        assert getattr(f, "low_confidence", False) is False


# ==================== 排序 ====================

class TestSort:
    def test_severity_then_cvss_then_confidence_then_time(self):
        findings = [
            mk("low-conf-high", ResultSeverity.HIGH, 0.5, cvss=7.5, seq=3),
            mk("high-cvss", ResultSeverity.HIGH, 0.9, cvss=9.8, seq=1),
            mk("critical", ResultSeverity.CRITICAL, 0.7, cvss=9.0, seq=2),
            mk("low-sev", ResultSeverity.LOW, 0.9, cvss=None, seq=0),
            mk("no-cvss", ResultSeverity.HIGH, 0.8, cvss=None, seq=4),
            mk("earlier", ResultSeverity.HIGH, 0.9, cvss=7.5, seq=0),
            mk("later", ResultSeverity.HIGH, 0.9, cvss=7.5, seq=2),
        ]
        ordered = sort_findings(findings)
        titles = [f.title for f in ordered]
        assert titles == [
            "critical",          # CRITICAL 最前
            "high-cvss",         # HIGH, CVSS 9.8
            "earlier",           # HIGH, CVSS 7.5, conf 0.9, seq 0（时间升序）
            "later",             # HIGH, CVSS 7.5, conf 0.9, seq 2
            "low-conf-high",     # HIGH, CVSS 7.5, conf 0.5
            "no-cvss",           # HIGH, 无 CVSS（视为 0）排最后
            "low-sev",           # LOW
        ]


# ==================== 全流水线 + SummarySnapshot（验收标准 2） ====================

class TestPipelineAndSnapshot:
    def test_ingest_dedup_filter_sort_produce_snapshot(self):
        bus = EventBus()
        agent = _make_agent(bus=bus)
        agent.subscribe()

        f1 = mk("SQLi /admin", ResultSeverity.HIGH, 0.8, evidence=["POST /admin?id=1 error"])
        dup = mk("SQLi /admin", ResultSeverity.HIGH, 0.95, evidence=["POST /admin?id=1 error"])
        fail = mk("失败输出", ResultSeverity.HIGH, 0.9, evidence=["[错误] 工具不在白名单"])
        low = mk("低置信线索", ResultSeverity.MEDIUM, 0.4, evidence=["maybe"])
        info = mk("开放端口", ResultSeverity.INFO, 0.9, evidence=["80/tcp open"],
                  ftype=ResultType.ASSET)

        agent.ingest_findings("s1", [f1, dup, fail, low, info], source="test")

        snap: SummarySnapshot = agent.build_snapshot("s1")
        assert snap.session_id == "s1"
        assert snap.updated_at
        d = snap.to_dict()
        assert set(d.keys()) == {"session_id", "updated_at", "findings", "stats", "flags",
                                 "next_best_path"}
        assert set(d["stats"].keys()) == {"agents_active", "nodes_total", "paths_pheromone_top3"}
        assert d["flags"] == []
        assert d["next_best_path"] == []

        # 失败输出被硬过滤；SQLi 去重合并（保留 conf 0.95）；低置信降级保留
        assert len(d["findings"]) == 3
        sqli = next(f for f in d["findings"] if f["title"] == "SQLi /admin")
        assert sqli["confidence"] == 0.95
        assert sqli["fingerprint"] == fingerprint_of(f1)
        low_entry = next(f for f in d["findings"] if f["title"] == "低置信线索")
        assert low_entry["low_confidence"] is True
        # 排序：HIGH(SQLi) > MEDIUM(低置信) > INFO(端口)
        assert [f["severity"] for f in d["findings"]] == ["high", "medium", "info"]

    def test_normalize_agent_result_and_dict(self):
        from kali_mcp.core.result_aggregator import AgentResult
        from datetime import datetime

        ar = AgentResult(
            agent_id="recon_agent", task_id="m1", tool_name="nmap_scan",
            target="10.0.0.9", success=True, execution_time=1.0,
            timestamp=datetime.now(),
            findings=[mk("SQLi", evidence=["x"], target="10.0.0.9")],
        )
        fdict = {"type": "vulnerability", "severity": "critical", "title": "RCE",
                 "evidence": ["RCE at /exec"], "confidence": 0.9, "target": "10.0.0.9"}
        normalized = normalize_findings([ar, fdict, {"bogus": 1}])
        assert len(normalized) == 2
        assert all(f._target == "10.0.0.9" for f in normalized)

    def test_mission_completed_event_ingests_result(self):
        from kali_mcp.core.result_aggregator import AgentResult
        from datetime import datetime

        bus = EventBus()
        agent = _make_agent(bus=bus)
        agent.subscribe()
        ar = AgentResult(
            agent_id="web_vuln_agent", task_id="m2", tool_name="fastsec_scan",
            target="10.0.0.5", success=True, execution_time=1.0,
            timestamp=datetime.now(),
            findings=[mk("XSS", ResultSeverity.MEDIUM, 0.85, evidence=["xss at /q"])],
        )
        agent.on_mission_completed(Event("mission.completed", {
            "session_id": "s-m1", "target": "10.0.0.5", "result": ar,
        }))
        snap = agent.build_snapshot("s-m1")
        assert len(snap.findings) == 1
        assert snap.findings[0].title == "XSS"


# ==================== 2s 节流（验收标准 3） ====================

class TestThrottle:
    def test_same_session_throttled_to_one_push_per_2s(self):
        clock = FakeClock()
        bus = EventBus()
        agent = _make_agent(bus=bus, clock=clock, throttle=2.0)
        agent.subscribe()

        assert agent.ingest_findings("s1", [mk("a")], source="t") == 1
        assert _summary_count(bus) == 1            # t=1000: 首推

        agent.ingest_findings("s1", [mk("b")], source="t")
        assert _summary_count(bus) == 1            # 窗口内合并，不重复推

        clock.advance(1.0)
        agent.ingest_findings("s1", [mk("c")], source="t")
        assert _summary_count(bus) == 1            # 1001-1000=1s < 2s，仍节流

        clock.advance(1.5)
        agent.ingest_findings("s1", [mk("d")], source="t")
        assert _summary_count(bus) == 2            # 1002.5-1000=2.5s ≥ 2s，推

        # delta 已合并：4 条全部在快照里
        snap = agent.build_snapshot("s1")
        assert len(snap.findings) == 4

    def test_flush_forces_pending_push(self):
        clock = FakeClock()
        bus = EventBus()
        agent = _make_agent(bus=bus, clock=clock, throttle=2.0)
        agent.subscribe()
        agent.ingest_findings("s1", [mk("a")], source="t")
        agent.ingest_findings("s1", [mk("b")], source="t")   # 节流中
        assert _summary_count(bus) == 1
        assert agent.flush("s1") == 1                        # 强制冲刷 pending delta
        assert _summary_count(bus) == 2
        assert len(agent.build_snapshot("s1").findings) == 2

    def test_flag_found_forces_immediate_push(self):
        clock = FakeClock()
        bus = EventBus()
        em = EventManager()
        agent = _make_agent(bus=bus, em=em, clock=clock, throttle=2.0)
        agent.subscribe()
        agent.ingest_findings("s1", [mk("a")], source="t")   # push 1
        agent.ingest_findings("s1", [mk("b")], source="t")   # throttled
        agent.on_flag_found(Event("flag.found", {"session_id": "s1", "flag": "flag{abc123}"}))
        assert _summary_count(bus) == 2                      # 立即高优推送（绕过节流）
        snap = agent.build_snapshot("s1")
        assert snap.flags == ["flag{abc123}"]
        # SSE 已推送 flag 事件
        types = [e["event_type"] for e in em.get_events("s1")]
        assert "flag_found" in types
        assert "info" in types

    def test_throttle_is_per_session(self):
        clock = FakeClock()
        bus = EventBus()
        agent = _make_agent(bus=bus, clock=clock, throttle=2.0)
        agent.subscribe()
        agent.ingest_findings("s1", [mk("a")], source="t")
        agent.ingest_findings("s2", [mk("b")], source="t")   # 不同 session 互不节流
        assert _summary_count(bus) == 2


# ==================== LLM 三分类（mock brain） ====================

class TestLLMClassify:
    def test_three_class_labels_applied(self):
        payload = {"results": [
            {"index": 0, "label": "false_positive"},
            {"index": 1, "label": "confirmed"},
            {"index": 2, "label": "suspicious"},
        ]}
        agent = _make_agent(brain=FakeBrain(payload=payload))
        agent.ingest_findings("s1", [
            mk("FP 线索", evidence=["fp evidence"]),
            mk("确认漏洞", evidence=["confirmed evidence"]),
            mk("存疑线索", evidence=["sus evidence"]),
        ], source="t")
        snap = agent.build_snapshot("s1")
        assert len(snap.findings) == 2                       # FP 被丢弃
        labels = {f.title: getattr(f, "_llm_label", None) for f in snap.findings}
        assert labels["确认漏洞"] == "confirmed"
        assert labels["存疑线索"] == "suspicious"
        assert agent.get_stats()["total_discarded"] == 1

    def test_brain_unavailable_skips_classification(self):
        agent = _make_agent(brain=FakeBrain(payload={"results": [
            {"index": 0, "label": "false_positive"},
        ]}, available=False))
        agent.ingest_findings("s1", [mk("A", evidence=["e1"])], source="t")
        snap = agent.build_snapshot("s1")
        assert len(snap.findings) == 1                       # 降级安全：全保留
        assert getattr(snap.findings[0], "_llm_label", None) is None

    def test_brain_exception_degrades_safely(self):
        agent = _make_agent(brain=FakeBrain(raises=True))
        agent.ingest_findings("s1", [mk("A", evidence=["e1"]), mk("B", evidence=["e2"])], source="t")
        snap = agent.build_snapshot("s1")
        assert len(snap.findings) == 2                       # 异常 → 跳过，不丢 finding

    def test_batch_split_at_20(self):
        payload = {"results": [
            {"index": i, "label": "confirmed"} for i in range(2)
        ]}
        brain = FakeBrain(payload=payload)
        agent = _make_agent(brain=brain)
        items = [mk(f"f{i}", evidence=[f"e{i}"]) for i in range(25)]
        agent.ingest_findings("s1", items, source="t")
        # 25 条 → 2 批（20 + 5）；payload 的 index 0/1 命中每批前两条
        # （第一批 f0/f1，第二批 f20/f21）
        snap = agent.build_snapshot("s1")
        assert len(snap.findings) == 25                      # 无 false_positive，全保留
        labeled = [f for f in snap.findings if getattr(f, "_llm_label", None) == "confirmed"]
        assert len(labeled) == 4
        assert sorted(f.title for f in labeled) == ["f0", "f1", "f20", "f21"]

    def test_injected_classifier_callable(self):
        from kali_mcp.core.summarizer_agent import fingerprint_of

        def classifier(batch: List[Finding]) -> Dict[str, str]:
            return {fingerprint_of(batch[0]): "false_positive"}

        agent = _make_agent(classifier=classifier)
        agent.ingest_findings("s1", [mk("A", evidence=["e1"]), mk("B", evidence=["e2"])], source="t")
        snap = agent.build_snapshot("s1")
        assert [f.title for f in snap.findings] == ["B"]


# ==================== 其余事件（vuln.verified / dag.updated / tool.result） ====================

class TestEvents:
    def test_vuln_verified_marks_and_boosts(self):
        bus = EventBus()
        agent = _make_agent(bus=bus)
        agent.subscribe()
        agent.on_vuln_verified(Event("vuln.verified", {
            "session_id": "s2", "target": "10.0.0.2",
            "finding": {"type": "vulnerability", "severity": "critical",
                        "title": "RCE verified", "evidence": ["RCE at /exec"],
                        "confidence": 0.7},
        }))
        snap = agent.build_snapshot("s2")
        assert len(snap.findings) == 1
        f = snap.findings[0]
        assert f._verified is True
        assert f.confidence >= 0.85
        assert f.severity == ResultSeverity.CRITICAL

    def test_dag_updated_updates_stats_and_next_path(self):
        clock = FakeClock()
        bus = EventBus()
        agent = _make_agent(bus=bus, clock=clock, throttle=2.0)
        agent.subscribe()
        agent.ingest_findings("s3", [mk("x")], source="t")   # push 1
        clock.advance(3.0)
        agent.on_dag_updated(Event("dag.updated", {
            "session_id": "s3",
            "stats": {"agents_active": 3, "nodes_total": 42,
                      "paths_pheromone_top3": [{"edge": "e1", "pheromone": 0.8}]},
            "next_best_path": ["n1->n2", "n2->n3"],
        }))
        assert _summary_count(bus) == 2
        snap = agent.build_snapshot("s3")
        assert snap.stats["agents_active"] == 3
        assert snap.stats["nodes_total"] == 42
        assert snap.stats["paths_pheromone_top3"] == [{"edge": "e1", "pheromone": 0.8}]
        assert snap.next_best_path == ["n1->n2", "n2->n3"]

    def test_tool_result_critical_keyword_lead(self):
        bus = EventBus()
        agent = _make_agent(bus=bus)
        agent.subscribe()
        agent.on_tool_result(Event("tool.result", {
            "session_id": "s4", "target": "10.0.0.4", "tool_name": "fastsec_scan",
            "output": "critical: SQL injection found at /admin?id=1",
        }))
        snap = agent.build_snapshot("s4")
        assert len(snap.findings) == 1
        assert snap.findings[0].severity == ResultSeverity.CRITICAL
        assert snap.findings[0].source == "tool.result:fastsec_scan"
        # 无关键词的输出不产线索
        agent.on_tool_result(Event("tool.result", {
            "session_id": "s4", "tool_name": "nmap_scan",
            "output": "all clean, no issues detected",
        }))
        assert len(agent.build_snapshot("s4").findings) == 1

    def test_handlers_swallow_garbage(self):
        bus = EventBus()
        agent = _make_agent(bus=bus)
        agent.subscribe()
        agent.on_mission_completed(Event("mission.completed", {"bogus": object()}))
        agent.on_tool_result(Event("tool.result", None))
        agent.on_flag_found(Event("flag.found", {}))
        agent.on_dag_updated(Event("dag.updated", {"session_id": "s5", "stats": "not-a-dict"}))
        agent.on_vuln_verified(Event("vuln.verified", {"session_id": "s5", "finding": {}}))
        agent.on_mission_failed(Event("mission.failed", {"session_id": "s5"}))
        assert agent.build_snapshot("s5").session_id == "s5"
        # 总线本身未崩
        assert bus.get_stats()["total_errors"] == 0
