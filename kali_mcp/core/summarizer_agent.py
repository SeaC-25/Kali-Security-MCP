#!/usr/bin/env python3
"""
SummarizerAgent — 总结智能体（架构设计 §6，P3 阶段）

汇总各子 agent 的发现：去重、去误报、严重性排序，并实时推送。

- §6.1 订阅 EventBus 事件：mission.completed / mission.failed / tool.result
  （critical/high 关键词命中过滤）/ vuln.verified / dag.updated / flag.found；
- §6.2 汇总流水线（纯函数，可单测）：
  规范化 → 去重（sha1 fingerprint = target|type|title|首条evidence，
  同 fingerprint 保留 confidence 最高者并合并 evidence）→ 去误报三层
  （硬过滤 is_tool_failure_output / executor 拒绝标记 → confidence<0.6
  阈值降级 low_confidence → LLM 三分类 {confirmed, suspicious, false_positive}，
  批量 ≤20 条/次，LLM 不可用静默跳过）→ 排序（severity 序 →
  CVSS 降序 → confidence 降序 → 时间升序）→ 产出 SummarySnapshot；
- §6.3 实时推送：每条 summary.update 写 EventBus，并经
  EventManager.create_emitter(session_id) 发 SSE；同一 session 每 2s
  最多推送一条汇总（窗口内合并 delta，flag.found 强制立即高优推送）。

降级安全：LLM 不可用 / 异常时三分类静默跳过；所有订阅 handler 捕获
异常，不让事件总线因单个 handler 崩溃而中断。
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from kali_mcp.core.event_bus import Event, EventBus
from kali_mcp.core.event_stream import EventData, EventManager, EventType, get_event_manager
from kali_mcp.core.result_aggregator import (
    AgentResult,
    Finding,
    ResultAggregator,
    ResultSeverity,
    ResultType,
)

logger = logging.getLogger(__name__)

# 订阅者名（EventBus 注册与反注册共用）
SUBSCRIBER_NAME = "SummarizerAgent"

# severity 排序序（CRITICAL 最前）
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# tool.result 即时线索过滤：命中这些关键词才纳入汇总（§6.1）
_TOOL_RESULT_KEYWORDS = (
    "critical", "high", "严重", "高危", "漏洞", "vulnerab",
    "sql injection", "xss", "rce", "lfi", "ssrf", "cve-",
    "exploit", "未授权", "弱口令", "认证绕过",
)

# confidence 阈值：低于该值标记 low_confidence（降级展示，不丢弃）
CONFIDENCE_THRESHOLD = 0.6

# LLM 三分类批量上限（§6.2：≤20 条/次）
LLM_BATCH_SIZE = 20

_LLM_LABELS = ("confirmed", "suspicious", "false_positive")


# ==================== 纯函数流水线（§6.2，可单测） ====================

def _coerce_severity(value: Any) -> ResultSeverity:
    if isinstance(value, ResultSeverity):
        return value
    if isinstance(value, str):
        try:
            return ResultSeverity(value.strip().lower())
        except ValueError:
            pass
    return ResultSeverity.INFO


def _coerce_type(value: Any) -> ResultType:
    if isinstance(value, ResultType):
        return value
    if isinstance(value, str):
        try:
            return ResultType(value.strip().lower())
        except ValueError:
            pass
    return ResultType.INFO


def _coerce_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_finding(item: Any, target: str = "") -> Optional[Finding]:
    """规范化单个输入 → Finding（复用 result_aggregator.Finding）。

    支持：Finding / Finding 形状的 dict。AgentResult 由 normalize_findings
    展开处理。不可规范化的输入返回 None。
    """
    if item is None:
        return None
    if isinstance(item, Finding):
        f = item
        if target:
            f._target = str(target)
        elif not hasattr(f, "_target"):
            f._target = ""
        return f
    if isinstance(item, AgentResult):
        # 单个 AgentResult 可含多个 finding，走 normalize_findings 展开
        return None
    if isinstance(item, dict):
        try:
            title = item.get("title")
            if title is None:
                return None
            evidence = item.get("evidence") or []
            if isinstance(evidence, str):
                evidence = [evidence]
            f = Finding(
                finding_type=_coerce_type(item.get("type") or item.get("finding_type") or "info"),
                severity=_coerce_severity(item.get("severity") or "info"),
                title=str(title),
                description=str(item.get("description") or item.get("desc") or ""),
                evidence=[str(e) for e in evidence],
                source=str(item.get("source") or ""),
                confidence=float(item.get("confidence") or 0.5),
                cve_id=item.get("cve_id") or item.get("cve"),
                cvss_score=_coerce_float(item.get("cvss_score") or item.get("cvss")),
                poc_available=bool(item.get("poc_available") or item.get("poc")),
                flag_content=item.get("flag_content") or item.get("flag"),
            )
            f._target = str(item.get("target") or target or "")
            if item.get("verified") or item.get("is_verified"):
                f._verified = True
            if item.get("rejected") or item.get("executor_rejected") or item.get("is_failure"):
                f._executor_rejected = True
            return f
        except (TypeError, ValueError):
            return None
    return None


def normalize_findings(items: Any, default_target: str = "") -> List[Finding]:
    """规范化一批输入 → Finding 列表（AgentResult / dict 序列化自动展开）。"""
    if items is None:
        return []
    if isinstance(items, (Finding, dict)):
        items = [items]
    out: List[Finding] = []
    for item in items:
        if isinstance(item, AgentResult):
            if not item.success:
                continue  # 失败结果不产 finding（与 ResultAggregator 一致）
            findings = list(item.findings)
            if not findings and item.parsed_data:
                findings = item.parsed_data.get("findings") or []
            for f in findings:
                nf = normalize_finding(f, target=item.target or default_target)
                if nf is not None:
                    out.append(nf)
        elif isinstance(item, dict) and item.get("findings") and (
            "agent_id" in item or "tool_name" in item or "success" in item
        ):
            # AgentResult 的 dict 序列化
            if item.get("success") is False:
                continue
            for f in item.get("findings", []):
                nf = normalize_finding(f, target=item.get("target") or default_target)
                if nf is not None:
                    out.append(nf)
        else:
            nf = normalize_finding(item, target=default_target)
            if nf is not None:
                out.append(nf)
    return out


def fingerprint_of(finding: Finding) -> str:
    """§6.2 去重指纹：sha1(f"{target}|{finding_type}|{title}|{首条evidence}")。"""
    ftype = finding.finding_type
    if isinstance(ftype, ResultType):
        ftype = ftype.value
    evidence = finding.evidence[0] if finding.evidence else ""
    raw = "{target}|{ftype}|{title}|{evidence}".format(
        target=getattr(finding, "_target", "") or "",
        ftype=ftype,
        title=finding.title or "",
        evidence=evidence,
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _merge_evidence(a: List[str], b: List[str]) -> List[str]:
    """合并证据列表：保序去重。"""
    seen = set()
    out: List[str] = []
    for e in list(a) + list(b):
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """§6.2 去重：同 fingerprint 保留 confidence 最高者，合并 evidence。"""
    best: Dict[str, Finding] = {}
    for f in findings:
        fp = fingerprint_of(f)
        existing = best.get(fp)
        if existing is None:
            best[fp] = f
            continue
        merged_ev = _merge_evidence(existing.evidence, f.evidence)
        if (f.confidence or 0.0) > (existing.confidence or 0.0):
            f.evidence = merged_ev
            f._ingest_seq = min(getattr(f, "_ingest_seq", 0), getattr(existing, "_ingest_seq", 0))
            best[fp] = f
        else:
            existing.evidence = merged_ev
    return list(best.values())


def hard_filter_findings(
    findings: List[Finding],
    failure_checker: Optional[Callable[[str], bool]] = None,
) -> List[Finding]:
    """§6.2 去误报第一层：硬过滤。

    - executor 拒绝标记（_executor_rejected，来自事件数据 rejected 字段）；
    - is_tool_failure_output 特征（复用 result_aggregator._is_failure_output，
      与 base_agent_v2.is_tool_failure_output 同一套标记）。
    """
    checker = failure_checker or ResultAggregator._is_failure_output
    kept: List[Finding] = []
    for f in findings:
        if getattr(f, "_executor_rejected", False):
            continue
        text = "\n".join(f.evidence or []) + "\n" + (f.description or "")
        if checker(text):
            continue
        kept.append(f)
    return kept


def apply_confidence_threshold(
    findings: List[Finding],
    threshold: float = CONFIDENCE_THRESHOLD,
) -> List[Finding]:
    """§6.2 去误报第二层：confidence < 阈值 → 标记 low_confidence（降级展示，不丢弃）。"""
    for f in findings:
        if (f.confidence or 0.0) < threshold:
            f.low_confidence = True
    return findings


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """§6.2 排序：severity 序 → CVSS 降序 → confidence 降序 → 时间（_ingest_seq）升序。"""
    def sev_key(f: Finding) -> int:
        s = f.severity
        if isinstance(s, ResultSeverity):
            s = s.value
        return SEVERITY_ORDER.get(str(s).lower(), 99)

    def cvss_key(f: Finding) -> float:
        return -(f.cvss_score if f.cvss_score is not None else 0.0)

    return sorted(
        findings,
        key=lambda f: (
            sev_key(f),
            cvss_key(f),
            -(f.confidence or 0.0),
            getattr(f, "_ingest_seq", 0),
        ),
    )


def finding_to_dict(finding: Finding) -> Dict[str, Any]:
    """Finding → 可序列化 dict（含 fingerprint / 降级标记 / LLM 标签）。"""
    ftype = finding.finding_type
    if isinstance(ftype, ResultType):
        ftype = ftype.value
    sev = finding.severity
    if isinstance(sev, ResultSeverity):
        sev = sev.value
    return {
        "fingerprint": fingerprint_of(finding),
        "type": ftype,
        "severity": sev,
        "title": finding.title,
        "description": finding.description,
        "evidence": list(finding.evidence),
        "source": finding.source,
        "confidence": finding.confidence,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "poc_available": finding.poc_available,
        "flag_content": finding.flag_content,
        "target": getattr(finding, "_target", "") or "",
        "low_confidence": bool(getattr(finding, "low_confidence", False)),
        "verified": bool(getattr(finding, "_verified", False)),
        "llm_label": getattr(finding, "_llm_label", None),
    }


@dataclass
class SummarySnapshot:
    """§6.2 汇总快照。"""

    session_id: str
    updated_at: str                      # ISO 时间戳
    findings: List[Finding]              # 已去重/去误报/排序
    stats: Dict[str, Any]                # agents_active / nodes_total / paths_pheromone_top3
    flags: List[str] = field(default_factory=list)
    next_best_path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "updated_at": self.updated_at,
            "findings": [finding_to_dict(f) for f in self.findings],
            "stats": dict(self.stats),
            "flags": list(self.flags),
            "next_best_path": list(self.next_best_path),
        }


# ==================== 会话状态 ====================

class _SessionState:
    """单 session 的增量汇总状态。"""

    def __init__(self) -> None:
        self.findings: Dict[str, Finding] = {}       # fingerprint -> Finding（去重存储）
        self.flags: List[str] = []
        self.next_best_path: List[str] = []
        self.stats: Dict[str, Any] = {
            "agents_active": 0,
            "nodes_total": 0,
            "paths_pheromone_top3": [],
        }
        self.last_push: float = 0.0      # 上次推送时间戳（节流用）
        self.seq: int = 0                # 摄入序号（时间升序键）
        self.dirty: bool = False         # 自上次推送后有变更
        self.sse_emitted = set()         # 已发 SSE 的 fingerprint
        self.sse_flags = set()           # 已发 SSE 的 flag


# ==================== 总结智能体 ====================

class SummarizerAgent:
    """总结智能体（架构设计 §6）。

    订阅 EventBus 事件 → 汇总流水线（规范化/去重/去误报/排序）→
    SummarySnapshot → EventBus summary.update + EventManager SSE 推送（2s 节流）。
    """

    SUBSCRIBED_EVENTS = (
        "mission.completed",
        "mission.failed",
        "tool.result",
        "vuln.verified",
        "dag.updated",
        "flag.found",
    )

    def __init__(
        self,
        bus: Optional[EventBus] = None,
        event_manager: Optional[EventManager] = None,
        brain: Any = None,
        throttle_seconds: float = 2.0,
        now: Optional[Callable[[], float]] = None,
        failure_checker: Optional[Callable[[str], bool]] = None,
        classifier: Optional[Callable[[List[Finding]], Dict[str, str]]] = None,
    ):
        self.bus = bus
        self.event_manager = event_manager if event_manager is not None else get_event_manager()
        self.brain = brain                      # LLMBrain，可选（LLM 三分类）
        self.throttle_seconds = float(throttle_seconds)
        self._now = now or time.time
        self._failure_checker = failure_checker  # 硬过滤判定（默认复用 ResultAggregator._is_failure_output）
        self._classifier = classifier            # 注入式三分类器（测试/定制用），返回 {fingerprint: label}
        self._sessions: Dict[str, _SessionState] = {}
        self._subscribed = False
        self._total_ingested = 0
        self._total_discarded = 0
        self._total_pushed = 0

    # ------------------------------------------------------------------
    # 订阅 / 反订阅（§6.1）
    # ------------------------------------------------------------------

    def subscribe(self, bus: Optional[EventBus] = None) -> "SummarizerAgent":
        """订阅 §6.1 的 6 类事件。重复调用同实例幂等。"""
        bus = bus or self.bus
        if bus is None:
            raise ValueError("SummarizerAgent.subscribe 需要 EventBus")
        self.bus = bus
        if self._subscribed:
            return self
        for pattern in self.SUBSCRIBED_EVENTS:
            priority = 10 if pattern == "flag.found" else 5
            bus.subscribe(pattern, self._route, SUBSCRIBER_NAME, priority=priority)
        self._subscribed = True
        logger.info("SummarizerAgent 已订阅 %d 类事件", len(self.SUBSCRIBED_EVENTS))
        return self

    def unsubscribe(self) -> None:
        if self.bus is not None:
            for pattern in self.SUBSCRIBED_EVENTS:
                self.bus.unsubscribe(pattern, SUBSCRIBER_NAME)
        self._subscribed = False

    def _route(self, event: Event) -> None:
        """统一路由：单点兜底异常，handler 崩溃不中断事件总线。"""
        try:
            handler = getattr(self, "on_" + event.event_type.replace(".", "_"), None)
            if handler is not None:
                handler(event)
        except Exception as e:  # noqa: BLE001 —— 总线防护：绝不向 emit 抛出
            logger.error("SummarizerAgent 处理 %s 异常（已隔离）: %s", event.event_type, e)

    # ------------------------------------------------------------------
    # 事件 handler（§6.1）
    # ------------------------------------------------------------------

    def on_mission_completed(self, event: Event) -> None:
        data = event.data or {}
        session_id, target, items = self._extract_mission_items(data)
        self._update_agents(data)
        if not session_id:
            return
        if items:
            self.ingest_findings(session_id, items, source="mission.completed", target=target)
        else:
            self._push(session_id)  # 空结果也触发增量汇总（如 stats 变化）

    def on_mission_failed(self, event: Event) -> None:
        data = event.data or {}
        session_id, target, items = self._extract_mission_items(data)
        self._update_agents(data)
        if not session_id:
            return
        # 失败 AgentResult（success=False）不产 finding；有可归一化条目时仍入库
        if items:
            self.ingest_findings(session_id, items, source="mission.failed", target=target)
        else:
            self._push(session_id)

    def on_tool_result(self, event: Event) -> None:
        data = event.data or {}
        session_id = str(data.get("session_id") or "")
        if not session_id:
            return
        target = str(data.get("target") or "")
        tool_name = str(data.get("tool_name") or "")
        output = data.get("output")
        if output is None:
            output = data.get("result")
        if isinstance(output, dict):
            output = json.dumps(output, ensure_ascii=False)
        text = str(output or "")
        if not text or not self._matches_tool_result_keywords(text):
            return  # §6.1：仅 critical/high 关键词命中的即时线索
        f = Finding(
            finding_type=ResultType.VULNERABILITY,
            severity=self._keyword_severity(text),
            title=f"高危线索: {tool_name}" if tool_name else "高危线索",
            description=f"工具 {tool_name or 'unknown'} 输出命中 critical/high 关键词",
            evidence=[self._tool_result_evidence(text)],
            source=f"tool.result:{tool_name}" if tool_name else "tool.result",
            confidence=0.6,
        )
        f._target = target
        self.ingest_findings(session_id, [f], source="tool.result")

    def on_vuln_verified(self, event: Event) -> None:
        data = event.data or {}
        session_id = str(data.get("session_id") or "")
        if not session_id:
            return
        finding = data.get("finding")
        if finding is None:
            finding = data.get("result")
        if finding is None:
            finding = data
        f = normalize_finding(finding, target=str(data.get("target") or ""))
        if f is None:
            return
        f._verified = True                                    # 最高可信发现
        f.confidence = max(f.confidence or 0.0, 0.85)
        self.ingest_findings(session_id, [f], source="vuln.verified")

    def on_dag_updated(self, event: Event) -> None:
        data = event.data or {}
        session_id = str(data.get("session_id") or "")
        if not session_id:
            return
        st = self._sessions.setdefault(session_id, _SessionState())
        self._apply_dag_stats(st, data)
        self._push(session_id)  # 触发增量汇总（2s 节流内合并）

    def on_flag_found(self, event: Event) -> None:
        data = event.data or {}
        session_id = str(data.get("session_id") or "")
        flag = data.get("flag") or data.get("flag_content") or ""
        if not session_id or not flag:
            return
        st = self._sessions.setdefault(session_id, _SessionState())
        if flag not in st.flags:
            st.flags.append(str(flag))
            st.dirty = True
        self._push(session_id, force=True)  # §6.1：flag.found 立即高优推送（绕过节流）

    # ------------------------------------------------------------------
    # 汇总流水线（§6.2）
    # ------------------------------------------------------------------

    def ingest_findings(
        self,
        session_id: str,
        items: Any,
        source: str = "",
        target: str = "",
        push: bool = True,
        force_push: bool = False,
    ) -> int:
        """规范化 → 硬过滤 → 阈值降级 → 批内去重 → 合并入库 → LLM 三分类 → （可选）推送。

        返回纳入候选的数量（经硬过滤后）。
        """
        if not session_id:
            logger.debug("SummarizerAgent: 缺少 session_id，跳过 ingest")
            return 0
        st = self._sessions.setdefault(session_id, _SessionState())
        normalized = normalize_findings(items, default_target=target)
        if not normalized:
            return 0
        kept = hard_filter_findings(normalized, failure_checker=self._failure_checker)
        dropped_hard = len(normalized) - len(kept)
        if dropped_hard:
            self._total_discarded += dropped_hard
        if not kept:
            return 0
        apply_confidence_threshold(kept)
        for f in kept:
            if not hasattr(f, "_ingest_seq"):
                f._ingest_seq = st.seq
                st.seq += 1
        batch = deduplicate_findings(kept)  # 批内去重（同批同 fingerprint 合并）
        added: List[Finding] = []
        for f in batch:
            if self._store_add(st, f):
                added.append(f)
        if added:
            st.dirty = True
            labels = self._classify(added)
            for f in added:
                fp = fingerprint_of(f)
                label = labels.get(fp)
                if label == "false_positive":
                    st.findings.pop(fp, None)
                    self._total_discarded += 1
                elif label in ("confirmed", "suspicious"):
                    f._llm_label = label
        if push:
            self._push(session_id, force=force_push)
        return len(kept)

    def _store_add(self, st: _SessionState, finding: Finding) -> bool:
        """合并入库：同 fingerprint 保留 confidence 最高者，合并 evidence。返回是否新增。"""
        fp = fingerprint_of(finding)
        existing = st.findings.get(fp)
        if existing is None:
            st.findings[fp] = finding
            return True
        merged_ev = _merge_evidence(existing.evidence, finding.evidence)
        if (finding.confidence or 0.0) > (existing.confidence or 0.0):
            finding.evidence = merged_ev
            finding._ingest_seq = min(
                getattr(finding, "_ingest_seq", 0), getattr(existing, "_ingest_seq", 0)
            )
            finding._verified = bool(getattr(finding, "_verified", False)) or bool(
                getattr(existing, "_verified", False)
            )
            if getattr(finding, "_llm_label", None) is None:
                finding._llm_label = getattr(existing, "_llm_label", None)
            st.findings[fp] = finding
        else:
            existing.evidence = merged_ev
            if getattr(finding, "_verified", False):
                existing._verified = True
        return False

    # ------------------------------------------------------------------
    # LLM 三分类（§6.2 第三层；降级安全）
    # ------------------------------------------------------------------

    def _classify(self, findings: List[Finding]) -> Dict[str, str]:
        """对新增 findings 做三分类，返回 {fingerprint: label}。

        注入式 classifier 优先；否则用 brain（LLM_BATCH_SIZE 批量，≤20 条/次）；
        brain 不可用或异常 → 返回 {}（静默跳过，保留原 finding）。
        """
        if not findings:
            return {}
        if self._classifier is not None:
            try:
                return dict(self._classifier(findings) or {})
            except Exception as e:
                logger.warning("SummarizerAgent 注入 classifier 异常（跳过）: %s", e)
                return {}
        if self.brain is None or not getattr(self.brain, "available", False):
            return {}
        labels: Dict[str, str] = {}
        for i in range(0, len(findings), LLM_BATCH_SIZE):
            batch = findings[i:i + LLM_BATCH_SIZE]
            try:
                labels.update(self._llm_classify_batch(batch) or {})
            except Exception as e:
                logger.warning("SummarizerAgent LLM 三分类失败（跳过该批）: %s", e)
                continue
        return labels

    def _llm_classify_batch(self, batch: List[Finding]) -> Dict[str, str]:
        """调用 LLMBrain 对一批（≤20）finding 做三分类。

        复用 LLMBrain._invoke_text + _parse_json_payload（同一 JSON 管线）。
        """
        system = (
            "You are a triage assistant for a security assessment summary. "
            "Classify each finding as one of: confirmed, suspicious, false_positive. "
            'Output ONLY JSON: {"results":[{"index":0,"label":"confirmed"}, ...]}'
        )
        lines = []
        for idx, f in enumerate(batch):
            ftype = f.finding_type
            if isinstance(ftype, ResultType):
                ftype = ftype.value
            sev = f.severity
            if isinstance(sev, ResultSeverity):
                sev = sev.value
            evidence = (f.evidence[0] if f.evidence else "")[:200]
            lines.append(
                f"[{idx}] type={ftype} severity={sev} title={f.title} "
                f"confidence={f.confidence} evidence={evidence}"
            )
        messages = [{"role": "user", "content": "Findings to triage:\n" + "\n".join(lines)}]
        text = self.brain._invoke_text(system, messages, max_tokens=len(batch) * 40 + 200,
                                       prefer_json=True)
        payload = self.brain._parse_json_payload(text) if hasattr(self.brain, "_parse_json_payload") else None
        if not payload:
            return {}
        results = payload.get("results") or payload.get("result") or []
        if isinstance(results, dict):
            results = [{"index": k, "label": v} for k, v in results.items()]
        labels: Dict[str, str] = {}
        for item in results:
            if not isinstance(item, dict):
                continue
            try:
                idx = int(item.get("index"))
                label = str(item.get("label") or "").strip().lower()
            except (TypeError, ValueError):
                continue
            if label not in _LLM_LABELS or not (0 <= idx < len(batch)):
                continue
            labels[fingerprint_of(batch[idx])] = label
        return labels

    # ------------------------------------------------------------------
    # 快照 / 推送（§6.3）
    # ------------------------------------------------------------------

    def build_snapshot(self, session_id: str) -> SummarySnapshot:
        """产出 §6.2 的 SummarySnapshot（纯内存，幂等）。"""
        st = self._sessions.get(session_id)
        if st is None:
            st = _SessionState()
        return SummarySnapshot(
            session_id=str(session_id),
            updated_at=datetime.fromtimestamp(self._now(), tz=timezone.utc).isoformat(),
            findings=sort_findings(list(st.findings.values())),
            stats=dict(st.stats),
            flags=list(st.flags),
            next_best_path=list(st.next_best_path),
        )

    def push(self, session_id: str, force: bool = False) -> bool:
        """推送一条 summary.update（受 2s 节流约束，force 可绕过）。"""
        return self._push(session_id, force=force)

    def flush(self, session_id: Optional[str] = None) -> int:
        """强制冲刷：忽略节流推送（用于阶段收尾/关闭时合并 pending delta）。"""
        pushed = 0
        for sid in (list(self._sessions) if session_id is None else [session_id]):
            if self._push(sid, force=True):
                pushed += 1
        return pushed

    def _push(self, session_id: str, force: bool = False) -> bool:
        st = self._sessions.get(session_id)
        if st is None or not st.dirty:
            return False
        now = self._now()
        if not force and (now - st.last_push) < self.throttle_seconds:
            return False  # 节流：窗口内合并 delta，不重复推送
        snapshot = self.build_snapshot(session_id)
        st.last_push = now
        st.dirty = False
        if self.bus is not None:
            try:
                self.bus.emit("summary.update", snapshot.to_dict(), source=SUBSCRIBER_NAME)
            except Exception as e:
                logger.error("SummarizerAgent 写 EventBus summary.update 失败: %s", e)
        try:
            self._emit_sse(session_id, snapshot)
        except Exception as e:
            logger.error("SummarizerAgent SSE 推送失败: %s", e)
        self._total_pushed += 1
        logger.debug("SummarizerAgent 推送 summary.update: session=%s findings=%d",
                     session_id, len(snapshot.findings))
        return True

    def _emit_sse(self, session_id: str, snapshot: SummarySnapshot) -> None:
        """§6.3 复用 EventManager.create_emitter(session_id) 发 SSE（同步 emit_sync）。"""
        if self.event_manager is None:
            return
        emitter = self.event_manager.create_emitter(session_id)
        emitter.emit_sync(EventData(
            event_type=EventType.INFO,
            message=f"汇总更新: {len(snapshot.findings)} 条发现",
            metadata={"summary": snapshot.to_dict()},
        ))
        st = self._sessions.get(session_id)
        for f in snapshot.findings:
            fp = fingerprint_of(f)
            if st is not None and fp in st.sse_emitted:
                continue  # 仅推送 delta
            sev = f.severity.value if isinstance(f.severity, ResultSeverity) else str(f.severity)
            ftype = f.finding_type.value if isinstance(f.finding_type, ResultType) else str(f.finding_type)
            verified = bool(getattr(f, "_verified", False))
            emitter.emit_sync(EventData(
                event_type=EventType.FINDING_VERIFIED if verified else EventType.FINDING_NEW,
                finding_id=fp,
                severity=sev,
                vulnerability_type=ftype,
                message=f"[{sev.upper()}] {f.title}",
                metadata={
                    "fingerprint": fp,
                    "title": f.title,
                    "severity": sev,
                    "vulnerability_type": ftype,
                    "verified": verified,
                },
            ))
            if st is not None:
                st.sse_emitted.add(fp)
        for flag in snapshot.flags:
            if st is not None and flag in st.sse_flags:
                continue
            emitter.emit_sync(EventData(
                event_type=EventType.FLAG_FOUND,
                flag=flag,
                message=f"发现 Flag: {flag}",
                metadata={"flag": flag},
            ))
            if st is not None:
                st.sse_flags.add(flag)

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _extract_mission_items(self, data: Dict[str, Any]):
        """从 mission.completed / mission.failed 事件数据提取 (session_id, target, items)。"""
        session_id = str(data.get("session_id") or "")
        target = str(data.get("target") or "")
        result = data.get("result")
        if result is None:
            result = data.get("agent_result")
        items: List[Any] = []
        if result is not None:
            items.append(result)
        items.extend(data.get("findings") or [])
        ticket = data.get("ticket")
        if isinstance(ticket, dict):
            if not session_id:
                session_id = str(ticket.get("session_id") or "")
            if not target:
                target = str(ticket.get("target") or "")
        return session_id, target, items

    def _update_agents(self, data: Dict[str, Any]) -> None:
        """从事件数据更新 agents_active（若提供）。"""
        agents_active = data.get("agents_active")
        if agents_active is None:
            return
        session_id = str(data.get("session_id") or "")
        if not session_id:
            return
        st = self._sessions.setdefault(session_id, _SessionState())
        val = self._coerce_stat_count(agents_active)
        if val != st.stats["agents_active"]:
            st.stats["agents_active"] = val
            st.dirty = True

    def _apply_dag_stats(self, st: _SessionState, data: Dict[str, Any]) -> None:
        """从 dag.updated 事件数据合并 stats / next_best_path（幂等，仅变更时置 dirty）。"""
        changed = False
        stats = data.get("stats") or data.get("snapshot") or {}
        if isinstance(stats, dict):
            if stats.get("agents_active") is not None:
                val = self._coerce_stat_count(stats["agents_active"])
                if val != st.stats["agents_active"]:
                    st.stats["agents_active"] = val
                    changed = True
            if stats.get("nodes_total") is not None:
                val = self._coerce_stat_count(stats["nodes_total"])
                if val != st.stats["nodes_total"]:
                    st.stats["nodes_total"] = val
                    changed = True
            if stats.get("paths_pheromone_top3") is not None:
                val = list(stats["paths_pheromone_top3"])
                if val != st.stats["paths_pheromone_top3"]:
                    st.stats["paths_pheromone_top3"] = val
                    changed = True
        for key in ("agents_active", "nodes_total", "paths_pheromone_top3"):
            if key in data and data[key] is not None:
                val = (
                    self._coerce_stat_count(data[key])
                    if key != "paths_pheromone_top3"
                    else list(data[key])
                )
                if val != st.stats[key]:
                    st.stats[key] = val
                    changed = True
        nbp = data.get("next_best_path") or data.get("recommended_path")
        if nbp is not None:
            nbp_list = [str(p) for p in nbp]
            if nbp_list != st.next_best_path:
                st.next_best_path = nbp_list
                changed = True
        if changed:
            st.dirty = True

    @staticmethod
    def _coerce_stat_count(value: Any) -> int:
        if isinstance(value, (list, tuple, set)):
            return len(value)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _matches_tool_result_keywords(text: str) -> bool:
        lowered = text.lower()
        return any(kw in lowered for kw in _TOOL_RESULT_KEYWORDS)

    @staticmethod
    def _keyword_severity(text: str) -> ResultSeverity:
        lowered = text.lower()
        if "critical" in lowered or "严重" in lowered:
            return ResultSeverity.CRITICAL
        return ResultSeverity.HIGH

    @classmethod
    def _tool_result_evidence(cls, text: str) -> str:
        """摘录命中的关键词上下文片段作为证据（复用 ResultAggregator 摘录逻辑）。"""
        lowered = text.lower()
        for kw in _TOOL_RESULT_KEYWORDS:
            if kw in lowered:
                return ResultAggregator._extract_evidence_snippet(text, kw)
        return text[:160]

    def reset(self, session_id: Optional[str] = None) -> None:
        """清空会话状态（全部或单个 session）。"""
        if session_id is None:
            self._sessions.clear()
        else:
            self._sessions.pop(session_id, None)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "sessions": len(self._sessions),
            "total_ingested": self._total_ingested,
            "total_discarded": self._total_discarded,
            "total_pushed": self._total_pushed,
        }


__all__ = [
    "SummarizerAgent",
    "SummarySnapshot",
    "normalize_finding",
    "normalize_findings",
    "fingerprint_of",
    "deduplicate_findings",
    "hard_filter_findings",
    "apply_confidence_threshold",
    "sort_findings",
    "finding_to_dict",
    "SEVERITY_ORDER",
    "CONFIDENCE_THRESHOLD",
    "LLM_BATCH_SIZE",
]
