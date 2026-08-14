#!/usr/bin/env python3
"""
蚁群算法（ACO）路径引导 — 架构设计 §5（P2 阶段交付）。

职责：
- 信息素 τ 沉积在边上（边 = 一次「从 X 深入 Y」的攻击路径段），τ ∈ [0.05, 1.0]，初始 0.1；
- 沉积：Δτ = deposit_rate · success_signal · (1 + sev_weight)，τ ← min(1.0, τ + Δτ)；
- 蒸发：每 TICK（每新增 5 个节点 或 60s，取先到者）τ ← max(0.05, (1 − ρ)·τ)，ρ = 0.10；
- 启发式 η = 0.4·severity_norm + 0.3·kb_sim + 0.2·target_rel − 0.05·cost_norm − 0.05·fail_rate；
- 选路 P(e) = τ^α · η^β / Σ(τ^α · η^β)，α=1，β=2；
- 接口：recommend_next(n, agent_role, k) → top-k 候选边（附 τ/η/P 分解值）；
  select_next(n) → 轮盘赌采样。

关键约束（§1.2 / §5.5）：ACO 只输出推荐评分，**不触发任何工具**，LLM 才是决策者。

依赖方向：本模块**不 import attack_dag**（通过 Protocol 鸭子类型访问 DAGService 的读接口），
attack_dag 单向依赖本模块的纯函数与常量 → 无循环导入。

两种运行形态：
1. `ACO(dag=...)` — 绑定 DAGService：沉积/蒸发经 `dag.apply("deposit"/"evaporate")`
   走单一写入者串行落库；tick 计数由 DAGService 在写路径上自动执行；
2. `ACO()` + `load_edges(...)` — 纯内存形态（单测/演示用），沉积/蒸发就地生效。

数值计算全部用纯 Python（math 标准库），不引入 numpy。
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ==================== 常量（§5.1 / §5.2 / §5.3 / §5.4，均可配置注入） ====================

PHEROMONE_MIN = 0.05       # τ 下界
PHEROMONE_MAX = 1.0        # τ 上界
PHEROMONE_INIT = 0.1       # 初始信息素

DEPOSIT_RATE = 0.15        # 沉积速率（默认，配置项）
EVAP_RHO = 0.10            # 蒸发系数 ρ（默认，配置项）
TICK_NODE_COUNT = 5        # 每新增 5 个节点 → 一次 TICK
TICK_INTERVAL_SEC = 60.0   # 或距上次蒸发 60s → 一次 TICK

ALPHA = 1                  # 信息素权重
BETA = 2                   # 启发式权重

# 严重性 → sev_weight（§5.1）
SEV_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.6,
    "MEDIUM": 0.3,
    "LOW": 0.1,
    "INFO": 0.0,
}

# 启发式权重 w = [severity_norm, kb_sim, target_rel, cost_norm, fail_rate]（§5.3，Σw=1.0）
HEURISTIC_W: Tuple[float, float, float, float, float] = (0.4, 0.3, 0.2, 0.05, 0.05)

# agent_role → 相关边类型（§4.1 边语义 × §2.1 角色职责），未知角色 = 全部边
ROLE_EDGE_TYPES: Dict[str, Tuple[str, ...]] = {
    "recon_agent": ("evidence", "yields"),
    "subdomain_agent": ("evidence", "yields"),
    "web_recon_agent": ("evidence", "yields"),
    "source_code_agent": ("evidence", "yields"),
    "web_vuln_agent": ("drives", "yields", "enables"),
    "vuln_scanner_agent": ("drives", "yields", "enables"),
    "vuln_verifier_agent": ("drives", "yields", "enables"),
    "auth_agent": ("drives", "yields", "enables"),
    "network_vuln_agent": ("drives", "yields", "enables"),
    "exploit_agent": ("drives", "enables"),
    "lateral_agent": ("drives", "enables"),
    "privilege_agent": ("drives", "enables"),
    "pwn_agent": ("drives", "enables"),
    "forensics_agent": ("drives", "enables"),
    "crypto_agent": ("drives", "enables"),
    "code_audit_agent": ("drives", "enables"),
    "code_analyze_agent": ("drives", "enables"),
}

ALL_EDGE_TYPES: Tuple[str, ...] = ("evidence", "drives", "yields", "enables", "contains")


# ==================== 纯函数（§5 数学核心，attack_dag 亦复用，保持单一定义） ====================

def sev_weight(severity: Any) -> float:
    """severity 字符串（CRITICAL/HIGH/MEDIUM/LOW/INFO）→ sev_weight（§5.1）。"""
    if severity is None:
        return 0.0
    return SEV_WEIGHTS.get(str(severity).upper(), 0.0)


def deposit_delta(success_signal: float, severity: Any, deposit_rate: float = DEPOSIT_RATE) -> float:
    """Δτ_e = deposit_rate · success_signal · (1 + sev_weight)（§5.1）。

    success_signal ∈ [0,1]：verifier 置信度 / 平台验证得分；无 verifier 时 = agent 自报 confidence。
    """
    return deposit_rate * _clamp01(success_signal) * (1.0 + sev_weight(severity))


def evaporate_tau(tau: float, rho: float = EVAP_RHO, floor: float = PHEROMONE_MIN) -> float:
    """τ_e ← max(0.05, (1 − ρ) · τ_e)（§5.2）。"""
    return max(floor, (1.0 - rho) * tau)


def clamp_tau(tau: float) -> float:
    """τ 裁剪到 [PHEROMONE_MIN, PHEROMONE_MAX]。"""
    if math.isnan(tau) or math.isinf(tau):
        return PHEROMONE_MIN
    return max(PHEROMONE_MIN, min(PHEROMONE_MAX, tau))


def _clamp01(v: float) -> float:
    if v is None:
        return 0.0
    v = float(v)
    if math.isnan(v) or math.isinf(v):
        return 0.0
    return max(0.0, min(1.0, v))


def _severity_norm(meta: Dict[str, Any]) -> float:
    """severity_norm 取值：meta.severity_norm（已归一化）> meta.severity（等级映射）> meta.cvss（CVSS/10）。"""
    if meta.get("severity_norm") is not None:
        return _clamp01(meta["severity_norm"])
    if meta.get("severity") is not None:
        return sev_weight(meta["severity"])
    if meta.get("cvss") is not None:
        return _clamp01(float(meta["cvss"]) / 10.0)
    return 0.0


def heuristic(meta: Dict[str, Any], w: Sequence[float] = HEURISTIC_W) -> Tuple[float, Dict[str, float]]:
    """启发式 η（§5.3），全部归一化到 [0,1]；η 截断到 ≥ 0（负值视作 0，不进选路）。

    返回 (η, components)，components 给出五项分解值（供 LLM 审计 / 单测复算）。
    """
    meta = meta or {}
    comps = {
        "severity_norm": _severity_norm(meta),
        "kb_sim": _clamp01(meta.get("kb_sim", 0.0)),
        "target_rel": _clamp01(meta.get("target_rel", 0.0)),
        "cost_norm": _clamp01(meta.get("cost_norm", 0.0)),
        "fail_rate": _clamp01(meta.get("fail_rate", 0.0)),
    }
    w1, w2, w3, w4, w5 = (float(x) for x in w[:5])
    eta = (w1 * comps["severity_norm"]
           + w2 * comps["kb_sim"]
           + w3 * comps["target_rel"]
           - w4 * comps["cost_norm"]
           - w5 * comps["fail_rate"])
    return max(0.0, eta), comps


def normalize_probabilities(raw: Sequence[float]) -> List[float]:
    """P(e) = τ^α·η^β / Σ(τ^α·η^β)（§5.4）；返回归一化概率，ΣP = 1。

    raw 全为 0（如全部 η=0 且 τ>0 不可能，这里作为兜底）→ 均分，保证 ΣP=1 恒成立。
    """
    total = sum(raw)
    if total <= 0.0 or len(raw) == 0:
        n = len(raw)
        return [1.0 / n for _ in range(n)] if n else []
    return [r / total for r in raw]


def role_relevant_edge_types(agent_role: str) -> Tuple[str, ...]:
    """角色相关的边类型（未知角色 → 全部）。"""
    return ROLE_EDGE_TYPES.get(agent_role or "", ALL_EDGE_TYPES)


# ==================== 选路结果 ====================

@dataclass
class EdgeScore:
    """一条候选边的 ACO 评分分解（§5.5 的 LLM 注入格式）。"""

    edge_id: str
    source_id: str
    target_id: str
    edge_type: str
    tau: float                       # 信息素
    eta: float                       # 启发式
    p: float                         # 归一化概率 P(e)
    components: Dict[str, float] = field(default_factory=dict)  # η 的五项分解
    weight: float = 1.0              # 边权重 w（元数据）

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "tau": round(self.tau, 6),
            "eta": round(self.eta, 6),
            "p": round(self.p, 6),
            "components": {k: round(v, 6) for k, v in self.components.items()},
            "weight": self.weight,
        }


# 边对象的最小接口（鸭子类型；DAGService.DAGEdge 天然满足）
class EdgeLike:
    """类型占位（Protocol 语义）：实现方须具备 edge_id/edge_type/source_id/target_id/
    weight/tau/meta 属性。仅作类型标注用，无运行时作用。"""


# ==================== ACO 主体 ====================

class ACO:
    """蚁群算法路径引导器。

    参数（默认值即架构设计 §5 的初始值，P5 阶段做小网格校准）：
    - alpha / beta：选路公式指数（§5.4）
    - rho：蒸发系数（§5.2）
    - deposit_rate：沉积速率（§5.1）
    - tick_node_count / tick_interval_sec：TICK 触发阈值（§5.2）
    - w：启发式权重（§5.3）
    - rng：可注入 random.Random 以复现轮盘赌采样
    """

    def __init__(
        self,
        dag=None,                                   # DAGService | None（None = 纯内存形态）
        *,
        session_id: Optional[str] = None,
        alpha: float = ALPHA,
        beta: float = BETA,
        rho: float = EVAP_RHO,
        deposit_rate: float = DEPOSIT_RATE,
        tick_node_count: int = TICK_NODE_COUNT,
        tick_interval_sec: float = TICK_INTERVAL_SEC,
        w: Sequence[float] = HEURISTIC_W,
        rng: Optional[random.Random] = None,
    ) -> None:
        self.dag = dag
        self.session_id = session_id
        self.alpha = alpha
        self.beta = beta
        self.rho = rho
        self.deposit_rate = deposit_rate
        self.tick_node_count = max(1, int(tick_node_count))
        self.tick_interval_sec = float(tick_interval_sec)
        self.w = tuple(w)
        self.rng = rng if rng is not None else random.Random()

        # 纯内存形态的边表 {edge_id: edge} 与出边索引 {source_id: [edge_id]}
        self._edges: Dict[str, Any] = {}
        self._out: Dict[str, List[str]] = {}

        # tick 状态（仅纯内存形态使用；dag 形态由 DAGService 在写路径上自动 tick）
        self._nodes_since_tick = 0
        self._last_tick_at = time.time()

    # ---------- 数据接入 ----------

    def load_edges(self, edges: Sequence[Any]) -> None:
        """纯内存形态：载入候选边（含 τ 初值与 meta 启发式字段）。"""
        self._edges = {}
        self._out = {}
        for e in edges:
            self._edges[e.edge_id] = e
            self._out.setdefault(e.source_id, []).append(e.edge_id)

    @property
    def bound_session_id(self) -> Optional[str]:
        if self.session_id is not None:
            return self.session_id
        if self.dag is not None and hasattr(self.dag, "session_id"):
            return self.dag.session_id
        return None

    # ---------- 候选边与 τ ----------

    def _candidate_edges(self, node_id: str, session_id: Optional[str]) -> List[Any]:
        """C(n) = 节点 n 的可达前沿边（§5.4）。"""
        if self.dag is not None:
            return self.dag.get_outgoing_edges(node_id, session_id=session_id or self.bound_session_id)
        sid = session_id or self.bound_session_id
        out = []
        for eid in self._out.get(node_id, ()):
            e = self._edges[eid]
            if sid is None or getattr(e, "session_id", None) in (None, sid):
                out.append(e)
        return out

    def _tau_of(self, edge: Any) -> float:
        return clamp_tau(getattr(edge, "tau", PHEROMONE_INIT))

    # ---------- 启发式与选路（只读，不触发任何工具） ----------

    def compute_scores(self, node_id: str, agent_role: str = "", session_id: Optional[str] = None) -> List[EdgeScore]:
        """计算节点 n 的候选边评分列表（含 τ/η/P 分解值，P 已归一化 ΣP=1）。"""
        candidates = self._candidate_edges(node_id, session_id)
        if agent_role:
            rel = role_relevant_edge_types(agent_role)
            candidates = [e for e in candidates if e.edge_type in rel]
        if not candidates:
            return []

        entries: List[Tuple[Any, float, Dict[str, float]]] = []
        for e in candidates:
            eta, comps = heuristic(getattr(e, "meta", None), self.w)
            entries.append((e, eta, comps))

        # 全部 η=0（如候选边无任何启发式字段）→ 退化为 τ 主导的均匀启发式，保证 ΣP=1
        if all(eta <= 0.0 for _, eta, _ in entries):
            entries = [(e, 1.0, comps) for e, _, comps in entries]

        raw = [self._tau_of(e) ** self.alpha * eta ** self.beta for e, eta, _ in entries]
        probs = normalize_probabilities(raw)

        return [
            EdgeScore(
                edge_id=e.edge_id,
                source_id=e.source_id,
                target_id=e.target_id,
                edge_type=e.edge_type,
                tau=self._tau_of(e),
                eta=eta,
                p=p,
                components=comps,
                weight=getattr(e, "weight", 1.0),
            )
            for (e, eta, comps), p in zip(entries, probs)
        ]

    def recommend_next(self, node_id: str, agent_role: str = "", k: int = 5,
                       session_id: Optional[str] = None) -> List[EdgeScore]:
        """按 P(e) 降序返回 top-k 候选边，附 τ/η/P 分解值（§5.5）。"""
        scores = self.compute_scores(node_id, agent_role, session_id)
        scores.sort(key=lambda s: s.p, reverse=True)
        return scores[: max(0, int(k))]

    def select_next(self, node_id: str, agent_role: str = "", session_id: Optional[str] = None) -> Optional[EdgeScore]:
        """按 P(e) 轮盘赌采样（LLM 未明确选向时的兜底展示，§5.5）。"""
        scores = self.compute_scores(node_id, agent_role, session_id)
        if not scores:
            return None
        r = self.rng.random()
        cum = 0.0
        for s in scores:
            cum += s.p
            if r <= cum:
                return s
        return scores[-1]  # 浮点舍入兜底

    # ---------- 信息素更新（写路径：dag 形态经 DAGService 单一写入者落库） ----------

    async def deposit(self, edge_ids: Sequence[str], success_signal: float,
                      severity: Any = "INFO", session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """沉积：Δτ = deposit_rate · success_signal · (1 + sev_weight)（§5.1）。

        dag 形态 → 转发 `dag.apply("deposit", ...)`（单一写入者串行落库）；
        纯内存形态 → 就地更新。返回每条边的 {edge_id, old_tau, new_tau, delta, ...}。
        """
        if self.dag is not None:
            result = await self.dag.apply("deposit", {
                "edge_ids": list(edge_ids),
                "success_signal": success_signal,
                "severity": severity,
                "session_id": session_id or self.bound_session_id,
            })
            return result.get("records", [])
        return self._deposit_local(edge_ids, success_signal, severity, session_id)

    def _deposit_local(self, edge_ids: Sequence[str], success_signal: float,
                       severity: Any, session_id: Optional[str]) -> List[Dict[str, Any]]:
        delta = deposit_delta(success_signal, severity, self.deposit_rate)
        sev_w = sev_weight(severity)
        records = []
        sid = session_id or self.bound_session_id
        for eid in edge_ids:
            e = self._edges.get(eid)
            if e is None:
                continue
            if sid is not None and getattr(e, "session_id", None) not in (None, sid):
                continue
            old = self._tau_of(e)
            new = clamp_tau(old + delta)
            e.tau = new
            records.append({
                "edge_id": eid,
                "source_id": e.source_id,
                "target_id": e.target_id,
                "edge_type": e.edge_type,
                "old_tau": old,
                "new_tau": new,
                "delta": new - old,
                "success_signal": _clamp01(success_signal),
                "severity": severity,
                "sev_weight": sev_w,
            })
        return records

    async def deposit_path(self, verified_node_id: str, success_signal: float,
                           severity: Any = "INFO", session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """沿验证成功的 finding/observation 节点**回溯整条攻击路径**逐跳沉积（§5.1）。

        实现说明：§5.1 规定「沿 enables/yields 路径回溯」——本实现从验证节点沿
        入边（yields/enables/drives/evidence，即路径上的全部线段）一直回溯到
        mission/summary 或无可入边为止。之所以覆盖 drives/evidence：LLM 实际选择
        发生在前沿边（如 hypothesis --drives--> attack_action）上，若只强化
        yields/enables，则选择点上的 τ 永远不会收到成功反馈，ACO 失去引导作用。
        """
        if self.dag is not None:
            result = await self.dag.apply("deposit_path", {
                "verified_node_id": verified_node_id,
                "success_signal": success_signal,
                "severity": severity,
                "session_id": session_id or self.bound_session_id,
            })
            return result.get("records", [])
        sid = session_id or self.bound_session_id
        records: List[Dict[str, Any]] = []
        seen: set = set()
        current = verified_node_id
        while current not in seen:
            seen.add(current)
            incoming = self._incoming_edges_local(current, sid)
            if not incoming:
                break
            batch = [e.edge_id for e in incoming]
            records.extend(self._deposit_local(batch, success_signal, severity, sid))
            current = incoming[0].source_id  # 回溯上游（多条入边时沿第一条继续）
        return records

    def _incoming_edges_local(self, node_id: str, session_id: Optional[str]) -> List[Any]:
        incoming = []
        for eid, e in self._edges.items():
            if e.target_id != node_id:
                continue
            if session_id is not None and getattr(e, "session_id", None) not in (None, session_id):
                continue
            incoming.append(e)
        return incoming

    async def evaporate(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """蒸发：每边 τ ← max(0.05, (1 − ρ)·τ)（§5.2）。dag 形态经 DAGService 落库。"""
        if self.dag is not None:
            result = await self.dag.apply("evaporate", {"now": now})
            return result.get("records", [])
        now = now if now is not None else time.time()
        records = []
        for eid, e in list(self._edges.items()):
            old = self._tau_of(e)
            new = evaporate_tau(old, self.rho)
            if new != old:
                e.tau = new
            records.append({
                "edge_id": eid,
                "source_id": e.source_id,
                "target_id": e.target_id,
                "edge_type": e.edge_type,
                "old_tau": old,
                "new_tau": new,
                "rho": self.rho,
            })
        self._nodes_since_tick = 0
        self._last_tick_at = now
        return records

    async def on_nodes_added(self, count: int = 1, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """TICK 计数（§5.2）：每新增 count 个节点计入；达到 tick_node_count 或距上次
        蒸发 ≥ tick_interval_sec → 触发蒸发（取先到者）。

        dag 形态下返回 [] —— tick 由 DAGService 在写路径上统一管理（避免双蒸发）。
        """
        if self.dag is not None:
            return []
        now = now if now is not None else time.time()
        self._nodes_since_tick += max(1, int(count))
        if self._nodes_since_tick >= self.tick_node_count or \
                (now - self._last_tick_at) >= self.tick_interval_sec:
            return await self.evaporate(now=now)
        return []

    async def maybe_evaporate(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """时间维度惰性蒸发检查（读路径兜底，仅纯内存形态；dag 形态返回 []）。"""
        if self.dag is not None:
            return []
        now = now if now is not None else time.time()
        if (now - self._last_tick_at) >= self.tick_interval_sec:
            return await self.evaporate(now=now)
        return []
