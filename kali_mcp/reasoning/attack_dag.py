#!/usr/bin/env python3
"""
攻击 DAG（Attack DAG）— 「执行过程事实图」建模与持久化（架构设计 §4，P2 阶段交付）。

节点类型：observation / hypothesis / attack_action / finding / mission / summary
边类型：  evidence / drives / yields / enables / contains（带 pheromone τ、weight w、meta）

设计要点（§4.2）：
- **单一写入者**：所有变更经 `apply()`（或总线 `dag.command` 事件）提交，
  `asyncio.Lock` 串行 apply；落库后 emit `dag.updated`（delta + snapshot_hash）。
- **无环不变量**：攻击图方向严格 evidence→hypothesis→action→finding；
  禁止反向边（边类型 × 端点类型不匹配 → InvalidEdgeError）与回边（成环 → CycleError）。
  环检测复用 `kali_mcp.core.task_decomposer.TaskGraph.validate` 的 DFS 思路
  （visited / rec_stack），但语义从「预规划任务图」改为「执行过程事实图」。
- **持久化**：`data/attack_dag.sqlite`，表 nodes / edges / pheromone，按 session_id 隔离。
- **读接口**：get_subgraph(node_id, depth)、get_frontier(max_hypotheses)、
  get_pheromone_view(agent_role) → 供 LLM 输入的压缩 DAG 视图。

ACO 信息素数学（沉积/蒸发常量与纯函数）来自 `kali_mcp.reasoning.aco`（§5），
本模块只做状态持有与持久化，避免数学双份实现。依赖方向：attack_dag → aco（无环导入）。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .aco import (
    DEPOSIT_RATE,
    EVAP_RHO,
    PHEROMONE_INIT,
    PHEROMONE_MAX,
    PHEROMONE_MIN,
    TICK_INTERVAL_SEC,
    TICK_NODE_COUNT,
    deposit_delta,
    evaporate_tau,
    role_relevant_edge_types,
)

logger = logging.getLogger(__name__)

# ==================== 类型常量（§4.1） ====================

NODE_TYPES: Tuple[str, ...] = (
    "observation", "hypothesis", "attack_action", "finding", "mission", "summary",
)

EDGE_TYPES: Tuple[str, ...] = ("evidence", "drives", "yields", "enables", "contains")

# 无环不变量：边类型 × 合法（源类型 → 目标类型）映射（§4.1 / §4.2「禁止反向/回边」）
_EDGE_TRANSITIONS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "evidence": ("observation", ("hypothesis",)),                    # observation → hypothesis
    "drives": ("hypothesis", ("attack_action",)),                    # hypothesis → attack_action
    "yields": ("attack_action", ("observation", "finding")),         # attack_action → observation/finding
    "enables": ("finding", ("hypothesis",)),                         # finding → hypothesis
    "contains": ("summary", NODE_TYPES),                             # summary → 任意节点
}


def _legal_transition(edge_type: str, src_type: str, dst_type: str) -> bool:
    """边方向合法性：反向边（与 §4.1 方向不符）→ False。"""
    rule = _EDGE_TRANSITIONS.get(edge_type)
    if rule is None:
        return False
    return src_type == rule[0] and dst_type in rule[1]


# ==================== 异常 ====================

class DAGError(Exception):
    """攻击 DAG 操作基类异常。"""


class InvalidNodeTypeError(DAGError):
    """未知节点类型。"""


class UnknownNodeError(DAGError):
    """边引用了不存在的节点。"""


class InvalidEdgeError(DAGError):
    """非法边：未知边类型 / 自环 / 方向与节点类型不匹配（反向边）。"""


class CycleError(DAGError):
    """回边：添加该边会形成环，违反无环不变量。"""


# ==================== 数据模型（§4.1） ====================

@dataclass
class DAGNode:
    """攻击 DAG 节点。"""

    node_id: str
    node_type: str                       # observation/hypothesis/attack_action/finding/mission/summary
    session_id: str
    label: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.node_type not in NODE_TYPES:
            raise InvalidNodeTypeError(
                f"未知节点类型 {self.node_type!r}，合法: {NODE_TYPES}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "session_id": self.session_id,
            "label": self.label,
            "meta": self.meta,
            "created_at": self.created_at,
        }


@dataclass
class DAGEdge:
    """攻击 DAG 边（攻击路径段）：evidence / drives / yields / enables / contains。

    tau 为信息素（§5.1，∈[0.05,1.0]，初始 0.1），内存中随边对象持有，
    持久化到 pheromone 表（edges 表不含 tau 列）。
    """

    edge_id: str
    edge_type: str
    source_id: str
    target_id: str
    session_id: str
    weight: float = 1.0
    tau: float = PHEROMONE_INIT
    meta: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.edge_type not in EDGE_TYPES:
            raise InvalidEdgeError(
                f"未知边类型 {self.edge_type!r}，合法: {EDGE_TYPES}")
        self.tau = max(PHEROMONE_MIN, min(PHEROMONE_MAX, float(self.tau)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "session_id": self.session_id,
            "weight": self.weight,
            "tau": self.tau,
            "meta": self.meta,
            "created_at": self.created_at,
        }


@dataclass
class FrontierEdge:
    """get_frontier 返回项：一条前沿候选边及其端点节点。"""

    edge: DAGEdge
    source: Optional[DAGNode]
    target: Optional[DAGNode]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge": self.edge.to_dict(),
            "source": self.source.to_dict() if self.source else None,
            "target": self.target.to_dict() if self.target else None,
        }


# ==================== DAGService（单一写入者，§4.2） ====================

class DAGService:
    """攻击 DAG 唯一写入者。

    - 所有 agent（含 orchestrator）通过 `apply()` 或 `bus.emit("dag.command", {op, payload})`
      提交变更意图；`asyncio.Lock` 串行 apply（另加 threading.Lock 兜底同步总线路径）。
    - 校验无环（复用 TaskGraph.validate 的 DFS 思路），非法边抛异常拒绝、不落库。
    - 落盘 data/attack_dag.sqlite（表 nodes/edges/pheromone，按 session_id 隔离），
      每次写操作即时持久化（write-through）。
    - 成功 apply 后 emit `dag.updated`（{delta, snapshot_hash}）。
    - 自动 TICK（§5.2）：每新增 TICK_NODE_COUNT 个节点 或 距上次蒸发
      TICK_INTERVAL_SEC 秒 → 全边蒸发。
    """

    # 读操作允许的写命令（apply 分发表）
    _OPS = ("add_node", "add_edge", "update_node", "deposit", "deposit_path", "evaporate")

    def __init__(
        self,
        db_path: Optional[str] = None,          # None → 内存库 (:memory:)
        bus=None,                               # 可选 EventBus（订阅 dag.command / 发 dag.updated）
        session_id: str = "default",
        *,
        deposit_rate: float = DEPOSIT_RATE,
        rho: float = EVAP_RHO,
        tick_node_count: int = TICK_NODE_COUNT,
        tick_interval_sec: float = TICK_INTERVAL_SEC,
    ) -> None:
        self.session_id = session_id
        self.bus = bus
        self.db_path = db_path
        self.deposit_rate = deposit_rate
        self.rho = rho
        self.tick_node_count = max(1, int(tick_node_count))
        self.tick_interval_sec = float(tick_interval_sec)

        # 串行化：asyncio.Lock 为写路径主锁；threading.Lock 仅兜底 EventBus
        # 同步 handler（线程内无运行中事件循环时用 asyncio.run 建临时循环执行）。
        self._lock = asyncio.Lock()
        self._thread_lock = threading.Lock()

        # 内存态（单一真相源；sqlite 为镜像）
        self._nodes: Dict[str, DAGNode] = {}
        self._edges: Dict[str, DAGEdge] = {}
        self._out_edges: Dict[str, List[str]] = defaultdict(list)   # node_id → [edge_id]
        self._in_edges: Dict[str, List[str]] = defaultdict(list)    # node_id → [edge_id]
        self._id_seq = 1

        # TICK 状态（§5.2）
        self._nodes_since_tick = 0
        self._last_tick_at = time.time()

        self._db: Optional[sqlite3.Connection] = None
        self._init_db()
        self._load()

    # ---------- 存储 ----------

    def _init_db(self) -> None:
        if self.db_path is None or str(self.db_path) == ":memory:":
            conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            p = Path(self.db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(p), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                node_id    TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                node_type  TEXT NOT NULL,
                label      TEXT NOT NULL DEFAULT '',
                meta       TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS edges (
                edge_id    TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                edge_type  TEXT NOT NULL,
                source_id  TEXT NOT NULL,
                target_id  TEXT NOT NULL,
                weight     REAL NOT NULL DEFAULT 1.0,
                meta       TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pheromone (
                edge_id    TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                tau        REAL NOT NULL DEFAULT 0.1,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_session   ON nodes(session_id);
            CREATE INDEX IF NOT EXISTS idx_edges_session   ON edges(session_id);
            CREATE INDEX IF NOT EXISTS idx_pheromone_session ON pheromone(session_id);
            """
        )
        conn.commit()
        self._db = conn

    @staticmethod
    def _dumps_meta(meta: Any) -> str:
        return json.dumps(meta or {}, ensure_ascii=False, sort_keys=True, default=str)

    def _load(self) -> None:
        """从 sqlite 全量载入内存态（含 pheromone 合并到边对象 tau）。"""
        assert self._db is not None
        self._nodes.clear()
        self._edges.clear()
        self._out_edges.clear()
        self._in_edges.clear()
        for row in self._db.execute("SELECT * FROM nodes"):
            n = DAGNode(
                node_id=row["node_id"],
                node_type=row["node_type"],
                session_id=row["session_id"],
                label=row["label"],
                meta=json.loads(row["meta"] or "{}"),
                created_at=row["created_at"],
            )
            self._nodes[n.node_id] = n
        tau_map: Dict[str, float] = {}
        for row in self._db.execute("SELECT edge_id, tau FROM pheromone"):
            tau_map[row["edge_id"]] = row["tau"]
        for row in self._db.execute("SELECT * FROM edges"):
            e = DAGEdge(
                edge_id=row["edge_id"],
                edge_type=row["edge_type"],
                source_id=row["source_id"],
                target_id=row["target_id"],
                session_id=row["session_id"],
                weight=row["weight"],
                tau=tau_map.get(row["edge_id"], PHEROMONE_INIT),
                meta=json.loads(row["meta"] or "{}"),
                created_at=row["created_at"],
            )
            self._edges[e.edge_id] = e
            self._out_edges[e.source_id].append(e.edge_id)
            self._in_edges[e.target_id].append(e.edge_id)
        self._id_seq = self._max_id_seq() + 1

    def _max_id_seq(self) -> int:
        best = 0
        pat = re.compile(r"^(?:n|e)(\d+)$")
        for nid in list(self._nodes) + list(self._edges):
            m = pat.match(nid)
            if m:
                best = max(best, int(m.group(1)))
        return best

    def _next_node_id(self) -> str:
        nid = f"n{self._id_seq}"
        self._id_seq += 1
        return nid

    def _next_edge_id(self) -> str:
        eid = f"e{self._id_seq}"
        self._id_seq += 1
        return eid

    # ---------- 持久化原语（write-through） ----------

    def _persist_node(self, n: DAGNode) -> None:
        assert self._db is not None
        self._db.execute(
            "INSERT OR REPLACE INTO nodes(node_id, session_id, node_type, label, meta, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (n.node_id, n.session_id, n.node_type, n.label, self._dumps_meta(n.meta), n.created_at),
        )
        self._db.commit()

    def _persist_edge(self, e: DAGEdge) -> None:
        assert self._db is not None
        self._db.execute(
            "INSERT OR REPLACE INTO edges(edge_id, session_id, edge_type, source_id, target_id, weight, meta, created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (e.edge_id, e.session_id, e.edge_type, e.source_id, e.target_id,
             e.weight, self._dumps_meta(e.meta), e.created_at),
        )
        self._db.execute(
            "INSERT OR REPLACE INTO pheromone(edge_id, session_id, tau, updated_at) VALUES(?,?,?,?)",
            (e.edge_id, e.session_id, e.tau, e.created_at),
        )
        self._db.commit()

    def _persist_tau(self, e: DAGEdge) -> None:
        assert self._db is not None
        self._db.execute(
            "INSERT OR REPLACE INTO pheromone(edge_id, session_id, tau, updated_at) VALUES(?,?,?,?)",
            (e.edge_id, e.session_id, e.tau, time.time()),
        )
        self._db.commit()

    # ---------- 写入入口（单一写入者，§4.2） ----------

    async def apply(self, op: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """串行执行一个 DAG 写命令（asyncio.Lock），成功落库后 emit `dag.updated`。

        op ∈ add_node / add_edge / update_node / deposit / deposit_path / evaporate。
        校验失败抛 DAGError 子类（不落库、不 emit）。
        """
        if op not in self._OPS:
            raise DAGError(f"未知 DAG 命令 {op!r}，合法: {self._OPS}")
        async with self._lock:
            result = self._apply_locked(op, payload)
        self._emit_updated(op, result)
        return result

    def _emit_updated(self, op: str, result: Dict[str, Any]) -> None:
        if self.bus is None:
            return
        try:
            self.bus.emit("dag.updated", {
                "op": op,
                "session_id": self.session_id,
                "delta": result,
                "snapshot_hash": self.snapshot_hash(),
            }, source="DAGService")
        except Exception:  # 事件推送失败不阻断写路径
            logger.exception("DAGService: emit dag.updated 失败")

    def register(self, bus) -> None:
        """订阅 `dag.command` 事件（{op, payload}），串行 apply。"""
        self.bus = bus
        bus.subscribe("dag.command", self._on_dag_command, "DAGService", priority=5)

    def _on_dag_command(self, event) -> None:
        """EventBus 同步 handler：优先调度到运行中的事件循环，否则建临时循环同步执行。"""
        data = event.data or {}
        op = data.get("op")
        payload = data.get("payload") or {}
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        try:
            if loop is not None:
                loop.create_task(self.apply(op, payload))
            else:
                with self._thread_lock:  # 同步路径互斥，保证跨线程串行
                    asyncio.run(self.apply(op, payload))
        except Exception:
            logger.exception("DAGService: dag.command 处理失败 op=%r", op)

    # ---------- apply 实现（锁内执行） ----------

    def _apply_locked(self, op: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if op == "add_node":
            return self._add_node_locked(payload)
        if op == "add_edge":
            return self._add_edge_locked(payload)
        if op == "update_node":
            return self._update_node_locked(payload)
        if op == "deposit":
            return self._deposit_locked(payload)
        if op == "deposit_path":
            return self._deposit_path_locked(payload)
        if op == "evaporate":
            return self._evaporate_locked(payload.get("now"))
        raise DAGError(f"未知 DAG 命令 {op!r}")  # pragma: no cover

    def _add_node_locked(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        p = payload.get("node") if isinstance(payload.get("node"), dict) else payload
        node_id = p.get("node_id") or self._next_node_id()
        node_type = p["node_type"]
        if node_type not in NODE_TYPES:
            raise InvalidNodeTypeError(f"未知节点类型 {node_type!r}，合法: {NODE_TYPES}")
        session = p.get("session_id") or self.session_id
        existing = self._nodes.get(node_id)
        if existing is not None:
            if existing.session_id != session:
                raise DAGError(f"节点 {node_id} 已存在于会话 {existing.session_id}，与 {session} 冲突")
            return {"op": "add_node", "node": existing.to_dict(), "created": False, "evaporated": []}
        node = DAGNode(
            node_id=node_id,
            node_type=node_type,
            session_id=session,
            label=p.get("label", ""),
            meta=dict(p.get("meta") or {}),
            created_at=p.get("created_at") or time.time(),
        )
        self._nodes[node_id] = node
        self._out_edges.setdefault(node_id, [])
        self._in_edges.setdefault(node_id, [])
        self._persist_node(node)
        self._nodes_since_tick += 1
        evaporated = self._maybe_tick_locked()
        return {"op": "add_node", "node": node.to_dict(), "created": True, "evaporated": evaporated}

    def _add_edge_locked(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        p = payload.get("edge") if isinstance(payload.get("edge"), dict) else payload
        edge_id = p.get("edge_id") or self._next_edge_id()
        edge_type = p["edge_type"]
        source_id = p["source_id"]
        target_id = p["target_id"]
        session = p.get("session_id") or self.session_id
        if edge_id in self._edges:
            return {"op": "add_edge", "edge": self._edges[edge_id].to_dict(), "created": False, "evaporated": []}

        src = self._nodes.get(source_id)
        tgt = self._nodes.get(target_id)
        if src is None or tgt is None:
            missing = source_id if src is None else target_id
            raise UnknownNodeError(f"边 {edge_id} 引用不存在的节点 {missing}")
        if src.session_id != session or tgt.session_id != session:
            raise DAGError(f"边 {edge_id} 的端点与会话 {session} 不一致")
        if edge_type not in EDGE_TYPES:
            raise InvalidEdgeError(f"未知边类型 {edge_type!r}，合法: {EDGE_TYPES}")
        if source_id == target_id:
            raise InvalidEdgeError(f"自环边 {edge_id}（{source_id}→{target_id}）被拒绝")
        if not _legal_transition(edge_type, src.node_type, tgt.node_type):
            raise InvalidEdgeError(
                f"反向边被拒绝: {edge_type} {src.node_type}({source_id}) → {tgt.node_type}({target_id})"
                f"，合法方向见 §4.1")
        if self._would_create_cycle(source_id, target_id):
            raise CycleError(f"回边被拒绝: {edge_id} ({source_id}→{target_id}) 将形成环，违反无环不变量")

        edge = DAGEdge(
            edge_id=edge_id,
            edge_type=edge_type,
            source_id=source_id,
            target_id=target_id,
            session_id=session,
            weight=float(p.get("weight", 1.0)),
            tau=float(p.get("tau", PHEROMONE_INIT)),
            meta=dict(p.get("meta") or {}),
            created_at=p.get("created_at") or time.time(),
        )
        self._edges[edge_id] = edge
        self._out_edges[source_id].append(edge_id)
        self._in_edges[target_id].append(edge_id)
        self._persist_edge(edge)
        evaporated = self._maybe_tick_locked()
        return {"op": "add_edge", "edge": edge.to_dict(), "created": True, "evaporated": evaporated}

    def _update_node_locked(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        node_id = payload["node_id"]
        node = self._nodes.get(node_id)
        if node is None:
            raise UnknownNodeError(f"节点 {node_id} 不存在")
        if "label" in payload:
            node.label = payload["label"]
        if "meta" in payload and isinstance(payload["meta"], dict):
            merged = dict(node.meta)
            merged.update(payload["meta"])
            node.meta = merged
        self._persist_node(node)
        return {"op": "update_node", "node": node.to_dict()}

    def _deposit_locked(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """沉积（§5.1）：Δτ = deposit_rate · success_signal · (1 + sev_weight)。"""
        edge_ids = list(payload.get("edge_ids") or ())
        success_signal = payload.get("success_signal", 1.0)
        severity = payload.get("severity", "INFO")
        session = payload.get("session_id") or self.session_id
        delta = deposit_delta(success_signal, severity, self.deposit_rate)
        records = []
        for eid in edge_ids:
            e = self._edges.get(eid)
            if e is None or e.session_id != session:
                continue
            old = e.tau
            e.tau = max(PHEROMONE_MIN, min(PHEROMONE_MAX, old + delta))
            self._persist_tau(e)
            records.append({
                "edge_id": eid,
                "source_id": e.source_id,
                "target_id": e.target_id,
                "edge_type": e.edge_type,
                "old_tau": old,
                "new_tau": e.tau,
                "delta": e.tau - old,
                "success_signal": max(0.0, min(1.0, float(success_signal or 0.0))),
                "severity": severity,
            })
        evaporated = self._maybe_tick_locked()
        return {"op": "deposit", "records": records, "evaporated": evaporated}

    def _deposit_path_locked(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """从验证成功的节点沿入边回溯整条路径逐跳沉积（§5.1，见 aco.deposit_path 说明）。"""
        verified = payload.get("verified_node_id")
        if verified is None or verified not in self._nodes:
            raise UnknownNodeError(f"节点 {verified!r} 不存在，无法回溯沉积")
        session = payload.get("session_id") or self.session_id
        success_signal = payload.get("success_signal", 1.0)
        severity = payload.get("severity", "INFO")
        delta = deposit_delta(success_signal, severity, self.deposit_rate)
        records = []
        seen: Set[str] = set()
        current = verified
        while current not in seen:
            seen.add(current)
            incoming = [eid for eid in self._in_edges.get(current, ())
                        if self._edges[eid].session_id == session]
            if not incoming:
                break
            # 沿本跳所有入边沉积；多条入边时沿第一条继续回溯上游
            first_upstream: Optional[str] = None
            for eid in incoming:
                e = self._edges[eid]
                old = e.tau
                e.tau = max(PHEROMONE_MIN, min(PHEROMONE_MAX, old + delta))
                self._persist_tau(e)
                records.append({
                    "edge_id": eid,
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "edge_type": e.edge_type,
                    "old_tau": old,
                    "new_tau": e.tau,
                    "delta": e.tau - old,
                    "success_signal": max(0.0, min(1.0, float(success_signal or 0.0))),
                    "severity": severity,
                })
                if first_upstream is None:
                    first_upstream = e.source_id
            current = first_upstream
        evaporated = self._maybe_tick_locked()
        return {"op": "deposit_path", "records": records, "evaporated": evaporated}

    def _evaporate_locked(self, now: Optional[float]) -> Dict[str, Any]:
        """蒸发（§5.2）：τ ← max(0.05, (1 − ρ)·τ)。"""
        records = []
        for e in list(self._edges.values()):
            old = e.tau
            new = evaporate_tau(old, self.rho)
            if new != old:
                e.tau = new
                self._persist_tau(e)
            records.append({
                "edge_id": e.edge_id,
                "source_id": e.source_id,
                "target_id": e.target_id,
                "edge_type": e.edge_type,
                "old_tau": old,
                "new_tau": new,
                "rho": self.rho,
            })
        self._nodes_since_tick = 0
        self._last_tick_at = now if now is not None else time.time()
        return {"op": "evaporate", "records": records}

    def _maybe_tick_locked(self) -> List[Dict[str, Any]]:
        """TICK 判定（§5.2）：新增 TICK_NODE_COUNT 个节点 或 距上次蒸发 ≥ TICK_INTERVAL_SEC 秒
        → 触发一次全边蒸发。返回蒸发记录（无蒸发返回 []）。"""
        now = time.time()
        if self._nodes_since_tick >= self.tick_node_count or \
                (now - self._last_tick_at) >= self.tick_interval_sec:
            result = self._evaporate_locked(now)
            return result["records"]
        return []

    # ---------- 无环校验（复用 TaskGraph.validate 的 DFS 思路） ----------

    def _would_create_cycle(self, source_id: str, target_id: str) -> bool:
        """添加 source→target 边会成环 ⇔ 当前图中 target 可达 source。

        思路同 `TaskGraph.validate` 的 DFS 环检测（kali_mcp/core/task_decomposer.py），
        此处改为增量式可达性判断（新边加入前的图是无环的）。
        """
        if source_id == target_id:
            return True
        stack: List[str] = [target_id]
        visited: Set[str] = set()
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            for eid in self._out_edges.get(cur, ()):
                nxt = self._edges[eid].target_id
                if nxt == source_id:
                    return True
                stack.append(nxt)
        return False

    def validate(self, session_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """全图校验（复用 TaskGraph.validate 的 DFS visited/rec_stack 思路）：
        环检测 + 悬空边端点检测。返回 (ok, errors)。"""
        errors: List[str] = []
        sid = session_id or self.session_id
        sub_nodes = {nid for nid, n in self._nodes.items() if n.session_id == sid}

        # 环检测（DFS + 递归栈，同 TaskGraph.validate）
        visited: Set[str] = set()
        rec_stack: Set[str] = set()

        def has_cycle(node_id: str) -> bool:
            visited.add(node_id)
            rec_stack.add(node_id)
            for eid in self._out_edges.get(node_id, ()):
                neighbor = self._edges[eid].target_id
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            rec_stack.remove(node_id)
            return False

        for nid in sub_nodes:
            if nid not in visited and has_cycle(nid):
                errors.append(f"检测到环: {nid}")

        # 悬空边 / 越会话引用
        for e in self._edges.values():
            if e.session_id != sid:
                continue
            if e.source_id not in sub_nodes or e.target_id not in sub_nodes:
                errors.append(f"边 {e.edge_id} 引用了不存在或跨会话的节点")
        return len(errors) == 0, errors

    # ---------- 读接口（§4.2，供 LLM 输入的视图） ----------

    def get_node(self, node_id: str, session_id: Optional[str] = None) -> Optional[DAGNode]:
        n = self._nodes.get(node_id)
        if n is None:
            return None
        if (session_id or self.session_id) != n.session_id:
            return None
        return n

    def get_edge(self, edge_id: str, session_id: Optional[str] = None) -> Optional[DAGEdge]:
        e = self._edges.get(edge_id)
        if e is None:
            return None
        if (session_id or self.session_id) != e.session_id:
            return None
        return e

    def get_outgoing_edges(self, node_id: str, session_id: Optional[str] = None) -> List[DAGEdge]:
        """节点 n 的出边（ACO 的候选边集合 C(n)，§5.4）。"""
        node = self._nodes.get(node_id)
        if node is None:
            return []
        sid = session_id or node.session_id
        return [self._edges[eid] for eid in self._out_edges.get(node_id, ())
                if self._edges[eid].session_id == sid]

    def get_incoming_edges(self, node_id: str, session_id: Optional[str] = None) -> List[DAGEdge]:
        node = self._nodes.get(node_id)
        if node is None:
            return []
        sid = session_id or node.session_id
        return [self._edges[eid] for eid in self._in_edges.get(node_id, ())
                if self._edges[eid].session_id == sid]

    def get_subgraph(self, node_id: str, depth: int = 1,
                     session_id: Optional[str] = None) -> Dict[str, Any]:
        """以 node_id 为根的 BFS 出边子图（depth 层），返回 {nodes, edges}（含根节点）。"""
        node = self._nodes.get(node_id)
        if node is None:
            return {"node_id": node_id, "depth": depth, "nodes": [], "edges": []}
        sid = session_id or node.session_id
        seen_nodes: List[str] = [node_id]
        seen_edges: List[str] = []
        frontier: List[str] = [node_id]
        for _ in range(max(0, int(depth))):
            nxt: List[str] = []
            for cur in frontier:
                for eid in self._out_edges.get(cur, ()):
                    e = self._edges[eid]
                    if e.session_id != sid or eid in seen_edges:
                        continue
                    seen_edges.append(eid)
                    if e.target_id not in seen_nodes:
                        seen_nodes.append(e.target_id)
                        nxt.append(e.target_id)
            frontier = nxt
        return {
            "node_id": node_id,
            "depth": depth,
            "session_id": sid,
            "nodes": [self._nodes[i].to_dict() for i in seen_nodes],
            "edges": [self._edges[i].to_dict() for i in seen_edges],
        }

    def get_frontier(self, max_hypotheses: int = 20,
                     session_id: Optional[str] = None) -> List[FrontierEdge]:
        """前沿候选边：优先取 hypothesis 节点的出边（决策点），无 hypothesis 时退回
        全部节点出边；按 τ 降序，截断到 max_hypotheses 条。"""
        sid = session_id or self.session_id
        hyps = [n.node_id for n in self._nodes.values()
                if n.session_id == sid and n.node_type == "hypothesis"]
        seeds = hyps if hyps else [n.node_id for n in self._nodes.values() if n.session_id == sid]
        cand: List[FrontierEdge] = []
        for src in seeds:
            for eid in self._out_edges.get(src, ()):
                e = self._edges[eid]
                if e.session_id != sid:
                    continue
                cand.append(FrontierEdge(
                    edge=e,
                    source=self._nodes.get(e.source_id),
                    target=self._nodes.get(e.target_id),
                ))
        cand.sort(key=lambda fe: fe.edge.tau, reverse=True)
        return cand[: max(0, int(max_hypotheses))]

    def get_pheromone_view(self, agent_role: str = "", limit: int = 10,
                           session_id: Optional[str] = None) -> Dict[str, Any]:
        """按 agent_role 相关边类型过滤、按 τ 降序取 top-limit 的压缩视图（供 LLM 输入）。"""
        sid = session_id or self.session_id
        rel = role_relevant_edge_types(agent_role)
        session_edges = [e for e in self._edges.values() if e.session_id == sid]
        edges = [e for e in session_edges if e.edge_type in rel]
        edges.sort(key=lambda e: e.tau, reverse=True)
        top = edges[: max(0, int(limit))]
        taus = [e.tau for e in edges]
        return {
            "session_id": sid,
            "agent_role": agent_role,
            "updated_at": time.time(),
            "edges": [{
                "edge_id": e.edge_id,
                "edge_type": e.edge_type,
                "source_id": e.source_id,
                "target_id": e.target_id,
                "tau": round(e.tau, 4),
                "weight": e.weight,
                "target_label": self._nodes.get(e.target_id).label if e.target_id in self._nodes else "",
            } for e in top],
            "stats": {
                "nodes": sum(1 for n in self._nodes.values() if n.session_id == sid),
                "edges": len(session_edges),
                "role_relevant_edges": len(edges),
                "tau_max": round(max(taus), 4) if taus else 0.0,
                "tau_min": round(min(taus), 4) if taus else 0.0,
            },
        }

    def wipe_session(self, session_id: str) -> Dict[str, int]:
        """删除某会话的全部节点/边/信息素（痕迹清理，会话级）。

        - 同时清理内存态（_nodes/_edges/_out_edges/_in_edges）与 sqlite 镜像
          （nodes/edges/pheromone 三表 DELETE WHERE session_id=?）。
        - 与 _load/_persist 走同一存储路径；幂等：不存在的 session 返回 0。
        - 返回 {nodes, edges, pheromone} 各删除行数。
        """
        sid = session_id or self.session_id
        counts = {"nodes": 0, "edges": 0, "pheromone": 0}

        # 1) 内存态
        node_ids = [nid for nid, n in self._nodes.items() if n.session_id == sid]
        edge_ids = [eid for eid, e in self._edges.items() if e.session_id == sid]
        for eid in edge_ids:
            self._out_edges.pop(eid, None)
            self._in_edges.pop(eid, None)
        for eid in edge_ids:
            self._edges.pop(eid, None)
            # 邻接表里可能残留对已删边的引用（防御性清理）
            for lst in list(self._out_edges.values()):
                if eid in lst:
                    lst.remove(eid)
            for lst in list(self._in_edges.values()):
                if eid in lst:
                    lst.remove(eid)
        for nid in node_ids:
            self._nodes.pop(nid, None)
            self._out_edges.pop(nid, None)
            self._in_edges.pop(nid, None)
        counts["nodes"] = len(node_ids)
        counts["edges"] = len(edge_ids)

        # 2) sqlite 镜像（best-effort；内存态已清，落库失败不阻断）
        if self._db is not None:
            try:
                for table in ("nodes", "edges", "pheromone"):
                    cur = self._db.execute(
                        f"DELETE FROM {table} WHERE session_id=?", (sid,)
                    )
                    counts[table] = int(cur.rowcount)
                self._db.commit()
            except Exception as e:  # noqa: BLE001 —— 清理失败仅记录
                logger.warning("[DAGService] wipe_session %s 落库失败: %s", sid, e)

        return counts

    def node_count(self, session_id: Optional[str] = None) -> int:
        sid = session_id or self.session_id
        return sum(1 for n in self._nodes.values() if n.session_id == sid)

    def edge_count(self, session_id: Optional[str] = None) -> int:
        sid = session_id or self.session_id
        return sum(1 for e in self._edges.values() if e.session_id == sid)

    def snapshot_hash(self) -> str:
        """状态快照哈希（节点/边/τ 全量），用于 dag.updated 的变更指纹。"""
        parts: List[str] = []
        for n in self._nodes.values():
            parts.append(f"n:{n.node_id}:{n.node_type}:{n.session_id}")
        for e in self._edges.values():
            parts.append(f"e:{e.edge_id}:{e.source_id}->{e.target_id}:{e.edge_type}:{e.tau:.6f}")
        digest = hashlib.sha256("\n".join(sorted(parts)).encode("utf-8")).hexdigest()
        return digest
