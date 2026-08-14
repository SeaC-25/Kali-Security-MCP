#!/usr/bin/env python3
"""
攻击 DAG + 蚁群算法 ACO 单元测试（架构设计 §4 / §5，P2 阶段）。

覆盖验收标准：
- 沉积单调有界（τ 始终 ∈ [0.05, 1.0]）
- 蒸发收敛（多 tick 后 τ 逼近下界 0.05）
- P(e) 归一化（ΣP = 1）
- 无环不变式（非法回边被拒）
- 并发写入串行化（并发 add 不破坏状态）
- sqlite 落盘重载一致
- 最小端到端演示：构造节点 + 边，沉积信息素，recommend_next top-k 按 P 降序、
  τ/η/P 分解值正确（与手算一致）
"""

from __future__ import annotations

import asyncio
import json
import sqlite3

import pytest

from kali_mcp.core.event_bus import EventBus
from kali_mcp.reasoning.aco import (
    ACO,
    HEURISTIC_W,
    PHEROMONE_INIT,
    PHEROMONE_MAX,
    PHEROMONE_MIN,
    SEV_WEIGHTS,
    deposit_delta,
    evaporate_tau,
)
from kali_mcp.reasoning.attack_dag import (
    CycleError,
    DAGEdge,
    DAGNode,
    DAGService,
    InvalidEdgeError,
    InvalidNodeTypeError,
    UnknownNodeError,
)

SID = "s-test"


def _run(coro):
    """同步测试内运行协程（避免 pytest-asyncio 依赖）。"""
    return asyncio.run(coro)


# ==================== 信息素：沉积（§5.1） ====================

class TestDeposit:
    def test_deposit_monotonic_bounded(self):
        """沉积单调有界：τ 单调不减且始终 ∈ [0.05, 1.0]，顶到上限 1.0 封顶。"""
        aco = ACO(deposit_rate=0.15)
        edges = [
            DAGEdge(edge_id="e0", edge_type="yields", source_id="a1", target_id="o1", session_id=SID),
            DAGEdge(edge_id="e1", edge_type="yields", source_id="a1", target_id="o2", session_id=SID),
            DAGEdge(edge_id="e2", edge_type="enables", source_id="f1", target_id="h2", session_id=SID),
        ]
        aco.load_edges(edges)

        async def go():
            prev = [PHEROMONE_INIT] * 3
            for _ in range(200):
                recs = await aco.deposit(["e0", "e1", "e2"], success_signal=1.0, severity="CRITICAL")
                assert len(recs) == 3
                for i, r in enumerate(recs):
                    assert r["old_tau"] == prev[i]          # 顺序返回
                    assert r["new_tau"] >= r["old_tau"]     # 单调不减
                    assert PHEROMONE_MIN <= r["new_tau"] <= PHEROMONE_MAX
                    prev[i] = r["new_tau"]
            # CRITICAL + signal=1.0 → Δ=0.15·1·(1+1.0)=0.3，多轮后必然封顶
            assert all(e.tau == PHEROMONE_MAX for e in edges)
            # 封顶后再沉积仍 ≤ 1.0
            recs = await aco.deposit(["e0"], success_signal=1.0, severity="CRITICAL")
            assert recs[0]["new_tau"] == PHEROMONE_MAX

        _run(go())

    def test_deposit_delta_math(self):
        """Δτ = deposit_rate · success_signal · (1 + sev_weight)（§5.1 逐条落实）。"""
        assert deposit_delta(1.0, "CRITICAL") == pytest.approx(0.15 * 1.0 * (1 + 1.0))
        assert deposit_delta(1.0, "HIGH") == pytest.approx(0.15 * 1.0 * (1 + 0.6))
        assert deposit_delta(0.5, "MEDIUM") == pytest.approx(0.15 * 0.5 * (1 + 0.3))
        assert deposit_delta(1.0, "LOW") == pytest.approx(0.15 * 1.0 * (1 + 0.1))
        assert deposit_delta(1.0, "INFO") == pytest.approx(0.15 * 1.0 * (1 + 0.0))
        # success_signal=0 → 无沉积；越界信号裁剪到 [0,1]
        assert deposit_delta(0.0, "CRITICAL") == 0.0
        assert deposit_delta(2.0, "CRITICAL") == deposit_delta(1.0, "CRITICAL")
        assert SEV_WEIGHTS["CRITICAL"] == 1.0 and SEV_WEIGHTS["HIGH"] == 0.6
        assert SEV_WEIGHTS["MEDIUM"] == 0.3 and SEV_WEIGHTS["LOW"] == 0.1 and SEV_WEIGHTS["INFO"] == 0.0

    def test_deposit_dag_mode_persists(self, tmp_path):
        """dag 形态：ACO.deposit 经 DAGService 单一写入者落库，τ 持久化到 pheromone 表。"""
        dag = DAGService(db_path=str(tmp_path / "d.sqlite"), session_id=SID)
        aco = ACO(dag=dag)
        _run(dag.apply("add_node", {"node_id": "a1", "node_type": "attack_action"}))
        _run(dag.apply("add_node", {"node_id": "o1", "node_type": "observation"}))
        _run(dag.apply("add_edge", {"edge_id": "e1", "edge_type": "yields",
                                    "source_id": "a1", "target_id": "o1"}))
        recs = _run(aco.deposit(["e1"], success_signal=0.9, severity="HIGH"))
        assert len(recs) == 1
        assert recs[0]["old_tau"] == pytest.approx(PHEROMONE_INIT)
        assert recs[0]["new_tau"] == pytest.approx(PHEROMONE_INIT + 0.15 * 0.9 * (1 + 0.6))
        # 落盘：pheromone 表里就是沉积后的值（直查文件库）
        conn = sqlite3.connect(str(tmp_path / "d.sqlite"))
        row = conn.execute("SELECT tau FROM pheromone WHERE edge_id='e1'").fetchone()
        conn.close()
        assert row[0] == pytest.approx(recs[0]["new_tau"])
        assert dag.get_edge("e1").tau == pytest.approx(recs[0]["new_tau"])


# ==================== 信息素：蒸发（§5.2） ====================

class TestEvaporation:
    def test_evaporation_converges_to_floor(self):
        """蒸发收敛：多 tick 后 τ 逼近下界 0.05，且全程单调不增、不低于 0.05。"""
        aco = ACO(rho=0.10)
        e = DAGEdge(edge_id="e1", edge_type="yields", source_id="a1",
                    target_id="o1", session_id=SID, tau=0.9)
        aco.load_edges([e])
        prev = e.tau
        seen_floor = False
        for i in range(300):
            _run(aco.evaporate(now=1000.0 + i))
            assert e.tau <= prev + 1e-12, "蒸发必须单调不增"
            assert e.tau >= PHEROMONE_MIN, "τ 不得低于下界 0.05"
            if e.tau == PHEROMONE_MIN:
                seen_floor = True
            prev = e.tau
        assert seen_floor, "足够多 tick 后 τ 必须收敛到下界"
        assert e.tau == pytest.approx(PHEROMONE_MIN, abs=1e-12)

    def test_evaporate_tau_math(self):
        """τ ← max(0.05, (1 − ρ)·τ)，ρ=0.10（§5.2）。"""
        assert evaporate_tau(0.9, 0.10) == pytest.approx(0.81)
        assert evaporate_tau(0.1, 0.10) == pytest.approx(0.09)
        assert evaporate_tau(0.06, 0.10) == pytest.approx(0.054)
        assert evaporate_tau(0.05, 0.10) == pytest.approx(PHEROMONE_MIN)  # 下界截断

    def test_auto_tick_node_count(self, tmp_path):
        """TICK：每新增 5 个节点触发一次蒸发（此处 tick_node_count=1 → 每加 1 节点蒸发）。"""
        dag = DAGService(db_path=str(tmp_path / "t.sqlite"), session_id=SID, tick_node_count=1)
        _run(dag.apply("add_node", {"node_id": "a1", "node_type": "attack_action"}))
        _run(dag.apply("add_node", {"node_id": "o1", "node_type": "observation"}))
        _run(dag.apply("add_edge", {"edge_id": "e1", "edge_type": "yields",
                                    "source_id": "a1", "target_id": "o1", "tau": 0.9}))
        taus = [0.9]
        for i in range(5):
            _run(dag.apply("add_node", {"node_id": f"x{i}", "node_type": "observation"}))
            t = dag.get_edge("e1").tau
            assert t <= taus[-1] + 1e-12
            assert t >= PHEROMONE_MIN
            taus.append(t)
        # 5 次 tick 蒸发：0.9 · 0.9^5
        assert taus[-1] == pytest.approx(0.9 * (0.9 ** 5), abs=1e-12)

    def test_auto_tick_interval(self, tmp_path):
        """TICK：距上次蒸发 ≥ 60s（此处 interval=0 → 每次写操作都到时间阈值）触发蒸发。"""
        dag = DAGService(db_path=str(tmp_path / "t2.sqlite"), session_id=SID, tick_interval_sec=0.0)
        _run(dag.apply("add_node", {"node_id": "a1", "node_type": "attack_action"}))
        _run(dag.apply("add_node", {"node_id": "o1", "node_type": "observation"}))
        _run(dag.apply("add_edge", {"edge_id": "e1", "edge_type": "yields",
                                    "source_id": "a1", "target_id": "o1", "tau": 0.9}))
        # add_edge 自身即触发一次时间蒸发
        assert dag.get_edge("e1").tau == pytest.approx(0.81, abs=1e-12)
        _run(dag.apply("add_node", {"node_id": "o2", "node_type": "observation"}))
        assert dag.get_edge("e1").tau == pytest.approx(0.9 * 0.9 ** 2, abs=1e-12)


# ==================== 选路：P(e) 归一化（§5.4） ====================

class TestSelection:
    def _mk(self, specs):
        return [DAGEdge(edge_id=eid, edge_type=spec[1], source_id=spec[2],
                        target_id=spec[3], session_id=SID, tau=spec[4],
                        meta=spec[5] if len(spec) > 5 else {}) for eid, *spec in specs]

    def test_probability_normalized_and_manual_recompute(self):
        """P(e) = τ^α·η^β / Σ，ΣP=1；τ/η/P 与手算一致（α=1，β=2）。"""
        edges = [
            DAGEdge("e1", "drives", "h1", "a1", SID, tau=0.8,
                    meta={"severity_norm": 0.9, "kb_sim": 0.7, "target_rel": 0.5}),
            DAGEdge("e2", "drives", "h1", "a2", SID, tau=0.3,
                    meta={"severity_norm": 0.2, "kb_sim": 0.1}),
            DAGEdge("e3", "drives", "h1", "a3", SID, tau=0.1, meta={}),
        ]
        aco = ACO(alpha=1, beta=2)
        aco.load_edges(edges)
        scores = aco.compute_scores("h1")
        assert len(scores) == 3
        assert sum(s.p for s in scores) == pytest.approx(1.0, abs=1e-9)

        # 手算 η（§5.3：w=[0.4,0.3,0.2,0.05,0.05]）
        def eta(sev, kb, rel, cost=0.0, fail=0.0):
            return (0.4 * sev + 0.3 * kb + 0.2 * rel - 0.05 * cost - 0.05 * fail)
        eta1, eta2, eta3 = eta(0.9, 0.7, 0.5), eta(0.2, 0.1, 0.0), eta(0.0, 0.0, 0.0)
        assert eta1 == pytest.approx(0.67)
        assert eta2 == pytest.approx(0.11)
        assert eta3 == 0.0
        raw1, raw2, raw3 = 0.8 * eta1 ** 2, 0.3 * eta2 ** 2, 0.1 * eta3 ** 2
        denom = raw1 + raw2 + raw3
        expected = {"e1": raw1 / denom, "e2": raw2 / denom, "e3": raw3 / denom}
        by_id = {s.edge_id: s for s in scores}
        for eid, p in expected.items():
            assert by_id[eid].p == pytest.approx(p, abs=1e-9), f"{eid} P 手算不符"
        assert by_id["e3"].p == 0.0  # η=0 → P=0
        assert by_id["e1"].eta == pytest.approx(eta1)
        assert by_id["e1"].components["severity_norm"] == pytest.approx(0.9)
        assert by_id["e1"].components["kb_sim"] == pytest.approx(0.7)
        assert by_id["e1"].components["target_rel"] == pytest.approx(0.5)

    def test_probability_normalized_all_zero_eta(self):
        """启发式全 0（无任何 meta 字段）→ 退化为 τ 主导，仍 ΣP=1。"""
        aco = ACO()
        aco.load_edges([
            DAGEdge("e1", "drives", "h1", "a1", SID, tau=0.5),
            DAGEdge("e2", "drives", "h1", "a2", SID, tau=0.2),
        ])
        scores = aco.compute_scores("h1")
        assert sum(s.p for s in scores) == pytest.approx(1.0, abs=1e-9)
        # τ 主导：e1(0.5) 概率高于 e2(0.2)：P = τ/Στ = 0.5/0.7
        assert scores[0].p == pytest.approx(0.5 / 0.7, abs=1e-9)
        assert scores[0].eta == 1.0  # 兜底均匀启发式

    def test_recommend_next_topk_sorted_by_p(self):
        aco = ACO()
        aco.load_edges([
            DAGEdge("e1", "drives", "h1", "a1", SID, tau=0.1,
                    meta={"severity": "LOW", "kb_sim": 0.4, "target_rel": 0.5,
                          "cost_norm": 0.1, "fail_rate": 0.2}),
            DAGEdge("e2", "drives", "h1", "a2", SID, tau=0.34,
                    meta={"severity": "HIGH", "kb_sim": 0.8, "target_rel": 0.9,
                          "cost_norm": 0.3, "fail_rate": 0.4}),
            DAGEdge("e3", "drives", "h1", "a3", SID, tau=0.34,
                    meta={"severity": "CRITICAL", "kb_sim": 0.6, "target_rel": 0.4,
                          "cost_norm": 0.5, "fail_rate": 0.3}),
        ])
        scores = aco.recommend_next("h1", agent_role="web_vuln_agent", k=2)
        assert [s.edge_id for s in scores] == ["e2", "e3"]  # 按 P 降序
        assert scores[0].p >= scores[1].p
        for s in scores:
            assert PHEROMONE_MIN <= s.tau <= PHEROMONE_MAX
            assert 0.0 <= s.eta <= 1.0
            assert 0.0 <= s.p <= 1.0
        # 角色过滤：非 web 相关角色（如 recon_agent 只认 evidence/yields）→ drives 边被滤掉
        assert aco.recommend_next("h1", agent_role="recon_agent", k=5) == []

    def test_select_next_roulette_deterministic(self):
        """轮盘赌采样：种子固定 → 结果确定；采样值 ∈ 候选边集合且 P 分布偏向高 P 边。"""
        import random
        edges = [
            DAGEdge("e1", "drives", "h1", "a1", SID, tau=0.1, meta={"severity_norm": 0.1}),
            DAGEdge("e2", "drives", "h1", "a2", SID, tau=0.9, meta={"severity_norm": 0.9}),
            DAGEdge("e3", "drives", "h1", "a3", SID, tau=0.5, meta={"severity_norm": 0.5}),
        ]
        rng = random.Random(42)
        aco = ACO(rng=rng)
        aco.load_edges(edges)
        picks = [aco.select_next("h1").edge_id for _ in range(1000)]
        # 确定性：同种子复现
        rng2 = random.Random(42)
        aco2 = ACO(rng=rng2)
        aco2.load_edges(edges)
        picks2 = [aco2.select_next("h1").edge_id for _ in range(1000)]
        assert picks == picks2
        # 分布偏向高 P 边 e2
        from collections import Counter
        cnt = Counter(picks)
        assert cnt["e2"] > cnt["e3"] > cnt["e1"]
        assert set(cnt) <= {"e1", "e2", "e3"}


# ==================== 无环不变量（§4.2） ====================

class TestAcyclicInvariant:
    def _build(self):
        dag = DAGService(db_path=":memory:", session_id=SID)
        _run(dag.apply("add_node", {"node_id": "n1", "node_type": "observation", "label": "port 80"}))
        _run(dag.apply("add_node", {"node_id": "h1", "node_type": "hypothesis"}))
        _run(dag.apply("add_node", {"node_id": "a1", "node_type": "attack_action"}))
        _run(dag.apply("add_node", {"node_id": "s1", "node_type": "summary"}))
        _run(dag.apply("add_edge", {"edge_id": "e1", "edge_type": "evidence",
                                    "source_id": "n1", "target_id": "h1"}))
        _run(dag.apply("add_edge", {"edge_id": "e2", "edge_type": "drives",
                                    "source_id": "h1", "target_id": "a1"}))
        return dag

    def test_rejects_reverse_edges(self):
        """反向边被拒：evidence 要求 observation→hypothesis，hypothesis→observation 非法。"""
        dag = self._build()
        with pytest.raises(InvalidEdgeError):
            _run(dag.apply("add_edge", {"edge_id": "bad", "edge_type": "evidence",
                                        "source_id": "h1", "target_id": "n1"}))
        with pytest.raises(InvalidEdgeError):
            _run(dag.apply("add_edge", {"edge_id": "bad2", "edge_type": "drives",
                                        "source_id": "a1", "target_id": "h1"}))
        assert dag.get_edge("bad") is None and dag.get_edge("bad2") is None

    def test_rejects_cycles(self):
        """回边被拒：n1→h1→a1 已有，a1→n1 (yields 方向合法) 会成环 → CycleError。"""
        dag = self._build()
        with pytest.raises(CycleError):
            _run(dag.apply("add_edge", {"edge_id": "e3", "edge_type": "yields",
                                        "source_id": "a1", "target_id": "n1"}))
        assert dag.get_edge("e3") is None
        ok, errors = dag.validate()
        assert ok and errors == []

    def test_rejects_self_loop(self):
        dag = self._build()
        with pytest.raises(InvalidEdgeError):
            _run(dag.apply("add_edge", {"edge_id": "loop", "edge_type": "contains",
                                        "source_id": "s1", "target_id": "s1"}))
        assert dag.get_edge("loop") is None

    def test_rejects_unknown_nodes_and_types(self):
        dag = self._build()
        with pytest.raises(UnknownNodeError):
            _run(dag.apply("add_edge", {"edge_id": "x", "edge_type": "evidence",
                                        "source_id": "ghost", "target_id": "h1"}))
        with pytest.raises(InvalidNodeTypeError):
            _run(dag.apply("add_node", {"node_id": "x", "node_type": "banana"}))
        with pytest.raises(InvalidEdgeError):
            _run(dag.apply("add_edge", {"edge_id": "x2", "edge_type": "teleport",
                                        "source_id": "n1", "target_id": "h1"}))

    def test_dag_remains_valid_after_legal_growth(self):
        dag = self._build()
        _run(dag.apply("add_node", {"node_id": "f1", "node_type": "finding"}))
        _run(dag.apply("add_node", {"node_id": "h2", "node_type": "hypothesis"}))
        _run(dag.apply("add_edge", {"edge_id": "e4", "edge_type": "enables",
                                    "source_id": "f1", "target_id": "h2"}))  # finding→hypothesis 合法
        ok, errors = dag.validate()
        assert ok and errors == []


# ==================== 并发写入串行化（§4.2） ====================

class TestConcurrency:
    def test_concurrent_writes_serialized(self, tmp_path):
        """两个并发 add 不破坏状态：30 并发节点 + 30 并发边，全部落库且图仍无环。"""
        dag = DAGService(db_path=str(tmp_path / "c.sqlite"), session_id=SID)

        async def go():
            await dag.apply("add_node", {"node_id": "h0", "node_type": "hypothesis"})
            async def add_node(i):
                return await dag.apply("add_node", {
                    "node_id": f"n{i}", "node_type": "observation", "meta": {"i": i}})
            results = await asyncio.gather(*[add_node(i) for i in range(30)])
            assert all(r["created"] for r in results)
            assert dag.node_count() == 31
            assert dag.get_node("n29").meta["i"] == 29

            async def add_edge(i):
                return await dag.apply("add_edge", {
                    "edge_id": f"e{i}", "edge_type": "evidence",
                    "source_id": f"n{i}", "target_id": "h0"})
            await asyncio.gather(*[add_edge(i) for i in range(30)])
            assert dag.edge_count() == 30
            ok, errors = dag.validate()
            assert ok and errors == []
            # 与顺序写入等价
            expected = {f"n{i}": f"e{i}" for i in range(30)}
            for nid, eid in expected.items():
                e = dag.get_edge(eid)
                assert e.source_id == nid and e.target_id == "h0"

        _run(go())

    def test_concurrent_deposit_atomic(self, tmp_path):
        """并发沉积：Δτ 串行应用，最终 τ = min(1.0, τ₀ + n·Δ)，无丢失更新。"""
        dag = DAGService(db_path=str(tmp_path / "cd.sqlite"), session_id=SID)
        _run(dag.apply("add_node", {"node_id": "a1", "node_type": "attack_action"}))
        _run(dag.apply("add_node", {"node_id": "o1", "node_type": "observation"}))
        _run(dag.apply("add_edge", {"edge_id": "e1", "edge_type": "yields",
                                    "source_id": "a1", "target_id": "o1"}))
        delta = 0.15 * 0.8 * (1 + 0.6)  # signal=0.8, HIGH

        async def go():
            await asyncio.gather(*[
                dag.apply("deposit", {"edge_ids": ["e1"], "success_signal": 0.8, "severity": "HIGH"})
                for _ in range(10)])
        _run(go())
        expected = min(PHEROMONE_MAX, PHEROMONE_INIT + 10 * delta)
        assert dag.get_edge("e1").tau == pytest.approx(expected, abs=1e-12)


# ==================== sqlite 落盘 / 重载 / 会话隔离（§4.2） ====================

class TestPersistence:
    def test_sqlite_persistence_reload(self, tmp_path):
        """落盘 → 新实例重载：节点/边/τ/快照哈希一致。"""
        db = str(tmp_path / "dag.sqlite")
        dag = DAGService(db_path=db, session_id=SID)
        _run(dag.apply("add_node", {"node_id": "n1", "node_type": "observation", "label": "p80"}))
        _run(dag.apply("add_node", {"node_id": "h1", "node_type": "hypothesis", "label": "phpmyadmin"}))
        _run(dag.apply("add_edge", {"edge_id": "e1", "edge_type": "evidence",
                                    "source_id": "n1", "target_id": "h1", "meta": {"kb_sim": 0.6}}))
        _run(dag.apply("deposit", {"edge_ids": ["e1"], "success_signal": 0.9, "severity": "HIGH"}))
        tau1 = dag.get_edge("e1").tau
        snap1 = dag.snapshot_hash()
        assert tau1 == pytest.approx(PHEROMONE_INIT + 0.15 * 0.9 * (1 + 0.6))

        dag2 = DAGService(db_path=db, session_id=SID)
        assert dag2.get_node("n1").label == "p80"
        assert dag2.get_node("h1").label == "phpmyadmin"
        assert dag2.get_edge("e1").tau == pytest.approx(tau1)
        assert dag2.get_edge("e1").meta["kb_sim"] == 0.6
        assert dag2.snapshot_hash() == snap1
        ok, errors = dag2.validate()
        assert ok and errors == []

        # 表结构：nodes / edges / pheromone
        conn = sqlite3.connect(db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"nodes", "edges", "pheromone"} <= tables
        conn.close()

    def test_session_isolation(self, tmp_path):
        """按 session_id 隔离：不同会话互不可见；自动 id 全局唯一；显式 id 跨会话冲突报错。"""
        db = str(tmp_path / "iso.sqlite")
        dag_a = DAGService(db_path=db, session_id="s-a")
        _run(dag_a.apply("add_node", {"node_id": "n1", "node_type": "observation"}))
        _run(dag_a.apply("add_node", {"node_id": "h1", "node_type": "hypothesis"}))
        _run(dag_a.apply("add_edge", {"edge_id": "e1", "edge_type": "evidence",
                                      "source_id": "n1", "target_id": "h1"}))
        _run(dag_a.apply("deposit", {"edge_ids": ["e1"], "success_signal": 1.0, "severity": "HIGH"}))

        dag_b = DAGService(db_path=db, session_id="s-b")
        assert dag_b.node_count() == 0 and dag_b.edge_count() == 0
        assert dag_b.get_node("n1") is None
        assert dag_b.get_pheromone_view()["edges"] == []
        # B 会话写自己的数据：自动 id 全局唯一（不会与 s-a 的 n1 冲突）
        node_b = _run(dag_b.apply("add_node", {"node_type": "finding", "label": "b"}))["node"]
        assert node_b["node_id"] not in ("n1", "h1")
        assert dag_b.get_node(node_b["node_id"]).label == "b"
        assert dag_a.get_node(node_b["node_id"]) is None  # A 看不到 B 的节点
        # 显式复用他会话的 id → 冲突报错（id 为全局引用，如 dag.node.n102）
        from kali_mcp.reasoning.attack_dag import DAGError
        with pytest.raises(DAGError):
            _run(dag_b.apply("add_node", {"node_id": "n1", "node_type": "observation"}))
        # 重载后仍隔离
        dag_a2 = DAGService(db_path=db, session_id="s-a")
        assert dag_a2.node_count() == 2 and dag_a2.edge_count() == 1
        assert dag_a2.get_pheromone_view()["edges"][0]["edge_id"] == "e1"
        assert DAGService(db_path=db, session_id="s-b").node_count() == 1


# ==================== EventBus 集成（§4.2 单一写入者） ====================

class TestEventBusIntegration:
    def test_bus_command_apply_and_dag_updated(self):
        """订阅 dag.command 事件串行 apply；成功落库后 emit dag.updated（含 snapshot_hash）。"""
        bus = EventBus()
        dag = DAGService(db_path=":memory:", session_id=SID, bus=bus)
        dag.register(bus)

        async def go():
            bus.emit("dag.command", {
                "op": "add_node",
                "payload": {"node_id": "n1", "node_type": "observation", "label": "via bus"},
            })
            for _ in range(200):
                if dag.get_node("n1") is not None:
                    break
                await asyncio.sleep(0.01)
            assert dag.get_node("n1") is not None
            assert dag.get_node("n1").label == "via bus"
            # 事件循环：emit 是同步的（handler 线程内 asyncio.run 已执行完）
            events = bus.get_recent_events("dag.updated", limit=10)
            assert any("snapshot_hash" in (e.get("data_keys") or []) for e in events)
            # 非法命令经总线也抛拒（不落库）
            bus.emit("dag.command", {
                "op": "add_edge",
                "payload": {"edge_id": "x", "edge_type": "evidence",
                            "source_id": "n1", "target_id": "ghost"},
            })
            await asyncio.sleep(0.05)
            assert dag.get_edge("x") is None

        _run(go())


# ==================== 读接口（§4.2） ====================

class TestReadAPI:
    def _build(self):
        dag = DAGService(db_path=":memory:", session_id=SID)
        _run(dag.apply("add_node", {"node_id": "n1", "node_type": "observation", "label": "p80"}))
        _run(dag.apply("add_node", {"node_id": "h1", "node_type": "hypothesis", "label": "phpmyadmin?"}))
        _run(dag.apply("add_node", {"node_id": "a1", "node_type": "attack_action", "label": "dir scan"}))
        _run(dag.apply("add_node", {"node_id": "f1", "node_type": "finding", "label": "SQLi high"}))
        _run(dag.apply("add_edge", {"edge_id": "e1", "edge_type": "evidence",
                                    "source_id": "n1", "target_id": "h1"}))
        _run(dag.apply("add_edge", {"edge_id": "e2", "edge_type": "drives",
                                    "source_id": "h1", "target_id": "a1"}))
        _run(dag.apply("add_edge", {"edge_id": "e3", "edge_type": "yields",
                                    "source_id": "a1", "target_id": "f1", "tau": 0.9}))
        _run(dag.apply("deposit", {"edge_ids": ["e2"], "success_signal": 1.0, "severity": "HIGH"}))
        return dag

    def test_get_subgraph_bfs_depth(self):
        dag = self._build()
        sub = dag.get_subgraph("h1", depth=1)
        assert {n["node_id"] for n in sub["nodes"]} == {"h1", "a1"}
        assert {e["edge_id"] for e in sub["edges"]} == {"e2"}
        sub2 = dag.get_subgraph("h1", depth=2)
        assert {n["node_id"] for n in sub2["nodes"]} == {"h1", "a1", "f1"}
        assert {e["edge_id"] for e in sub2["edges"]} == {"e2", "e3"}

    def test_get_frontier_hypothesis_edges(self):
        dag = self._build()
        frontier = dag.get_frontier(max_hypotheses=10)
        # 前沿 = hypothesis h1 的出边（drives），按 τ 降序：e2 被沉积过 → 优先
        assert [fe.edge.edge_id for fe in frontier] == ["e2"]
        assert frontier[0].source.node_id == "h1"
        assert frontier[0].target.node_id == "a1"

    def test_get_pheromone_view_role_filter(self):
        dag = self._build()
        view = dag.get_pheromone_view(agent_role="web_vuln_agent", limit=10)
        assert view["stats"]["nodes"] == 4
        assert view["stats"]["edges"] == 3            # 会话全量边
        assert view["stats"]["role_relevant_edges"] == 2  # drives/yields/enables
        # web_vuln_agent 相关边类型 drives/yields/enables → e2/e3
        assert {e["edge_id"] for e in view["edges"]} == {"e2", "e3"}
        # 按 τ 降序：e3(0.9) > e2(0.34)
        assert [e["edge_id"] for e in view["edges"]] == ["e3", "e2"]
        # recon_agent 只看 evidence/yields → e1/e3
        view_r = dag.get_pheromone_view(agent_role="recon_agent", limit=10)
        assert {e["edge_id"] for e in view_r["edges"]} == {"e1", "e3"}


# ==================== 端到端演示（验收项 2） ====================

class TestEndToEndDemo:
    def test_end_to_end_demo(self):
        """构造 6 节点 + 5 边 → 沉积信息素（回溯路径）→ recommend_next top-k 按 P 降序，
        τ/η/P 分解值与手算一致。"""
        dag = DAGService(db_path=":memory:", session_id=SID)
        aco = ACO(dag=dag)

        async def go():
            await dag.apply("add_node", {"node_id": "h1", "node_type": "hypothesis",
                                         "label": "/admin 可能是 phpMyAdmin"})
            await dag.apply("add_node", {"node_id": "a1", "node_type": "attack_action",
                                         "label": "fastsec_scan dir=/admin"})
            await dag.apply("add_node", {"node_id": "a2", "node_type": "attack_action",
                                         "label": "sqlmap GET /admin?id=1"})
            await dag.apply("add_node", {"node_id": "a3", "node_type": "attack_action",
                                         "label": "nmap -sV /admin"})
            await dag.apply("add_node", {"node_id": "o1", "node_type": "observation",
                                         "label": "phpMyAdmin 5.1"})
            await dag.apply("add_node", {"node_id": "f1", "node_type": "finding",
                                         "label": "SQLi at /admin (HIGH)"})
            # 三条 drives 候选（h1 → a1/a2/a3），meta 驱动启发式 η
            await dag.apply("add_edge", {"edge_id": "e1", "edge_type": "drives",
                                         "source_id": "h1", "target_id": "a1",
                                         "meta": {"severity": "LOW", "kb_sim": 0.4, "target_rel": 0.5,
                                                  "cost_norm": 0.1, "fail_rate": 0.2}})
            await dag.apply("add_edge", {"edge_id": "e2", "edge_type": "drives",
                                         "source_id": "h1", "target_id": "a2",
                                         "meta": {"severity": "HIGH", "kb_sim": 0.8, "target_rel": 0.9,
                                                  "cost_norm": 0.3, "fail_rate": 0.4}})
            await dag.apply("add_edge", {"edge_id": "e3", "edge_type": "drives",
                                         "source_id": "h1", "target_id": "a3",
                                         "meta": {"severity": "CRITICAL", "kb_sim": 0.6, "target_rel": 0.4,
                                                  "cost_norm": 0.5, "fail_rate": 0.3}})
            # 产出边
            await dag.apply("add_edge", {"edge_id": "e4", "edge_type": "yields",
                                         "source_id": "a1", "target_id": "o1"})
            await dag.apply("add_edge", {"edge_id": "e5", "edge_type": "yields",
                                         "source_id": "a2", "target_id": "f1"})

            # ---- 沉积：f1 被 verifier 判定成功（HIGH, signal=1.0），沿路径回溯 ----
            recs = await aco.deposit_path("f1", success_signal=1.0, severity="HIGH")
            deposited = {r["edge_id"]: r for r in recs}
            assert set(deposited) == {"e5", "e2"}  # f1←e5←a2←e2←h1
            assert deposited["e5"]["new_tau"] == pytest.approx(
                PHEROMONE_INIT + 0.15 * 1.0 * (1 + 0.6))
            assert deposited["e2"]["new_tau"] == pytest.approx(
                PHEROMONE_INIT + 0.15 * 1.0 * (1 + 0.6))
            assert dag.get_edge("e1").tau == pytest.approx(PHEROMONE_INIT)  # 未涉及路径

            # ---- recommend_next(h1, web_vuln_agent, k=3)：top-k 按 P 降序 ----
            scores = aco.recommend_next("h1", agent_role="web_vuln_agent", k=3)
            assert [s.edge_id for s in scores] == ["e2", "e3", "e1"]
            assert scores[0].p >= scores[1].p >= scores[2].p

            # ---- 手算 τ/η/P 分解值（§5.3 / §5.4）----
            def eta(sev, kb, rel, cost, fail):
                return (0.4 * sev + 0.3 * kb + 0.2 * rel - 0.05 * cost - 0.05 * fail)

            w1, w2, w3, w4, w5 = HEURISTIC_W
            assert (w1, w2, w3, w4, w5) == (0.4, 0.3, 0.2, 0.05, 0.05)
            eta1 = eta(SEV_WEIGHTS["LOW"], 0.4, 0.5, 0.1, 0.2)
            eta2 = eta(SEV_WEIGHTS["HIGH"], 0.8, 0.9, 0.3, 0.4)
            eta3 = eta(SEV_WEIGHTS["CRITICAL"], 0.6, 0.4, 0.5, 0.3)
            assert eta1 == pytest.approx(0.245)
            assert eta2 == pytest.approx(0.625)
            assert eta3 == pytest.approx(0.62)
            tau1, tau2, tau3 = PHEROMONE_INIT, PHEROMONE_INIT + 0.24, PHEROMONE_INIT
            raw1, raw2, raw3 = tau1 * eta1 ** 2, tau2 * eta2 ** 2, tau3 * eta3 ** 2
            denom = raw1 + raw2 + raw3
            expected = {
                "e1": (tau1, eta1, raw1 / denom),
                "e2": (tau2, eta2, raw2 / denom),
                "e3": (tau3, eta3, raw3 / denom),
            }
            for s in scores:
                exp_tau, exp_eta, exp_p = expected[s.edge_id]
                assert s.tau == pytest.approx(exp_tau, abs=1e-12)
                assert s.eta == pytest.approx(exp_eta, abs=1e-12)
                assert s.p == pytest.approx(exp_p, abs=1e-9)
            assert sum(s.p for s in scores) == pytest.approx(1.0, abs=1e-9)

            # ---- 展示输出（验收报告用）----
            print("\n[E2E demo] session=%s  nodes=%d edges=%d" % (SID, dag.node_count(), dag.edge_count()))
            print("[E2E demo] deposit_path(f1, signal=1.0, HIGH) ->", json.dumps(deposited, indent=2))
            print("[E2E demo] recommend_next(h1, web_vuln_agent, k=3):")
            for s in scores:
                c = s.components
                print("  edge %s (%s→%s) %-7s P=%.4f τ=%.4f η=%.4f "
                      "[sev=%.2f kb=%.2f rel=%.2f cost=%.2f fail=%.2f]" % (
                          s.edge_id, s.source_id, s.target_id, s.edge_type, s.p, s.tau, s.eta,
                          c["severity_norm"], c["kb_sim"], c["target_rel"],
                          c["cost_norm"], c["fail_rate"]))

        _run(go())
