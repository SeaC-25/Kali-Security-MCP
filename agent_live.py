#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_live.py — 17-agent 渗透测试集群实时可视化执行器（纯展示层）

在终端实时、分色、结构化地展示 Kali MCP 多智能体集群
(AgentRegistry + MeshMessageBus + 17 agent + CoordinatorAgent) 执行一次
渗透测试请求的全过程：

    ① 意图分析 → ② 任务分解 → ③ 调度决策 → ④ 智能体执行 → ⑤ 结果聚合 → ⑥ 报告 → ⑦ 总结

数据来源（不改动仓库任何代码，全部为运行时 hook）：
  1. 集群各模块（logger 名 kali_mcp.*）的日志 → 实时格式化打印（阶段横幅 / agent 前缀 / 颜色）
  2. event_bus 的 tool.result 事件 → 工具执行结束（耗时 / 成败）实时打印
  3. coordinator 实例方法的运行时包装 → 任务清单 / 调度决策 / findings / 报告的结构化展示

用法:
  Windows: C:/Windows/py.exe -3 agent_live.py "任务描述" [--no-cache] [--timeout N] [--report-lines N] [--agents recon,web_vuln]
  POSIX:   python3 agent_live.py "任务描述" [--no-cache] [--timeout N]

--agents: 仅执行指定 agent（逗号分隔，按 agent_id 精确或前缀匹配，
          如 recon 匹配 recon_agent、web_vuln 匹配 web_vuln_agent）；
          缺省执行全部 17 个 agent。用于专业分工：每个专业 subagent
          只驱动自己的 agent。

示例:
  C:/Windows/py.exe -3 agent_live.py "对 http://localhost:8000/ 做 web 漏洞扫描：目录枚举、CMS识别、注入检测" --no-cache --timeout 300
  C:/Windows/py.exe -3 agent_live.py "对 http://localhost:8000/ 做端口和服务识别" --no-cache --timeout 300 --agents recon
  C:/Windows/py.exe -3 agent_live.py "对 http://localhost:8000/ 检测 SQL 注入和 XSS" --no-cache --timeout 300 --agents web_vuln
"""

import argparse
import ast
import asyncio
import logging
import os
import re
import sys
import threading
import time
import traceback
from collections import defaultdict, deque

# ---- 路径引导：保证从任意 cwd 启动都能 import 仓库模块 ----
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# ---- ANSI 颜色（Windows 10+ 终端需先启用 VT 处理）----
if os.name == "nt":
    os.system("")

USE_COLOR = True

RESET = "\033[0m"
DIM = "\033[2m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"
C_CYAN = "\033[36m"
C_WHITE = "\033[37m"
C_GRAY = "\033[90m"
B_RED = "\033[1;31m"
B_GREEN = "\033[1;32m"
B_YELLOW = "\033[1;33m"
B_BLUE = "\033[1;34m"
B_MAGENTA = "\033[1;35m"
B_CYAN = "\033[1;36m"
B_WHITE = "\033[1;37m"


def colorize(text, code):
    if not USE_COLOR:
        return text
    return f"{code}{text}{RESET}"


_PRINT_LOCK = threading.Lock()


def live_print(text: str):
    """线程安全实时打印（executor 工作线程与主协程并发调用）。"""
    with _PRINT_LOCK:
        try:
            print(text, flush=True)
        except Exception:
            try:
                print(text.encode("ascii", "replace").decode("ascii"), flush=True)
            except Exception:
                pass


def phase_banner(title: str, code: str, sub: str = ""):
    bar = "=" * 62
    live_print("")
    live_print(colorize(bar, code))
    line = f"  {title}"
    if sub:
        line += colorize(f"   ·  {sub}", DIM)
    live_print(colorize(line, code))
    live_print(colorize(bar, code))


# ==================== 实时状态机（日志 + 事件 → 彩色输出） ====================

class LiveState:
    """把集群日志行与 tool.result 事件转成阶段化、分色的实时输出。"""

    SEV_COLOR = {
        "critical": B_RED,
        "high": B_RED,
        "medium": B_YELLOW,
        "low": C_BLUE,
        "info": C_BLUE,
        "informational": C_BLUE,
    }

    def __init__(self, backend_label: str):
        self.backend_label = backend_label
        self.coordinator = None
        self.current_phase = ""
        self._t0 = time.time()
        # exec_tool 名 -> deque(agent_id)：把"调用工具"日志与 tool.result 事件配对
        self._pending = defaultdict(deque)
        self.exec_started = 0
        self.exec_ok = 0
        self.exec_fail = 0
        self.report_lines = 0
        self.report_printed = False
        self._session_prefix = re.compile(r"^\[[^\]]*session[^\]]*\]\s*")
        self._tool_start_re = re.compile(
            r"^\[([^\]]+)\]\s*调用工具:\s*(\S+?)\s*→\s*(\S+?),\s*参数:\s*(\{.*\})$",
            re.S,
        )

    def elapsed(self) -> float:
        return time.time() - self._t0

    def _enter_phase(self, name: str, code: str):
        if self.current_phase == name:
            return
        self.current_phase = name
        phase_banner(name, code, sub=f"t={self.elapsed():.1f}s")

    # ---------------- 日志行处理 ----------------

    def on_log(self, logger_name: str, level: int, msg: str):
        msg = self._session_prefix.sub("", msg)

        if msg.startswith("分析意图"):
            self._enter_phase("① 意图分析", B_BLUE)
            live_print(colorize(f"  {msg}", C_BLUE))
        elif msg.startswith("意图:"):
            live_print(colorize(f"  {msg}", B_BLUE))
        elif msg.startswith("分解任务"):
            self._enter_phase("② 任务分解", B_CYAN)
        elif msg.startswith("生成 ") and " 个任务" in msg:
            live_print(colorize(f"  {msg}", B_CYAN))
        elif msg.startswith("调度智能体"):
            self._enter_phase("③ 调度决策", B_MAGENTA)
        elif msg.startswith("调度任务:"):
            live_print(colorize(f"  {msg}", C_MAGENTA))
        elif msg.startswith("调度决策:"):
            live_print(colorize(f"  {msg}", B_MAGENTA))
        elif msg.startswith("战略决策:"):
            live_print(colorize(f"  ▶ {msg}", B_MAGENTA))
        elif msg.startswith("执行任务"):
            self._enter_phase("④ 智能体执行", B_YELLOW)
        elif self._tool_start_re.match(msg):
            self._on_tool_start(msg)
        elif "执行成功" in msg and "输出长度" in msg:
            return  # 与 tool.result 事件重复，跳过
        elif "工具 " in msg and "执行失败" in msg:
            live_print(colorize(f"  {msg}", C_YELLOW))
        elif msg.startswith("聚合结果"):
            self._enter_phase("⑤ 结果聚合", B_CYAN)
        elif msg.startswith("开始聚合"):
            live_print(colorize(f"  {msg}", C_CYAN))
        elif msg.startswith("聚合完成"):
            live_print(colorize(f"  {msg}", B_CYAN))
        elif msg.startswith("会话完成"):
            self._enter_phase("⑦ 会话完成", B_GREEN)
            live_print(colorize(f"  {msg}", B_GREEN))
        elif msg.startswith("会话失败"):
            phase_banner("⚠ 会话失败", B_RED, sub=f"t={self.elapsed():.1f}s")
            live_print(colorize(f"  {msg}", B_RED))
        elif "发现 Flag" in msg:
            live_print(colorize(f"  {msg}", B_GREEN))
        else:
            if level >= logging.ERROR:
                live_print(colorize(f"  {msg}", C_RED))
            elif level >= logging.WARNING:
                live_print(colorize(f"  {msg}", C_YELLOW))
            else:
                live_print(colorize(f"  {msg}", C_GRAY))

    def _on_tool_start(self, msg: str):
        m = self._tool_start_re.match(msg)
        if not m:
            return
        agent_id, mcp_tool, exec_tool, params_raw = m.groups()
        self._pending[exec_tool].append(agent_id)
        self.exec_started += 1

        params = {}
        try:
            parsed = ast.literal_eval(params_raw)
            if isinstance(parsed, dict):
                params = parsed
        except Exception:
            pass
        target = (
            params.get("target") or params.get("url") or params.get("domain") or ""
        )
        target_disp = f" {target}" if target else ""
        if len(target_disp) > 70:
            target_disp = target_disp[:67] + "..."
        live_print(
            colorize(f"  ▶ [t={self.elapsed():.1f}s] [{agent_id}] {mcp_tool} → {exec_tool}", B_CYAN)
            + colorize(f"{target_disp} ({self.backend_label})", C_CYAN)
        )

    # ---------------- tool.result 事件处理 ----------------

    def on_tool_result(self, event):
        try:
            data = event.data or {}
        except Exception:
            return
        tool = data.get("tool_name") or "?"
        agent_id = "?"
        if self._pending.get(tool):
            agent_id = self._pending[tool].popleft()
        target = data.get("target") or ""
        duration = float(data.get("duration") or 0)
        success = bool(data.get("success"))
        output = str(data.get("output") or "")
        target_disp = f" {target}" if target else ""
        if len(target_disp) > 70:
            target_disp = target_disp[:67] + "..."

        if success:
            self.exec_ok += 1
            live_print(
                colorize(f"  [OK] [t={self.elapsed():.1f}s] [{agent_id}] {tool}{target_disp} 耗时 {duration:.1f}s", C_GREEN)
            )
        else:
            self.exec_fail += 1
            timed_out = "timeout" in output[:300].lower()
            if timed_out:
                live_print(
                    colorize(f"  [TIMEOUT] [t={self.elapsed():.1f}s] [{agent_id}] {tool}{target_disp} 耗时 {duration:.1f}s", B_YELLOW)
                )
            else:
                live_print(
                    colorize(f"  [FAIL] [t={self.elapsed():.1f}s] [{agent_id}] {tool}{target_disp} 耗时 {duration:.1f}s", B_RED)
                )
                snippet = output[:200].strip().replace("\n", " ")
                if snippet:
                    live_print(colorize(f"         {snippet}", C_RED))

    # ---------------- 结构化展示（由实例方法包装触发） ----------------

    def print_tasks(self, task_graph):
        try:
            tasks = sorted(task_graph.tasks.values(), key=lambda t: t.task_id)
        except Exception:
            return
        if not tasks:
            live_print(colorize("  (无任务)", C_GRAY))
            return
        live_print(colorize("  ┌─ 任务分解清单 ────────────────────────────────", B_CYAN))
        for t in tasks:
            deps = ",".join(t.dependencies) if getattr(t, "dependencies", None) else "-"
            live_print(
                colorize(f"  │ {t.task_id}", C_CYAN)
                + colorize(f"  [{t.tool_name}]", C_GREEN)
                + colorize(f"  {t.name}", C_WHITE)
                + colorize(f"  依赖: {deps}", C_YELLOW if t.dependencies else C_GRAY)
            )
        live_print(colorize(f"  └─ 共 {len(tasks)} 个任务", B_CYAN))

    def print_decisions(self, plan):
        try:
            decisions = list(plan.scheduling_decisions)
        except Exception:
            return
        if not decisions:
            return
        live_print(colorize("  ┌─ 调度决策 ───────────────────────────────────", B_MAGENTA))
        for d in decisions:
            task = d.task
            reason = "; ".join(getattr(d, "reasoning", None) or [])[:140]
            if d.selected_agent is None:
                live_print(
                    colorize(f"  │ {task.task_id} [{task.tool_name}]", C_CYAN)
                    + colorize("  → coordinator (承接 report_generator)", B_YELLOW)
                    + (colorize(f"  原因: {reason}", C_YELLOW) if reason else "")
                )
            else:
                live_print(
                    colorize(f"  │ {task.task_id} [{task.tool_name}]", C_CYAN)
                    + colorize(f"  → {d.selected_agent.agent_id}", B_GREEN)
                    + colorize(f"  conf={d.confidence:.2f}", C_GRAY)
                    + (colorize(f"  {reason}", C_MAGENTA) if reason else "")
                )
        live_print(colorize(f"  └─ 共 {len(decisions)} 项调度决策", B_MAGENTA))

    def print_findings(self, agg):
        try:
            findings = list(getattr(agg, "unique_findings", None) or [])
            flags = list(getattr(agg, "extracted_flags", None) or [])
        except Exception:
            return
        if not findings and not flags:
            live_print(colorize("  (聚合后无唯一发现)", C_GRAY))
            return
        live_print(colorize("  ┌─ 聚合发现 (Findings) ─────────────────────────", B_CYAN))
        for f in findings:
            sev = str(getattr(f, "severity", "") or "?")
            if hasattr(f.severity, "value"):
                sev = str(f.severity.value)
            code = self.SEV_COLOR.get(sev.lower(), C_GRAY)
            title = str(getattr(f, "title", "") or "")
            source = str(getattr(f, "source", "") or "")
            conf = float(getattr(f, "confidence", 0) or 0)
            evidence = getattr(f, "evidence", None) or []
            live_print(
                colorize(f"  │ [{sev.upper()}] {title}", code)
                + colorize(f"  (来源: {source}, 置信度: {conf:.0%})", C_GRAY)
            )
            if evidence:
                first = str(evidence[0]) if not isinstance(evidence[0], str) else evidence[0]
                snippet = first.replace("\n", " ")[:140]
                if snippet:
                    live_print(colorize(f"  │   证据: {snippet}", code))
        for flag in flags:
            live_print(colorize(f"  │ [FLAG] {flag}", B_GREEN))
        live_print(colorize(f"  └─ 共 {len(findings)} 个唯一发现 / {len(flags)} 个Flag", B_CYAN))

    def print_report(self, report: str, max_lines: int = 15):
        self.report_printed = True
        lines = report.splitlines()
        self.report_lines = len(lines)
        phase_banner("⑥ 报告生成", B_GREEN, sub=f"t={self.elapsed():.1f}s")
        for ln in lines[:max_lines]:
            live_print(colorize(f"  {ln}" if ln.strip() else "  ", C_GREEN))
        if len(lines) > max_lines:
            live_print(
                colorize(f"  … 共 {len(lines)} 行 / {len(report)} 字符（仅显示前 {max_lines} 行）", C_GRAY)
            )

    def print_summary(self, session, wall: float):
        phase_banner("★ 总结", B_WHITE, sub=f"总耗时 {wall:.1f}s")
        agg = getattr(session, "aggregated_result", None)
        findings_n = len(getattr(agg, "unique_findings", None) or []) if agg else 0
        flags_n = len(getattr(agg, "extracted_flags", None) or []) if agg else 0
        stats = None
        try:
            stats = self.coordinator.agent_scheduler.get_statistics()
        except Exception:
            pass
        if stats is not None:
            sched_line = (
                f"总分配={getattr(stats, 'total_assignments', '?')} "
                f"成功={getattr(stats, 'successful_assignments', '?')} "
                f"失败={getattr(stats, 'failed_assignments', '?')} "
                f"成功率={getattr(stats, 'success_rate', 0):.0%}"
            )
        else:
            sched_line = "N/A"
        rows = [
            ("会话ID", getattr(session, "session_id", "?")),
            ("用户请求", (getattr(session, "user_input", "") or "")[:80]),
            ("会话状态", getattr(session.state, "value", session.state)),
            ("总耗时", f"{wall:.1f}s"),
            (
                "任务数",
                f"{getattr(session, 'total_tasks', 0)} 总 / "
                f"{getattr(session, 'completed_tasks', 0)} 完成 / "
                f"{getattr(session, 'failed_tasks', 0)} 失败",
            ),
            (
                "工具执行",
                f"{self.exec_started} 次启动, {self.exec_ok} 成功, {self.exec_fail} 失败",
            ),
            ("调度统计", sched_line),
            ("唯一发现", f"{findings_n} 个"),
            ("Flag", f"{flags_n} 个"),
            (
                "报告",
                f"{self.report_lines} 行 / {len(getattr(session, 'report', '') or '')} 字符"
                if getattr(session, "report", None)
                else "无 (coordinator 未承接 report_generator)",
            ),
        ]
        for k, v in rows:
            live_print(colorize(f"  {k:<8}: {v}", C_WHITE))
        if getattr(session, "error", None):
            live_print(colorize(f"  ERROR  : {session.error}", B_RED))
        if session.state.value == "completed":
            live_print(colorize(f"  → 执行完成，退出码 0", B_GREEN))


# ==================== 实时日志 Handler ====================

class LiveLogHandler(logging.Handler):
    """把集群 (kali_mcp.*) 的日志实时转成彩色终端输出（纯展示，不改仓库）。"""

    def __init__(self, state: LiveState):
        super().__init__(level=logging.INFO)
        self.state = state

    def emit(self, record):
        try:
            if record.name.startswith("kali_mcp") or (
                record.name.startswith("paramiko") and record.levelno >= logging.WARNING
            ):
                msg = record.getMessage()
                self.state.on_log(record.name, record.levelno, msg)
        except Exception:
            pass


def setup_live_logging(state: LiveState):
    root = logging.getLogger()
    for h in list(root.handlers):  # 清掉三方库可能装的默认 handler，避免重复输出
        root.removeHandler(h)
    root.setLevel(logging.DEBUG)
    handler = LiveLogHandler(state)
    root.addHandler(handler)
    return handler


# ==================== 运行时 hook（实例方法包装，不改仓库文件） ====================

def resolve_allowed_agents(agent_registry, agents_arg: str):
    """把 --agents 逗号列表解析为允许执行的 agent_id 集合（精确或前缀匹配）。

    返回 None 表示不限制（执行全部 agent）。
    """
    if not agents_arg:
        return None
    tokens = [t.strip() for t in agents_arg.split(",") if t.strip()]
    all_agents = agent_registry.get_all_agents()
    allowed = set()
    for token in tokens:
        matched = {
            a.agent_id for a in all_agents
            if a.agent_id == token or a.agent_id.startswith(token)
        }
        if not matched:
            live_print(
                colorize(
                    f"  [警告] --agents 未匹配任何 agent: {token}"
                    f"（可用: {', '.join(sorted(a.agent_id for a in all_agents))}）",
                    B_YELLOW,
                )
            )
        allowed |= matched
    return allowed


def hook_runtime(coordinator, executor, state: LiveState, no_cache: bool, allowed_agents=None):
    """包装 coordinator/executor 的实例方法：结构化信息到达即打印。"""

    # 1. 任务分解 → 任务清单
    _decompose = coordinator.task_decomposer.decompose

    def _wrapped_decompose(intent):
        plan = _decompose(intent)
        try:
            state.print_tasks(plan.task_graph)
        except Exception:
            pass
        return plan

    coordinator.task_decomposer.decompose = _wrapped_decompose

    # 2. 执行计划创建 → 调度决策（--agents 过滤：仅保留允许 agent 的决策，
    #    其余替换为 coordinator 承接的跳过决策；集群核心调度逻辑不改动）
    _create_plan = coordinator._create_execution_plan

    async def _wrapped_create_plan(intent, decomposer_plan):
        plan = await _create_plan(intent, decomposer_plan)
        try:
            state.print_decisions(plan)
        except Exception:
            pass
        if allowed_agents is not None:
            from kali_mcp.core.agent_scheduler import SchedulingDecision

            allowed = set(allowed_agents)
            new_decisions = []
            skipped = 0
            for d in plan.scheduling_decisions:
                if d.selected_agent is None or d.selected_agent.agent_id in allowed:
                    new_decisions.append(d)
                else:
                    skipped += 1
                    new_decisions.append(
                        SchedulingDecision(
                            task=d.task,
                            selected_agent=None,
                            strategy=d.strategy,
                            confidence=d.confidence,
                            reasoning=[
                                f"--agents 过滤跳过（仅允许: {', '.join(sorted(allowed))}），原调度: {d.selected_agent.agent_id}"
                            ],
                        )
                    )
            plan.scheduling_decisions = new_decisions
            plan.required_agents = {a for a in plan.required_agents if a in allowed}
            if skipped:
                live_print(
                    colorize(
                        f"  [--agents 过滤] 仅允许执行: {', '.join(sorted(allowed))}；"
                        f"已过滤 {skipped} 项调度决策（对应任务跳过，不执行）",
                        B_YELLOW,
                    )
                )
        return plan

    coordinator._create_execution_plan = _wrapped_create_plan

    # 3. 结果聚合 → findings
    _aggregate = coordinator.result_aggregator.aggregate_results

    async def _wrapped_aggregate(intent, agent_results):
        agg = await _aggregate(intent, agent_results)
        try:
            state.print_findings(agg)
        except Exception:
            pass
        return agg

    coordinator.result_aggregator.aggregate_results = _wrapped_aggregate

    # 4. 报告生成 → 报告前 N 行
    _finalize = coordinator._finalize_coordinator_report

    async def _wrapped_finalize(session):
        report = await _finalize(session)
        try:
            if report:
                state.print_report(report)
        except Exception:
            pass
        return report

    coordinator._finalize_coordinator_report = _wrapped_finalize

    # 5. --no-cache：透传绕过 result_cache，强制真实执行
    if no_cache:
        _exec_tool = executor.execute_tool_with_data

        def _wrapped_exec_tool(tool_name, data):
            data = dict(data)
            data["no_cache"] = True
            data["skip_cache"] = True
            return _exec_tool(tool_name, data)

        executor.execute_tool_with_data = _wrapped_exec_tool


# ==================== 事件总线订阅（tool.result） ====================

def setup_event_bus(state: LiveState):
    from kali_mcp.core.event_bus import EventBus
    from kali_mcp.core.local_executor import set_event_bus

    bus = EventBus()
    bus.subscribe("tool.result", state.on_tool_result, "AgentLiveViewer", priority=100)
    set_event_bus(bus)  # 注入执行器，使工具结果以事件形式实时流出
    return bus


# ==================== 集群构建（与 mcp_server.py 构造逻辑一致） ====================

AGENT_CLASSES = None


def _agent_classes():
    global AGENT_CLASSES
    if AGENT_CLASSES is None:
        from kali_mcp.agents.information_gathering.recon_agent import ReconAgent
        from kali_mcp.agents.information_gathering.subdomain_agent import SubdomainAgent
        from kali_mcp.agents.information_gathering.web_recon_agent import WebReconAgent
        from kali_mcp.agents.vulnerability_discovery.vuln_scanner_agent import VulnScannerAgent
        from kali_mcp.agents.vulnerability_discovery.web_vuln_agent import WebVulnAgent
        from kali_mcp.agents.vulnerability_discovery.auth_agent import AuthAgent
        from kali_mcp.agents.vulnerability_discovery.network_vuln_agent import NetworkVulnAgent
        from kali_mcp.agents.vulnerability_discovery.vuln_verifier_agent import VulnVerifierAgent
        from kali_mcp.agents.exploitation.exploit_agent import ExploitAgent
        from kali_mcp.agents.exploitation.privilege_agent import PrivilegeAgent
        from kali_mcp.agents.exploitation.lateral_agent import LateralAgent
        from kali_mcp.agents.specialized.pwn_agent import PwnAgent
        from kali_mcp.agents.specialized.crypto_agent import CryptoAgent
        from kali_mcp.agents.specialized.forensics_agent import ForensicsAgent
        from kali_mcp.agents.specialized.code_audit_agent import CodeAuditAgent
        from kali_mcp.agents.specialized.source_code_agent import SourceCodeAgent
        from kali_mcp.agents.specialized.code_analyze_agent import CodeAnalyzeAgent
        AGENT_CLASSES = [
            (ReconAgent, "侦察智能体"),
            (SubdomainAgent, "子域名智能体"),
            (WebReconAgent, "Web侦察智能体"),
            (VulnScannerAgent, "漏洞扫描智能体"),
            (WebVulnAgent, "Web漏洞智能体"),
            (AuthAgent, "认证攻击智能体"),
            (NetworkVulnAgent, "网络漏洞智能体"),
            (VulnVerifierAgent, "漏洞验证智能体"),
            (ExploitAgent, "漏洞利用智能体"),
            (PrivilegeAgent, "权限提升智能体"),
            (LateralAgent, "横向移动智能体"),
            (PwnAgent, "二进制利用智能体"),
            (CryptoAgent, "密码学智能体"),
            (ForensicsAgent, "取证智能体"),
            (CodeAuditAgent, "代码审计智能体"),
            (SourceCodeAgent, "源码获取智能体"),
            (CodeAnalyzeAgent, "代码分析智能体"),
        ]
    return AGENT_CLASSES


def build_cluster(timeout: int):
    from kali_mcp.core.local_executor import LocalCommandExecutor
    from kali_mcp.core.mesh_message_bus import MeshMessageBus
    from kali_mcp.core.agent_registry import AgentRegistry
    from kali_mcp.core.agent_coordinator import CoordinatorAgent

    executor = LocalCommandExecutor(timeout=timeout)
    message_bus = MeshMessageBus()
    agent_registry = AgentRegistry()

    agents = []
    for agent_class, desc in _agent_classes():
        agent = agent_class(
            message_bus=message_bus,
            tool_registry=agent_registry,
            executor=executor,
        )
        agents.append(agent)
        agent_registry.register_agent(agent)

    coordinator = CoordinatorAgent(agent_registry=agent_registry)
    return executor, agent_registry, coordinator


def get_backend_label() -> str:
    try:
        from kali_mcp.core.backend import resolve_backend

        info = resolve_backend()
        mode = info.get("mode", "?")
        if mode == "ssh":
            try:
                from kali_mcp.core.backend import _ssh_parse_target

                host = _ssh_parse_target()
                if host:
                    return f"ssh后端 {host[0]}"
            except Exception:
                pass
            return "ssh后端"
        return f"{mode}后端"
    except Exception:
        return "local后端"


def print_cluster_info(agent_registry, backend_label: str):
    phase_banner("集群启动", B_WHITE, sub=f"{len(agent_registry)} agents · 后端={backend_label}")
    for a in agent_registry.get_all_agents():
        live_print(colorize(f"  - {a.agent_id}", C_CYAN) + colorize(f"  ({a.name})", C_GRAY))


# ==================== 主流程 ====================

def main() -> int:
    global USE_COLOR

    parser = argparse.ArgumentParser(
        description="Kali MCP 17-agent 渗透测试集群实时可视化执行器（纯展示层）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            '  C:/Windows/py.exe -3 agent_live.py "对 http://localhost:8000/ 做 web 漏洞扫描"\n'
            '  python3 agent_live.py "对 http://localhost:8000/ 做 web 漏洞扫描：目录枚举、CMS识别、注入检测" --no-cache --timeout 300\n'
        ),
    )
    parser.add_argument("task", nargs="+", help="任务描述（多词自动以空格连接）")
    parser.add_argument("--no-cache", action="store_true", help="绕过 result_cache，强制真实执行")
    parser.add_argument("--timeout", type=int, default=300, help="命令执行超时秒数（默认 300）")
    parser.add_argument("--report-lines", type=int, default=15, help="报告显示行数（默认 15）")
    parser.add_argument(
        "--agents",
        default=None,
        help=(
            "仅执行指定 agent（逗号分隔，agent_id 精确或前缀匹配，如 recon,web_vuln）；"
            "缺省执行全部 17 个 agent"
        ),
    )
    parser.add_argument("--no-color", action="store_true", help="禁用 ANSI 颜色")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False
    task_desc = " ".join(args.task)
    timeout = max(1, args.timeout)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    backend_label = get_backend_label()
    state = LiveState(backend_label)
    setup_live_logging(state)

    phase_banner("Kali MCP · 17-agent 集群实时可视化执行器", B_WHITE, sub=f"backend={backend_label}")
    live_print(colorize(f"  任务: {task_desc}", C_WHITE))
    live_print(colorize(f"  参数: no_cache={args.no_cache}  timeout={timeout}s  agents={args.agents or 'all'}", C_GRAY))

    t0 = time.time()
    try:
        executor, agent_registry, coordinator = build_cluster(timeout)
    except BaseException:
        live_print(colorize("  [异常] 集群构建失败：", B_RED))
        live_print(traceback.format_exc())
        return 1

    state.coordinator = coordinator
    print_cluster_info(agent_registry, backend_label)

    allowed_agents = resolve_allowed_agents(agent_registry, args.agents)
    if allowed_agents is not None:
        live_print(
            colorize(
                f"  [--agents 过滤] 本会话仅执行: {', '.join(sorted(allowed_agents))}"
                "（其余 agent 的调度决策将被跳过）",
                B_YELLOW,
            )
        )

    try:
        setup_event_bus(state)
        hook_runtime(coordinator, executor, state, args.no_cache, allowed_agents)
    except BaseException:
        live_print(colorize("  [异常] 运行时 hook 失败：", B_RED))
        live_print(traceback.format_exc())
        return 1

    live_print(
        colorize(
            f"  [开始] 提交请求 → coordinator.process_request()  no_cache={args.no_cache} timeout={timeout}s",
            B_CYAN,
        )
    )

    try:
        session = asyncio.run(coordinator.process_request(task_desc))
    except BaseException:
        live_print(colorize("  [异常] 集群执行抛出未捕获异常：", B_RED))
        live_print(traceback.format_exc())
        live_print(colorize(f"  总耗时 {time.time() - t0:.1f}s", B_RED))
        return 1

    wall = time.time() - t0
    state.print_summary(session, wall)
    return 0


if __name__ == "__main__":
    sys.exit(main())
