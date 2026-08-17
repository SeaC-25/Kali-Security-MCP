#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
import shlex
import unicodedata
from typing import Dict, Any, Optional, List, Set, Tuple
import time
import json
import uuid
import random
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        # IMPORTANT: In MCP stdio transport, stdout is reserved for JSON-RPC messages.
        # All logs/banners must go to stderr, otherwise the client handshake will fail.
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)


def _llm_api_key_available() -> bool:
    """Return True when an LLM provider API key is configured (Anthropic or OpenAI)."""
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))


# 深度智能化模式 - 启用连接池和结果缓存
OPTIMIZATION_ENABLED = True
logger.info("✅ 深度智能化模式 - 启用连接池优化和结果缓存")

# vuln_db 模块导入
try:
    from kali_mcp.mcp_tools.vuln_db_tools import register_vulnerability_tools, VULN_TOOL_COUNT
    VULN_DB_TOOLS_AVAILABLE = True
    logger.info(f"✅ vuln_db({VULN_TOOL_COUNT}) 模块加载成功")
except ImportError as e:
    VULN_DB_TOOLS_AVAILABLE = False
    register_vulnerability_tools = None
    VULN_TOOL_COUNT = 0
    logger.warning(f"⚠️ vuln_db 模块加载失败: {e}")

# 多智能体集群系统模块导入（v4.0）—— 已移除
# 原生子代理架构（harness 侧 18 markdown 子代理）下，17 Python agent 保留为
# 解析器来源（extract_findings 复用 _parse_*_output），不再由 MCP 构造/调度；
# 编排面（agent_run/agent_status）与集群初始化块已删除。DAG/ACO/kb 能力工具
# 见 kg_dag_tools.py（独立构造服务，不依赖 coordinator）。


# 深度测试引擎导入 (v2.1 - Burp Suite级别交互能力)
try:
    from deep_test_engine import (
        DeepTestEngine,
        HTTPInteractionEngine,
        ResponseAnalyzer,
        DynamicFuzzer,
        ENGINES_AVAILABLE
    )
    DEEP_TEST_ENGINE_AVAILABLE = True
    logger.info("✅ 深度测试引擎加载成功 - HTTP/WS/gRPC交互能力已启用")
except ImportError as e:
    DEEP_TEST_ENGINE_AVAILABLE = False
    logger.warning(f"⚠️ 深度测试引擎加载失败: {e}")

# 已删除伪智能化CTF引擎导入，现在使用真正的AI智能化MCP工具

# v6.0: 反检测浏览器引擎导入 (Playwright)
try:
    from kali_mcp.core.browser_engine import StealthBrowserEngine, HAS_PLAYWRIGHT
    BROWSER_ENGINE_AVAILABLE = HAS_PLAYWRIGHT
    if BROWSER_ENGINE_AVAILABLE:
        logger.info("✅ 反检测浏览器引擎加载成功 - Playwright 心跳维持已启用")
    else:
        logger.warning("⚠️ playwright 未安装, 浏览器引擎不可用. 运行: pip install playwright && playwright install chromium")
except ImportError as e:
    BROWSER_ENGINE_AVAILABLE = False
    logger.warning(f"⚠️ 浏览器引擎模块加载失败: {e}")


# ==================== 从模块导入核心类 (v5.0 模块化) ====================

from kali_mcp.core.mcp_session import SessionContext, StrategyEngine
from kali_mcp.core.ai_context import AIContextManager
from kali_mcp.core.interaction import IntelligentInteractionManager
from kali_mcp.core.ml_optimizer import MLStrategyOptimizer
from kali_mcp.core.memory_persistence import AdvancedMemoryPersistence
from kali_mcp.core.local_executor import (
    LocalCommandExecutor, sanitize_shell_arg, ALLOWED_TOOLS, validate_tool_name,
    set_event_bus,
)
from kali_mcp.core.multi_target import TargetProfile, AttackTask, MultiTargetOrchestrator
from kali_mcp.core.context_analyzer import ContextPattern, AdvancedContextAnalyzer
from kali_mcp.core.knowledge_graph import KnowledgeNode, KnowledgeRelation, AttackKnowledgeGraph
from kali_mcp.core.adaptive_exec_engine import ExecutionContext, AdaptiveExecutionEngine

# 全局ML策略优化器实例
ml_strategy_optimizer = MLStrategyOptimizer()

# 全局攻击会话存储
_ATTACK_SESSIONS = {}
_CURRENT_ATTACK_SESSION_ID = None

# 全局任务和工作流存储
_TASKS = {}
_WORKFLOWS = {}

# 全局自适应攻击存储
_ADAPTIVE_ATTACKS = {}

# 全局CTF模式状态
_CTF_MODE_ENABLED = False
_CTF_SESSIONS = {}
_CURRENT_CTF_SESSION = None
_DETECTED_FLAGS = []
_CTF_CHALLENGES = {}

# 全局AI上下文管理器实例
ai_context_manager = AIContextManager()

# Default configuration
# 注意: 已移除硬编码的远程 Kali API 地址。执行后端 (local/ssh/docker)
# 由 kali_mcp.core.backend.resolve_backend() 在启动时动态解析。
from kali_mcp.core.backend import resolve_backend  # noqa: E402
DEFAULT_REQUEST_TIMEOUT = 10  # 10 seconds ultra fast timeout for API requests

# ==================== MCP工具注册模块导入 (v5.0 模块化) ====================

from kali_mcp.mcp_tools import (
    register_recon_tools,
    register_ai_session_tools,
    register_code_audit_tools,
    register_misc_tools,
    register_apt_tools,
    register_ctf_tools,

    register_advanced_ctf_tools,
    register_session_tools,
    register_pwn_tools,
    register_adaptive_tools,
    register_deep_test_tools,
    register_vuln_mgmt_tools,
    register_chain_mgmt_tools,
    register_pentagi_bridge_tools,
    register_llm_react_tools,
    register_assessment_tools,
    register_harness_tools,
)

# v6.0: 浏览器自动化工具
try:
    from kali_mcp.mcp_tools.browser_tools import register_browser_tools
    _BROWSER_TOOLS_IMPORT_OK = True
except ImportError:
    _BROWSER_TOOLS_IMPORT_OK = False
    register_browser_tools = None

from kali_mcp.security import load_tool_profile, engagement_manager

def setup_mcp_server(
    profile_name: str = None,
    force_enable_modules: List[str] = None,
    force_disable_modules: List[str] = None,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastMCP:
    """
    Set up the MCP server with all tool functions.

    v5.0 模块化架构: 工具按类别分散到 kali_mcp/mcp_tools/ 模块中,
    通过 register_xxx_tools() 函数注册到 FastMCP 实例。

    Returns:
        Configured FastMCP instance
    """
    # 创建全局本地命令执行器
    global executor
    executor = LocalCommandExecutor(timeout=300)
    logger.info("本地命令执行器已初始化")

    # ==================== v5.1: 统一事件总线初始化 ====================
    event_bus = None
    try:
        from kali_mcp.core.event_bus import (
            EventBus,
            KnowledgeGraphSubscriber,
            VulnManagerSubscriber,
            MLOptimizerSubscriber,
            DecisionBrainSubscriber,
            DiggerSubscriber,
        )
        event_bus = EventBus()

        # 连接知识图谱订阅者
        try:
            kg = AttackKnowledgeGraph()
            KnowledgeGraphSubscriber(kg).register(event_bus)
            logger.info("  ✅ 知识图谱 → 事件总线")
        except Exception as e:
            logger.debug(f"  知识图谱订阅跳过: {e}")

        # 连接漏洞管理器订阅者
        try:
            from kali_mcp.core.vuln_manager import VulnManager
            vm = VulnManager()
            VulnManagerSubscriber(vm).register(event_bus)
            logger.info("  ✅ 漏洞管理器 → 事件总线")
        except Exception as e:
            logger.debug(f"  漏洞管理器订阅跳过: {e}")

        # 连接ML优化器订阅者
        try:
            MLOptimizerSubscriber(ml_strategy_optimizer).register(event_bus)
            logger.info("  ✅ ML优化器 → 事件总线")
        except Exception as e:
            logger.debug(f"  ML优化器订阅跳过: {e}")

        # 连接决策引擎订阅者
        try:
            from kali_mcp.core.decision_brain import DecisionBrain
            db = DecisionBrain(
                ml_optimizer=ml_strategy_optimizer,
                vuln_manager=vm if 'vm' in dir() else None,
            )
            DecisionBrainSubscriber(db).register(event_bus)
            logger.info("  ✅ 决策引擎 → 事件总线")
        except Exception as e:
            logger.debug(f"  决策引擎订阅跳过: {e}")

        # v5.2: 连接Digger事件订阅者
        try:
            DiggerSubscriber(
                ml_optimizer=ml_strategy_optimizer,
                vuln_manager=VulnManager() if 'VulnManager' in dir() else None,
            ).register(event_bus)
            logger.info("  ✅ Digger事件 → 事件总线")
        except Exception as e:
            logger.debug(f"  Digger订阅跳过: {e}")

        # 注入事件总线到执行器
        set_event_bus(event_bus)
        logger.info("✅ 统一事件总线初始化完成")
    except ImportError as e:
        logger.warning(f"⚠️ 事件总线模块加载失败: {e}")
    except Exception as e:
        logger.warning(f"⚠️ 事件总线初始化失败: {e}")

    # 声明使用全局的多智能体系统标志（已移除集群初始化，仅保留 agent_adapter=None
    # 占位：pwn 工具注册依赖该参数，原生子代理架构下恒为 None——无 coordinator 协作）
    global MULTI_AGENT_SYSTEM_AVAILABLE
    MULTI_AGENT_SYSTEM_AVAILABLE = False
    agent_adapter = None

    mcp = FastMCP(
        "kali-mcp",
        host=host,
        port=port,
        instructions="""Kali安全测试MCP服务器 - 重要使用规则：

1. 优先使用MCP工具而非bash命令
   当用户需要执行安全测试时，必须调用本服务器的MCP工具，而非直接运行nmap/curl/gobuster等命令。
   MCP工具提供：参数安全清理、授权范围校验、结构化输出解析、工具链自动编排。

2. 使用预定义的Skill加速常见任务
   - /kali-quick-scan <target> - 快速扫描
   - /kali-web-pentest <url> - Web渗透测试
   - /kali-ctf-solve <target> - CTF解题
   - /kali-vuln-assess <target> - 漏洞评估
   - /kali-net-recon <network> - 网络侦察

3. 工具选择指南
   - 端口扫描 → nmap_scan (不要用 nmap 命令)
   - 目录扫描 → gobuster_scan (不要用 gobuster 命令)
   - 漏洞扫描 → nuclei_scan (不要用 nuclei 命令)
   - SQL注入 → sqlmap_scan (不要用 sqlmap 命令)

直接运行bash命令会绕过安全机制和结果解析。"""
    )
    tool_profile = load_tool_profile(
        profile_name=profile_name,
        force_enable=force_enable_modules or [],
        force_disable=force_disable_modules or [],
    )
    engagement_manager.set_profile(tool_profile.name)
    logger.info(f"🔐 工具档位: {tool_profile.summary()}")

    def _module_enabled(module_key: str) -> bool:
        enabled = tool_profile.allows(module_key)
        if not enabled:
            logger.info(f"  ⏭️ 跳过模块[{module_key}]，由工具档位策略禁用")
        return enabled

    # ==================== 多智能体集群系统初始化 (v4.0) ====================
    # 已移除：原生子代理架构（harness 侧 18 markdown 子代理 + hooks 自动触发）
    # 不再由 MCP 构造 17-agent 集群 / CoordinatorAgent / embedding 预加载。
    # 能力层经 kg_dag_tools（dag_apply/dag_recommend/dag_status/kb_search）与
    # extract_findings_tools 独立构造服务提供（见下方注册段）。

    # ==================== 按类别注册MCP工具 (v5.0 模块化) ====================
    logger.info("📦 开始注册MCP工具模块...")

    # K1: surface converged; archived modules unregistered (see PLAN)
    # Only keep-set modules register below; the archived modules' register
    # calls were removed so their tools never register (module files stay on
    # disk). Keep modules register wholesale, then the post-registration prune
    # trims them to K1_KEEP_TOOLS. Archived tools remain reachable via kali_run.
    from kali_mcp.mcp_tools.meta_tools import register_meta_tools, K1_KEEP_TOOLS

    def _safe_register(module_key: str, label: str, fn, *fn_args):
        if not _module_enabled(module_key):
            return
        try:
            fn(*fn_args)
            logger.info(f"  ✅ {label}注册完成")
        except Exception as e:
            logger.warning(f"  ⚠️ {label}注册失败: {e}")

    _safe_register("recon", "信息收集工具", register_recon_tools, mcp, executor)
    # ai_tools 是纯 CLI 工具包装（execute_command/nuclei/whatweb/masscan/ffuf 等），
    # 零 LLM API 依赖（ai_context_manager/ml_strategy_optimizer 仅为本地对象透传）。
    # 注册与否由工具档位(profile)决定，不再被 LLM-key 门控连坐（K0-4 修正）。
    _safe_register("ai_session", "CLI扫描工具", register_ai_session_tools, mcp, executor, ai_context_manager, ml_strategy_optimizer)
    _safe_register("code_audit", "代码审计工具", register_code_audit_tools, mcp, executor)
    _safe_register("session", "会话管理工具", register_session_tools, mcp, executor, _ATTACK_SESSIONS, _CURRENT_ATTACK_SESSION_ID)
    _safe_register("pwn", "PWN工具", register_pwn_tools, mcp, executor, agent_adapter)

    # P0 harness tools (always-on orchestration surface: task/graph/playbook/verify/chain)
    _safe_register("harness", "P0 Harness编排工具", register_harness_tools, mcp, executor)

    # 痕迹清理工具（三粒度 task/session/global；chain REPORT 终态自动触发 task 级）
    try:
        from kali_mcp.mcp_tools.wipe_tools import register_wipe_tools

        _safe_register("harness", "痕迹清理工具", register_wipe_tools, mcp, executor)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"  ⚠️ 痕迹清理工具注册失败: {e}")

    # KG/DAG 能力工具（原生子代理架构：dag_apply/dag_recommend/dag_status/kb_search，
    # 独立构造 DAGService/ACOCore/KnowledgeRetriever，不依赖 coordinator）
    try:
        from kali_mcp.mcp_tools.kg_dag_tools import register_kg_dag_tools

        _safe_register("harness", "KG/DAG 工具", register_kg_dag_tools, mcp, executor)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"  ⚠️ KG/DAG 工具注册失败: {e}")

    # 证据提炼工具（复用 17 agent 确定性解析器：_parse_*_output → Finding）
    try:
        from kali_mcp.mcp_tools.extract_findings_tools import register_extract_findings_tools

        _safe_register("harness", "证据提取工具", register_extract_findings_tools, mcp, executor)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"  ⚠️ 证据提取工具注册失败: {e}")

    # fastsec 全能力工具面（12 个独立 MCP 工具，替代 kali_run 元回退）
    try:
        from kali_mcp.mcp_tools.fastsec_tools import register_fastsec_tools

        _safe_register("harness", "fastsec 能力工具", register_fastsec_tools, mcp, executor)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"  ⚠️ fastsec 能力工具注册失败: {e}")

    if VULN_DB_TOOLS_AVAILABLE and _module_enabled("vuln_db"):
        try:
            register_vulnerability_tools(mcp)
            logger.info("  ✅ 漏洞数据库工具注册成功")
        except Exception as e:
            logger.warning(f"  ⚠️ 漏洞数据库工具注册失败: {e}")

    # K1 meta surface: kali_run (fallback executor for archived tools)
    _safe_register("meta", "K1元工具(通用执行)", register_meta_tools, mcp, executor)

    # K2 async surface: scan_start/scan_collect/scan_wait/scan_jobs
    from kali_mcp.mcp_tools.async_tools import register_async_tools
    _safe_register("async", "K2异步扫描工具", register_async_tools, mcp, executor)

    # K3 orchestrate workflow surface: wf_init/transition/record_result/record_issue/status/pack
    from kali_mcp.mcp_tools.workflow_tools import register_wf_tools
    _safe_register("wf", "K3工作流工具", register_wf_tools, mcp, executor)

    # K4 thin task board (file-backed, lease, ≤3 concurrency) — default surface
    try:
        from kali_mcp.mcp_tools.board_tools import register_board_tools
        _safe_register("board", "K4薄任务板", register_board_tools, mcp, executor)
        logger.info("  ✅ K4 薄任务板注册成功")
    except Exception as e:
        logger.warning(f"  ⚠️ K4 薄任务板注册失败: {e}")

    # K1: prune the MCP surface to the keep-set. Keep modules registered
    # wholesale above, so drop non-keep tools here; archived modules were
    # never registered at all. Archived tools stay reachable via kali_run.
    _k1_tm = getattr(mcp, "_tool_manager", None)
    if _k1_tm is not None and hasattr(_k1_tm, "_tools"):
        for _k1_name in list(_k1_tm._tools.keys()):
            if _k1_name not in K1_KEEP_TOOLS:
                _k1_tm._tools.pop(_k1_name, None)
        logger.info(f"✅ K1: MCP surface converged to {len(_k1_tm._tools)} tools")

    logger.info("📦 所有MCP工具模块注册完成")

    return mcp

# ==================== 全局实例 ====================

# 全局自适应执行引擎实例
adaptive_execution_engine = AdaptiveExecutionEngine()

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Server")
    parser.add_argument("--server", type=str, default=None,
                      help="Kali API server URL (legacy, optional; execution backend is auto-detected via resolve_backend)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-websocket", action="store_true", help="Disable WebSocket connections, use HTTP only")

    # 传输模式配置
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                      help="Transport mode: stdio (default, for Claude Desktop/Code) or sse (for remote access)")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                      help="SSE server host (default: 127.0.0.1, only used with --transport=sse)")
    parser.add_argument("--port", type=int, default=8765,
                      help="SSE server port (default: 8765, only used with --transport=sse)")
    parser.add_argument(
        "--tool-profile",
        type=str,
        choices=["strict", "compliance", "full", "harness"],
        default=os.environ.get("KALI_MCP_TOOL_PROFILE", "compliance"),
        help="Tool registration profile (default: compliance)",
    )
    parser.add_argument(
        "--enable-module",
        action="append",
        default=[],
        help="Force-enable module key (repeatable), e.g. --enable-module pwn",
    )
    parser.add_argument(
        "--disable-module",
        action="append",
        default=[],
        help="Force-disable module key (repeatable), e.g. --disable-module apt",
    )

    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""

    # 解析命令行参数
    args = parse_args()

    # 启动时解析一次执行后端 (local/ssh/docker) - 失败绝不阻塞服务器启动
    try:
        backend_info = resolve_backend()
        _backend_mode = backend_info.get("mode", "unknown")
        _detected = backend_info.get("detected_tools", [])
        if _backend_mode == "local":
            _backend_label = f"local (本地检测到 {len(_detected)} 个工具)"
        elif _backend_mode == "ssh":
            _backend_label = "ssh (已配置远程主机)"
        elif _backend_mode == "docker":
            _backend_label = "docker (容器执行)"
        else:
            _backend_label = "unavailable (未检测到执行后端)"
        logger.info(f"⚡ 执行后端: {_backend_mode} - {backend_info.get('details', '')}")
    except Exception as e:  # noqa: BLE001 - 后端解析失败不应阻塞服务器
        logger.warning(f"⚠️ 执行后端解析失败: {e}")
        _backend_label = "unknown (解析失败)"
    # 按终端显示宽度 (73 列) 填充横幅内容，保持框线对齐
    _backend_line_content = "  ⚡ 执行后端: " + _backend_label
    _backend_pad = 73 - sum(2 if unicodedata.east_asian_width(c) in "WF" else 1
                            for c in _backend_line_content)
    backend_banner_line = _backend_line_content + " " * max(0, _backend_pad)

    # 根据传输模式显示不同的横幅
    if args.transport == "sse":
        banner = f"""
╔═══════════════════════════════════════════════════════════════════════╗
║                      Kali MCP 智能安全测试系统                          ║
║                    Intelligent Security Testing Framework              ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║  🌐 运行模式: SSE 远程访问模式 (REMOTE ACCESS MODE)                     ║
║{backend_banner_line}║
║                                                                         ║
║  ✅ HTTP服务: 监听 http://{args.host}:{args.port}                       ║
║  ✅ 远程连接: 外部AI可通过SSE协议连接                                   ║
║  ✅ MCP工具: 运行时按模块动态注册                                      ║
║                                                                         ║
╠═══════════════════════════════════════════════════════════════════════╣
║  连接方式:                                                              ║
║  - SSE端点: http://{args.host}:{args.port}/sse                          ║
║  - 消息端点: http://{args.host}:{args.port}/messages                    ║
╚═══════════════════════════════════════════════════════════════════════╝
        """.strip()
    else:
        banner = f"""
╔═══════════════════════════════════════════════════════════════════════╗
║                      Kali MCP 智能安全测试系统                          ║
║                    Intelligent Security Testing Framework              ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║  🟢 运行模式: 本地执行模式 (LOCAL EXECUTION MODE)                       ║
║{backend_banner_line}║
║                                                                         ║
║  ✅ 直接执行: 通过subprocess调用本地安全工具                            ║
║  ✅ 无需后端: 不需要启动kali_server.py                                 ║
║  ✅ 无需配置: 不需要KALI_API_URL环境变量                                ║
║  ✅ MCP工具: 运行时按模块动态注册                                      ║
║                                                                         ║
╠═══════════════════════════════════════════════════════════════════════╣
║  系统信息:                                                              ║
║  - 传输模式: stdio (Claude Desktop/Code 本地连接)                       ║
║  - 工作目录: {os.getcwd()[:50]}                                         ║
║  - Python版本: {sys.version.split()[0]}                                 ║
╚═══════════════════════════════════════════════════════════════════════╝
        """.strip()

    # IMPORTANT: In MCP stdio transport, stdout is reserved for JSON-RPC messages.
    # Always print the banner to stderr to avoid breaking the handshake.
    print(banner, file=sys.stderr)
    logger.info("=" * 80)
    logger.info("🚀 启动 Kali MCP 服务器...")
    logger.info(f"📡 传输模式: {args.transport.upper()}")
    logger.info(f"🔐 工具档位: {args.tool_profile}")
    if args.transport == "sse":
        logger.info(f"🌐 监听地址: http://{args.host}:{args.port}")
    logger.info("=" * 80)

    try:
        # Set up and run the MCP server
        mcp = setup_mcp_server(
            profile_name=args.tool_profile,
            force_enable_modules=args.enable_module,
            force_disable_modules=args.disable_module,
            host=args.host,
            port=args.port,
        )
        logger.info("✅ MCP服务器初始化完成")
        tool_count = len(getattr(getattr(mcp, "_tool_manager", None), "_tools", {}))
        if tool_count > 0:
            logger.info(f"📡 {tool_count} 个安全工具已就绪")
        else:
            logger.info("📡 安全工具已就绪")
        logger.info("🚀 服务器启动中...")

        # 根据传输模式启动
        if args.transport == "sse":
            logger.info(f"🌐 SSE服务器启动于 http://{args.host}:{args.port}")
            logger.info(f"📌 外部AI连接地址: http://<your-ip>:{args.port}/sse")
            mcp.run(transport="sse")
        else:
            logger.info("📌 stdio模式: 等待Claude Desktop/Code连接...")
            mcp.run()

    except KeyboardInterrupt:
        logger.info("\n🛑 收到停止信号，正在关闭服务器...")
    except Exception as e:
        logger.error(f"❌ 服务器错误: {str(e)}")
        raise
    finally:
        logger.info("✅ MCP服务器已安全关闭")

if __name__ == "__main__":
    main()
