#!/usr/bin/env python3
"""
Kali MCP - 智能化渗透测试MCP服务器
模块化架构版本 v2.0

核心功能:
- 208个安全工具的统一接口 (含25个v2.0新增工具)
- 100%工具覆盖率的终极扫描引擎
- 智能工具编排和结果驱动执行
- 扫描缓存和去重，避免重复扫描
- AD攻击、取证、移动安全专项工具
- 异步并行执行
- AI驱动的工具推荐
- 自适应攻击策略

v2.0 新增:
- UltimateScanEngine: 终极扫描引擎
- ToolOrchestrator: 智能工具编排
- SmartScanOptimizer: 智能缓存和去重
- ADAttackOrchestrator: AD攻击编排
- ForensicsOrchestrator: 取证工具编排
- MobileSecurityScanner: 移动安全扫描
"""

__version__ = "2.0.0"
__author__ = "Kali MCP Team"

# 基础模块
from .core.executor import AsyncExecutor
from .core.session import SessionManager, SessionContext
from .core.strategy import StrategyEngine
from .core.cache import ResultCache

from .tools.base import BaseTool, ToolResult, ToolRegistry

# v2.0 新增模块 - 动态导入
from .core import (
    ULTIMATE_ENGINE_AVAILABLE,
    ORCHESTRATOR_AVAILABLE,
    OPTIMIZER_AVAILABLE,
    SKILL_DISPATCHER_AVAILABLE,
)

from .tools import (
    AD_TOOLS_AVAILABLE,
    FORENSICS_TOOLS_AVAILABLE,
    MOBILE_TOOLS_AVAILABLE,
    CLOUD_TOOLS_AVAILABLE,
    CONTAINER_TOOLS_AVAILABLE,
)

# MCP工具注册函数
from .mcp_tools_v2 import register_v2_tools, V2_TOOL_COUNT

__all__ = [
    # 版本信息
    "__version__",
    "__author__",

    # 核心模块
    "AsyncExecutor",
    "SessionManager",
    "SessionContext",
    "StrategyEngine",
    "ResultCache",

    # 工具系统
    "BaseTool",
    "ToolResult",
    "ToolRegistry",

    # v2.0 可用性标志
    "ULTIMATE_ENGINE_AVAILABLE",
    "ORCHESTRATOR_AVAILABLE",
    "OPTIMIZER_AVAILABLE",
    "SKILL_DISPATCHER_AVAILABLE",
    "AD_TOOLS_AVAILABLE",
    "FORENSICS_TOOLS_AVAILABLE",
    "MOBILE_TOOLS_AVAILABLE",
    "CLOUD_TOOLS_AVAILABLE",
    "CONTAINER_TOOLS_AVAILABLE",

    # v2.0 工具注册
    "register_v2_tools",
    "V2_TOOL_COUNT",
]
