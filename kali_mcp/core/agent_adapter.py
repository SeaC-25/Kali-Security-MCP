#!/usr/bin/env python3
"""
代理适配器 - 连接MCP工具层和多智能体系统

提供渐进式迁移路径：
- 简单工具继续直接调用executor
- 复杂工具通过代理协调执行
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AgentAdapter:
    """MCP工具到多智能体系统的适配器"""

    def __init__(self, executor, coordinator_agent=None, agent_registry=None):
        self.executor = executor
        self.coordinator = coordinator_agent
        self.registry = agent_registry
        self.agent_enabled = coordinator_agent is not None
        self.stats = {"agent_calls": 0, "direct_calls": 0, "fallbacks": 0}

    def should_use_agent(self, tool_name: str, data: Dict[str, Any]) -> bool:
        """判断是否应该使用代理执行"""
        if not self.agent_enabled:
            return False

        # 复杂工具走代理路径
        complex_tools = {
            "intelligent_ctf_solve", "ctf_web_comprehensive_solver", "ctf_pwn_solver",
            "adaptive_web_penetration", "adaptive_network_penetration",
            "intelligent_apt_campaign", "apt_web_application_attack", "apt_network_penetration",
            "comprehensive_recon", "smart_web_recon", "smart_network_recon",
            "advanced_web_security_assessment", "intelligent_vulnerability_assessment",
        }

        if tool_name not in complex_tools:
            return False

        # 数据复杂度检查
        target_count = len(data.get("targets", [])) if "targets" in data else 1
        has_multi_phase = data.get("multi_phase", False) or data.get("comprehensive", False)

        return target_count > 1 or has_multi_phase or True  # 默认复杂工具走代理

    def _run_async(self, coro):
        """在同步上下文中运行异步协程"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 已有事件循环（如在 FastAPI/MCP 中），用 run_coroutine_threadsafe
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(coro, loop)
                return future.result(timeout=300)
            else:
                return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def execute_via_agent(self, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """通过代理系统执行"""
        if not self.coordinator:
            logger.warning(f"代理系统未初始化，回退到直接执行")
            self.stats["fallbacks"] += 1
            return self.executor.execute_tool_with_data(tool_name, data)

        start_time = time.time()
        try:
            self.stats["agent_calls"] += 1
            logger.info(f"🤖 通过代理执行: {tool_name}")

            # 构造用户输入字符串传给 process_request
            target = data.get("target") or data.get("url") or ""
            intent = self._infer_intent(tool_name, data)
            user_input = f"{intent}: {tool_name} on {target}" if target else f"{intent}: {tool_name}"

            # 通过协调器执行（异步 → 同步桥接）
            session = self._run_async(self.coordinator.process_request(user_input))
            elapsed = time.time() - start_time

            # 从 ExecutionSession 提取结果
            if session.state.value == "completed" and session.aggregated_result:
                agg = session.aggregated_result
                summary = getattr(agg, "summary", "") or str(agg)
                raw = getattr(agg, "raw_results", {})
            else:
                summary = session.error or f"代理执行状态: {session.state.value}"
                raw = {}

            logger.info(f"✅ 代理执行完成: {tool_name} ({elapsed:.2f}s) state={session.state.value}")

            return {
                "success": session.state.value == "completed",
                "tool_name": tool_name,
                "output": summary,
                "agent_result": raw,
                "session_id": session.session_id,
                "via_agent": True,
                "execution_time": elapsed
            }

        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"❌ 代理执行失败: {e} ({elapsed:.2f}s)，回退到直接执行")
            self.stats["fallbacks"] += 1
            return self.executor.execute_tool_with_data(tool_name, data)

    def execute_direct(self, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """直接执行（不通过代理）"""
        self.stats["direct_calls"] += 1
        return self.executor.execute_tool_with_data(tool_name, data)

    def _infer_intent(self, tool_name: str, data: Dict[str, Any]) -> str:
        """推断用户意图"""
        intent_map = {
            "intelligent_ctf_solve": "ctf_solve",
            "ctf_web_comprehensive_solver": "ctf_web",
            "ctf_pwn_solver": "ctf_pwn",
            "adaptive_web_penetration": "web_pentest",
            "adaptive_network_penetration": "network_pentest",
            "intelligent_apt_campaign": "apt_attack",
            "comprehensive_recon": "reconnaissance",
            "smart_web_recon": "web_recon",
            "smart_network_recon": "network_recon",
        }
        return intent_map.get(tool_name, "general_security_test")

    def get_stats(self) -> Dict[str, int]:
        """获取执行统计"""
        return self.stats.copy()
