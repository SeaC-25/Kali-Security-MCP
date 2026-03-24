#!/usr/bin/env python3
"""端到端测试：验证适配器与协调器的集成"""

import sys
import logging
from kali_mcp.core.agent_adapter import AgentAdapter
from kali_mcp.core.local_executor import LocalCommandExecutor

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

from kali_mcp.core.agent_coordinator import CoordinatorState

class MockAggregatedResult:
    def __init__(self, user_input):
        self.summary = f'模拟代理执行完成: {user_input}'
        self.findings = ["发现开放端口80", "检测到SQL注入漏洞"]
        self.agents_used = ["ReconAgent", "WebVulnAgent"]
        self.success = True
        self.raw_results = {}

class MockSession:
    """模拟ExecutionSession（匹配真实CoordinatorState Enum）"""
    def __init__(self, user_input):
        self.session_id = "mock_session_001"
        self.user_input = user_input
        self.state = CoordinatorState.COMPLETED
        self.error = None
        self.aggregated_result = MockAggregatedResult(user_input)

class MockCoordinator:
    """模拟协调器（匹配真实 CoordinatorAgent.process_request 接口）"""
    async def process_request(self, user_input: str, session_id=None):
        logger.info(f"🤖 [MockCoordinator] 接收请求: {user_input}")
        return MockSession(user_input)

print("=" * 70)
print("端到端测试：适配器 + 协调器集成")
print("=" * 70)

# 初始化组件
executor = LocalCommandExecutor()
coordinator = MockCoordinator()
adapter = AgentAdapter(executor, coordinator_agent=coordinator)

print(f"\n✅ 适配器初始化完成")
print(f"   代理启用: {adapter.agent_enabled}")

# 测试1: 复杂工具走代理路径
print("\n" + "-" * 70)
print("测试1: 复杂工具 intelligent_ctf_solve")
print("-" * 70)

data = {"target": "http://ctf.example.com", "mode": "aggressive"}
should_use = adapter.should_use_agent("intelligent_ctf_solve", data)
print(f"should_use_agent: {should_use}")

if should_use:
    result = adapter.execute_via_agent("intelligent_ctf_solve", data)
    print(f"\n执行结果:")
    print(f"  via_agent: {result.get('via_agent')}")
    print(f"  summary: {result.get('output')}")
    print(f"  agents_used: {result.get('agent_result', {}).get('agents_used')}")

# 测试2: 简单工具直接执行
print("\n" + "-" * 70)
print("测试2: 简单工具 nmap_scan")
print("-" * 70)

data = {"target": "192.168.1.1", "scan_type": "-sV"}
should_use = adapter.should_use_agent("nmap_scan", data)
print(f"should_use_agent: {should_use}")
print(f"预期: 直接执行（不通过代理）")

# 测试3: 统计信息
print("\n" + "-" * 70)
print("执行统计")
print("-" * 70)
stats = adapter.get_stats()
print(f"  代理调用: {stats['agent_calls']}")
print(f"  直接调用: {stats['direct_calls']}")
print(f"  回退次数: {stats['fallbacks']}")

print("\n✅ 端到端测试完成")
