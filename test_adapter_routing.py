#!/usr/bin/env python3
"""验证适配器路由逻辑"""

from kali_mcp.core.agent_adapter import AgentAdapter
from kali_mcp.core.tool_router import ToolRouter

# 测试工具路由器
print("=" * 60)
print("工具路由器测试")
print("=" * 60)

complex_tools = ["intelligent_ctf_solve", "adaptive_web_penetration", "comprehensive_recon"]
simple_tools = ["nmap_scan", "gobuster_scan", "sqlmap_scan"]

print(f"\n复杂工具（应该走代理路径）:")
for tool in complex_tools:
    route = ToolRouter.get_route(tool, {})
    print(f"  {tool}: {route}")

print(f"\n简单工具（应该直接执行）:")
for tool in simple_tools:
    route = ToolRouter.get_route(tool, {})
    print(f"  {tool}: {route}")

# 测试适配器（无实际代理）
print("\n" + "=" * 60)
print("适配器测试（无代理模式）")
print("=" * 60)

class MockExecutor:
    def execute_tool_with_data(self, tool, data):
        return {"success": True, "output": f"Mock execution: {tool}"}

adapter = AgentAdapter(MockExecutor(), coordinator_agent=None)

print(f"\n代理启用状态: {adapter.agent_enabled}")
print(f"should_use_agent('intelligent_ctf_solve'): {adapter.should_use_agent('intelligent_ctf_solve', {})}")
print(f"should_use_agent('nmap_scan'): {adapter.should_use_agent('nmap_scan', {})}")

print("\n✅ 适配器路由逻辑验证完成")
