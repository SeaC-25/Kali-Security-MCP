#!/usr/bin/env python3
"""
测试工具系统
"""

import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kali_mcp.tools.base import (
    BaseTool,
    ToolResult,
    ToolRegistry,
    ToolCategory,
    RiskLevel,
    Finding,
    tool,
    get_registry
)


class TestToolResult:
    """ToolResult 测试类"""

    def test_create_result(self):
        """测试创建结果对象"""
        result = ToolResult(
            success=True,
            tool_name="test_tool",
            target="127.0.0.1",
            summary="测试成功"
        )

        assert result.success is True
        assert result.tool_name == "test_tool"
        assert result.target == "127.0.0.1"

    def test_add_finding(self):
        """测试添加发现项"""
        result = ToolResult(success=True)
        result.add_finding("port", "80/tcp", severity="low", service="http")

        assert len(result.findings) == 1
        assert result.findings[0].finding_type == "port"
        assert result.findings[0].value == "80/tcp"

    def test_flag_detection(self):
        """测试Flag检测"""
        result = ToolResult(success=True)

        # 添加包含Flag的发现
        result.add_finding("text", "flag{test_flag_12345}")

        assert len(result.flags_found) == 1
        assert "flag{test_flag_12345}" in result.flags_found

    def test_extract_flags(self):
        """测试Flag提取"""
        result = ToolResult(success=True)

        text = """
        Some random text
        flag{first_flag}
        More text here
        FLAG{SECOND_FLAG}
        ctf{third_flag}
        """

        flags = result.extract_flags(text)

        assert len(flags) >= 3
        assert any("first_flag" in f for f in flags)

    def test_to_dict(self):
        """测试转换为字典"""
        result = ToolResult(
            success=True,
            tool_name="nmap",
            target="192.168.1.1",
            summary="发现3个开放端口"
        )
        result.add_finding("port", "22/ssh")
        result.add_finding("port", "80/http")

        data = result.to_dict()

        assert data["success"] is True
        assert data["tool"] == "nmap"
        assert data["findings_count"] == 2

    def test_suggest_next_step(self):
        """测试建议下一步"""
        result = ToolResult(success=True)
        result.suggest_next_step("尝试SQL注入", "sqlmap_scan")

        assert len(result.next_steps) == 1
        assert "SQL注入" in result.next_steps[0]
        assert "sqlmap_scan" in result.recommended_tools


class TestToolRegistry:
    """ToolRegistry 测试类"""

    def test_singleton(self):
        """测试单例模式"""
        registry1 = ToolRegistry()
        registry2 = ToolRegistry()

        assert registry1 is registry2

    def test_register_tool(self):
        """测试注册工具"""
        registry = get_registry()

        @tool(name="test_tool_1", category=ToolCategory.UTILITY)
        class TestTool1(BaseTool):
            async def execute(self, target, **kwargs):
                return ToolResult(success=True)

        # 验证工具已注册
        tool_instance = registry.get("test_tool_1")
        assert tool_instance is not None

    def test_get_by_category(self):
        """测试按分类获取工具"""
        registry = get_registry()

        # 创建并注册测试工具
        @tool(name="test_network_tool", category=ToolCategory.NETWORK)
        class TestNetworkTool(BaseTool):
            async def execute(self, target, **kwargs):
                return ToolResult(success=True)

        network_tools = registry.get_by_category(ToolCategory.NETWORK)
        assert len(network_tools) > 0

    def test_list_tools(self):
        """测试列出工具"""
        registry = get_registry()
        tools = registry.list_tools()

        assert isinstance(tools, list)
        # 验证工具信息结构
        if tools:
            tool_info = tools[0]
            assert "name" in tool_info
            assert "category" in tool_info

    def test_search_tools(self):
        """测试搜索工具"""
        registry = get_registry()

        @tool(name="searchable_scanner", description="A searchable test scanner")
        class SearchableScanner(BaseTool):
            async def execute(self, target, **kwargs):
                return ToolResult(success=True)

        results = registry.search("searchable")
        assert len(results) > 0

    def test_get_stats(self):
        """测试获取统计"""
        registry = get_registry()
        stats = registry.get_stats()

        assert "total_tools" in stats
        assert "by_category" in stats
        assert stats["total_tools"] >= 0


class TestFinding:
    """Finding 测试类"""

    def test_create_finding(self):
        """测试创建发现项"""
        finding = Finding(
            finding_type="vulnerability",
            value="SQL Injection",
            severity="high",
            confidence=0.95,
            details={"parameter": "id", "type": "boolean-based"}
        )

        assert finding.finding_type == "vulnerability"
        assert finding.severity == "high"
        assert finding.confidence == 0.95

    def test_finding_to_dict(self):
        """测试发现项转字典"""
        finding = Finding(
            finding_type="port",
            value="443/https",
            severity="info"
        )

        data = finding.to_dict()

        assert data["type"] == "port"
        assert data["value"] == "443/https"
        assert data["severity"] == "info"


class TestToolDecorator:
    """@tool 装饰器测试"""

    def test_class_decorator(self):
        """测试类装饰器"""
        @tool(
            name="decorated_class_tool",
            category=ToolCategory.WEB,
            description="A decorated class tool",
            risk_level=RiskLevel.MEDIUM,
            timeout=120
        )
        class DecoratedClassTool(BaseTool):
            async def execute(self, target, **kwargs):
                return ToolResult(success=True, summary="Executed")

        # 验证属性被正确设置
        assert DecoratedClassTool.name == "decorated_class_tool"
        assert DecoratedClassTool.category == ToolCategory.WEB
        assert DecoratedClassTool.risk_level == RiskLevel.MEDIUM
        assert DecoratedClassTool.default_timeout == 120

    @pytest.mark.asyncio
    async def test_function_decorator(self):
        """测试函数装饰器"""
        @tool(name="decorated_func_tool", category=ToolCategory.UTILITY)
        async def decorated_func(target: str) -> ToolResult:
            return ToolResult(success=True, summary=f"Scanned {target}")

        # 执行装饰后的函数
        registry = get_registry()
        result = await registry.execute("decorated_func_tool", "test.com")

        assert result.success is True


class TestBaseToolExecution:
    """BaseTool 执行测试"""

    @pytest.mark.asyncio
    async def test_tool_run_with_timing(self):
        """测试工具执行计时"""
        @tool(name="timing_test_tool")
        class TimingTestTool(BaseTool):
            async def execute(self, target, **kwargs):
                await asyncio.sleep(0.1)  # 模拟执行时间
                return ToolResult(success=True)

        registry = get_registry()
        result = await registry.execute("timing_test_tool", "test")

        assert result.execution_time >= 0.1
        assert result.tool_name == "timing_test_tool"

    @pytest.mark.asyncio
    async def test_tool_error_handling(self):
        """测试工具错误处理"""
        @tool(name="error_test_tool")
        class ErrorTestTool(BaseTool):
            async def execute(self, target, **kwargs):
                raise ValueError("Test error")

        registry = get_registry()
        result = await registry.execute("error_test_tool", "test")

        assert result.success is False
        assert "Test error" in result.error_message


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
