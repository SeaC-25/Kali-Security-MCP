"""
Tests for ToolRegistry and BaseTool (kali_mcp/tools/base.py)

Covers:
- ToolRegistry: singleton, register, get, get_by_category, list_tools, search, get_stats
- BaseTool: _generate_summary, _suggest_next_steps, validate_target, get_info
"""

import asyncio
from typing import Dict, Any, List
from unittest.mock import patch

import pytest

from kali_mcp.tools.base import (
    BaseTool,
    ToolResult,
    ToolCategory,
    RiskLevel,
    ToolRegistry,
    Finding,
)


# ===================== Test Tool Implementations =====================

class DummyTool(BaseTool):
    name = "dummy_test_tool"
    description = "A dummy tool for testing"
    category = ToolCategory.NETWORK
    risk_level = RiskLevel.LOW

    async def execute(self, target: str, **kwargs) -> ToolResult:
        return ToolResult(success=True, tool_name=self.name, target=target)


class WebDummyTool(BaseTool):
    name = "web_dummy_test_tool"
    description = "A web dummy tool"
    category = ToolCategory.WEB
    risk_level = RiskLevel.MEDIUM

    async def execute(self, target: str, **kwargs) -> ToolResult:
        return ToolResult(success=True, tool_name=self.name, target=target)


# ===================== ToolRegistry Tests =====================

@pytest.fixture
def registry():
    """Create a fresh registry (bypass singleton for testing)."""
    reg = object.__new__(ToolRegistry)
    reg._tools = {}
    reg._instances = {}
    reg._categories = {cat: [] for cat in ToolCategory}
    reg._initialized = True
    return reg


class TestRegistryRegister:
    def test_register_tool(self, registry):
        result = registry.register(DummyTool)
        assert result is DummyTool
        assert "dummy_test_tool" in registry._tools

    def test_register_overwrites(self, registry):
        registry.register(DummyTool)
        registry.register(DummyTool)
        assert "dummy_test_tool" in registry._tools

    def test_register_adds_to_category(self, registry):
        registry.register(DummyTool)
        assert "dummy_test_tool" in registry._categories[ToolCategory.NETWORK]


class TestRegistryGet:
    def test_get_registered(self, registry):
        registry.register(DummyTool)
        tool = registry.get("dummy_test_tool")
        assert tool is not None
        assert isinstance(tool, DummyTool)

    def test_get_nonexistent(self, registry):
        assert registry.get("nonexistent") is None

    def test_get_returns_same_instance(self, registry):
        registry.register(DummyTool)
        t1 = registry.get("dummy_test_tool")
        t2 = registry.get("dummy_test_tool")
        assert t1 is t2  # Lazy singleton


class TestRegistryCategory:
    def test_get_by_category(self, registry):
        registry.register(DummyTool)
        registry.register(WebDummyTool)
        network_tools = registry.get_by_category(ToolCategory.NETWORK)
        assert len(network_tools) == 1
        assert network_tools[0].name == "dummy_test_tool"

    def test_get_by_category_empty(self, registry):
        tools = registry.get_by_category(ToolCategory.EXPLOIT)
        assert tools == []


class TestRegistryListTools:
    def test_list_all(self, registry):
        registry.register(DummyTool)
        registry.register(WebDummyTool)
        tools = registry.list_tools()
        assert len(tools) == 2

    def test_list_by_category(self, registry):
        registry.register(DummyTool)
        registry.register(WebDummyTool)
        tools = registry.list_tools(category=ToolCategory.WEB)
        assert len(tools) == 1
        assert tools[0]["name"] == "web_dummy_test_tool"

    def test_list_by_risk_level(self, registry):
        registry.register(DummyTool)
        registry.register(WebDummyTool)
        tools = registry.list_tools(risk_level=RiskLevel.LOW)
        assert len(tools) == 1
        assert tools[0]["name"] == "dummy_test_tool"


class TestRegistrySearch:
    def test_search_by_name(self, registry):
        registry.register(DummyTool)
        registry.register(WebDummyTool)
        results = registry.search("web")
        assert len(results) >= 1
        assert any(r["name"] == "web_dummy_test_tool" for r in results)

    def test_search_by_description(self, registry):
        registry.register(DummyTool)
        results = registry.search("dummy")
        assert len(results) >= 1

    def test_search_no_results(self, registry):
        registry.register(DummyTool)
        results = registry.search("zzz_nonexistent")
        assert results == []


class TestRegistryStats:
    def test_stats_empty(self, registry):
        stats = registry.get_stats()
        assert stats["total_tools"] == 0
        assert stats["loaded_instances"] == 0

    def test_stats_with_tools(self, registry):
        registry.register(DummyTool)
        registry.register(WebDummyTool)
        registry.get("dummy_test_tool")  # Load one instance
        stats = registry.get_stats()
        assert stats["total_tools"] == 2
        assert stats["loaded_instances"] == 1
        assert stats["by_category"]["network"] >= 1


# ===================== BaseTool Tests =====================

class TestBaseToolMethods:
    def test_validate_target(self):
        tool = DummyTool()
        assert tool.validate_target("10.0.0.1") is True
        assert tool.validate_target("") is False
        assert tool.validate_target("  ") is False

    def test_get_info(self):
        tool = DummyTool()
        info = tool.get_info()
        assert info["name"] == "dummy_test_tool"
        assert info["category"] == "network"
        assert info["risk_level"] == "low"
        assert info["timeout"] == 300
        assert info["requires_root"] is False

    def test_generate_summary_failure(self):
        tool = DummyTool()
        result = ToolResult(success=False, error_message="timeout")
        summary = tool._generate_summary(result)
        assert "失败" in summary or "timeout" in summary

    def test_generate_summary_no_findings(self):
        tool = DummyTool()
        result = ToolResult(success=True)
        summary = tool._generate_summary(result)
        assert "未发现" in summary

    def test_generate_summary_with_findings(self):
        tool = DummyTool()
        result = ToolResult(success=True)
        result.add_finding("port", "80")
        result.add_finding("port", "443")
        result.add_finding("service", "http")
        summary = tool._generate_summary(result)
        assert "port" in summary

    def test_suggest_next_steps_web_port(self):
        tool = DummyTool()
        result = ToolResult(success=True)
        result.add_finding("port", "80")
        suggestions = tool._suggest_next_steps(result)
        assert any("gobuster" in s for s in suggestions)

    def test_suggest_next_steps_ssh_port(self):
        tool = DummyTool()
        result = ToolResult(success=True)
        result.add_finding("port", "22")
        suggestions = tool._suggest_next_steps(result)
        assert any("hydra" in s or "SSH" in s for s in suggestions)

    def test_suggest_next_steps_mysql_port(self):
        tool = DummyTool()
        result = ToolResult(success=True)
        result.add_finding("port", "3306")
        suggestions = tool._suggest_next_steps(result)
        assert any("sqlmap" in s or "MySQL" in s for s in suggestions)

    def test_suggest_next_steps_high_vuln(self):
        tool = DummyTool()
        result = ToolResult(success=True)
        result.add_finding("vulnerability", "CVE-2024-1234", severity="critical")
        suggestions = tool._suggest_next_steps(result)
        assert any("searchsploit" in s for s in suggestions)

    def test_suggest_max_5(self):
        tool = DummyTool()
        result = ToolResult(success=True)
        # Add many findings
        for port in ["80", "443", "22", "3306", "8080", "8443"]:
            result.add_finding("port", port)
        suggestions = tool._suggest_next_steps(result)
        assert len(suggestions) <= 5


# ===================== BaseTool.run Tests =====================

class TestBaseToolRun:
    @pytest.mark.asyncio
    async def test_run_success(self):
        tool = DummyTool()
        result = await tool.run("10.0.0.1")
        assert result.success is True
        assert result.tool_name == "dummy_test_tool"
        assert result.target == "10.0.0.1"
        assert result.execution_time > 0

    @pytest.mark.asyncio
    async def test_run_sets_summary(self):
        tool = DummyTool()
        result = await tool.run("10.0.0.1")
        assert result.summary is not None and result.summary != ""
