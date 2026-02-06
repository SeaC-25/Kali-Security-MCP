#!/usr/bin/env python3
"""
集成测试
"""

import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestModuleIntegration:
    """模块集成测试"""

    def test_import_all_modules(self):
        """测试导入所有模块"""
        # 核心模块
        from kali_mcp.core import (
            AsyncExecutor,
            SessionManager,
            StrategyEngine,
            ResultCache
        )

        # 工具模块
        from kali_mcp.tools import (
            BaseTool,
            ToolResult,
            ToolRegistry,
            get_registry
        )

        # AI 模块
        from kali_mcp.ai import (
            IntentAnalyzer,
            ToolRecommender,
            LearningEngine
        )

        # 输出模块
        from kali_mcp.output import (
            OutputFormatter,
            ReportGenerator,
            ProgressTracker
        )

        # 监控模块
        from kali_mcp.monitor import (
            MetricsCollector,
            HealthChecker,
            get_health_checker,
            get_metrics_collector
        )

        # 验证所有导入成功
        assert AsyncExecutor is not None
        assert BaseTool is not None
        assert IntentAnalyzer is not None

    def test_package_init(self):
        """测试包初始化"""
        import kali_mcp

        assert hasattr(kali_mcp, '__version__')
        assert kali_mcp.__version__ == "2.0.0"


class TestWorkflowIntegration:
    """工作流集成测试"""

    @pytest.fixture
    def setup_components(self):
        """设置组件"""
        from kali_mcp.core import AsyncExecutor, SessionManager
        from kali_mcp.ai import IntentAnalyzer, ToolRecommender
        from kali_mcp.tools import get_registry

        return {
            "executor": AsyncExecutor(),
            "session_manager": SessionManager(),
            "intent_analyzer": IntentAnalyzer(),
            "recommender": ToolRecommender(),
            "registry": get_registry()
        }

    def test_intent_to_recommendation_flow(self, setup_components):
        """测试意图到推荐的流程"""
        intent_analyzer = setup_components["intent_analyzer"]
        recommender = setup_components["recommender"]

        # 分析意图
        intent = intent_analyzer.analyze("扫描 http://example.com 的漏洞")

        # 基于意图推荐工具
        recommendations = recommender.recommend(
            target=intent.extracted_target or "http://example.com",
            target_type="web",
            limit=5
        )

        assert len(recommendations) > 0

    def test_session_workflow(self, setup_components):
        """测试会话工作流"""
        from kali_mcp.core.session import AttackMode
        session_manager = setup_components["session_manager"]

        # 创建会话
        session = session_manager.create_session(
            target="192.168.1.1",
            mode=AttackMode.PENTEST,
            session_name="Test Session"
        )

        assert session is not None
        assert session.target == "192.168.1.1"

        # 获取会话
        retrieved = session_manager.get_session(session.session_id)
        assert retrieved is not None

    @pytest.mark.asyncio
    async def test_executor_with_metrics(self, setup_components):
        """测试执行器与指标集成"""
        from kali_mcp.monitor import get_metrics_collector

        executor = setup_components["executor"]
        metrics = get_metrics_collector()

        # 重置指标
        metrics.reset()

        # 执行命令
        result = await executor.run_command("echo 'test'", timeout=10)

        # 记录指标
        metrics.record_execution("test_command", result.success, 0.1)

        # 获取摘要
        summary = metrics.get_summary()
        assert summary["total_executions"] >= 1


class TestCTFIntegration:
    """CTF 场景集成测试"""

    @pytest.fixture
    def ctf_setup(self):
        """CTF 测试设置"""
        from kali_mcp.ai import IntentAnalyzer
        from kali_mcp.tools.base import ToolResult

        return {
            "analyzer": IntentAnalyzer(),
            "ToolResult": ToolResult
        }

    def test_ctf_flag_detection(self, ctf_setup, ctf_flag):
        """测试 CTF Flag 检测"""
        ToolResult = ctf_setup["ToolResult"]

        result = ToolResult(success=True)
        result.add_finding("text", f"Found: {ctf_flag}")

        assert len(result.flags_found) > 0
        assert ctf_flag in result.flags_found

    def test_ctf_intent_recognition(self, ctf_setup):
        """测试 CTF 意图识别"""
        from kali_mcp.ai.intent import IntentType

        analyzer = ctf_setup["analyzer"]

        # 测试各种 CTF 相关输入
        ctf_inputs = [
            "找 flag",
            "解决这道 CTF 题目",
            "这是一道 Web 题，帮我拿到 flag",
        ]

        for input_text in ctf_inputs:
            intent = analyzer.analyze(input_text)
            assert intent.intent_type == IntentType.CTF_SOLVE


class TestReportIntegration:
    """报告生成集成测试"""

    def test_generate_markdown_report(self, sample_scan_result, sample_vuln_result):
        """测试生成 Markdown 报告"""
        from kali_mcp.output.reporter import ReportGenerator, ReportData, ReportFormat, ReportType
        from datetime import datetime

        reporter = ReportGenerator()

        report_data = ReportData(
            title="测试渗透报告",
            target="192.168.1.100",
            report_type=ReportType.PENTEST,
            start_time=datetime.now(),
            findings=sample_scan_result.get("findings", []) + sample_vuln_result.get("findings", [])
        )

        report = reporter.generate(report_data, ReportFormat.MARKDOWN)

        assert "# 测试渗透报告" in report or "测试渗透报告" in report
        assert "192.168.1.100" in report

    def test_generate_json_report(self, sample_scan_result):
        """测试生成 JSON 报告"""
        from kali_mcp.output.reporter import ReportGenerator, ReportData, ReportFormat, ReportType
        from datetime import datetime
        import json

        reporter = ReportGenerator()

        report_data = ReportData(
            title="JSON Report Test",
            target="test.com",
            report_type=ReportType.PENTEST,
            start_time=datetime.now()
        )

        report = reporter.generate(report_data, ReportFormat.JSON)

        # 验证是有效的 JSON
        data = json.loads(report)
        assert "title" in data or "target" in data


class TestHealthCheckIntegration:
    """健康检查集成测试"""

    @pytest.mark.asyncio
    async def test_full_health_check(self):
        """测试完整健康检查"""
        from kali_mcp.monitor import get_health_checker

        checker = get_health_checker()
        report = await checker.full_health_check()

        assert "status" in report
        assert "timestamp" in report
        assert "system" in report
        assert "summary" in report

    def test_system_resources_check(self):
        """测试系统资源检查"""
        from kali_mcp.monitor import get_health_checker

        checker = get_health_checker()
        resources = checker.check_system_resources()

        assert "cpu_usage" in resources
        assert "memory_usage" in resources
        assert "disk_usage" in resources

        # 验证值在合理范围
        assert 0 <= resources["cpu_usage"] <= 100
        assert 0 <= resources["memory_usage"] <= 100
        assert 0 <= resources["disk_usage"] <= 100


@pytest.mark.slow
class TestSlowIntegration:
    """慢速集成测试"""

    @pytest.mark.asyncio
    @pytest.mark.requires_tools("nmap")
    async def test_nmap_scan_integration(self):
        """测试 Nmap 扫描集成（需要 nmap）"""
        from kali_mcp.core import AsyncExecutor

        executor = AsyncExecutor()
        result = await executor.run_command("nmap -sn 127.0.0.1", timeout=30)

        assert result.success is True
        assert "127.0.0.1" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
