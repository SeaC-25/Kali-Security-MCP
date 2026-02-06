#!/usr/bin/env python3
"""
测试 AsyncExecutor 异步执行器
"""

import pytest
import asyncio
import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kali_mcp.core.executor import AsyncExecutor


class TestAsyncExecutor:
    """AsyncExecutor 测试类"""

    @pytest.fixture
    def executor(self):
        """创建执行器实例"""
        return AsyncExecutor()

    @pytest.mark.asyncio
    async def test_run_simple_command(self, executor):
        """测试执行简单命令"""
        result = await executor.run_command("echo 'Hello World'", timeout=10)

        assert result.success is True
        assert "Hello World" in result.stdout
        assert result.return_code == 0

    @pytest.mark.asyncio
    async def test_run_command_with_error(self, executor):
        """测试执行失败的命令"""
        result = await executor.run_command("ls /nonexistent_directory_12345", timeout=10)

        assert result.success is False
        assert result.return_code != 0

    @pytest.mark.asyncio
    async def test_run_command_timeout(self, executor):
        """测试命令超时"""
        result = await executor.run_command("sleep 10", timeout=1)

        assert result.success is False
        # 检查状态或错误消息
        from kali_mcp.core.executor import ExecutionStatus
        assert result.status == ExecutionStatus.TIMEOUT or "timeout" in result.error_message.lower() or "超时" in result.error_message

    @pytest.mark.asyncio
    async def test_run_parallel_commands(self, executor):
        """测试并行执行命令"""
        commands = [
            "echo 'Command 1'",
            "echo 'Command 2'",
            "echo 'Command 3'"
        ]

        results = await executor.run_parallel(commands, timeout=10)

        assert len(results) == 3
        for i, result in enumerate(results):
            assert result.success is True
            assert f"Command {i+1}" in result.stdout

    @pytest.mark.asyncio
    async def test_run_command_with_pipe(self, executor):
        """测试管道命令"""
        result = await executor.run_command("echo 'test line 1\ntest line 2' | grep 'line 2'", timeout=10)

        assert result.success is True
        assert "line 2" in result.stdout

    @pytest.mark.asyncio
    async def test_get_stats(self, executor):
        """测试获取统计信息"""
        # 执行几个命令
        await executor.run_command("echo 'test1'", timeout=10)
        await executor.run_command("echo 'test2'", timeout=10)

        stats = executor.get_stats()

        assert "total_executed" in stats
        assert stats["total_executed"] >= 2

    @pytest.mark.asyncio
    async def test_command_sanitization(self, executor):
        """测试命令安全性"""
        # 测试危险字符处理
        result = await executor.run_command("echo 'test; ls'", timeout=10)
        # 应该正常执行echo而不是执行ls
        assert result.success is True


class TestExecutorEdgeCases:
    """边界情况测试"""

    @pytest.fixture
    def executor(self):
        return AsyncExecutor()

    @pytest.mark.asyncio
    async def test_empty_command(self, executor):
        """测试空命令"""
        result = await executor.run_command("", timeout=10)
        # 空命令应该返回错误或空结果
        assert result is not None

    @pytest.mark.asyncio
    async def test_very_long_output(self, executor):
        """测试长输出"""
        result = await executor.run_command("seq 1 1000", timeout=30)

        assert result.success is True
        assert len(result.stdout) > 0

    @pytest.mark.asyncio
    async def test_binary_output(self, executor):
        """测试二进制输出处理"""
        result = await executor.run_command("head -c 100 /dev/urandom | base64", timeout=10)

        assert result.success is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
