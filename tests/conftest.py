#!/usr/bin/env python3
"""
Pytest 配置和共享 fixtures
"""

import pytest
import asyncio
import sys
import os
import tempfile
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(scope="session")
def event_loop():
    """创建事件循环"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """创建临时目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_target():
    """模拟目标"""
    return {
        "ip": "192.168.1.100",
        "url": "http://testsite.local",
        "domain": "testsite.local"
    }


@pytest.fixture
def sample_scan_result():
    """示例扫描结果"""
    return {
        "success": True,
        "tool": "nmap_scan",
        "target": "192.168.1.100",
        "findings": [
            {"type": "port", "value": "22/ssh", "severity": "info"},
            {"type": "port", "value": "80/http", "severity": "info"},
            {"type": "port", "value": "443/https", "severity": "info"},
        ],
        "execution_time": 15.5
    }


@pytest.fixture
def sample_vuln_result():
    """示例漏洞结果"""
    return {
        "success": True,
        "tool": "nuclei_scan",
        "target": "http://testsite.local",
        "findings": [
            {
                "type": "vulnerability",
                "value": "SQL Injection",
                "severity": "high",
                "details": {"parameter": "id", "url": "/api/users?id=1"}
            },
            {
                "type": "vulnerability",
                "value": "XSS",
                "severity": "medium",
                "details": {"parameter": "search", "url": "/search"}
            }
        ]
    }


@pytest.fixture
def ctf_flag():
    """CTF Flag 示例"""
    return "flag{test_flag_12345678}"


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch, temp_dir):
    """设置测试环境"""
    # 使用临时目录作为数据目录
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(temp_dir))


# 标记慢速测试
def pytest_configure(config):
    """配置 pytest 标记"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_tools: marks tests that require external tools"
    )


# 跳过需要外部工具的测试
def pytest_collection_modifyitems(config, items):
    """修改测试集合"""
    import shutil

    for item in items:
        # 检查是否需要外部工具
        if "requires_tools" in item.keywords:
            required_tools = item.keywords["requires_tools"].args
            for tool in required_tools:
                if not shutil.which(tool):
                    item.add_marker(
                        pytest.mark.skip(reason=f"需要工具 {tool}")
                    )
                    break
