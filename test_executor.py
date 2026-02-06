#!/usr/bin/env python3
"""测试LocalCommandExecutor功能"""

import sys
sys.path.insert(0, '/home/zss/MCP-Kali-Server-main')

from mcp_server import LocalCommandExecutor

def test_executor():
    print("=" * 60)
    print("测试LocalCommandExecutor功能")
    print("=" * 60)

    executor = LocalCommandExecutor(timeout=10)

    # 1. 测试工具可用性检查
    print("\n1. 测试Kali工具可用性检查...")
    tools = ['nmap', 'gobuster', 'sqlmap', 'nikto', 'hydra', 'masscan']
    for tool in tools:
        available = executor.check_tool_available(tool)
        status = '✅' if available else '❌'
        result = '可用' if available else '未安装'
        print(f"   {status} {tool}: {result}")

    # 2. 测试简单命令执行
    print("\n2. 测试简单命令执行...")
    result = executor.execute_command('whoami')
    if result['success']:
        print(f"   ✅ whoami: {result['output'].strip()}")
    else:
        print(f"   ❌ 失败: {result['error']}")

    # 3. 测试nmap命令构建和执行
    print("\n3. 测试nmap工具...")
    result = executor.execute_command('nmap --version', timeout=5)
    if result['success']:
        version = result['output'].split('\n')[0]
        print(f"   ✅ {version}")
    else:
        print(f"   ❌ nmap不可用: {result['error']}")

    print("\n" + "=" * 60)
    print("✅ 测试完成")
    print("=" * 60)

if __name__ == "__main__":
    test_executor()
