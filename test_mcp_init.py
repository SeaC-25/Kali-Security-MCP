#!/usr/bin/env python3
"""测试MCP服务器初始化"""

import sys
import asyncio
import inspect
sys.path.insert(0, '/home/zss/MCP-Kali-Server-main')

def test_mcp_init():
    print("=" * 60)
    print("测试MCP服务器初始化")
    print("=" * 60)

    try:
        # 导入并初始化
        from mcp_server import setup_mcp_server
        import mcp_server
        print("\n✅ 模块导入成功")

        # 初始化MCP服务器
        print("\n初始化MCP服务器...")
        mcp = setup_mcp_server()
        print(f"✅ MCP服务器初始化成功")

        # 检查全局executor
        if hasattr(mcp_server, 'executor'):
            executor = mcp_server.executor
            print(f"\n检查全局executor:")
            print(f"   类型: {type(executor).__name__}")
            print(f"   工作目录: {executor.working_dir}")
            print(f"   超时设置: {executor.timeout}秒")
        else:
            print("\n⚠️ executor未找到（可能在setup后才创建）")
        print(f"   服务器名称: {mcp.name}")

        # 获取已注册的工具数量
        if hasattr(mcp, 'list_tools'):
            tools = mcp.list_tools()
            if inspect.iscoroutine(tools):
                tools = asyncio.run(tools)
            print(f"   已注册工具数: {len(tools)}")
            print(f"\n前10个工具:")
            for i, tool in enumerate(tools[:10], 1):
                tool_name = None
                if isinstance(tool, dict):
                    tool_name = tool.get('name')
                else:
                    tool_name = getattr(tool, 'name', None)
                if not tool_name:
                    tool_name = 'unknown'
                print(f"      {i}. {tool_name}")
        else:
            print("   (无法获取工具列表)")

        print("\n" + "=" * 60)
        print("✅ MCP服务器初始化测试完成")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    test_mcp_init()
