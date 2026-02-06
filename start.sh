#!/bin/bash
# KaliMCP 本地启动脚本
# 纯Linux单机部署 - 无需后端服务器

PROJECT_DIR="/home/zss/MCP-Kali-Server-main"
cd "$PROJECT_DIR"

echo "======================================"
echo "  KaliMCP 本地服务器启动脚本"
echo "======================================"
echo ""

# 检查虚拟环境
if [ ! -d ".venv" ]; then
    echo "❌ 虚拟环境不存在，正在创建..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install mcp fastmcp requests
    echo "✅ 虚拟环境创建完成"
else
    echo "✅ 虚拟环境已存在"
fi

# 激活虚拟环境
source .venv/bin/activate
echo "✅ 虚拟环境已激活"

# 检查关键工具
echo ""
echo "🔍 检查Kali工具..."
for tool in nmap sqlmap gobuster; do
    if command -v $tool &> /dev/null; then
        echo "  ✅ $tool"
    else
        echo "  ⚠️  $tool 未安装"
    fi
done

echo ""
echo "🚀 启动MCP服务器..."
echo "======================================"
echo ""

# 启动MCP服务器
python mcp_server.py

echo ""
echo "======================================"
echo "✅ MCP服务器已关闭"
echo "======================================"
