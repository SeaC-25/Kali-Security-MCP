#!/bin/bash

#############################################################################
#  Kali MCP Server + Claude Skill 卸载脚本
#############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CLAUDE_DIR="$HOME/.claude"
MCP_INSTALL_DIR="$HOME/.local/share/kali-mcp"

echo -e "${YELLOW}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           Kali MCP Server 卸载程序                               ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo ""
echo "此脚本将删除以下内容:"
echo "  - MCP 服务器: $MCP_INSTALL_DIR"
echo "  - Claude 配置中的 Kali MCP 相关文件"
echo ""
read -p "是否继续卸载? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "卸载已取消"
    exit 0
fi

echo ""

# 删除 MCP 服务器
if [ -d "$MCP_INSTALL_DIR" ]; then
    rm -rf "$MCP_INSTALL_DIR"
    echo -e "${GREEN}[✓]${NC} 已删除 MCP 服务器目录"
else
    echo -e "${YELLOW}[!]${NC} MCP 服务器目录不存在"
fi

# 删除 Claude commands
if [ -d "$CLAUDE_DIR/commands" ]; then
    rm -f "$CLAUDE_DIR/commands/ctf.md"
    rm -f "$CLAUDE_DIR/commands/pentest.md"
    rm -f "$CLAUDE_DIR/commands/apt.md"
    rm -f "$CLAUDE_DIR/commands/vuln.md"
    rm -f "$CLAUDE_DIR/commands/recon.md"
    rm -f "$CLAUDE_DIR/commands/pwn.md"
    echo -e "${GREEN}[✓]${NC} 已删除快捷命令"
fi

# 删除 skills (可选，询问用户)
if [ -f "$CLAUDE_DIR/skills/kali-security.md" ]; then
    read -p "是否同时删除 Skill 知识库 (kali-security.md, 1.9MB)? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$CLAUDE_DIR/skills/kali-security.md"
        rm -f "$CLAUDE_DIR/skills/kali-index.json"
        rm -f "$CLAUDE_DIR/skills/attack-history.json"
        echo -e "${GREEN}[✓]${NC} 已删除 Skill 知识库"
    fi
fi

# 从 MCP 配置中移除 kali-intelligent-ctf
MCP_CONFIG="$CLAUDE_DIR/claude_desktop_config.json"
if [ -f "$MCP_CONFIG" ]; then
    python3 << EOF 2>/dev/null || true
import json

config_file = "$MCP_CONFIG"

try:
    with open(config_file, 'r') as f:
        config = json.load(f)

    if 'mcpServers' in config and 'kali-intelligent-ctf' in config['mcpServers']:
        del config['mcpServers']['kali-intelligent-ctf']

        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print("已从 MCP 配置中移除 kali-intelligent-ctf")
except Exception as e:
    print(f"配置更新失败: {e}")
EOF
    echo -e "${GREEN}[✓]${NC} 已更新 MCP 配置"
fi

echo ""
echo -e "${GREEN}卸载完成!${NC}"
echo ""
echo "注意: 全局 CLAUDE.md 文件未被删除，如需删除请手动执行:"
echo "  rm $CLAUDE_DIR/CLAUDE.md"
echo ""
