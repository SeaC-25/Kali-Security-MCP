#!/bin/bash

#############################################################################
#  Kali MCP Server + Claude Skill 一键安装脚本
#
#  功能:
#    - 安装 MCP 服务器及其依赖
#    - 配置 Claude Code 的 MCP 服务器
#    - 部署 Skill 知识库和快捷命令
#
#  使用方法:
#    chmod +x install.sh
#    ./install.sh
#
#  作者: Kali MCP Team
#  版本: 1.0.0
#############################################################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLAUDE_DIR="$HOME/.claude"
MCP_INSTALL_DIR="$HOME/.local/share/kali-mcp"

# 打印带颜色的消息
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║     🔧 Kali MCP Server + Claude Skill 一键安装程序 🔧           ║"
    echo "║                                                                  ║"
    echo "║     版本: 1.0.0                                                  ║"
    echo "║     193个安全工具 | 58K行知识库 | 6个快捷命令                    ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${CYAN}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# 检查系统环境
check_environment() {
    print_step "检查系统环境..."

    # 检查是否为 Linux
    if [[ "$(uname)" != "Linux" ]]; then
        print_error "此脚本仅支持 Linux 系统"
        exit 1
    fi

    # 检查是否为 Kali Linux (可选)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "kali" ]]; then
            print_success "检测到 Kali Linux $VERSION"
        else
            print_warning "当前系统为 $ID，建议在 Kali Linux 上运行以获得完整功能"
        fi
    fi

    # 检查 Python 版本
    if ! command -v python3 &> /dev/null; then
        print_error "未找到 Python3，请先安装 Python 3.8+"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    print_success "Python 版本: $PYTHON_VERSION"

    # 检查 pip
    if ! command -v pip3 &> /dev/null; then
        print_warning "未找到 pip3，尝试安装..."
        sudo apt-get update && sudo apt-get install -y python3-pip
    fi

    # 检查 Claude Code 是否已安装
    if command -v claude &> /dev/null; then
        print_success "检测到 Claude Code CLI"
    else
        print_warning "未检测到 Claude Code CLI，请确保已安装: npm install -g @anthropic-ai/claude-code"
    fi
}

# 安装 Python 依赖
install_dependencies() {
    print_step "安装 Python 依赖..."

    # 创建虚拟环境（可选）
    # python3 -m venv "$MCP_INSTALL_DIR/venv"
    # source "$MCP_INSTALL_DIR/venv/bin/activate"

    # 安装 MCP 依赖
    pip3 install --user mcp pydantic aiohttp aiofiles 2>/dev/null || {
        print_warning "部分依赖安装失败，尝试使用 sudo..."
        sudo pip3 install mcp pydantic aiohttp aiofiles
    }

    print_success "Python 依赖安装完成"
}

# 安装 MCP 服务器
install_mcp_server() {
    print_step "安装 MCP 服务器..."

    # 创建安装目录
    mkdir -p "$MCP_INSTALL_DIR"

    # 复制 MCP 服务器文件
    cp "$PROJECT_DIR/mcp_server.py" "$MCP_INSTALL_DIR/"

    # 复制其他必要文件（如果存在）
    [ -f "$PROJECT_DIR/fast_config.py" ] && cp "$PROJECT_DIR/fast_config.py" "$MCP_INSTALL_DIR/"
    [ -f "$PROJECT_DIR/connection_pool.py" ] && cp "$PROJECT_DIR/connection_pool.py" "$MCP_INSTALL_DIR/"
    [ -d "$PROJECT_DIR/pwnpasi" ] && cp -r "$PROJECT_DIR/pwnpasi" "$MCP_INSTALL_DIR/"

    # 设置执行权限
    chmod +x "$MCP_INSTALL_DIR/mcp_server.py"

    print_success "MCP 服务器已安装到: $MCP_INSTALL_DIR"
}

# 配置 Claude Code
configure_claude() {
    print_step "配置 Claude Code..."

    # 创建 Claude 配置目录
    mkdir -p "$CLAUDE_DIR"/{commands,skills}

    # 复制全局 CLAUDE.md
    cp "$SCRIPT_DIR/claude-config/CLAUDE.md" "$CLAUDE_DIR/CLAUDE.md"
    print_success "已安装全局指令文件"

    # 复制 commands
    cp "$SCRIPT_DIR/claude-config/commands/"*.md "$CLAUDE_DIR/commands/" 2>/dev/null || true
    COMMANDS_COUNT=$(ls -1 "$CLAUDE_DIR/commands/"*.md 2>/dev/null | wc -l)
    print_success "已安装 $COMMANDS_COUNT 个快捷命令"

    # 复制 skills
    cp "$SCRIPT_DIR/claude-config/skills/"* "$CLAUDE_DIR/skills/" 2>/dev/null || true
    print_success "已安装 Skill 知识库和索引"

    # 配置 MCP 服务器
    configure_mcp_settings
}

# 配置 MCP 服务器设置
configure_mcp_settings() {
    print_step "配置 MCP 服务器连接..."

    # Claude Code 的 MCP 配置文件路径
    MCP_CONFIG_FILE="$CLAUDE_DIR/claude_desktop_config.json"

    # 检查是否存在现有配置
    if [ -f "$MCP_CONFIG_FILE" ]; then
        print_warning "检测到现有 MCP 配置，将进行合并..."
        # 备份现有配置
        cp "$MCP_CONFIG_FILE" "$MCP_CONFIG_FILE.backup.$(date +%Y%m%d%H%M%S)"

        # 使用 Python 合并配置
        python3 << EOF
import json
import os

config_file = "$MCP_CONFIG_FILE"
mcp_install_dir = "$MCP_INSTALL_DIR"

# 读取现有配置
with open(config_file, 'r') as f:
    config = json.load(f)

# 确保 mcpServers 存在
if 'mcpServers' not in config:
    config['mcpServers'] = {}

# 添加 Kali MCP 服务器配置
config['mcpServers']['kali-intelligent-ctf'] = {
    "command": "python3",
    "args": [os.path.join(mcp_install_dir, "mcp_server.py")],
    "env": {}
}

# 写回配置
with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)

print("配置已合并")
EOF
    else
        # 创建新配置
        cat > "$MCP_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "python3",
      "args": ["$MCP_INSTALL_DIR/mcp_server.py"],
      "env": {}
    }
  }
}
EOF
    fi

    print_success "MCP 服务器配置完成"
}

# 验证安装
verify_installation() {
    print_step "验证安装..."

    local errors=0

    # 检查 MCP 服务器文件
    if [ -f "$MCP_INSTALL_DIR/mcp_server.py" ]; then
        print_success "MCP 服务器文件 ✓"
    else
        print_error "MCP 服务器文件缺失"
        ((errors++))
    fi

    # 检查 CLAUDE.md
    if [ -f "$CLAUDE_DIR/CLAUDE.md" ]; then
        print_success "全局指令文件 ✓"
    else
        print_error "全局指令文件缺失"
        ((errors++))
    fi

    # 检查 skills
    if [ -f "$CLAUDE_DIR/skills/kali-security.md" ]; then
        SKILL_LINES=$(wc -l < "$CLAUDE_DIR/skills/kali-security.md")
        print_success "Skill 知识库 ✓ ($SKILL_LINES 行)"
    else
        print_warning "Skill 知识库未安装（可选）"
    fi

    # 检查 commands
    COMMANDS_COUNT=$(ls -1 "$CLAUDE_DIR/commands/"*.md 2>/dev/null | wc -l)
    if [ "$COMMANDS_COUNT" -gt 0 ]; then
        print_success "快捷命令 ✓ ($COMMANDS_COUNT 个)"
    else
        print_warning "快捷命令未安装（可选）"
    fi

    # 检查 Python 语法
    if python3 -m py_compile "$MCP_INSTALL_DIR/mcp_server.py" 2>/dev/null; then
        print_success "Python 语法检查 ✓"
    else
        print_error "MCP 服务器存在语法错误"
        ((errors++))
    fi

    return $errors
}

# 显示安装完成信息
show_completion() {
    echo ""
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║                    🎉 安装完成! 🎉                               ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}安装位置:${NC}"
    echo "  MCP 服务器: $MCP_INSTALL_DIR"
    echo "  Claude 配置: $CLAUDE_DIR"
    echo ""
    echo -e "${CYAN}快捷命令:${NC}"
    echo "  /ctf TARGET [CATEGORY]   - CTF 快速解题"
    echo "  /pentest TARGET [MODE]   - 渗透测试"
    echo "  /apt TARGET              - APT 攻击模拟"
    echo "  /vuln TARGET [TYPE]      - 漏洞评估"
    echo "  /recon TARGET [DEPTH]    - 信息收集"
    echo "  /pwn BINARY [REMOTE]     - PWN 攻击"
    echo ""
    echo -e "${CYAN}下一步:${NC}"
    echo "  1. 重启 Claude Code 以加载新配置"
    echo "  2. 在 Claude Code 中测试: server_health()"
    echo "  3. 尝试快捷命令: /ctf http://example.com web"
    echo ""
    echo -e "${YELLOW}注意: 本工具仅用于授权的安全测试和 CTF 竞赛${NC}"
    echo ""
}

# 主安装流程
main() {
    print_banner

    echo ""
    echo -e "${YELLOW}此脚本将安装 Kali MCP Server 及相关配置到您的系统${NC}"
    echo ""
    read -p "是否继续安装? [Y/n] " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
        echo "安装已取消"
        exit 0
    fi

    echo ""

    check_environment
    install_dependencies
    install_mcp_server
    configure_claude

    echo ""
    if verify_installation; then
        show_completion
    else
        print_error "安装过程中出现错误，请检查上述信息"
        exit 1
    fi
}

# 运行主程序
main "$@"
