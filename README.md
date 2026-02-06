# Kali MCP Server

<div align="center">

![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Protocol-00D4AA?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Tools](https://img.shields.io/badge/Tools-193-orange?style=for-the-badge)

**🤖 AI 驱动的智能渗透测试框架**

*通过 MCP 协议将 193 个 Kali Linux 安全工具与 AI 无缝集成*

[English](#english) | [中文](#中文)

</div>

---

## 中文

### 🎯 简介

Kali MCP Server 是一个基于 Model Context Protocol (MCP) 的智能安全测试框架，将 Kali Linux 的 **193 个**专业安全工具与 AI 助手（如 Claude）深度集成。支持自动化渗透测试、CTF 竞赛解题、漏洞评估等场景。

### ✨ 核心特性

| 特性 | 说明 |
|------|------|
| **193 个安全工具** | 涵盖信息收集、漏洞扫描、密码攻击、Web 测试、PWN 等 |
| **AI 智能编排** | 自动分析目标，智能选择工具链 |
| **CTF 竞赛模式** | 自动 Flag 检测，一键解题 |
| **APT 攻击模拟** | 完整的 MITRE ATT&CK 框架支持 |
| **模块化架构** | 清晰的代码组织，易于扩展 |
| **本地执行模式** | 无需额外后端服务器，直接调用系统工具 |

---

### 📁 项目结构

```
MCP-Kali-Server/
├── mcp_server.py              # 主 MCP 服务器 (193 个工具)
├── kali_mcp/                  # 模块化核心库
│   ├── core/                  # 核心模块
│   │   ├── executor.py        # 异步命令执行器
│   │   ├── session.py         # 会话管理
│   │   ├── strategy.py        # 策略引擎
│   │   └── cache.py           # 结果缓存
│   ├── tools/                 # 工具封装
│   │   ├── base.py            # 工具基类
│   │   ├── network.py         # 网络工具 (nmap, masscan)
│   │   ├── web.py             # Web 工具 (sqlmap, nuclei)
│   │   ├── password.py        # 密码工具 (hydra, john)
│   │   ├── exploit.py         # 漏洞利用
│   │   └── pwn.py             # PWN 工具
│   ├── ai/                    # AI 模块
│   │   ├── intent.py          # 意图识别
│   │   ├── recommend.py       # 工具推荐
│   │   └── learning.py        # 学习引擎
│   ├── output/                # 输出模块
│   │   ├── formatter.py       # 格式化
│   │   ├── reporter.py        # 报告生成
│   │   └── progress.py        # 进度追踪
│   └── monitor/               # 监控模块
│       ├── health.py          # 健康检查
│       └── metrics.py         # 性能指标
├── pwnpasi/                   # PWN 自动化模块
├── tests/                     # 测试用例 (63 个测试)
├── deploy/                    # 部署配置
├── status_check.py            # 系统状态检查
├── fast_config.py             # CTF 快速模式配置
└── connection_pool.py         # 连接池优化
```

---

### 🚀 快速开始

#### 环境要求

- Kali Linux 2023.1+ (推荐 2024.1+)
- Python 3.10+
- Kali 系统安全工具 (nmap, sqlmap, nuclei 等)

#### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/yourusername/MCP-Kali-Server.git
cd MCP-Kali-Server

# 2. 安装 Python 依赖
pip install -r requirements.txt --break-system-packages

# 3. 验证系统状态
python status_check.py

# 4. 运行测试 (可选)
pytest
```

---

### 💻 使用方法

#### 方式一：本地使用（Claude Code CLI）

在项目目录创建 `.mcp.json`：

```json
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "python",
      "args": ["mcp_server.py"]
    }
  }
}
```

然后直接使用 Claude Code：

```bash
claude
```

#### 方式二：Claude Desktop 集成

编辑 Claude Desktop 配置文件：

| 系统 | 配置文件路径 |
|------|-------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

配置内容：

```json
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "python",
      "args": ["/path/to/MCP-Kali-Server/mcp_server.py"]
    }
  }
}
```

#### 方式三：远程 Kali 服务器（SSH 隧道）

如果 Kali 在虚拟机或远程服务器上：

**1. 确保 Kali SSH 服务运行：**

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

**2. 配置 Claude Desktop：**

```json
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "ssh",
      "args": [
        "-o", "StrictHostKeyChecking=no",
        "user@kali-server-ip",
        "python /path/to/MCP-Kali-Server/mcp_server.py"
      ]
    }
  }
}
```

**3. VMware NAT 端口转发（如适用）：**

| 主机端口 | 虚拟机端口 | 说明 |
|---------|-----------|------|
| 2222 | 22 | SSH |

配置后使用：
```json
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "ssh",
      "args": ["-p", "2222", "user@localhost",
               "python /path/to/MCP-Kali-Server/mcp_server.py"]
    }
  }
}
```

---

### 🔧 工具分类

#### 信息收集 (25 个工具)

| 工具 | 说明 |
|------|------|
| `nmap_scan` | 端口扫描和服务识别 |
| `masscan_fast_scan` | 高速端口扫描 |
| `subfinder_scan` | 子域名枚举 |
| `amass_enum` | 全面子域名收集 |
| `whatweb_scan` | Web 技术识别 |
| `theharvester_osint` | OSINT 情报收集 |
| `dnsrecon_scan` | DNS 侦察 |
| `sherlock_search` | 用户名社交媒体搜索 |

#### Web 应用测试 (35 个工具)

| 工具 | 说明 |
|------|------|
| `gobuster_scan` | 目录/文件爆破 |
| `ffuf_scan` | 快速模糊测试 |
| `sqlmap_scan` | SQL 注入测试 |
| `nuclei_scan` | 漏洞模板扫描 |
| `nikto_scan` | Web 服务器扫描 |
| `wpscan_scan` | WordPress 安全扫描 |
| `joomscan_scan` | Joomla 安全扫描 |

#### 密码攻击 (15 个工具)

| 工具 | 说明 |
|------|------|
| `hydra_attack` | 在线密码爆破 |
| `john_crack` | 离线密码破解 |
| `hashcat_crack` | GPU 加速破解 |
| `medusa_bruteforce` | 并行密码测试 |

#### 漏洞利用 (20 个工具)

| 工具 | 说明 |
|------|------|
| `metasploit_run` | Metasploit 模块执行 |
| `searchsploit_search` | Exploit-DB 搜索 |
| `enum4linux_scan` | Windows/Samba 枚举 |

#### PWN 与逆向 (20 个工具)

| 工具 | 说明 |
|------|------|
| `quick_pwn_check` | PWN 漏洞快速检查 |
| `pwnpasi_auto_pwn` | 自动化 PWN 利用 |
| `auto_reverse_analyze` | 自动逆向分析 |
| `radare2_analyze_binary` | Radare2 分析 |
| `ghidra_analyze_binary` | Ghidra 分析 |

#### 智能化工具 (58 个工具)

| 工具 | 说明 |
|------|------|
| `intelligent_ctf_solve` | 智能 CTF 解题 |
| `ai_create_session` | 创建 AI 攻击会话 |
| `ai_analyze_intent` | 意图分析 |
| `comprehensive_recon` | 全面侦察 |
| `intelligent_vulnerability_assessment` | 智能漏洞评估 |
| `intelligent_penetration_testing` | 智能渗透测试 |
| `apt_comprehensive_attack` | APT 综合攻击 |
| `adaptive_web_penetration` | 自适应 Web 渗透 |

---

### 📖 使用示例

#### CTF 竞赛模式

```
你: 帮我解决这个 CTF Web 题目 http://ctf.example.com

Claude: 我来启用 CTF 模式并分析这个目标...
[执行 enable_ctf_mode]
[执行 intelligent_ctf_solve]
[自动检测 Flag: flag{xxx}]
```

#### 渗透测试模式

```
你: 对 192.168.1.100 进行全面的渗透测试

Claude: 我来创建一个渗透测试会话...
[执行 ai_create_session]
[执行 nmap_scan - 发现端口 22, 80, 443]
[执行 nuclei_scan - 发现漏洞]
[生成渗透测试报告]
```

#### 单工具使用

```
你: 用 nmap 扫描 scanme.nmap.org

Claude: [执行 nmap_scan]
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
...
```

---

### 🎮 攻击模式

#### Enterprise 渗透测试模式
- 11 阶段 MITRE ATT&CK 框架
- 完整报告生成
- CVSS 评分
- 合规性验证

#### AWD 竞赛速度模式
- 10-20 分钟时限
- 8+ 并发攻击向量
- 每 30 秒策略调整
- 实时 Flag 提取

---

### 🧪 运行测试

```bash
# 运行所有测试 (63 个)
pytest

# 运行特定测试
pytest tests/test_executor.py

# 详细输出
pytest -v

# 跳过慢速测试
pytest -m "not slow"
```

---

### ⚠️ 安全声明

**本项目仅用于：**
- ✅ 授权的渗透测试
- ✅ CTF 竞赛和安全培训
- ✅ 安全研究和漏洞分析
- ✅ 防御性安全评估

**严禁用于：**
- ❌ 未经授权的攻击
- ❌ 恶意目的
- ❌ 任何违法活动

---

## English

### 🎯 Introduction

Kali MCP Server is an intelligent security testing framework based on Model Context Protocol (MCP), deeply integrating **193** professional security tools from Kali Linux with AI assistants like Claude. It supports automated penetration testing, CTF challenge solving, vulnerability assessment, and more.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| **193 Security Tools** | Covering reconnaissance, vulnerability scanning, password attacks, web testing, PWN, etc. |
| **AI-Powered Orchestration** | Automatic target analysis and intelligent tool chain selection |
| **CTF Competition Mode** | Automatic flag detection, one-click solving |
| **APT Attack Simulation** | Full MITRE ATT&CK framework support |
| **Modular Architecture** | Clean code organization, easy to extend |
| **Local Execution Mode** | No additional backend server required |

### 🚀 Quick Start

```bash
# Clone the project
git clone https://github.com/yourusername/MCP-Kali-Server.git
cd MCP-Kali-Server

# Install dependencies
pip install -r requirements.txt --break-system-packages

# Verify system status
python status_check.py
```

### 💻 Usage

#### Local Usage (Claude Code CLI)

Create `.mcp.json` in project directory:

```json
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "python",
      "args": ["mcp_server.py"]
    }
  }
}
```

#### Claude Desktop Integration

Edit configuration file:

```json
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "python",
      "args": ["/path/to/MCP-Kali-Server/mcp_server.py"]
    }
  }
}
```

#### Remote Kali Server (SSH Tunnel)

```json
{
  "mcpServers": {
    "kali-intelligent-ctf": {
      "command": "ssh",
      "args": [
        "user@kali-server-ip",
        "python /path/to/MCP-Kali-Server/mcp_server.py"
      ]
    }
  }
}
```

### 🔧 Tool Categories

| Category | Count | Examples |
|----------|-------|----------|
| Reconnaissance | 25 | nmap, masscan, subfinder |
| Web Testing | 35 | sqlmap, nuclei, gobuster |
| Password Attacks | 15 | hydra, john, hashcat |
| Exploitation | 20 | metasploit, searchsploit |
| PWN & Reverse | 20 | pwntools, radare2, ghidra |
| Intelligent Tools | 58 | AI-powered automation |

### 📄 License

MIT License - See [LICENSE](LICENSE) for details.

### 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ❤️ for the security community

</div>
