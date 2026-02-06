# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## ⚠️ 当前部署配置 - 必读！

**当前系统运行在：本地执行模式（LOCAL EXECUTION MODE）**

```
┌─────────────────────────────────────────────────────────────┐
│  🟢 本地执行模式 (ACTIVE)                                      │
│  ✅ MCP服务器直接通过subprocess调用本地安全工具                │
│  ✅ 无需启动kali_server.py后端                               │
│  ✅ 无需配置KALI_API_URL环境变量                              │
│  ✅ 所有193个工具直接在本地Kali Linux系统执行                  │
└─────────────────────────────────────────────────────────────┘
```

### 快速验证系统状态

运行以下命令立即了解当前配置：

```bash
# 方法1: 使用诊断脚本（推荐）
python status_check.py

# 方法2: 检查mcp_server.py配置
grep "OPTIMIZATION_ENABLED\|本地执行模式" mcp_server.py

# 方法3: 通过MCP工具检查
# 在Claude Code中运行: server_health()
```

### 配置对比表

| 特性 | 本地执行模式 (当前) | 分离式部署模式 |
|------|-------------------|---------------|
| 需要启动kali_server.py | ❌ 不需要 | ✅ 需要 |
| KALI_API_URL环境变量 | ❌ 不需要 | ✅ 必需 |
| 工具执行方式 | subprocess直接调用 | HTTP API远程调用 |
| 连接池优化 | ❌ 禁用 | ✅ 启用 |
| 适用场景 | Kali本机部署 | 远程Kali服务器 |
| 当前状态 | 🟢 活跃使用 | ⚪ 可选配置 |

### 如何切换到分离式部署模式

如果未来需要使用远程Kali服务器，需要：

1. 修改 `mcp_server.py` 第36行：
   ```python
   OPTIMIZATION_ENABLED = True  # 改为True
   ```

2. 设置环境变量：
   ```bash
   export KALI_API_URL="http://<kali-server-ip>:5000"
   ```

3. 启动后端服务器：
   ```bash
   python kali_server.py --port 5000
   ```

---

## Project Overview

**MCP-Kali-Server** is an intelligent MCP (Model Context Protocol) server that bridges AI agents with Kali Linux security tools. It provides an adaptive attack framework for penetration testing, CTF competitions, and security assessments through 193 integrated security tools.

**Key Purpose**: Enable AI-driven, autonomous security testing through intelligent tool orchestration and adaptive attack strategies.

## Core Architecture

This project uses a **client-server split architecture**:

### Architecture Overview
```
┌─────────────────────┐         HTTP/WebSocket        ┌──────────────────────┐
│   mcp_server.py     │ ◄─────────────────────────► │   kali_server.py     │
│  (MCP Client/AI)    │                              │  (Backend Executor)  │
│  - 193 MCP tools    │                              │  - Command execution │
│  - AI orchestration │                              │  - Task management   │
│  - Strategy engine  │                              │  - Parallel worker   │
└─────────────────────┘                              └──────────────────────┘
         ▲                                                     ▲
         │                                                     │
         │ Communicates via                                   │ Runs security tools
         │ optimized_request()                                │ on Kali Linux OS
         │                                                     │
    Claude AI Agent                                      Kali Linux Server
```

### 1. MCP Server (`mcp_server.py` - 12,271 lines)

The MCP client that exposes tools to AI agents. Contains the entire MCP tool implementation layer.

#### Intelligent Management Layer
- **IntelligentInteractionManager** (line 367): Manages AI-driven tool orchestration
  - Intent recognition from natural language
  - Automatic tool sequencing based on objectives
  - Predictive next-action recommendations

- **StrategyEngine** (line 97): Selects optimal attack strategies based on context
  - Maintains strategy effectiveness metrics
  - Adapts strategies based on historical success rates

- **AIContextManager** (line 207): Maintains conversation state across attack sessions
  - Tracks discovered assets, completed tasks
  - Provides context-aware tool suggestions

- **MLStrategyOptimizer** (line 653): Machine learning-based strategy optimization
  - Real-time feedback learning
  - Attack success rate prediction

- **AdaptiveExecutionEngine** (line 12016): Executes multi-stage adaptive attacks
  - MITRE ATT&CK framework alignment
  - 11-phase attack lifecycle management

#### Session Management
- **SessionContext** (line 51): Dataclass for managing attack session state
  - Tracks target info, attack mode, discovered assets
  - Maintains conversation history for context continuity

### 2. Kali Server (`kali_server.py` - 328KB)

The backend Flask server that actually executes security tools on Kali Linux:
- **TaskManager**: Manages concurrent tool execution with priority queues
- **WebSocket support**: Real-time progress updates via SocketIO
- **Parallel execution**: ThreadPoolExecutor for running multiple tools simultaneously
- **Command isolation**: Subprocess management with timeout controls

### 3. Performance Optimization Modules

#### Connection Pool (`connection_pool.py`)
- **OptimizedHTTPSession**: Reuses HTTP connections to reduce overhead
- **ConnectionPoolManager**: Manages per-host connection pools
- Thread-safe connection reuse with retry strategies
- Typical connection reuse rate: 30-50%

#### Fast Mode Configuration (`fast_config.py`)
- Aggressive timing profiles for time-constrained scenarios (CTF competitions)
- Quick scan configurations:
  - Nmap: `-T5` timing, common ports only (not full 1-65535 range)
  - Gobuster: 50 threads, small wordlists
  - Masscan: 10,000 packets/sec rate
- Default timeout: 30 seconds (down from 300 seconds)

### 4. PWN Automation Module (`pwnpasi/`)

Specialized PWN challenge automation:
- Binary exploitation automation
- ROP chain generation
- Stack overflow exploitation
- Integrated with main MCP server for CTF challenges

### 5. Attack Modes

The system supports two primary modes defined in `1.md`:

#### Enterprise Penetration Testing Mode
- Full-lifecycle APT simulation
- 11-stage MITRE ATT&CK framework execution
- Comprehensive reporting with CVSS scoring
- Compliance-focused with authorization verification
- Output organized by attack phase in timestamped directories

#### AWD Competition Speed Mode
- 10-20 minute time limit
- Parallel execution of 8+ attack vectors
- Real-time strategy adjustment every 30 seconds
- Prioritized vulnerability discovery (High → Medium → Low)
- Instant flag extraction and reporting

## Key MCP Tools

The server exposes **193 tools** via FastMCP (registered at line 3133). Critical tools include:

### Intelligent Automation
- `intelligent_apt_campaign`: Full autonomous APT attack campaign
- `start_adaptive_apt_attack`: Customizable adaptive attack chain
- `intelligent_ctf_solve`: Automated CTF challenge solving
- `ai_intelligent_target_analysis`: AI-powered target reconnaissance
- `intelligent_vulnerability_assessment`: Comprehensive vulnerability analysis

### Network Reconnaissance
- `nmap_scan`: Flexible nmap wrapper with multiple scan types
- `masscan_fast_scan`: Ultra-fast port scanning
- `comprehensive_network_scan`: Multi-tool network analysis
- `arp_scan`: Local network device discovery
- `fping_scan`: Fast ICMP-based host discovery

### Web Application Testing
- `nuclei_scan`: Template-based vulnerability scanning
- `gobuster_scan`: Directory/DNS/vhost enumeration
- `sqlmap_scan`: Automated SQL injection testing
- `adaptive_web_penetration`: Intelligent web attack orchestration
- `nikto_scan`: Web server vulnerability scanning

### Attack Strategy Management
- `get_adaptive_attack_status`: Real-time attack progress monitoring
- `trigger_next_attack_phase`: Manual phase progression
- `adjust_attack_strategy`: Dynamic strategy modification

## Environment Variables

Key environment variables for configuration:

```bash
# Backend server endpoint (REQUIRED for client-server communication)
export KALI_API_URL="http://192.168.1.100:5000"

# CTF competition settings
export CTF_PARALLEL_ATTACKS=8          # Number of parallel attack vectors
export CTF_LEARNING_MODE=true          # Enable ML-based strategy learning

# Backend server configuration (when running kali_server.py)
export API_PORT=5000                   # Backend API server port
export DEBUG_MODE=1                    # Enable debug logging
```

## Development Workflows

### Running the System

**Option 1: Both components on same machine**
```bash
# Terminal 1: Start Kali backend server
python kali_server.py --port 5000

# Terminal 2: Start MCP server (in another terminal)
export KALI_API_URL="http://localhost:5000"
python mcp_server.py
```

**Option 2: Separate machines (typical setup)**
```bash
# On Kali Linux machine: Start backend
python kali_server.py --port 5000

# On client machine: Start MCP server
export KALI_API_URL="http://192.168.1.100:5000"
python mcp_server.py
```

**Option 3: Fast CTF mode**
```bash
export KALI_API_URL="http://192.168.1.100:5000"
export CTF_PARALLEL_ATTACKS=8
export CTF_LEARNING_MODE=true
python mcp_server.py --mode=intelligent_ctf
```

### Configuration Management

The system uses `fast_config.py` for speed optimization settings. To adjust timeouts or scan aggressiveness:

```python
# Edit FAST_MODE_CONFIG in fast_config.py
FAST_MODE_CONFIG = {
    "global_timeout": 30,  # seconds
    "nmap_fast": {
        "common_ports": "21,22,80,443,8080",
        "timing": "-T5"
    }
}
```

### Working with Attack Sessions

Attack operations maintain state through SessionContext. When adding new tools:

1. Register tool with `@mcp.tool()` decorator after line 3133
2. Use `_get_or_create_session()` to access session context
3. Update session metadata with `session.add_conversation()`
4. Store discovered assets in `session.discovered_assets`

### API Communication Pattern

All tools communicate with the backend Kali server via HTTP:

```python
# Use optimized connection pool
from connection_pool import optimized_request

response = optimized_request(
    method="POST",
    url=f"{KALI_API_URL}/api/execute",
    json={"command": "nmap -sV target.com"},
    timeout=30
)
```

The backend server exposes several key endpoints:
- `/api/execute` - Execute single command
- `/api/parallel_execute` - Execute multiple commands in parallel
- `/api/task/status/<task_id>` - Check task status
- `/health` - Health check endpoint

### Testing and Debugging

Check system health and performance:

```python
# Via MCP tools:
await optimization_stats()  # Get connection pool and cache statistics
await server_health()       # Check backend server status

# Via backend directly:
curl http://<kali-server>:5000/health
```

## Output Directory Structure

Attack results are saved in timestamped directories following MITRE ATT&CK phases:

```
<target>_<YYYY-MM-DD_HHMM>/
├── 01_reconnaissance/
├── 02_initial_access/
├── 03_execution/
├── 04_privilege_escalation/
├── 05_lateral_movement/
├── 06_persistence/
├── 07_data_collection/
├── 08_exfiltration_simulation/
├── logs/
├── screenshots/
├── evidence/
└── final_report/
```

## Critical Design Patterns

### 1. Client-Server Separation
The MCP server (client) handles AI orchestration and strategy, while the Kali server (backend) executes actual security tools. This separation allows:
- Running MCP server on any machine with Claude access
- Security tool isolation on dedicated Kali Linux systems
- Horizontal scaling by adding more Kali backend workers

### 2. Intent-Based Execution
The system interprets natural language intents rather than requiring explicit tool names:
- "solve this CTF challenge" → `intelligent_ctf_solve`
- "scan for SQL injection" → `sqlmap_scan` + context analysis
- "comprehensive security assessment" → multi-tool orchestration

### 3. Adaptive Strategy Selection
StrategyEngine maintains effectiveness scores for each strategy and automatically selects the highest-performing approach based on target characteristics and historical success rates.

### 4. Parallel Attack Execution
For time-critical operations (CTF mode), the system launches multiple attack vectors concurrently rather than sequentially, controlled by `CTF_PARALLEL_ATTACKS` environment variable.

### 5. Real-time Feedback Loop
Attack status is monitored continuously (every 30 seconds in AWD mode, every 5 minutes in enterprise mode) with automatic strategy adjustment based on success/failure patterns.

### 6. Connection Pooling and Caching
- HTTP connections are pooled and reused across tool invocations
- Results for idempotent operations are cached (15-minute TTL)
- Connection reuse typically achieves 30-50% performance boost

## Important Constraints

### Security and Legal Compliance
- **DEFENSIVE ONLY**: This codebase is for authorized security testing, CTF competitions, and educational purposes
- All attack operations should verify authorization before execution
- Never execute attacks against unauthorized targets
- Report discovery of active vulnerabilities responsibly

### Performance Considerations
- Default timeout: 30 seconds (aggressive for responsiveness)
- Nmap scans use common ports by default, not full range
- Connection pooling is critical for multi-tool workflows
- Consider using fast mode configurations for CTF scenarios
- Backend server can handle parallel requests via ThreadPoolExecutor

### File Size Warning
`mcp_server.py` is 12,271 lines. When making edits:
- Use `offset` and `limit` parameters for Read operations
- Use Grep for locating specific functions
- Consider refactoring if adding substantial new functionality

## Common Troubleshooting

### MCP Tool Not Found
Ensure the tool is registered with `@mcp.tool()` decorator near line 3133 where `mcp = FastMCP("kali-mcp")` is initialized.

### Timeout Issues
Adjust timeout values in `fast_config.py` or per-tool in individual function definitions. Default is 30 seconds.

### Connection Pool Exhaustion
Check `OptimizedHTTPSession` pool size settings in `connection_pool.py` (default: 10 connections, 20 max per host).

### Kali Server Communication Failure
1. Verify `KALI_API_URL` environment variable is set correctly
2. Check that kali_server.py is running: `curl http://<server>:5000/health`
3. Ensure firewall allows traffic on the API port (default: 5000)
4. Check backend server logs for errors

### Backend Server Not Responding
If the backend server becomes unresponsive:
1. Check if Kali server process is still running
2. Review logs for task queue overflow or deadlocks
3. Restart backend server: `python kali_server.py --port 5000`
4. Verify system resources (CPU, memory) on Kali machine

### Performance Degradation
If response times increase significantly:
1. Check optimization stats: `await optimization_stats()`
2. Verify connection pool reuse rate (should be >30%)
3. Consider adjusting `FAST_MODE_CONFIG` timeouts
4. Review backend server task queue depth

---

## 🔗 Claude Skill 深度绑定

本项目已与 Claude Code Skill 系统深度集成，实现智能化安全测试。

### 绑定架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        深度绑定架构                                      │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 4: 反馈学习层    ~/.claude/skills/attack-history.json            │
│  Layer 3: 命令编排层    ~/.claude/commands/*.md (6个快捷命令)           │
│  Layer 2: 知识索引层    ~/.claude/skills/kali-index.json                │
│  Layer 1: 指令绑定层    ~/.claude/CLAUDE.md (全局行为规则)              │
│  Base:    知识库        ~/.claude/skills/kali-security.md (58K行)       │
└─────────────────────────────────────────────────────────────────────────┘
```

### 绑定文件清单

| 文件 | 用途 | 大小 |
|------|------|------|
| `~/.claude/CLAUDE.md` | 全局指令系统，定义MCP-Skill交互规则 | 176行 |
| `~/.claude/skills/kali-security.md` | 完整知识库，193个工具详解 | 58,543行 |
| `~/.claude/skills/kali-index.json` | 机器可解析的工具映射和决策树 | 结构化JSON |
| `~/.claude/skills/attack-history.json` | 动态学习数据，攻击历史记录 | 动态更新 |
| `~/.claude/commands/*.md` | 6个快捷命令 | 每个约100行 |

### 快捷命令

| 命令 | 用途 |
|------|------|
| `/ctf TARGET [CATEGORY]` | CTF快速解题 |
| `/pentest TARGET [MODE]` | 渗透测试 |
| `/apt TARGET` | APT攻击模拟 |
| `/vuln TARGET [TYPE]` | 漏洞评估 |
| `/recon TARGET [DEPTH]` | 信息收集 |
| `/pwn BINARY [REMOTE]` | PWN攻击 |

### 自动行为

深度绑定后，Claude Code 会自动：

1. **识别攻击场景** - 根据目标自动选择CTF/渗透测试/漏洞研究模式
2. **智能工具选择** - 参考skill知识库选择最佳工具组合
3. **决策树导航** - 根据工具输出自动决定下一步
4. **经验学习** - 记录成功/失败模式，优化后续策略
5. **Flag自动提取** - CTF模式下自动检测和提取Flag

### 知识库层次

skill知识库采用五层架构：
- **L1**: 快速参考 - CTF速查表、渗透测试速查表
- **L2**: 工具详解 - 193个工具的三段式解析
- **L3**: 场景剧本 - 50+实战场景
- **L4**: 方法论 - MITRE/OWASP/PTES/CTF框架
- **L5**: 高级技巧 - 绕过技术、AI辅助策略
