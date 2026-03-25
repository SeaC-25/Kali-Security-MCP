# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Project Overview

**MCP-Kali-Server** is an MCP (Model Context Protocol) server that bridges AI agents with 200+ Kali Linux security tools. It supports penetration testing, CTF competitions, and security assessments through intelligent tool orchestration.

**Architecture**: v6.0 modular architecture. The system runs in **local execution mode** — `mcp_server.py` calls Kali tools directly via `subprocess`, no backend server needed. Core components: declarative `tool_registry`, structured `output_parsers`, `hybrid_decision_engine` for multi-agent routing, and session TTL auto-cleanup.

## Running the System

```bash
# Start MCP server (local execution mode, default)
python mcp_server.py

# Or use the startup script (creates venv if needed, checks tool availability)
bash start.sh

# With a specific tool profile
python mcp_server.py --tool-profile strict    # minimal tools
python mcp_server.py --tool-profile compliance # default, most tools
python mcp_server.py --tool-profile full       # all tools

# Force-enable/disable specific modules
python mcp_server.py --enable-module pwn --disable-module apt

# SSE mode for remote access
python mcp_server.py --transport sse --host 0.0.0.0 --port 8765

# Check system status
python status_check.py
```

The MCP configuration is in `.mcp.json`. Virtual environment is at `.venv/`.

## Installing Dependencies

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Optional: PWN tools
pip install pwntools
```

## Testing

```bash
pytest                         # run all tests
pytest -x                      # stop on first failure
pytest --cov=kali_mcp          # with coverage
pytest -k "test_name"          # run specific test
```

## Core Architecture

```
mcp_server.py (520 lines, entry point)
│   Creates FastMCP instance, initializes multi-agent system,
│   registers all tools via register_xxx_tools() pattern
│
├── kali_mcp/core/              Core logic (15+ modules)
│   ├── local_executor.py       LocalCommandExecutor — subprocess tool execution
│   ├── mcp_session.py          SessionContext + StrategyEngine
│   ├── agent_registry.py       Multi-agent registry (v4.0)
│   ├── agent_coordinator.py    Central coordinator agent
│   └── ...                     AI context, ML optimizer, knowledge graph, etc.
│
├── kali_mcp/mcp_tools/         MCP tool registration (28 modules, 200+ tools)
│   Each module exports register_xxx_tools(mcp, executor, ...) function
│
├── kali_mcp/agents/            17 specialized agents
│   ├── information_gathering/  ReconAgent, SubdomainAgent, WebReconAgent
│   ├── vulnerability_discovery/ VulnScanner, WebVuln, Auth, NetworkVuln, VulnVerifier
│   ├── exploitation/           ExploitAgent, PrivilegeAgent, LateralAgent
│   └── specialized/            PwnAgent, CryptoAgent, ForensicsAgent, CodeAudit, etc.
│
├── kali_mcp/security/          Authorization & compliance
│   ├── engagement.py           EngagementContext — scope/authorization management
│   └── tool_profile.py         Tool profiles: strict | compliance | full
│
├── kali_mcp/diggers/           Deep vulnerability diggers (v3.0)
├── deep_test_engine/           HTTP/WebSocket/gRPC interaction engine
└── pwnpasi/                    PWN automation (ROP, heap exploit, fuzzing)
```

### Request Flow

```
Claude AI → MCP protocol (stdio/SSE)
  → FastMCP instance (mcp_server.py)
    → Tool function (kali_mcp/mcp_tools/*.py)
      → LocalCommandExecutor.execute_tool_with_data()
        → Compliance check (EngagementManager + PentestPolicy)
          → Parameter sanitization (shlex.quote)
            → subprocess.run() executes Kali tool
              → Result returned to Claude
```

### Tool Registration Pattern (how to add new tools)

1. **Create or edit a module** in `kali_mcp/mcp_tools/`:

```python
# kali_mcp/mcp_tools/my_tools.py
def register_my_tools(mcp, executor):
    @mcp.tool()
    def my_new_tool(target: str, option: str = "default") -> Dict[str, Any]:
        """Tool description shown to the AI."""
        data = {"target": target, "option": option}
        return executor.execute_tool_with_data("toolname", data)
```

2. **Export from `__init__.py`**: Add `from .my_tools import register_my_tools` to `kali_mcp/mcp_tools/__init__.py`

3. **Register in `mcp_server.py`**: Add the import and call `_safe_register("my_module", "My Tools", register_my_tools, mcp, executor)` in `setup_mcp_server()`

4. **Add module key** to `ALL_MODULE_KEYS` in `kali_mcp/security/tool_profile.py` and configure which profiles enable it

5. **If using a new CLI tool**, add it to `ALLOWED_TOOLS` set in `kali_mcp/core/local_executor.py` (whitelist of 67 permitted binaries)

### Security Model

- **Tool whitelist**: `ALLOWED_TOOLS` in `local_executor.py` — only these binaries can be invoked
- **Parameter sanitization**: All arguments pass through `shlex.quote()` before subprocess execution
- **Tool profiles** (set via `--tool-profile` or `KALI_MCP_TOOL_PROFILE` env var):
  - `strict` — Only system, compliance, and assessment tools (for minimal model refusal)
  - `compliance` — Default. Most tools enabled, some high-risk modules disabled
  - `full` — Everything enabled including APT, PWN, deep test
- **Engagement context**: Optional authorization scope management via `KALI_MCP_ENGAGEMENT_JSON` or `KALI_MCP_ENGAGEMENT_FILE` env vars. When set, tools validate targets against authorized scope before execution.

### Multi-Agent System (v4.0)

Initialized in `setup_mcp_server()` when the `multi_agent` module is enabled. State stored in the global `MULTI_AGENT_STATE` dict:

```python
MULTI_AGENT_STATE = {
    "agent_registry": AgentRegistry,       # Registry of all 17 agents
    "multi_agent_coordinator": CoordinatorAgent, # Central coordinator
    "message_bus": MeshMessageBus,         # Inter-agent messaging
    "initialized": bool
}
```

Each agent in `kali_mcp/agents/` receives `message_bus`, `tool_registry`, and `executor` at init. Agents are domain-specialized and coordinated by `CoordinatorAgent`.

### Global State Variables (in mcp_server.py)

| Variable | Type | Purpose |
|----------|------|---------|
| `executor` | LocalCommandExecutor | Shared tool execution engine |
| `MULTI_AGENT_STATE` | dict | Multi-agent system references |
| `_ATTACK_SESSIONS` | dict | Active attack session storage |
| `_TASKS` / `_WORKFLOWS` | dict | Concurrent task and workflow storage |
| `_ADAPTIVE_ATTACKS` | dict | Adaptive attack state |
| `_CTF_MODE_ENABLED` | bool | CTF mode flag |
| `ai_context_manager` | AIContextManager | Persistent AI context |
| `ml_strategy_optimizer` | MLStrategyOptimizer | ML-based strategy selection |

## Key Environment Variables

```bash
KALI_MCP_TOOL_PROFILE=compliance          # Tool profile (strict/compliance/full)
KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT=1     # Require authorization context
KALI_MCP_ENGAGEMENT_JSON='{"target_scope":["10.0.0.0/8"]}'  # Inline auth context
KALI_MCP_ENGAGEMENT_FILE=/path/to/engagement.json           # Auth context file
```

## Important Notes

- **stdout is reserved for MCP JSON-RPC** in stdio transport mode. All logs/print must go to `sys.stderr`.
- Default command timeout is **300 seconds** in `LocalCommandExecutor`. Fast mode (CTF) uses 30 seconds.
- `mcp_server.py` is a slim entry point (~520 lines). All logic lives in `kali_mcp/core/` (core classes) and `kali_mcp/mcp_tools/` (tool registrations).
- Tool modules may have varying signatures for their `register_xxx_tools()` functions — some take only `(mcp, executor)`, others require additional state objects. Check existing patterns in `setup_mcp_server()`.
- The `kali_server.py` backend Flask server exists for remote/distributed deployment but is **not used** in the default local execution mode.
### Subagent Parallel Execution Pattern

When facing complex security assessment tasks, use Claude Code's `Task` tool to dispatch parallel subagents for independent workstreams. This significantly speeds up multi-target or multi-phase operations.

**When to use subagents:**
- Scanning multiple independent targets simultaneously
- Running information gathering while vulnerability scanning proceeds
- Parallel code audit + black-box testing
- Any 2+ independent tasks that don't share state

**Pattern for security assessment:**

```
# Dispatch parallel reconnaissance subagents
Task(subagent_type="Bash", prompt="Run nmap -sV -sC target1 and report results")
Task(subagent_type="Bash", prompt="Run gobuster on http://target2 and report results")

# Dispatch exploration subagent for codebase analysis
Task(subagent_type="Explore", prompt="Find all SQL query patterns in the source code")

# General-purpose research agent
Task(subagent_type="general-purpose", prompt="Research CVE-2024-XXXX and find exploit methods")
```

**Available subagent types for security work:**
| Type | Use Case | Tools Available |
|------|----------|----------------|
| `Bash` | Run Kali tools, execute commands | Shell commands |
| `Explore` | Search codebase, find patterns | Read, Grep, Glob |
| `general-purpose` | Research, multi-step analysis | All tools |
| `Plan` | Design attack strategies | Read-only tools |

**Best practices:**
- Launch independent agents in a single message for true parallelism
- Use `run_in_background=true` for long-running scans
- Each agent gets fresh context — include all necessary details in the prompt
- Collect results and synthesize findings in the main conversation

- **自动压缩规则**: 当对话上下文剩余容量低于 5% 时，必须自动执行 `/compact` 进行上下文压缩，避免因上下文溢出导致会话中断。压缩前应确保关键发现和当前工作状态已记录在 memory 或 `.planning/` 中。
