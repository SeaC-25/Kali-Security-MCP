# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this repository.

---

## Project Overview

**Kali MCP** is an MCP (Model Context Protocol) server that bridges AI agents with Kali Linux security tools. Current architecture = **能力层 MCP + 18 原生 markdown 子代理 + hooks 自动集成**：

- **能力层 MCP**（服务端单点）：`mcp_server.py --tool-profile harness` 暴露纯能力工具——扫描/枚举（fastsec 全能力 23 个独立工具 + nmap_scan/kali_run 等）+ **DAG/ACO 读写与观测**（`dag_apply`/`dag_recommend`/`dag_status`）+ **知识库检索**（`kb_search`）+ **证据提炼**（`extract_findings`，复用 17 个 Python agent 的确定性解析器）+ 任务板 + **痕迹清理**（`wipe_traces`）。
- **18 个原生子代理**：`coordinator`（派发/评审/done，自动读 DAG/ACO 推荐）+ 17 个专业子代理。定义在 `.claude/agents/*.md`（Claude Code）、`AGENTS.md`（Codex）、`opencode.json`（OpenCode）、`skills/kali-*.md`（Pi）。正文 5 节：角色/工具面/决策协议/**自动集成约束**（扫描后必调 extract_findings+dag_apply）/协作协议（dag_recommend 仅参考）。
- **hooks 自动触发**：`.claude/settings.json` PostToolUse → `scripts/kali_auto_dag_hook.py`，工具调用后自动建 DAG 节点 + 提炼证据（LLM 透明）。其余 harness 见 `scripts/hooks/README.md`。

**已移除**：MCP 编排面（两个 pure-orchestration 工具）与 17-agent 集群初始化（`MULTI_AGENT_STATE`/`K4_LEGACY_CLUSTER` 相关代码已删）——编排移入 harness 侧 coordinator 子代理。17 个 Python agent 类保留为解析器来源（extract_findings 复用 `_parse_*_output`），不再由 MCP 构造/调度。

## Running the System

```bash
# Start MCP server (capability layer, harness profile)
python mcp_server.py --tool-profile harness

# Other profiles
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

MCP 配置在 `.mcp.json`（Claude Code / Pi）与 `.omp/mcp.json`（Pi 实际运行实例）。

## Installing Dependencies

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# fastsec Go 引擎（可选，改动后重编译）
cd tools/fastsec && go build -o fastsec ./cmd/fastsec
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
mcp_server.py (entry point)
│   FastMCP instance; registers tools via register_xxx_tools() pattern
│
├── kali_mcp/core/              Core logic
│   ├── local_executor.py       LocalCommandExecutor — subprocess tool execution
│   ├── trace_wipe.py           痕迹清理（三粒度 task/session/global，白名单防路径穿越）
│   ├── playbooks/stealth.py    UA_POOL / RATE_DISCIPLINE / build_stealth_command / check_brand_ua_clean
│   ├── playbooks/chain.py      run_surface_chain（REPORT 终态自动 wipe，KALI_MCP_AUTO_WIPE）
│   └── ...                     task_workspace / target_graph / findings_store 等
│
├── kali_mcp/mcp_tools/         MCP tool registration
│   ├── kg_dag_tools.py         dag_apply / dag_recommend / dag_status / kb_search（独立构造服务）
│   ├── fastsec_tools.py        fastsec 全能力 23 个独立 MCP 工具（薄包装 execute_tool_with_data("fastsec")）
│   ├── extract_findings_tools.py  extract_findings（复用 17 agent 解析器）
│   ├── wipe_tools.py           wipe_traces
│   └── ...                     harness_tools / meta_tools / board_tools ...
│
├── kali_mcp/agents/            17 specialized agents（解析器来源，不再由 MCP 调度）
├── kali_mcp/reasoning/         attack_dag / aco / knowledge_retriever（服务端单点，不重写）
├── kali_mcp/security/          engagement / tool_profile
│
├── .claude/agents/*.md         18 原生子代理（Claude Code）
├── AGENTS.md                   Codex 子代理定义
├── opencode.json               OpenCode 子代理定义 + mcp.kali
├── skills/kali-*.md            Pi 子代理定义
├── scripts/
│   ├── kali_auto_dag_hook.py   自动集成 hook（PostToolUse）
│   ├── gen_native_subagents.py 子代理定义生成器
│   └── hooks/README.md         四 harness hook 接线指南
└── tools/fastsec/              自研 Go 扫描引擎
```

### Request Flow

```
Claude Code 主 agent
  → coordinator 子代理（派发 mission）
    → 专业子代理（如 recon_agent）调 MCP 能力工具（fastsec_dir_scan/fastsec_port_scan/nmap_scan）
      → PostToolUse hook 自动 dag_apply 建节点 + extract_findings 提炼（LLM 透明）
      → coordinator 读 dag_recommend 决定下一步（ACO 只推荐不决策）
      → LocalCommandExecutor.execute_tool_with_data()
        → Compliance check (EngagementManager + PentestPolicy)
          → Parameter sanitization (shlex.quote)
            → subprocess.run() executes tool
```

## Tool Registration Pattern (how to add new tools)

1. **Create a module** in `kali_mcp/mcp_tools/`:

```python
# kali_mcp/mcp_tools/my_tools.py
def register_my_tools(mcp, executor):
    @mcp.tool()
    def my_new_tool(target: str, option: str = "default") -> Dict[str, Any]:
        """Tool description shown to the AI."""
        data = {"target": target, "option": option}
        return executor.execute_tool_with_data("toolname", data)
```

2. **Register in `mcp_server.py`**: `_safe_register("my_module", "My Tools", register_my_tools, mcp, executor)` in `setup_mcp_server()`.

3. **Add tool name to `K1_KEEP_TOOLS`** in `kali_mcp/mcp_tools/meta_tools.py`（否则注册后被 K1 裁剪）。

4. **Add module key** to `ALL_MODULE_KEYS` in `kali_mcp/security/tool_profile.py` and configure which profiles enable it.

5. **If using a new CLI tool**, add it to `ALLOWED_TOOLS` set in `kali_mcp/core/local_executor.py` (whitelist).

## Security Model

- **Tool whitelist**: `ALLOWED_TOOLS` in `local_executor.py` — only these binaries can be invoked
- **Parameter sanitization**: All arguments pass through `shlex.quote()` before subprocess execution
- **Tool profiles** (set via `--tool-profile` or `KALI_MCP_TOOL_PROFILE` env var): `strict` / `compliance`（默认）/ `full` / `harness`
- **Engagement context**: Optional authorization scope via `KALI_MCP_ENGAGEMENT_JSON` or `KALI_MCP_ENGAGEMENT_FILE`. Known gap: `ENFORCEMENT_ENABLED=False` 恒放行（已记录，未改）。
- **Stealth & Rate Discipline**（`kali_mcp/core/playbooks/stealth.py`）:
  - XSS 默认无害 marker 单请求（`-xss-benign`，无 alert(1)）；`-xss-benign=false` 才跑完整集
  - SQLi 默认 `-danger-level 0` 只读探测（无 SLEEP/写操作）；时间盲注需 `-danger-level 1`（SLEEP≤1s）；写操作需 `-danger-level 2` 显式授权
  - 品牌 UA 已移除（KaliMCP-POCScanner/kali-mcp-probe/fastsec-ai 全清）；回归钩子 `check_brand_ua_clean()`
  - 速率纪律 = 口头限定（RATE_DISCIPLINE 常量注入 agent 提示词/子代理定义）+ fastsec 内建节流兜底（-c 20 / delay 300-800ms）
- **痕迹清理**（`kali_mcp/core/trace_wipe.py`）:
  - `wipe_traces` 三粒度：task（删 workspace/tasks/<id>/ 整目录，chain REPORT 终态自动）/ session（DAG 会话 + d01_session.json）/ global（清运行时状态，永不自动）
  - 删除**不可恢复**；保留白名单硬编码：kb_vectors.db / models / wordlists / tools/fastsec/data / scripts / tests
  - 目标侧清除只输出命令模板（target_manual_cleanup），不自动执行
  - task_id 经 `normalize_task_id` 白名单校验（防路径穿越）；非法 id 拒绝不删

## Key Environment Variables

```bash
KALI_MCP_TOOL_PROFILE=harness            # Tool profile
KALI_MCP_AUTO_WIPE=0                     # 关闭 chain 终态自动清理（默认开）
KALI_MCP_KEEP_REPORT=1                   # task 级清理保留 report/ 子目录
KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT=1    # Require authorization context
KALI_MCP_ENGAGEMENT_JSON='{"target_scope":["10.0.0.0/8"]}'  # Inline auth context
KALI_MCP_ENGAGEMENT_FILE=/path/to/engagement.json           # Auth context file
LLM_PROVIDER=anthropic|openai            # LLM provider（原生子代理由 harness 自带 LLM）
```

## Important Notes

- **stdout is reserved for MCP JSON-RPC** in stdio transport mode. All logs/print must go to `sys.stderr`.
- Default command timeout is **300 seconds** in `LocalCommandExecutor`.
- `mcp_server.py` is a slim entry point. All logic lives in `kali_mcp/core/` and `kali_mcp/mcp_tools/`.
- **DAG/ACO 不重写**：1318 行图算法留在服务端（`kali_mcp/reasoning/`），只经 MCP `dag_apply`/`dag_recommend` 暴露；"ACO 只推荐不决策"是硬约束。
- **extract_findings 证据确定性**：evidence 只来自 `_parse_*_output` 正则解析器返回，禁止 LLM 自编。
- 17 个 Python agent 类 / coordinator / multi_agent_tools / agent_coordinator **保留不删**（extract_findings 解析器来源 + harness 参考）；multi_agent_tools 不再注册。

## Subagent Parallel Execution Pattern

复杂安全评估任务用 Task 派发并行子代理（多目标侦察/扫描/代码审计并行），主对话只做汇总决策。18 个原生子代理定义见 `.claude/agents/`（coordinator 负责派发与评审；专业子代理各自调能力工具，扫描后由 hook 自动建 DAG/提炼证据）。

- **自动压缩规则**: 当对话上下文剩余容量低于 5% 时，必须自动执行 `/compact` 进行上下文压缩，避免因上下文溢出导致会话中断。压缩前应确保关键发现和当前工作状态已记录在 memory 或 `.planning/` 中。
