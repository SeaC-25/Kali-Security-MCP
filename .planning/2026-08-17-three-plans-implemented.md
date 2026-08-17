在 Kali-Security-MCP-main 仓库中，从第一个会话到第三个会话的三个计划已全部实现并验证：

**会话1（native-agents）**：新增 `kali_mcp/mcp_tools/kg_dag_tools.py`（dag_apply/dag_recommend/dag_status/kb_search 四能力工具，独立构造 DAGService/ACO/KnowledgeRetriever，不依赖 coordinator）；`extract_findings_tools.py`（复用 17 agent 确定性解析器）；移除 mcp_server.py 的 agent_run/agent_status 编排面与 17-agent 集群初始化（MULTI_AGENT_STATE 删除）；生成 18 个原生子代理（Claude Code `.claude/agents/*.md`、Codex `AGENTS.md`、OpenCode `opencode.json`、Pi `skills/kali-*.md`）；hooks 自动集成层（`.claude/settings.json` PostToolUse → `scripts/kali_auto_dag_hook.py`，工具调用后自动 dag_apply 建节点 + extract_findings 提炼）。

**会话2（stealth）**：fastsec Go 引擎 XSS 无害 marker 单请求验证（`-xss-benign` 默认 on，证据存 marker 非 alert(1)，转义检查防误报）；`-danger-level` 分级（0 只读探测默认 / 1 时间盲注 SLEEP≤1s / 2 完整 payload）；wafProbes 无害化；品牌 UA 全清（KaliMCP-POCScanner/kali-mcp-probe/fastsec-ai/__fastsec_baseline_probe__/__dir_probe_404__）；RATE_DISCIPLINE 常量注入 web_vuln_agent/vuln_verifier；verifier VERIFY_STRATEGIES 改只读探针（marker/echo/URL 编码遍历）；`-c 50` → 8；fastsec 重编译（fastsec.exe + fastsec_windows.exe）。

**会话3（trace-wipe）**：`kali_mcp/core/trace_wipe.py`（task/session/global 三粒度；normalize_task_id 白名单防路径穿越；保留白名单 kb_vectors.db/models/wordlists；目标侧只出命令模板）；DAGService.wipe_session 新方法；`wipe_tools.py` MCP 注册；chain.py REPORT 终态自动 wipe（KALI_MCP_AUTO_WIPE=0 关 / KALI_MCP_KEEP_REPORT=1 保留 report）。

验证：pytest 474 passed / 1 个 pre-existing 失败（test_executor_result_cache_hit，httpx 工具解析环境问题，HEAD 上同样失败）；fastsec XSS marker E2E 通过（1 基线+1 marker 请求、0 alert）；level-0 inject 无 SLEEP/写操作；harness 档位服务器 5 新工具全部注册、agent_run/agent_status 不在 surface。测试迁移：test_observability_tools.py 改 kg_dag_tools + patch 注入；3 个 chain 测试加 KALI_MCP_AUTO_WIPE=0（新契约：终态后 workspace 被清）。REAL_SOURCES 17→18（KB 源实际 18 个，pre-existing 过期常量）。go.mod 被 go1.26 build tidy（移除未用 x/sys）。
