# Harness Hooks 自动集成层（治"靠提示才调 DAG"的根因）

每次子代理调用扫描/枚举 MCP 工具后，hook **自动**执行：
1. `dag_apply(add_node attack_action)` 建节点；
2. 有原始输出时 `extract_findings` 提炼证据（LLM 透明）；
3. 返回 `[AUTO-DAG] 已记录节点 <id>（findings=N）` 附加块，主 agent 可见但无需指示。

核心脚本：`../kali_auto_dag_hook.py`（stdin JSON，兼容 Claude Code PostToolUse 格式；
失败恒退出 0，不阻断 harness 主流程）。触发工具面 + 工具→agent 映射见脚本内
`AUTO_TRIGGER_TOOLS` / `TOOL_TO_AGENT`。

## Claude Code（已配好）

`.claude/settings.json` 的 `PostToolUse` hook 已指向本仓库
`scripts/kali_auto_dag_hook.py`。生效条件：Claude Code 工作目录 = 本仓库根
（`.claude/settings.json` 所在目录）。

## Codex

`~/.codex/config.toml` 或项目 `codex.md` 配 tool-use 后 hook：

```toml
# ~/.codex/config.toml（示例）
[hooks]
# Codex 的 tool-use after hook 机制；命令收到 {tool_name}/{tool_input}/{tool_response}
# 后透传给 kali_auto_dag_hook.py
"tool.use.after" = "py -3 F:/springInFer-skill/Kali-Security-MCP-main/Kali-Security-MCP-main/scripts/kali_auto_dag_hook.py"
```

## OpenCode

`opencode.json` 的 `plugin`/hook 机制（`tool.execute.after`）：

```jsonc
{
  "plugin": [
    {
      "name": "kali-auto-dag",
      "hook": "tool.execute.after",
      "command": "py -3 F:/springInFer-skill/Kali-Security-MCP-main/Kali-Security-MCP-main/scripts/kali_auto_dag_hook.py"
    }
  ]
}
```

本仓库 `opencode.json` 已含 18 个 `"agent"` 定义（与 `mcp.kali` 并存）。

## Pi（oh-my-pi）

omp 的 hook 等价机制（或 wrapper）：子代理工具调用后，把
`{tool_name, tool_input, tool_response}` JSON 写到脚本 stdin：

```bash
echo '{"tool_name":"fastsec_scan","tool_input":{"url":"<target>"},"tool_response":"<output>"}' \
  | py -3 F:/springInFer-skill/Kali-Security-MCP-main/Kali-Security-MCP-main/scripts/kali_auto_dag_hook.py
```

## 兜底（hook 拿不到原始 output）

某些 harness 的 hook 机制只在服务端有原始输出 → 回退：hook 只建节点
（`output_preview` 为空），证据提炼交给子代理正文"自动集成约束"节
（extract_findings 由子代理自己调）。脚本对空 output 已按此路径工作
（`findings_count: 0`，仍建节点）。
