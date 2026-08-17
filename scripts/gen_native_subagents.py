#!/usr/bin/env python3
"""生成 18 个 harness 原生子代理定义（四 harness：Claude Code / Codex / OpenCode / Pi）。

数据来源：kali_mcp 17 个 Python agent 的 ROLE_PROMPT + AgentCapability
（get_supported_tools / specialties），外加 coordinator（ORCHESTRATOR_PROMPT 翻译）。

正文 5 节（4b 模板）：
  1. 角色/目标   —— ROLE_PROMPT 翻译（沿用中文）
  2. 工具面       —— supported_tools + 自动集成工具集
  3. 决策/输出协议 —— call_tool/run_tool/done JSON schema（llm_agent_base 输出协议）
  4. 自动集成约束 —— 扫描后自动 extract_findings + dag_apply（必须，非可考虑）
  5. 协作协议     —— dag_status/dag_recommend 参考（ACO 只推荐不决策）

输出：
  .claude/agents/{slug}.md ×18      Claude Code
  AGENTS.md                         Codex（## Role: 分节 ×18）
  opencode.json                     OpenCode（"agent" 节 ×18）
  skills/kali-{agent_id}.md ×18     Pi skills
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FACTS = json.loads(Path("/tmp/agent_facts.json").read_text(encoding="utf-8"))

# 自动集成工具集（hooks/子代理每次扫描后必调）
AUTO_TOOLS = ["dag_apply", "dag_recommend", "dag_status", "kb_search", "extract_findings"]

RATE_DISCIPLINE = """## 速率与痕迹纪律（每次工具调用前必读）
1. 任何扫描/爆破工具调用前，先评估目标业务影响：优先用低并发与默认节流（fastsec 默认 -c 20 / delay 300-800ms 已内建，不要用 -c 覆盖超过默认）。
2. 不需要 -c 50 类激进并发；多目标时用 -c/-delay 参数（fastsec -c 8 --delay-min 500）。
3. 不向生产目标发送对业务有影响的 payload：XSS 用无害 marker（-xss-benign 默认），不跑 alert(1) 集除非显式授权。
4. 验证用最小请求（基线+marker），不留扫描特征参数。
5. 所有请求 UA 用真实浏览器 UA，禁止任何 KaliMCP 品牌 UA（POCScanner/probe 旧标识）。
6. 验证即停，不自动推进：利用到 shell/PoC 存在即回传，不自动后渗透；SQLi/XSS 默认 -danger-level 0（只读探测），写操作（INSERT/UPDATE/DELETE/DROP/--dump）需显式授权与 -danger-level 2。"""

OUTPUT_PROTOCOL = """## 决策/输出协议
- 每次只输出一个 JSON 对象，不要 markdown 围栏，必须可被 json.loads 解析。
- action 只能是 call_tool | run_tool | done：
  * call_tool: {"thinking": [...], "action": "call_tool", "tool_name": "...", "params": {...}, "reason": "...", "plan": [...], "confidence": 0.0~1.0, "hypothesis_id": "..."}
  * run_tool: {"thinking": [...], "action": "run_tool", "command": "...", "reason": "...", "plan": [...]}
  * done: {"thinking": [...], "action": "done", "summary": "...", "structured_summary": {"findings": [{"title": "...", "severity": "high", "confidence": 0.8, "evidence": ["..."]}], "next_hypotheses": ["..."]}, "plan": []}
- done 时 structured_summary.findings 每项必须给出 severity(high/medium/low/info) 与 confidence(0~1)，
  evidence 只引用 extract_findings 返回的真实工具输出，禁止 LLM 自编证据。"""

AUTO_INTEGRATION = """## 自动集成约束（必须每次执行，非可考虑）
1. 调用任何扫描/枚举工具（fastsec_sqli_scan / fastsec_xss_scan / fastsec_dir_scan /
   fastsec_port_scan / nmap_scan / kali_run 等）后，**必须**立即调用
   `extract_findings(agent_id="{agent_id}", tool_name=<刚才的工具名>, output=<原始输出>, target=<目标>)`
   提炼证据；evidence 只来自其返回值，禁止自编。
2. 每次工具调用后**必须**调用 `dag_apply(op="add_node", payload={{...}})` 建 attack_action 节点
   （label 含工具名与目标，meta 含 tool/output_preview）；命中后 `dag_apply(op="deposit", ...)`
   沉积信息素。DAG 节点类型合法方向：observation→(evidence)→hypothesis→(drives)→attack_action→(yields)→observation/finding。"""

# 能力工具提示（harness 面：fastsec 全能力独立工具 + nmap + kali_run 回退）
CAPABILITY_TOOLS = """- fastsec 全能力独立工具（直接调用，各工具意图单一）：
  fastsec_port_scan（端口扫描）/ fastsec_dir_scan（目录枚举）/ fastsec_cms_scan（CMS 识别）/
  fastsec_sqli_scan（SQLi，danger_level 默认 0 只读）/ fastsec_xss_scan（XSS，xss_benign 默认无害 marker）/
  fastsec_brute（登录爆破）/ fastsec_osint（OSINT）/ fastsec_fingerprint（服务指纹）/
  fastsec_template_scan（模板扫描）/ fastsec_crack（哈希破解）/ fastsec_kerberos（AS-REP/Kerberoast）/
  fastsec_diff（行为差异）/ fastsec_orchestrate（编排扫描）/ fastsec_seq（状态化序列）/
  fastsec_audit（静态审计）/ fastsec_file（取证分析）/ fastsec_user（用户名搜索）/
  fastsec_shell（payload 生成）/ fastsec_sam（SAM 提取）/ fastsec_smb（SMB 横向）/
  fastsec_dump（数据提取，需 danger_level>=1）/ fastsec_kb（本地知识库查询）
- nmap_scan / kali_run（元回退）"""

COLLAB = """## 协作协议
- 发现通过 coordinator 汇总，或读 `dag_status` 交换进展（其他子代理建的节点/边可见）。
- 下一步行动前读 `dag_recommend(node_id=<当前节点>, agent_role="{agent_id}", k=5)` 参考 ACO 推荐路径
  ——**仅参考，你可否决**（ACO 只推荐不决策）。"""


def agent_slug(agent_id: str) -> str:
    return agent_id.replace("_", "-")


def build_body(agent_id: str, name_cn: str) -> str:
    f = FACTS.get(agent_id, {})
    role = (f.get("role") or "").strip()
    tools = f.get("tools", [])
    specs = f.get("specialties", [])
    tools_str = "\n".join(f"- {t}" for t in tools) or "- (无显式工具面，经 kali_run 访问)"
    specs_str = "、".join(specs) or "通用"
    body = f"""# {agent_id}（{name_cn}）

## 角色/目标
{role}

## 工具面（允许调用的 MCP 能力工具）
{tools_str}

{CAPABILITY_TOOLS}

自动集成工具（每次工具调用后必用，见下节）：
- dag_apply / dag_recommend / dag_status / kb_search / extract_findings

{OUTPUT_PROTOCOL}

{AUTO_INTEGRATION.replace("{agent_id}", agent_id)}

{COLLAB.replace("{agent_id}", agent_id)}

{RATE_DISCIPLINE}
"""
    return body


def build_coordinator_body() -> str:
    roles = "\n".join(f"- {aid}: {', '.join(FACTS.get(aid, {}).get('specialties', [])[:3]) or '专业子代理'}" for aid in sorted(FACTS))
    return f"""# coordinator（编排子代理）

## 角色/目标
你是渗透评估编排者：把任务分解派发给 18 个专业子代理，评审结果，决定何时完成。
可用子代理：
{roles}

## 工具面
- dag_apply / dag_recommend / dag_status / kb_search / extract_findings
- 通过 task/子代理机制派发 mission（objective/target/constraints/priority），不直接执行扫描。

## 决策/输出协议
- 每次只输出一个 JSON 对象，不要 markdown 围栏，必须可被 json.loads 解析。
- action 只能是 dispatch_mission | review | done：
  * dispatch_mission: {{"thinking": [...], "action": "dispatch_mission", "agent_role": "<精确的子代理 id>", "objective": "具体目标", "target": "目标", "context_refs": ["dag.node.n1", "kb.chunk.3"], "constraints": ["只读验证; 无破坏性命令"], "priority": 8, "reason": "...", "plan": ["..."]}}
  * review: {{"thinking": [...], "action": "review", "assessment": "还缺什么/为何未完成", "reason": "", "plan": [...]}}
  * done: {{"thinking": [...], "action": "done", "summary": "...", "structured_summary": {{"findings": [{{"title": "...", "severity": "high", "confidence": 0.8, "evidence": ["..."]}}], "next_hypotheses": ["..."]}}, "plan": []}}

## DAG/ACO 自动集成（每轮必做，LLM 透明）
1. 每派发一个 mission 后：`dag_apply(op="add_node", payload={{node_type: "mission", label: <objective>, meta: {{agent_role, objective}}}})`。
2. 每收到子代理结果后：`dag_apply(op="add_edge", payload={{source_id: <mission node>, target_id: <attack_action node>, edge_type: "drives"}})` +
   `dag_apply(op="deposit", payload={{edge_ids: [...], success_signal: <0~1>}})`。
3. 决定下一步前读 `dag_recommend(node_id=<当前节点>, k=5)` ——**仅参考，你可否决**（ACO 只推荐不决策）。
4. 派发前查 `dag_status`/`kb_search` 避免重复劳动与知识复用。

## 规则
1. 每次只一个 action：dispatch_mission | review | done。
2. agent_role 必须精确匹配子代理 id；objective 具体且不重复（先查 dag_status）。
3. review 用于结果不足时——不无限空转。
4. 覆盖目标或无有价值下一步即 done，给 summary。
5. 只输出 json.loads 可解析的 JSON，无散文、无 markdown 围栏。

{RATE_DISCIPLINE}
"""


CN_NAMES = {
    "auth_agent": "认证攻击子代理", "code_analyze_agent": "代码分析子代理",
    "code_audit_agent": "代码审计子代理", "crypto_agent": "密码学子代理",
    "exploit_agent": "漏洞利用子代理", "forensics_agent": "取证子代理",
    "lateral_agent": "横向移动子代理", "network_vuln_agent": "网络漏洞子代理",
    "privilege_agent": "提权子代理", "pwn_agent": "PWN/二进制子代理",
    "recon_agent": "侦察子代理", "source_code_agent": "源码获取子代理",
    "subdomain_agent": "子域名字代理", "vuln_scanner_agent": "漏洞扫描子代理",
    "vuln_verifier_agent": "漏洞验证子代理", "web_recon_agent": "Web 侦察子代理",
    "web_vuln_agent": "Web 漏洞子代理",
}


def main() -> None:
    claude_dir = REPO / ".claude" / "agents"
    claude_dir.mkdir(parents=True, exist_ok=True)
    skills_dir = REPO / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)

    md_agents = []  # Codex AGENTS.md 节
    opencode_agents = {}  # opencode.json agent 节

    for agent_id, cn in CN_NAMES.items():
        body = build_body(agent_id, cn)
        slug = agent_slug(agent_id)

        # Claude Code
        desc = (FACTS.get(agent_id, {}).get("role") or "")[:120]
        fm = f"""---
name: {slug}
description: {desc}
tools: Read,Grep,Bash,fastsec_scan,nmap_scan,kali_run,dag_apply,dag_recommend,dag_status,kb_search,extract_findings
---

"""
        (claude_dir / f"{slug}.md").write_text(fm + body, encoding="utf-8")

        # Pi skills
        (skills_dir / f"kali-{agent_id}.md").write_text(
            f"---\nname: kali-{agent_id}\ndescription: {desc}\n---\n\n" + body,
            encoding="utf-8",
        )

        # Codex
        md_agents.append(f"## Role: {agent_id}\n\n{body.strip()}")

        # OpenCode
        opencode_agents[agent_id] = {
            "description": desc,
            "prompt": body.strip(),
            "tools": ["read", "grep", "bash", "fastsec_scan", "nmap_scan", "kali_run",
                      "dag_apply", "dag_recommend", "dag_status", "kb_search", "extract_findings"],
        }

    # coordinator（第 18 个）
    coord_body = build_coordinator_body()
    (claude_dir / "coordinator.md").write_text(
        "---\nname: coordinator\ndescription: 编排 18 个专业子代理（派发/评审/done，含 DAG/ACO 自动集成）\ntools: Read,Grep,Bash,dag_apply,dag_recommend,dag_status,kb_search,extract_findings\n---\n\n"
        + coord_body, encoding="utf-8")
    (skills_dir / "kali-coordinator.md").write_text(
        "---\nname: kali-coordinator\ndescription: 编排 18 个专业子代理（派发/评审/done，含 DAG/ACO 自动集成）\n---\n\n"
        + coord_body, encoding="utf-8")
    md_agents.append(f"## Role: coordinator\n\n{coord_body.strip()}")
    opencode_agents["coordinator"] = {
        "description": "编排 18 个专业子代理（派发/评审/done，含 DAG/ACO 自动集成）",
        "prompt": coord_body.strip(),
        "tools": ["read", "grep", "bash", "dag_apply", "dag_recommend", "dag_status", "kb_search", "extract_findings"],
    }

    # Codex AGENTS.md
    header = """# Codex Agent 定义（Kali MCP 原生子代理）

仓库 = 能力层 MCP（kali_mcp）+ 18 个原生 markdown 子代理 + hooks 自动集成。
主 agent 用 coordinator 派发；子代理调 MCP 能力工具（fastsec_scan/nmap_scan/kali_run）
后**自动** extract_findings 提炼证据 + dag_apply 建图（hooks 或正文约束，见各 Role 节）。
"""
    (REPO / "AGENTS.md").write_text(header + "\n\n".join(md_agents) + "\n", encoding="utf-8")

    # OpenCode opencode.json
    opencode = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "kali": {
                "type": "stdio",
                "command": "py",
                "args": ["-3", "mcp_server.py", "--tool-profile", "harness"],
                "cwd": str(REPO),
            }
        },
        "agent": opencode_agents,
    }
    (REPO / "opencode.json").write_text(
        json.dumps(opencode, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"claude agents: {len(list(claude_dir.glob('*.md')))}")
    print(f"pi skills: {len(list(skills_dir.glob('*.md')))}")
    print(f"codex roles: {len(md_agents)}")
    print(f"opencode agents: {len(opencode_agents)}")


if __name__ == "__main__":
    main()
