# Kali MCP — LLM 自主多智能体渗透系统

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Protocol-00D4AA?style=for-the-badge)
![Embedding](https://img.shields.io/badge/Embedding-bge--small--zh-8A2BE2?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**深度推理增强的 LLM 自主多智能体渗透系统**


[中文](#中文) | [English](#english) | [架构设计 ARCH_DESIGN](ARCH_DESIGN.md)

</div>

---

## 中文

在开始前，非常感谢github社区，作为世界最大的程序员无偿共享社区，本项目中的很多技术灵感皆从github项目迸发

### 定位

Kali MCP 是一套 **LLM 自主多智能体渗透系统**，依据「向量化知识库 + 联网搜索 + 自身能力」逐步动态规划下一步，而不是沿预定义路径执行。1 个 **OrchestratorAgent**（主 LLM 决策者）负责顶层规划与派活，**17 个子 agent 各自都是 LLM 自主智能体**（角色 prompt + 工具面 + LLMBrain 决策循环），它们的发现沉淀为**攻击 DAG 节点**，**蚁群算法（ACO）** 在攻击路径上沉积信息素（成功置信度）为后续行动提供**推荐**（仅推荐，不决策），最终由 **SummarizerAgent** 去重、去误报、排序并实时推送（SSE）给主 agent 与用户。

无 LLM 密钥时系统**依然可以运行**：自动降级到 legacy 确定性路径（子 agent 回退到原规则路由，`K4_LEGACY_CLUSTER=1` 集群照常可用）——但那是**回退模式**，本项目的核心竞争力是 **LLM 自主决策的深度推理渗透**。

### 架构

```mermaid
flowchart TB
    U["用户 / 主 agent"] -->|自然语言任务| ORCH

    subgraph ORCH["OrchestratorAgent（主 LLM 决策者）"]
        OL["LLMBrain 顶层规划循环"]
        OB["MissionBrief 生成"]
        OV["结果评审 / 回收 / 再规划"]
    end

    subgraph KB["向量化知识库"]
        IDX[("kb_vectors.db<br/>sqlite-vec")]
        RT["KnowledgeRetriever<br/>语义 top-k + 元数据过滤 + BM25 融合"]
        EMB["Embedding 模型<br/>BAAI/bge-small-zh-v1.5 本地 512 维"]
    end

    subgraph DAG["攻击 DAG + ACO"]
        DAGS["DAGService<br/>唯一写入者"]
        ACO["蚁群算法<br/>信息素蒸发/沉积/选路"]
        PHE[("攻击路径信息素表")]
    end

    subgraph AGENTS["17 个 LLM 子 agent"]
        A1["recon_agent"] -->|共享| LB["LLMAgentBase<br/>LLMBrain 决策循环"]
        A2["web_vuln_agent"] -->|共享| LB
        A3["exploit_agent"] -->|共享| LB
        AX["...其余 14 个"]
    end

    SUM["SummarizerAgent 总结智能体"]
    ES["EventStream<br/>SSE 推送"]
    BUS["EventBus<br/>tool.result / mission / dag / summary"]
    MESH["MeshMessageBus<br/>agent 点对点"]
    TB["ToolBridge<br/>call_tool + catalog"]
    EX["executor / fastsec 等真实工具"]
    WS["WebSearch<br/>ddg/tavily 工具"]

    ORCH -->|mission.created| BUS
    ORCH -->|检索| RT
    ORCH -->|读取 τ/η 推荐| DAGS
    BUS --> DAGS
    DAGS -->|dag.updated| ACO
    ACO -->|候选边评分| ORCH
    ACO -->|候选边评分| LB
    LB -->|call_tool| TB
    TB --> EX
    LB -->|tool.result| BUS
    LB -->|检索| RT
    TB -.注册.-> WS
    BUS --> SUM
    MESH --> AGENTS
    SUM -->|summary.update| BUS
    SUM -->|SSE| ES
    ES --> U
    ORCH -->|mission.review| BUS
    DAGS -->|dag.updated| SUM
```

### 核心能力

| 能力 | 说明 | 代码模块 |
|---|---|---|
| **LLM 是唯一决策者** | 任何「下一步做什么」的结论都来自 LLM 决策 JSON（`call_tool / run_tool / done / retry`）。DAG、ACO、知识库只作为**上下文与评分推荐**注入 LLM 输入，**不得直接触发工具**。顶层规划由重构后的 orchestrator 执行（LLM 循环：目标理解 → dispatch_mission → 结果评审 → 再规划 → 终止判定） | `kali_mcp/core/llm_brain.py`、`kali_mcp/core/agent_coordinator.py` |
| **17 个 LLM 自主子 agent** | 每个子 agent 继承 `LLMAgentBase`：角色 prompt（ROLE_PROMPT）+ 工具面（`AgentCapability.supported_tools ∩ ToolBridge` 注册表）+ `llm_drive_mission` 决策循环。任务以 **MissionTicket**（即 DAG 节点）经 `mission.created` 事件下发、按角色认领。工具调用仍走原 `_call_tool` executor 桥，输出由确定性正则提炼成 Finding 证据（结构化证据提取保持确定性，避免 LLM 编造） | `kali_mcp/agents/llm_agent_base.py` |
| **攻击 DAG + 蚁群算法（ACO）** | 子 agent 的发现（observation / hypothesis / attack_action / finding / mission / summary）作为 DAG 节点，边承载信息素 τ ∈ [0.05, 1]。验证/平台判定成功时沿 `enables`/`yields` 路径**沉积信息素**，定期蒸发，`P(e) = τ^α·η^β` 归一化后给出候选边评分。**诚实说明：ACO 只做路径推荐（top-k 候选边），LLM 可以采纳、引用或否决——否决本身作为负反馈进入启发式；LLM 才是决策者** | `kali_mcp/reasoning/attack_dag.py`、`kali_mcp/reasoning/aco.py` |
| **总结智能体 SummarizerAgent** | 订阅 `mission.completed/failed`、`tool.result`（critical/high 过滤）、`vuln.verified`、`dag.updated`、`flag.found`；流水线：规范化 → sha1 指纹去重 → 三层去误报（硬过滤 / confidence 阈值 / LLM 三分类研判）→ 严重性排序 → `SummarySnapshot`；经 EventBus + EventStream 实时 SSE 推送（同 session 2s 节流，`flag.found` 立即高优推送） | `kali_mcp/core/summarizer_agent.py` |
| **向量化知识库** | 本地 `sentence-transformers` embedding（**`BAAI/bge-small-zh-v1.5`，512 维，权重随仓库提供**）+ `sqlite-vec` 单文件向量库（`data/kb_vectors.db`）+ `rank-bm25` 关键词召回，**RRF 融合**。orchestrator 下发任务前与子 agent 执行中（每 3 步）注入 KB 命中块，语义检索经验库（战术 / writeup / 口令 / 绕过技巧等）。索引构建幂等增量（`content_hash` 跳过未变文件） | `kali_mcp/reasoning/knowledge_retriever.py`、`scripts/build_kb_index.py`、`scripts/kb_sources.yaml` |
| **联网搜索** | `web_search` / `web_fetch` 注册为 ToolBridge 普通工具（进入工具目录，走标准 `call_tool` 路径，天然留审计日志），LLM 自主决定何时搜索 CVE / 漏洞情报 / 绕过技巧。后端按 `WEB_SEARCH_BACKEND=ddg\|tavily` 切换（默认 ddg 免费无 key） | `kali_mcp/core/search_backends.py`、`kali_mcp/core/tool_bridge.py` |
| **自研 fastsec 扫描引擎** | Go 单二进制 AI 原生扫描器，**替代 25 个外部工具**（gobuster/nikto/sqlmap/whatweb/subfinder/ffuf/nuclei/hydra/dirb/wfuzz/feroxbuster/dnsrecon/fierce/dnsenum/theharvester/sherlock/joomscan/wpscan/medusa/patator/ncrack/crowbar/brutespray/searchsploit/masscan）。能力：目录枚举 / CMS 指纹 / 注入检测 / XSS 反射 / 登录爆破（含 263 万口令字典）/ Kerberos AS-REP 与 Kerberoast / 服务指纹 / OSINT / 哈希破解 / 反连 shell 生成 / SAM 提取等，内置 `tools/fastsec/data/` 字典与知识库 | `tools/fastsec/` |
| **执行后端自适应** | 启动时 `resolve_backend()` 自动检测：本地 subprocess（默认）、SSH 远程主机、Docker 容器，无需改代码 | `kali_mcp/core/backend.py` |

### 17 个 LLM 自主子 agent

每个子 agent 都是一个 **LLM 自主智能体**：用自己的角色 prompt、自己的工具面、自己的 LLMBrain 决策循环，在任务简报、知识库命中、攻击图信息素视图与已有发现的上下文中逐步决定「调哪个工具、什么参数、如何解读输出、何时回报」。工具调用失败判定与结构化证据提取仍是确定性代码。

| 分组 | 智能体 | 职责 |
|---|---|---|
| **信息收集** | `recon_agent` | 端口扫描 / 服务识别 / OS 指纹 / 拓扑侦察 |
| | `subdomain_agent` | 子域名枚举 / DNS 记录 / OSINT |
| | `web_recon_agent` | 目录枚举 / 技术栈识别 / WAF 检测 / CMS 指纹 |
| **漏洞发现** | `vuln_scanner_agent` | CVE / 模板化漏洞扫描 |
| | `web_vuln_agent` | SQLi / XSS / 命令注入等 Web 漏洞 |
| | `auth_agent` | 在线爆破 / 哈希破解 / 凭据喷洒 |
| | `network_vuln_agent` | SMB 枚举 / LLMNR 投毒 / MITM / 嗅探 |
| | `vuln_verifier_agent` | 候选漏洞验证 / PoC 构造 / 利用确认 |
| **利用** | `exploit_agent` | Metasploit / exploit 搜索 / 反弹 shell |
| | `privilege_agent` | Linux / Windows 提权向量分析 |
| | `lateral_agent` | DCSync / Kerberoast / AD 攻击 / 凭据重用 |
| **专门** | `code_analyze_agent` | 白盒源码树扫描 / 危险模式分析 |
| | `code_audit_agent` | SAST 静态分析 / 危险模式搜索 |
| | `crypto_agent` | CTF 密码学 / 编码识别 / 哈希破解 |
| | `forensics_agent` | 隐写 / 内存取证 / 文件系统取证 / 流量分析 |
| | `pwn_agent` | 二进制漏洞检查 / 逆向 / 反编译 |
| | `source_code_agent` | .git/.svn 泄露 / 备份扫描 / LFI 读源码 |

### 工具面（MCP surface）

MCP 表面已从 192 个工具收敛为 **keep-set（约 50 个原生注册）+ `kali_run` 元回退**：归档模块文件保留但**不再注册**，其命令仍可经 `kali_mcp.core.tool_registry` 构建，通过 `kali_run` 按名调用（keep-set 或归档、registry key 或别名均可）。

| 类别 | 工具 |
|---|---|
| **KG/DAG 能力** | `dag_apply`（DAGService.apply 写命令：add_node/add_edge/update_node/deposit/deposit_path/evaporate，串行落库）、`dag_recommend`（ACO 候选边 P(e) 评分，只推荐不决策）、`dag_status`（攻击 DAG 全局状态：节点/边、信息素 top 路径、前沿候选边）、`kb_search`（语义+关键词混合检索知识库） |
| **证据提炼** | `extract_findings`（复用 17 个 Python agent 的确定性正则解析器，工具输出 → 结构化 Finding，LLM 透明） |
| **痕迹清理** | `wipe_traces`（三粒度：task 删 workspace/tasks/<id>/ 整目录 / session 删 DAG 会话+d01_session.json / global 清运行时状态；目标侧清除只出命令模板） |
| **任务板** | `start_task`、`task_status`、`run_surface_chain`、`verify_finding`、`task_create`、`task_claim`、`task_complete`、`task_renew`、`task_list`、`board_snapshot` |
| **fastsec 扫描** | **23 个独立能力工具**（fastsec 二进制全模式）：`fastsec_port_scan`、`fastsec_dir_scan`、`fastsec_cms_scan`、`fastsec_sqli_scan`（`danger_level` 默认 0 只读）、`fastsec_xss_scan`（`xss_benign` 默认无害 marker）、`fastsec_brute`、`fastsec_osint`、`fastsec_fingerprint`、`fastsec_template_scan`、`fastsec_crack`、`fastsec_kerberos`、`fastsec_diff`、`fastsec_soceng`（社工字典）、`fastsec_orchestrate`（编排扫描）、`fastsec_seq`（状态化序列）、`fastsec_audit`（静态审计）、`fastsec_file`（取证分析）、`fastsec_user`（用户名搜索）、`fastsec_shell`（payload 生成）、`fastsec_sam`（SAM 提取）、`fastsec_smb`（SMB 横向）、`fastsec_dump`（数据提取，需 `danger_level>=1`）、`fastsec_kb`（本地知识库）；`fastsec_scan`（旧 kali_run 回退名） |
| **端口/服务** | `nmap_scan`、`rustscan_scan`、`naabu_scan`、`comprehensive_recon`、`server_health` |
| **口令/域渗透** | `john_crack`、`hashcat_crack`、`kerbrute_attack`、`GetNPUsers_scan`、`GetUserSPNs_scan`、`nxc_attack`、`evil_winrm_attack`、`secretsdump_scan`、`psexec_attack`、`smbexec_attack` |
| **利用** | `metasploit_run`、`quick_pwn_check` |
| **会话/工作流** | `start_attack_session`、`list_attack_sessions`、`wf_init`、`wf_transition`、`wf_record_result`、`wf_record_issue`、`wf_status`、`wf_pack_turn` |
| **异步扫描** | `scan_start`、`scan_collect`、`scan_wait`、`scan_jobs` |
| **元回退** | `kali_run`（任意 registry 工具按名执行） |

> 预定义 playbook（`run_playbook` / `run_surface_chain`）已**移出主路径**（战术内容向量化进 KB 作参考），仅设置 `K4_LEGACY_PLAYBOOKS=1` 时作为过渡期兼容注册。

### fastsec 自研扫描引擎

`tools/fastsec/` 是 Go 单二进制引擎（含 `data/` 内置字典：`dns/` 子域字典 63MB、`brute/` 口令字典 40MB 含 263 万 top 口令、`knowledge/` 经验库 2.5MB），核心能力：

| 能力 | 参数（MCP 工具） |
|---|---|
| 目录枚举 | `fastsec_dir_scan`（`-dir <url>` / `-w <wordlist>`） |
| CMS 识别 | `fastsec_cms_scan`（`-cms <url>`） |
| SQL 注入检测 | `fastsec_sqli_scan`（`-inject <param,...>`，`danger_level` 0=只读默认） |
| XSS 反射检测 | `fastsec_xss_scan`（`-xss <param,...>`，`xss_benign` 默认无害 marker） |
| 登录爆破 | `fastsec_brute`（`-brute <host>`、`-service http-form\|tcp-banner`、`-U/-P` 字典、`-form-*` 表单配置） |
| 口令字典生成 | `-soceng <name>`（社工字典） |
| Kerberos | `fastsec_kerberos`（`-kerberos <kdc>`、`-domain`、`-kusers`（AS-REP / Kerberoast）、`-kpass`） |
| 服务指纹 | `fastsec_fingerprint`（`-fingerprint <host>` / `-fp-ports`） |
| 模板扫描 | `fastsec_template_scan`（`-t <file>` / `-d <dir>`，nuclei 风格模板） |
| 行为差异 | `fastsec_diff`（`-diff <params>`） |
| OSINT | `fastsec_osint`（`-osint <domain>`） |
| 哈希破解 | `fastsec_crack`（`-crack md5:<hash>` / `-crack-wordlist`） |
| 端口扫描 | `fastsec_port_scan`（`-scan <target>` / `-scan-range`） |
| 社工字典 | `fastsec_soceng`（`-soceng <name>`，本地生成） |
| 编排扫描 | `fastsec_orchestrate`（`-orchestrate <target>`） |
| 状态化序列 | `fastsec_seq`（`-seq <yaml>`） |
| 静态审计 | `fastsec_audit`（`-audit <path>`，SAST） |
| 取证分析 | `fastsec_file`（`-file <path>`，替代 binwalk） |
| 用户名搜索 | `fastsec_user`（`-user <name>`，替代 sherlock） |
| 反连 payload | `fastsec_shell`（`-shell <lang>` / `-s-host` / `-s-port` / `-s-enc`，只生成不执行） |
| SAM 提取 | `fastsec_sam`（`-sam <hive>` / `-system <hive>`） |
| SMB 横向 | `fastsec_smb`（`-smb <host>` / `-smb-cmd` / `-smb-user` / `-smb-pass`） |
| 数据提取 | `fastsec_dump`（`-dump <url>` / `-dump-param`，需 `danger_level>=1` 显式授权） |
| 知识库查询 | `fastsec_kb`（`-kb <query>`，内置 knowledge.json，非扫描） |

### 快速开始

#### 1. 环境准备

```bash
# Python 3.10+
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

- **embedding 模型已随仓库提供**：`data/models/models--BAAI--bge-small-zh-v1.5/`（512 维，完全离线可跑，无需联网下载）。
- **知识库索引已随仓库提供**：`data/kb_vectors.db`（sqlite-vec 单文件）。
- fastsec 引擎需要 Go 工具链时自行 `cd tools/fastsec && go build -o fastsec ./cmd/fastsec`（或直接用仓库内已构建产物；扫描也可完全走 `nmap_scan` 等 keep-set 工具，不强制 fastsec）。

#### 2. MCP 接入（Claude Code / Codex / OpenCode / Pi）—— 原生子代理为主路径

Kali MCP 是标准 **stdio MCP 服务器**。当前架构 = **能力层 MCP + 18 个原生 markdown 子代理 + hooks 自动集成**：

- **能力层 MCP**（服务端）：`python mcp_server.py --tool-profile harness` 暴露纯能力工具——扫描/枚举（fastsec_scan/nmap_scan/kali_run 等）+ **DAG/ACO 读写与观测**（`dag_apply`/`dag_recommend`/`dag_status`）+ **知识库检索**（`kb_search`）+ **证据提炼**（`extract_findings`，复用 17 个 Python agent 的确定性解析器）+ 任务板 + 痕迹清理（`wipe_traces`）。MCP 编排面（两个 pure-orchestration 工具）与 17-agent 集群初始化已**移除**——编排移入 harness 侧 coordinator 子代理。
- **18 个原生子代理**（仓库已生成，见下表）：`coordinator`（派发/评审/done，自动读 DAG/ACO 推荐）+ 17 个专业子代理（recon/web_vuln/auth 等）。每个正文含角色目标、工具面、决策 JSON 协议、**自动集成约束**（扫描后必调 extract_findings + dag_apply，LLM 透明）、协作协议（dag_status/dag_recommend 参考，ACO 只推荐不决策）与速率纪律。
- **hooks 自动触发**：`.claude/settings.json` 的 PostToolUse hook（其余 harness 见 `scripts/hooks/README.md`）在子代理每次扫描工具调用后**自动** `dag_apply` 建节点 + `extract_findings` 提炼——治"靠提示才调 DAG"的根因。

| harness | 子代理文件 | hook 落点 |
|---|---|---|
| Claude Code | `.claude/agents/*.md` ×18 | `.claude/settings.json`（已配） |
| Codex | `AGENTS.md`（`## Role:` ×18） | `~/.codex/config.toml`（示例见 `scripts/hooks/README.md`） |
| OpenCode | `opencode.json` 的 `"agent"` 节 ×18 | `plugin`/`tool.execute.after`（示例见 hooks README） |
| Pi（omp） | `skills/kali-*.md` ×18 | omp hook 等价机制（示例见 hooks README） |

接入后直接说：

```
对 http://target/ 做一次完整渗透：先侦察，再扫 Web 漏洞，验证后给出利用建议
```

主 agent 发起 → `coordinator` 子代理派发 → 专业子代理调能力工具 → hook 自动建 DAG/提炼证据 → coordinator 读 `dag_recommend` 决定下一步。

##### Claude Code

项目级配置 `.mcp.json`（MCP 能力层）：

```json
{
  "mcpServers": {
    "kali": {
      "command": "python",
      "args": ["mcp_server.py", "--tool-profile", "harness"],
      "cwd": ".",
      "env": { "KALI_MCP_TOOL_PROFILE": "harness" }
    }
  }
}
```

子代理自动加载：`.claude/agents/`（18 个已生成）；hooks 自动集成：`.claude/settings.json`（已配 PostToolUse → `scripts/kali_auto_dag_hook.py`）。

##### Codex（OpenAI Codex CLI）

用户级配置 `~/.codex/config.toml`：

```toml
[mcp_servers.kali]
command = "python"
args = ["mcp_server.py", "--tool-profile", "harness"]
env = { KALI_MCP_TOOL_PROFILE = "harness" }
```

子代理定义在仓库根 `AGENTS.md`（`## Role:` 分节 ×18）；tool-use 后 hook 见 `scripts/hooks/README.md`。

##### OpenCode

项目级 `opencode.json`（本仓库已生成：18 个 `"agent"` 定义 + `"mcp.kali"` 并存）：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "kali": {
      "type": "local",
      "command": ["python", "mcp_server.py", "--tool-profile", "harness"],
      "environment": { "KALI_MCP_TOOL_PROFILE": "harness" },
      "enabled": true
    }
  },
  "agent": { }
}
```

`"agent"` 节的 18 个定义已生成在仓库根 `opencode.json`；hook（`tool.execute.after`）示例见 `scripts/hooks/README.md`。

##### Pi / Oh My Pi

Pi（omp）读取仓库根目录标准 `.mcp.json`（与 Claude Code 同一格式）：

```json
{
  "mcpServers": {
    "kali": {
      "command": "python",
      "args": ["mcp_server.py", "--tool-profile", "harness"],
      "cwd": ".",
      "env": { "KALI_MCP_TOOL_PROFILE": "harness" }
    }
  }
}
```

子代理定义在 `skills/kali-*.md` ×18（frontmatter name/description + 正文 5 节）；主 agent 用 task 调度 coordinator 或直接派专业子代理。hook 等价机制示例见 `scripts/hooks/README.md`。

> 注意：`command` 里把 `python` 换成你机器上的解释器绝对路径（Windows 常见 `C:\Windows\py.exe -3` 或 `.venv\Scripts\python.exe`）；`cwd` 指向仓库根目录，保证 `mcp_server.py`、`data/`、`tools/fastsec/` 相对路径正确。

#### 3. CLI 实时可视化（不接 harness）

```bash
# Windows
C:/Windows/py.exe -3 agent_live.py "对 http://localhost:8000/ 做 web 漏洞扫描：目录枚举、CMS识别、注入检测" --no-cache --timeout 300

# Linux / macOS
python3 agent_live.py "对 http://localhost:8000/ 做 web 漏洞扫描" --agents recon,web_vuln --no-cache
```

`agent_live.py` 是纯展示层：逐行分色打印 orchestrator 的规划/派活决策、每个子 agent 的 LLM 决策与工具调用结果、findings 与总结推送，Windows Terminal 分屏即可获得类 tmux 的实时观察体验。`--agents` 可按 agent_id 精确或前缀匹配（如 `recon` 匹配 `recon_agent`）。

#### 4. SSE 远程模式

```bash
python mcp_server.py --transport sse --host 0.0.0.0 --port 8765 --tool-profile harness
# SSE 端点: http://<your-ip>:8765/sse
```

供远程客户端 / 多机部署接入（OpenCode 等支持 remote MCP 的 harness 可用 `"type": "remote", "url": "http://<ip>:8765/sse"` 连接）。

### LLM Provider 配置

决策循环由 `kali_mcp/core/llm_brain.py` 的 `LLMBrain` 驱动，双 provider 支持，全部走环境变量：

| 环境变量 | 说明 |
|---|---|
| `LLM_PROVIDER` | 显式指定 provider：`anthropic`（或 `claude`）/ `openai`（或 `codex`）。不设时自动探测：存在 `OPENAI_API_KEY` 走 OpenAI，否则走 Claude |
| `ANTHROPIC_API_KEY`（或 `ANTHROPIC_AUTH_TOKEN`） | Claude provider 密钥 |
| `ANTHROPIC_MODEL` | Claude 模型名 |
| `ANTHROPIC_BASE_URL` | 自定义 Claude 端点（自动补 `/v1` 后缀，兼容代理/网关） |
| `OPENAI_API_KEY`（或 `OPENAI_AUTH_TOKEN`） | OpenAI provider 密钥 |
| `OPENAI_MODEL` | OpenAI 模型名 |
| `OPENAI_BASE_URL` | 自定义 OpenAI 端点（兼容代理 / 兼容网关） |

**无任何 LLM key**：`LLMBrain.available = False`，子 agent 自动回退 legacy 确定性路径（`kali_mcp/agents/*/_execute_task_impl_legacy`），集群照常运行、不空转；但 LLM 自主决策（动态规划、语义检索、ACO 引导、联网情报）不可用——**那不是本项目的常态模式**。

联网搜索可选配置：`WEB_SEARCH_BACKEND=ddg|tavily`（默认 `ddg`）；切 `tavily` 需 `TAVILY_API_KEY`。

### 知识库与 Embedding

- **Embedding 模型**：`BAAI/bge-small-zh-v1.5`（512 维，中文友好），权重随仓库提供于 `data/models/models--BAAI--bge-small-zh-v1.5/`（HuggingFace cache 结构），完全离线加载（`snapshot_download(local_files_only=True)`）。
- **向量库**：`data/kb_vectors.db`（sqlite-vec 单文件，随仓库提供），失败自动降级 numpy+JSON。
- **召回**：向量 top-k + BM25 关键词 + **RRF 融合**；中英混合 tokenizer（ASCII 词 + CJK 单字）。
- **数据源**（`scripts/kb_sources.yaml`）：

| source | 内容 | parser |
|---|---|---|
| `credentials_guide` | `data/wordlists/` 渗透字典与默认账号库 | markdown |
| `runbook_internal` | `doc/runbook-internal.md` 内部运行约定 | markdown |
| `capability_plan` | `doc/能力升级总计划.md` 演进方向 | markdown |
| `writeups` | `docs/writeups/*.md` 实战 writeup | markdown |
| `plans` | `docs/plans/*.md` 设计/计划文档 | markdown |
| `recipes` | `tools_recipes/*.yaml` 工具配方 | yaml |
| `playbooks` | playbook docstring 摘录 | playbook_docstring |
| `attack_chains` | `knowledge_graph.py` AttackChain 结构化条目（25 条） | attack_chain |

重建 / 增量更新知识库索引（幂等：按 `content_hash` 跳过未变文件）：

```bash
python scripts/build_kb_index.py
```

### 执行后端

`mcp_server.py` 启动时经 `kali_mcp/core/backend.resolve_backend()` 自动检测执行后端，无需改代码：

| 后端 | 说明 |
|---|---|
| `local`（默认） | subprocess 直接调用本机工具（Kali / 自建环境） |
| `ssh` | 通过 SSH 在远程 Kali 主机执行（配置远程主机信息后自动启用） |
| `docker` | 在容器内执行 |

### 环境变量总表

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `KALI_MCP_TOOL_PROFILE` | `harness` | 工具档位：`strict` / `compliance` / `full` / `harness` |
| `KALI_MCP_FORCE_ENABLE_MODULES` | — | 强制启用模块（逗号分隔），如 `multi_agent` |
| `KALI_MCP_FORCE_DISABLE_MODULES` | — | 强制禁用模块（逗号分隔） |
| `K4_LEGACY_CLUSTER` | — | `1` 时初始化 17-agent 多智能体集群（LLM orchestrator 入口） |
| `K4_LEGACY_PLAYBOOKS` | — | `1` 时注册 legacy playbook 工具（过渡期兼容） |
| `KALI_MCP_WORKSPACE` | `workspace/` | 任务工作区（扫描产物/证据/报告落盘） |
| `KALI_MCP_AUTO_WIPE` | `1` | chain REPORT 终态自动清理 task 痕迹；`0` 关闭 |
| `KALI_MCP_KEEP_REPORT` | 未设 | `1` 时 task 级清理保留 `report/` 子目录 |
| `KALI_MCP_ENGAGEMENT_JSON` / `KALI_MCP_ENGAGEMENT_FILE` | — | 授权范围声明（目标 scope），工具执行前校验 |
| `KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT` | — | `1` 时强制要求授权上下文 |
| `LLM_PROVIDER` | 自动探测 | `anthropic` / `openai` |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` / `ANTHROPIC_BASE_URL` | — | Claude provider |
| `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` | — | OpenAI provider |
| `WEB_SEARCH_BACKEND` | `ddg` | 搜索后端：`ddg` / `tavily` |
| `TAVILY_API_KEY` | — | tavily 后端密钥 |

### 目录结构

```
Kali-Security-MCP/
├── mcp_server.py            # MCP 入口（FastMCP；工具按模块注册 + K1 收敛裁剪）
├── agent_live.py            # CLI 实时可视化（逐行分色打印 orchestrator/agent 决策）
├── kali_mcp/
│   ├── core/                # llm_brain / agent_coordinator / summarizer_agent /
│   │                        # tool_bridge / search_backends / event_bus / registry ...
│   ├── agents/              # 17 个 LLM 自主子 agent（LLMAgentBase + llm_drive_mission）
│   ├── reasoning/           # knowledge_retriever / attack_dag / aco / chain_engine
│   ├── mcp_tools/           # harness_tools / multi_agent_tools / meta_tools / board_tools ...
│   └── security/            # tool_profile / engagement（授权范围）
├── tools/fastsec/           # 自研 Go 扫描引擎 + 内置字典（dns/brute/knowledge）
├── data/
│   ├── kb_vectors.db        # 向量化知识库索引（sqlite-vec，随仓库提供）
│   ├── models/              # embedding 模型权重（bge-small-zh-v1.5，随仓库提供）
│   └── wordlists/           # 口令/默认账号指南（KB 源）
├── scripts/
│   ├── build_kb_index.py    # 知识库索引构建（幂等增量）
│   └── kb_sources.yaml      # KB 数据源声明
├── docs/                    # writeups / plans
├── doc/                     # runbook-internal / 能力升级总计划
├── tests/                   # pytest 全量测试（含 KB 索引 / LLM agent / DAG / ACO / e2e）
├── workspace/               # 任务工作区（运行产物）
├── .mcp.json                # MCP 部署配置实例（Claude Code / Pi 等）
├── CLAUDE.md                # Claude Code 仓库指引
└── requirements.txt
```

### 测试

```bash
pytest                    # 全量
pytest -x                 # 首个失败即停
pytest --cov=kali_mcp     # 覆盖率
pytest -k "kb or dag or aco or orchestrator or llm"   # 关键子系统
```

### 合规声明

本项目仅用于**已获书面授权**的渗透测试、CTF 竞赛、安全研究与防御性评估。使用前通过 `set_engagement_context`（或 `KALI_MCP_ENGAGEMENT_JSON/FILE`）声明授权范围；越权扫描、破坏性操作、未授权攻击严格禁止。使用者须自行确保对目标的所有操作均符合适用法律法规。

**Stealth & Rate Discipline**：XSS 等检测默认无害 marker 单请求验证（`-xss-benign`，不向生产打 alert(1) 集）；SQLi 默认 `-danger-level 0` 只读探测（写操作需显式 `-danger-level 2` 授权）；所有外发请求 UA 为真实浏览器随机 UA（品牌 UA 已移除）；速率纪律见 `RATE_DISCIPLINE`（`kali_mcp/core/playbooks/stealth.py`），机械兜底 = fastsec 内建节流（-c 20 / delay 300-800ms）。

**痕迹清理（雁过无痕）**：`wipe_traces` 工具按粒度自动清理本机痕迹——`task`（删 workspace/tasks/<id>/ 整目录，chain REPORT 终态默认自动触发，`KALI_MCP_AUTO_WIPE=0` 关闭）、`session`（删 DAG 会话 + d01_session.json）、`global`（清运行时状态，**永不自动**，需显式 `scope="global"`）。删除**不可恢复**；知识库/模型/字典（kb_vectors.db/models/wordlists 等）永不进清理清单。目标侧清除只输出命令模板（`target_manual_cleanup`），不自动执行——目标侧删除属操作者授权动作。

### License

MIT License — 详见 [LICENSE](LICENSE)。

---

## English

### Positioning

Kali MCP is an **LLM-autonomous multi-agent penetration testing system**:  
the **LLM is the sole decision-maker**, planning each next step dynamically from a **vectorized knowledge base + live web search + its own capabilities** — not along a predefined path.  
One **OrchestratorAgent** (the top-level LLM planner) understands the goal, dispatches missions, and reviews results;  
each of the **17 sub-agents is itself an LLM-autonomous agent** (role prompt + tool surface + an LLMBrain decision loop).  
Their discoveries become **nodes in an attack DAG**, an **Ant Colony Optimization (ACO)** layer deposits **pheromone (success confidence)** along attack paths to *recommend* — never decide — subsequent moves, and a **SummarizerAgent** deduplicates, filters false positives, ranks, and pushes results in real time (SSE).

Without any LLM API key the system **still runs**: it degrades to the legacy deterministic path (sub-agents fall back to rule routing; the `K4_LEGACY_CLUSTER=1` cluster stays available) — but that is the **fallback mode**. The core value of this project is **deep-reasoning penetration driven by LLM autonomy**.

### Quick Start

```bash
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

The embedding model (`BAAI/bge-small-zh-v1.5`, 512-dim) ships in `data/models/` and the vectorized KB index (`data/kb_vectors.db`) ships in `data/` — fully offline, no download needed.

**Connect from any MCP-capable harness** (all use the same stdio server `python mcp_server.py --tool-profile harness`):

- **Claude Code / Pi**: `.mcp.json` at project root —

```json
{
  "mcpServers": {
    "kali": {
      "command": "python",
      "args": ["mcp_server.py", "--tool-profile", "harness"],
      "env": {
        "KALI_MCP_TOOL_PROFILE": "harness",
        "K4_LEGACY_CLUSTER": "1",
        "KALI_MCP_FORCE_ENABLE_MODULES": "multi_agent",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

- **Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.kali]
command = "python"
args = ["mcp_server.py", "--tool-profile", "harness"]
env = { KALI_MCP_TOOL_PROFILE = "harness", K4_LEGACY_CLUSTER = "1", KALI_MCP_FORCE_ENABLE_MODULES = "multi_agent", OPENAI_API_KEY = "sk-..." }
```

- **OpenCode** (`opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "kali": {
      "type": "local",
      "command": ["python", "mcp_server.py", "--tool-profile", "harness"],
      "environment": { "KALI_MCP_TOOL_PROFILE": "harness", "K4_LEGACY_CLUSTER": "1", "KALI_MCP_FORCE_ENABLE_MODULES": "multi_agent", "OPENAI_API_KEY": "sk-..." },
      "enabled": true
    }
  }
}
```

**CLI live view** (no harness needed):

```bash
python3 agent_live.py "scan http://localhost:8000/ for web vulnerabilities" --no-cache
```

**LLM provider env vars**: `LLM_PROVIDER=anthropic|openai` (auto-detected from keys), `ANTHROPIC_API_KEY/MODEL/BASE_URL`, `OPENAI_API_KEY/MODEL/BASE_URL`. No key → deterministic fallback mode.

**KB rebuild**: `python scripts/build_kb_index.py` (idempotent, content-hash incremental).

### Architecture

```mermaid
flowchart TB
    U["User / Main agent"] -->|natural-language task| ORCH

    subgraph ORCH["OrchestratorAgent (main LLM decision-maker)"]
        OL["LLMBrain top-level planning loop"]
        OB["MissionBrief generation"]
        OV["Result review / recycle / re-plan"]
    end

    subgraph KB["Vectorized knowledge base"]
        IDX[("kb_vectors.db<br/>sqlite-vec")]
        RT["KnowledgeRetriever<br/>semantic top-k + metadata filter + BM25 fusion"]
        EMB["Embedding model<br/>BAAI/bge-small-zh-v1.5 local 512-dim"]
    end

    subgraph DAG["Attack DAG + ACO"]
        DAGS["DAGService<br/>single writer"]
        ACO["Ant Colony Optimization<br/>pheromone evaporation/deposit/route"]
        PHE[("attack-path pheromone table")]
    end

    subgraph AGENTS["17 LLM sub-agents"]
        A1["recon_agent"] -->|shared| LB["LLMAgentBase<br/>LLMBrain decision loop"]
        A2["web_vuln_agent"] -->|shared| LB
        A3["exploit_agent"] -->|shared| LB
        AX["...remaining 14"]
    end

    SUM["SummarizerAgent"]
    ES["EventStream<br/>SSE push"]
    BUS["EventBus<br/>tool.result / mission / dag / summary"]
    MESH["MeshMessageBus<br/>agent peer-to-peer"]
    TB["ToolBridge<br/>call_tool + catalog"]
    EX["executor / fastsec etc. real tools"]
    WS["WebSearch<br/>ddg/tavily tools"]

    ORCH -->|mission.created| BUS
    ORCH -->|retrieve| RT
    ORCH -->|read τ/η recommendation| DAGS
    BUS --> DAGS
    DAGS -->|dag.updated| ACO
    ACO -->|candidate edge scores| ORCH
    ACO -->|candidate edge scores| LB
    LB -->|call_tool| TB
    TB --> EX
    LB -->|tool.result| BUS
    LB -->|retrieve| RT
    TB -.register.-> WS
    BUS --> SUM
    MESH --> AGENTS
    SUM -->|summary.update| BUS
    SUM -->|SSE| ES
    ES --> U
    ORCH -->|mission.review| BUS
    DAGS -->|dag.updated| SUM
```

### Core Capabilities

| Capability | Description | Module |
|---|---|---|
| **LLM is the sole decision-maker** | Every "what next" conclusion comes from an LLM decision JSON (`call_tool / run_tool / done / retry`). DAG, ACO and the knowledge base only provide **context and scored recommendations** — they never trigger tools directly | `kali_mcp/core/llm_brain.py`, `kali_mcp/core/agent_coordinator.py` |
| **17 LLM-autonomous sub-agents** | Each extends `LLMAgentBase` (role prompt + tool surface + `llm_drive_mission` decision loop); deterministic regex parsers distill Finding evidence to prevent LLM fabrication | `kali_mcp/agents/llm_agent_base.py` |
| **Attack DAG + ACO** | Discoveries become DAG nodes; edges carry pheromone τ ∈ [0.05, 1]; `P(e) = τ^α·η^β` scores candidate edges. **ACO only recommends — the LLM decides** | `kali_mcp/reasoning/attack_dag.py`, `kali_mcp/reasoning/aco.py` |
| **SummarizerAgent** | sha1-fingerprint dedupe → three-layer false-positive filtering → severity sort → real-time SSE push | `kali_mcp/core/summarizer_agent.py` |
| **Vectorized knowledge base** | Local `BAAI/bge-small-zh-v1.5` embeddings (shipped) + `sqlite-vec` single-file store (`data/kb_vectors.db`, shipped) + BM25, RRF-fused; idempotent incremental index builds | `kali_mcp/reasoning/knowledge_retriever.py`, `scripts/build_kb_index.py` |
| **Live web search** | `web_search` / `web_fetch` as ordinary ToolBridge tools; backend `ddg` (free) / `tavily` | `kali_mcp/core/search_backends.py` |
| **fastsec engine** | Self-developed Go scanner replacing 25 external tools (gobuster/nikto/sqlmap/ffuf/nuclei/hydra/whatweb/...): dir / CMS / SQLi / XSS / brute (2.63M-pass dicts) / Kerberos / fingerprint / OSINT / hash crack / reverse-shell / SAM | `tools/fastsec/` |
| **Adaptive execution backend** | Auto-detected at startup: local subprocess (default) / SSH / Docker | `kali_mcp/core/backend.py` |

### The 17 LLM-Autonomous Sub-agents

| Group | Agents |
|---|---|
| **Information gathering** | `recon_agent`, `subdomain_agent`, `web_recon_agent` |
| **Vulnerability discovery** | `vuln_scanner_agent`, `web_vuln_agent`, `auth_agent`, `network_vuln_agent`, `vuln_verifier_agent` |
| **Exploitation** | `exploit_agent`, `privilege_agent`, `lateral_agent` |
| **Specialized** | `code_analyze_agent`, `code_audit_agent`, `crypto_agent`, `forensics_agent`, `pwn_agent`, `source_code_agent` |

### MCP Tool Surface (converged keep-set)

| Category | Tools |
|---|---|
| **KG/DAG capability** | `dag_apply` (DAGService.apply writes), `dag_recommend` (ACO top-k, recommend-only), `dag_status`, `kb_search` |
| **Evidence extraction** | `extract_findings` (deterministic parsers from the 17 Python agents) |
| **Trace wiping** | `wipe_traces` (task/session/global; target cleanup = templates only) |
| **Task board** | `start_task`, `task_status`, `run_surface_chain`, `verify_finding`, `task_create/claim/complete/renew/list`, `board_snapshot` |
| **fastsec** | `fastsec_scan` (dir/cms/inject/xss/brute/osint/fingerprint/crack/kerberos/template) |
| **Port/service** | `nmap_scan`, `rustscan_scan`, `naabu_scan`, `comprehensive_recon`, `server_health` |
| **Credential / AD** | `john_crack`, `hashcat_crack`, `kerbrute_attack`, `GetNPUsers_scan`, `GetUserSPNs_scan`, `nxc_attack`, `evil_winrm_attack`, `secretsdump_scan`, `psexec_attack`, `smbexec_attack` |
| **Exploit / PWN** | `metasploit_run`, `quick_pwn_check` |
| **Session / workflow** | `start_attack_session`, `list_attack_sessions`, `wf_init/transition/record_result/record_issue/status/pack_turn` |
| **Async scan** | `scan_start/collect/wait/jobs` |
| **Meta fallback** | `kali_run` (any registry tool by name) |

> Orchestration (the two pure-orchestration tools) was removed from the MCP surface — orchestration now lives in the harness-side `coordinator` subagent (see `.claude/agents/coordinator.md`).

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `KALI_MCP_TOOL_PROFILE` | `harness` | `strict` / `compliance` / `full` / `harness` |
| `KALI_MCP_FORCE_ENABLE_MODULES` | — | Force-enable modules, e.g. `multi_agent` |
| `K4_LEGACY_CLUSTER` | — | `1` initializes the 17-agent cluster (LLM orchestrator entry) |
| `K4_LEGACY_PLAYBOOKS` | — | `1` registers legacy playbook tools |
| `KALI_MCP_WORKSPACE` | `workspace/` | Task workspace (evidence/reports) |
| `KALI_MCP_ENGAGEMENT_JSON/FILE` | — | Authorization scope declaration |
| `LLM_PROVIDER` | auto | `anthropic` / `openai` |
| `ANTHROPIC_API_KEY/MODEL/BASE_URL` | — | Claude provider |
| `OPENAI_API_KEY/MODEL/BASE_URL` | — | OpenAI provider |
| `WEB_SEARCH_BACKEND` | `ddg` | `ddg` / `tavily` |
| `TAVILY_API_KEY` | — | tavily key |

### Compliance

For **authorized** penetration testing, CTF competitions, security research and defensive assessments only. Declare your engagement scope (`set_engagement_context` or `KALI_MCP_ENGAGEMENT_JSON/FILE`) before use. Unauthorized scanning or destructive operations are strictly prohibited.

### License

MIT — see [LICENSE](LICENSE).
