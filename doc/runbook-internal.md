# 内部运行约定（P0/M2 + Phase2 余项 + Phase3 Markdown 报告已落地）

## 任务目录

默认根目录（`KALI_MCP_WORKSPACE` 可覆盖）：

```text
workspace/tasks/{task_id}/
  graph/graph.json
  evidence/
  logs/actions.jsonl
  findings/findings.json
  handoff/handoff.json
  handoff/progress.md
  report/summary.json
```

## 主脑 MCP 能力（harness）

- `start_task` / `get_task`
- `graph_upsert` / `graph_query` / `graph_next_actions` / `graph_mark_dead`
- `run_playbook`（`web_surface` | `api_surface` | `auth_surface` | `svc_surface`：`quick` | `standard` | `thorough`）
- `run_surface_chain`（`start_task` 后按需串联四表面剧本；**不是** `run_goal` 大包）
- `verify_finding`
- `export_task_summary`（JSON `report/summary.json` + Markdown `report/report.md`；可选 `format=docx|all` → `report/report.docx`，需 `python-docx`；含 ATT&CK coverage + observer；主表仅 verified）
- `compile_task_handoff` / `continue_from_handoff`
- `observe_task`（Observer 旁路：重复扫/空结果/WAF 启发式建议；默认不硬拦，可选 `auto_mark_dead`）
- `propose_insights`（洞察支路：只产 `source=insight` 的 candidate，须 `verify_finding`；**永不直连执行器**）
- `attack_coverage`（ATT&CK technique 标签覆盖统计，报告附录用）
- `task_timeline`（只读 `logs/actions.jsonl` 时间线：count / duration_ms_sum / by_tool；不新增写入通路）

## 环境变量

| 变量 | 作用 |
|------|------|
| `KALI_MCP_WORKSPACE` | 任务根目录 |
| `KALI_MCP_HTTPX_BIN` | ProjectDiscovery httpx 绝对路径（Kali 示例：`/home/zss/go/bin/httpx`） |
| `KALI_MCP_TOOL_PROFILE` | **`harness`（默认，主脑瘦面）** / `strict` / `compliance` / `full` |
| `KALI_MCP_TOOL_TIMEOUT_HTTPX` | 执行器 httpx 超时秒数（默认 60） |
| `KALI_MCP_TOOL_TIMEOUT_NUCLEI` | 执行器 nuclei 超时秒数（默认 180） |
| `KALI_MCP_INSIGHT_ENABLED` | 洞察支路开关（默认 true） |
| `KALI_MCP_INSIGHT_MAX_PER_PHASE` | 每阶段最多假设条数（默认 5） |
| `KALI_MCP_INSIGHT_ONLY_WHEN_STUCK` | 仅卡死/空 next_actions 时产假设（默认 true；`force=true` 可覆盖） |
| `KALI_MCP_MULTI_MAX_TARGETS` | `run_surface_chain_multi` 单次目标数上限（默认 **20**，硬顶 50；超限直接 `ok=false`） |
| `KALI_MCP_MULTI_MAX_WORKERS` | multi 并行 worker 上限（默认 **4**，硬顶 8；与 `max_workers` 参数取 min） |
| `KALI_MCP_CHAIN_TIMEOUT_S` | `run_surface_chain` wall-clock 熔断（秒；默认 **0** = 不限；>0 超时则 `aborted=wall_clock_timeout`，status 直接反映） |
| engagement 强制 | **默认不强制**（内部全自动口径） |

## 推荐调用

1. `start_task(targets="http://靶", depth="standard")`
2. 单剧本：`run_playbook(task_id=..., playbook="web_surface", target=..., depth="standard")`  
   或串联：`run_surface_chain(task_id=..., target=..., depth="mixed")`  
   - 默认顺序：`web_surface(standard)` → `api_surface(quick)` → `auth_surface(quick)` → `svc_surface(quick)`  
   - `depth=mixed` 保留上表混合深度；`quick|standard|thorough` 则四步同深度  
   - `playbooks` 可逗号/空格指定子集或重排；`stop_on_error=true` 可遇错中止  
   - 产出：`report/.../chain_summary.json` + handoff；CLI 等价：`python utils/lab/run_chain.py <url> <task_id>`
3. 看 `findings` / `auto_verified` / `report_path` / `handoff_json`
4. 中断后续跑：`continue_from_handoff(task_id=...)`

## Kali 真机验收（记录）

- 主机：`192.168.157.8`，工程：`~/MCP-v2/Kali-Security-MCP-main`
- 研究 lab：`http://127.0.0.1:18081/`（`utils/lab/`，`bash start_lab.sh` / `stop_lab.sh`）；**主验收靶以 18081 为准**（18080 旧 SimpleHTTP 勿当主靶）
- 单测：`tests/test_p0_harness.py`
  - 本地 Windows `py -3`：以当日 `pytest tests/test_p0_harness.py -q` 为准（含 action_log schema / task_timeline / chain duration）
  - Kali venv Python 3.13：以同步后 `pytest` 为准（docx 需 `python-docx`；死代理时用 `utils/wheels` 离线装）
- 剧本：`web_surface` | `api_surface` | `auth_surface` | `svc_surface`（无 `run_goal`）
- MCP 默认 profile：`harness`；httpx：`-no-stdin` + 执行器 `stdin=DEVNULL`
- **终端态 handoff 修复**（`continue_from_handoff`）：
  - 空 next / 只读检查 / 仅 insight 残队列时，**不**把 `chain_done` 改成 `resumed`
  - 续跑规划读 live graph 时 `include_insights=True`（否则 residual 被默认滤空）
  - chain 收尾 `continue` 用 `update_status=False`；成功后**清空** next_checks 并盖 `last_tool`，防默认 recon 回流
- **`propose_insights` 默认 `enqueue_verify=False`**：只写 candidate findings，不往图上塞 `insight_verify:*`；需要 sticky 队列时 MCP 显式 `enqueue_verify=true`
- **真机任务 `lab_no_enqueue_1`**（`run_surface_chain` depth=`mixed` @ 18081）：
  - `ok: true`；`chain_done` + `REPORT`；**6 verified**；`report_md` 存在
  - `next_count_with_insights=0`；`continue` 后仍 `chain_done`/`REPORT`；`mutated_meta=false`
  - insights：`created_count=5`、`skipped=false`（候选在 findings，不进 next 队列）
  - Observer 无 `observer_analyze` 自引用
  - 产物：`workspace/tasks/lab_no_enqueue_1/`
- 历史：`lab_clean_queue_1`、`lab_reg_20260727` 等仍可对照；**禁止**用 `rpt_probe` 冒充验收
- Windows 本机曾出现的 `rpt_probe` / `chain_clear_dbg` / `dbg_next` 已移至 `workspace/archive_non_delivery/isolated_20260727/`（非交付；真验收用 `lab_reg_*` 或 `doc/lab-acceptance/*.json`）
- **e2e 验收脚本**：`python utils/lab/e2e_checklist.py --ensure-lab --run-chain --task-id lab_reg_YYYYMMDD`（可选 `--pytest`；JSON 落 `doc/lab-acceptance/`；禁止 `rpt_probe`）
- 主机运维记录（非产品代码）：sqlmap `1.10.6` 见 `doc/lab-acceptance/sqlmap_upgrade_20260728.json`；nodesource SHA1 源已禁用见 `doc/lab-acceptance/nodesource_apt_fix_20260728.json`；sqlmap 后真机复验见 `doc/lab-acceptance/lab_reg_20260728_post_sqlmap_acceptance.json`

- Phase2/3 能力：`observe_task`、`propose_insights`、`attack_coverage`、markdown 报告、YAML recipes、result cache TTL、`task_status`、`run_surface_chain_multi`

## 口径

- 不强制 engagement
- 操作记 what/when（JSONL）
- 证据原样落盘，报告默认不脱敏
- 洞察只产 candidate，须 verify；Observer 默认只建议不拦截

## 自检

```bash
cd Kali-Security-MCP-main
. .venv/bin/activate   # 若有
export KALI_MCP_HTTPX_BIN=/home/zss/go/bin/httpx   # Kali
python -m pytest tests/test_p0_harness.py -q
# Windows 开发机：
# py -3 -m pytest tests/test_p0_harness.py -q
```

## 已知后续（未做，小步）

- Kali/本地单测条数差时：以两侧 `pytest` 输出为准，同步后再对账（有代码变更后两侧再对账一次）
- 已做（勿再当缺口）：YAML recipes、result cache TTL、chain 自动 observer/insights/report_md、`status_check` harness 面板、**可选 docx 报告**、**insight 跨域映射优先读 `autonomous_engine.cross_domain_mappings`**（`get_cross_domain_map` / `mapping_source`；`drive_executor` 恒 false；引擎不可用时回退内联表）、**`run_surface_chain_multi(parallel=True)`**（分 task_id 并行 + `elapsed_sec`；默认仍串行；实测见 `doc/lab-acceptance/multi_bench_*.json` / `utils/lab/run_multi_bench.py`）、**multi 配额**（`KALI_MCP_MULTI_MAX_TARGETS` / `KALI_MCP_MULTI_MAX_WORKERS`，返回体含 `quota`）、**action_log 事件 schema + chain 步进/结束/export 的 `duration_ms` + 只读 `task_timeline`**（`ACTION_EVENT_FIELDS`；不另起 telemetry 中台）、**报告/status_check 展示 `duration_ms` / `duration_ms_sum`**、**`status_check.probe_tool_versions()` + recipe `notes/min_version_note`（nuclei 模板对齐 `-s/-rl/-timeout`）**
- 工具版本真源：本机/Kali 上 `python status_check.py` 第 5 节；`doc/progress-snapshot-20260728.md` 记录一次 Kali 探针。**二进制版本 ≠ `tools_recipes/*.yaml` mtime**
- 仍开放（非阻断）：工作区 git baseline（需负责人点名）；根目录杂项归档范围；Phase4 余项若再扩「任务级 wall-clock 超时熔断」需单独产品确认
