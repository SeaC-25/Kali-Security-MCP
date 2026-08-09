# 进度快照 2026-07-28

## 单测

- 本地 Windows：`py -3 -m pytest tests/test_p0_harness.py -q` → **47 passed**（2026-07-28 对账）
- Kali `192.168.157.8` venv：同命令 → **47 passed**（同日对账；与 Windows 条数一致）

## 已完成（勿再当缺口）

- harness 主链路：graph / surfaces / chain / verify / handoff / observer / insights / report
- 可选 docx、`run_surface_chain_multi(parallel=True)`、action_log schema、`task_timeline`
- insight 跨域映射优先 `autonomous_engine`（`drive_executor=false`）
- 报告/status 展示 `duration_ms` / `duration_ms_sum`
- **工具版本清单**：`status_check.probe_tool_versions()`（PATH + version 探针）
- **recipe 元数据**：`notes` / `min_version_note`；nuclei 与 registry 对齐 `-s/-rl/-timeout`

## Kali 工具版本（2026-07-28 探针，仅该主机）

| 工具 | 探针结果 |
|------|----------|
| nmap | 7.99 |
| nuclei | Engine v3.4.10 |
| sqlmap | 1.10.6#stable（本轮已 apt 升级，见 lab-acceptance/sqlmap_upgrade_20260728.json） |
| ffuf | 2.1.0-dev |
| feroxbuster | 2.13.1 |
| nikto | 2.5.0 |
| whatweb | 0.6.2 |
| curl | 8.20.0 |
| httpx | Go 二进制路径 `/home/zss/go/bin/httpx`（需 `KALI_MCP_HTTPX_BIN`） |
| gobuster | 在 PATH；`version` 子命令因构建而异 |

**口径：** 二进制版本 ≠ YAML recipe 修改时间。recipe 是命令模板层；「老」的往往是模板过瘦，不是 Kali 包一定古董。

## 真机 lab

- 主靶仍：`http://127.0.0.1:18081/`
- 禁止 `rpt_probe` 作交付
- multi bench 证据：`doc/lab-acceptance/multi_bench_20260727_164731.json`（当次 wall time only）

## 本轮补完（同日）

- 真机 chain：`lab_reg_20260728` → `doc/lab-acceptance/lab_reg_20260728_acceptance.json`（6 verified，chain_done+REPORT，continue 幂等，insight 不 sticky）
- e2e 脚本：`utils/lab/e2e_checklist.py`（runbook 已挂一行）
- sqlmap：apt 升级 **已完成** `1.9.8-1` → `1.10.6-1`（`1.10.6#stable`）；见 `doc/lab-acceptance/sqlmap_upgrade_20260728.json`（主机运维，非产品 bug）
- pytest：Windows / Kali 均为 **47 passed**（sqlmap 包升级不要求改 recipe）
- **nodesource apt 告警**：已禁用坏源列表 → `nodesource.list.disabled-sha1-20260728`；`apt-get update` exit 0、输出无 nodesource；见 `doc/lab-acceptance/nodesource_apt_fix_20260728.json`（Node 仍可用 Volta v22.23.1）
- **sqlmap 后 e2e 复验**：`lab_reg_20260728_post_sqlmap` → `doc/lab-acceptance/lab_reg_20260728_post_sqlmap_acceptance.json`（四 surface ok、**6 verified**、chain_done+REPORT、continue 幂等、insight 不 sticky、`overall_ok=true`；`--pytest` 已跑）

## 已知后续（小步）

- 有 harness/代码变更时再跑两侧 pytest 对账（当前已 47=47）
- 若需从 nodesource 再装 Node 系统包：换官方新签名源，**不要** force-trust SHA1；坏源仍为 `nodesource.list.disabled-sha1-20260728`
