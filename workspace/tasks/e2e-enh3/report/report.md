# 渗透任务报告 — `e2e-enh3`

- **导出时间**: 2026-08-11T05:22:19+00:00
- **任务状态**: playbook_done
- **阶段**: FINGERPRINT
- **深度**: quick
- **目标**: `http://175.27.191.147:4180/`
- **工作区**: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3`

> 口径：报告主表仅含 **verified**；证据与复现命令默认**不脱敏**（真值）。

## 1. 摘要

- 图节点: **11** / 边: **4** / dead: 0
- verified findings: **5**
- candidate findings: 3
- other (fp/blocked/...): 1
- action log 条数（最近窗口）: 45
- duration_ms_sum: **337718.052**（known=37）
- Observer 重复建议: 1

## 2. Verified Findings（主表）

### 1. api_endpoint:http://175.27.191.147:4180/swagger

- **finding_id**: `c5e3047c45b1`
- **status**: verified
- **severity**: medium
- **target**: `http://175.27.191.147:4180/swagger`
- **source**: playbook
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sS --noproxy "*" -L "http://175.27.191.147:4180/swagger"
```
- **expected_signal**: `re:(?i)(api|json|swagger|openapi|graphql|health|status|ok|html|200|401|403)`
- **evidence_paths**:
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052146+0000_api_probe__swagger.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052147+0000_verify_c5e3047c45b1.txt`

### 2. api_endpoint:http://175.27.191.147:4180/swagger-ui

- **finding_id**: `4d4aaf69295c`
- **status**: verified
- **severity**: medium
- **target**: `http://175.27.191.147:4180/swagger-ui`
- **source**: playbook
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sS --noproxy "*" -L "http://175.27.191.147:4180/swagger-ui"
```
- **expected_signal**: `re:(?i)(api|json|swagger|openapi|graphql|health|status|ok|html|200|401|403)`
- **evidence_paths**:
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052146+0000_api_probe__swagger-ui.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052147+0000_verify_4d4aaf69295c.txt`

### 3. api_endpoint:http://175.27.191.147:4180/swagger-ui.html

- **finding_id**: `ad98c2a30c8a`
- **status**: verified
- **severity**: medium
- **target**: `http://175.27.191.147:4180/swagger-ui.html`
- **source**: playbook
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sS --noproxy "*" -L "http://175.27.191.147:4180/swagger-ui.html"
```
- **expected_signal**: `re:(?i)(api|json|swagger|openapi|graphql|health|status|ok|html|200|401|403)`
- **evidence_paths**:
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052146+0000_api_probe__swagger-ui.html.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052147+0000_verify_ad98c2a30c8a.txt`

### 4. api_endpoint:http://175.27.191.147:4180/openapi.json

- **finding_id**: `e2269d7c1dae`
- **status**: verified
- **severity**: medium
- **target**: `http://175.27.191.147:4180/openapi.json`
- **source**: playbook
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sS --noproxy "*" -L "http://175.27.191.147:4180/openapi.json"
```
- **expected_signal**: `re:(?i)(api|json|swagger|openapi|graphql|health|status|ok|html|200|401|403)`
- **evidence_paths**:
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052146+0000_api_probe__openapi.json.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052147+0000_verify_e2269d7c1dae.txt`

### 5. api_endpoint:http://175.27.191.147:4180/v2/api-docs

- **finding_id**: `4b22487f97ce`
- **status**: verified
- **severity**: medium
- **target**: `http://175.27.191.147:4180/v2/api-docs`
- **source**: playbook
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sS --noproxy "*" -L "http://175.27.191.147:4180/v2/api-docs"
```
- **expected_signal**: `re:(?i)(api|json|swagger|openapi|graphql|health|status|ok|html|200|401|403)`
- **evidence_paths**:
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052146+0000_api_probe__v2_api-docs.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052147+0000_verify_4b22487f97ce.txt`

## 3. 执行时间线（action_log）

- duration_ms_sum: **337718.052** / known events: 37

| # | ts | phase | tool | target | exit | duration_ms | source | evidence |
|---|----|-------|------|--------|------|-------------|--------|----------|
| 1 | 2026-08-11T05:20:06+00:00 | RECON | run_surface_chain | http://175.27.191.147:4180/ |  |  | harness |  |
| 2 | 2026-08-11T05:20:07+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1580.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 3 | 2026-08-11T05:20:07+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1604.1 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 4 | 2026-08-11T05:20:11+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3790.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 5 | 2026-08-11T05:20:11+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3801.56 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 6 | 2026-08-11T05:21:43+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 90890.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 7 | 2026-08-11T05:21:43+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 91770.94 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 8 | 2026-08-11T05:21:43+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 9 | 2026-08-11T05:21:43+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 97205.538 | harness |  |
| 10 | 2026-08-11T05:21:45+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api | 7 | 2424.95 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 11 | 2026-08-11T05:21:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v1 | 0 | 141.07 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 12 | 2026-08-11T05:21:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v2 | 0 | 120.06 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 13 | 2026-08-11T05:21:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger | 0 | 135.18 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 14 | 2026-08-11T05:21:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui | 0 | 146.97 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 15 | 2026-08-11T05:21:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui.html | 0 | 152.82 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 16 | 2026-08-11T05:21:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/openapi.json | 0 | 128.18 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 17 | 2026-08-11T05:21:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/v2/api-docs | 0 | 135.37 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 18 | 2026-08-11T05:21:47+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger | 0 | 129.17 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 19 | 2026-08-11T05:21:47+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui | 0 | 152.42 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 20 | 2026-08-11T05:21:47+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui.html | 0 | 128.96 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 21 | 2026-08-11T05:21:47+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/openapi.json | 0 | 134.9 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 22 | 2026-08-11T05:21:47+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/v2/api-docs | 0 | 136.62 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 23 | 2026-08-11T05:21:47+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 24 | 2026-08-11T05:21:47+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 4205.614 | harness |  |
| 25 | 2026-08-11T05:21:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/login | 0 | 143.08 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 26 | 2026-08-11T05:21:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/admin/login | 0 | 123.54 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 27 | 2026-08-11T05:21:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/user/login | 0 | 136.4 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 28 | 2026-08-11T05:21:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/signin | 0 | 126.73 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 29 | 2026-08-11T05:21:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/sign-in | 0 | 121.98 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 30 | 2026-08-11T05:21:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/auth/login | 0 | 126.29 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 31 | 2026-08-11T05:21:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/account/login | 0 | 130.15 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 32 | 2026-08-11T05:21:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/wp-login.php | 0 | 124.51 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 33 | 2026-08-11T05:21:48+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 34 | 2026-08-11T05:21:48+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 1092.566 | harness |  |
| 35 | 2026-08-11T05:21:51+00:00 | RECON | nmap | 175.27.191.147 | 0 | 3170.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 36 | 2026-08-11T05:21:51+00:00 | RECON | nmap | 175.27.191.147 | 0 | 3186.95 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 37 | 2026-08-11T05:21:52+00:00 | VERIFY | verify_finding | 175.27.191.147:22 | 1 | 18.08 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 38 | 2026-08-11T05:21:52+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 39 | 2026-08-11T05:21:52+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 3244.401 | harness |  |
| 40 | 2026-08-11T05:21:56+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 41 | 2026-08-11T05:21:56+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 4486.086 | harness |  |
| 42 | 2026-08-11T05:22:19+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 43 | 2026-08-11T05:22:19+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 22554.097 | harness |  |
| 44 | 2026-08-11T05:22:19+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 45 | 2026-08-11T05:22:19+00:00 | FINGERPRINT | propose_insights |  | 0 | 18.77 | insight |  |

## 4. ATT&CK 覆盖附录（标签层）

### 全部 findings

- labeled: 9 / total: 9 (ratio=1.0)
- techniques: T1046, T1078, T1595
- tactics_present: Discovery, Initial Access, Reconnaissance

### verified only

- labeled: 5 / total: 5
- techniques: T1595
- tactics_present: Reconnaissance

_ATT&CK is label-only; empty technique_ids preferred over wrong tags_

## 5. Candidate / 未证实假设（附录，不与主表混排）

### 1. insight_http_probe:http://175.27.191.147

- **finding_id**: `2482a98679f7`
- **status**: candidate
- **severity**: info
- **target**: `http://175.27.191.147`
- **source**: insight
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sk -o /dev/null -w "%{http_code}" "http://175.27.191.147/"
```
- **expected_signal**: `200`

### 2. insight_https_probe:https://175.27.191.147

- **finding_id**: `f009095adfd3`
- **status**: candidate
- **severity**: info
- **target**: `https://175.27.191.147`
- **source**: insight
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sk -o /dev/null -w "%{http_code}" "https://175.27.191.147/"
```
- **expected_signal**: `200`

### 3. insight_auth_surface:http://175.27.191.147:4180/login

- **finding_id**: `9e03b94696ed`
- **status**: candidate
- **severity**: info
- **target**: `http://175.27.191.147:4180/login`
- **source**: insight
- **technique_ids**: T1078

**复现命令（真值）**

```
curl -sk -o /dev/null -w "%{http_code}" "http://175.27.191.147:4180/login"
```
- **expected_signal**: `200`

## 6. 其他状态 findings（false_positive / blocked 等）

### 1. open_port:175.27.191.147:22/ssh

- **finding_id**: `3e7863f492f3`
- **status**: false_positive
- **severity**: info
- **target**: `175.27.191.147:22`
- **source**: playbook
- **technique_ids**: T1046

**复现命令（真值）**

```
nmap -sV -p 22 175.27.191.147
```
- **expected_signal**: `22`
- **evidence_paths**:
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052151+0000_svc_nmap.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\evidence\2026-08-11T052151+0000_verify_3e7863f492f3.txt`

## 7. Observer 建议（旁路，默认不拦截）

- same tool+target+args repeated 2 times; prefer skip/cache

## 8. Handoff / 续跑指针

- handoff_json: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\handoff\handoff.json`
- progress_md: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh3\handoff\progress.md`

---

_generated by kali_mcp.core.report_export @ 2026-08-11T05:22:19+00:00_
