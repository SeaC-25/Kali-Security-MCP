# 渗透任务报告 — `e2e-enh2`

- **导出时间**: 2026-08-11T05:19:32+00:00
- **任务状态**: playbook_done
- **阶段**: FINGERPRINT
- **深度**: quick
- **目标**: `http://175.27.191.147:4180/`
- **工作区**: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2`

> 口径：报告主表仅含 **verified**；证据与复现命令默认**不脱敏**（真值）。

## 1. 摘要

- 图节点: **11** / 边: **4** / dead: 0
- verified findings: **5**
- candidate findings: 3
- other (fp/blocked/...): 1
- action log 条数（最近窗口）: 45
- duration_ms_sum: **327777.262**（known=37）
- Observer 重复建议: 1

## 2. Verified Findings（主表）

### 1. api_endpoint:http://175.27.191.147:4180/swagger

- **finding_id**: `505288125470`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051910+0000_api_probe__swagger.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051911+0000_verify_505288125470.txt`

### 2. api_endpoint:http://175.27.191.147:4180/swagger-ui

- **finding_id**: `7a8090fce677`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051910+0000_api_probe__swagger-ui.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051911+0000_verify_7a8090fce677.txt`

### 3. api_endpoint:http://175.27.191.147:4180/swagger-ui.html

- **finding_id**: `552df4e2364f`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051910+0000_api_probe__swagger-ui.html.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051911+0000_verify_552df4e2364f.txt`

### 4. api_endpoint:http://175.27.191.147:4180/openapi.json

- **finding_id**: `c732dde0ad21`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051911+0000_api_probe__openapi.json.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051911+0000_verify_c732dde0ad21.txt`

### 5. api_endpoint:http://175.27.191.147:4180/v2/api-docs

- **finding_id**: `aeca5beee657`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051911+0000_api_probe__v2_api-docs.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051911+0000_verify_aeca5beee657.txt`

## 3. 执行时间线（action_log）

- duration_ms_sum: **327777.262** / known events: 37

| # | ts | phase | tool | target | exit | duration_ms | source | evidence |
|---|----|-------|------|--------|------|-------------|--------|----------|
| 1 | 2026-08-11T05:17:30+00:00 | RECON | run_surface_chain | http://175.27.191.147:4180/ |  |  | harness |  |
| 2 | 2026-08-11T05:17:32+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1600.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 3 | 2026-08-11T05:17:32+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1623.92 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 4 | 2026-08-11T05:17:35+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3950.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 5 | 2026-08-11T05:17:35+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3965.19 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 6 | 2026-08-11T05:19:07+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 90890.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 7 | 2026-08-11T05:19:07+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 91776.92 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 8 | 2026-08-11T05:19:07+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 9 | 2026-08-11T05:19:07+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 97396.167 | harness |  |
| 10 | 2026-08-11T05:19:10+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api | 7 | 2446.01 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 11 | 2026-08-11T05:19:10+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v1 | 0 | 115.53 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 12 | 2026-08-11T05:19:10+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v2 | 0 | 124.99 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 13 | 2026-08-11T05:19:10+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger | 0 | 126.81 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 14 | 2026-08-11T05:19:10+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui | 0 | 136.86 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 15 | 2026-08-11T05:19:10+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui.html | 0 | 118.94 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 16 | 2026-08-11T05:19:11+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/openapi.json | 0 | 135.46 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 17 | 2026-08-11T05:19:11+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/v2/api-docs | 0 | 128.74 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 18 | 2026-08-11T05:19:11+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger | 0 | 124.5 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 19 | 2026-08-11T05:19:11+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui | 0 | 131.11 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 20 | 2026-08-11T05:19:11+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui.html | 0 | 118.08 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 21 | 2026-08-11T05:19:11+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/openapi.json | 0 | 133.47 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 22 | 2026-08-11T05:19:11+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/v2/api-docs | 0 | 138.93 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 23 | 2026-08-11T05:19:11+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 24 | 2026-08-11T05:19:11+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 4120.409 | harness |  |
| 25 | 2026-08-11T05:19:12+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/login | 0 | 142.68 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 26 | 2026-08-11T05:19:12+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/admin/login | 0 | 122.79 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 27 | 2026-08-11T05:19:12+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/user/login | 0 | 120.4 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 28 | 2026-08-11T05:19:12+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/signin | 0 | 124.85 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 29 | 2026-08-11T05:19:12+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/sign-in | 0 | 123.62 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 30 | 2026-08-11T05:19:12+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/auth/login | 0 | 159.4 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 31 | 2026-08-11T05:19:12+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/account/login | 0 | 141.96 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 32 | 2026-08-11T05:19:13+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/wp-login.php | 0 | 125.61 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 33 | 2026-08-11T05:19:13+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 34 | 2026-08-11T05:19:13+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 1124.86 | harness |  |
| 35 | 2026-08-11T05:19:16+00:00 | RECON | nmap | 175.27.191.147 | 0 | 3290.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 36 | 2026-08-11T05:19:16+00:00 | RECON | nmap | 175.27.191.147 | 0 | 3301.26 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 37 | 2026-08-11T05:19:16+00:00 | VERIFY | verify_finding | 175.27.191.147:22 | 1 | 17.73 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 38 | 2026-08-11T05:19:16+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 39 | 2026-08-11T05:19:16+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 3356.758 | harness |  |
| 40 | 2026-08-11T05:19:16+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 41 | 2026-08-11T05:19:16+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 0.014 | harness |  |
| 42 | 2026-08-11T05:19:32+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 43 | 2026-08-11T05:19:32+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 16303.681 | harness |  |
| 44 | 2026-08-11T05:19:32+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 45 | 2026-08-11T05:19:32+00:00 | FINGERPRINT | propose_insights |  | 0 | 19.613 | insight |  |

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

- **finding_id**: `4a83ef0b9143`
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

- **finding_id**: `e047e2f7bbcc`
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

- **finding_id**: `417998c58f87`
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

- **finding_id**: `ada5ac202c82`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051916+0000_svc_nmap.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\evidence\2026-08-11T051916+0000_verify_ada5ac202c82.txt`

## 7. Observer 建议（旁路，默认不拦截）

- same tool+target+args repeated 2 times; prefer skip/cache

## 8. Handoff / 续跑指针

- handoff_json: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\handoff\handoff.json`
- progress_md: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh2\handoff\progress.md`

---

_generated by kali_mcp.core.report_export @ 2026-08-11T05:19:32+00:00_
