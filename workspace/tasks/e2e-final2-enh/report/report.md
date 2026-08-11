# 渗透任务报告 — `e2e-final2-enh`

- **导出时间**: 2026-08-11T05:33:12+00:00
- **任务状态**: playbook_done
- **阶段**: FINGERPRINT
- **深度**: quick
- **目标**: `http://175.27.191.147:4180/`
- **工作区**: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh`

> 口径：报告主表仅含 **verified**；证据与复现命令默认**不脱敏**（真值）。

## 1. 摘要

- 图节点: **9** / 边: **2** / dead: 0
- verified findings: **5**
- candidate findings: 3
- other (fp/blocked/...): 0
- action log 条数（最近窗口）: 44
- duration_ms_sum: **333134.217**（known=36）
- Observer 重复建议: 1

## 2. Verified Findings（主表）

### 1. api_endpoint:http://175.27.191.147:4180/swagger

- **finding_id**: `77583c4d5149`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053245+0000_api_probe__swagger.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053246+0000_verify_77583c4d5149.txt`

### 2. api_endpoint:http://175.27.191.147:4180/swagger-ui

- **finding_id**: `a2a9bfb9b8f6`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053246+0000_api_probe__swagger-ui.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053246+0000_verify_a2a9bfb9b8f6.txt`

### 3. api_endpoint:http://175.27.191.147:4180/swagger-ui.html

- **finding_id**: `131f5c5a93ca`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053246+0000_api_probe__swagger-ui.html.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053246+0000_verify_131f5c5a93ca.txt`

### 4. api_endpoint:http://175.27.191.147:4180/openapi.json

- **finding_id**: `033469767ad5`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053246+0000_api_probe__openapi.json.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053247+0000_verify_033469767ad5.txt`

### 5. api_endpoint:http://175.27.191.147:4180/v2/api-docs

- **finding_id**: `33188808a62d`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053246+0000_api_probe__v2_api-docs.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\evidence\2026-08-11T053247+0000_verify_33188808a62d.txt`

## 3. 执行时间线（action_log）

- duration_ms_sum: **333134.217** / known events: 36

| # | ts | phase | tool | target | exit | duration_ms | source | evidence |
|---|----|-------|------|--------|------|-------------|--------|----------|
| 1 | 2026-08-11T05:31:05+00:00 | RECON | run_surface_chain | http://175.27.191.147:4180/ |  |  | harness |  |
| 2 | 2026-08-11T05:31:07+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1550.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 3 | 2026-08-11T05:31:07+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1579.91 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 4 | 2026-08-11T05:31:11+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3850.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 5 | 2026-08-11T05:31:11+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3866.11 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 6 | 2026-08-11T05:32:43+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 90880.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 7 | 2026-08-11T05:32:43+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 91742.67 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 8 | 2026-08-11T05:32:43+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 9 | 2026-08-11T05:32:43+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 97218.174 | harness |  |
| 10 | 2026-08-11T05:32:45+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api | 7 | 2413.37 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 11 | 2026-08-11T05:32:45+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v1 | 0 | 126.57 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 12 | 2026-08-11T05:32:45+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v2 | 0 | 131.43 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 13 | 2026-08-11T05:32:45+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger | 0 | 145.16 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 14 | 2026-08-11T05:32:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui | 0 | 136.77 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 15 | 2026-08-11T05:32:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui.html | 0 | 148.62 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 16 | 2026-08-11T05:32:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/openapi.json | 0 | 124.56 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 17 | 2026-08-11T05:32:46+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/v2/api-docs | 0 | 130.04 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 18 | 2026-08-11T05:32:46+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger | 0 | 130.94 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 19 | 2026-08-11T05:32:46+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui | 0 | 131.93 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 20 | 2026-08-11T05:32:46+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui.html | 0 | 128.4 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 21 | 2026-08-11T05:32:47+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/openapi.json | 0 | 122.5 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 22 | 2026-08-11T05:32:47+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/v2/api-docs | 0 | 119.75 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 23 | 2026-08-11T05:32:47+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 24 | 2026-08-11T05:32:47+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 4132.349 | harness |  |
| 25 | 2026-08-11T05:32:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/login | 0 | 126.28 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 26 | 2026-08-11T05:32:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/admin/login | 0 | 126.11 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 27 | 2026-08-11T05:32:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/user/login | 0 | 124.34 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 28 | 2026-08-11T05:32:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/signin | 0 | 125.39 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 29 | 2026-08-11T05:32:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/sign-in | 0 | 126.68 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 30 | 2026-08-11T05:32:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/auth/login | 0 | 123.6 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 31 | 2026-08-11T05:32:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/account/login | 0 | 132.47 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 32 | 2026-08-11T05:32:48+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/wp-login.php | 0 | 117.56 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 33 | 2026-08-11T05:32:48+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 34 | 2026-08-11T05:32:48+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 1068.985 | harness |  |
| 35 | 2026-08-11T05:32:52+00:00 | RECON | nmap | 175.27.191.147 | 0 | 4070.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 36 | 2026-08-11T05:32:52+00:00 | RECON | nmap | 175.27.191.147 | 0 | 4081.11 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 37 | 2026-08-11T05:32:52+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 38 | 2026-08-11T05:32:52+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 4103.29 | harness |  |
| 39 | 2026-08-11T05:32:56+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 40 | 2026-08-11T05:32:56+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 4069.414 | harness |  |
| 41 | 2026-08-11T05:33:12+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 42 | 2026-08-11T05:33:12+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 15908.772 | harness |  |
| 43 | 2026-08-11T05:33:12+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 44 | 2026-08-11T05:33:12+00:00 | FINGERPRINT | propose_insights |  | 0 | 20.963 | insight |  |

## 4. ATT&CK 覆盖附录（标签层）

### 全部 findings

- labeled: 8 / total: 8 (ratio=1.0)
- techniques: T1078, T1190, T1595
- tactics_present: Initial Access, Reconnaissance

### verified only

- labeled: 5 / total: 5
- techniques: T1595
- tactics_present: Reconnaissance

_ATT&CK is label-only; empty technique_ids preferred over wrong tags_

## 5. Candidate / 未证实假设（附录，不与主表混排）

### 1. insight_auth_surface:http://175.27.191.147:4180/login

- **finding_id**: `3664cdb8bb94`
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

### 2. insight_api_health:http://175.27.191.147:4180/api/health

- **finding_id**: `5916f09080a1`
- **status**: candidate
- **severity**: info
- **target**: `http://175.27.191.147:4180/api/health`
- **source**: insight
- **technique_ids**: T1595

**复现命令（真值）**

```
curl -sk "http://175.27.191.147:4180/api/health"
```
- **expected_signal**: `ok`

### 3. insight_admin_path:http://175.27.191.147:4180/admin

- **finding_id**: `6f850ebd3bbd`
- **status**: candidate
- **severity**: low
- **target**: `http://175.27.191.147:4180/admin`
- **source**: insight
- **technique_ids**: T1190

**复现命令（真值）**

```
curl -sk -o /dev/null -w "%{http_code}" "http://175.27.191.147:4180/admin"
```
- **expected_signal**: `200`

## 7. Observer 建议（旁路，默认不拦截）

- same tool+target+args repeated 2 times; prefer skip/cache

## 8. Handoff / 续跑指针

- handoff_json: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\handoff\handoff.json`
- progress_md: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final2-enh\handoff\progress.md`

---

_generated by kali_mcp.core.report_export @ 2026-08-11T05:33:12+00:00_
