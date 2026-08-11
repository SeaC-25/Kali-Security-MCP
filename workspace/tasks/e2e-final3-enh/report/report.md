# 渗透任务报告 — `e2e-final3-enh`

- **导出时间**: 2026-08-11T05:35:51+00:00
- **任务状态**: playbook_done
- **阶段**: FINGERPRINT
- **深度**: quick
- **目标**: `http://175.27.191.147:4180/`
- **工作区**: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh`

> 口径：报告主表仅含 **verified**；证据与复现命令默认**不脱敏**（真值）。

## 1. 摘要

- 图节点: **9** / 边: **2** / dead: 0
- verified findings: **5**
- candidate findings: 3
- other (fp/blocked/...): 0
- action log 条数（最近窗口）: 41
- duration_ms_sum: **301546.358**（known=33）
- Observer 重复建议: 0

## 2. Verified Findings（主表）

### 1. api_endpoint:http://175.27.191.147:4180/swagger

- **finding_id**: `bc6fd2e8bf7f`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053533+0000_api_probe__swagger.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053534+0000_verify_bc6fd2e8bf7f.txt`

### 2. api_endpoint:http://175.27.191.147:4180/swagger-ui

- **finding_id**: `a8d6a53e7975`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053533+0000_api_probe__swagger-ui.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053534+0000_verify_a8d6a53e7975.txt`

### 3. api_endpoint:http://175.27.191.147:4180/swagger-ui.html

- **finding_id**: `ce7d431e1d59`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053534+0000_api_probe__swagger-ui.html.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053534+0000_verify_ce7d431e1d59.txt`

### 4. api_endpoint:http://175.27.191.147:4180/openapi.json

- **finding_id**: `c8b161d6c4e8`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053534+0000_api_probe__openapi.json.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053534+0000_verify_c8b161d6c4e8.txt`

### 5. api_endpoint:http://175.27.191.147:4180/v2/api-docs

- **finding_id**: `ad9fd53be3b0`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053534+0000_api_probe__v2_api-docs.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\evidence\2026-08-11T053535+0000_verify_ad9fd53be3b0.txt`

## 3. 执行时间线（action_log）

- duration_ms_sum: **301546.358** / known events: 33

| # | ts | phase | tool | target | exit | duration_ms | source | evidence |
|---|----|-------|------|--------|------|-------------|--------|----------|
| 1 | 2026-08-11T05:33:58+00:00 | RECON | run_surface_chain | http://175.27.191.147:4180/ |  |  | harness |  |
| 2 | 2026-08-11T05:33:58+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 0.5 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 3 | 2026-08-11T05:33:58+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 0.5 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 4 | 2026-08-11T05:35:30+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 90880.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 5 | 2026-08-11T05:35:30+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 92313.89 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 6 | 2026-08-11T05:35:30+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 7 | 2026-08-11T05:35:30+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 92352.803 | harness |  |
| 8 | 2026-08-11T05:35:33+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api | 7 | 2464.19 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 9 | 2026-08-11T05:35:33+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v1 | 0 | 127.68 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 10 | 2026-08-11T05:35:33+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v2 | 0 | 151.93 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 11 | 2026-08-11T05:35:33+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger | 0 | 137.08 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 12 | 2026-08-11T05:35:33+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui | 0 | 119.92 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 13 | 2026-08-11T05:35:34+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui.html | 0 | 125.75 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 14 | 2026-08-11T05:35:34+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/openapi.json | 0 | 123.86 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 15 | 2026-08-11T05:35:34+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/v2/api-docs | 0 | 125.99 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 16 | 2026-08-11T05:35:34+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger | 0 | 136.87 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 17 | 2026-08-11T05:35:34+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui | 0 | 134.77 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 18 | 2026-08-11T05:35:34+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui.html | 0 | 118.91 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 19 | 2026-08-11T05:35:34+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/openapi.json | 0 | 122.51 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 20 | 2026-08-11T05:35:35+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/v2/api-docs | 0 | 139.75 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 21 | 2026-08-11T05:35:35+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 22 | 2026-08-11T05:35:35+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 4173.215 | harness |  |
| 23 | 2026-08-11T05:35:35+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/login | 0 | 132.12 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 24 | 2026-08-11T05:35:35+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/admin/login | 0 | 132.31 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 25 | 2026-08-11T05:35:35+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/user/login | 0 | 129.22 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 26 | 2026-08-11T05:35:35+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/signin | 0 | 127.48 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 27 | 2026-08-11T05:35:35+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/sign-in | 0 | 128.06 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 28 | 2026-08-11T05:35:35+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/auth/login | 0 | 122.32 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 29 | 2026-08-11T05:35:36+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/account/login | 0 | 140.35 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 30 | 2026-08-11T05:35:36+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/wp-login.php | 0 | 134.23 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 31 | 2026-08-11T05:35:36+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 32 | 2026-08-11T05:35:36+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 1110.118 | harness |  |
| 33 | 2026-08-11T05:35:36+00:00 | RECON | nmap | 175.27.191.147 | 0 | 1.0 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 34 | 2026-08-11T05:35:36+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 35 | 2026-08-11T05:35:36+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 24.309 | harness |  |
| 36 | 2026-08-11T05:35:36+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 37 | 2026-08-11T05:35:36+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 2.561 | harness |  |
| 38 | 2026-08-11T05:35:51+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 39 | 2026-08-11T05:35:51+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 15592.682 | harness |  |
| 40 | 2026-08-11T05:35:51+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 41 | 2026-08-11T05:35:51+00:00 | FINGERPRINT | propose_insights |  | 0 | 19.48 | insight |  |

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

- **finding_id**: `6f8253d925f5`
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

- **finding_id**: `04c5933dd248`
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

- **finding_id**: `b75955fe6f5a`
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

- （无）

## 8. Handoff / 续跑指针

- handoff_json: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\handoff\handoff.json`
- progress_md: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final3-enh\handoff\progress.md`

---

_generated by kali_mcp.core.report_export @ 2026-08-11T05:35:51+00:00_
