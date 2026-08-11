# 渗透任务报告 — `e2e-final-enh`

- **导出时间**: 2026-08-11T05:30:09+00:00
- **任务状态**: playbook_done
- **阶段**: FINGERPRINT
- **深度**: quick
- **目标**: `http://175.27.191.147:4180/`
- **工作区**: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh`

> 口径：报告主表仅含 **verified**；证据与复现命令默认**不脱敏**（真值）。

## 1. 摘要

- 图节点: **11** / 边: **4** / dead: 0
- verified findings: **5**
- candidate findings: 3
- other (fp/blocked/...): 1
- action log 条数（最近窗口）: 45
- duration_ms_sum: **329359.631**（known=37）
- Observer 重复建议: 1

## 2. Verified Findings（主表）

### 1. api_endpoint:http://175.27.191.147:4180/swagger

- **finding_id**: `df466d3a88df`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052944+0000_api_probe__swagger.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052945+0000_verify_df466d3a88df.txt`

### 2. api_endpoint:http://175.27.191.147:4180/swagger-ui

- **finding_id**: `d3d59363e23c`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052944+0000_api_probe__swagger-ui.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052945+0000_verify_d3d59363e23c.txt`

### 3. api_endpoint:http://175.27.191.147:4180/swagger-ui.html

- **finding_id**: `156697c2c184`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052944+0000_api_probe__swagger-ui.html.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052945+0000_verify_156697c2c184.txt`

### 4. api_endpoint:http://175.27.191.147:4180/openapi.json

- **finding_id**: `e87e54f4f513`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052945+0000_api_probe__openapi.json.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052945+0000_verify_e87e54f4f513.txt`

### 5. api_endpoint:http://175.27.191.147:4180/v2/api-docs

- **finding_id**: `339d1607c281`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052945+0000_api_probe__v2_api-docs.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052945+0000_verify_339d1607c281.txt`

## 3. 执行时间线（action_log）

- duration_ms_sum: **329359.631** / known events: 37

| # | ts | phase | tool | target | exit | duration_ms | source | evidence |
|---|----|-------|------|--------|------|-------------|--------|----------|
| 1 | 2026-08-11T05:28:04+00:00 | RECON | run_surface_chain | http://175.27.191.147:4180/ |  |  | harness |  |
| 2 | 2026-08-11T05:28:06+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1550.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 3 | 2026-08-11T05:28:06+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 1578.95 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 4 | 2026-08-11T05:28:09+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3750.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 5 | 2026-08-11T05:28:09+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 3763.96 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 6 | 2026-08-11T05:29:41+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 90880.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 7 | 2026-08-11T05:29:41+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 91748.95 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 8 | 2026-08-11T05:29:41+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 9 | 2026-08-11T05:29:41+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 97122.284 | harness |  |
| 10 | 2026-08-11T05:29:44+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api | 7 | 2435.71 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 11 | 2026-08-11T05:29:44+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v1 | 0 | 123.27 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 12 | 2026-08-11T05:29:44+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v2 | 0 | 136.54 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 13 | 2026-08-11T05:29:44+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger | 0 | 145.38 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 14 | 2026-08-11T05:29:44+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui | 0 | 121.45 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 15 | 2026-08-11T05:29:44+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui.html | 0 | 124.16 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 16 | 2026-08-11T05:29:45+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/openapi.json | 0 | 132.43 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 17 | 2026-08-11T05:29:45+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/v2/api-docs | 0 | 133.64 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 18 | 2026-08-11T05:29:45+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger | 0 | 135.05 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 19 | 2026-08-11T05:29:45+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui | 0 | 137.27 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 20 | 2026-08-11T05:29:45+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui.html | 0 | 131.95 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 21 | 2026-08-11T05:29:45+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/openapi.json | 0 | 145.73 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 22 | 2026-08-11T05:29:45+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/v2/api-docs | 0 | 136.42 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 23 | 2026-08-11T05:29:45+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 24 | 2026-08-11T05:29:45+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 4186.814 | harness |  |
| 25 | 2026-08-11T05:29:46+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/login | 0 | 131.26 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 26 | 2026-08-11T05:29:46+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/admin/login | 0 | 129.08 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 27 | 2026-08-11T05:29:46+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/user/login | 0 | 125.18 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 28 | 2026-08-11T05:29:46+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/signin | 0 | 141.1 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 29 | 2026-08-11T05:29:46+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/sign-in | 0 | 129.53 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 30 | 2026-08-11T05:29:46+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/auth/login | 0 | 139.57 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 31 | 2026-08-11T05:29:46+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/account/login | 0 | 132.89 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 32 | 2026-08-11T05:29:47+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/wp-login.php | 0 | 127.06 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 33 | 2026-08-11T05:29:47+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 34 | 2026-08-11T05:29:47+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 1119.722 | harness |  |
| 35 | 2026-08-11T05:29:50+00:00 | RECON | nmap | 175.27.191.147 | 0 | 3160.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 36 | 2026-08-11T05:29:50+00:00 | RECON | nmap | 175.27.191.147 | 0 | 3176.72 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 37 | 2026-08-11T05:29:50+00:00 | VERIFY | verify_finding | 175.27.191.147:22 | 1 | 16.55 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 38 | 2026-08-11T05:29:50+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 39 | 2026-08-11T05:29:50+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 3230.98 | harness |  |
| 40 | 2026-08-11T05:29:54+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 41 | 2026-08-11T05:29:54+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 3915.457 | harness |  |
| 42 | 2026-08-11T05:30:09+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 43 | 2026-08-11T05:30:09+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 15042.645 | harness |  |
| 44 | 2026-08-11T05:30:09+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 45 | 2026-08-11T05:30:09+00:00 | FINGERPRINT | propose_insights |  | 0 | 21.929 | insight |  |

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

- **finding_id**: `495a01279d3d`
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

- **finding_id**: `58394aee6f7d`
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

- **finding_id**: `184fd7ffa099`
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

- **finding_id**: `87da77f92b8b`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052950+0000_svc_nmap.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\evidence\2026-08-11T052950+0000_verify_87da77f92b8b.txt`

## 7. Observer 建议（旁路，默认不拦截）

- same tool+target+args repeated 2 times; prefer skip/cache

## 8. Handoff / 续跑指针

- handoff_json: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\handoff\handoff.json`
- progress_md: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-final-enh\handoff\progress.md`

---

_generated by kali_mcp.core.report_export @ 2026-08-11T05:30:09+00:00_
