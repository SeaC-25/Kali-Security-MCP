# 渗透任务报告 — `e2e-enh4`

- **导出时间**: 2026-08-11T05:24:37+00:00
- **任务状态**: playbook_done
- **阶段**: FINGERPRINT
- **深度**: quick
- **目标**: `http://175.27.191.147:4180/`
- **工作区**: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4`

> 口径：报告主表仅含 **verified**；证据与复现命令默认**不脱敏**（真值）。

## 1. 摘要

- 图节点: **11** / 边: **4** / dead: 0
- verified findings: **5**
- candidate findings: 3
- other (fp/blocked/...): 1
- action log 条数（最近窗口）: 42
- duration_ms_sum: **302665.742**（known=34）
- Observer 重复建议: 0

## 2. Verified Findings（主表）

### 1. api_endpoint:http://175.27.191.147:4180/swagger

- **finding_id**: `e061963e35d2`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052418+0000_api_probe__swagger.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052419+0000_verify_e061963e35d2.txt`

### 2. api_endpoint:http://175.27.191.147:4180/swagger-ui

- **finding_id**: `a1859672621c`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052418+0000_api_probe__swagger-ui.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052419+0000_verify_a1859672621c.txt`

### 3. api_endpoint:http://175.27.191.147:4180/swagger-ui.html

- **finding_id**: `c1896c811b9c`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052418+0000_api_probe__swagger-ui.html.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052419+0000_verify_c1896c811b9c.txt`

### 4. api_endpoint:http://175.27.191.147:4180/openapi.json

- **finding_id**: `043e5364e33c`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052419+0000_api_probe__openapi.json.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052419+0000_verify_043e5364e33c.txt`

### 5. api_endpoint:http://175.27.191.147:4180/v2/api-docs

- **finding_id**: `6d3e4ba1fee3`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052419+0000_api_probe__v2_api-docs.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052419+0000_verify_6d3e4ba1fee3.txt`

## 3. 执行时间线（action_log）

- duration_ms_sum: **302665.742** / known events: 34

| # | ts | phase | tool | target | exit | duration_ms | source | evidence |
|---|----|-------|------|--------|------|-------------|--------|----------|
| 1 | 2026-08-11T05:22:43+00:00 | RECON | run_surface_chain | http://175.27.191.147:4180/ |  |  | harness |  |
| 2 | 2026-08-11T05:22:43+00:00 | RECON | curl | http://175.27.191.147:4180/ | 0 | 0.0 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 3 | 2026-08-11T05:22:43+00:00 | FINGERPRINT | whatweb | http://175.27.191.147:4180/ | 0 | 0.5 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 4 | 2026-08-11T05:24:15+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 90890.0 | executor | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 5 | 2026-08-11T05:24:15+00:00 | VERIFY | nuclei | http://175.27.191.147:4180/ | 1 | 92334.05 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 6 | 2026-08-11T05:24:15+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 7 | 2026-08-11T05:24:15+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 92374.717 | harness |  |
| 8 | 2026-08-11T05:24:18+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api | 7 | 2429.79 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 9 | 2026-08-11T05:24:18+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v1 | 0 | 138.53 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 10 | 2026-08-11T05:24:18+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/api/v2 | 0 | 126.79 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 11 | 2026-08-11T05:24:18+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger | 0 | 121.09 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 12 | 2026-08-11T05:24:18+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui | 0 | 138.01 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 13 | 2026-08-11T05:24:18+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/swagger-ui.html | 0 | 135.0 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 14 | 2026-08-11T05:24:19+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/openapi.json | 0 | 122.84 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 15 | 2026-08-11T05:24:19+00:00 | RECON | curl_api_probe | http://175.27.191.147:4180/v2/api-docs | 0 | 132.93 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 16 | 2026-08-11T05:24:19+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger | 0 | 123.95 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 17 | 2026-08-11T05:24:19+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui | 0 | 127.63 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 18 | 2026-08-11T05:24:19+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/swagger-ui.html | 0 | 122.36 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 19 | 2026-08-11T05:24:19+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/openapi.json | 0 | 130.84 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 20 | 2026-08-11T05:24:19+00:00 | VERIFY | verify_finding | http://175.27.191.147:4180/v2/api-docs | 0 | 130.84 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 21 | 2026-08-11T05:24:19+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 22 | 2026-08-11T05:24:19+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 4125.964 | harness |  |
| 23 | 2026-08-11T05:24:20+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/login | 0 | 125.91 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 24 | 2026-08-11T05:24:20+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/admin/login | 0 | 135.59 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 25 | 2026-08-11T05:24:20+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/user/login | 0 | 122.66 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 26 | 2026-08-11T05:24:20+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/signin | 0 | 121.15 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 27 | 2026-08-11T05:24:20+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/sign-in | 0 | 134.35 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 28 | 2026-08-11T05:24:20+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/auth/login | 0 | 121.96 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 29 | 2026-08-11T05:24:20+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/account/login | 0 | 127.84 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 30 | 2026-08-11T05:24:21+00:00 | RECON | curl_auth_probe | http://175.27.191.147:4180/wp-login.php | 0 | 129.9 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 31 | 2026-08-11T05:24:21+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 32 | 2026-08-11T05:24:21+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 1082.211 | harness |  |
| 33 | 2026-08-11T05:24:21+00:00 | RECON | nmap | 175.27.191.147 | 0 | 0.5 | playbook | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 34 | 2026-08-11T05:24:21+00:00 | VERIFY | verify_finding | 175.27.191.147:22 | 1 | 18.61 | verify | F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MC |
| 35 | 2026-08-11T05:24:21+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 36 | 2026-08-11T05:24:21+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 0 | 59.857 | harness |  |
| 37 | 2026-08-11T05:24:21+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 38 | 2026-08-11T05:24:21+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 0.606 | harness |  |
| 39 | 2026-08-11T05:24:37+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 40 | 2026-08-11T05:24:37+00:00 | RECON | run_surface_chain_step | http://175.27.191.147:4180/ | 1 | 16758.183 | harness |  |
| 41 | 2026-08-11T05:24:37+00:00 | OBSERVE | observer_analyze |  | 0 |  | observer |  |
| 42 | 2026-08-11T05:24:37+00:00 | FINGERPRINT | propose_insights |  | 0 | 20.584 | insight |  |

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

- **finding_id**: `e196730c0452`
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

- **finding_id**: `6a6fa0728974`
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

- **finding_id**: `ea41621299a8`
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

- **finding_id**: `e6b809a65203`
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
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052421+0000_svc_nmap.txt`
  - `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\evidence\2026-08-11T052421+0000_verify_e6b809a65203.txt`

## 7. Observer 建议（旁路，默认不拦截）

- （无）

## 8. Handoff / 续跑指针

- handoff_json: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\handoff\handoff.json`
- progress_md: `F:\springInFer-skill\Kali-Security-MCP-main\Kali-Security-MCP-main\workspace\tasks\e2e-enh4\handoff\progress.md`

---

_generated by kali_mcp.core.report_export @ 2026-08-11T05:24:37+00:00_
