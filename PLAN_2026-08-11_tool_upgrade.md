# 接入工具推陈出新升级计划（fastsec 模式推广）

> 2026-08-11
> 原则: 兼容是地基，创新是价值——每个接入工具都按 fastsec 已验证的模式升级：
> 前置(指纹/diff 预筛) + 执行(stealth 反检测) + 后置(3-gate 确认 + findings 入库)

---

## 1. 通用升级框架（fastsec 已验证，全工具复用）

```
┌─ 前置智能层 ──────────────┐
│ 技术指纹(whatweb/nuclei)    │ → 选对工具参数/方言
│ diff 预筛(行为差异)          │ → 只测可疑参数，请求量降 80%
├─ 执行层 ──────────────────┤
│ stealth(UA池/节奏/代理)      │ → WAF/EDR 难识别
│ 并发调度(异步 job)           │ → 不阻塞流程
├─ 后置确认层 ───────────────┤
│ 3-gate 基线对比              │ → 零误报
│ findings 入库               │ → 跨会话复用
└────────────────────────────┘
```

fastsec 已有资产直接复用：`internal/stealth`（UA/节奏/代理）、`internal/diff`（行为差异）、`internal/verify`（3-gate）、`internal/priority`（参数分级）。

---

## 2. 各工具天花板分析 + 创新方向

### 2.1 sqlmap（优先级最高，用户点名）
**天花板**：
- 慢：每参数全库 payload 盲测，布尔盲注逐字符二分
- 指纹明显：默认 UA/特征，WAF 秒 ban
- 黑盒盲目：不利用已发现的技术指纹
- 误报：无基线对比确认

**升级（sqlmap++ 智能注入）**：
| 创新 | 实现 | 收益 |
|------|------|------|
| 指纹引导方言 | 先 whatweb/nuclei 指纹 → 选 DBMS（MySQL/MSSQL/PG）→ 只测对应 payload | 请求量 -80% |
| diff 预筛注入点 | fastsec diff 找行为差异参数 → 只送可疑参数给 sqlmap | 避免全参数盲测 |
| 3-gate 确认 | sqlmap 报注入 → 基线对比真伪 | 零误报 |
| stealth 前置 | UA 池 + 节奏 + 代理 → sqlmap | WAF 难识别 |
| 结果入库 | 确认注入 → findings_store | 跨会话复用 |

### 2.2 爆破类（hydra/kerbrute/medusa/ncrack）
**天花板**：盲目字典、无节奏（锁账号）、不利用社工信息
**升级**：
- 社工字典生成：先 OSINT（真实姓名/域名）→ 生成定制字典（姓名+年份/公司名+@）
- stealth 节奏：多账号轮换 + 随机间隔，避免锁定
- 结果入库：命中凭据 → findings_store（高价值）

### 2.3 扫描类（nmap/rustscan/naabu/masscan）
**天花板**：静态端口-服务映射，不联动后续
**升级**：
- 自动编排：扫描 → 服务指纹 → 自动选后续工具（web→fastsec/内核→searchsploit/数据库→sqlmap++）
- 结果入库：开放端口 → 图谱，跨会话资产复用

### 2.4 Web 目录类（gobuster/ffuf/dirb/wfuzz）
**天花板**：纯字典暴力，无智能、慢、不隐身
**升级**：
- 先 JS 提取端点（fastsec 思路）→ 缩小字典
- 3-gate 确认：发现的路径基线对比（SPA 通配过滤）
- stealth 限速

### 2.5 OSINT 类（theharvester/sherlock/recon-ng）
**天花板**：单点查询，不聚合、不排序
**升级**：
- 聚合：多源结果合并去重 → 优先级排序（email→username→domain）
- 结果入库 → 社工字典生成输入（联动 2.2）

### 2.6 AD/内网类（nxc/impacket/kerbrute）
**天花板**：单步工具，无攻击链编排
**升级**：
- 攻击链编排：userenum → AS-REP/Kerberoast → 密码喷洒 → 哈希传递（internal_lateral playbook 已做，补 stealth 节奏）
- 结果入库：有效用户/哈希 → 图谱

### 2.7 代码审计类（semgrep/bandit）
**天花板**：静态规则，误报高
**升级**：
- 结果分级：规则权重 + 漏洞上下文 → 优先级排序
- 入库 → 关联 fastsec 扫描（代码漏洞 → 运行时验证）

---

## 3. 实施优先级

| 优先级 | 工具 | 理由 |
|--------|------|------|
| **P0** | sqlmap++ | 用户点名、价值最高（SQL 注入=数据泄露）、fastsec 资产直接复用 |
| P1 | 爆破类 | 高频使用、stealth 收益大 |
| P2 | 扫描/目录类 | 自动编排价值 |
| P3 | OSINT/AD/审计 | 聚合与编排 |

## 4. 阶段计划

- **P0-sqlmap++**：
  1. 指纹引导方言（调用 whatweb/nuclei 结果 → payload 集）
  2. diff 预筛注入点（fastsec diff → 候选参数）
  3. stealth 前置（UA/节奏/代理封装 sqlmap 调用）
  4. 3-gate 确认 + 入库
  5. 端到端验证（授权目标/本地 lab）
- **P1-爆破**：社工字典生成器 + stealth 节奏
- **P2-扫描/目录**：自动编排链
- **P3-OSINT/AD/审计**：聚合 + 入库

## 5. 验收标准

1. sqlmap++ 对比原生 sqlmap：同目标请求量降 ≥60%，误报降为 0（3-gate），WAF 识别难度上升（stealth）
2. 全升级工具：findings 入库 + 反检测内建
3. 工具链自动编排：指纹→预筛→执行→确认→入库 全自动

## 6. 技术方案

sqlmap++ 实现形态（Go 编排器 + sqlmap 执行）：
```
internal/sqlmap/
├── oracle.go     # 指纹 → DBMS 方言 → payload 集
├── prescreen.go  # diff 预筛注入点
├── stealth.go    # 复用 internal/stealth 封装 sqlmap 调用
├── confirm.go    # 3-gate 确认注入真伪
└── runner.go     # 并发调度 + 结果入库
```

或轻量版：Python 包装层（MCP playbook 内），复用 fastsec 二进制输出 + 调 sqlmap CLI。
