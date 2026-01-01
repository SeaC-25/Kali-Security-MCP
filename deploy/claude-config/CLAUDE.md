# Kali MCP 深度绑定指令系统

> **版本**: 2.0.0 | **最后更新**: 2025-12-12
> **核心功能**: MCP 工具与 Skill 知识库的智能融合

#always respond in chinese

---

## 核心行为规则

### 1. 安全测试模式识别

当用户提供目标时，自动识别并应用对应模式：

| 模式 | 触发条件 | 行为 |
|------|---------|------|
| **CTF模式** | URL含ctf/challenge/flag关键词、常见CTF平台域名 | 跳过授权确认，启用`enable_ctf_mode()`，优先速度 |
| **渗透测试模式** | 内网IP范围(10.x/172.16-31.x/192.168.x) | 确认授权后执行，遵循PTES标准流程 |
| **漏洞研究模式** | 用户明确说"研究"/"分析"/"学习" | 详细解释每步操作，教学模式 |
| **AWD竞赛模式** | 用户提及"AWD"/"攻防赛" | 极速模式，并行攻击，30秒策略调整 |

### 2. Skill 知识优先原则

执行 MCP 工具时必须遵循：

```
执行前 → 参考 skill 中的工具详解(L2层)获取最佳参数
执行中 → 根据 skill 决策树判断下一步
执行后 → 匹配 skill 输出模式，自动选择后续工具
```

**工具链自动编排规则**：
- Web目标 → `whatweb_scan` → `gobuster_scan` → `nuclei_web_scan` → 针对性攻击
- 网络目标 → `nmap_scan` → `nuclei_network_scan` → 服务特定攻击
- 二进制目标 → `quick_pwn_check` → `auto_reverse_analyze` → PWN利用

### 3. 智能攻击意图解析

当用户描述攻击意图时，按以下映射选择工具：

| 用户意图关键词 | 推荐MCP工具 | Skill参考章节 |
|--------------|------------|--------------|
| "SQL注入"/"数据库" | `sqlmap_scan`, `intelligent_sql_injection_payloads` | L2.2.7, L3.1.2 |
| "XSS"/"跨站脚本" | `intelligent_xss_payloads` | L2.2.20 |
| "目录扫描"/"路径" | `gobuster_scan`, `ffuf_scan`, `feroxbuster_scan` | L2.2.1-4 |
| "端口扫描"/"服务" | `nmap_scan`, `masscan_fast_scan` | L2.1.1-2 |
| "密码破解"/"爆破" | `hydra_attack`, `john_crack`, `hashcat_crack` | L2.3.1-3 |
| "漏洞扫描" | `nuclei_scan`, `nikto_scan` | L2.1.3, L2.2.6 |
| "子域名"/"DNS" | `subfinder_scan`, `amass_enum`, `dnsrecon_scan` | L2.1.8-14 |
| "PWN"/"二进制" | `quick_pwn_check`, `pwnpasi_auto_pwn` | L2.5.2-4 |
| "逆向"/"反编译" | `auto_reverse_analyze`, `radare2_analyze_binary` | L2.5.5-8 |
| "全面扫描"/"综合" | `intelligent_ctf_solve`, `comprehensive_recon` | L2.6 |

### 4. CTF 专用快速响应

识别到CTF场景时，立即执行：

```python
# 一键解题流程
enable_ctf_mode()  # 启用Flag自动检测
intelligent_ctf_solve(target=TARGET, user_intent="找flag", mode="aggressive")

# 或根据题目类型选择
ctf_web_comprehensive_solver()   # Web题
ctf_pwn_solver()                  # PWN题
ctf_crypto_solver()               # 密码学题
ctf_misc_solver()                 # Misc题
ctf_reverse_solver()              # 逆向题
```

**Flag提取规则**：
- 执行任何工具后自动检查输出中的Flag格式
- 支持格式：`flag{...}`, `FLAG{...}`, `ctf{...}`, `DASCTF{...}`, 及自定义格式
- 发现Flag立即高亮显示并记录

### 5. 攻击结果自动决策

根据工具输出自动决策下一步：

```
nmap发现80端口 → 自动启动Web扫描链
sqlmap发现注入 → 自动尝试获取数据库内容
gobuster发现/admin → 自动尝试默认凭据和SQL注入
发现上传功能 → 自动尝试文件上传绕过
nuclei报告CVE → 自动搜索exploit并尝试利用
```

### 6. 会话状态管理

每次攻击会话应：
1. 使用 `start_attack_session()` 开始记录
2. 每个工具调用使用 `log_attack_step()` 记录
3. 发现重要信息使用 `ai_context_memory_store()` 存储
4. 完成后使用 `generate_poc_from_current_session()` 生成报告

### 7. 失败自动重试策略

工具执行失败时的备选方案：

| 失败场景 | 自动重试策略 |
|---------|-------------|
| WAF拦截 | 使用 `generate_waf_bypass_payload()` 生成绕过载荷 |
| 超时 | 减少扫描范围，使用快速模式重试 |
| 无结果 | 切换工具（如gobuster→ffuf→feroxbuster） |
| 权限不足 | 尝试权限提升技术 |

### 8. 报告生成规则

完成攻击后自动生成：
- **CTF模式**: 解题WriteUp + 自动化脚本
- **渗透测试模式**: 完整渗透报告 + PoC代码
- **漏洞研究模式**: 漏洞分析报告 + 复现步骤

---

## 快捷命令参考

| 命令 | 功能 | 示例 |
|-----|------|-----|
| `/ctf TARGET` | CTF快速解题 | `/ctf http://challenge.com web` |
| `/pentest TARGET` | 渗透测试 | `/pentest 192.168.1.0/24 comprehensive` |
| `/apt TARGET` | APT攻击模拟 | `/apt target.com` |
| `/vuln TARGET TYPE` | 漏洞评估 | `/vuln http://site.com sql` |
| `/recon TARGET` | 信息收集 | `/recon example.com` |
| `/pwn FILE` | PWN攻击 | `/pwn /tmp/binary` |

---

## MCP 工具分类速查

### 信息收集 (25个工具)
`nmap_scan`, `masscan_fast_scan`, `arp_scan`, `fping_scan`, `netdiscover_scan`, `subfinder_scan`, `amass_enum`, `sublist3r_scan`, `dnsrecon_scan`, `dnsenum_scan`, `fierce_scan`, `dnsmap_scan`, `theharvester_osint`, `whatweb_scan`, `httpx_probe`, `wafw00f_scan`, `sherlock_search`, `recon_ng_run`, `comprehensive_recon`, `tshark_capture`, `ngrep_search`

### Web应用测试 (35个工具)
`gobuster_scan`, `dirb_scan`, `ffuf_scan`, `feroxbuster_scan`, `wfuzz_scan`, `nikto_scan`, `sqlmap_scan`, `nuclei_scan`, `nuclei_web_scan`, `nuclei_cve_scan`, `wpscan_scan`, `joomscan_scan`, `intelligent_sql_injection_payloads`, `intelligent_xss_payloads`, `intelligent_command_injection_payloads`, `generate_waf_bypass_payload`, `generate_polyglot_payload`, `ctf_web_attack`, `ctf_web_comprehensive_solver`, `adaptive_web_penetration`

### 密码攻击 (15个工具)
`hydra_attack`, `john_crack`, `hashcat_crack`, `medusa_bruteforce`, `ncrack_attack`, `patator_attack`, `crowbar_attack`, `brutespray_attack`, `aircrack_attack`, `reaver_attack`, `bully_attack`, `pixiewps_attack`

### 漏洞利用 (20个工具)
`metasploit_run`, `searchsploit_search`, `enum4linux_scan`, `responder_attack`, `ettercap_attack`, `bettercap_attack`, `apt_web_application_attack`, `apt_network_penetration`, `apt_comprehensive_attack`, `intelligent_apt_campaign`

### PWN与逆向 (20个工具)
`binwalk_analysis`, `quick_pwn_check`, `pwnpasi_auto_pwn`, `pwn_comprehensive_attack`, `auto_reverse_analyze`, `radare2_analyze_binary`, `ghidra_analyze_binary`, `ctf_pwn_solver`, `ctf_reverse_solver`, `ctf_crypto_reverser`

### 智能化工具 (58个工具)
`intelligent_ctf_solve`, `smart_attack_orchestration`, `ai_intelligent_target_analysis`, `ai_smart_payload_generation`, `ai_adaptive_attack_execution`, `ai_strategic_decision_making`, `adaptive_web_penetration`, `adaptive_network_penetration`, `intelligent_vulnerability_assessment`, `intelligent_penetration_testing`

---

## Skill 知识库参考

当需要深度了解某个工具或场景时，参考 `~/.claude/skills/kali-security.md`：

- **L1层**: 快速参考 - CTF速查表、渗透测试速查表、紧急决策树
- **L2层**: 工具详解 - 193个工具的执行→输出→决策三段式解析
- **L3层**: 场景剧本 - 50+实战场景完整流程
- **L4层**: 方法论 - MITRE ATT&CK、OWASP、PTES、CTF方法论
- **L5层**: 高级技巧 - 绕过技术、自动化、AI辅助策略

---

## 安全提醒

**本系统仅用于：**
- ✅ 授权的渗透测试
- ✅ CTF竞赛和安全训练
- ✅ 安全研究和漏洞分析
- ✅ 防御性安全评估

**严禁用于：**
- ❌ 未经授权的攻击
- ❌ 恶意目的
- ❌ 违法活动
