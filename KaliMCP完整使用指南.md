# 🚀 KaliMCP 完整使用指南

## 📋 项目简介

**KaliMCP** 是一个基于MCP（Model Context Protocol）的全功能CTF自动化平台，集成了Web安全测试、网络渗透、逆向工程和PWN利用等所有主要CTF技术领域的工具。

### 🎯 核心能力

- **Web安全测试**: SQL注入、XSS、目录扫描、漏洞检测等
- **网络渗透**: 端口扫描、服务枚举、漏洞利用等
- **逆向工程**: 二进制分析、反编译、加密算法识别等
- **PWN利用**: 自动化二进制漏洞利用、栈溢出、ROP链等
- **CTF专用**: Flag自动检测、解题脚本生成、PoC自动化等

## 📚 目录结构

```
KaliMCP/
├── 📄 mcp_server.py          # MCP服务器主程序
├── 📄 kali_server.py         # Kali服务器程序
├── 📁 pwnpasi/               # PWN自动化工具
├── 📄 本机依赖环境安装指南.md   # Windows环境依赖
├── 📄 Kali服务器依赖环境.md    # Kali Linux环境依赖
└── 📄 KaliMCP完整使用指南.md   # 本文档
```

## 🚀 快速开始

### 第一步：环境准备

1. **准备Kali Linux服务器**
   - 参考 `Kali服务器依赖环境.md` 完成Kali环境配置

2. **配置本机环境**
   - 参考 `本机依赖环境安装指南.md` 完成Windows环境配置

### 第二步：启动服务

1. **启动Kali服务器**
```bash
# 在Kali虚拟机中
cd /path/to/kali-server
python3 kali_server.py
```

2. **启动MCP客户端**
```bash
# 在Windows本机
cd F:\kali\MCP-Kali-Server-main
python mcp_server.py --server http://192.168.102.66:5000
```

## 🛠️ 核心功能使用

### 🌐 Web安全测试

#### 基础Web扫描
```python
# 端口扫描
nmap_scan("192.168.1.100", "-sV", "80,443,8080", "-T4")

# 目录扫描
gobuster_scan("http://target.com", "dir", "/usr/share/wordlists/dirb/common.txt")

# Web漏洞扫描
nuclei_web_scan("http://target.com", "comprehensive")
```

#### SQL注入测试
```python
# 自动SQL注入检测
sqlmap_scan("http://target.com/page.php?id=1", "", "--batch --level=2")

# 智能SQL注入Payload生成
intelligent_sql_injection_payloads("http://target.com", "mysql", True)
```

#### 综合Web安全评估
```python
# 全面Web应用安全评估
advanced_web_security_assessment("http://target.com", wordpress_check=True)

# 自动化Web安全工作流
auto_web_security_workflow("http://target.com", "comprehensive")
```

### 🔍 网络渗透测试

#### 网络发现
```python
# 主机发现
netdiscover_scan("", "192.168.1.0/24", False)

# 快速端口扫描
masscan_fast_scan("192.168.1.0/24", "80,443,22,21,23", "5000")
```

#### 服务枚举
```python
# 服务版本检测
nmap_scan("192.168.1.100", "-sV -sC", "1-65535", "-T4")

# SMB枚举
enum4linux_scan("192.168.1.100", "-a")
```

#### 综合网络渗透
```python
# 全面网络渗透测试
network_penetration_test("192.168.1.100", "single")

# 自动化网络发现
auto_network_discovery_workflow("192.168.1.0/24", "standard")
```

### 🔧 逆向工程

#### 二进制分析
```python
# 自动选择最佳逆向工具
auto_reverse_analyze("C:/path/to/binary.exe")

# Radare2分析
radare2_analyze_binary("C:/path/to/binary.exe")

# IDA Pro分析（如果可用）
ida_analyze_binary("C:/path/to/binary.exe")
```

#### CTF逆向求解
```python
# CTF逆向题目自动求解
ctf_reverse_solver("C:/path/to/challenge.exe", ["hint1", "hint2"])

# 密码学逆向专用
ctf_crypto_reverser("C:/path/to/crypto_challenge.exe", "encrypted_data")
```

### ⚡ PWN利用

#### 快速PWN检查
```python
# 快速漏洞评估
quick_pwn_check("C:/path/to/binary.exe")
```

#### 自动化PWN攻击
```python
# PwnPasi一键利用
pwnpasi_auto_pwn(
    binary_path="C:/path/to/vuln_binary",
    remote_ip="192.168.1.100",  # 可选
    remote_port=9999,           # 可选
    verbose=True
)
```

#### CTF PWN求解
```python
# CTF PWN题目综合求解
ctf_pwn_solver(
    binary_path="C:/path/to/pwn_challenge",
    challenge_name="Buffer Overflow Easy",
    challenge_hints=["stack", "ret2libc"]
)
```

#### 综合PWN攻击
```python
# 多方法PWN攻击
pwn_comprehensive_attack(
    binary_path="C:/path/to/target",
    attack_methods=["pwnpasi_auto", "ret2libc", "rop_chain"],
    remote_target="192.168.1.100:9999"
)
```

## 🏆 CTF专用功能

### CTF模式
```python
# 启用CTF模式（自动Flag检测）
enable_ctf_mode()

# 创建CTF会话
create_ctf_session("HCTF 2024", "MyTeam")

# 添加题目
add_ctf_challenge("Web Easy", "web", 8080, "http")
```

### 智能CTF求解
```python
# Web题目自动求解
ctf_web_attack("http://ctf.challenge.com:8080", "Web Easy")

# PWN题目自动求解
ctf_pwn_solver("./pwn_challenge", "PWN Medium", ["stack overflow", "64-bit"])

# 全自动CTF求解
advanced_ctf_solver("http://challenge.com", {"category": "web", "hints": ["sql"]})
```

### Flag检测
```python
# 查看检测到的Flag
get_detected_flags()

# 获取题目状态
get_ctf_challenges_status()
```

## 🤖 智能化功能

### 自适应攻击
```python
# 智能APT攻击活动
intelligent_apt_campaign("target.company.com")

# 自适应Web渗透
adaptive_web_penetration("http://target.com")

# 自适应网络渗透
adaptive_network_penetration("192.168.1.100")
```

### 智能分析
```python
# 目标分析
analyze_target_intelligence("target.com")

# 智能扫描计划
generate_adaptive_scan_plan("target.com", time_budget="thorough")

# 智能漏洞评估
intelligent_vulnerability_assessment("target.com", "comprehensive")
```

### Payload生成
```python
# 智能Payload生成
generate_intelligent_payload(
    vulnerability_type="sql_injection",
    target_info={"platform": "mysql", "waf_detected": True},
    evasion_level="high",
    quantity=10
)

# WAF绕过Payload
generate_waf_bypass_payload("xss", "cloudflare", "<script>alert(1)</script>")

# 多语言通用Payload
generate_polyglot_payload(["html", "javascript", "sql"], {"browser": "chrome"})
```

## 📝 PoC生成和攻击记录

### 攻击会话管理
```python
# 开始攻击会话
start_attack_session("target.com", "apt", "Web App Pentest")

# 记录攻击步骤
log_attack_step(
    tool_name="sqlmap",
    command="sqlmap -u http://target.com/page.php?id=1 --batch",
    success=True,
    output="[FOUND] SQL injection vulnerability",
    payload="1' AND 1=1--"
)

# 结束会话并生成PoC
end_attack_session()
generate_poc_from_current_session()
```

### 自动化攻击+PoC生成
```python
# 自动APT攻击并生成PoC
auto_apt_attack_with_poc("target.com", "APT Test Campaign")

# 自动CTF解题并生成脚本
auto_ctf_solve_with_poc("http://ctf.challenge.com", "Web Challenge", "web")

# 智能化攻击并生成高级PoC
intelligent_attack_with_poc("target.com", "apt", ["data_extraction", "persistence"])
```

## 🔄 工作流示例

### Web应用安全测试完整流程
```python
# 1. 启动攻击会话
start_attack_session("webapp.company.com", "apt", "Web App Security Assessment")

# 2. 信息收集
nmap_result = nmap_scan("webapp.company.com", "-sV", "80,443,8080", "-T4")
tech_result = nuclei_technology_detection("http://webapp.company.com")

# 3. 目录扫描
dir_result = gobuster_scan("http://webapp.company.com", "dir", "/usr/share/wordlists/dirb/big.txt")

# 4. 漏洞扫描
vuln_result = nuclei_web_scan("http://webapp.company.com", "comprehensive")
sql_result = sqlmap_scan("http://webapp.company.com/login.php", "username=admin&password=test", "--batch")

# 5. 生成报告
end_attack_session()
generate_poc_from_current_session()
```

### CTF PWN题目完整求解流程
```python
# 1. 启用CTF模式
enable_ctf_mode()
create_ctf_session("HCTF 2024", "TeamName")

# 2. 快速分析
pwn_info = quick_pwn_check("./challenge_binary")

# 3. 自动化利用
if pwn_info["quick_attack_possible"]:
    pwn_result = pwnpasi_auto_pwn("./challenge_binary", verbose=True)
else:
    pwn_result = pwn_comprehensive_attack("./challenge_binary", ["pwnpasi_auto", "rop_chain"])

# 4. Flag检测
flags = get_detected_flags()
print(f"Found flags: {flags}")
```

## 📊 并发任务管理

### 并发扫描
```python
# 并行端口扫描多个目标
parallel_port_scanning(
    targets=["192.168.1.100", "192.168.1.101", "192.168.1.102"],
    ports="1-1000",
    priority=3
)

# 并行目录扫描
parallel_directory_scanning(
    urls=["http://site1.com", "http://site2.com", "http://site3.com"],
    wordlist="/usr/share/wordlists/dirb/common.txt"
)
```

### 工作流管理
```python
# 提交预定义工作流
comprehensive_web_security_scan("http://target.com", "Web Security Assessment")
network_penetration_testing("192.168.1.100", "Network Pentest")
fast_reconnaissance("target.com", "Quick Recon")

# 查看任务状态
get_workflow_status("workflow_id_here")
get_concurrent_system_stats()
```

## 🎯 最佳实践

### CTF比赛中的使用建议

1. **快速信息收集**
   ```python
   # 使用快速侦察工作流
   fast_reconnaissance("ctf.challenge.com")
   ```

2. **智能题目求解**
   ```python
   # 根据题目类型自动选择最佳策略
   advanced_ctf_solver("http://challenge.com", {"category": "web", "time_limit": "15min"})
   ```

3. **并发处理多题目**
   ```python
   # 同时处理多个题目
   enable_ctf_mode()
   # 为每个题目启动独立的求解流程
   ```

### 渗透测试中的使用建议

1. **系统化攻击**
   ```python
   # 使用智能渗透测试工作流
   intelligent_penetration_testing("target.com", "single", "owasp")
   ```

2. **完整记录**
   ```python
   # 全程记录攻击过程，自动生成PoC
   auto_apt_attack_with_poc("target.com", "Pentest Campaign")
   ```

## 🔧 故障排除

### 常见问题

1. **连接问题**
   - 检查Kali服务器是否正常运行
   - 确认IP地址和端口配置正确
   - 检查防火墙和网络连接

2. **工具缺失**
   - 运行 `reverse_tool_check()` 检查可用的逆向工具
   - 参考依赖环境文档安装缺失的工具

3. **权限问题**
   - 确保有足够权限访问目标文件
   - 检查Kali服务器上的工具权限

### 调试模式
```bash
# 启用调试模式
python mcp_server.py --debug --server http://192.168.102.66:5000
```

## 📞 技术支持

- 查看详细日志获取错误信息
- 检查 `本机依赖环境安装指南.md` 确保环境配置正确
- 确认 `Kali服务器依赖环境.md` 中的所有工具已正确安装

---

**🎯 提示**: 这是一个功能强大的自动化平台，建议先在测试环境中熟悉各项功能，然后再在实际CTF比赛或渗透测试中使用。

**⚠️ 免责声明**: 请仅在授权的环境中使用此工具，遵守相关法律法规和道德准则。
