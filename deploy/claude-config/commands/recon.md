# 信息收集命令

**用法**: `/recon $ARGUMENTS`
**参数**: `TARGET [DEPTH]` - 目标域名/IP，深度(quick/standard/deep)

---

## 执行流程

全面信息收集和侦察：

### 1. 解析参数
从 `$ARGUMENTS` 中提取 TARGET 和 DEPTH，默认 DEPTH = standard

### 2. 判断目标类型
- 域名 → 执行域名侦察流程
- IP地址 → 执行网络侦察流程
- URL → 执行Web应用侦察流程

### 3. 域名目标侦察

**快速模式** (depth=quick):
```
subfinder_scan(domain=TARGET)
whatweb_scan(target=TARGET)
```

**标准模式** (depth=standard):
```
# 子域名枚举
subfinder_scan(domain=TARGET)
amass_enum(domain=TARGET, mode="enum")

# DNS信息
dnsrecon_scan(domain=TARGET)

# 技术识别
whatweb_scan(target=TARGET, aggression="3")
nuclei_technology_detection(target=TARGET)

# OSINT
theharvester_osint(domain=TARGET, sources="google,bing,linkedin")
```

**深度模式** (depth=deep):
```
# 完整侦察
comprehensive_recon(target=TARGET, domain_enum=True, port_scan=True, web_scan=True)

# 更多子域名源
sublist3r_scan(domain=TARGET)
dnsenum_scan(domain=TARGET)

# 深度OSINT
auto_osint_workflow(target_domain=TARGET, scope="extensive")
```

### 4. IP目标侦察

**快速模式**:
```
nmap_scan(target=TARGET, scan_type="-sV -T4", ports="1-1000")
```

**标准模式**:
```
nmap_scan(target=TARGET, scan_type="-sV -sC", ports="1-10000")
nuclei_network_scan(target=TARGET)
```

**深度模式**:
```
comprehensive_network_scan(target=TARGET, deep_scan=True)
auto_network_discovery_workflow(target_network=TARGET)
```

### 5. Web应用侦察

```
# 技术栈识别
whatweb_scan(target=TARGET)
wafw00f_scan(target=TARGET)

# 目录扫描
gobuster_scan(url=TARGET, mode="dir")

# 漏洞预扫描
nuclei_scan(target=TARGET, severity="critical,high")
```

### 6. 输出信息汇总
- 发现的子域名列表
- 开放端口和服务
- 技术栈信息
- 潜在攻击面
- 推荐的下一步操作

---

## 示例

- `/recon example.com` - 标准域名侦察
- `/recon 192.168.1.0/24 quick` - 快速网段扫描
- `/recon https://target.com deep` - 深度Web应用侦察
