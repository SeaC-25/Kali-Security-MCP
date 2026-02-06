# 漏洞评估命令

**用法**: `/vuln $ARGUMENTS`
**参数**: `TARGET [TYPE]` - 目标URL/IP，漏洞类型(sql/xss/rce/lfi/ssrf/xxe/all)

---

## 执行流程

针对特定漏洞类型进行快速评估：

### 1. 解析参数
从 `$ARGUMENTS` 中提取 TARGET 和 TYPE，默认 TYPE = all

### 2. 根据漏洞类型执行测试

**SQL注入** (type=sql):
```
# 自动SQL注入检测
sqlmap_scan(url=TARGET, additional_args="--batch --crawl=2 --forms")

# 智能SQL注入Payload
intelligent_sql_injection_payloads(target_url=TARGET, waf_detected=检测WAF结果)
```

**XSS跨站脚本** (type=xss):
```
# 智能XSS Payload生成
intelligent_xss_payloads(target_url=TARGET, browser_type="chrome", content_type="html")

# 使用nuclei XSS模板
nuclei_scan(target=TARGET, tags="xss")
```

**远程代码执行** (type=rce):
```
# 命令注入测试
intelligent_command_injection_payloads(target_url=TARGET, os_type="linux")

# RCE漏洞扫描
nuclei_scan(target=TARGET, tags="rce")

# 搜索已知RCE漏洞
searchsploit_search(term=从目标识别的技术栈)
```

**本地文件包含** (type=lfi):
```
# LFI专用Payload
generate_intelligent_payload(vulnerability_type="lfi", quantity=10)

# LFI漏洞扫描
nuclei_scan(target=TARGET, tags="lfi")
```

**SSRF服务端请求伪造** (type=ssrf):
```
# SSRF专用Payload
generate_intelligent_payload(vulnerability_type="ssrf", quantity=10)

# SSRF漏洞扫描
nuclei_scan(target=TARGET, tags="ssrf")
```

**XXE XML外部实体** (type=xxe):
```
# XXE专用Payload
generate_intelligent_payload(vulnerability_type="xxe", quantity=10)

# XXE漏洞扫描
nuclei_scan(target=TARGET, tags="xxe")
```

**全面扫描** (type=all):
```
# 综合漏洞评估
intelligent_vulnerability_assessment(target=TARGET, assessment_depth="comprehensive")

# 多类型Nuclei扫描
nuclei_scan(target=TARGET, severity="critical,high,medium")
```

### 3. 生成报告
- 漏洞类型和位置
- 风险等级（CVSS评分）
- 利用PoC
- 修复建议

---

## 示例

- `/vuln http://target.com/page?id=1 sql` - SQL注入测试
- `/vuln http://target.com/search xss` - XSS测试
- `/vuln http://target.com all` - 全面漏洞扫描
