package injector

// XSS 反射检测（反射型 XSS：提交 payload 后检查响应是否未转义回显）。
// 复用本包 get/mutate 请求辅助与 stealth.Client，结构与 SQLi 检测（Scan/Format）对齐：
//   1. 每个参数先取基线响应；
//   2. 逐 payload 提交，命中条件 = 响应体包含原始 payload 且基线不含（排除静态脚本误报）；
//   3. 首个命中即判定该参数反射 XSS（停止后续 payload）。
// 不做 HTML 上下文（属性/标签内）判定——未转义回显即视为可执行上下文风险，
// 与 fastsec 其余检测（反射/回显特征）的保守策略一致。

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"fastsec/internal/stealth"
)

// xssPayloads: 反射型 XSS 测试载荷（各自含唯一标记，避免与页面静态脚本混淆）
var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`<img src=x onerror=alert(1)>`,
	`"><svg onload=alert(1)>`,
	`'><script>alert(1)</script>`,
	`<svg/onload=alert(1)>`,
	`<body onload=alert(1)>`,
	`javascript:alert(1)`,
}

// XSSFinding: 单参数 XSS 检测结果
type XSSFinding struct {
	Param     string
	Reflected bool
	Payload   string
	URL       string // 命中请求 URL（证据）
	Context   string // 响应中回显上下文（证据，截断 ±60 字符）
}

// XSSResult: 全部参数结果
type XSSResult struct {
	Target   string
	Findings []XSSFinding
}

// ScanXSS: XSS 反射检测主入口。
// params 为空时从 baseURL query 自动发现；两者皆空 → 空结果（clean，无误报）。
func ScanXSS(baseURL string, params []string, c *stealth.Client) XSSResult {
	res := XSSResult{Target: baseURL}
	if len(params) == 0 {
		params = discoverParams(baseURL)
	}
	if len(params) == 0 {
		return res
	}
	var findings []XSSFinding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, p := range params {
		wg.Add(1)
		go func(param string) {
			defer wg.Done()
			sem <- struct{}{}
			f := scanOneXSS(baseURL, param, c)
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
			<-sem
		}(p)
	}
	wg.Wait()
	res.Findings = findings
	return res
}

// discoverParams: 从 URL query 自动发现待测参数
func discoverParams(baseURL string) []string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	var out []string
	for k := range q {
		out = append(out, k)
	}
	return out
}

// scanOneXSS: 对单个参数跑全量 payload，首个未转义回显即判定命中
func scanOneXSS(baseURL, param string, c *stealth.Client) XSSFinding {
	f := XSSFinding{Param: param}
	_, baseBody, _, _ := get(baseURL, c)
	for _, p := range xssPayloads {
		u := mutate(baseURL, param, p)
		s, body, _, _ := get(u, c)
		if s != 200 && s != 201 && s != 302 {
			continue
		}
		// 命中：响应体含原始 payload（未转义回显），且基线不含（排除静态脚本）
		if strings.Contains(body, p) && !strings.Contains(baseBody, p) {
			f.Reflected = true
			f.Payload = p
			f.URL = u
			f.Context = extractContext(body, p)
			break
		}
	}
	return f
}

// extractContext: 取 payload 回显位置 ±60 字符作为证据上下文
func extractContext(body, payload string) string {
	idx := strings.Index(body, payload)
	if idx < 0 {
		return ""
	}
	start := idx - 60
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 60
	if end > len(body) {
		end = len(body)
	}
	return strings.ReplaceAll(body[start:end], "\n", " ")
}

// FormatXSS renders results.
func FormatXSS(r XSSResult) string {
	var sb strings.Builder
	reflected := 0
	for _, f := range r.Findings {
		if f.Reflected {
			reflected++
		}
	}
	sb.WriteString(fmt.Sprintf("[xss] %d/%d params XSS reflected\n", reflected, len(r.Findings)))
	if len(r.Findings) == 0 {
		sb.WriteString("  (URL 无 query 参数且未指定 -xss 参数名 → 无参数可测，clean)\n")
	}
	for _, f := range r.Findings {
		if f.Reflected {
			sb.WriteString(fmt.Sprintf("  [!] %s XSS reflected: %s\n", f.Param, f.Payload))
			if f.Context != "" {
				sb.WriteString(fmt.Sprintf("      evidence: %s\n", f.Context))
			}
		} else {
			sb.WriteString(fmt.Sprintf("  - %s: clean\n", f.Param))
		}
	}
	return sb.String()
}
