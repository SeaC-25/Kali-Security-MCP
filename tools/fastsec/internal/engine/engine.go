// Package engine: concurrent HTTP scanning with nuclei-compatible templates,
// stealth transport and 3-gate confirmation (baseline vs attack).
package engine

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fastsec/internal/stealth"
	"fastsec/internal/template"
	"fastsec/internal/verify"
)

// Config holds engine options.
type Config struct {
	Concurrency int
	Timeout     time.Duration
	DelayMinMs  int
	DelayMaxMs  int
	Proxy       string
	VerifyGate  bool
	Headers     map[string]string
	Cookies     string
}

func DefaultConfig() *Config {
	return &Config{
		Concurrency: 20,
		Timeout:     10 * time.Second,
		DelayMinMs:  300,
		DelayMaxMs:  800,
		VerifyGate:  true,
		Headers:     map[string]string{},
	}
}

// Engine runs templates against targets.
type Engine struct {
	cfg     *Config
	client  *stealth.Client
	mu      sync.Mutex
	results []template.MatchResult
}

func New(cfg *Config) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Engine{
		cfg:    cfg,
		client: stealth.NewClient(cfg.Proxy, stealth.NewThrottle(cfg.DelayMinMs, cfg.DelayMaxMs), cfg.Concurrency*2),
	}
}

// Run executes all templates against one base URL.
func (e *Engine) Run(baseURL string, templates []*template.Template) []template.MatchResult {
	e.results = nil
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for _, tpl := range templates {
		for _, req := range tpl.Requests {
			// payloads expansion (clusterbomb/pitchfork)
			combos := expandPayloads(req)
			if len(combos) == 0 {
				combos = []map[string]string{{}}
			}
			for _, combo := range combos {
				for _, path := range req.Path {
					wg.Add(1)
					sem <- struct{}{}
					go func(t *template.Template, rq template.Request, p string, pl map[string]string) {
						defer wg.Done()
						defer func() { <-sem }()
						e.scanOne(baseURL, t, rq, p, pl)
					}(tpl, req, path, combo)
				}
			}
		}
	}
	wg.Wait()
	return e.results
}

// expandPayloads generates payload combinations for a request.
// maxPayloadCombos: 笛卡尔积上限（防模板 payloads 爆炸）
const maxPayloadCombos = 1000

func expandPayloads(rq template.Request) []map[string]string {
	if len(rq.Payloads) == 0 {
		return nil
	}
	// 预计算组合数，超限截断（每 key 最多取前 N）
	keys := make([]string, 0, len(rq.Payloads))
	for k := range rq.Payloads {
		keys = append(keys, k)
	}
	total := 1
	trimmed := map[string][]string{}
	for _, k := range keys {
		vals := rq.Payloads[k]
		if len(vals) > 0 {
			total *= len(vals)
		}
		trimmed[k] = vals
	}
	// 超限：每 key 截断到能控制总量
	if total > maxPayloadCombos {
		// 每个 key 只取前几个，保证 total <= max
		factor := 1
		_ = factor
		for _, k := range keys {
			vals := trimmed[k]
			// 单 key 超限直接截断
			if len(vals) > maxPayloadCombos {
				trimmed[k] = vals[:maxPayloadCombos]
			}
		}
		// 多 key 组合超限：逐 key 截断
		for {
			total = 1
			for _, k := range keys {
				total *= len(trimmed[k])
			}
			if total <= maxPayloadCombos {
				break
			}
			// 截断最大的 key 一半
			biggest := keys[0]
			for _, k := range keys {
				if len(trimmed[k]) > len(trimmed[biggest]) {
					biggest = k
				}
			}
			vals := trimmed[biggest]
			trimmed[biggest] = vals[:len(vals)/2]
			if len(trimmed[biggest]) == 0 {
				break
			}
		}
	}
	// 生成笛卡尔积（已控制上限）
	var out []map[string]string
	var rec func(i int, acc map[string]string)
	rec = func(i int, acc map[string]string) {
		if i == len(keys) {
			m := map[string]string{}
			for k, v := range acc {
				m[k] = v
			}
			out = append(out, m)
			return
		}
		k := keys[i]
		for _, v := range trimmed[k] {
			acc[k] = v
			rec(i+1, acc)
		}
		delete(acc, k)
	}
	rec(0, map[string]string{})
	return out
}

// expandVars substitutes {{BaseURL}}/{{Hostname}}/{{path}}/{{var}} in a string.
func expandVars(s, baseURL string, payload map[string]string) string {
	s = strings.ReplaceAll(s, "{{BaseURL}}", baseURL)
	u, err := url.Parse(baseURL)
	host := baseURL
	if err == nil && u.Host != "" {
		host = u.Host
	}
	s = strings.ReplaceAll(s, "{{Hostname}}", host)
	s = strings.ReplaceAll(s, "{{hostname}}", host)
	for k, v := range payload {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	// 归一化 scheme:// 之后的双斜杠（BaseURL 以 / 结尾 + 模板 path 以 / 开头）
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		// 清理 host 之后的双斜杠（BaseURL 尾 / + 模板 path 首 /）
		rest = strings.ReplaceAll(rest, "//", "/")
		s = s[:i+3] + rest
	}
	return s
}

func (e *Engine) scanOne(baseURL string, tpl *template.Template, rq template.Request, path string, payload map[string]string) {
	url := expandVars(path, baseURL, payload)
	method := rq.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	bodyStr := expandVars(rq.Body, baseURL, payload)
	if bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return
	}
	for k, v := range rq.Headers {
		req.Header.Set(k, expandVars(v, baseURL, payload))
	}
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}
	if e.cfg.Cookies != "" {
		req.Header.Set("Cookie", e.cfg.Cookies)
	}
	if method == "POST" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	headerStr := flattenHeader(resp.Header)
	status := resp.StatusCode
	resp.Body.Close()

	matched := Matches(&rq, status, body, headerStr)
	if !matched {
		return
	}

	if e.cfg.VerifyGate {
		if !verify.ThreeGate(e.client.HTTP(), req, resp, body, e.cfg.Timeout) {
			return
		}
	}

	extracted := Extract(&rq, body, headerStr)
	pl := ""
	if len(payload) > 0 {
		parts := make([]string, 0, len(payload))
		for k, v := range payload {
			parts = append(parts, k+"="+v)
		}
		pl = strings.Join(parts, "&")
	}
	e.mu.Lock()
	e.results = append(e.results, template.MatchResult{
		TemplateID: tpl.ID,
		Severity:   tpl.Info.Severity,
		Matched:    url,
		Extracted:  extracted,
		StatusCode: status,
		Verified:   true,
		Payload:    pl,
	})
	e.mu.Unlock()
}

func flattenHeader(h http.Header) string {
	var sb strings.Builder
	for k, v := range h {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(v, ", "))
		sb.WriteString("\n")
	}
	return sb.String()
}

// FormatResults renders results as text.
func FormatResults(results []template.MatchResult) string {
	var sb strings.Builder
	if len(results) == 0 {
		sb.WriteString("[-] 未发现匹配\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("[+] 发现 %d 个已验证匹配:\n", len(results)))
	for _, r := range results {
		sev := r.Severity
		if sev == "" {
			sev = "info"
		}
		pl := ""
		if r.Payload != "" {
			pl = " [" + r.Payload + "]"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s (%s) 已验证%s\n", sev, r.Matched, r.TemplateID, pl))
		for _, ex := range r.Extracted {
			sb.WriteString(fmt.Sprintf("      提取: %s\n", ex))
		}
	}
	return sb.String()
}
