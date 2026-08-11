// Package engine: concurrent HTTP scanning with nuclei-compatible templates,
// stealth transport and 3-gate confirmation (baseline vs attack).
package engine

import (
	"fmt"
	"io"
	"net/http"
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
			for _, path := range req.Path {
				wg.Add(1)
				sem <- struct{}{}
				go func(t *template.Template, rq template.Request, p string) {
					defer wg.Done()
					defer func() { <-sem }()
					e.scanOne(baseURL, t, rq, p)
				}(tpl, req, path)
			}
		}
	}
	wg.Wait()
	return e.results
}

func (e *Engine) scanOne(baseURL string, tpl *template.Template, rq template.Request, path string) {
	url := strings.ReplaceAll(path, "{{BaseURL}}", baseURL)
	method := rq.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if rq.Body != "" {
		bodyReader = strings.NewReader(rq.Body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return
	}
	for k, v := range rq.Headers {
		req.Header.Set(k, v)
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

	// 3-gate confirmation: 只有验证通过的才上报（零误报核心）
	if e.cfg.VerifyGate {
		if !verify.ThreeGate(e.client.HTTP(), req, resp, body, e.cfg.Timeout) {
			return
		}
	}

	extracted := Extract(&rq, body, headerStr)
	e.mu.Lock()
	e.results = append(e.results, template.MatchResult{
		TemplateID: tpl.ID,
		Severity:   tpl.Info.Severity,
		Matched:    url,
		Extracted:  extracted,
		StatusCode: status,
		Verified:   true,
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
		sb.WriteString(fmt.Sprintf("  [%s] %s (%s) 已验证\n", sev, r.Matched, r.TemplateID))
		for _, ex := range r.Extracted {
			sb.WriteString(fmt.Sprintf("      提取: %s\n", ex))
		}
	}
	return sb.String()
}
