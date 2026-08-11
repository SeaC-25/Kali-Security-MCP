// Package session: stateful attack sequence engine.
// nuclei 是单请求无状态匹配器；本引擎支持多步请求链：
//   Step1 登录 → 提取 token → Step2 带 token 访问受保护端点 → Step3 对比行为
// 会话通过 cookie jar 保持，变量在步骤间传递。纯代码、确定性、可审计。
package session

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"fastsec/internal/stealth"
)

// Step defines one request in the attack sequence.
type Step struct {
	Name    string            `yaml:"name"`
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	// Extract regexes from response body into variables (e.g. token)
	Extract map[string]string `yaml:"extract"`
	// Baseline check: which matchers must pass for this step to succeed
	MustContain []string `yaml:"must_contain"`
	// Compare mode: after this step, compare with baseline for behavioral diff
	DiffParams []string `yaml:"diff_params"`
	// Save the full response body to this variable
	SaveBody string `yaml:"save_body"`
}

// Config for a sequence run.
type Config struct {
	BaseURL     string
	Steps       []Step
	Concurrency int
	Timeout     time.Duration
	DelayMinMs  int
	DelayMaxMs  int
	Proxy       string
}

// Result of a sequence execution.
type Result struct {
	StepName   string
	URL        string
	StatusCode int
	BodyLen    int
	BodySnippet string
	Matched    bool
	Extracted  map[string]string
	Diff       []string // behavioral differences found (param -> deviation)
}

// Runner executes a multi-step sequence with session state.
type Runner struct {
	cfg     *Config
	client  *stealth.Client
	cookies *cookiejar.Jar
	vars    map[string]string
	mu      sync.Mutex
}

func New(cfg *Config) *Runner {
	jar, _ := cookiejar.New(nil)
	return &Runner{
		cfg:     cfg,
		cookies: jar,
		vars:    map[string]string{},
	}
}

// Run executes all steps in order, propagating session and extracted vars.
func (r *Runner) Run() []Result {
	var results []Result
	throttle := stealth.NewThrottle(r.cfg.DelayMinMs, r.cfg.DelayMaxMs)
	tr := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}
	if r.cfg.Proxy != "" {
		if pu, err := url.Parse(r.cfg.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	httpClient := &http.Client{Transport: tr, Timeout: r.cfg.Timeout, Jar: r.cookies}

	for _, step := range r.cfg.Steps {
		if throttle != nil {
			throttle.Wait()
		}
		res := r.execStep(httpClient, step)
		results = append(results, res)
		// behavioral diff for marked steps
		if len(step.DiffParams) > 0 && res.StatusCode > 0 {
			diffs := r.diffStep(httpClient, step, res)
			res.Diff = diffs
			results[len(results)-1] = res
		}
	}
	return results
}

func (r *Runner) execStep(client *http.Client, step Step) Result {
	path := r.expand(step.Path)
	method := step.Method
	if method == "" {
		method = "GET"
	}
	bodyStr := r.expand(step.Body)
	var bodyReader io.Reader
	if bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}
	req, err := http.NewRequest(method, r.cfg.BaseURL+path, bodyReader)
	if err != nil {
		return Result{StepName: step.Name, URL: path}
	}
	req.Header.Set("User-Agent", stealth.RandomUA())
	for k, v := range step.Headers {
		req.Header.Set(k, r.expand(v))
	}
	if method == "POST" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{StepName: step.Name, URL: path}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()

	res := Result{
		StepName:   step.Name,
		URL:        path,
		StatusCode: resp.StatusCode,
		BodyLen:    len(body),
		BodySnippet: string(body[:min(64, len(body))]),
		Extracted:  map[string]string{},
	}
	// must_contain check
	res.Matched = true
	for _, mc := range step.MustContain {
		if !strings.Contains(string(body), r.expand(mc)) {
			res.Matched = false
			break
		}
	}
	// extract variables
	for varName, regex := range step.Extract {
		re, err := regexp.Compile(regex)
		if err == nil {
			if m := re.FindStringSubmatch(string(body)); len(m) > 1 {
				r.mu.Lock()
				r.vars[varName] = m[1]
				r.mu.Unlock()
				res.Extracted[varName] = m[1]
			}
		}
	}
	if step.SaveBody != "" {
		r.mu.Lock()
		r.vars[step.SaveBody] = string(body)
		r.mu.Unlock()
	}
	return res
}

// diffStep mutates DiffParams and compares responses (behavioral diff on a stateful step).
func (r *Runner) diffStep(client *http.Client, step Step, base Result) []string {
	var out []string
	mutations := []string{"2", "0", "-1", "999999", "1'", "admin"}
	for _, param := range step.DiffParams {
		for _, m := range mutations {
			u := mutateParam(r.cfg.BaseURL+step.Path, param, m)
			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", stealth.RandomUA())
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			statusDiff := resp.StatusCode != base.StatusCode
			lenDiff := len(body) != base.BodyLen
			if statusDiff || lenDiff {
				out = append(out, fmt.Sprintf("%s=%s (status %d->%d len %d->%d)",
					param, m, base.StatusCode, resp.StatusCode, base.BodyLen, len(body)))
				break // one deviation per param is enough
			}
		}
	}
	return out
}

// expand substitutes {{var}} with session variables.
func (r *Runner) expand(s string) string {
	for k, v := range r.vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func mutateParam(baseURL, param, value string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Format renders sequence results.
func Format(results []Result) string {
	var sb strings.Builder
	sb.WriteString("[+] 状态化攻击序列执行结果:\n")
	for _, r := range results {
		mark := "✓"
		if !r.Matched {
			mark = "✗"
		}
		sb.WriteString(fmt.Sprintf("  %s %s %s -> %d (%dB)\n", mark, r.StepName, r.URL, r.StatusCode, r.BodyLen))
		for k, v := range r.Extracted {
			sb.WriteString(fmt.Sprintf("      提取 %s = %s\n", k, v))
		}
		for _, d := range r.Diff {
			sb.WriteString(fmt.Sprintf("      差异: %s\n", d))
		}
	}
	return sb.String()
}
