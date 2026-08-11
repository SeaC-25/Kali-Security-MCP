// Package diff: behavioral difference detection engine.
package diff

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fastsec/internal/stealth"
)

// Config for difference scanning.
type Config struct {
	Concurrency int
	Timeout     time.Duration
	DelayMinMs  int
	DelayMaxMs  int
	Proxy       string
	Mutations   []string
	Headers     map[string]string
}

func DefaultConfig() *Config {
	return &Config{
		Concurrency: 10,
		Timeout:     10 * time.Second,
		DelayMinMs:  100,
		DelayMaxMs:  300,
		Mutations: []string{
			"1", "2", "0", "-1", "999999", "1'", "true", "false",
			"null", "admin", "guest", "other", "999",
		},
		Headers: map[string]string{},
	}
}

// Finding describes a behavioral difference.
type Finding struct {
	URL       string
	Param     string
	BaseResp  string
	Mutations []Diff
	Severity  string
}

type Diff struct {
	Value       string
	StatusDiff  bool
	StatusBase  int
	StatusNew   int
	BodyDiff    bool
	BodyLenBase int
	BodyLenNew  int
}

type fingerprint struct {
	status int
	length int
	sample string
}

func fpOf(status int, body []byte) fingerprint {
	sample := ""
	if len(body) > 64 {
		sample = string(body[:64])
	} else {
		sample = string(body)
	}
	return fingerprint{status: status, length: len(body), sample: sample}
}

func get(client *stealth.Client, u string, headers map[string]string) (int, []byte) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return resp.StatusCode, body
}

func scanParam(client *stealth.Client, baseURL, param, value string, cfg *Config, sem chan struct{}, results chan<- Finding, wg *sync.WaitGroup) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	base := mutate(baseURL, param, value)
	bresp, bbody := get(client, base, cfg.Headers)
	if bresp == 0 {
		return
	}
	bfp := fpOf(bresp, bbody)

	var diffs []Diff
	for _, m := range cfg.Mutations {
		if m == value {
			continue
		}
		u := mutate(baseURL, param, m)
		s, body := get(client, u, cfg.Headers)
		if s == 0 {
			continue
		}
		nfp := fpOf(s, body)
		statusDiff := s != bfp.status
		bodyDiff := nfp.length != bfp.length || (bfp.sample != "" && nfp.sample != bfp.sample)
		if statusDiff || bodyDiff {
			diffs = append(diffs, Diff{
				Value:       m,
				StatusDiff:  statusDiff,
				StatusBase:  bfp.status,
				StatusNew:   s,
				BodyDiff:    bodyDiff,
				BodyLenBase: bfp.length,
				BodyLenNew:  nfp.length,
			})
		}
	}
	if len(diffs) > 0 {
		results <- Finding{
			URL:       base,
			Param:     param,
			BaseResp:  fmt.Sprintf("status=%d len=%d", bfp.status, bfp.length),
			Mutations: diffs,
			Severity:  "medium",
		}
	}
}

func mutate(baseURL, param, value string) string {
	u, err := url.Parse(baseURL)
	if err == nil {
		q := u.Query()
		q.Set(param, value)
		u.RawQuery = q.Encode()
		return u.String()
	}
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	return baseURL + sep + url.QueryEscape(param) + "=" + url.QueryEscape(value)
}

// Scan runs difference detection against a URL.
func Scan(baseURL string, baseParams []string, cfg *Config) []Finding {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	client := stealth.NewClient(cfg.Proxy, stealth.NewThrottle(cfg.DelayMinMs, cfg.DelayMaxMs), cfg.Concurrency)
	sem := make(chan struct{}, cfg.Concurrency)
	results := make(chan Finding, 256)
	var wg sync.WaitGroup

	for _, p := range baseParams {
		wg.Add(1)
		go scanParam(client, baseURL, p, "1", cfg, sem, results, &wg)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	var out []Finding
	for f := range results {
		out = append(out, f)
	}
	return out
}

// Format renders findings as text.
func Format(fs []Finding) string {
	var sb strings.Builder
	if len(fs) == 0 {
		sb.WriteString("[-] 无行为差异（参数未暴露数据）\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("[+] 发现 %d 个行为差异（潜在 IDOR/越权/逻辑漏洞）:\n", len(fs)))
	for _, f := range fs {
		sb.WriteString(fmt.Sprintf("  [%s] %s\n", f.Severity, f.URL))
		sb.WriteString(fmt.Sprintf("        基线: %s\n", f.BaseResp))
		for _, d := range f.Mutations {
			mark := ""
			if d.StatusDiff {
				mark = fmt.Sprintf(" 状态 %d→%d", d.StatusBase, d.StatusNew)
			}
			if d.BodyDiff {
				mark += fmt.Sprintf(" 长度 %d→%d", d.BodyLenBase, d.BodyLenNew)
			}
			sb.WriteString(fmt.Sprintf("        %s=%s →%s\n", f.Param, d.Value, mark))
		}
	}
	return sb.String()
}
