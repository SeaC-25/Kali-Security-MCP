// Package dir: smart directory enumeration.
// JS 端点预提取 + 3-gate 通配过滤（Go）。
package dir

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"fastsec/internal/stealth"
)

// Result: 目录枚举结果
type Result struct {
	BaseURL  string
	Findings []Finding
}

// Finding: 确认路径
type Finding struct {
	Path   string
	Status int
	Len    int
}

// JS API 路径提取正则
var jsPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'](/api/[^"']{2,80})["']`),
	regexp.MustCompile(`["'](/v\d+/[^"']{2,80})["']`),
	regexp.MustCompile(`["'](/admin[^"']{2,60})["']`),
	regexp.MustCompile(`["'](/user[^"']{2,60})["']`),
	regexp.MustCompile(`["'](/manage[^"']{2,60})["']`),
	regexp.MustCompile(`["'](/login[^"']{2,40})["']`),
	regexp.MustCompile(`["'](/config[^"']{2,40})["']`),
	regexp.MustCompile(`["'](/\.git[^"']{2,40})["']`),
}

// ExtractJSEndpoints: 拉首页 → 找 JS → 提取 API 路径
func ExtractJSEndpoints(baseURL string, cli *stealth.Client) []string {
	endpoints := map[string]bool{}
	html := get(baseURL, cli)
	jsFiles := regexp.MustCompile(`(?:src|href)="([^"]+\.js[^"]*)"`).FindAllStringSubmatch(html, -1)
	for _, m := range jsFiles[:min(len(jsFiles), 5)] {
		jsURL := m[1]
		if !strings.HasPrefix(jsURL, "http") {
			jsURL = strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimPrefix(jsURL, "/")
		}
		jsContent := get(jsURL, cli)
		for _, pat := range jsPatterns {
			for _, mm := range pat.FindAllStringSubmatch(jsContent, -1) {
				p := mm[1]
				if p != "" && !strings.HasSuffix(p, ".js") && !strings.HasSuffix(p, ".css") {
					endpoints[p] = true
				}
			}
		}
	}
	out := make([]string, 0, len(endpoints))
	for k := range endpoints {
		out = append(out, k)
	}
	return out
}

func get(u string, cli *stealth.Client) string {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}
	resp, err := cli.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return string(body)
}

func probe(u string, cli *stealth.Client) (int, int) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, 0
	}
	resp, err := cli.Do(req)
	if err != nil {
		return 0, 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	resp.Body.Close()
	return resp.StatusCode, len(body)
}

// Scan: 智能目录枚举
func Scan(baseURL string, wordlist []string, cli *stealth.Client, maxPaths int) Result {
	res := Result{BaseURL: baseURL}

	// D1: JS 端点
	jsEndpoints := ExtractJSEndpoints(baseURL, cli)
	fmt.Printf("[dir] D1 JS 提取 %d 个端点\n", len(jsEndpoints))

	// 合并候选
	var candidates []string
	candidates = append(candidates, jsEndpoints...)
	for _, p := range wordlist {
		if strings.HasPrefix(p, "/") {
			candidates = append(candidates, p)
		}
	}
	if maxPaths > 0 && len(candidates) > maxPaths {
		candidates = candidates[:maxPaths]
	}

	// D2: 3-gate 基线（404 默认）
	baseStatus, baseLen := probe(strings.TrimSuffix(baseURL, "/")+"/__dir_probe_404__", cli)
	fmt.Printf("[dir] 基线(404): status=%d len=%d\n", baseStatus, baseLen)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	for _, path := range candidates {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			u := strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimPrefix(p, "/")
			status, blen := probe(u, cli)
			// 3-gate: 状态不同 或 长度差异 >20% = 真路径
			isReal := false
			if status != baseStatus {
				isReal = true
			} else if baseLen > 0 && abs(blen-baseLen) > baseLen/5 {
				isReal = true
			}
			if isReal && (status == 200 || status == 301 || status == 302 || status == 403) {
				mu.Lock()
				res.Findings = append(res.Findings, Finding{Path: p, Status: status, Len: blen})
				mu.Unlock()
				fmt.Printf("  [+] %d %s (%dB)\n", status, p, blen)
			}
		}(path)
	}
	wg.Wait()
	return res
}

// Format: 渲染结果
func Format(r Result) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[dir] %d confirmed paths on %s\n", len(r.Findings), r.BaseURL))
	for _, f := range r.Findings {
		sb.WriteString(fmt.Sprintf("  %d %s (%dB)\n", f.Status, f.Path, f.Len))
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
