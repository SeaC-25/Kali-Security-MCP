// Package osint: multi-source OSINT aggregation + priority ranking.
// 从 HTML/JSON 响应提取 email/subdomain/host（Go 原生，替代 theharvester 等外部工具）。
package osint

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"fastsec/internal/stealth"
)

// Sources: OSINT 数据源（公开 API，无需 key）——多源聚合
var Sources = []string{
	"https://crt.sh/?q=%s&output=json",                  // 证书透明度（子域/邮箱）
	"https://api.hackertarget.com/hostsearch/?q=%s",     // 子域
	"https://api.hackertarget.com/dnslookup/?q=%s",      // DNS
	"https://api.hackertarget.com/reverseiplookup/?q=%s", // 反查 IP
	"https://crt.sh/?q=%%25.%s&output=json",              // 泛域名证书
	"https://api.hackertarget.com/subnetcalc/?q=%s",     // 子网
	"https://api.hackertarget.com/zonetransfer/?q=%s",   // DNS 域传送
	"https://api.hackertarget.com/mtr/?q=%s",            // 路由
	"https://api.hackertarget.com/ping/?q=%s",           // 存活
}

// Result: 聚合结果
type Result struct {
	Domain     string
	Emails     []string
	Subdomains []string
	Priority   []Item
}

// Item: 优先级条目
type Item struct {
	Type  string // email | subdomain
	Value string
}

var emailRe = regexp.MustCompile(`[\w.+-]+@[\w.-]+\.\w+`)
var subdomainRe = regexp.MustCompile(`(?:[\w-]+\.)+`)

// fetch: GET 数据源
func fetch(url string, cli *stealth.Client) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	resp, err := cli.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	resp.Body.Close()
	return string(body)
}

// Aggregate: 多源聚合 + 去重 + 排序
func Aggregate(domain string, cli *stealth.Client) Result {
	res := Result{Domain: domain}
	// 域名校验：非空 + 合法格式
	if domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " /") {
		return res
	}
	emails := map[string]bool{}
	subdomains := map[string]bool{}

	// crt.sh（证书透明度，JSON）
	body := fetch(fmt.Sprintf(Sources[0], domain), cli)
	for _, m := range emailRe.FindAllString(body, -1) {
		emails[strings.ToLower(m)] = true
	}
	// 多源子域提取（hackertarget + 反查 + 泛域名）
	for _, srcIdx := range []int{1, 4} {
		bodyN := fetch(fmt.Sprintf(Sources[srcIdx], domain), cli)
		for _, line := range strings.Split(bodyN, "\n") {
			host := strings.Split(line, ",")[0]
			host = strings.TrimSpace(host)
			host = strings.TrimPrefix(host, "*.")
			if strings.HasSuffix(host, "."+domain) || strings.Contains(host, domain) {
				subdomains[host] = true
			}
		}
	}
	// DNS 查询结果
	body3 := fetch(fmt.Sprintf(Sources[2], domain), cli)
	for _, m := range regexp.MustCompile(`([\w-]+\.)+`+regexp.QuoteMeta(domain)).FindAllString(body3, -1) {
		subdomains[strings.TrimSpace(m)] = true
	}
	// 从 crt.sh JSON 提取子域
	for _, m := range regexp.MustCompile(`"name_value":"([^"]+)"`).FindAllStringSubmatch(body, -1) {
		for _, name := range strings.Split(m[1], "\n") {
			name = strings.TrimSpace(name)
			if strings.HasSuffix(name, "."+domain) {
				subdomains[name] = true
			}
		}
	}

	// 优先级: email > subdomain
	var items []Item
	for e := range emails {
		items = append(items, Item{Type: "email", Value: e})
	}
	for s := range subdomains {
		items = append(items, Item{Type: "subdomain", Value: s})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Type != items[j].Type {
			return items[i].Type == "email"
		}
		return items[i].Value < items[j].Value
	})

	res.Emails = sortedKeys(emails)
	res.Subdomains = sortedKeys(subdomains)
	res.Priority = items
	return res
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Format: 渲染
func Format(r Result) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[osint] %s: %d emails, %d subdomains\n", r.Domain, len(r.Emails), len(r.Subdomains)))
	for _, it := range r.Priority[:min(len(r.Priority), 15)] {
		sb.WriteString(fmt.Sprintf("  [%s] %s\n", it.Type, it.Value))
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
