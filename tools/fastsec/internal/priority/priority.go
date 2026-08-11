// Package priority: parameter prioritization engine.
// 对 diff 候选参数自动分级打分——参数名语义权重 + 变异差异度。
// 输出"最值得深挖的 Top N"，让 AI/人在海量候选中聚焦。
package priority

import (
	"fmt"
	"sort"
	"strings"
)

// Score of a discovered parameter.
type Score struct {
	Param    string
	URL      string
	Score    int
	Reason   []string
	Severity string
}

// Param name semantic weights (Chinese/English targets common).
var nameWeights = []struct {
	pattern string
	weight  int
	reason  string
}{
	{"id", 10, "ID 型参数最可能直接暴露对象"},
	{"userId", 12, "用户 ID，越权高发"},
	{"user_id", 12, "用户 ID，越权高发"},
	{"uid", 12, "用户 ID，越权高发"},
	{"account", 10, "账户参数，横向越权"},
	{"order", 10, "订单 ID，业务越权"},
	{"orderId", 10, "订单 ID，业务越权"},
	{"order_id", 10, "订单 ID，业务越权"},
	{"email", 10, "邮箱，PII 越权"},
	{"mobile", 10, "手机号，PII 越权"},
	{"phone", 10, "手机号，PII 越权"},
	{"file", 9, "文件参数，可能路径穿越"},
	{"filename", 9, "文件参数，可能路径穿越"},
	{"download", 9, "下载参数，可能任意文件"},
	{"path", 8, "路径参数，可能穿越"},
	{"page", 4, "分页参数，低价值"},
	{"sort", 3, "排序参数，低价值"},
	{"category", 3, "分类参数，低价值"},
	{"search", 2, "搜索参数，最低价值"},
	{"q", 2, "搜索参数，最低价值"},
	{"keyword", 2, "搜索参数，最低价值"},
	{"lang", 2, "语言参数，最低价值"},
	{"callback", 8, "回调参数，可能 SSRF/反射"},
	{"url", 8, "URL 参数，可能 SSRF"},
	{"next", 8, "跳转参数，可能开放重定向"},
	{"redirect", 8, "跳转参数，可能开放重定向"},
	{"return", 6, "返回参数，可能重定向"},
}

// mutationWeights: 变异差异的类型权重（状态码变化 > 长度变化 > 样本变化）
const (
	weightStatusDiff = 6
	weightBodyDiff   = 3
	weightSampleDiff = 1
)

// ScoreDiffs scores discovered diff findings.
// findings: map[param] -> list of deviation descriptions (from diff engine)
func ScoreDiffs(findings map[string][]string) []Score {
	var out []Score
	for param, devs := range findings {
		s := Score{Param: param, Score: 0}
		// name weight
		matchedName := false
		for _, nw := range nameWeights {
			if strings.Contains(strings.ToLower(param), nw.pattern) {
				s.Score += nw.weight
				s.Reason = append(s.Reason, nw.reason)
				matchedName = true
				break
			}
		}
		if !matchedName {
			s.Score += 3
			s.Reason = append(s.Reason, "未知参数名，保守分值")
		}
		// mutation deviation weight
		for _, d := range devs {
			dl := strings.ToLower(d)
			if strings.Contains(dl, "status") {
				s.Score += weightStatusDiff
			}
			if strings.Contains(dl, "len") {
				s.Score += weightBodyDiff
			}
		}
		// severity
		switch {
		case s.Score >= 20:
			s.Severity = "critical"
		case s.Score >= 14:
			s.Severity = "high"
		case s.Score >= 9:
			s.Severity = "medium"
		default:
			s.Severity = "low"
		}
		out = append(out, s)
	}
	// sort by score desc
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// Format renders prioritized params.
func Format(scores []Score, topN int) string {
	var sb strings.Builder
	if len(scores) == 0 {
		sb.WriteString("[-] 无可排序参数\n")
		return sb.String()
	}
	if topN <= 0 || topN > len(scores) {
		topN = len(scores)
	}
	sb.WriteString(fmt.Sprintf("[+] 参数优先级 Top %d（值得优先深挖）:\n", topN))
	for i, s := range scores[:topN] {
		sb.WriteString(fmt.Sprintf("  #%d [%s] %s  (score=%d)\n", i+1, s.Severity, s.Param, s.Score))
		for _, r := range s.Reason {
			sb.WriteString(fmt.Sprintf("      · %s\n", r))
		}
	}
	return sb.String()
}
