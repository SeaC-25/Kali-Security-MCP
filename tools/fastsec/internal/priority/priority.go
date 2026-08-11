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
	// ID/对象型（越权高发）
	{"id", 10, "ID 型参数最可能直接暴露对象"},
	{"userId", 12, "用户 ID，越权高发"},
	{"user_id", 12, "用户 ID，越权高发"},
	{"uid", 12, "用户 ID，越权高发"},
	{"userid", 12, "用户 ID，越权高发"},
	{"account", 10, "账户参数，横向越权"},
	{"accountId", 10, "账户 ID，横向越权"},
	{"account_id", 10, "账户 ID，横向越权"},
	{"order", 10, "订单 ID，业务越权"},
	{"orderId", 10, "订单 ID，业务越权"},
	{"order_id", 10, "订单 ID，业务越权"},
	{"orderNo", 10, "订单号，业务越权"},
	{"order_no", 10, "订单号，业务越权"},
	{"email", 10, "邮箱，PII 越权"},
	{"mobile", 10, "手机号，PII 越权"},
	{"phone", 10, "手机号，PII 越权"},
	{"tel", 10, "电话，PII 越权"},
	{"username", 10, "用户名，账号枚举"},
	{"nickname", 7, "昵称，信息泄露"},
	{"name", 6, "姓名，PII"},
	{"realname", 9, "真实姓名，PII 越权"},
	{"real_name", 9, "真实姓名，PII 越权"},
	// 文件型
	{"file", 9, "文件参数，可能路径穿越"},
	{"filename", 9, "文件参数，可能路径穿越"},
	{"file_name", 9, "文件参数，可能路径穿越"},
	{"download", 9, "下载参数，可能任意文件"},
	{"upload", 9, "上传参数，可能任意文件上传"},
	{"attachment", 8, "附件参数，可能任意文件"},
	{"image", 7, "图片参数，可能路径穿越"},
	{"img", 7, "图片参数，可能路径穿越"},
	{"avatar", 7, "头像参数，可能路径穿越"},
	// 路径/URL 型
	{"path", 8, "路径参数，可能穿越"},
	{"url", 8, "URL 参数，可能 SSRF"},
	{"link", 8, "链接参数，可能 SSRF"},
	{"src", 8, "资源参数，可能 SSRF"},
	{"href", 8, "链接参数，可能 SSRF"},
	{"redirect", 8, "跳转参数，可能开放重定向"},
	{"next", 8, "跳转参数，可能开放重定向"},
	{"return", 6, "返回参数，可能重定向"},
	{"returnUrl", 8, "返回 URL，可能开放重定向"},
	{"return_url", 8, "返回 URL，可能开放重定向"},
	{"callback", 8, "回调参数，可能 SSRF/反射"},
	{"webhook", 8, "Webhook，可能 SSRF"},
	{"target", 8, "目标参数，可能 SSRF"},
	{"host", 8, "主机参数，可能 SSRF"},
	{"domain", 7, "域名参数，可能 SSRF"},
	// 认证/会话
	{"token", 9, "令牌参数，可能泄露"},
	{"session", 8, "会话参数"},
	{"sessionId", 8, "会话 ID"},
	{"session_id", 8, "会话 ID"},
	{"cookie", 7, "Cookie 参数"},
	{"auth", 8, "认证参数"},
	{"authorization", 8, "认证头参数"},
	{"apikey", 9, "API 密钥，高危"},
	{"api_key", 9, "API 密钥，高危"},
	{"key", 7, "密钥参数"},
	{"secret", 9, "密钥参数，高危"},
	{"password", 9, "密码参数"},
	{"pwd", 9, "密码参数"},
	{"pass", 9, "密码参数"},
	{"code", 7, "验证码/授权码"},
	{"verifyCode", 7, "验证码"},
	{"verify_code", 7, "验证码"},
	// 业务型
	{"price", 9, "价格参数，逻辑漏洞"},
	{"amount", 9, "金额参数，逻辑漏洞"},
	{"balance", 9, "余额参数，逻辑漏洞"},
	{"quantity", 7, "数量参数，逻辑漏洞"},
	{"count", 5, "数量参数"},
	{"coupon", 8, "优惠券参数，逻辑漏洞"},
	{"discount", 8, "折扣参数，逻辑漏洞"},
	{"points", 7, "积分参数，逻辑漏洞"},
	{"score", 6, "分数参数"},
	{"credit", 8, "信用/积分参数"},
	{"role", 9, "角色参数，越权"},
	{"permission", 8, "权限参数"},
	{"level", 7, "等级参数"},
	{"status", 6, "状态参数"},
	{"type", 5, "类型参数"},
	{"category", 3, "分类参数，低价值"},
	// 查询型（低价值）
	{"page", 4, "分页参数，低价值"},
	{"pageSize", 3, "分页大小，低价值"},
	{"page_size", 3, "分页大小，低价值"},
	{"limit", 3, "限制参数，低价值"},
	{"offset", 3, "偏移参数，低价值"},
	{"sort", 3, "排序参数，低价值"},
	{"orderBy", 3, "排序参数，低价值"},
	{"order_by", 3, "排序参数，低价值"},
	{"search", 2, "搜索参数，最低价值"},
	{"q", 2, "搜索参数，最低价值"},
	{"keyword", 2, "搜索参数，最低价值"},
	{"query", 3, "查询参数"},
	{"lang", 2, "语言参数，最低价值"},
	{"locale", 2, "语言参数，最低价值"},
	{"format", 3, "格式参数"},
	{"action", 4, "动作参数"},
	{"method", 3, "方法参数"},
	{"mode", 3, "模式参数"},
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
