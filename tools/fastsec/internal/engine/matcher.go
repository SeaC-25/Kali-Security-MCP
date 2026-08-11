package engine

import (
	"regexp"
	"strconv"
	"strings"

	"fastsec/internal/template"
)

// Matches evaluates all matchers of a request against a response.
func Matches(req *template.Request, statusCode int, body []byte, header string) bool {
	if len(req.Matchers) == 0 {
		// 无 matcher: 仅 2xx 算匹配（避免把 404/5xx 当信息泄露上报）
		return statusCode >= 200 && statusCode < 300
	}
	all := req.Matchers
	if len(all) > 0 && all[0].Condition == "or" {
		for _, m := range all {
			if matchOne(m, statusCode, body, header) {
				return true
			}
		}
		return false
	}
	for _, m := range all {
		if !matchOne(m, statusCode, body, header) {
			return false
		}
	}
	return true
}

func matchOne(m template.Matcher, statusCode int, body []byte, header string) bool {
	var hay string
	switch m.Part {
	case "header":
		hay = header
	case "status_code":
		hay = strconv.Itoa(statusCode)
	default:
		hay = string(body)
	}

	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if statusCode == s {
				return true
			}
		}
		return false
	case "word":
		for _, w := range m.Words {
			if strings.Contains(hay, w) {
				return true
			}
		}
		return false
	case "regex":
		for _, r := range m.Regex {
			re, err := regexp.Compile(r)
			if err != nil {
				continue
			}
			if re.MatchString(hay) {
				return true
			}
		}
		return false
	case "dsl":
		// nuclei DSL subset: status_code ==/!=/>/>=/</<= N,
		// contains(body, "x"), len(body) > N, && || !, parentheses
		for _, expr := range m.Regex {
			if evalDSL(expr, statusCode, hay) {
				return true
			}
		}
		return false
	case "binary":
		for _, r := range m.Regex {
			if strings.Contains(hay, r) {
				return true
			}
		}
		return false
	}
	return false
}

// evalDSL evaluates a nuclei-style DSL expression.
// Supports: status_code, body, header variables; == != > < >= <=;
// contains(v, "s"); len(v) > N; && || ! ( ) 
func evalDSL(expr string, statusCode int, body string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}
	// tokenize top-level && and || (not inside parens)
	if idx := findOp(expr, "||"); idx >= 0 {
		return evalDSL(expr[:idx], statusCode, body) || evalDSL(expr[idx+2:], statusCode, body)
	}
	if idx := findOp(expr, "&&"); idx >= 0 {
		return evalDSL(expr[:idx], statusCode, body) && evalDSL(expr[idx+2:], statusCode, body)
	}
	// unwrap outer parens
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && balanced(expr[1:len(expr)-1]) {
		expr = expr[1 : len(expr)-1]
	}
	if strings.HasPrefix(expr, "!") {
		return !evalDSL(expr[1:], statusCode, body)
	}
	// comparison ops
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if idx := strings.Index(expr, op); idx >= 0 {
			left := strings.TrimSpace(expr[:idx])
			right := strings.TrimSpace(expr[idx+len(op):])
			return compareValue(left, right, op, statusCode, body)
		}
	}
	// bare variable truthiness
	if strings.TrimSpace(expr) == "status_code" {
		return statusCode > 0
	}
	return false
}

func compareValue(left, right, op string, statusCode int, body string) bool {
	// functions on left: contains(body, "x"), len(body)
	if strings.HasPrefix(left, "contains(") && strings.HasSuffix(left, ")") {
		inner := left[len("contains(") : len(left)-1]
		parts := splitFuncArgs(inner)
		if len(parts) == 2 {
			val := valueOf(strings.TrimSpace(parts[0]), statusCode, body)
			needle := unquoteStr(strings.TrimSpace(parts[1]))
			res := strings.Contains(val, needle)
			rhs := parseBool(strings.TrimSpace(right))
			switch op {
			case "==":
				return res == rhs
			case "!=":
				return res != rhs
			}
		}
		return false
	}
	if strings.HasPrefix(left, "len(") && strings.HasSuffix(left, ")") {
		inner := left[len("len(") : len(left)-1]
		val := valueOf(strings.TrimSpace(inner), statusCode, body)
		lv := float64(len(val))
		rv, err := strconv.ParseFloat(strings.TrimSpace(right), 64)
		if err != nil {
			return false
		}
		switch op {
		case "==":
			return lv == rv
		case "!=":
			return lv != rv
		case ">":
			return lv > rv
		case "<":
			return lv < rv
		case ">=":
			return lv >= rv
		case "<=":
			return lv <= rv
		}
		return false
	}
	// numeric comparison
	lv, lerr := strconv.ParseFloat(valueOf(strings.TrimSpace(left), statusCode, body), 64)
	rv, rerr := strconv.ParseFloat(strings.TrimSpace(right), 64)
	if lerr == nil && rerr == nil {
		switch op {
		case "==":
			return lv == rv
		case "!=":
			return lv != rv
		case ">":
			return lv > rv
		case "<":
			return lv < rv
		case ">=":
			return lv >= rv
		case "<=":
			return lv <= rv
		}
	}
	// string comparison
	ls := valueOf(strings.TrimSpace(left), statusCode, body)
	rs := unquoteStr(strings.TrimSpace(right))
	switch op {
	case "==":
		return ls == rs
	case "!=":
		return ls != rs
	}
	return false
}

func valueOf(v string, statusCode int, body string) string {
	switch v {
	case "status_code":
		return strconv.Itoa(statusCode)
	case "body":
		return body
	case "header":
		return body // header not separately stored; body approximation
	default:
		return v
	}
}

func parseBool(s string) bool {
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func unquoteStr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func splitFuncArgs(s string) []string {
	var parts []string
	depth := 0
	cur := ""
	for _, c := range s {
		switch c {
		case '(':
			depth++
			cur += string(c)
		case ')':
			depth--
			cur += string(c)
		case ',':
			if depth == 0 {
				parts = append(parts, cur)
				cur = ""
			} else {
				cur += string(c)
			}
		default:
			cur += string(c)
		}
	}
	if strings.TrimSpace(cur) != "" {
		parts = append(parts, cur)
	}
	return parts
}

// findOp finds an operator at top nesting level (depth 0), outside quotes.
func findOp(s, op string) int {
	depth := 0
	inQuote := byte(0)
	for i := 0; i <= len(s)-len(op); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
			continue
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
		}
		if depth == 0 && s[i:i+len(op)] == op {
			return i
		}
	}
	return -1
}

func balanced(s string) bool {
	d := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			d++
		case ')':
			d--
			if d < 0 {
				return false
			}
		}
	}
	return d == 0
}

// Extract pulls data from a response per extractors.
func Extract(req *template.Request, body []byte, header string) []string {
	var out []string
	for _, ex := range req.Extractors {
		var hay string
		switch ex.Part {
		case "header":
			hay = header
		default:
			hay = string(body)
		}
		switch ex.Type {
		case "regex":
			for _, r := range ex.Regex {
				re, err := regexp.Compile(r)
				if err != nil {
					continue
				}
				groups := re.FindStringSubmatch(hay)
				if len(groups) > 0 {
					idx := ex.Group
					if idx < 0 || idx >= len(groups) {
						idx = 1
					}
					if idx < len(groups) {
						out = append(out, groups[idx])
					}
				}
			}
		case "word":
			for _, w := range ex.Words {
				if strings.Contains(hay, w) {
					out = append(out, w)
				}
			}
		}
	}
	return out
}
