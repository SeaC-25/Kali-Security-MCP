package engine

import (
	"regexp"
	"strings"

	"fastsec/internal/template"
)

// Matches evaluates all matchers of a request against a response.
func Matches(req *template.Request, statusCode int, body []byte, header string) bool {
	if len(req.Matchers) == 0 {
		return statusCode >= 200 && statusCode < 500
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
		hay = itoa(statusCode)
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
	}
	return false
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
