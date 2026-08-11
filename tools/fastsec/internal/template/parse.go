package template

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseFile loads one template YAML file (nuclei subset, zero-dep parser).
func ParseFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(data), path)
}

// Parse parses template YAML text into a Template.
func Parse(text, path string) (*Template, error) {
	t := &Template{Path: path}
	lines := strings.Split(text, "\n")
	var section string
	var curReq *Request
	var curMatch *Matcher
	var curExt *Extractor

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			switch {
			case trimmed == "info:":
				section = "info"
			case trimmed == "requests:":
				section = "requests"
			default:
				section = ""
			}
			continue
		}
		if section == "info" && indent == 2 {
			key, val, ok := splitKV(trimmed)
			if !ok {
				continue
			}
			switch key {
			case "name":
				t.Info.Name = unquote(val)
			case "severity":
				t.Info.Severity = unquote(val)
			case "author":
				t.Info.Author = unquote(val)
			}
			continue
		}
		if section == "requests" || section == "request" {
			// new request item at indent 2: "- method: GET" or "- raw:"
			if indent == 2 && strings.HasPrefix(trimmed, "- ") {
				body := strings.TrimSpace(trimmed[2:])
				// strip trailing colon for labeled items like "- request:"
				label := strings.TrimSuffix(body, ":")
				if label == "request" || label == "http" || label == "raw" || label == "" {
					t.Requests = append(t.Requests, Request{Method: "GET"})
					curReq = &t.Requests[len(t.Requests)-1]
					section = "request"
				} else if strings.HasPrefix(body, "method:") {
					// "- method: POST" inline
					t.Requests = append(t.Requests, Request{Method: "GET"})
					curReq = &t.Requests[len(t.Requests)-1]
					curReq.Method = unquote(strings.TrimSpace(body[len("method:"):]))
					section = "request"
				}
				continue
			}
			if indent == 2 {
				key, val, ok := splitKV(trimmed)
				if !ok {
					continue
				}
				switch key {
				case "method":
					if curReq != nil {
						curReq.Method = unquote(val)
					}
				case "body":
					if curReq != nil {
						curReq.Body = unquote(val)
					}
				case "stop-at-first-match":
					if curReq != nil {
						curReq.StopAtFirstMatch = val == "true"
					}
				}
				continue
			}
			if indent == 4 {
				key, val, ok := splitKV(trimmed)
				if !ok {
					continue
				}
				if key == "path" && curReq != nil {
					p := unquote(val)
					if p != "" {
						curReq.Path = append(curReq.Path, p)
					}
				}
				// 其他已知 4-indent 字段进入对应子区（matchers/extractors/headers）
				if key == "matchers:" && curReq != nil {
					section = "matchers"
				}
				if key == "extractors:" && curReq != nil {
					section = "extractors"
				}
				if key == "headers:" && curReq != nil {
					if curReq.Headers == nil {
						curReq.Headers = map[string]string{}
					}
					section = "headers"
				}
				continue
			}
			// path list items at indent 6: "      - {{BaseURL}}/x"
			if indent == 6 && strings.HasPrefix(trimmed, "- ") && curReq != nil && section == "request" {
				item := strings.TrimSpace(trimmed)
				item = strings.TrimPrefix(item, "- ")
				p := unquote(item)
				if p != "" && (strings.Contains(p, "{{BaseURL}}") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "http")) {
					curReq.Path = append(curReq.Path, p)
				}
				continue
			}
		}
		if section == "matchers" {
			if indent == 4 && strings.HasPrefix(trimmed, "- ") {
				curMatch = &Matcher{Part: "body"}
				if curReq != nil {
					curReq.Matchers = append(curReq.Matchers, *curMatch)
					curMatch = &curReq.Matchers[len(curReq.Matchers)-1]
				}
				continue
			}
			if curMatch == nil {
				continue
			}
			if indent == 6 {
				key, val, ok := splitKV(trimmed)
				if !ok {
					continue
				}
				switch key {
				case "type":
					curMatch.Type = unquote(val)
				case "part":
					curMatch.Part = unquote(val)
				case "condition":
					curMatch.Condition = unquote(val)
				case "status:":
					curMatch.Type = "status"
				case "words:":
					curMatch.Type = "word"
				case "regex:":
					curMatch.Type = "regex"
				}
				continue
			}
			if indent == 8 && curMatch != nil {
				item := strings.TrimSpace(trimmed)
				item = strings.TrimPrefix(item, "- ")
				item = unquote(item)
				if curMatch.Type == "status" {
					if n, err := strconv.Atoi(item); err == nil {
						curMatch.Status = append(curMatch.Status, n)
					}
				} else if curMatch.Type == "word" {
					curMatch.Words = append(curMatch.Words, item)
				} else if curMatch.Type == "regex" {
					curMatch.Regex = append(curMatch.Regex, item)
				}
			}
			if indent == 6 && strings.HasPrefix(trimmed, "- ") && curMatch != nil {
				item := strings.TrimPrefix(trimmed, "- ")
				item = unquote(item)
				if curMatch.Type == "status" {
					if n, err := strconv.Atoi(item); err == nil {
						curMatch.Status = append(curMatch.Status, n)
					}
				} else if curMatch.Type == "word" {
					curMatch.Words = append(curMatch.Words, item)
				} else if curMatch.Type == "regex" {
					curMatch.Regex = append(curMatch.Regex, item)
				}
			}
			continue
		}
		if section == "extractors" {
			if indent == 4 && strings.HasPrefix(trimmed, "- ") {
				curExt = &Extractor{Part: "body"}
				if curReq != nil {
					curReq.Extractors = append(curReq.Extractors, *curExt)
					curExt = &curReq.Extractors[len(curReq.Extractors)-1]
				}
				continue
			}
			if curExt == nil {
				continue
			}
			if indent == 6 {
				key, val, ok := splitKV(trimmed)
				if !ok {
					continue
				}
				switch key {
				case "type":
					curExt.Type = unquote(val)
				case "part":
					curExt.Part = unquote(val)
				case "group":
					if n, err := strconv.Atoi(unquote(val)); err == nil {
						curExt.Group = n
					}
				case "regex:":
					curExt.Type = "regex"
				case "words:":
					curExt.Type = "word"
				}
				continue
			}
			if indent == 8 && curExt != nil {
				item := unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				if curExt.Type == "regex" {
					curExt.Regex = append(curExt.Regex, item)
				} else if curExt.Type == "word" {
					curExt.Words = append(curExt.Words, item)
				}
			}
			continue
		}
		if section == "headers" && indent == 6 {
			key, val, ok := splitKV(trimmed)
			if ok && curReq != nil {
				curReq.Headers[key] = unquote(val)
			}
			continue
		}
	}
	if t.ID == "" {
		t.ID = strings.TrimSuffix(filepath.Base(path), ".yaml")
	}
	if len(t.Requests) == 0 {
		return nil, fmt.Errorf("no requests in template %s", path)
	}
	return t, nil
}

func splitKV(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	return key, val, true
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

// LoadDir loads all .yaml templates from a directory.
func LoadDir(dir string) ([]*Template, error) {
	var out []*Template
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		t, err := ParseFile(filepath.Join(dir, e.Name()))
		if err == nil {
			out = append(out, t)
		}
	}
	return out, nil
}
