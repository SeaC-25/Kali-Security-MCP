package template

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// yaml 结构（对齐 nuclei 官方模板）
type yamlTemplate struct {
	ID     string `yaml:"id"`
	Info   struct {
		Name     string      `yaml:"name"`
		Severity string      `yaml:"severity"`
		Tags     yamlStrList `yaml:"tags"`
		Author   string      `yaml:"author"`
	} `yaml:"info"`
	HTTP []yamlHTTP `yaml:"http"`
}

// yamlStrList accepts both "a,b,c" and ["a","b"].
type yamlStrList []string

func (y *yamlStrList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		*y = out
		return nil
	case yaml.SequenceNode:
		var arr []string
		if err := node.Decode(&arr); err != nil {
			return err
		}
		*y = arr
		return nil
	}
	return fmt.Errorf("unexpected yaml kind %d for string list", node.Kind)
}

type yamlHTTP struct {
	Method      string            `yaml:"method"`
	Path        []string          `yaml:"path"`
	Raw         []string          `yaml:"raw"`
	Headers     map[string]string `yaml:"headers"`
	Body        string            `yaml:"body"`
	Matchers    []yamlMatcher     `yaml:"matchers"`
	Extractors  []yamlExtractor   `yaml:"extractors"`
	Redirects   bool              `yaml:"redirects"`
	Payloads    map[string]yamlStrList `yaml:"payloads"`
	Attack      string            `yaml:"attack"`
	StopAtFirst bool              `yaml:"stop-at-first-match"`
}

type yamlMatcher struct {
	Type      string       `yaml:"type"`
	Words     []string     `yaml:"words"`
	Regex     []string     `yaml:"regex"`
	Status    []int        `yaml:"status"`
	Part      string       `yaml:"part"`
	Condition string       `yaml:"condition"`
	DSL       yamlStrList  `yaml:"dsl"`
}

type yamlExtractor struct {
	Type  string   `yaml:"type"`
	Regex []string `yaml:"regex"`
	Words []string `yaml:"words"`
	Part  string   `yaml:"part"`
	Group int      `yaml:"group"`
}

// ParseFile loads one nuclei-compatible template.
func ParseFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(data), path)
}

// Parse parses a nuclei-format template into our engine model.
func Parse(text, path string) (*Template, error) {
	var yt yamlTemplate
	if err := yaml.Unmarshal([]byte(text), &yt); err != nil {
		return nil, fmt.Errorf("yaml parse %s: %w", path, err)
	}
	t := &Template{
		ID:   yt.ID,
		Path: path,
		Info: Info{
			Name:     yt.Info.Name,
			Severity: yt.Info.Severity,
			Tags:     yt.Info.Tags,
			Author:   yt.Info.Author,
		},
	}
	if t.ID == "" {
		t.ID = strings.TrimSuffix(filepath.Base(path), ".yaml")
	}

	for _, h := range yt.HTTP {
		req := Request{
			Method:           h.Method,
			Headers:          h.Headers,
			Body:             h.Body,
			StopAtFirstMatch: h.StopAtFirst,
			Redirects:        h.Redirects,
			Attack:           h.Attack,
		}
		if req.Method == "" {
			req.Method = "GET"
		}
		// payloads
		if len(h.Payloads) > 0 {
			req.Payloads = map[string][]string{}
			for k, v := range h.Payloads {
				req.Payloads[k] = []string(v)
			}
		}
		if len(h.Path) > 0 {
			req.Path = append(req.Path, h.Path...)
		}
		for _, raw := range h.Raw {
			method, p, hdrs, body := parseRaw(raw)
			if method != "" && p != "" {
				req.Path = append(req.Path, p)
				req.Method = method
				for k, v := range hdrs {
					if req.Headers == nil {
						req.Headers = map[string]string{}
					}
					req.Headers[k] = v
				}
				if body != "" {
					req.Body = body
				}
			}
		}
		for _, m := range h.Matchers {
			mm := Matcher{
				Type:      m.Type,
				Words:     m.Words,
				Regex:     m.Regex,
				Status:    m.Status,
				Part:      m.Part,
				Condition: m.Condition,
			}
			if mm.Part == "" {
				mm.Part = "body"
			}
			if m.Type == "" {
				switch {
				case len(m.Status) > 0:
					mm.Type = "status"
				case len(m.Words) > 0:
					mm.Type = "word"
				case len(m.Regex) > 0:
					mm.Type = "regex"
				case len(m.DSL) > 0:
					mm.Type = "dsl"
					mm.Regex = []string(m.DSL)
				}
			}
			if mm.Type == "dsl" && len(mm.Regex) == 0 {
				mm.Regex = []string(m.DSL)
			}
			req.Matchers = append(req.Matchers, mm)
		}
		for _, e := range h.Extractors {
			ee := Extractor{
				Type:  e.Type,
				Regex: e.Regex,
				Words: e.Words,
				Part:  e.Part,
				Group: e.Group,
			}
			if ee.Part == "" {
				ee.Part = "body"
			}
			req.Extractors = append(req.Extractors, ee)
		}
		t.Requests = append(t.Requests, req)
	}

	if len(t.Requests) == 0 {
		return nil, fmt.Errorf("no http requests in %s", path)
	}
	return t, nil
}

// parseRaw parses a nuclei raw HTTP request block.
func parseRaw(raw string) (method, path string, headers map[string]string, body string) {
	raw = strings.TrimSpace(raw)
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return "", "", nil, ""
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return "", "", nil, ""
	}
	method = parts[0]
	path = parts[1]
	headers = map[string]string{}
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			bodyStart = i + 1
			break
		}
		kv := strings.SplitN(l, ":", 2)
		if len(kv) == 2 {
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	if bodyStart >= 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}
	return method, path, headers, body
}

// LoadDir loads all .yaml templates from a directory (recursive).
func LoadDir(dir string) ([]*Template, error) {
	var out []*Template
	var walkErr error
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			// 记录首个错误（权限/不存在），但继续遍历其他
			if walkErr == nil {
				walkErr = err
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		if strings.Contains(p, "/workflows/") {
			return nil
		}
		t, err := ParseFile(p)
		if err == nil {
			out = append(out, t)
		}
		return nil
	})
	if walkErr != nil {
		// 目录不存在等错误上报，但已加载的模板仍返回
		return out, walkErr
	}
	_ = err
	return out, nil
}
