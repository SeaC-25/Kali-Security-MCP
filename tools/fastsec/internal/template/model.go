package template

// Template is a nuclei-compatible scan template.
type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"-"`
	Path     string    `yaml:"-"`
}

type Info struct {
	Name     string   `yaml:"name"`
	Severity string   `yaml:"severity"`
	Tags     []string `yaml:"tags"`
	Author   string   `yaml:"author"`
}

// Request is one HTTP request block in a template.
type Request struct {
	Method           string              `yaml:"method"`
	Path             []string            `yaml:"path"`
	Headers          map[string]string   `yaml:"headers"`
	Body             string              `yaml:"body"`
	Matchers         []Matcher           `yaml:"matchers"`
	Extractors       []Extractor         `yaml:"extractors"`
	StopAtFirstMatch bool                `yaml:"stop-at-first-match"`
	Redirects        bool                `yaml:"redirects"`
	Payloads         map[string][]string `yaml:"payloads"`
	Attack           string              `yaml:"attack"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
}

type Extractor struct {
	Type  string   `yaml:"type"`
	Regex []string `yaml:"regex"`
	Words []string `yaml:"words"`
	Part  string   `yaml:"part"`
	Group int      `yaml:"group"`
}

// MatchResult describes a template hit.
type MatchResult struct {
	TemplateID string
	Severity   string
	Matched    string
	Extracted  []string
	StatusCode int
	Verified   bool
	Payload    string
}
