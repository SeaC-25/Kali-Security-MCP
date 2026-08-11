// fastsec — AI 原生扫描引擎：nuclei 模板兼容 + 3-gate 确认 + 反检测内建。
//
// 用法:
//   fastsec -u http://target -t /path/to/template.yaml
//   fastsec -u http://target -d /path/to/templates/
//   fastsec -u http://target -t tpl.yaml -c 50 -delay-min 200 -delay-max 600
//   fastsec -u http://target -t tpl.yaml -proxy http://127.0.0.1:8080
//   fastsec -u http://target -t tpl.yaml -no-verify
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fastsec/internal/engine"
	"fastsec/internal/template"
)

func main() {
	url := flag.String("u", "", "target URL (required)")
	tplFile := flag.String("t", "", "single template file")
	tplDir := flag.String("d", "", "template directory")
	concurrency := flag.Int("c", 20, "concurrency")
	minDelay := flag.Int("delay-min", 300, "min delay ms between requests")
	maxDelay := flag.Int("delay-max", 800, "max delay ms between requests")
	proxy := flag.String("proxy", "", "proxy URL (e.g. http://127.0.0.1:8080)")
	noVerify := flag.Bool("no-verify", false, "disable 3-gate confirmation")
	headerFlag := flag.String("H", "", "extra headers (k:v;k:v)")
	cookies := flag.String("cookie", "", "cookie header value")
	timeout := flag.Int("timeout", 10, "per-request timeout seconds")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	if *url == "" {
		fmt.Fprintln(os.Stderr, "错误: 需要 -u 目标 URL")
		flag.Usage()
		os.Exit(2)
	}

	var templates []*template.Template
	switch {
	case *tplFile != "":
		t, e := template.ParseFile(*tplFile)
		if e != nil {
			fmt.Fprintf(os.Stderr, "模板解析失败: %v\n", e)
			os.Exit(1)
		}
		templates = []*template.Template{t}
	case *tplDir != "":
		var err error
		templates, err = template.LoadDir(*tplDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "加载模板目录失败: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "错误: 需要 -t 模板文件或 -d 模板目录")
		os.Exit(2)
	}
	if len(templates) == 0 {
		fmt.Fprintln(os.Stderr, "无可用模板")
		os.Exit(1)
	}

	cfg := engine.DefaultConfig()
	cfg.Concurrency = *concurrency
	cfg.Timeout = time.Duration(*timeout) * time.Second
	cfg.DelayMinMs = *minDelay
	cfg.DelayMaxMs = *maxDelay
	cfg.Proxy = *proxy
	cfg.VerifyGate = !*noVerify
	cfg.Cookies = *cookies
	if *headerFlag != "" {
		for _, pair := range strings.Split(*headerFlag, ";") {
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) == 2 {
				cfg.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	if *verbose {
		fmt.Printf("[fastsec] 目标=%s 模板=%d 并发=%d 延迟=%d-%dms 3-gate=%v\n",
			*url, len(templates), cfg.Concurrency, cfg.DelayMinMs, cfg.DelayMaxMs, cfg.VerifyGate)
		for _, t := range templates {
			fmt.Printf("  模板: %s (%s, %s)\n", filepath.Base(t.Path), t.ID, t.Info.Severity)
		}
	}

	eng := engine.New(cfg)
	t0 := time.Now()
	results := eng.Run(*url, templates)
	dur := time.Since(t0)

	fmt.Print(engine.FormatResults(results))
	fmt.Printf("\n[fastsec] 完成: %d 匹配 / %d 模板, 耗时 %s\n", len(results), len(templates), dur.Round(time.Millisecond))
}
