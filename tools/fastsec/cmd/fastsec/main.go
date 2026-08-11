// fastsec — AI 原生扫描引擎：模板兼容 + 3-gate + 行为差异 + 状态化序列 + 参数分级。
// -json 模式输出纯 JSON（stdout 无人类文本），供 AI 决策层消费。
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"fastsec/internal/stealth"

	"fastsec/internal/brute"
	"fastsec/internal/diff"
	"fastsec/internal/dir"
	"fastsec/internal/engine"
	"fastsec/internal/injector"
	"fastsec/internal/orchestrate"
	"fastsec/internal/osint"
	"fastsec/internal/soceng"
	"fastsec/internal/priority"
	"fastsec/internal/session"
	"fastsec/internal/template"
)

// wafDetect: WAF 检测（调用 injector 完整指纹库）
func wafDetect(url, param string, cli *stealth.Client) struct {
	WAFDetected bool
	WAFName     string
} {
	d := injector.DetectWAF(url, param, cli)
	return struct {
		WAFDetected bool
		WAFName     string
	}{WAFDetected: d.WAFDetected, WAFName: d.WAFName}
}

func main() {
	url := flag.String("u", "", "target URL (required unless -l)")
	listFile := flag.String("l", "", "target list file (one URL per line)")
	tplFile := flag.String("t", "", "single template file")
	tplDir := flag.String("d", "", "template directory")
	diffParams := flag.String("diff", "", "behavioral diff params (comma list)")
	injectParams := flag.String("inject", "", "SQL injection scan params (comma list, e.g. id,user)")
	bruteTarget := flag.String("brute", "", "brute-force target (host or http://url)")
	bruteService := flag.String("service", "http-form", "brute service: http-form|tcp-banner")
	brutePort := flag.Int("port", 0, "brute port (tcp-banner)")
	userFile := flag.String("U", "", "brute user list file")
	passFile := flag.String("P", "", "brute password list file")
	dirURL := flag.String("dir", "", "directory enumerate target URL")
	socengName := flag.String("soceng", "", "social-eng name for password dict")
	orchestrateTarget := flag.String("orchestrate", "", "scan orchestration target")
	osintDomain := flag.String("osint", "", "OSINT aggregation domain")
	seqFile := flag.String("seq", "", "stateful attack sequence YAML file")
	topN := flag.Int("top", 5, "top-N prioritized params to show (with -diff)")
	concurrency := flag.Int("c", 20, "concurrency")
	minDelay := flag.Int("delay-min", 300, "min delay ms between requests")
	maxDelay := flag.Int("delay-max", 800, "max delay ms between requests")
	proxy := flag.String("proxy", "", "proxy URL")
	noVerify := flag.Bool("no-verify", false, "disable 3-gate confirmation")
	headerFlag := flag.String("H", "", "extra headers (k:v;k:v)")
	cookies := flag.String("cookie", "", "cookie header value")
	timeout := flag.Int("timeout", 10, "per-request timeout seconds")
	verbose := flag.Bool("v", false, "verbose")
	jsonOut := flag.String("json", "", "JSON output (file path or /dev/stdout for pure JSON)")
	flag.Parse()

	jsonMode := *jsonOut != ""
	var jsonWriter *os.File
	if jsonMode && *jsonOut != "/dev/stdout" {
		f, err := os.Create(*jsonOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "创建 JSON 输出失败: %v\n", err)
			os.Exit(1)
		}
		jsonWriter = f
	}

	// 模式 flag 优先（brute/dir/soceng/orchestrate/osint 不需要 -u）
	hasMode := *bruteTarget != "" || *dirURL != "" || *socengName != "" ||
		*orchestrateTarget != "" || *osintDomain != "" || *injectParams != "" || *diffParams != "" || *seqFile != ""

	var targets []string
	if *url != "" {
		targets = []string{*url}
	} else if *listFile != "" {
		f, err := os.Open(*listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开目标列表失败: %v\n", err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			t := strings.TrimSpace(sc.Text())
			if t != "" && !strings.HasPrefix(t, "#") {
				targets = append(targets, t)
			}
		}
		f.Close()
	}
	if len(targets) == 0 && !hasMode {
		fmt.Fprintln(os.Stderr, "错误: 需要 -u 目标 URL 或 -l 目标列表文件 或模式 flag")
		flag.Usage()
		os.Exit(2)
	}

	// 状态化序列模式
	if *seqFile != "" {
		data, err := os.ReadFile(*seqFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取序列文件失败: %v\n", err)
			os.Exit(1)
		}
		var seq struct {
			BaseURL string         `yaml:"base_url"`
			Steps   []session.Step `yaml:"steps"`
		}
		if err := yaml.Unmarshal(data, &seq); err != nil {
			fmt.Fprintf(os.Stderr, "序列 YAML 解析失败: %v\n", err)
			os.Exit(1)
		}
		cfg := &session.Config{
			BaseURL:     seq.BaseURL,
			Steps:       seq.Steps,
			Concurrency: *concurrency,
			Timeout:     time.Duration(*timeout) * time.Second,
			DelayMinMs:  *minDelay,
			DelayMaxMs:  *maxDelay,
			Proxy:       *proxy,
		}
		var allResults []map[string]any
		for _, t := range targets {
			cfg.BaseURL = t
			if !jsonMode {
				fmt.Printf("=== 状态化序列 %s ===\n", t)
			}
			runner := session.New(cfg)
			results := runner.Run()
			if !jsonMode {
				fmt.Print(session.Format(results))
			}
			for _, r := range results {
				allResults = append(allResults, map[string]any{
					"step":     r.StepName,
					"url":      r.URL,
					"status":   r.StatusCode,
					"body_len": r.BodyLen,
					"matched":  r.Matched,
					"extracted": r.Extracted,
					"diff":     r.Diff,
				})
			}
		}
		if jsonMode {
			out, _ := json.MarshalIndent(allResults, "", "  ")
			if jsonWriter != nil {
				jsonWriter.Write(out)
				jsonWriter.Close()
			} else {
				fmt.Println(string(out))
			}
		}
		return
	}

	// SQL 注入检测模式（injector，含 WAF 检测 + 绕过）
	if *injectParams != "" {
		params := strings.Split(*injectParams, ",")
		cli := stealth.NewClient(*proxy, stealth.NewThrottle(*minDelay, *maxDelay), *concurrency)

		// 1) WAF 检测（先于注入检测——WAF 会拦截 payload 导致误判 clean）
		wafDet := wafDetect(*url, params[0], cli)
		if wafDet.WAFDetected {
			fmt.Printf("[injector] 检测到 WAF (%s) → 先绕过再检测\n", wafDet.WAFName)
			// 2) 绕过：找穿透 payload
			ok, layer, payload := injector.BypassWAF(*url, params[0], "1 AND 1=1", cli)
			if ok {
				fmt.Printf("[injector] 绕过成功 (%s): %s\n", layer, payload)
				// 3) 用绕过 payload 重新注入检测（布尔：AND 1=1 → 用穿透变体）
				res := injector.ScanBypass(*url, params, payload, cli)
				fmt.Print(injector.Format(res))
			} else {
				fmt.Printf("[injector] 全部绕过层被拦\n")
			}
		} else {
			// 无 WAF，直接检测
			res := injector.Scan(*url, params, "", true, cli)
			fmt.Print(injector.Format(res))
		}
		return
	}

	// 爆破模式
	if *bruteTarget != "" {
		// 用户/密码：优先 -U/-P 文件，否则内置完整字典
		var users []string
		var passwords []string
		if *userFile != "" {
			if f, err := os.ReadFile(*userFile); err == nil {
				for _, l := range strings.Split(string(f), "\n") {
					if l = strings.TrimSpace(l); l != "" {
						users = append(users, l)
					}
				}
			}
		}
		if *passFile != "" {
			if f, err := os.ReadFile(*passFile); err == nil {
				for _, l := range strings.Split(string(f), "\n") {
					if l = strings.TrimSpace(l); l != "" {
						passwords = append(passwords, l)
					}
				}
			}
		}
		if len(users) == 0 {
			users = []string{
				"admin", "root", "test", "Administrator", "guest", "user", "sa",
				"backup", "service", "operator", "audit", "support", "manager",
				"sysadmin", "webadmin", "postgres", "mysql", "oracle", "tomcat",
				"jenkins", "gitlab", "grafana", "elastic", "redis", "mongodb",
				"system", "super", "dba", "dba1", "cisco", "huawei", "h3c",
				"ruijie", "sangfor", "weaver", "tongda", "seeyon", "ruoyi",
				"admin1", "admin2", "administrator1", "wangwei", "zhangsan",
				"lisi", "wangwu", "zhaoliu", "sunqi", "zhoushi", "wuheng",
				"zhongguo", "yonghu", "guanli", "kaifazhe",
			}
		}
		if len(passwords) == 0 {
			passwords = []string{
				"123456", "12345678", "123456789", "1234567890", "123123", "111111",
				"888888", "666666", "000000", "5201314", "qwe123", "qweasd",
				"asd123", "abc123", "a123456", "Aa123456", "Admin123", "Password1",
				"P@ssw0rd", "Passw0rd", "admin123", "admin@123", "Admin@123",
				"admin888", "admin666", "admin2024", "admin2025", "Admin2024",
				"Admin2025", "qwer1234", "1qaz2wsx", "zaq12wsx", "zxcvbn",
				"asdfgh", "woaini", "woshinibaba", "nihao123", "wang123",
				"li123456", "root", "toor", "sangfor", "weaver", "td123456",
				"123qwe", "qazwsx", "admin#123", "Admin#123", "admin@2024",
				"admin@2025", "password123", "Password123", "qwerty", "qwerty123",
				"administrator", "Administrator1", "admin!@#", "Test@123",
				"test123", "Test123", "guest123", "p@ssword", "changeme",
				"letmein", "welcome", "monkey", "dragon", "master", "shadow",
				"superman", "michael", "secret", "12345", "1234", "54321",
				"1q2w3e4r", "q1w2e3r4", "asdf1234", "zxcv1234", "abcd1234",
				"112233", "123321", "100200", "1314520", "7758521", "woaini1314",
				"admin000", "Admin000", "p@ssw0rd", "Passw0rd!", "Admin@1234",
			}
		}
		cfg := brute.DefaultConfig(*bruteTarget, *bruteService, users, passwords)
		if *bruteService == "tcp-banner" && *brutePort > 0 {
			cfg.Target = fmt.Sprintf("%s:%d", *bruteTarget, *brutePort)
		}
		res := brute.Run(cfg)
		fmt.Print(brute.Format(res))
		return
	}

	// 目录枚举模式
	if *dirURL != "" {
		cli := stealth.NewClient(*proxy, stealth.NewThrottle(*minDelay, *maxDelay), *concurrency)
		// 无字典时用常见路径
		var wordlist []string
		res := dir.Scan(*dirURL, wordlist, cli, 300)
		fmt.Print(dir.Format(res))
		return
	}

	// 社工字典模式
	if *socengName != "" {
		pwds := soceng.Generate(*socengName, "", "", "", "")
		fmt.Print(soceng.Format(pwds))
		return
	}

	// 扫描编排模式
	if *orchestrateTarget != "" {
		var ports []int
		res := orchestrate.Orchestrate(*orchestrateTarget, ports)
		fmt.Print(orchestrate.Format(res))
		return
	}

	// OSINT 聚合模式
	if *osintDomain != "" {
		cli := stealth.NewClient(*proxy, stealth.NewThrottle(*minDelay, *maxDelay), *concurrency)
		res := osint.Aggregate(*osintDomain, cli)
		fmt.Print(osint.Format(res))
		return
	}

	// 行为差异 + 参数分级
	if *diffParams != "" {
		cfg := diff.DefaultConfig()
		cfg.Concurrency = *concurrency
		cfg.DelayMinMs = *minDelay
		cfg.DelayMaxMs = *maxDelay
		cfg.Proxy = *proxy
		if *headerFlag != "" {
			for _, pair := range strings.Split(*headerFlag, ";") {
				kv := strings.SplitN(pair, ":", 2)
				if len(kv) == 2 {
					cfg.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
				}
			}
		}
		params := strings.Split(*diffParams, ",")
		var allFindings map[string][]string
		var jsonFindings []map[string]any
		for _, t := range targets {
			if !jsonMode {
				fmt.Printf("=== 差异检测 %s ===\n", t)
			}
			fs := diff.Scan(t, params, cfg)
			if !jsonMode {
				fmt.Print(diff.Format(fs))
			}
			if allFindings == nil {
				allFindings = map[string][]string{}
			}
			for _, f := range fs {
				var muts []map[string]any
				for _, d := range f.Mutations {
					desc := fmt.Sprintf("status %d->%d len %d->%d",
						d.StatusBase, d.StatusNew, d.BodyLenBase, d.BodyLenNew)
					allFindings[f.Param] = append(allFindings[f.Param], desc)
					muts = append(muts, map[string]any{
						"value": d.Value, "status_diff": d.StatusDiff,
						"status_base": d.StatusBase, "status_new": d.StatusNew,
						"body_diff": d.BodyDiff, "body_len_base": d.BodyLenBase,
						"body_len_new": d.BodyLenNew,
					})
				}
				jsonFindings = append(jsonFindings, map[string]any{
					"url": f.URL, "param": f.Param, "baseline": f.BaseResp,
					"severity": f.Severity, "mutations": muts,
				})
			}
		}
		var jsonPriority []map[string]any
		if len(allFindings) > 0 {
			scores := priority.ScoreDiffs(allFindings)
			if !jsonMode {
				fmt.Print(priority.Format(scores, *topN))
			}
			for _, s := range scores {
				jsonPriority = append(jsonPriority, map[string]any{
					"param": s.Param, "score": s.Score,
					"severity": s.Severity, "reasons": s.Reason,
				})
			}
		}
		if jsonMode {
			out, _ := json.MarshalIndent(map[string]any{
				"findings": jsonFindings, "priority": jsonPriority,
			}, "", "  ")
			if jsonWriter != nil {
				jsonWriter.Write(out)
				jsonWriter.Close()
			} else {
				fmt.Println(string(out))
			}
		}
		return
	}

	// 模板扫描模式
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
		fmt.Fprintln(os.Stderr, "错误: 需要 -t 模板、-d 模板目录、-diff 参数、或 -seq 序列")
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

	if *verbose && !jsonMode {
		fmt.Printf("[fastsec] 目标=%d 模板=%d 并发=%d 延迟=%d-%dms 3-gate=%v\n",
			len(targets), len(templates), cfg.Concurrency, cfg.DelayMinMs, cfg.DelayMaxMs, cfg.VerifyGate)
	}

	eng := engine.New(cfg)
	t0 := time.Now()
	var all []map[string]any
	for _, tgt := range targets {
		results := eng.Run(tgt, templates)
		if !jsonMode {
			fmt.Printf("\n=== %s ===\n", tgt)
			fmt.Print(engine.FormatResults(results))
		}
		for _, r := range results {
			all = append(all, map[string]any{
				"template": r.TemplateID, "severity": r.Severity, "url": r.Matched,
				"verified": r.Verified, "extracted": r.Extracted,
				"status": r.StatusCode, "payload": r.Payload,
			})
		}
	}
	dur := time.Since(t0)

	if jsonMode {
		out, _ := json.MarshalIndent(all, "", "  ")
		if jsonWriter != nil {
			jsonWriter.Write(out)
			jsonWriter.Close()
		} else {
			fmt.Println(string(out))
		}
	} else {
		fmt.Printf("\n[fastsec] 完成: %d 匹配 / %d 目标 / %d 模板, 耗时 %s\n",
			len(all), len(targets), len(templates), dur.Round(time.Millisecond))
	}
}
