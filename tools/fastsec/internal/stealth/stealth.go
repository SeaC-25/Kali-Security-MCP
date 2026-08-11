// Package stealth provides anti-detection for scanning:
// real-browser UA pool, request pacing, optional proxy.
package stealth

import (
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

// UA_POOL — real browsers (avoid AI-tool fingerprint like python-requests/Go-http-client).
var UA_POOL = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}

// Throttle randomizes request pacing to mimic human browsing.
type Throttle struct {
	MinDelay time.Duration
	MaxDelay time.Duration
	rng      *rand.Rand
}

func NewThrottle(minMs, maxMs int) *Throttle {
	if minMs <= 0 {
		minMs = 300
	}
	if maxMs < minMs {
		maxMs = minMs + 500
	}
	return &Throttle{
		MinDelay: time.Duration(minMs) * time.Millisecond,
		MaxDelay: time.Duration(maxMs) * time.Millisecond,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (t *Throttle) Wait() {
	if t == nil {
		return
	}
	d := t.MinDelay + time.Duration(t.rng.Int63n(int64(t.MaxDelay-t.MinDelay)))
	time.Sleep(d)
}

// RandomUA returns a random real-browser UA.
func RandomUA() string {
	return UA_POOL[rand.Intn(len(UA_POOL))]
}

// Client is a stealth HTTP client: keep-alive, optional proxy, random UA, pacing.
type Client struct {
	http     *http.Client
	throttle *Throttle
}

func NewClient(proxy string, throttle *Throttle, maxConns int) *Client {
	if maxConns <= 0 {
		maxConns = 50
	}
	tr := &http.Transport{
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &Client{
		http:     &http.Client{Transport: tr, Timeout: 10 * time.Second},
		throttle: throttle,
	}
}

// Do sends one request with stealth headers (random UA + browser-like headers).
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c.throttle != nil {
		c.throttle.Wait()
	}
	req.Header.Set("User-Agent", RandomUA())
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	}
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "keep-alive")
	}
	return c.http.Do(req)
}

// HTTP returns the underlying http.Client (for advanced use).
func (c *Client) HTTP() *http.Client { return c.http }
