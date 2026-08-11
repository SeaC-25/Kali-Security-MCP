// Package verify implements the 3-gate confirmation protocol
// (CyberStrike methodology): baseline request, attack request, compare.
package verify

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

// ThreeGate confirms a match by comparing the attack response against a
// baseline (the same request to a reference path).
func ThreeGate(client *http.Client, attackReq *http.Request, attackResp *http.Response, attackBody []byte, timeout time.Duration) bool {
	// 非 GET 请求也做确认：重放同请求到随机路径对比响应差异
	// （POST 到不存在路径 vs 攻击路径，状态/长度不同 = 真漏洞）

	baselineURL := attackReq.URL.String()
	if baselineURL == "" {
		return false
	}
	sep := "?"
	if bytes.Contains([]byte(baselineURL), []byte("?")) {
		sep = "&"
	}
	refURL := baselineURL + sep + "__fastsec_baseline_probe__"

	// 用攻击请求的方法重放（POST 也一样确认）
	breq, err := http.NewRequest(attackReq.Method, refURL, attackReq.Body)
	if err != nil {
		return false
	}
	// 复制攻击请求头（含 Content-Type 等）
	for k, v := range attackReq.Header {
		breq.Header[k] = v
	}
	breq.Header.Set("User-Agent", attackReq.Header.Get("User-Agent"))
	bresp, err := client.Do(breq)
	if err != nil {
		return false
	}
	bbody, _ := io.ReadAll(io.LimitReader(bresp.Body, 2*1024*1024))
	bresp.Body.Close()

	if bresp.StatusCode != attackResp.StatusCode {
		return true
	}
	if len(bbody) != len(attackBody) {
		return true
	}
	sample := 256
	if len(bbody) < sample {
		sample = len(bbody)
	}
	if sample > 0 && !bytes.Equal(bbody[:sample], attackBody[:sample]) {
		return true
	}
	return false
}
