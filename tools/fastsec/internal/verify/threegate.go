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
	if attackReq.Method != http.MethodGet && attackReq.Method != http.MethodHead {
		if attackResp.StatusCode >= 200 && attackResp.StatusCode < 400 && len(attackBody) > 0 {
			return true
		}
		return attackResp.StatusCode >= 200 && attackResp.StatusCode < 500
	}

	baselineURL := attackReq.URL.String()
	if baselineURL == "" {
		return false
	}
	sep := "?"
	if bytes.Contains([]byte(baselineURL), []byte("?")) {
		sep = "&"
	}
	refURL := baselineURL + sep + "__fastsec_baseline_probe__"

	breq, err := http.NewRequest(http.MethodGet, refURL, nil)
	if err != nil {
		return false
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
