package kerberos

import "encoding/hex"

// ExtractAuthenticatorExport: 从 TGS-REQ 提取 AP-REQ authenticator 密文（测试用）
func ExtractAuthenticatorExport(tgsData []byte) []byte {
	h := hex.EncodeToString(tgsData)
	idx := indexHex(h, "6e82")
	if idx < 0 {
		return nil
	}
	sub := h[idx:]
	ti := indexHex(sub, "618201a5")
	if ti < 0 {
		ti = indexHex(sub, "618201")
		if ti < 0 {
			return nil
		}
	}
	tlen := 0x1a5
	after := sub[ti+8+tlen*2:]
	ai := indexHex(after, "a0030201")
	if ai < 0 {
		return nil
	}
	m := after[ai:]
	rest := m[12:] // 跳过 a0030201XX (10 hex) + a2 (2 hex)
	// a2 长度字段（a2 XX XX XX 或 a2 XX）
	lenBytes := 0
	if len(rest) >= 6 && rest[0:2] == "82" {
		lenBytes = 6
	} else if len(rest) >= 4 && rest[0:2] == "81" {
		lenBytes = 4
	} else if len(rest) >= 2 {
		lenBytes = 2
	}
	rest2 := rest[lenBytes:]
	if len(rest2) < 2 || rest2[0:2] != "04" {
		return nil
	}
	olen := 0
	obytes := 0
	if len(rest2) >= 8 && rest2[2:4] == "82" {
		olen = hexByte(rest2[4:6])*256 + hexByte(rest2[6:8])
		obytes = 8
	} else if len(rest2) >= 6 && rest2[2:4] == "81" {
		olen = hexByte(rest2[4:6])
		obytes = 6
	} else if len(rest2) >= 4 {
		olen = hexByte(rest2[2:4])
		obytes = 4
	}
	if olen <= 0 || len(rest2) < obytes+olen*2 {
		return nil
	}
	ctHex := rest2[obytes : obytes+olen*2]
	ct, _ := hex.DecodeString(ctHex)
	return ct
}

func indexHex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func hexByte(h string) int {
	b, _ := hex.DecodeString(h)
	if len(b) > 0 {
		return int(b[0])
	}
	return 0
}
