package smb

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
)

// ---------- NTLMv2 认证（公开算法，支持密码和 NTHash） ----------

// ntlmHash: NT Hash = MD4(UTF-16LE(password))
func ntlmHash(password string) []byte {
	return md4(utf16le(password))
}

// utf16le: UTF-16LE 编码
func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range []byte(s) {
		out = append(out, r, 0)
	}
	return out
}

// ntlmv2Hash: NTLMv2 Hash = HMAC-MD5(NTHash, UTF-16LE(user) + UTF-16LE(domain))
func ntlmv2Hash(ntHash []byte, user, domain string) []byte {
	mac := hmac.New(md5.New, ntHash)
	mac.Write(utf16le(user))
	mac.Write(utf16le(domain))
	return mac.Sum(nil)
}

// ntlmv2Response: 计算 NTLMv2 响应
//  参数: ntlmv2Hash, serverChallenge(8B), timestamp(8B), clientChallenge(8B), targetInfo
//  返回: NTLMv2Response (48+ 字节)
func ntlmv2Response(hash []byte, serverChallenge, clientChallenge []byte, targetInfo []byte, timestamp []byte) []byte {
	// blob = 0x01010000 || timestamp(8) || clientChallenge(8) || 0x00000000(4) || targetInfo || 0x00000000(4)
	blob := []byte{0x01, 0x01, 0x00, 0x00}
	blob = append(blob, timestamp...)
	blob = append(blob, clientChallenge...)
	blob = append(blob, 0, 0, 0, 0) // reserved
	blob = append(blob, targetInfo...)
	blob = append(blob, 0, 0, 0, 0) // reserved

	// NTProofStr = HMAC-MD5(NTLMv2Hash, serverChallenge + blob)
	mac := hmac.New(md5.New, hash)
	mac.Write(serverChallenge)
	mac.Write(blob)
	ntProof := mac.Sum(nil)

	// NTLMv2Response = NTProofStr + blob
	resp := append(ntProof, blob...)
	return resp
}

// lmHash: LM Hash（旧兼容，NTLMv2 认证时用空响应或 LMv2）
// LMv2 = HMAC-MD5(NTLMv2Hash, serverChallenge + clientChallenge) + clientChallenge
func lmv2Response(hash []byte, serverChallenge, clientChallenge []byte) []byte {
	mac := hmac.New(md5.New, hash)
	mac.Write(serverChallenge)
	mac.Write(clientChallenge)
	proof := mac.Sum(nil)
	return append(proof, clientChallenge...)
}

// ---------- MD4（RFC 1320，与 crack 包一致） ----------

func md4(data []byte) []byte {
	origLen := uint64(len(data)) * 8
	padded := append(append([]byte{}, data...), 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var lenBuf [8]byte
	for i := 0; i < 8; i++ {
		lenBuf[i] = byte(origLen >> (8 * i))
	}
	padded = append(padded, lenBuf[:]...)

	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	rol := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

	for i := 0; i < len(padded); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = uint32(padded[i+4*j]) | uint32(padded[i+4*j+1])<<8 |
				uint32(padded[i+4*j+2])<<16 | uint32(padded[i+4*j+3])<<24
		}
		aa, bb, cc, dd := a, b, c, d

		f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
		for j := 0; j < 16; j++ {
			switch j % 4 {
			case 0:
				a = rol(a+f(b, c, d)+x[j], 3)
			case 1:
				d = rol(d+f(a, b, c)+x[j], 7)
			case 2:
				c = rol(c+f(d, a, b)+x[j], 11)
			case 3:
				b = rol(b+f(c, d, a)+x[j], 19)
			}
		}
		g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
		order := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for j := 0; j < 16; j++ {
			switch j % 4 {
			case 0:
				a = rol(a+g(b, c, d)+x[order[j]]+0x5a827999, 3)
			case 1:
				d = rol(d+g(a, b, c)+x[order[j]]+0x5a827999, 5)
			case 2:
				c = rol(c+g(d, a, b)+x[order[j]]+0x5a827999, 9)
			case 3:
				b = rol(b+g(c, d, a)+x[order[j]]+0x5a827999, 13)
			}
		}
		h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
		order3 := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for j := 0; j < 16; j++ {
			switch j % 4 {
			case 0:
				a = rol(a+h(b, c, d)+x[order3[j]]+0x6ed9eba1, 3)
			case 1:
				d = rol(d+h(a, b, c)+x[order3[j]]+0x6ed9eba1, 9)
			case 2:
				c = rol(c+h(d, a, b)+x[order3[j]]+0x6ed9eba1, 11)
			case 3:
				b = rol(b+h(c, d, a)+x[order3[j]]+0x6ed9eba1, 15)
			}
		}
		a += aa
		b += bb
		c += cc
		d += dd
	}
	out := make([]byte, 16)
	le := func(v uint32, off int) {
		out[off] = byte(v)
		out[off+1] = byte(v >> 8)
		out[off+2] = byte(v >> 16)
		out[off+3] = byte(v >> 24)
	}
	le(a, 0)
	le(b, 4)
	le(c, 8)
	le(d, 12)
	return out
}

// ---------- NTLMSSP 报文构造 ----------

// ntlmsspNegotiate: NTLMSSP NEGOTIATE_MESSAGE
//  flags: NEGOTIATE_NTLM(0x20000000) | NEGOTIATE_OEM(0x2) | NEGOTIATE_UNICODE(0x1) | NEGOTIATE_ALWAYS_SIGN(0x8000) | NEGOTIATE_EXTENDED_SESSIONSECURITY(0x80000)
func ntlmsspNegotiate(domain, workstation string) []byte {
	// 类型 1 报文
	msg := make([]byte, 40)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1) // Type 1
	flags := uint32(0x00000001 | 0x00000002 | 0x00008000 | 0x00080000 | 0x20000000)
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	// 域/工作站名偏移（ASCII）
	domainB := []byte(domain)
	workB := []byte(workstation)
	binary.LittleEndian.PutUint16(msg[16:18], uint16(len(domainB))) // domain len
	binary.LittleEndian.PutUint16(msg[18:20], uint16(len(domainB))) // domain max len
	binary.LittleEndian.PutUint32(msg[20:24], 40)                   // domain offset
	binary.LittleEndian.PutUint16(msg[24:26], uint16(len(workB)))
	binary.LittleEndian.PutUint16(msg[26:28], uint16(len(workB)))
	binary.LittleEndian.PutUint32(msg[28:32], 40+uint32(len(domainB)))
	msg = append(msg, domainB...)
	msg = append(msg, workB...)
	return msg
}

// ntlmsspAuthenticate: 构造 NTLMSSP AUTHENTICATE_MESSAGE（Type 3）
//  基于服务器 CHALLENGE_MESSAGE（Type 2）计算 NTLMv2 响应
func ntlmsspAuthenticate(challenge []byte, user, domain, password, hash string) ([]byte, error) {
	// 解析 Type 2
	if len(challenge) < 56 || string(challenge[0:8]) != "NTLMSSP\x00" {
		return nil, errInvalidChallenge
	}
	if binary.LittleEndian.Uint32(challenge[8:12]) != 2 {
		return nil, errInvalidChallenge
	}
	serverChallenge := append([]byte{}, challenge[24:32]...)
	// 目标信息（Type 2 的 target info，偏移 40 处）
	var targetInfo []byte
	targetInfoLen := int(binary.LittleEndian.Uint16(challenge[40:42]))
	if targetInfoLen > 0 && 40+8+targetInfoLen <= len(challenge) {
		targetInfo = append([]byte{}, challenge[48:48+targetInfoLen]...)
	}
	flags := binary.LittleEndian.Uint32(challenge[60:64])

	// 计算 NTLMv2 响应
	var ntHash []byte
	if hash != "" {
		// pass-the-hash：直接用 NTHash
		ntHash = mustHexDecode(hash)
	} else {
		ntHash = ntlmHash(password)
	}
	v2Hash := ntlmv2Hash(ntHash, user, domain)

	// 客户端质询 8 字节 + 时间戳 8 字节
	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge)
	timestamp := ntTimestamp()

	ntResp := ntlmv2Response(v2Hash, serverChallenge, clientChallenge, targetInfo, timestamp)
	lmResp := lmv2Response(v2Hash, serverChallenge, clientChallenge)

	// Type 3 报文
	userB := utf16le(user)
	domainB := utf16le(domain)
	var workB []byte

	msg := make([]byte, 64)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3

	// LM 响应
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(lmResp)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(lmResp)))
	binary.LittleEndian.PutUint32(msg[16:20], 64)
	// NT 响应
	binary.LittleEndian.PutUint16(msg[20:22], uint16(len(ntResp)))
	binary.LittleEndian.PutUint16(msg[22:24], uint16(len(ntResp)))
	binary.LittleEndian.PutUint32(msg[24:28], 64+uint32(len(lmResp)))
	// 域
	domOff := 64 + uint32(len(lmResp)) + uint32(len(ntResp))
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainB)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainB)))
	binary.LittleEndian.PutUint32(msg[32:36], domOff)
	// 用户
	userOff := domOff + uint32(len(domainB))
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(userB)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(userB)))
	binary.LittleEndian.PutUint32(msg[40:44], userOff)
	// 工作站
	workOff := userOff + uint32(len(userB))
	binary.LittleEndian.PutUint16(msg[44:46], uint16(len(workB)))
	binary.LittleEndian.PutUint16(msg[46:48], uint16(len(workB)))
	binary.LittleEndian.PutUint32(msg[48:52], workOff)
	// 会话密钥（空）+ flags
	binary.LittleEndian.PutUint32(msg[56:60], 0) // session key len
	binary.LittleEndian.PutUint32(msg[60:64], flags)

	// 拼接
	out := msg
	out = append(out, lmResp...)
	out = append(out, ntResp...)
	out = append(out, domainB...)
	out = append(out, userB...)
	out = append(out, workB...)
	return out, nil
}

// ntTimestamp: Windows FILETIME 时间戳（1601-01-01 起 100ns）
func ntTimestamp() []byte {
	// 当前时间转 FILETIME
	// Unix 纪元到 1601 偏移 = 11644473600 秒
	now := uint64(nowUnixNano()/100 + 11644473600*1e7)
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, now)
	return out
}

// mustHexDecode: hex 解码（hash 认证）
func mustHexDecode(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexVal(s[i*2])
		lo := hexVal(s[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// SPNEGO 包装：NTLMSSP 包在 SPNEGO token 里
//  未包装的 NTLMSSP 也可用（很多服务器接受）——直接返回 NTLMSSP
var _ = strings.Contains

// nowUnixNano: 当前时间纳秒
func nowUnixNano() int64 {
	return time.Now().UnixNano()
}
