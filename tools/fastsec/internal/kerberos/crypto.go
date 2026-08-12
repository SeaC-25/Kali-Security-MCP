package kerberos

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"fmt"
	"time"

	"fastsec/internal/kerberos/der"
)

// ---------- RC4 实现（Go 标准库无 RC4，crypto/rc4 有） ----------
// Go 标准库 crypto/rc4 可用，此处封装

// rc4Encrypt: RC4 加密/解密（流密码，加解密同操作）
func rc4Crypt(key, data []byte) ([]byte, error) {
	// 标准库 crypto/rc4
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// ---------- HMAC ----------

// hmacSHA1: HMAC-SHA1
func hmacSHA1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// hmacMD5: HMAC-MD5
func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ---------- RC4-HMAC (etype 23) ----------

// ntlmKey: 从密码生成 RC4-HMAC 密钥（= NTLM 哈希）
func ntlmKey(password string) []byte {
	// MD4(UTF-16LE(password))
	utf16 := make([]byte, 0, len(password)*2)
	for _, b := range []byte(password) {
		utf16 = append(utf16, b, 0)
	}
	return md4(utf16)
}

// md4: MD4 完整实现（RFC 1320）——与 crack 包一致
func md4(data []byte) []byte {
	// 填充
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

		// 第 1 轮
		f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
		// 4 个一组，s = 3,7,11,19
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
		// 第 2 轮
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
		// 第 3 轮
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

// usageBytes: 加密 usage 转 4 字节小端（RFC 4757 RC4-HMAC 用 LE）
func usageBytes(usage int) []byte {
	return []byte{byte(usage), byte(usage >> 8), byte(usage >> 16), byte(usage >> 24)}
}

// rc4HMACEncrypt: RC4-HMAC 加密（etype 23, RFC 4757）
//  输入: key (16字节 NTLM), usage, 明文
//  输出: checksum(16) || rc4(confounder || 明文)
func rc4HMACEncrypt(key []byte, usage int, plaintext []byte) ([]byte, error) {
	// RFC 4757（MIT/Windows 兼容）：
	//   K1 = HMAC-MD5(key, usage-LE)[:16]
	//   checksum = HMAC-MD5(K1, confounder || plaintext)[:16]
	//   ke = HMAC-MD5(K1, checksum)[:16]
	//   输出 = checksum(16) || RC4(ke, confounder || plaintext)
	confounder := make([]byte, 8)
	if _, err := rand.Read(confounder); err != nil {
		return nil, err
	}
	msg := append(confounder, plaintext...)
	K1 := hmacMD5(key, usageBytes(usage))[:16]
	checksum := hmacMD5(K1, msg)[:16]
	ke := hmacMD5(K1, checksum)[:16]
	cipher, err := rc4Crypt(ke, msg)
	if err != nil {
		return nil, err
	}
	return append(checksum, cipher...), nil
}

// rc4HMACDecrypt: RFC 4757 解密 + 校验（剥掉 confounder）
func rc4HMACDecrypt(key []byte, usage int, data []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("ciphertext too short: %d", len(data))
	}
	receivedChecksum := data[:16]
	K1 := hmacMD5(key, usageBytes(usage))[:16]
	ke := hmacMD5(K1, receivedChecksum)[:16]
	cipher := data[16:]
	decrypted, err := rc4Crypt(ke, cipher)
	if err != nil {
		return nil, err
	}
	// 校验 checksum
	calc := hmacMD5(K1, decrypted)[:16]
	ok := hmac.Equal(calc, receivedChecksum)
	if !ok {
		return nil, fmt.Errorf("checksum mismatch (wrong key?)")
	}
	// 剥掉 8 字节 confounder
	if len(decrypted) < 8 {
		return nil, fmt.Errorf("plaintext too short after confounder")
	}
	return decrypted[8:], nil
}

// ---------- PA-ENC-TIMESTAMP（预认证数据） ----------

// buildPAEncTimestamp: 构造 PA-ENC-TIMESTAMP（预认证时间戳）
// 返回 EncryptedData（用密码 RC4-HMAC 加密）
func buildPAEncTimestamp(key []byte, usage int, now time.Time) ([]byte, error) {
	// PA-ENC-TIMESTAMP ::= SEQUENCE {
	//   patimestamp[0] KerberosTime,
	//   pausec[1] INTEGER }
	plaintext := der.Sequence(
		der.Explicit(0, der.KerberosTime(now)),
		der.Explicit(1, der.Integer(0)), // 微秒 0
	)
	cipher, err := rc4HMACEncrypt(key, usage, plaintext)
	if err != nil {
		return nil, err
	}
	ed := EncryptedData{Etype: EncTypeRC4Hmac, Kvno: 1, Cipher: cipher}
	return ed.Encode(), nil
}

// buildPAData: 构造 PA-DATA 元素
func buildPAData(padataType int, value []byte) []byte {
	// PA-DATA ::= SEQUENCE {
	//   padata-type[1] Int32,
	//   padata-value[2] OCTET STRING }
	return der.Sequence(
		der.Explicit(1, der.Integer(padataType)),
		der.Explicit(2, der.OctetString(value)),
	)
}

// buildPADataList: 构造 PA-DATA 列表（SEQUENCE OF PA-DATA）
func buildPADataList(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	return der.Sequence(content)
}

// ---------- 导出（测试/外部调用） ----------

// NTLMKeyExport: 导出 NTLM key
func NTLMKeyExport(password string) []byte {
	return ntlmKey(password)
}

// RC4HMACEncryptExport: 导出 RC4-HMAC 加密
func RC4HMACEncryptExport(key []byte, usage int, plaintext []byte) ([]byte, error) {
	return rc4HMACEncrypt(key, usage, plaintext)
}

// RC4HMACDecryptExport: 导出 RC4-HMAC 解密
func RC4HMACDecryptExport(password string, usage int, data []byte) ([]byte, error) {
	key := ntlmKey(password)
	return rc4HMACDecrypt(key, usage, data)
}

// buildPAEncTimestampAES: AES-256 版 PA-ENC-TIMESTAMP（etype 18）
func buildPAEncTimestampAES(key []byte, usage int, now time.Time) ([]byte, error) {
	plaintext := der.Sequence(
		der.Explicit(0, der.KerberosTime(now)),
		der.Explicit(1, der.Integer(0)),
	)
	cipher, err := aesEncrypt(key, usage, plaintext)
	if err != nil {
		return nil, err
	}
	ed := EncryptedData{Etype: EncTypeAES256, Kvno: 1, Cipher: cipher}
	return ed.Encode(), nil
}
