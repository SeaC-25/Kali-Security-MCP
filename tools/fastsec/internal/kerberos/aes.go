package kerberos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
)

// ---------- PBKDF2 (RFC 2898) ----------

func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	prf := func(p, s []byte) []byte {
		h := hmac.New(sha1.New, p)
		h.Write(s)
		return h.Sum(nil)
	}
	hashLen := 20
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		var u []byte
		u = prf(password, append(salt, byte(block>>24), byte(block>>16), byte(block>>8), byte(block)))
		t := append([]byte{}, u...)
		for i := 1; i < iter; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// ---------- n-fold (RFC 3961 §5.1, impacket 精确移植) ----------

func bitRotateRight(ba []byte, bits int) []byte {
	nbits := len(ba) * 8
	bits %= nbits
	if bits == 0 {
		out := make([]byte, len(ba))
		copy(out, ba)
		return out
	}
	bitArr := make([]bool, nbits)
	for i := 0; i < nbits; i++ {
		bitArr[i] = ba[i/8]&(1<<(7-i%8)) != 0
	}
	rotated := make([]bool, nbits)
	for i := 0; i < nbits; i++ {
		rotated[(i+bits)%nbits] = bitArr[i]
	}
	out := make([]byte, len(ba))
	for i := 0; i < nbits; i++ {
		if rotated[i] {
			out[i/8] |= 1 << (7 - i%8)
		}
	}
	return out
}

func onesComplementAdd(a, b []byte) []byte {
	n := len(a)
	v := make([]int, n)
	for i := 0; i < n; i++ {
		v[i] = int(a[i]) + int(b[i])
	}
	// end-around carry（大端反码加法，impacket 语义）
	for {
		carry := 0
		overflow := false
		for i := n - 1; i >= 0; i-- {
			s := v[i] + carry
			v[i] = s & 0xff
			carry = s >> 8
		}
		if carry > 0 {
			overflow = true
			v[n-1] += carry
		}
		// 检查是否还有溢出
		clean := true
		for _, x := range v {
			if x > 0xff {
				clean = false
				break
			}
		}
		if clean && !overflow {
			break
		}
		if !overflow {
			// 规范化（理论上 carry 循环已处理）
			for i := 0; i < n; i++ {
				for v[i] > 0xff {
					v[i] -= 0x100
					if i > 0 {
						v[i-1]++
					} else {
						v[n-1]++
					}
				}
			}
			// 再检查（规范化可能引入新溢出，循环重来）
			still := false
			for _, x := range v {
				if x > 0xff {
					still = true
					break
				}
			}
			if !still {
				break
			}
		}
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(v[i] & 0xff)
	}
	return out
}

// nfold: RFC 3961 §5.1（impacket 算法）
func nfold(ba []byte, nbytes int) []byte {
	slen := len(ba)
	if slen == 0 || nbytes <= 0 {
		return nil
	}
	gcd := func(a, b int) int {
		for b != 0 {
			a, b = b, a%b
		}
		return a
	}
	lcm := nbytes * slen / gcd(nbytes, slen)
	bigstr := make([]byte, 0, lcm)
	for i := 0; i < lcm/slen; i++ {
		bigstr = append(bigstr, bitRotateRight(ba, 13*i)...)
	}
	var result []byte
	for p := 0; p < lcm; p += nbytes {
		slice := bigstr[p : p+nbytes]
		if result == nil {
			result = make([]byte, nbytes)
			copy(result, slice)
		} else {
			result = onesComplementAdd(result, slice)
		}
	}
	return result
}

// ---------- AES 基础 ----------

func aesECBEncrypt(key, block []byte) []byte {
	c, _ := aes.NewCipher(key)
	out := make([]byte, 16)
	c.Encrypt(out, block)
	return out
}

func aesECBDecrypt(key, block []byte) []byte {
	c, _ := aes.NewCipher(key)
	out := make([]byte, 16)
	c.Decrypt(out, block)
	return out
}

// zeropad: 零填充到 16 倍数
func zeropad(data []byte, size int) []byte {
	padLen := size - len(data)%size
	if padLen == size {
		return append([]byte{}, data...)
	}
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	return out
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// aesCTSCrypt: impacket 精确 AES-CTS（CBC + 交换最后两块截断）
func aesCTSCrypt(key, iv, data []byte, decrypt bool) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("too short: %d", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 16 {
		if decrypt {
			out := make([]byte, 16)
			block.Decrypt(out, data)
			if len(iv) == 16 {
				for i := range out {
					out[i] ^= iv[i]
				}
			}
			return out, nil
		}
		out := make([]byte, 16)
		if len(iv) == 16 {
			for i := range out {
				data[i] ^= iv[i]
			}
		}
		block.Encrypt(out, data)
		return out, nil
	}

	if !decrypt {
		// 加密：CBC + zeropad + 交换最后两块截断
		plain := zeropad(data, 16)
		mode := cipher.NewCBCEncrypter(block, iv)
		ctAll := make([]byte, len(plain))
		mode.CryptBlocks(ctAll, plain)
		lastlen := len(data) % 16
		if lastlen == 0 {
			lastlen = 16
		}
		// ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
		out := make([]byte, 0, len(data))
		out = append(out, ctAll[:len(ctAll)-32]...)
		out = append(out, ctAll[len(ctAll)-16:]...)
		out = append(out, ctAll[len(ctAll)-32:len(ctAll)-16][:lastlen]...)
		return out, nil
	}

	// 解密（impacket 算法）
	// 分块
	var cblocks [][]byte
	for p := 0; p < len(data); p += 16 {
		end := p + 16
		if end > len(data) {
			end = len(data)
		}
		cblocks = append(cblocks, data[p:end])
	}
	lastlen := len(cblocks[len(cblocks)-1])
	prevCblock := make([]byte, 16)
	if len(iv) == 16 {
		copy(prevCblock, iv)
	}
	var plaintext []byte
	// CBC 解密除最后两块
	for i := 0; i < len(cblocks)-2; i++ {
		dec := aesECBDecrypt(key, cblocks[i])
		pt := xorBytes(dec, prevCblock)
		plaintext = append(plaintext, pt...)
		copy(prevCblock, cblocks[i])
	}
	// 倒数第二块
	bb := aesECBDecrypt(key, cblocks[len(cblocks)-2])
	lastPlaintext := xorBytes(bb[:lastlen], cblocks[len(cblocks)-1])
	omitted := bb[lastlen:]
	// 最后块 + omitted
	combined := append(append([]byte{}, cblocks[len(cblocks)-1]...), omitted...)
	decLast := aesECBDecrypt(key, combined)
	plaintext = append(plaintext, xorBytes(decLast, prevCblock)...)
	plaintext = append(plaintext, lastPlaintext...)
	return plaintext, nil
}

// ---------- AES-256-CTS (RFC 3962) ----------

// aesStringToKey: String-to-Key（RFC 3962 §4）
func aesStringToKey(password, salt string) []byte {
	tkey := pbkdf2SHA1([]byte(password), []byte(salt), 4096, 32)
	return aesDeriveKey(tkey, []byte("kerberos"))
}

// aesDeriveKey: DK(T, K)（RFC 3961 §5.3）
func aesDeriveKey(baseKey []byte, constant []byte) []byte {
	plaintext := nfold(constant, 16)
	var seed []byte
	pt := plaintext
	for len(seed) < 32 {
		ct := aesECBEncrypt(baseKey, pt)
		seed = append(seed, ct...)
		pt = ct
	}
	return seed[:32]
}

// aesKcKe: ki + ke，constant = usage(4B BE) + 0x55/0xAA
func aesKcKe(baseKey []byte, usage int) (ki, ke []byte) {
	usageBytes := []byte{byte(usage >> 24), byte(usage >> 16), byte(usage >> 8), byte(usage)}
	ki = aesDeriveKey(baseKey, append(append([]byte{}, usageBytes...), 0x55))
	ke = aesDeriveKey(baseKey, append(append([]byte{}, usageBytes...), 0xAA))
	return ki, ke
}

// aesEncrypt: AES-256-CTS 完整加密
func aesEncrypt(baseKey []byte, usage int, plaintext []byte) ([]byte, error) {
	ki, ke := aesKcKe(baseKey, usage)
	confounder := make([]byte, 16)
	if _, err := rand.Read(confounder); err != nil {
		return nil, err
	}
	msg := append(confounder, plaintext...)
	h := hmac.New(sha1.New, ki)
	h.Write(msg)
	checksum := h.Sum(nil)[:12]
	ct, err := aesCTSCrypt(ke, make([]byte, 16), msg, false)
	if err != nil {
		return nil, err
	}
	return append(ct, checksum...), nil
}

// aesDecrypt: AES-256-CTS 完整解密
func aesDecrypt(baseKey []byte, usage int, data []byte) ([]byte, error) {
	ki, ke := aesKcKe(baseKey, usage)
	if len(data) < 12+16+16 {
		return nil, fmt.Errorf("ciphertext too short: %d", len(data))
	}
	checksum := data[len(data)-12:]
	ciphertext := data[:len(data)-12]
	pt, err := aesCTSCrypt(ke, make([]byte, 16), ciphertext, true)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha1.New, ki)
	h.Write(pt)
	calc := h.Sum(nil)[:12]
	if !hmac.Equal(calc, checksum) {
		return nil, fmt.Errorf("AES checksum mismatch")
	}
	return pt[16:], nil
}

// ---------- 导出 ----------

func AESStringToKeyExport(password, salt string) []byte {
	return aesStringToKey(password, salt)
}

func AESEncryptExport(key []byte, usage int, plaintext []byte) ([]byte, error) {
	return aesEncrypt(key, usage, plaintext)
}

func AESDecryptExport(key []byte, usage int, data []byte) ([]byte, error) {
	return aesDecrypt(key, usage, data)
}

// aesChecksum: hmac-sha1-96-aes256 checksum（RFC 3962 §4.1.1）
//  K = derive(key, usage||0x99)，checksum = HMAC-SHA1(K, data)[:12]
func aesChecksum(baseKey []byte, usage int, data []byte) []byte {
	usageBytes := []byte{byte(usage >> 24), byte(usage >> 16), byte(usage >> 8), byte(usage)}
	kc := aesDeriveKey(baseKey, append(append([]byte{}, usageBytes...), 0x99))
	h := hmac.New(sha1.New, kc)
	h.Write(data)
	return h.Sum(nil)[:12]
}
