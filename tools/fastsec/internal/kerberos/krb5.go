// Package kerberos: 完整 RFC 4120 Kerberos 协议实现。
// 包含：DER 编解码、AS-REQ/AS-REP、TGS-REQ/TGS-REP、RC4-HMAC 预认证、
// AS-REP Roasting、Kerberoast、用户枚举。
package kerberos

import (
	"fmt"
	"strings"
	"time"

	"fastsec/internal/kerberos/der"
)

// 消息类型
const (
	MsgASReq      = 10
	MsgASRep      = 11
	MsgTGSReq     = 12
	MsgTGSRep     = 13
	MsgAPReq      = 14
	MsgKRBError   = 30
)

// 错误码
const (
	KDCErrNone             = 0
	KDCErrCPrincipalUnknown = 6
	KDCErrSPrincipalUnknown = 7
	KDCErrPreauthRequired  = 25
	KDCErrPreauthFailed    = 24
	KDCErrServerNotFound   = 20
	KDCErrBadOption        = 13
)

// 加密类型
const (
	EncTypeNull      = 0
	EncTypeDESCBC    = 1
	EncTypeDES3CBC   = 16
	EncTypeRC4Hmac   = 23 // RC4-HMAC（Kerberoast 最常用）
	EncTypeRC4HmacExp = 24
	EncTypeAES128    = 17
	EncTypeAES256    = 18
)

// PrincipalName: RFC 4120 PrincipalName
type PrincipalName struct {
	NameType int
	Name     []string
}

// Encode: 编码 PrincipalName
func (p PrincipalName) Encode() []byte {
	// PrincipalName ::= SEQUENCE {
	//   name-type[0] Int32,
	//   name-string[1] SEQUENCE OF KerberosString }
	var nameStrings []byte
	for _, n := range p.Name {
		nameStrings = append(nameStrings, der.GeneralString(n)...)
	}
	return der.Sequence(
		der.Explicit(0, der.Int32(p.NameType)),
		der.Explicit(1, der.Sequence(nameStrings)),
	)
}

// Decode: 解析 PrincipalName
func DecodePrincipalName(data []byte) (*PrincipalName, error) {
	tlv, err := der.Parse(data)
	if err != nil {
		return nil, err
	}
	if !tlv.Constructed || tlv.Tag != der.TagSequence {
		return nil, fmt.Errorf("invalid principal: tag=%d", tlv.Tag)
	}
	items, err := der.ParseSeq(tlv.Content)
	if err != nil {
		return nil, err
	}
	p := &PrincipalName{}
	for _, item := range items {
		if item.Class != der.ClassContextSpecific {
			continue
		}
		switch item.Tag {
		case 0: // name-type[0] 显式：Content 是 INTEGER TLV
			if inner, err := der.Parse(item.Content); err == nil {
				if n, err := inner.IntValue(); err == nil {
					p.NameType = n
				}
			}
		case 1: // name-string[1] 显式 SEQUENCE：Content 是 SEQUENCE TLV
			seqTLV, err := der.Parse(item.Content)
			if err != nil {
				break
			}
			strs, err := der.ParseSeq(seqTLV.Content)
			if err == nil {
				for _, s := range strs {
					// GeneralString (tag 27) 或 OctetString
					p.Name = append(p.Name, string(s.Content))
				}
			}
		}
	}
	return p, nil
}

// String: PrincipalName 转字符串（user@realm 风格）
func (p *PrincipalName) String() string {
	return strings.Join(p.Name, "/")
}

// Realm: 编码 Realm（GeneralString）
func Realm(r string) []byte {
	return der.GeneralString(r)
}

// EncryptedData: RFC 4120 EncryptedData
type EncryptedData struct {
	Etype     int
	Kvno      int
	Cipher    []byte
}

// Encode: 编码 EncryptedData（MIT 兼容：最短 INTEGER，kvno 0 时省略）
func (e EncryptedData) Encode() []byte {
	// EncryptedData ::= SEQUENCE {
	//   etype[0] Int32,
	//   kvno[1] UInt32 OPTIONAL,
	//   cipher[2] OCTET STRING }
	var seq [][]byte
	seq = append(seq, der.Explicit(0, der.Integer(e.Etype)))
	if e.Kvno != 0 {
		seq = append(seq, der.Explicit(1, der.Integer(e.Kvno)))
	}
	seq = append(seq, der.Explicit(2, der.OctetString(e.Cipher)))
	return der.Sequence(seq...)
}

// Decode: 解析 EncryptedData
func DecodeEncryptedData(data []byte) (*EncryptedData, error) {
	tlv, err := der.Parse(data)
	if err != nil {
		return nil, err
	}
	items, err := der.ParseSeq(tlv.Content)
	if err != nil {
		return nil, err
	}
	e := &EncryptedData{}
	if len(items) == 1 && items[0].Tag == der.TagSequence {
		items, _ = der.ParseSeq(items[0].Content)
	}
	for _, item := range items {
		if item.Class != der.ClassContextSpecific {
			continue
		}
		switch item.Tag {
		case 0: // etype[0] 显式：Content 是 INTEGER TLV
			if inner, err := der.Parse(item.Content); err == nil {
				if n, err := inner.IntValue(); err == nil {
					e.Etype = n
				}
			}
		case 1: // kvno[1]
			if inner, err := der.Parse(item.Content); err == nil {
				if n, err := inner.IntValue(); err == nil {
					e.Kvno = n
				}
			}
		case 2: // cipher[2] 显式：Content 是 OCTET STRING TLV，需剥 header
			if inner, err := der.Parse(item.Content); err == nil {
				e.Cipher = inner.Content
			} else {
				e.Cipher = item.Content
			}
		}
	}
	return e, nil
}

// KerberosTime: 编码时间（通用时间）
func KerberosTime(t time.Time) []byte {
	return der.KerberosTime(t)
}

// NowTime: 当前时间
func NowTime() []byte {
	return KerberosTime(time.Now())
}
