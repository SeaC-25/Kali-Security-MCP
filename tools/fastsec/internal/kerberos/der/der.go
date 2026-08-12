// Package der: RFC 4120 Kerberos ASN.1 DER 编解码器（完整）。
// 完整支持 Kerberos 消息所需的所有 DER 类型：INTEGER/OCTET STRING/SEQUENCE/
// BIT STRING/ENUMERATED/NULL/GeneralString，及 context-specific/application 标签。
package der

import (
	"encoding/hex"
	"fmt"
	"time"
)

// 类常量
const (
	ClassUniversal       = 0
	ClassApplication     = 1
	ClassContextSpecific = 2
	ClassPrivate         = 3
)

// 通用标签
const (
	TagBool        = 1
	TagInteger     = 2
	TagBitString   = 3
	TagOctetString = 4
	TagNull        = 5
	TagOID         = 6
	TagEnumerated  = 10
	TagUtcTime     = 23
	TagGeneralized = 24
	TagSequence    = 16
	TagSet         = 17
)

// TLV: 一个 DER 元素
type TLV struct {
	Class       int
	Constructed bool
	Tag         int
	Content     []byte
	Full        []byte // 完整编码（含 header）
}

// EncodeTLV: 编码 DER 元素
func EncodeTLV(class int, constructed bool, tag int, content []byte) []byte {
	if tag > 30 {
		panic("tag > 30 not supported")
	}
	var id byte
	id |= byte(class) << 6
	if constructed {
		id |= 0x20
	}
	id |= byte(tag)
	var out []byte
	out = append(out, id)
	// 长度编码
	switch {
	case len(content) < 128:
		out = append(out, byte(len(content)))
	case len(content) < 256:
		out = append(out, 0x81, byte(len(content)))
	case len(content) < 65536:
		out = append(out, 0x82, byte(len(content)>>8), byte(len(content)))
	default:
		out = append(out, 0x83, byte(len(content)>>16), byte(len(content)>>8), byte(len(content)))
	}
	return append(out, content...)
}

// Integer: 编码有符号 INTEGER（最小字节数，正数高位补 0）
func Integer(n int) []byte {
	if n == 0 {
		return EncodeTLV(ClassUniversal, false, TagInteger, []byte{0})
	}
	if n < 0 {
		// 负数补码
		var bytes []byte
		v := n
		for v != 0 {
			bytes = append([]byte{byte(v & 0xff)}, bytes...)
			v >>= 8
		}
		if bytes[0]&0x80 == 0 {
			bytes = append([]byte{0xff}, bytes...)
		}
		return EncodeTLV(ClassUniversal, false, TagInteger, bytes)
	}
	var bytes []byte
	v := n
	for v > 0 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
		v >>= 8
	}
	if bytes[0]&0x80 != 0 {
		bytes = append([]byte{0}, bytes...)
	}
	return EncodeTLV(ClassUniversal, false, TagInteger, bytes)
}

// Int32: 编码固定 4 字节 INTEGER
func Int32(n int) []byte {
	return EncodeTLV(ClassUniversal, false, TagInteger, []byte{
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	})
}

// OctetString: 编码 OCTET STRING
func OctetString(b []byte) []byte {
	return EncodeTLV(ClassUniversal, false, TagOctetString, b)
}

// GeneralString: 编码 GeneralString（KerberosString 用，tag=27/0x1b）
func GeneralString(s string) []byte {
	return EncodeTLV(ClassUniversal, false, 27, []byte(s))
}

// Enumerated: 编码 ENUMERATED
func Enumerated(n int) []byte {
	return EncodeTLV(ClassUniversal, false, TagEnumerated, intBytes(n))
}

// Null: 编码 NULL
func Null() []byte {
	return EncodeTLV(ClassUniversal, false, TagNull, nil)
}

// Bool: 编码 BOOLEAN
func Bool(b bool) []byte {
	v := byte(0)
	if b {
		v = 0xff
	}
	return EncodeTLV(ClassUniversal, false, TagBool, []byte{v})
}

// BitString: 编码 BIT STRING（unused bits = 0）
func BitString(b []byte) []byte {
	content := append([]byte{0}, b...) // 0 未用位
	return EncodeTLV(ClassUniversal, false, TagBitString, content)
}

// Sequence: 编码 SEQUENCE
func Sequence(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	return EncodeTLV(ClassUniversal, true, TagSequence, content)
}

// Set: 编码 SET
func Set(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	return EncodeTLV(ClassUniversal, true, TagSet, content)
}

// Explicit: context-specific constructed 标签（显式）
func Explicit(tag int, content []byte) []byte {
	return EncodeTLV(ClassContextSpecific, true, tag, content)
}

// Implicit: context-specific primitive 标签（隐式）
func Implicit(tag int, content []byte) []byte {
	return EncodeTLV(ClassContextSpecific, false, tag, content)
}

// Application: application constructed 标签（消息级）
func Application(tag int, content []byte) []byte {
	return EncodeTLV(ClassApplication, true, tag, content)
}

// KerberosTime: 编码时间（通用时间格式，UTC）
func KerberosTime(t time.Time) []byte {
	// 格式: YYYYMMDDHHMMSSZ (GeneralizedTime)
	s := t.UTC().Format("20060102150405") + "Z"
	return EncodeTLV(ClassUniversal, false, TagGeneralized, []byte(s))
}

// NowKerberosTime: 当前时间
func NowKerberosTime() []byte {
	return KerberosTime(time.Now())
}

// Parse: 解析第一个 DER 元素
func Parse(data []byte) (*TLV, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("DER too short: %d bytes", len(data))
	}
	id := data[0]
	class := int(id >> 6)
	constructed := id&0x20 != 0
	tag := int(id & 0x1f)
	if tag == 0x1f {
		return nil, fmt.Errorf("long-form tag not supported")
	}
	i := 1
	var length int
	if data[i] < 0x80 {
		length = int(data[i])
		i++
	} else {
		numBytes := int(data[i] & 0x7f)
		if numBytes > 4 {
			return nil, fmt.Errorf("length too long: %d bytes", numBytes)
		}
		i++
		for j := 0; j < numBytes; j++ {
			length = length<<8 | int(data[i])
			i++
		}
	}
	if i+length > len(data) {
		return nil, fmt.Errorf("DER truncated: need %d have %d", i+length, len(data))
	}
	content := data[i : i+length]
	return &TLV{
		Class:       class,
		Constructed: constructed,
		Tag:         tag,
		Content:     content,
		Full:        data[:i+length],
	}, nil
}

// ParseSeq: 解析 SEQUENCE 内容为元素列表
func ParseSeq(content []byte) ([]*TLV, error) {
	var items []*TLV
	rest := content
	for len(rest) > 0 {
		tlv, err := Parse(rest)
		if err != nil {
			return nil, err
		}
		items = append(items, tlv)
		rest = rest[len(tlv.Full):]
	}
	return items, nil
}

// IntValue: 从 INTEGER TLV 提取值
func (t *TLV) IntValue() (int, error) {
	if t.Tag != TagInteger {
		return 0, fmt.Errorf("not an integer: tag=%d", t.Tag)
	}
	if len(t.Content) == 0 {
		return 0, nil
	}
	val := 0
	for _, b := range t.Content {
		val = val<<8 | int(b)
	}
	// 负数
	if t.Content[0]&0x80 != 0 {
		val = val - (1 << (8 * len(t.Content)))
	}
	return val, nil
}

// OctetStringValue: 从 OCTET STRING TLV 提取字节
func (t *TLV) OctetStringValue() ([]byte, error) {
	if t.Tag != TagOctetString {
		return nil, fmt.Errorf("not an octet string: tag=%d", t.Tag)
	}
	return t.Content, nil
}

// Hex: 调试用
func (t *TLV) Hex() string {
	return hex.EncodeToString(t.Full)
}

func intBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	v := n
	for v > 0 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}
