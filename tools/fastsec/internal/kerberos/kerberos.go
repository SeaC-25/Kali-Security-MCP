// Package kerberos: Kerberos 协议引擎。
//
// ⚠️ 诚实声明（2026-08-11）：本包**未实现**完整 Kerberos 协议。
// 完整实现需要 RFC 4120 ASN.1 DER 编解码 + 协议状态机，当前代码库未完成。
// 之前的版本包含骨架/占位逻辑（buildASReq 拼字符串、isASRep 只查首字节、
// extractASREPHash 返回占位格式）——这些是虚构的，已移除。
//
// 用途：明确告诉调用方此功能不可用，避免假装能执行 Kerberos 攻击。
// 后续计划：用 ASN.1 库实现完整 AS-REQ/AS-REP/TGS-REQ 编码。
package kerberos

import "fmt"

// Status: 引擎状态
const Status = "not-implemented"

// Scan: 明确返回未实现
func Scan() (string, error) {
	return "", fmt.Errorf("kerberos engine not implemented (requires full RFC 4120 ASN.1; current build has no fake implementation)")
}

// StatusLine: 状态说明
func StatusLine() string {
	return "[kerberos] NOT IMPLEMENTED — no fake AS-REQ/TGS-REQ (full RFC 4120 ASN.1 required)"
}
