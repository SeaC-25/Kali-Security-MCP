package smb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Config: SMB 连接配置
type Config struct {
	Host     string
	Port     int
	Domain   string
	User     string
	Password string
	Hash     string // NTHash（pass-the-hash）
	Timeout  time.Duration
}

// Result: 执行结果
type Result struct {
	Host    string
	User    string
	Auth    string
	Command string
	Output  string
	Success bool
}

// 协议常量
const (
	smb2HeaderSize  = 64
	smb2Negotiate   = 0x0000
	smb2SessionSetup = 0x0001
	smb2TreeConnect  = 0x0003
	smb2Create       = 0x0005
	smb2Write        = 0x0006
	smb2Read         = 0x0007
	smb2Close        = 0x0008
)

// SMBClient: SMB2 客户端
type SMBClient struct {
	cfg       *Config
	conn      net.Conn
	processID uint32
	sessionID uint64
	treeID    uint32
	seq       uint64
}

var errInvalidChallenge = errors.New("无效的 NTLM 挑战")

// New: 创建客户端
func New(cfg *Config) *SMBClient {
	if cfg.Port == 0 {
		cfg.Port = 445
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &SMBClient{cfg: cfg, processID: 0x1234}
}

// Connect: 协商 + NTLMv2 认证 + 树连接
func (c *SMBClient) Connect() error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port), c.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("连接 %s:%d: %v", c.cfg.Host, c.cfg.Port, err)
	}
	c.conn = conn
	if err := c.negotiate(); err != nil {
		conn.Close()
		return err
	}
	if err := c.sessionSetup(); err != nil {
		conn.Close()
		return err
	}
	if err := c.treeConnect(); err != nil {
		conn.Close()
		return err
	}
	return nil
}

// ExecRemote: 便捷函数
func ExecRemote(cfg *Config, command string) Result {
	c := New(cfg)
	defer c.Close()
	if err := c.Connect(); err != nil {
		return Result{Host: cfg.Host, User: cfg.User, Command: command, Output: err.Error(), Success: false}
	}
	out, err := c.Exec(command)
	if err != nil {
		return Result{Host: cfg.Host, User: cfg.User, Command: command, Output: err.Error(), Success: false}
	}
	return Result{Host: cfg.Host, User: cfg.User, Command: command, Output: out, Success: true}
}

// smb2Header: [MS-SMB2] 2.2.1.2 标准头
func (c *SMBClient) smb2Header(command uint16, flags uint32, treeID uint32, sessionID uint64, messageID uint64) []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xfe, 0x53, 0x4d, 0x42})
	hdr[4] = 64
	hdr[5] = 0 // CreditCharge
	hdr[6] = 1 // ChannelSequence（impacket 一致）
	hdr[7] = 0
	binary.LittleEndian.PutUint16(hdr[10:12], command)
	binary.LittleEndian.PutUint16(hdr[12:14], 1) // CreditRequest（smbclient 用 1）
	f := uint16(0)
	if command == smb2SessionSetup {
		f = 0x2000 // SMB2_FLAGS_SIGNED（smbclient 一致）
	}
	binary.LittleEndian.PutUint16(hdr[14:16], f)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(messageID))
	binary.LittleEndian.PutUint32(hdr[24:28], 0) // ProcessId
	binary.LittleEndian.PutUint32(hdr[28:32], treeID)
	binary.LittleEndian.PutUint64(hdr[32:40], sessionID)
	binary.LittleEndian.PutUint32(hdr[48:52], uint32(messageID>>32))
	return hdr
}

// transact: NetBIOS 会话头 + 读响应
func (c *SMBClient) transact(msg []byte) ([]byte, error) {
	frame := make([]byte, 4+len(msg))
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	copy(frame[4:], msg)
	if _, err := c.conn.Write(frame); err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := readFull(c.conn, head); err != nil {
		return nil, err
	}
	respLen := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if respLen <= 0 || respLen > 1<<20 {
		return nil, fmt.Errorf("无效响应长度: %d", respLen)
	}
	buf := make([]byte, respLen)
	if _, err := readFull(c.conn, buf); err != nil {
		return nil, err
	}
	if len(buf) < 64 {
		return nil, fmt.Errorf("响应过短: %d", len(buf))
	}
	return buf, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// negotiate: SMB2 协商（硬编码 smbclient 权威帧，已验证与 Samba 4.24 互操作）
func (c *SMBClient) negotiate() error {
	// smbclient 4.24 协商帧 body（5 dialects + 3.1.1 contexts，去 netbios）
	bodyHex := "fe534d42400000000000000000001f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024000400010000007f000000e5afdeab3a60134abc524033ed9bed9570000000050000001002000302031103000000000100260000000000010020000100fde6b4ee9871fecdce7e5c56498e30879f6271982e3b896b49151c5de2d0b0b2000002000a0000000000040002000100040003000000000000000800080000000000030002000100000005001200000000003100320037002e0030002e0030002e003100000000000000000110000000000093ad25509cb411e7b42383de968bcd7c"
	msg := mustHex(bodyHex)
	resp, err := c.transact(msg)
	if err != nil {
		return err
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0 {
		return fmt.Errorf("协商失败 status=0x%08x", status)
	}
	return nil
}

// sessionSetup: 两轮 NTLMSSP 认证（smbclient 权威帧）
func (c *SMBClient) sessionSetup() error {
	domain := c.cfg.Domain
	if domain == "" {
		domain = "WORKGROUP"
	}
	// 第一轮：compound（NEGOTIATE 头 + SESSION_SETUP 第二命令）——Samba 4.24 要求
	neg := ntlmsspNegotiate(domain, "FASTSEC")
	blob := spnegoWrap(neg)
	// compound：首命令头 Command=0(NEGOTIATE) NextCommand=16，第二命令头 Command=1(SESSION_SETUP)
	hdr := c.smb2Header(smb2Negotiate, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(hdr[16:20], 16) // NextCommand=16
	binary.LittleEndian.PutUint32(hdr[24:28], 1)  // ProcessId=1
	// 第二命令：SESSION_SETUP 头（Command=1, Flags=0x2000, Credit=1）
	hdr2 := c.smb2Header(smb2SessionSetup, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(hdr2[24:28], 1)
	body := buildSessionSetupBody(blob, 0)
	msg := append(hdr, hdr2...)
	msg = append(msg, body...)
	resp, err := c.transact(msg)
	if err != nil {
		return err
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0xC0000016 && status != 0x00000106 {
		return fmt.Errorf("会话设置(1)失败 status=0x%08x", status)
	}
	sessionID := binary.LittleEndian.Uint64(resp[32:40])
	// SESSION_SETUP 响应: [64:66]StructSize=9 [66:68]SessionFlags [68:72]SecOff [72:76]SecLen
	// 直接在响应中找 NTLMSSP（最稳，绕开响应头偏移差异）
	challenge := stripSpnego(resp[64:])
	if len(challenge) < 32 {
		return fmt.Errorf("挑战 blob 无效")
	}
	_ = sessionID

	// 第二轮：NTLMSSP AUTHENTICATE（NTLMv2）
	auth, err := ntlmsspAuthenticate(challenge, c.cfg.User, domain, c.cfg.Password, c.cfg.Hash)
	if err != nil {
		return err
	}
	authBlob := spnegoWrap(auth)
	hdr3 := c.smb2Header(smb2SessionSetup, 0, 0, sessionID, 0)
	binary.LittleEndian.PutUint32(hdr3[24:28], 1)
	body3 := buildSessionSetupBody(authBlob, 1)
	msg2 := append(hdr3, body3...)
	resp2, err := c.transact(msg2)
	if err != nil {
		return err
	}
	status2 := binary.LittleEndian.Uint32(resp2[8:12])
	if status2 != 0 {
		return fmt.Errorf("会话设置(2)失败 status=0x%08x", status2)
	}
	c.sessionID = sessionID
	return nil
}

// buildSessionSetupBody: 24 字节头 + blob（smbclient 权威，0 diff 验证）
func buildSessionSetupBody(blob []byte, secMode byte) []byte {
	// smbclient 权威 24 字节 body 头（帧 64-87）+ blob（帧 88 起）
	// [64]=25 StructSize [65]Flags [66]SecurityMode [67]Reserved
	// [68:71]Capabilities [72:75]Channel [76:78]SecOff=88(LE) [78:80]SecLen(LE)
	// [80:87]PrevSessionID=0
	body := make([]byte, 24)
	body[0] = 25
	body[3] = 1
	body[4] = 1
	binary.LittleEndian.PutUint16(body[12:14], 88) // SecOff = 88（帧 76）
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(blob))) // SecLen（帧 78）
	// body[16:24] PrevSessionID = 0
	body = append(body, blob...)
	return body
}

// spnegoWrap: SPNEGO 包装（smbclient 权威 60 48 结构）
//  60 <len> 06 06 2b 06 01 05 05 02 a0 <len> 30 <len> a0 0e 30 0c 06 0a 2b 06 01 04 01 82 37 02 02 0a a2 <len> 04 <len> <token>
func spnegoWrap(token []byte) []byte {
	inner2 := []byte{0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	// 长格式支持
	a2len := 2 + len(token)
	a2part := []byte{0xa2}
	a2part = append(a2part, derLen(a2len)...)
	a2part = append(a2part, 0x04)
	a2part = append(a2part, derLen(len(token))...)
	a2part = append(a2part, token...)
	inner1 := append(inner2, a2part...)
	part := []byte{0x30}
	part = append(part, derLen(len(inner1))...)
	part = append(part, inner1...)
	outer := []byte{0xa0}
	outer = append(outer, derLen(len(part))...)
	outer = append(outer, part...)
	total := len(outer) + 8
	out := []byte{0x60, byte(total), 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	out = append(out, outer...)
	return out
}

// derLen: DER 长度编码（<128 单字节，否则长格式）
func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

// treeConnect: 连接 IPC$
func (c *SMBClient) treeConnect() error {
	c.seq++
	hdr := c.smb2Header(smb2TreeConnect, 0, 0, c.sessionID, c.seq)
	path := "\\\\" + c.cfg.Host + "\\IPC$"
	pathB := utf16le(path)
	body := make([]byte, 8)
	body[0] = 9
	binary.LittleEndian.PutUint16(body[2:4], 64+9)
	binary.LittleEndian.PutUint16(body[4:6], uint16(len(pathB)))
	body = append(body, pathB...)
	msg := append(hdr, body...)
	resp, err := c.transact(msg)
	if err != nil {
		return err
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0 {
		return fmt.Errorf("树连接失败 status=0x%08x", status)
	}
	c.treeID = binary.LittleEndian.Uint32(resp[24:28])
	return nil
}

// openPipe: 打开命名管道
func (c *SMBClient) openPipe(pipe string, access uint32) (uint64, error) {
	c.seq++
	hdr := c.smb2Header(smb2Create, 0, c.treeID, c.sessionID, c.seq)
	body := make([]byte, 57)
	body[0] = 57
	binary.LittleEndian.PutUint32(body[4:8], access)
	binary.LittleEndian.PutUint32(body[8:12], 0x10000000)
	binary.LittleEndian.PutUint32(body[12:16], 0x00000007)
	binary.LittleEndian.PutUint32(body[16:20], 2)
	pathB := utf16le(pipe)
	binary.LittleEndian.PutUint16(body[52:54], 64+57)
	binary.LittleEndian.PutUint16(body[54:56], uint16(len(pathB)))
	body = append(body, pathB...)
	msg := append(hdr, body...)
	resp, err := c.transact(msg)
	if err != nil {
		return 0, err
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0 {
		return 0, fmt.Errorf("打开管道失败 status=0x%08x", status)
	}
	fileID := binary.LittleEndian.Uint64(resp[64+90 : 64+98])
	return fileID, nil
}

// writePipe: 写管道
func (c *SMBClient) writePipe(fileID uint64, data []byte) error {
	c.seq++
	hdr := c.smb2Header(smb2Write, 0, c.treeID, c.sessionID, c.seq)
	body := make([]byte, 49)
	body[0] = 49
	binary.LittleEndian.PutUint16(body[2:4], 64+49)
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	binary.LittleEndian.PutUint64(body[16:24], fileID)
	body = append(body, data...)
	msg := append(hdr, body...)
	resp, err := c.transact(msg)
	if err != nil {
		return err
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0 {
		return fmt.Errorf("写管道失败 status=0x%08x", status)
	}
	return nil
}

// readPipe: 读管道
func (c *SMBClient) readPipe(fileID uint64, size int) ([]byte, error) {
	c.seq++
	hdr := c.smb2Header(smb2Read, 0, c.treeID, c.sessionID, c.seq)
	body := make([]byte, 49)
	body[0] = 49
	binary.LittleEndian.PutUint32(body[4:8], uint32(size))
	binary.LittleEndian.PutUint64(body[16:24], fileID)
	msg := append(hdr, body...)
	resp, err := c.transact(msg)
	if err != nil {
		return nil, err
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0 {
		return nil, fmt.Errorf("读管道失败 status=0x%08x", status)
	}
	dataLen := int(binary.LittleEndian.Uint32(resp[64+4 : 64+8]))
	dataOff := int(binary.LittleEndian.Uint32(resp[64+8 : 64+12]))
	if dataOff+dataLen <= len(resp) {
		return resp[dataOff : dataOff+dataLen], nil
	}
	return nil, nil
}

// closePipe: 关闭管道
func (c *SMBClient) closePipe(fileID uint64) {
	c.seq++
	hdr := c.smb2Header(smb2Close, 0, c.treeID, c.sessionID, c.seq)
	body := make([]byte, 24)
	body[0] = 24
	binary.LittleEndian.PutUint64(body[8:16], fileID)
	msg := append(hdr, body...)
	c.transact(msg)
}

// Exec: SCM 服务执行命令
func (c *SMBClient) Exec(command string) (string, error) {
	svcFile, err := c.openPipe("\\PIPE\\svcctl", 0x001f01ff)
	if err != nil {
		return "", fmt.Errorf("svcctl: %v", err)
	}
	defer c.closePipe(svcFile)
	return c.scmCreateService(svcFile, command)
}

// scmCreateService: DCERPC svcctl 调用
func (c *SMBClient) scmCreateService(svcFile uint64, command string) (string, error) {
	// DCERPC bind（svcctl UUID: 367abb81-9844-35f1-ad32-98f038001003）
	bind := []byte{
		0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
		0x48, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xb8, 0x0a, 0xb9, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35,
		0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03,
		0x02, 0x00, 0x00, 0x00,
	}
	if err := c.writePipe(svcFile, bind); err != nil {
		return "", fmt.Errorf("DCERPC bind: %v", err)
	}
	if _, err := c.readPipe(svcFile, 4096); err != nil {
		return "", fmt.Errorf("DCERPC bind 响应: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	c.readPipe(svcFile, 4096)
	return "", fmt.Errorf("SCM 完整调用需 DCERPC 编解码（服务创建/启动/删除流程），当前到 DCERPC bind")
}

// Close: 关闭连接
func (c *SMBClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// ---------- 导出（测试） ----------

func (c *SMBClient) SessionIDExport() uint64 { return c.sessionID }
func (c *SMBClient) TreeIDExport() uint32   { return c.treeID }

var _ = strings.Contains
var _ = binary.BigEndian
