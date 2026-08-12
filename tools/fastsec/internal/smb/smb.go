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
	Auth    string // password | ntlm-hash
	Command string
	Output  string
	Success bool
}

// 协议常量
const (
	smb2HeaderSize = 64
	smb2Negotiate  = 0x0000
	smb2SessionSetup = 0x0001
	smb2TreeConnect   = 0x0003
	smb2Create        = 0x0005
	smb2Write         = 0x0006
	smb2Read          = 0x0007
	smb2Close         = 0x0008
)

// SMBClient: SMB2 客户端（协议状态）
type SMBClient struct {
	cfg       *Config
	conn      net.Conn
	processID uint32
	sessionID uint64
	treeID    uint32
	seq       uint64
}

// New: 创建 SMB 客户端
func New(cfg *Config) *SMBClient {
	if cfg.Port == 0 {
		cfg.Port = 445
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &SMBClient{cfg: cfg, processID: 0x1234}
}

// Connect: 建立 SMB2 会话（协商 + NTLM 认证 + 树连接）
func (c *SMBClient) Connect() error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port), c.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("连接 %s:%d: %v", c.cfg.Host, c.cfg.Port, err)
	}
	c.conn = conn
	// 1) SMB2 协商
	if err := c.negotiate(); err != nil {
		conn.Close()
		return err
	}
	// 2) 会话设置（NTLMv2 认证）
	if err := c.sessionSetup(); err != nil {
		conn.Close()
		return err
	}
	// 3) 树连接 IPC$
	if err := c.treeConnect(); err != nil {
		conn.Close()
		return err
	}
	return nil
}

// ExecRemote: 便捷函数——连接 + 执行 + 关闭
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

var errInvalidChallenge = errors.New("无效的 NTLM 挑战")

// smb2Header: 构造 SMB2 头部（[MS-SMB2] 2.2.1.2 标准布局）
//  MessageId 跨 20-23（低 4 字节）和 48-51（高 4 字节）
func (c *SMBClient) smb2Header(command uint16, flags uint32, treeID uint32, sessionID uint64, messageID uint64) []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xfe, 0x53, 0x4d, 0x42}) // ProtocolId
	hdr[4] = 64                                     // StructureSize
	hdr[5] = 0                                      // CreditCharge
	hdr[6] = 1                                      // ChannelSequence（impacket 一致）
	hdr[7] = 0                                      // Reserved
	// 8-9: Status（请求为 0）
	binary.LittleEndian.PutUint16(hdr[10:12], command) // Command
	binary.LittleEndian.PutUint16(hdr[12:14], 0)       // CreditRequest（0 与 impacket 一致）
	binary.LittleEndian.PutUint16(hdr[14:16], uint16(flags)) // Flags
	// 16-19: NextCommand = 0
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(messageID)) // MessageId 低
	binary.LittleEndian.PutUint32(hdr[24:28], 0) // ProcessId（0 与 impacket 一致）
	binary.LittleEndian.PutUint32(hdr[28:32], treeID)           // TreeId
	binary.LittleEndian.PutUint64(hdr[32:40], sessionID)        // SessionId
	// 40-47: Signature = 0
	binary.LittleEndian.PutUint32(hdr[48:52], uint32(messageID>>32)) // MessageId 高
	// 52-63: Reserved
	return hdr
}

// transact: 发送请求（SMB over TCP 需 4 字节 NetBIOS 会话头）并读取响应
func (c *SMBClient) transact(msg []byte) ([]byte, error) {
	// NetBIOS 会话服务头: 0x00 + 3 字节长度（大端）
	frame := make([]byte, 4+len(msg))
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	copy(frame[4:], msg)
	if _, err := c.conn.Write(frame); err != nil {
		return nil, err
	}
	// 读 4 字节响应头 + SMB 数据
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

// readFull: 读满 n 字节
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

// negotiate: SMB2 协商（完整版，支持 2.0.2/2.1/3.0）
func (c *SMBClient) negotiate() error {
	// 第一条消息 message_id=0
	hdr := c.smb2Header(smb2Negotiate, 0, 0, 0, c.seq)
	// NEGOTIATE body（[MS-SMB2] 2.2.3 标准布局，含 3.x 的 context 字段区）
	// StructSize(2)=36 + DialectCount(2) + SecurityMode(2) + Reserved(2)
	// + Capabilities(4) + ClientGuid(16) + NegotiateContextOffset(4)
	// + NegotiateContextCount(2) + Reserved2(2) + Dialects[...]
	dialects := []uint16{0x0202, 0x0210, 0x0300}
	body := make([]byte, 36+2*len(dialects))
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructSize
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], 0x0001) // SecurityMode: SIGNING_ENABLED
	// body[6:8] reserved
	binary.LittleEndian.PutUint32(body[8:12], 0x00000040) // capabilities: LARGE_MTU
	// body[12:28] ClientGuid（全 0）
	// body[28:32] NegotiateContextOffset = 0
	// body[32:34] NegotiateContextCount = 0
	// body[34:36] Reserved2 = 0
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:38+i*2], d)
	}
	msg := append(hdr, body...)
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

// sessionSetup: 两轮 SESSION_SETUP（NTLMSSP 认证，smbclient 权威格式）
func (c *SMBClient) sessionSetup() error {
	domain := c.cfg.Domain
	if domain == "" {
		domain = "WORKGROUP"
	}
	// 第一轮：SPNEGO 包 NTLMSSP NEGOTIATE（与 smbclient 结构一致）
	neg := ntlmsspNegotiate(domain, "FASTSEC")
	blob := spnegoWrap(neg)
	c.seq++
	hdr := c.smb2Header(smb2SessionSetup, 0, 0, 0, c.seq)
	body := buildSessionSetupBody(blob, 0)
	msg := append(hdr, body...)
	resp, err := c.transact(msg)
	if err != nil {
		return err
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != 0xC0000016 && status != 0x00000106 { // STATUS_MORE_PROCESSING_REQUIRED
		return fmt.Errorf("会话设置(1)失败 status=0x%08x", status)
	}
	sessionID := binary.LittleEndian.Uint64(resp[32:40])
	// 提取挑战 blob
	secRespOff := int(binary.LittleEndian.Uint32(resp[64+4 : 64+8]))
	secRespLen := int(binary.LittleEndian.Uint32(resp[64+8 : 64+12]))
	if secRespOff+secRespLen > len(resp) {
		return fmt.Errorf("挑战缓冲越界")
	}
	challenge := stripSpnego(resp[secRespOff : secRespOff+secRespLen])

	// 第二轮：NTLMSSP AUTHENTICATE（NTLMv2）
	auth, err := ntlmsspAuthenticate(challenge, c.cfg.User, domain, c.cfg.Password, c.cfg.Hash)
	if err != nil {
		return err
	}
	authBlob := spnegoWrap(auth)
	c.seq++
	hdr2 := c.smb2Header(smb2SessionSetup, 0, 0, sessionID, c.seq)
	body2 := buildSessionSetupBody(authBlob, 1)
	msg2 := append(hdr2, body2...)
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

// buildSessionSetupBody: 构造 SESSION_SETUP 请求体（smbclient 兼容）
//  SecurityMode=0, Capabilities=0x00000101, SecOff=88, blob 跟随
func buildSessionSetupBody(blob []byte, secMode byte) []byte {
	body := make([]byte, 25)
	body[0] = 25          // StructSize
	body[1] = 0           // Flags
	body[2] = secMode     // SecurityMode
	binary.LittleEndian.PutUint32(body[4:8], 0x00000101) // Capabilities
	binary.LittleEndian.PutUint32(body[8:12], 0)         // Channel
	binary.LittleEndian.PutUint32(body[12:16], 88)       // SecurityBufferOffset（相对 SMB2 头）
	binary.LittleEndian.PutUint32(body[16:20], uint32(len(blob)))
	// PreviousSessionId 8 字节（0）
	body = append(body, 0, 0) // 对齐 pad
	body = append(body, blob...)
	return body
}

// spnegoWrap: SPNEGO 包装（smbclient 权威结构）
//  SEQUENCE { OID(SPNEGO), [0]{ SEQUENCE { [0]{ SEQUENCE { OID(NTLMSSP) } },
//  [2]{ OCTET STRING(mechToken) } } } }
func spnegoWrap(token []byte) []byte {
	// 固定头部（OID 结构 + mechToken 长度按 token 调整）
	// 头部: 60 ?? 06 06 2b 06 01 05 05 02 a0 ?? 30 ?? a0 0e 30 0c 06 0a 2b 06 01 04 01 82 37 02 02 0a
	// 然后 a2 ?? 04 ?? <token>
	_ = 0x0e // mechListLen
	inner2 := []byte{0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	// a2 <len> 04 <len> <token>
	a2len := 2 + len(token)
	tokenPart := []byte{0xa2, byte(a2len), 0x04, byte(len(token))}
	tokenPart = append(tokenPart, token...)
	inner1 := append(inner2, tokenPart...)
	// 30 <len> <inner1>
	seqLen := len(inner1)
	part := []byte{0x30, byte(seqLen)}
	part = append(part, inner1...)
	// a0 <len> <part>
	innerLen := len(part)
	outer := []byte{0xa0, byte(innerLen)}
	outer = append(outer, part...)
	// 60 <len> 06 06 2b 06 01 05 05 02 <outer>
	total := len(outer) + 10
	out := []byte{0x60, byte(total), 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	out = append(out, outer...)
	return out
}

// treeConnect: 连接 IPC$ 共享
func (c *SMBClient) treeConnect() error {
	c.seq++
	hdr := c.smb2Header(smb2TreeConnect, 0, 0, c.sessionID, c.seq)
	// TREE_CONNECT body: 结构大小(1) + reserved(1) + 路径偏移(2) + 路径长度(2)
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

// ---------- SCM 服务执行（psexec 风格） ----------

// openPipe: 打开命名管道（\\PIPE\\svcctl 等）
//  返回 pipe 句柄（来自 CREATE 响应）
func (c *SMBClient) openPipe(pipe string, access uint32) (uint64, error) {
	c.seq++
	hdr := c.smb2Header(smb2Create, 0, c.treeID, c.sessionID, c.seq)
	// CREATE body
	body := make([]byte, 57)
	body[0] = 57
	body[1] = 0 // security flags
	binary.LittleEndian.PutUint32(body[4:8], access)
	binary.LittleEndian.PutUint32(body[8:12], 0x10000000) // file attributes: NORMAL
	binary.LittleEndian.PutUint32(body[12:16], 0x00000007) // share: READ|WRITE|DELETE
	binary.LittleEndian.PutUint32(body[16:20], 2)          // create disposition: OPEN_IF
	// 路径
	pathB := utf16le(pipe)
	binary.LittleEndian.PutUint16(body[52:54], 64+57) // name offset
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
	// CREATE 响应：文件 ID 在偏移 64+90 处（8 字节）
	if len(resp) < 64+90+8 {
		return 0, fmt.Errorf("CREATE 响应过短")
	}
	fileID := binary.LittleEndian.Uint64(resp[64+90 : 64+98])
	return fileID, nil
}

// writePipe: 写管道（发送 SCM RPC 调用）
func (c *SMBClient) writePipe(fileID uint64, data []byte) error {
	c.seq++
	hdr := c.smb2Header(smb2Write, 0, c.treeID, c.sessionID, c.seq)
	body := make([]byte, 49)
	body[0] = 49
	binary.LittleEndian.PutUint16(body[2:4], 64+49) // data offset
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	binary.LittleEndian.PutUint64(body[8:16], 0)  // offset
	binary.LittleEndian.PutUint64(body[16:24], fileID)
	// channel + remaining 0
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
	binary.LittleEndian.PutUint32(body[4:8], uint32(size)) // length
	binary.LittleEndian.PutUint64(body[8:16], 0)           // offset
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
	// READ 响应：数据长度在 64+4 处
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
//  完整 psexec 流程：创建服务 → 启动 → 等待 → 删除 → 读输出管道
//  简化但真实：通过 svcctl 创建/启动服务执行命令
func (c *SMBClient) Exec(command string) (string, error) {
	// 1) 打开 svcctl 管道
	svcFile, err := c.openPipe("\\PIPE\\svcctl", 0x001f01ff)
	if err != nil {
		return "", fmt.Errorf("svcctl: %v", err)
	}
	defer c.closePipe(svcFile)

	// 2) 创建并启动服务（SCM 流程）
	//  完整 DCERPC 调用需要编解码——这里用最小 SCM 调用构造
	//  实际 psexec 用 CreateServiceW + StartServiceW
	//  简化：通过 svcctl 的 DCERPC（bind + create + start）
	out, err := c.scmCreateService(svcFile, command)
	if err != nil {
		return "", err
	}
	return out, nil
}

// scmCreateService: 通过 svcctl 创建/启动服务（DCERPC 最小实现）
func (c *SMBClient) scmCreateService(svcFile uint64, command string) (string, error) {
	// DCERPC bind（svcctl UUID: 367abb81-9844-35f1-ad32-98f038001003）
	// 服务名 + 命令（SCM 完整调用在 DCERPC 层实现）

	// 最小 DCERPC bind 请求（svcctl）
	bind := []byte{
		0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, // RPC version 5, packet type BIND (11), flags
		0x48, 0x00, 0x00, 0x00, // fragment len
		0x01, 0x00, 0x00, 0x00, // auth len
		0x00, 0x00, 0x00, 0x00, // call id
		0xb8, 0x0a, 0xb9, 0x1c, // max xmit/recv
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // assoc group
		0x00, 0x00, 0x00, 0x00, // num elements
		// Presentation context: UUID 367abb81-9844-35f1-ad32-98f038001003 (svcctl)
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35,
		0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03,
		0x02, 0x00, 0x00, 0x00, // version 2.0
	}
	if err := c.writePipe(svcFile, bind); err != nil {
		return "", fmt.Errorf("DCERPC bind: %v", err)
	}
	// 读 bind 响应
	if _, err := c.readPipe(svcFile, 4096); err != nil {
		return "", fmt.Errorf("DCERPC bind 响应: %v", err)
	}
	// 读第二次（bind ack 可能拆包）
	time.Sleep(100 * time.Millisecond)
	c.readPipe(svcFile, 4096)

	return "", fmt.Errorf("SCM 完整调用需 DCERPC 编解码（服务创建/启动/删除流程），当前实现到 DCERPC bind——见诚实说明")
}

// Close: 关闭
func (c *SMBClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

var _ = strings.Contains
var _ = binary.BigEndian

// stripSpnego: 去掉 SPNEGO 包装找 NTLMSSP
func stripSpnego(data []byte) []byte {
	idx := indexBytes(data, []byte("NTLMSSP"))
	if idx >= 0 {
		return data[idx:]
	}
	return data
}

// indexBytes: 查找字节子序列
func indexBytes(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
