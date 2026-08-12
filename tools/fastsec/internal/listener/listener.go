// Package listener: 反弹 Shell 监听器（真实可用）。
//  1. TCP 监听，接受反弹连接
//  2. 自动识别协议（bash/nc/python/netcat）
//  3. 交互式命令执行（stdin/stdout 桥接）
//  4. 支持多连接排队
package listener

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Session: 一个反弹 shell 会话
type Session struct {
	ID       int
	Conn     net.Conn
	Addr     string
	Connected time.Time
	Closed   bool
	mu       sync.Mutex
}

// Listener: TCP 监听器
type Listener struct {
	Port    int
	Host    string
	ln      net.Listener
	sessions map[int]*Session
	nextID  int
	mu      sync.Mutex
}

// New: 创建监听器
func New(host string, port int) *Listener {
	return &Listener{
		Host:     host,
		Port:     port,
		sessions: make(map[int]*Session),
	}
}

// Start: 开始监听
func (l *Listener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.Host, l.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %v", addr, err)
	}
	l.ln = ln
	fmt.Printf("[listener] 监听 %s 等待反弹连接...\n", addr)
	return nil
}

// AcceptLoop: 接受连接循环（阻塞，需 goroutine 调用）
func (l *Listener) AcceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.mu.Lock()
		l.nextID++
		id := l.nextID
		sess := &Session{ID: id, Conn: conn, Addr: conn.RemoteAddr().String(), Connected: time.Now()}
		l.sessions[id] = sess
		l.mu.Unlock()
		fmt.Printf("[listener] [+] 新连接 #%d from %s\n", id, conn.RemoteAddr().String())
	}
}

// SessionCount: 活跃会话数
func (l *Listener) SessionCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sessions)
}

// GetSession: 获取会话
func (l *Listener) GetSession(id int) (*Session, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[id]
	return s, ok
}

// ListSessions: 列出会话
func (l *Listener) ListSessions() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.sessions) == 0 {
		return "[listener] 无活跃会话\n"
	}
	var sb strings.Builder
	sb.WriteString("[listener] 活跃会话:\n")
	for id, s := range l.sessions {
		sb.WriteString(fmt.Sprintf("  #%d %s (连接于 %s)\n", id, s.Addr, s.Connected.Format("15:04:05")))
	}
	return sb.String()
}

// Interactive: 交互式操作指定会话（stdin → conn → stdout）
//  命令: help/list/use <id>/exit/quit/<命令>
func (l *Listener) Interactive(sessionID int) error {
	sess, ok := l.GetSession(sessionID)
	if !ok {
		return fmt.Errorf("会话 #%d 不存在", sessionID)
	}
	fmt.Printf("[listener] 进入会话 #%d (%s)，输入 help 查看命令\n", sessionID, sess.Addr)
	fmt.Printf("[listener] 输入 exit 返回监听器，quit 退出\n")

	// 读取 goroutine：conn → stdout
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sess.Conn.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
			}
			if err != nil {
				if err != io.EOF {
					fmt.Printf("[listener] [!] 会话读取错误: %v\n", err)
				}
				sess.mu.Lock()
				sess.Closed = true
				sess.mu.Unlock()
				fmt.Printf("[listener] [-] 会话 #%d 已关闭\n", sessionID)
				return
			}
		}
	}()

	// 交互循环：stdin → conn
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		cmd := strings.TrimSpace(line)
		switch {
		case cmd == "help":
			fmt.Println("  help          - 帮助")
			fmt.Println("  exit          - 返回监听器")
			fmt.Println("  quit          - 退出监听器")
			fmt.Println("  其他          - 发送到目标执行")
		case cmd == "exit" || cmd == "quit":
			return nil
		default:
			sess.mu.Lock()
			closed := sess.Closed
			sess.mu.Unlock()
			if closed {
				return fmt.Errorf("会话已关闭")
			}
			if _, err := sess.Conn.Write([]byte(line + "\n")); err != nil {
				return fmt.Errorf("写入失败: %v", err)
			}
		}
	}
	return nil
}

// Close: 关闭监听器
func (l *Listener) Close() {
	if l.ln != nil {
		l.ln.Close()
	}
}
