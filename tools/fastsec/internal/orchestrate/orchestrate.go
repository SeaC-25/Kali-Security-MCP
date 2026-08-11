// Package orchestrate: scan → service fingerprint → auto-orchestrate next tools.
package orchestrate

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// PortService: 端口 → 服务映射
var PortService = map[int]string{
	22: "ssh", 21: "ftp", 25: "smtp", 53: "dns", 80: "http", 443: "https",
	445: "smb", 3306: "mysql", 1433: "mssql", 5432: "postgresql",
	6379: "redis", 27017: "mongodb", 3389: "rdp", 8080: "http-alt",
	8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
	2375: "docker", 9000: "php-fpm", 5900: "vnc",
}

// Action: 编排动作
type Action struct {
	Port    int
	Service string
	Tool    string
	Cmd     string
	Next    string
}

// Result: 编排结果
type Result struct {
	Target  string
	Ports   []int
	Actions []Action
}

// ScanPorts: TCP connect 扫描（快速）
func ScanPorts(target string, ports []int, timeout time.Duration) []int {
	var open []int
	for _, p := range ports {
		addr := fmt.Sprintf("%s:%d", target, p)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			open = append(open, p)
		}
	}
	sort.Ints(open)
	return open
}

// Orchestrate: 扫描 → 指纹 → 编排
func Orchestrate(target string, ports []int) Result {
	res := Result{Target: target}

	if len(ports) == 0 {
		// 默认常见端口
		for p := range PortService {
			ports = append(ports, p)
		}
	}

	res.Ports = ScanPorts(target, ports, 2*time.Second)
	fmt.Printf("[orchestrate] open ports: %v\n", res.Ports)

	for _, p := range res.Ports {
		svc := PortService[p]
		a := Action{Port: p, Service: svc}
		switch svc {
		case "http", "https", "http-alt", "https-alt":
			a.Tool = "fastsec"
			a.Cmd = fmt.Sprintf("fastsec -u http://%s:%d/ -d ~/fastsec/nuclei-templates/http/cves/", target, p)
			a.Next = "漏洞扫描"
		case "mysql", "mssql", "postgresql", "redis", "mongodb":
			a.Tool = "brute"
			a.Cmd = fmt.Sprintf("fastsec -brute %s -service tcp -port %d", target, p)
			a.Next = "数据库爆破"
		case "ssh":
			a.Tool = "brute"
			a.Cmd = fmt.Sprintf("fastsec -brute %s -service tcp -port 22", target)
			a.Next = "SSH 爆破"
		case "smb":
			a.Tool = "nxc"
			a.Cmd = fmt.Sprintf("nxc smb %s -u users.txt -p pass.txt", target)
			a.Next = "SMB 枚举"
		default:
			a.Tool = "nmap-sV"
			a.Cmd = fmt.Sprintf("nmap -sV -p %d %s", p, target)
			a.Next = "服务版本"
		}
		res.Actions = append(res.Actions, a)
		fmt.Printf("  %d/%s → %s: %s\n", p, svc, a.Tool, a.Cmd[:min(len(a.Cmd), 60)])
	}
	return res
}

// Format: 渲染
func Format(r Result) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[orchestrate] %d services orchestrated on %s\n", len(r.Actions), r.Target))
	for _, a := range r.Actions {
		sb.WriteString(fmt.Sprintf("  %d/%s → %s\n", a.Port, a.Service, a.Tool))
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
