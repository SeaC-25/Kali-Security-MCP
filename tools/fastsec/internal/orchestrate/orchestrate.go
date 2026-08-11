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
	// 基础
20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
53: "dns", 69: "tftp", 110: "pop3", 111: "rpcbind", 135: "msrpc",
139: "netbios", 143: "imap", 161: "snmp", 179: "bgp", 389: "ldap",
443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "printer",
548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps",
873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
	// Web
80: "http", 8080: "http-alt", 8081: "http-alt", 8082: "http-alt",
8088: "http-alt", 8888: "http-alt", 8000: "http-alt", 8008: "http-alt",
8009: "ajp", 8443: "https-alt", 9000: "http-alt", 9001: "http-alt",
9080: "http-alt", 9443: "https-alt", 10000: "http-alt", 5000: "http-alt",
7001: "weblogic", 7002: "weblogic-ssl", 8001: "http-alt", 8089: "http-alt",
8181: "http-alt", 8282: "http-alt", 9009: "http-alt", 9200: "elasticsearch",
9300: "elasticsearch-transport", 15672: "rabbitmq-mgmt", 6379: "redis",
11211: "memcached", 5984: "couchdb", 27017: "mongodb", 27018: "mongodb",
	// 数据库
3306: "mysql", 3307: "mysql", 1433: "mssql", 1434: "mssql-monitor",
1521: "oracle", 1522: "oracle", 2483: "oracle", 5432: "postgresql",
5433: "postgresql", 9042: "cassandra",
	// 远程
3389: "rdp", 5900: "vnc", 5901: "vnc", 5800: "vnc-web", 5985: "winrm",
5986: "winrm-ssl", 2222: "ssh", 5555: "adb",
	// 容器/云
2375: "docker", 2376: "docker-ssl", 6443: "k8s-api", 2379: "etcd",
2380: "etcd-peer", 10250: "kubelet", 10255: "kubelet-readonly",
	// 监控/消息
3000: "grafana", 9090: "prometheus", 9100: "node-exporter",
5601: "kibana", 61616: "activemq", 8161: "activemq-console",
8500: "consul", 4000: "docker-registry", 2049: "nfs", 3260: "iscsi",
	// 其他
88: "kerberos", 464: "kpasswd",
5500: "vnc", 5631: "pcanywhere", 6666: "unknown", 6699: "napster",
7000: "http-alt", 8086: "influxdb", 8125: "statsd", 9092: "kafka",
9418: "git", 50030: "hdfs", 50070: "hdfs-web",
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
