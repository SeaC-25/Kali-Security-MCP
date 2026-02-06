#!/usr/bin/env python3
"""
KaliMCP 快速模式配置
大幅优化工具执行时间，提升响应速度
"""

# 快速模式配置
FAST_MODE_CONFIG = {
    # 全局超时设置 - 从5分钟降到30秒
    "global_timeout": 30,

    # Nmap快速扫描配置
    "nmap_fast": {
        "common_ports": "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080",
        "scan_type": "-sS",  # SYN扫描最快
        "timing": "-T5",     # 最激进的时序
        "options": "--open --host-timeout 10s --max-retries 1"
    },

    # Gobuster快速目录扫描
    "gobuster_fast": {
        "threads": "50",     # 增加并发线程
        "timeout": "10s",    # 10秒超时
        "wordlist": "/usr/share/wordlists/dirb/small.txt",  # 使用小字典
        "options": "-q --no-error"  # 静默模式，不显示错误
    },

    # Nuclei快速漏洞扫描
    "nuclei_fast": {
        "rate_limit": "150",   # 每秒150个请求
        "timeout": "5",        # 5秒超时
        "concurrency": "25",   # 25个并发
        "options": "-silent -ni"  # 静默模式，不交互
    },

    # Masscan超快端口扫描
    "masscan_fast": {
        "rate": "10000",      # 每秒10000包
        "wait": "0",          # 不等待
        "retries": "1"        # 只重试1次
    },

    # SQLMap快速注入检测
    "sqlmap_fast": {
        "timeout": "10",      # 10秒超时
        "threads": "5",       # 5个线程
        "options": "--batch --smart --level=1 --risk=1"  # 最快检测级别
    }
}

# 快速扫描端口列表 (只扫描常用端口)
FAST_PORTS = {
    "top_10": "21,22,23,80,110,139,443,993,995,8080",
    "top_20": "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080",
    "web_only": "80,443,8080,8443,3000,5000,8000,9000",
    "common_services": "21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432"
}

# 快速字典文件路径
FAST_WORDLISTS = {
    "small_dir": "/usr/share/wordlists/dirb/small.txt",
    "common_dir": "/usr/share/wordlists/dirb/common.txt",
    "quick_dns": "/usr/share/wordlists/fierce/hosts.txt"
}

def get_fast_nmap_command(target, port_range="top_20"):
    """生成快速nmap命令"""
    config = FAST_MODE_CONFIG["nmap_fast"]
    ports = FAST_PORTS.get(port_range, FAST_PORTS["top_20"])

    return f'nmap {target} -p {ports} {config["scan_type"]} {config["timing"]} {config["options"]}'

def get_fast_gobuster_command(target, wordlist_type="small_dir"):
    """生成快速gobuster命令"""
    config = FAST_MODE_CONFIG["gobuster_fast"]
    wordlist = FAST_WORDLISTS.get(wordlist_type, FAST_WORDLISTS["small_dir"])

    return f'gobuster dir -u {target} -w {wordlist} -t {config["threads"]} --timeout {config["timeout"]} {config["options"]}'

def get_fast_nuclei_command(target):
    """生成快速nuclei命令"""
    config = FAST_MODE_CONFIG["nuclei_fast"]

    return f'nuclei -u {target} -rl {config["rate_limit"]} -timeout {config["timeout"]} -c {config["concurrency"]} {config["options"]}'

# 导出配置
__all__ = ['FAST_MODE_CONFIG', 'FAST_PORTS', 'FAST_WORDLISTS', 'get_fast_nmap_command', 'get_fast_gobuster_command', 'get_fast_nuclei_command']