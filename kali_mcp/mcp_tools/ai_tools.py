#!/usr/bin/env python3
"""
AI上下文感知和会话管理工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from kali_mcp.core.mcp_session import SessionContext
from kali_mcp.core.ai_context import AIContextManager
from kali_mcp.core.ml_optimizer import MLStrategyOptimizer
from kali_mcp.core.memory_persistence import AdvancedMemoryPersistence
logger = logging.getLogger(__name__)


def register_ai_session_tools(mcp, executor, ai_context_manager, ml_strategy_optimizer):
    """AI上下文感知和会话管理工具注册"""

    # ==================== AI上下文感知工具 ====================

    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.

        Args:
            command: The command to execute

        Returns:
            Command execution results
        """
        # 危险命令黑名单检查
        DANGEROUS_PATTERNS = [
            "rm -rf /", "rm -rf /*", "mkfs.", "dd if=",
            ":(){ :|:& };:", "> /dev/sda", "chmod -R 777 /",
            "mv / ", "wget|sh", "curl|sh",
        ]
        cmd_lower = command.lower().strip()
        for pattern in DANGEROUS_PATTERNS:
            if pattern.lower() in cmd_lower:
                logger.warning(f"[AUDIT] 拦截危险命令: {command}")
                return {
                    "success": False,
                    "error": f"命令被安全策略拦截: 包含危险模式 '{pattern}'",
                    "output": "",
                    "return_code": -1,
                    "command": command
                }
        logger.info(f"[AUDIT] 执行命令: {command}")
        return executor.execute_command(command)

    @mcp.tool()
    def nuclei_scan(target: str, templates: str = "", severity: str = "critical,high,medium",
                   tags: str = "", output_format: str = "json") -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner.

        Args:
            target: Target URL, IP, or domain to scan
            templates: Specific templates to use (e.g., 'http/cves/', 'http/misconfiguration/')
                       Note: In nuclei v3+, CVE templates are under 'http/cves/' or 'network/cves/'
            severity: Severity levels to include (critical,high,medium,low,info)
            tags: Tags to filter templates (e.g., 'sqli,xss,rce')
            output_format: Output format (json or text)

        Returns:
            Nuclei scan results
        """
        # 构建nuclei命令
        cmd_parts = ["nuclei", "-u", target]

        # 添加模板过滤 (nuclei v3+ 模板路径变化)
        if templates:
            cmd_parts.extend(["-t", templates])

        # 添加严重程度过滤 (-s 是短格式，兼容新旧版本)
        if severity:
            cmd_parts.extend(["-s", severity])

        # 添加标签过滤
        if tags:
            cmd_parts.extend(["-tags", tags])

        # 设置输出格式
        if output_format == "json":
            cmd_parts.append("-jsonl")  # nuclei v3+ 使用 -jsonl

        # 添加静默模式和其他优化参数
        cmd_parts.extend(["-silent", "-rl", "100", "-timeout", "10"])

        command = " ".join(cmd_parts)
        return executor.execute_command(command)

    @mcp.tool()
    def nuclei_cve_scan(target: str, year: str = "", severity: str = "critical,high") -> Dict[str, Any]:
        """
        Execute Nuclei CVE vulnerability scan.

        Args:
            target: Target URL, IP, or domain to scan
            year: Specific CVE year to scan (e.g., '2023', '2024')
            severity: Severity levels to include

        Returns:
            CVE scan results
        """
        templates = f"cves/{year}/" if year else "cves/"
        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_web_scan(target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Execute Nuclei web application security scan.

        Args:
            target: Target web application URL
            scan_type: Type of scan (quick, comprehensive, deep)

        Returns:
            Web application scan results
        """
        if scan_type == "quick":
            templates = "http/misconfiguration/,http/vulnerabilities/"
            severity = "critical,high"
        elif scan_type == "comprehensive":
            templates = "http/,vulnerabilities/web/"
            severity = "critical,high,medium"
        elif scan_type == "deep":
            templates = "http/,vulnerabilities/,cves/,exposures/"
            severity = "critical,high,medium,low"
        else:
            templates = "http/misconfiguration/"
            severity = "critical,high"

        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_network_scan(target: str, scan_type: str = "basic") -> Dict[str, Any]:
        """
        Execute Nuclei network security scan.

        Args:
            target: Target IP or network range
            scan_type: Type of scan (basic, full)

        Returns:
            Network scan results
        """
        if scan_type == "full":
            templates = "network/,dns/,ssl/,misconfiguration/"
            severity = "critical,high,medium"
        else:
            templates = "network/,dns/"
            severity = "critical,high"

        return nuclei_scan(target, templates, severity, "", "json")

    @mcp.tool()
    def nuclei_technology_detection(target: str) -> Dict[str, Any]:
        """
        Execute Nuclei technology detection scan.

        Args:
            target: Target URL or IP to analyze

        Returns:
            Technology detection results
        """
        return nuclei_scan(target, "technologies/", "info", "", "json")

    @mcp.tool()
    def dnsrecon_scan(domain: str, scan_type: str = "-t std",
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute DNSrecon for comprehensive DNS enumeration.

        Args:
            domain: Target domain for DNS enumeration
            scan_type: Type of DNS scan (e.g., "-t std", "-t axfr", "-t brt")
            additional_args: Additional DNSrecon arguments

        Returns:
            DNS enumeration results
        """
        data = {
            "domain": domain,
            "scan_type": scan_type,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("dnsrecon", data)

    @mcp.tool()
    def wpscan_scan(target: str, api_token: str = "",
                    additional_args: str = "--enumerate p,t,u") -> Dict[str, Any]:
        """
        Execute WPScan for WordPress security testing.

        Args:
            target: Target WordPress URL
            api_token: WPScan API token for vulnerability data
            additional_args: Additional WPScan arguments

        Returns:
            WordPress security scan results
        """
        data = {
            "target": target,
            "api_token": api_token,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("wpscan", data)

    @mcp.tool()
    def reaver_attack(interface: str, bssid: str,
                      additional_args: str = "-vv") -> Dict[str, Any]:
        """
        Execute Reaver for WPS PIN attacks.

        Args:
            interface: Wireless interface in monitor mode
            bssid: Target AP BSSID
            additional_args: Additional Reaver arguments

        Returns:
            WPS attack results
        """
        data = {
            "interface": interface,
            "bssid": bssid,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("reaver", data)

    @mcp.tool()
    def bettercap_attack(interface: str, caplet: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Bettercap for network attacks and reconnaissance.

        Args:
            interface: Network interface to use
            caplet: Bettercap caplet script to run
            additional_args: Additional Bettercap arguments

        Returns:
            Network attack results
        """
        data = {
            "interface": interface,
            "caplet": caplet,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("bettercap", data)

    @mcp.tool()
    def binwalk_analysis(file_path: str, extract: bool = False,
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Binwalk for firmware analysis and extraction.

        Args:
            file_path: Path to firmware file to analyze
            extract: Whether to extract found filesystems
            additional_args: Additional Binwalk arguments

        Returns:
            Firmware analysis results
        """
        data = {
            "file_path": file_path,
            "extract": extract,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("binwalk", data)

    @mcp.tool()
    def theharvester_osint(domain: str, sources: str = "anubis,crtsh,dnsdumpster,hackertarget,rapiddns,sublist3r,urlscan",
                           limit: str = "500", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute theHarvester for OSINT and information gathering.

        Args:
            domain: Target domain for information gathering
            sources: Data sources (default: free sources without API keys)
                     API-free: anubis,crtsh,dnsdumpster,hackertarget,rapiddns,sublist3r,urlscan
                     Need API: bing,google,hunter,securityTrails,shodan
            limit: Maximum number of results per source
            additional_args: Additional theHarvester arguments

        Returns:
            OSINT gathering results
        """
        data = {
            "domain": domain,
            "sources": sources,
            "limit": limit,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("theharvester", data)

    @mcp.tool()
    def netdiscover_scan(interface: str = "", range_ip: str = "",
                         passive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Netdiscover for network host discovery.

        Args:
            interface: Network interface to use
            range_ip: IP range to scan (e.g., "192.168.1.0/24")
            passive: Use passive mode (ARP sniffing)
            additional_args: Additional Netdiscover arguments

        Returns:
            Network discovery results
        """
        data = {
            "interface": interface,
            "range": range_ip,
            "passive": passive,
            "additional_args": additional_args
        }
        return executor.execute_tool_with_data("netdiscover", data)

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  mode: str = "FUZZ", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute FFUF web fuzzer (faster alternative to wfuzz).

        Args:
            url: Target URL with FUZZ keyword (e.g., 'http://example.com/FUZZ')
            wordlist: Path to wordlist file
            mode: Fuzzing mode (FUZZ for directories, HFUZZ for headers)
            additional_args: Additional FFUF arguments

        Returns:
            FFUF scan results
        """
        cmd = f"ffuf -u {url} -w {wordlist} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def whatweb_scan(target: str, aggression: str = "1", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WhatWeb for web technology identification.

        Args:
            target: Target URL or IP
            aggression: Aggression level (1-4, 1=passive, 4=aggressive)
            additional_args: Additional WhatWeb arguments

        Returns:
            Technology identification results
        """
        cmd = f"whatweb -a {aggression} {target} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def subfinder_scan(domain: str, sources: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for fast subdomain discovery.

        Args:
            domain: Target domain
            sources: Specific sources to use (comma-separated)
            additional_args: Additional Subfinder arguments

        Returns:
            Subdomain discovery results
        """
        cmd = f"subfinder -d {domain}"
        if sources:
            cmd += f" -sources {sources}"
        cmd += f" {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def httpx_probe(targets: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute HTTP probing for target URLs.

        Uses curl as fallback when ProjectDiscovery httpx is not available.

        Args:
            targets: Target URLs, IPs, or file containing targets
            additional_args: Additional arguments

        Returns:
            HTTP probing results
        """
        import shutil

        targets_clean = targets.replace("'", "\\'")

        # 检查是否有ProjectDiscovery的httpx (Go版本)
        httpx_path = shutil.which("httpx")
        if httpx_path:
            # 尝试检测是否是ProjectDiscovery版本
            test_result = executor.execute_command("httpx -version 2>&1 || true")
            if "projectdiscovery" in test_result.get("output", "").lower():
                args = additional_args.replace("-tech-detect", "-td")
                cmd = f"echo '{targets_clean}' | httpx -silent {args}"
                return executor.execute_command(cmd)

        # 使用curl作为备选方案进行HTTP探测
        targets_list = [t.strip() for t in targets_clean.split(",") if t.strip()]
        results = []
        for target in targets_list:
            if not target.startswith("http"):
                target = f"http://{target}"
            # 使用curl进行基本HTTP探测
            cmd = f"curl -sI -o /dev/null -w '%{{http_code}} %{{url_effective}} %{{content_type}}\\n' --connect-timeout 5 '{target}' 2>/dev/null || echo 'FAILED {target}'"
            result = executor.execute_command(cmd)
            results.append(result.get("output", ""))

        return {
            "success": True,
            "output": "\n".join(results),
            "note": "Using curl fallback (ProjectDiscovery httpx not installed)"
        }

    @mcp.tool()
    def masscan_fast_scan(target: str, ports: str = "80,443,22,21,25,53,110,143,993,995,8080,8443",
                          rate: str = "10000", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan for ultra-fast port scanning.

        Args:
            target: Target IP or network range
            ports: Ports to scan (comma-separated or range)
            rate: Scan rate (packets per second)
            additional_args: Additional Masscan arguments

        Returns:
            Fast port scan results
        """
        cmd = f"masscan {target} -p{ports} --rate={rate} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def hashcat_crack(hash_file: str, attack_mode: str = "0",
                      wordlist: str = "/usr/share/wordlists/rockyou.txt",
                      hash_type: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hashcat for GPU-accelerated password cracking.

        Args:
            hash_file: File containing hashes to crack
            attack_mode: Attack mode (0=dictionary, 1=combinator, 3=brute-force)
            wordlist: Wordlist file for dictionary attacks
            hash_type: Hash type (-m parameter)
            additional_args: Additional Hashcat arguments

        Returns:
            Password cracking results
        """
        cmd = f"hashcat -a {attack_mode}"
        if hash_type:
            cmd += f" -m {hash_type}"
        cmd += f" {hash_file} {wordlist} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def searchsploit_search(term: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Search exploit database using searchsploit.

        Args:
            term: Search term (software, version, CVE, etc.)
            additional_args: Additional searchsploit arguments

        Returns:
            Exploit search results
        """
        cmd = f"searchsploit {term} {additional_args}"
        return executor.execute_command(cmd)

    @mcp.tool()
    def aircrack_attack(capture_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                        bssid: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Aircrack-ng for WiFi password cracking.

        Args:
            capture_file: Path to capture file (.cap or .pcap)
            wordlist: Wordlist for dictionary attack
            bssid: Target BSSID (optional)
            additional_args: Additional Aircrack-ng arguments

        Returns:
            WiFi cracking results
        """
        cmd = f"aircrack-ng {capture_file} -w {wordlist}"
        if bssid:
            cmd += f" -b {bssid}"
        cmd += f" {additional_args}"
        return executor.execute_command(cmd)
