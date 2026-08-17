#!/usr/bin/env python3
"""fastsec 能力工具面：自研 Go 扫描引擎的每个能力暴露为独立 MCP 工具。

背景：fastsec 是单二进制 AI 原生扫描器（替代 25 个外部工具）。此前 MCP 面上只有
`kali_run` 元回退能按名调到它（`fastsec_scan` 只是 _MCP_TO_REGISTRY 映射，无原生
注册）——对 LLM/子代理是一层又深又难用的间接。本模块把每个能力注册为意图明确的
专用 MCP 工具，薄包装 `executor.execute_tool_with_data("fastsec", data)`：
复用 tool_registry 的 ToolSpec 命令构建 + ssh 后端路由 + 结果缓存 + 输出解析。

Stealth 默认（继承会话2 痕迹最小化）：
- `fastsec_xss_scan` 默认 `xss_benign=True`（无害 marker 单请求，无 alert(1)）
- `fastsec_sqli_scan` 默认 `danger_level=0`（只读探测，无时间盲注/写操作）
- 通用节流参数透传（concurrency/delay_min/delay_max），不覆盖内建默认。

保留 `kali_run("fastsec_scan", ...)` 作兼容回退；本模块工具为扫描主路径。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _run(executor, data: Dict[str, Any]) -> Dict[str, Any]:
    """执行 fastsec 命令（registry key="fastsec"）；失败返回错误结构不抛。"""
    try:
        return executor.execute_tool_with_data("fastsec", data)
    except Exception as e:  # noqa: BLE001 —— 工具失败返回错误，不抛异常
        return {"success": False, "error": f"fastsec 执行失败: {e}", "tool_name": "fastsec"}


def _base(url: str, concurrency: int = 8, delay_min: int = 300,
          delay_max: int = 800, proxy: str = "") -> Dict[str, Any]:
    """公共参数（温和节流默认，符合 RATE_DISCIPLINE）。"""
    data: Dict[str, Any] = {"url": url}
    if concurrency:
        data["concurrency"] = str(int(concurrency))
    if delay_min:
        data["delay_min"] = str(int(delay_min))
    if delay_max:
        data["delay_max"] = str(int(delay_max))
    if proxy:
        data["proxy"] = proxy
    return data


def register_fastsec_tools(mcp, executor):
    """注册 fastsec 全能力工具（harness 档位）。"""

    @mcp.tool()
    def fastsec_port_scan(
        target: str,
        scan_range: str = "1-1000",
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec 端口扫描（替代 nmap -sT 轻扫）。

        Args:
            target: 目标 IP/主机
            scan_range: 端口范围（默认 1-1000）
            concurrency: 并发（默认 8，温和）
            delay_min/delay_max: 请求间隔 ms（默认 300-800，内建节流）
            proxy: 代理 URL（可选）

        Returns:
            执行结果（含 output/parsed）
        """
        data = _base(target, concurrency, delay_min, delay_max, proxy)
        data["scan"] = target
        data["scan_range"] = scan_range
        return _run(executor, data)

    @mcp.tool()
    def fastsec_dir_scan(
        url: str,
        wordlist: str = "",
        concurrency: int = 8,
        delay_min: int = 500,
        delay_max: int = 1500,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec 目录枚举（替代 gobuster/dirb/ffuf；3-gate 基线防误报）。

        Args:
            url: 目标 URL
            wordlist: 字典路径（空 → fastsec 内置 data/dir/）
            concurrency: 并发（默认 8）
            delay_min/delay_max: 请求间隔 ms（默认 500-1500）

        Returns:
            执行结果
        """
        data = _base(url, concurrency, delay_min, delay_max, proxy)
        data["dir"] = url
        if wordlist:
            data["wordlist"] = wordlist
        return _run(executor, data)

    @mcp.tool()
    def fastsec_cms_scan(
        url: str,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec CMS 识别（wordpress/joomla/drupal 等指纹）。

        Args:
            url: 目标 URL
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            执行结果
        """
        data = _base(url, concurrency, delay_min, delay_max)
        data["cms"] = url
        return _run(executor, data)

    @mcp.tool()
    def fastsec_sqli_scan(
        url: str,
        params: str = "",
        danger_level: int = 0,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec SQL 注入检测（替代 sqlmap；只读探测默认）。

        Args:
            url: 目标 URL
            params: 待测参数逗号列表（空 → URL query 自动发现）
            danger_level: 0=只读探测（默认，安全）; 1=+时间盲注(SLEEP≤1s);
                          2=+完整 payload（仅显式授权）
            concurrency/delay_min/delay_max: 节流参数
            proxy: 代理 URL（可选）

        Returns:
            执行结果（injectable 标志在输出）
        """
        data = _base(url, concurrency, delay_min, delay_max, proxy)
        data["inject"] = params or "auto"
        data["danger_level"] = str(int(danger_level))
        return _run(executor, data)

    @mcp.tool()
    def fastsec_xss_scan(
        url: str,
        params: str = "auto",
        xss_benign: bool = True,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec XSS 反射检测（无害 marker 单请求默认，对目标影响最小）。

        Args:
            url: 目标 URL
            params: 待测参数逗号列表（auto → URL query 自动发现）
            xss_benign: True=无害 marker 单请求（默认，不向生产打 alert(1)）;
                        False=完整 alert(1) payload 集（仅显式授权/CTF）
            concurrency/delay_min/delay_max: 节流参数
            proxy: 代理 URL（可选）

        Returns:
            执行结果（未转义回显 marker → XSS 命中，证据含 marker 非 payload）
        """
        data = _base(url, concurrency, delay_min, delay_max, proxy)
        data["xss"] = params or "auto"
        data["xss_benign"] = "true" if xss_benign else "false"
        return _run(executor, data)

    @mcp.tool()
    def fastsec_brute(
        target: str,
        service: str = "http-form",
        user_file: str = "",
        pass_file: str = "",
        form_url: str = "",
        form_user: str = "username",
        form_pass: str = "password",
        form_success: str = "",
        port: int = 0,
        concurrency: int = 8,
        delay_min: int = 500,
        delay_max: int = 1500,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec 登录爆破（http-form/tcp-banner；内置 263 万口令字典）。

        Args:
            target: 爆破目标（host 或 http://url）
            service: http-form | tcp-banner
            user_file/pass_file: 自定义字典（空 → fastsec 内置 data/brute/）
            form_url/form_user/form_pass/form_success: http-form 表单配置
            port: tcp-banner 端口
            concurrency/delay_min/delay_max: 节流（默认 500-1500，慢速防封）
            proxy: 代理 URL（可选）

        Returns:
            执行结果
        """
        data: Dict[str, Any] = {"brute": target, "service": service}
        if user_file:
            data["user_file"] = user_file
        if pass_file:
            data["pass_file"] = pass_file
        if form_url:
            data["form_url"] = form_url
        data["form_user"] = form_user
        data["form_pass"] = form_pass
        if form_success:
            data["form_success"] = form_success
        if port:
            data["port"] = str(int(port))
        data.update(_base(target, concurrency, delay_min, delay_max, proxy))
        return _run(executor, data)

    @mcp.tool()
    def fastsec_osint(
        domain: str,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec OSINT 聚合（域名相关信息搜集）。

        Args:
            domain: 目标域名
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            执行结果
        """
        data = _base(domain, concurrency, delay_min, delay_max)
        data["osint"] = domain
        return _run(executor, data)

    @mcp.tool()
    def fastsec_fingerprint(
        host: str,
        ports: str = "80,443,22,3306,6379,8080,8443,9200,27017,1433,5432,7001,8090,4180,4174",
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec 服务指纹识别（版本/CMS/中间件）。

        Args:
            host: 目标主机
            ports: 待测端口逗号列表
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            执行结果
        """
        data = _base(host, concurrency, delay_min, delay_max)
        data["fingerprint"] = host
        data["fingerprint_ports"] = ports
        return _run(executor, data)

    @mcp.tool()
    def fastsec_template_scan(
        url: str,
        templates: str = "",
        template: str = "",
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec 模板化漏洞扫描（nuclei 风格模板，替代 nuclei/nikto）。

        Args:
            url: 目标 URL
            templates: 模板目录（默认 fastsec 内置模板）
            template: 单模板文件（可选）
            concurrency/delay_min/delay_max: 节流参数
            proxy: 代理 URL（可选）

        Returns:
            执行结果
        """
        data = _base(url, concurrency, delay_min, delay_max, proxy)
        if templates:
            data["templates"] = templates
        if template:
            data["template"] = template
        return _run(executor, data)

    @mcp.tool()
    def fastsec_crack(
        hash_value: str,
        wordlist: str = "",
        concurrency: int = 8,
    ) -> Dict[str, Any]:
        """fastsec 哈希破解（如 md5:5f4dcc3b5aa765d61d8327deb882cf99）。

        Args:
            hash_value: 格式 <algo>:<hash>（md5/sha1/sha256/ntlm 等）
            wordlist: 外部字典（空 → fastsec 内置 263 万口令）
            concurrency: 并发

        Returns:
            执行结果
        """
        data = {"crack": hash_value}
        if wordlist:
            data["crack_wordlist"] = wordlist
        data["concurrency"] = str(int(concurrency))
        return _run(executor, data)

    @mcp.tool()
    def fastsec_kerberos(
        kdc: str,
        domain: str = "",
        users: str = "",
        password: str = "",
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec Kerberos 攻击（AS-REP Roasting / Kerberoast）。

        Args:
            kdc: KDC IP
            domain: 域（如 corp.local）
            users: 用户列表逗号分隔（AS-REP 用）
            password: 口令（提供则启用 Kerberoast）
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            执行结果
        """
        data = _base(kdc, concurrency, delay_min, delay_max)
        data["kerberos"] = kdc
        if domain:
            data["domain"] = domain
        if users:
            data["kusers"] = users
        if password:
            data["kpass"] = password
        return _run(executor, data)

    @mcp.tool()
    def fastsec_diff(
        url: str,
        params: str = "",
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec 行为差异探测（参数值变化 → 响应差分，定位隐藏参数/逻辑差异）。

        Args:
            url: 目标 URL
            params: 待测参数逗号列表
            concurrency/delay_min/delay_max: 节流参数
            proxy: 代理 URL（可选）

        Returns:
            执行结果
        """
        data = _base(url, concurrency, delay_min, delay_max, proxy)
        data["diff"] = params or ""
        return _run(executor, data)

    @mcp.tool()
    def fastsec_soceng(
        name: str,
    ) -> Dict[str, Any]:
        """fastsec 社工口令字典生成（本地生成，不对外请求）。

        Args:
            name: 目标姓名/昵称

        Returns:
            生成的口令候选列表
        """
        data = {"soceng": name}
        return _run(executor, data)

    @mcp.tool()
    def fastsec_orchestrate(
        target: str,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec 扫描编排（单目标多能力编排扫描）。

        Args:
            target: 目标
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            编排扫描结果
        """
        data = _base(target, concurrency, delay_min, delay_max)
        data["orchestrate"] = target
        return _run(executor, data)

    @mcp.tool()
    def fastsec_seq(
        seq_file: str,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec 状态化攻击序列执行（YAML 序列文件）。

        Args:
            seq_file: 序列 YAML 文件路径（base_url + steps）
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            序列执行结果
        """
        data = _base("", concurrency, delay_min, delay_max)
        data.pop("url", None)
        data["seq"] = seq_file
        return _run(executor, data)

    @mcp.tool()
    def fastsec_audit(
        path: str,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec 静态代码审计（SAST，本地文件/目录）。

        Args:
            path: 待审计文件或目录路径
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            审计发现
        """
        data = _base("", concurrency, delay_min, delay_max)
        data.pop("url", None)
        data["audit"] = path
        return _run(executor, data)

    @mcp.tool()
    def fastsec_file(
        path: str,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec 取证文件分析（替代 binwalk）。

        Args:
            path: 待分析文件路径
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            文件分析结果
        """
        data = _base("", concurrency, delay_min, delay_max)
        data.pop("url", None)
        data["file"] = path
        return _run(executor, data)

    @mcp.tool()
    def fastsec_user(
        name: str,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec 用户名搜索（跨平台 OSINT，替代 sherlock）。

        Args:
            name: 用户名
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            搜索命中
        """
        data = _base("", concurrency, delay_min, delay_max)
        data.pop("url", None)
        data["user"] = name
        return _run(executor, data)

    @mcp.tool()
    def fastsec_shell(
        lang: str,
        host: str = "127.0.0.1",
        port: int = 4444,
        enc: str = "raw",
    ) -> Dict[str, Any]:
        """fastsec 反弹 shell payload 生成（只生成命令文本，不执行）。

        Args:
            lang: bash/python/perl/php/powershell 等
            host: 监听主机
            port: 监听端口
            enc: raw | base64 | hex | url

        Returns:
            生成的 payload 文本
        """
        data = {
            "shell": lang,
            "s_host": host,
            "s_port": str(int(port)),
            "s_enc": enc,
        }
        return _run(executor, data)

    @mcp.tool()
    def fastsec_sam(
        sam_file: str,
        system_file: str = "",
    ) -> Dict[str, Any]:
        """fastsec SAM 凭据提取（本地 hive 文件解析，取证用）。

        Args:
            sam_file: SAM hive 文件路径
            system_file: SYSTEM hive 文件路径（取 bootkey，可选）

        Returns:
            提取的凭据
        """
        data = {"sam": sam_file}
        if system_file:
            data["system"] = system_file
        return _run(executor, data)

    @mcp.tool()
    def fastsec_smb(
        host: str,
        command: str = "whoami",
        user: str = "administrator",
        port: int = 445,
        password: str = "",
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
    ) -> Dict[str, Any]:
        """fastsec SMB 远程命令执行（横向移动，需已授权凭据）。

        Args:
            host: 目标主机
            command: 远程执行的命令（默认 whoami，只读探测）
            user: SMB 用户名
            port: SMB 端口
            password: 口令或 NTLM hash
            concurrency/delay_min/delay_max: 节流参数

        Returns:
            远程执行结果
        """
        data = _base(host, concurrency, delay_min, delay_max)
        data["smb"] = host
        data["smb_cmd"] = command
        data["smb_user"] = user
        data["smb_port"] = str(int(port))
        if password:
            data["smb_pass"] = password
        return _run(executor, data)

    @mcp.tool()
    def fastsec_dump(
        url: str,
        param: str = "id",
        danger_level: int = 0,
        concurrency: int = 8,
        delay_min: int = 300,
        delay_max: int = 800,
        proxy: str = "",
    ) -> Dict[str, Any]:
        """fastsec SQL 注入数据提取（--dump 类，**数据泄露操作**）。

        危险门槛：danger_level 必须 ≥1 才执行（利用类操作，需显式授权）；
        默认 0 → 返回错误不执行（符合"验证即停/利用类需显式授权"纪律）。

        Args:
            url: 目标 URL（注入点）
            param: 注入参数
            danger_level: 1=允许数据提取（显式授权）; 0=拒绝（默认）
            concurrency/delay_min/delay_max: 节流参数
            proxy: 代理 URL（可选）

        Returns:
            提取的数据；danger_level<1 → 拒绝错误
        """
        if int(danger_level or 0) < 1:
            return {
                "success": False,
                "error": "fastsec_dump 是数据提取操作（利用类）：需显式 danger_level>=1 授权",
                "tool_name": "fastsec",
            }
        data = _base(url, concurrency, delay_min, delay_max, proxy)
        data["dump"] = url
        data["dump_param"] = param
        data["danger_level"] = str(int(danger_level))
        return _run(executor, data)

    @mcp.tool()
    def fastsec_kb(
        query: str,
    ) -> Dict[str, Any]:
        """fastsec 本地知识库查询（内置 data/index/knowledge.json，非扫描）。

        Args:
            query: 检索关键词

        Returns:
            知识库命中条目
        """
        return _run(executor, {"kb": query})
