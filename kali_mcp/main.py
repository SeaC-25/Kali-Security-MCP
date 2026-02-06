#!/usr/bin/env python3
"""
Kali MCP 主入口文件

智能化渗透测试MCP服务器 v2.0

功能:
- 193个安全工具的统一MCP接口
- 异步并行执行
- AI驱动的工具推荐和策略优化
- 统一输出格式和报告生成
- 实时进度追踪
- Web可视化界面

使用方法:
    python -m kali_mcp.main                    # 启动MCP服务器
    python -m kali_mcp.main --web              # 同时启动Web界面
    python -m kali_mcp.main --health-check     # 运行健康检查
    python -m kali_mcp.main --list-tools       # 列出所有工具
"""

import asyncio
import argparse
import logging
import sys
import os
import signal
from typing import Optional, Dict, Any, List
from pathlib import Path

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("kali_mcp")

# 版本信息
__version__ = "2.0.0"


def setup_environment():
    """设置运行环境"""
    # 确保数据目录存在
    data_dir = Path.home() / ".kali_mcp"
    data_dir.mkdir(exist_ok=True)

    (data_dir / "learning").mkdir(exist_ok=True)
    (data_dir / "reports").mkdir(exist_ok=True)
    (data_dir / "cache").mkdir(exist_ok=True)
    (data_dir / "logs").mkdir(exist_ok=True)

    # 设置环境变量
    os.environ.setdefault("KALI_MCP_DATA_DIR", str(data_dir))

    logger.info(f"数据目录: {data_dir}")


def load_all_tools():
    """加载所有工具模块"""
    from .tools import get_registry
    from .tools.base import ToolCategory

    # 导入各工具模块以触发注册
    try:
        from .tools import network
        logger.info(f"加载网络工具模块")
    except ImportError as e:
        logger.warning(f"网络工具模块加载失败: {e}")

    try:
        from .tools import web
        logger.info(f"加载Web工具模块")
    except ImportError as e:
        logger.warning(f"Web工具模块加载失败: {e}")

    try:
        from .tools import exploit
        logger.info(f"加载漏洞利用工具模块")
    except ImportError as e:
        logger.warning(f"漏洞利用工具模块加载失败: {e}")

    try:
        from .tools import password
        logger.info(f"加载密码攻击工具模块")
    except ImportError as e:
        logger.warning(f"密码攻击工具模块加载失败: {e}")

    try:
        from .tools import pwn
        logger.info(f"加载PWN工具模块")
    except ImportError as e:
        logger.warning(f"PWN工具模块加载失败: {e}")

    try:
        from .tools import osint
        logger.info(f"加载OSINT工具模块")
    except ImportError as e:
        logger.warning(f"OSINT工具模块加载失败: {e}")

    registry = get_registry()
    stats = registry.get_stats()
    logger.info(f"工具加载完成: 共 {stats['total_tools']} 个工具")

    return registry


def create_mcp_server():
    """创建MCP服务器"""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("FastMCP未安装，请运行: pip install mcp")
        sys.exit(1)

    # 创建MCP服务器实例
    mcp = FastMCP("kali-mcp")

    # 加载工具
    registry = load_all_tools()

    # 导入核心模块
    from .core import AsyncExecutor, SessionManager, StrategyEngine, ResultCache
    from .ai import IntentAnalyzer, ToolRecommender, LearningEngine
    from .output import OutputFormatter, ReportGenerator, get_progress_tracker
    from .monitor import get_health_checker, get_metrics_collector

    # 初始化组件
    executor = AsyncExecutor()
    session_manager = SessionManager()
    strategy_engine = StrategyEngine()
    cache = ResultCache()
    intent_analyzer = IntentAnalyzer()
    recommender = ToolRecommender()
    learning_engine = LearningEngine()
    formatter = OutputFormatter()
    reporter = ReportGenerator()
    health_checker = get_health_checker()
    metrics = get_metrics_collector()

    # ==================== 系统工具 ====================

    @mcp.tool()
    async def server_health() -> Dict[str, Any]:
        """
        检查Kali MCP服务器健康状态

        Returns:
            服务器健康信息
        """
        report = await health_checker.full_health_check()
        return report

    @mcp.tool()
    async def list_tools(category: str = "") -> Dict[str, Any]:
        """
        列出可用的安全工具

        Args:
            category: 工具分类 (network, web, exploit, password, pwn, osint)

        Returns:
            工具列表
        """
        from .tools.base import ToolCategory

        cat = None
        if category:
            try:
                cat = ToolCategory(category)
            except ValueError:
                pass

        tools = registry.list_tools(category=cat)
        return {
            "total": len(tools),
            "tools": tools
        }

    @mcp.tool()
    async def get_metrics() -> Dict[str, Any]:
        """
        获取性能指标统计

        Returns:
            性能指标
        """
        return metrics.get_summary()

    @mcp.tool()
    async def clear_cache() -> Dict[str, Any]:
        """
        清空结果缓存

        Returns:
            清空结果
        """
        cache.clear()
        return {"success": True, "message": "缓存已清空"}

    # ==================== AI工具 ====================

    @mcp.tool()
    async def analyze_intent(user_input: str) -> Dict[str, Any]:
        """
        分析用户意图

        Args:
            user_input: 用户输入

        Returns:
            意图分析结果
        """
        intent = intent_analyzer.analyze(user_input)
        return intent.to_dict()

    @mcp.tool()
    async def recommend_tools(
        target: str,
        target_type: str = "unknown",
        limit: int = 5
    ) -> Dict[str, Any]:
        """
        推荐适合目标的工具

        Args:
            target: 目标地址
            target_type: 目标类型 (web, network, binary, unknown)
            limit: 推荐数量

        Returns:
            推荐的工具列表
        """
        recommendations = recommender.recommend(
            target=target,
            target_type=target_type,
            limit=limit
        )
        return {
            "target": target,
            "target_type": target_type,
            "recommendations": [r.to_dict() for r in recommendations]
        }

    @mcp.tool()
    async def get_attack_strategy(
        target: str,
        objective: str = "reconnaissance"
    ) -> Dict[str, Any]:
        """
        获取攻击策略

        Args:
            target: 目标
            objective: 目标 (reconnaissance, vulnerability_scan, exploitation)

        Returns:
            攻击策略
        """
        strategy = strategy_engine.select_strategy(target, objective)
        return strategy

    # ==================== 会话管理 ====================

    @mcp.tool()
    async def create_session(
        target: str,
        mode: str = "pentest",
        name: str = ""
    ) -> Dict[str, Any]:
        """
        创建攻击会话

        Args:
            target: 目标
            mode: 模式 (pentest, ctf, analysis)
            name: 会话名称

        Returns:
            会话信息
        """
        session = session_manager.create_session(target, mode, name)
        return session.to_dict()

    @mcp.tool()
    async def get_session_status(session_id: str = "") -> Dict[str, Any]:
        """
        获取会话状态

        Args:
            session_id: 会话ID (空则获取当前会话)

        Returns:
            会话状态
        """
        session = session_manager.get_session(session_id)
        if session:
            return session.to_dict()
        return {"error": "会话未找到"}

    # ==================== 网络工具 ====================

    @mcp.tool()
    async def nmap_scan(
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        执行Nmap端口扫描

        Args:
            target: 目标IP或域名
            scan_type: 扫描类型 (-sV, -sS, -sT, -sU, -A)
            ports: 端口范围 (如 "1-1000" 或 "22,80,443")
            additional_args: 额外参数

        Returns:
            扫描结果
        """
        import time
        start_time = time.time()

        cmd = f"nmap {scan_type}"
        if ports:
            cmd += f" -p {ports}"
        if additional_args:
            cmd += f" {additional_args}"
        cmd += f" {target}"

        result = await executor.run_command(cmd, timeout=300)
        execution_time = time.time() - start_time

        # 记录指标
        metrics.record_execution("nmap_scan", result["success"], execution_time)

        return {
            "tool": "nmap_scan",
            "target": target,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time": execution_time
        }

    @mcp.tool()
    async def masscan_fast_scan(
        target: str,
        ports: str = "1-65535",
        rate: str = "10000"
    ) -> Dict[str, Any]:
        """
        执行Masscan快速端口扫描

        Args:
            target: 目标IP或网段
            ports: 端口范围
            rate: 扫描速率

        Returns:
            扫描结果
        """
        import time
        start_time = time.time()

        cmd = f"masscan {target} -p{ports} --rate={rate}"
        result = await executor.run_command(cmd, timeout=120)
        execution_time = time.time() - start_time

        metrics.record_execution("masscan_fast_scan", result["success"], execution_time)

        return {
            "tool": "masscan_fast_scan",
            "target": target,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time": execution_time
        }

    # ==================== Web工具 ====================

    @mcp.tool()
    async def gobuster_scan(
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        执行Gobuster目录扫描

        Args:
            url: 目标URL
            mode: 扫描模式 (dir, dns, vhost, fuzz)
            wordlist: 字典文件路径
            additional_args: 额外参数

        Returns:
            扫描结果
        """
        import time
        start_time = time.time()

        cmd = f"gobuster {mode} -u {url} -w {wordlist}"
        if additional_args:
            cmd += f" {additional_args}"

        result = await executor.run_command(cmd, timeout=300)
        execution_time = time.time() - start_time

        metrics.record_execution("gobuster_scan", result["success"], execution_time)

        return {
            "tool": "gobuster_scan",
            "target": url,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time": execution_time
        }

    @mcp.tool()
    async def sqlmap_scan(
        url: str,
        data: str = "",
        additional_args: str = "--batch"
    ) -> Dict[str, Any]:
        """
        执行SQLMap SQL注入扫描

        Args:
            url: 目标URL (带参数)
            data: POST数据
            additional_args: 额外参数

        Returns:
            扫描结果
        """
        import time
        start_time = time.time()

        cmd = f"sqlmap -u '{url}'"
        if data:
            cmd += f" --data='{data}'"
        if additional_args:
            cmd += f" {additional_args}"

        result = await executor.run_command(cmd, timeout=600)
        execution_time = time.time() - start_time

        metrics.record_execution("sqlmap_scan", result["success"], execution_time)

        return {
            "tool": "sqlmap_scan",
            "target": url,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time": execution_time
        }

    @mcp.tool()
    async def nuclei_scan(
        target: str,
        templates: str = "",
        severity: str = "critical,high,medium"
    ) -> Dict[str, Any]:
        """
        执行Nuclei漏洞扫描

        Args:
            target: 目标URL
            templates: 模板路径
            severity: 严重等级筛选

        Returns:
            扫描结果
        """
        import time
        start_time = time.time()

        cmd = f"nuclei -u {target} -severity {severity}"
        if templates:
            cmd += f" -t {templates}"

        result = await executor.run_command(cmd, timeout=600)
        execution_time = time.time() - start_time

        metrics.record_execution("nuclei_scan", result["success"], execution_time)

        return {
            "tool": "nuclei_scan",
            "target": target,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time": execution_time
        }

    @mcp.tool()
    async def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行Nikto Web服务器扫描

        Args:
            target: 目标URL或IP
            additional_args: 额外参数

        Returns:
            扫描结果
        """
        import time
        start_time = time.time()

        cmd = f"nikto -h {target}"
        if additional_args:
            cmd += f" {additional_args}"

        result = await executor.run_command(cmd, timeout=600)
        execution_time = time.time() - start_time

        metrics.record_execution("nikto_scan", result["success"], execution_time)

        return {
            "tool": "nikto_scan",
            "target": target,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time": execution_time
        }

    # ==================== 密码攻击工具 ====================

    @mcp.tool()
    async def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password_file: str = "/usr/share/wordlists/rockyou.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        执行Hydra密码爆破

        Args:
            target: 目标主机
            service: 服务类型 (ssh, ftp, http-post-form等)
            username: 单个用户名
            username_file: 用户名字典
            password_file: 密码字典
            additional_args: 额外参数

        Returns:
            攻击结果
        """
        import time
        start_time = time.time()

        cmd = f"hydra -t 4"
        if username:
            cmd += f" -l {username}"
        elif username_file:
            cmd += f" -L {username_file}"
        cmd += f" -P {password_file}"
        if additional_args:
            cmd += f" {additional_args}"
        cmd += f" {target} {service}"

        result = await executor.run_command(cmd, timeout=600)
        execution_time = time.time() - start_time

        metrics.record_execution("hydra_attack", result["success"], execution_time)

        return {
            "tool": "hydra_attack",
            "target": target,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time": execution_time
        }

    @mcp.tool()
    async def john_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = ""
    ) -> Dict[str, Any]:
        """
        执行John the Ripper密码破解

        Args:
            hash_file: 哈希文件路径
            wordlist: 字典文件
            format_type: 哈希格式

        Returns:
            破解结果
        """
        import time
        start_time = time.time()

        cmd = f"john --wordlist={wordlist}"
        if format_type:
            cmd += f" --format={format_type}"
        cmd += f" {hash_file}"

        result = await executor.run_command(cmd, timeout=600)

        # 获取破解结果
        show_result = await executor.run_command(f"john --show {hash_file}", timeout=30)

        execution_time = time.time() - start_time
        metrics.record_execution("john_crack", result["success"], execution_time)

        return {
            "tool": "john_crack",
            "success": result["success"],
            "output": result.get("stdout", ""),
            "cracked": show_result.get("stdout", ""),
            "execution_time": execution_time
        }

    # ==================== PWN工具 ====================

    @mcp.tool()
    async def quick_pwn_check(binary_path: str) -> Dict[str, Any]:
        """
        快速PWN漏洞检查

        Args:
            binary_path: 二进制文件路径

        Returns:
            分析结果
        """
        import time
        start_time = time.time()

        results = {}

        # checksec
        checksec_result = await executor.run_command(f"checksec --file={binary_path}", timeout=30)
        results["checksec"] = checksec_result.get("stdout", "")

        # file
        file_result = await executor.run_command(f"file {binary_path}", timeout=10)
        results["file_info"] = file_result.get("stdout", "")

        # strings (grep for interesting patterns)
        strings_result = await executor.run_command(
            f"strings {binary_path} | grep -iE '(flag|password|secret|key|shell)'",
            timeout=30
        )
        results["interesting_strings"] = strings_result.get("stdout", "")

        execution_time = time.time() - start_time
        metrics.record_execution("quick_pwn_check", True, execution_time)

        return {
            "tool": "quick_pwn_check",
            "binary": binary_path,
            "success": True,
            "results": results,
            "execution_time": execution_time
        }

    @mcp.tool()
    async def binwalk_analysis(
        file_path: str,
        extract: bool = False
    ) -> Dict[str, Any]:
        """
        执行Binwalk固件分析

        Args:
            file_path: 文件路径
            extract: 是否提取文件

        Returns:
            分析结果
        """
        import time
        start_time = time.time()

        cmd = "binwalk"
        if extract:
            cmd += " -e"
        cmd += f" {file_path}"

        result = await executor.run_command(cmd, timeout=300)
        execution_time = time.time() - start_time

        metrics.record_execution("binwalk_analysis", result["success"], execution_time)

        return {
            "tool": "binwalk_analysis",
            "file": file_path,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "execution_time": execution_time
        }

    # ==================== OSINT工具 ====================

    @mcp.tool()
    async def subfinder_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行Subfinder子域名发现

        Args:
            domain: 目标域名
            additional_args: 额外参数

        Returns:
            发现的子域名
        """
        import time
        start_time = time.time()

        cmd = f"subfinder -d {domain}"
        if additional_args:
            cmd += f" {additional_args}"

        result = await executor.run_command(cmd, timeout=300)
        execution_time = time.time() - start_time

        metrics.record_execution("subfinder_scan", result["success"], execution_time)

        return {
            "tool": "subfinder_scan",
            "domain": domain,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "execution_time": execution_time
        }

    @mcp.tool()
    async def theharvester_osint(
        domain: str,
        sources: str = "google,bing,yahoo"
    ) -> Dict[str, Any]:
        """
        执行theHarvester OSINT收集

        Args:
            domain: 目标域名
            sources: 数据源

        Returns:
            收集结果
        """
        import time
        start_time = time.time()

        cmd = f"theHarvester -d {domain} -b {sources}"
        result = await executor.run_command(cmd, timeout=300)
        execution_time = time.time() - start_time

        metrics.record_execution("theharvester_osint", result["success"], execution_time)

        return {
            "tool": "theharvester_osint",
            "domain": domain,
            "success": result["success"],
            "output": result.get("stdout", ""),
            "execution_time": execution_time
        }

    # ==================== 智能化工具 ====================

    @mcp.tool()
    async def intelligent_scan(
        target: str,
        objectives: List[str] = None,
        time_budget: str = "standard"
    ) -> Dict[str, Any]:
        """
        智能扫描 - 自动选择最佳工具组合

        Args:
            target: 目标
            objectives: 扫描目标 (port_scan, web_scan, vuln_scan)
            time_budget: 时间预算 (quick, standard, thorough)

        Returns:
            扫描结果
        """
        if objectives is None:
            objectives = ["port_scan", "web_scan"]

        results = {}

        # 分析目标类型
        target_type = "unknown"
        if target.startswith("http"):
            target_type = "web"
        elif "/" in target or target.replace(".", "").isdigit():
            target_type = "network"

        # 获取推荐工具
        recommendations = recommender.recommend(target, target_type, limit=5)

        # 执行推荐的工具
        for rec in recommendations[:3]:  # 最多执行3个
            tool_name = rec.tool_name
            tool = registry.get(tool_name)
            if tool:
                try:
                    result = await tool.run(target)
                    results[tool_name] = result.to_dict()
                except Exception as e:
                    results[tool_name] = {"error": str(e)}

        return {
            "target": target,
            "target_type": target_type,
            "tools_executed": list(results.keys()),
            "results": results
        }

    @mcp.tool()
    async def ctf_auto_solve(
        target: str,
        category: str = "auto"
    ) -> Dict[str, Any]:
        """
        CTF自动解题

        Args:
            target: CTF题目地址
            category: 题目类型 (web, pwn, crypto, misc, reverse, auto)

        Returns:
            解题结果
        """
        results = {
            "target": target,
            "category": category,
            "steps": [],
            "flags_found": []
        }

        # 自动检测类型
        if category == "auto":
            if target.startswith("http"):
                category = "web"
            elif os.path.isfile(target):
                category = "pwn"
            else:
                category = "misc"

        # 根据类型执行
        if category == "web":
            # Web题目流程
            steps = [
                ("whatweb", f"whatweb {target}"),
                ("gobuster", f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt"),
                ("nikto", f"nikto -h {target}"),
            ]

            for step_name, cmd in steps:
                result = await executor.run_command(cmd, timeout=120)
                step_result = {
                    "step": step_name,
                    "success": result["success"],
                    "output": result.get("stdout", "")[:2000]
                }
                results["steps"].append(step_result)

                # 检查Flag
                output = result.get("stdout", "") + result.get("stderr", "")
                import re
                flags = re.findall(r'(flag\{[^}]+\}|FLAG\{[^}]+\}|ctf\{[^}]+\})', output, re.IGNORECASE)
                results["flags_found"].extend(flags)

        elif category == "pwn":
            # PWN题目流程
            result = await executor.run_command(f"checksec --file={target}", timeout=30)
            results["steps"].append({
                "step": "checksec",
                "output": result.get("stdout", "")
            })

        return results

    @mcp.tool()
    async def generate_report(
        session_id: str = "",
        format: str = "markdown"
    ) -> Dict[str, Any]:
        """
        生成渗透测试报告

        Args:
            session_id: 会话ID
            format: 报告格式 (markdown, html, json)

        Returns:
            报告内容
        """
        session = session_manager.get_session(session_id)
        if not session:
            return {"error": "会话未找到"}

        from .output.reporter import ReportData

        report_data = ReportData(
            title=f"渗透测试报告 - {session.target}",
            target=session.target,
            scan_results=session.discovered_assets,
            start_time=session.start_time.isoformat() if session.start_time else "",
            end_time=session.end_time.isoformat() if session.end_time else ""
        )

        report = reporter.generate(report_data, format)

        return {
            "format": format,
            "report": report
        }

    @mcp.tool()
    async def execute_command(command: str, timeout: int = 60) -> Dict[str, Any]:
        """
        执行自定义命令

        Args:
            command: 要执行的命令
            timeout: 超时时间(秒)

        Returns:
            命令执行结果
        """
        result = await executor.run_command(command, timeout=timeout)
        return {
            "command": command,
            "success": result["success"],
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "return_code": result.get("return_code", -1)
        }

    logger.info(f"MCP服务器创建完成，注册了 {len(mcp._tool_manager._tools) if hasattr(mcp, '_tool_manager') else '多个'} 个工具")

    return mcp


async def run_health_check():
    """运行健康检查"""
    from .monitor import get_health_checker

    print("正在进行健康检查...")
    checker = get_health_checker()
    report = await checker.full_health_check()

    print(f"\n{'='*60}")
    print(f"Kali MCP 健康检查报告")
    print(f"{'='*60}")
    print(f"状态: {report['status']}")
    print(f"时间: {report['timestamp']}")

    print(f"\n系统资源:")
    system = report.get('system', {})
    print(f"  CPU使用率: {system.get('cpu_usage', 0):.1f}%")
    print(f"  内存使用率: {system.get('memory_usage', 0):.1f}%")
    print(f"  磁盘使用率: {system.get('disk_usage', 0):.1f}%")

    summary = report.get('summary', {})
    print(f"\n工具状态:")
    print(f"  核心工具: {summary.get('core_available', 0)}/{summary.get('core_total', 0)}")
    print(f"  可选工具: {summary.get('optional_available', 0)}/{summary.get('optional_total', 0)}")

    # 列出缺失的核心工具
    missing = checker.get_missing_tools()
    if missing:
        print(f"\n缺失的核心工具:")
        for tool in missing:
            print(f"  - {tool}")

    print(f"{'='*60}\n")


def list_all_tools():
    """列出所有工具"""
    registry = load_all_tools()

    print(f"\n{'='*60}")
    print(f"Kali MCP 工具列表")
    print(f"{'='*60}")

    stats = registry.get_stats()
    print(f"\n总计: {stats['total_tools']} 个工具\n")

    print("按分类统计:")
    for category, count in stats['by_category'].items():
        if count > 0:
            print(f"  {category}: {count}")

    print(f"\n{'='*60}\n")


def start_web_server(host: str = "0.0.0.0", port: int = 8080):
    """启动Web界面"""
    from .web import WebServer

    server = WebServer(host=host, port=port)
    print(f"启动Web界面: http://{host}:{port}")
    server.run()


def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        description="Kali MCP - 智能化渗透测试MCP服务器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m kali_mcp.main                    启动MCP服务器
  python -m kali_mcp.main --web              启动MCP服务器和Web界面
  python -m kali_mcp.main --health-check     运行健康检查
  python -m kali_mcp.main --list-tools       列出所有工具
        """
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"Kali MCP v{__version__}"
    )

    parser.add_argument(
        "--health-check",
        action="store_true",
        help="运行健康检查"
    )

    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="列出所有可用工具"
    )

    parser.add_argument(
        "--web",
        action="store_true",
        help="启动Web界面"
    )

    parser.add_argument(
        "--web-host",
        default="0.0.0.0",
        help="Web界面监听地址 (默认: 0.0.0.0)"
    )

    parser.add_argument(
        "--web-port",
        type=int,
        default=8080,
        help="Web界面端口 (默认: 8080)"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="启用调试模式"
    )

    args = parser.parse_args()

    # 设置日志级别
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # 设置环境
    setup_environment()

    # 处理命令
    if args.health_check:
        asyncio.run(run_health_check())
        return

    if args.list_tools:
        list_all_tools()
        return

    if args.web:
        # 启动Web界面（阻塞）
        start_web_server(args.web_host, args.web_port)
        return

    # 启动MCP服务器
    print(f"""
╔══════════════════════════════════════════════════════════╗
║           Kali MCP - 智能化渗透测试服务器                  ║
║                     Version {__version__}                       ║
╠══════════════════════════════════════════════════════════╣
║  功能:                                                    ║
║  - 193个安全工具统一接口                                  ║
║  - AI驱动的工具推荐                                       ║
║  - 自适应攻击策略                                         ║
║  - 实时进度追踪                                           ║
╠══════════════════════════════════════════════════════════╣
║  使用 --help 查看更多选项                                 ║
║  使用 --web 启动Web界面                                   ║
╚══════════════════════════════════════════════════════════╝
    """)

    mcp = create_mcp_server()

    # 运行MCP服务器
    try:
        mcp.run()
    except KeyboardInterrupt:
        print("\n服务器已停止")


if __name__ == "__main__":
    main()
