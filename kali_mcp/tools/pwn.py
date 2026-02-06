#!/usr/bin/env python3
"""
PWN和逆向工具模块

包含二进制漏洞利用和逆向分析工具:
- quick_pwn_check: 快速PWN检查
- pwnpasi_auto_pwn: 自动化PWN利用
- radare2_analyze: Radare2分析
- binwalk_analysis: 固件分析
- auto_reverse_analyze: 自动逆向分析
"""

import asyncio
import re
import json
import logging
from typing import Dict, List, Optional, Any

from .base import (
    BaseTool,
    ToolResult,
    ToolCategory,
    RiskLevel,
    Finding,
    tool,
    get_registry
)
from ..core.executor import get_executor, ExecutionResult

logger = logging.getLogger(__name__)


@tool(
    name="quick_pwn_check",
    category=ToolCategory.PWN,
    description="快速PWN检查 - 二进制保护分析和漏洞可能性评估",
    risk_level=RiskLevel.INFO,
    timeout=60
)
class QuickPwnCheck(BaseTool):
    """快速PWN检查工具"""

    async def execute(
        self,
        binary_path: str,
        **kwargs
    ) -> ToolResult:
        """
        执行快速PWN检查

        Args:
            binary_path: 二进制文件路径
        """
        result = ToolResult(
            success=True,
            tool_name="quick_pwn_check",
            target=binary_path
        )

        executor = get_executor()

        # 1. checksec检查保护
        checksec_result = await executor.run_command(f"checksec --file={binary_path}")
        if checksec_result.success:
            result.raw_output += f"=== checksec ===\n{checksec_result.stdout}\n\n"

            # 解析保护状态
            protections = {
                "RELRO": "No RELRO" not in checksec_result.stdout,
                "Stack Canary": "No canary" not in checksec_result.stdout,
                "NX": "NX disabled" not in checksec_result.stdout,
                "PIE": "No PIE" not in checksec_result.stdout,
            }

            for prot, enabled in protections.items():
                result.add_finding(
                    finding_type="protection",
                    value=prot,
                    severity="info" if enabled else "low",
                    enabled=enabled
                )

        # 2. 检查危险函数
        strings_result = await executor.run_command(f"objdump -t {binary_path} 2>/dev/null | grep -E 'gets|strcpy|sprintf|scanf|strcat'")
        dangerous_funcs = []
        if strings_result.success and strings_result.stdout.strip():
            for line in strings_result.stdout.split('\n'):
                for func in ['gets', 'strcpy', 'sprintf', 'scanf', 'strcat']:
                    if func in line:
                        dangerous_funcs.append(func)
                        result.add_finding(
                            finding_type="dangerous_function",
                            value=func,
                            severity="high"
                        )

        # 3. 文件类型
        file_result = await executor.run_command(f"file {binary_path}")
        if file_result.success:
            result.add_finding(
                finding_type="file_type",
                value=file_result.stdout.strip(),
                severity="info"
            )

        # 4. 评估攻击难度
        attack_difficulty = "medium"
        attack_methods = []

        if not protections.get("Stack Canary"):
            attack_methods.append("Stack Buffer Overflow")
            attack_difficulty = "easy"

        if not protections.get("NX"):
            attack_methods.append("Shellcode Injection")
            attack_difficulty = "easy"

        if not protections.get("PIE"):
            attack_methods.append("ROP Chain")

        if dangerous_funcs:
            attack_methods.append(f"Exploit via: {', '.join(set(dangerous_funcs))}")

        # 生成摘要
        disabled_prots = [p for p, e in protections.items() if not e]
        if disabled_prots:
            result.summary = f"发现可利用点! 禁用保护: {', '.join(disabled_prots)}"
            if attack_methods:
                result.suggest_next_step(f"建议攻击方法: {', '.join(attack_methods)}")
                result.suggest_next_step("使用 pwnpasi_auto_pwn 自动利用", "pwnpasi_auto_pwn")
        else:
            result.summary = "所有保护已启用，利用难度较高"
            result.suggest_next_step("需要更高级的利用技术如堆溢出、格式化字符串等")

        result.flags_found.extend(result.extract_flags(result.raw_output))

        return result


@tool(
    name="pwnpasi_auto_pwn",
    category=ToolCategory.PWN,
    description="PwnPasi自动化利用 - 自动化二进制漏洞利用框架",
    risk_level=RiskLevel.HIGH,
    timeout=300
)
class PwnpasiAutoPwn(BaseTool):
    """PwnPasi自动化PWN工具"""

    async def execute(
        self,
        binary_path: str,
        remote_ip: str = "",
        remote_port: int = 0,
        libc_path: str = "",
        padding: int = 0,
        verbose: bool = False,
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行PwnPasi自动化利用

        Args:
            binary_path: 二进制文件路径
            remote_ip: 远程IP
            remote_port: 远程端口
            libc_path: libc路径
            padding: 填充大小
            verbose: 详细输出
            additional_args: 额外参数
        """
        cmd_parts = ["python3", "-c", f'''
import sys
sys.path.insert(0, "/home/zss/MCP-Kali-Server-main/pwnpasi")
try:
    from pwnpasi import PwnPasi
    pwn = PwnPasi("{binary_path}")
    pwn.analyze()
    pwn.exploit()
except Exception as e:
    print(f"Error: {{e}}")
''']

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="pwnpasi_auto_pwn",
            target=binary_path,
            raw_output=exec_result.stdout + exec_result.stderr
        )

        # 检测是否获取shell
        if "shell" in exec_result.stdout.lower() or "$" in exec_result.stdout:
            result.add_finding(
                finding_type="exploit",
                value="Shell Obtained",
                severity="critical"
            )
            result.summary = "成功获取Shell!"
        else:
            result.summary = "自动利用尝试完成"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="radare2_analyze_binary",
    category=ToolCategory.PWN,
    description="Radare2二进制分析 - 深度逆向分析工具",
    risk_level=RiskLevel.INFO,
    timeout=120
)
class Radare2AnalyzeBinary(BaseTool):
    """Radare2分析工具"""

    async def execute(
        self,
        binary_path: str,
        **kwargs
    ) -> ToolResult:
        """执行Radare2分析"""
        executor = get_executor()

        # 执行分析命令
        commands = [
            f"r2 -q -c 'aaa; afl' {binary_path}",  # 分析并列出函数
            f"r2 -q -c 'iz' {binary_path}",         # 列出字符串
            f"r2 -q -c 'ii' {binary_path}",         # 列出导入
        ]

        result = ToolResult(
            success=True,
            tool_name="radare2_analyze_binary",
            target=binary_path
        )

        # 分析函数
        func_result = await executor.run_command(commands[0], timeout=60)
        if func_result.success:
            result.raw_output += f"=== Functions ===\n{func_result.stdout}\n\n"

            # 解析函数
            for line in func_result.stdout.split('\n'):
                if 'main' in line.lower() or 'vuln' in line.lower():
                    result.add_finding(
                        finding_type="function",
                        value=line.strip(),
                        severity="info"
                    )

        # 分析字符串
        str_result = await executor.run_command(commands[1], timeout=60)
        if str_result.success:
            result.raw_output += f"=== Strings ===\n{str_result.stdout}\n\n"

            # 检测Flag
            result.flags_found.extend(result.extract_flags(str_result.stdout))

            # 检测有趣的字符串
            interesting = ['password', 'flag', 'secret', 'admin', 'root']
            for line in str_result.stdout.split('\n'):
                for word in interesting:
                    if word in line.lower():
                        result.add_finding(
                            finding_type="string",
                            value=line.strip(),
                            severity="low"
                        )
                        break

        # 分析导入
        import_result = await executor.run_command(commands[2], timeout=60)
        if import_result.success:
            result.raw_output += f"=== Imports ===\n{import_result.stdout}\n\n"

        funcs = [f for f in result.findings if f.finding_type == "function"]
        strings = [f for f in result.findings if f.finding_type == "string"]

        result.summary = f"分析完成: {len(funcs)}个关键函数, {len(strings)}个有趣字符串"

        if result.flags_found:
            result.summary += f", 发现 {len(result.flags_found)} 个可能的Flag!"

        return result


@tool(
    name="binwalk_analysis",
    category=ToolCategory.PWN,
    description="Binwalk固件分析 - 提取和分析固件文件系统",
    risk_level=RiskLevel.INFO,
    timeout=300
)
class BinwalkAnalysis(BaseTool):
    """Binwalk分析工具"""

    async def execute(
        self,
        file_path: str,
        extract: bool = False,
        additional_args: str = "",
        **kwargs
    ) -> ToolResult:
        """
        执行Binwalk分析

        Args:
            file_path: 文件路径
            extract: 是否提取
            additional_args: 额外参数
        """
        cmd_parts = ["binwalk"]

        if extract:
            cmd_parts.append("-e")

        if additional_args:
            cmd_parts.append(additional_args)

        cmd_parts.append(file_path)

        cmd = " ".join(cmd_parts)

        executor = get_executor()
        exec_result = await executor.run_command(cmd, timeout=self.default_timeout)

        result = ToolResult(
            success=exec_result.success,
            tool_name="binwalk_analysis",
            target=file_path,
            raw_output=exec_result.stdout
        )

        # 解析发现的内容
        for line in exec_result.stdout.split('\n'):
            if line.strip() and not line.startswith('DECIMAL'):
                parts = line.split()
                if len(parts) >= 3:
                    result.add_finding(
                        finding_type="embedded",
                        value=" ".join(parts[2:]),
                        severity="info",
                        offset=parts[0] if parts else ""
                    )

        findings = result.findings
        result.summary = f"发现 {len(findings)} 个嵌入内容" if findings else "未发现嵌入内容"

        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        return result


@tool(
    name="auto_reverse_analyze",
    category=ToolCategory.PWN,
    description="自动逆向分析 - 智能选择工具进行综合分析",
    risk_level=RiskLevel.INFO,
    timeout=180
)
class AutoReverseAnalyze(BaseTool):
    """自动逆向分析工具"""

    async def execute(
        self,
        binary_path: str,
        **kwargs
    ) -> ToolResult:
        """执行自动逆向分析"""
        result = ToolResult(
            success=True,
            tool_name="auto_reverse_analyze",
            target=binary_path
        )

        executor = get_executor()

        # 1. 文件类型检测
        file_result = await executor.run_command(f"file {binary_path}")
        if file_result.success:
            result.add_finding(
                finding_type="file_type",
                value=file_result.stdout.strip(),
                severity="info"
            )
            result.raw_output += f"=== File Type ===\n{file_result.stdout}\n\n"

        # 2. 字符串提取
        strings_result = await executor.run_command(f"strings {binary_path} | head -100")
        if strings_result.success:
            result.raw_output += f"=== Strings (first 100) ===\n{strings_result.stdout}\n\n"

            # 检测Flag
            result.flags_found.extend(result.extract_flags(strings_result.stdout))

            # 检测密码相关
            for line in strings_result.stdout.split('\n'):
                if any(w in line.lower() for w in ['password', 'secret', 'key', 'flag']):
                    result.add_finding(
                        finding_type="interesting_string",
                        value=line.strip(),
                        severity="low"
                    )

        # 3. 安全检查
        checksec_result = await executor.run_command(f"checksec --file={binary_path} 2>/dev/null")
        if checksec_result.success:
            result.raw_output += f"=== Security Checks ===\n{checksec_result.stdout}\n\n"

        # 4. 使用objdump分析
        objdump_result = await executor.run_command(f"objdump -d {binary_path} | head -200")
        if objdump_result.success:
            result.raw_output += f"=== Disassembly (first 200 lines) ===\n{objdump_result.stdout}\n\n"

        result.summary = f"逆向分析完成"
        if result.flags_found:
            result.summary += f", 发现 {len(result.flags_found)} 个可能的Flag!"

        result.suggest_next_step("使用 radare2_analyze_binary 进行深度分析", "radare2_analyze_binary")
        result.suggest_next_step("使用 quick_pwn_check 检查可利用性", "quick_pwn_check")

        return result


@tool(
    name="heap_exploit_analyze",
    category=ToolCategory.PWN,
    description="堆漏洞分析 - 检测堆相关漏洞并建议利用技术",
    risk_level=RiskLevel.MEDIUM,
    timeout=120
)
class HeapExploitAnalyze(BaseTool):
    """堆漏洞分析工具"""

    async def execute(
        self,
        binary_path: str,
        **kwargs
    ) -> ToolResult:
        """
        执行堆漏洞分析

        Args:
            binary_path: 二进制文件路径
        """
        result = ToolResult(
            success=True,
            tool_name="heap_exploit_analyze",
            target=binary_path
        )

        executor = get_executor()

        # 1. 检测libc版本
        ldd_result = await executor.run_command(f"ldd {binary_path} 2>/dev/null | grep libc")
        libc_version = (2, 31)  # 默认
        if ldd_result.success and ldd_result.stdout.strip():
            result.raw_output += f"=== Libc Info ===\n{ldd_result.stdout}\n\n"
            # 尝试获取版本
            version_match = re.search(r'libc-(\d+)\.(\d+)', ldd_result.stdout)
            if version_match:
                libc_version = (int(version_match.group(1)), int(version_match.group(2)))

        result.add_finding(
            finding_type="libc_version",
            value=f"{libc_version[0]}.{libc_version[1]}",
            severity="info"
        )

        # 2. 检测堆相关函数
        heap_funcs_result = await executor.run_command(
            f"objdump -t {binary_path} 2>/dev/null | grep -E 'malloc|free|realloc|calloc'"
        )
        heap_funcs = []
        if heap_funcs_result.success and heap_funcs_result.stdout.strip():
            result.raw_output += f"=== Heap Functions ===\n{heap_funcs_result.stdout}\n\n"
            for func in ['malloc', 'free', 'realloc', 'calloc']:
                if func in heap_funcs_result.stdout:
                    heap_funcs.append(func)
                    result.add_finding(
                        finding_type="heap_function",
                        value=func,
                        severity="info"
                    )

        # 3. 建议利用技术
        suggested_techniques = []

        if libc_version < (2, 26):
            suggested_techniques.append("Fastbin Attack")
            suggested_techniques.append("House of Force")
        elif libc_version < (2, 29):
            suggested_techniques.append("Tcache Poisoning (简单)")
            suggested_techniques.append("Unsorted Bin Attack")
        elif libc_version < (2, 32):
            suggested_techniques.append("Tcache Poisoning (需绕过key)")
            suggested_techniques.append("Large Bin Attack")
        else:
            suggested_techniques.append("Tcache Poisoning (需绕过Safe Linking)")
            suggested_techniques.append("House of IO (高级)")

        if 'malloc' in heap_funcs and 'free' in heap_funcs:
            suggested_techniques.append("UAF (Use-After-Free)")
            suggested_techniques.append("Double Free")

        for tech in suggested_techniques:
            result.add_finding(
                finding_type="suggested_technique",
                value=tech,
                severity="medium"
            )

        result.summary = f"Libc {libc_version[0]}.{libc_version[1]}, 建议: {', '.join(suggested_techniques[:3])}"
        result.suggest_next_step("使用 pwnpasi_auto_pwn 进行自动利用", "pwnpasi_auto_pwn")

        return result


@tool(
    name="advanced_rop_analyze",
    category=ToolCategory.PWN,
    description="高级ROP分析 - SROP/ret2csu/ret2dlresolve gadget搜索",
    risk_level=RiskLevel.MEDIUM,
    timeout=180
)
class AdvancedRopAnalyze(BaseTool):
    """高级ROP分析工具"""

    async def execute(
        self,
        binary_path: str,
        technique: str = "all",
        **kwargs
    ) -> ToolResult:
        """
        执行高级ROP分析

        Args:
            binary_path: 二进制文件路径
            technique: 技术类型 (srop, ret2csu, ret2dlresolve, all)
        """
        result = ToolResult(
            success=True,
            tool_name="advanced_rop_analyze",
            target=binary_path
        )

        executor = get_executor()

        # 1. 检查架构
        file_result = await executor.run_command(f"file {binary_path}")
        arch = "x64"
        if file_result.success:
            if "32-bit" in file_result.stdout:
                arch = "x32"
            elif "ARM" in file_result.stdout:
                arch = "arm"
            elif "MIPS" in file_result.stdout:
                arch = "mips"
            result.add_finding(
                finding_type="architecture",
                value=arch,
                severity="info"
            )

        # 2. 搜索SROP所需的sigreturn gadget
        if technique in ["all", "srop"]:
            srop_result = await executor.run_command(
                f"ropper --file {binary_path} --search 'syscall' 2>/dev/null | head -20"
            )
            if srop_result.success and srop_result.stdout.strip():
                result.raw_output += f"=== SROP Gadgets ===\n{srop_result.stdout}\n\n"
                if "syscall" in srop_result.stdout:
                    result.add_finding(
                        finding_type="srop_gadget",
                        value="syscall found - SROP可行",
                        severity="medium"
                    )

        # 3. 搜索ret2csu gadgets (__libc_csu_init)
        if technique in ["all", "ret2csu"]:
            csu_result = await executor.run_command(
                f"objdump -d {binary_path} 2>/dev/null | grep -A 30 '__libc_csu_init'"
            )
            if csu_result.success and csu_result.stdout.strip():
                result.raw_output += f"=== ret2csu Gadgets ===\n{csu_result.stdout[:2000]}\n\n"
                # 检查是否有pop rbx等gadgets
                if "pop" in csu_result.stdout and "ret" in csu_result.stdout:
                    result.add_finding(
                        finding_type="ret2csu_gadget",
                        value="__libc_csu_init found - ret2csu可行",
                        severity="medium"
                    )

        # 4. ret2dlresolve检查
        if technique in ["all", "ret2dlresolve"]:
            plt_result = await executor.run_command(
                f"objdump -d {binary_path} 2>/dev/null | grep -E '@plt|.plt'"
            )
            if plt_result.success and plt_result.stdout.strip():
                result.raw_output += f"=== PLT Entries ===\n{plt_result.stdout[:1000]}\n\n"
                result.add_finding(
                    finding_type="ret2dlresolve",
                    value="PLT entries found - ret2dlresolve可行",
                    severity="medium"
                )

        # 5. 通用gadgets
        gadgets_result = await executor.run_command(
            f"ropper --file {binary_path} --search 'pop rdi; ret' 2>/dev/null | head -10"
        )
        if gadgets_result.success and gadgets_result.stdout.strip():
            result.raw_output += f"=== Common Gadgets ===\n{gadgets_result.stdout}\n\n"

        techniques_found = [f.value for f in result.findings if "可行" in str(f.value)]
        result.summary = f"架构: {arch}, 可用技术: {len(techniques_found)}"

        if techniques_found:
            result.suggest_next_step(f"可尝试: {', '.join([t.split(' -')[0] for t in techniques_found])}")

        return result


@tool(
    name="symbolic_ctf_solve",
    category=ToolCategory.PWN,
    description="符号执行CTF求解 - 使用angr自动求解crackme/flag路径",
    risk_level=RiskLevel.INFO,
    timeout=300
)
class SymbolicCtfSolve(BaseTool):
    """符号执行CTF求解工具"""

    async def execute(
        self,
        binary_path: str,
        target_addr: str = "",
        flag_prefix: str = "flag{",
        **kwargs
    ) -> ToolResult:
        """
        执行符号执行求解

        Args:
            binary_path: 二进制文件路径
            target_addr: 目标地址(16进制)
            flag_prefix: Flag前缀
        """
        result = ToolResult(
            success=True,
            tool_name="symbolic_ctf_solve",
            target=binary_path
        )

        # 构建angr求解脚本
        solve_script = f'''
import sys
sys.path.insert(0, "/home/zss/MCP-Kali-Server-main/pwnpasi")

try:
    from symbolic_analysis import quick_symbolic_analysis, CTFSolver, ANGR_AVAILABLE

    if not ANGR_AVAILABLE:
        print("ERROR: angr未安装")
        print("安装命令: pip install angr")
        sys.exit(1)

    # 快速分析
    analysis = quick_symbolic_analysis("{binary_path}")
    print("=== 符号执行分析 ===")
    for key, value in analysis.items():
        print(f"  {{key}}: {{value}}")

    # 尝试自动求解
    solver = CTFSolver("{binary_path}")
    solve_result = solver.auto_solve()

    print("\\n=== 求解结果 ===")
    print(f"  已解决: {{solve_result['solved']}}")
    if solve_result['solution_input']:
        print(f"  解: {{solve_result['solution_input']}}")
    if solve_result['vulnerabilities']:
        print(f"  漏洞: {{solve_result['vulnerabilities']}}")

except ImportError as e:
    print(f"导入错误: {{e}}")
    print("请确保angr已安装: pip install angr")
except Exception as e:
    print(f"分析错误: {{e}}")
'''

        executor = get_executor()
        exec_result = await executor.run_command(
            f"python3 -c '{solve_script}'",
            timeout=self.default_timeout
        )

        result.raw_output = exec_result.stdout + exec_result.stderr

        # 解析结果
        if "已解决: True" in exec_result.stdout:
            result.add_finding(
                finding_type="solution",
                value="符号执行成功找到解",
                severity="high"
            )
            result.summary = "符号执行求解成功!"

            # 提取解
            if "解:" in exec_result.stdout:
                for line in exec_result.stdout.split('\n'):
                    if "解:" in line:
                        result.add_finding(
                            finding_type="input",
                            value=line.split("解:")[1].strip(),
                            severity="high"
                        )
        else:
            result.summary = "符号执行分析完成，未找到自动解"
            result.suggest_next_step("尝试手动设置目标地址或使用其他技术")

        # 提取flags
        result.flags_found.extend(result.extract_flags(exec_result.stdout))

        if "angr未安装" in result.raw_output:
            result.success = False
            result.summary = "需要安装angr: pip install angr"

        return result


@tool(
    name="multi_arch_analyze",
    category=ToolCategory.PWN,
    description="多架构分析 - 支持ARM/MIPS/x86/x64架构的二进制分析",
    risk_level=RiskLevel.INFO,
    timeout=120
)
class MultiArchAnalyze(BaseTool):
    """多架构分析工具"""

    async def execute(
        self,
        binary_path: str,
        **kwargs
    ) -> ToolResult:
        """
        执行多架构分析

        Args:
            binary_path: 二进制文件路径
        """
        result = ToolResult(
            success=True,
            tool_name="multi_arch_analyze",
            target=binary_path
        )

        executor = get_executor()

        # 1. 检测架构
        file_result = await executor.run_command(f"file {binary_path}")
        arch_info = {
            "arch": "unknown",
            "bits": 0,
            "endian": "little"
        }

        if file_result.success:
            output = file_result.stdout.lower()
            result.raw_output += f"=== File Info ===\n{file_result.stdout}\n\n"

            # 识别架构
            if "x86-64" in output or "x86_64" in output:
                arch_info = {"arch": "x86_64", "bits": 64, "endian": "little"}
            elif "intel 80386" in output or "i386" in output:
                arch_info = {"arch": "x86", "bits": 32, "endian": "little"}
            elif "arm aarch64" in output or "aarch64" in output:
                arch_info = {"arch": "aarch64", "bits": 64, "endian": "little"}
            elif "arm" in output:
                arch_info = {"arch": "arm", "bits": 32, "endian": "little" if "lsb" in output else "big"}
            elif "mips64" in output:
                arch_info = {"arch": "mips64", "bits": 64, "endian": "big" if "msb" in output else "little"}
            elif "mips" in output:
                arch_info = {"arch": "mips", "bits": 32, "endian": "big" if "msb" in output else "little"}
            elif "powerpc" in output or "ppc" in output:
                arch_info = {"arch": "ppc", "bits": 64 if "64" in output else 32, "endian": "big"}
            elif "sparc" in output:
                arch_info = {"arch": "sparc", "bits": 64 if "64" in output else 32, "endian": "big"}
            elif "riscv" in output:
                arch_info = {"arch": "riscv", "bits": 64 if "64" in output else 32, "endian": "little"}

            for key, value in arch_info.items():
                result.add_finding(
                    finding_type=f"arch_{key}",
                    value=str(value),
                    severity="info"
                )

        # 2. 根据架构选择分析工具
        arch = arch_info["arch"]

        if arch in ["x86_64", "x86"]:
            # x86/x64使用标准工具
            ropper_result = await executor.run_command(
                f"ropper --file {binary_path} --search 'pop' 2>/dev/null | head -20"
            )
            if ropper_result.success:
                result.raw_output += f"=== ROP Gadgets ===\n{ropper_result.stdout}\n\n"

        elif arch in ["arm", "aarch64"]:
            # ARM使用特定gadget搜索
            ropper_result = await executor.run_command(
                f"ropper --file {binary_path} --arch ARM{'64' if arch == 'aarch64' else ''} 2>/dev/null | head -30"
            )
            if ropper_result.success:
                result.raw_output += f"=== ARM Gadgets ===\n{ropper_result.stdout}\n\n"

            # ARM特定: 检查系统调用
            svc_result = await executor.run_command(
                f"objdump -d {binary_path} 2>/dev/null | grep -E 'svc|swi' | head -10"
            )
            if svc_result.success and svc_result.stdout.strip():
                result.add_finding(
                    finding_type="arm_syscall",
                    value="SVC/SWI指令发现",
                    severity="medium"
                )
                result.raw_output += f"=== ARM Syscalls ===\n{svc_result.stdout}\n\n"

        elif arch in ["mips", "mips64"]:
            # MIPS分析
            objdump_result = await executor.run_command(
                f"objdump -d {binary_path} 2>/dev/null | grep -E 'jr\\s+\\$ra|syscall' | head -20"
            )
            if objdump_result.success:
                result.raw_output += f"=== MIPS Analysis ===\n{objdump_result.stdout}\n\n"

            # MIPS gadgets
            mips_gadgets = await executor.run_command(
                f"ropper --file {binary_path} --arch MIPS{'64' if '64' in arch else ''} 2>/dev/null | head -30"
            )
            if mips_gadgets.success:
                result.raw_output += f"=== MIPS Gadgets ===\n{mips_gadgets.stdout}\n\n"

        # 3. 通用分析
        checksec_result = await executor.run_command(f"checksec --file={binary_path} 2>/dev/null")
        if checksec_result.success:
            result.raw_output += f"=== Security Checks ===\n{checksec_result.stdout}\n\n"

        # 4. 架构特定建议
        arch_suggestions = {
            "x86_64": ["ret2libc", "ROP Chain", "SROP", "ret2csu"],
            "x86": ["ret2libc", "ROP Chain", "ret2plt"],
            "arm": ["ret2libc (ARM)", "ROP Chain", "Return to PLT"],
            "aarch64": ["ret2libc (AArch64)", "ROP Chain", "PACIBSP bypass"],
            "mips": ["ROP Chain (MIPS)", "Return to PLT", "Cache flush考虑"],
            "mips64": ["ROP Chain (MIPS64)", "ret2libc"]
        }

        suggestions = arch_suggestions.get(arch, ["通用ROP技术"])
        for sug in suggestions:
            result.add_finding(
                finding_type="suggestion",
                value=sug,
                severity="info"
            )

        result.summary = f"架构: {arch} ({arch_info['bits']}位, {arch_info['endian']}端), 建议: {', '.join(suggestions[:2])}"

        return result


@tool(
    name="pwn_comprehensive",
    category=ToolCategory.PWN,
    description="PWN综合分析 - 整合所有PWN分析能力的一站式工具",
    risk_level=RiskLevel.MEDIUM,
    timeout=300
)
class PwnComprehensive(BaseTool):
    """PWN综合分析工具"""

    async def execute(
        self,
        binary_path: str,
        auto_exploit: bool = False,
        **kwargs
    ) -> ToolResult:
        """
        执行PWN综合分析

        Args:
            binary_path: 二进制文件路径
            auto_exploit: 是否自动尝试利用
        """
        result = ToolResult(
            success=True,
            tool_name="pwn_comprehensive",
            target=binary_path
        )

        executor = get_executor()
        analysis_results = {}

        # 1. 基础信息
        result.raw_output += "=" * 50 + "\n"
        result.raw_output += "阶段1: 基础信息收集\n"
        result.raw_output += "=" * 50 + "\n\n"

        file_result = await executor.run_command(f"file {binary_path}")
        if file_result.success:
            analysis_results['file_type'] = file_result.stdout.strip()
            result.raw_output += f"文件类型: {file_result.stdout}\n"

        checksec_result = await executor.run_command(f"checksec --file={binary_path} 2>/dev/null")
        if checksec_result.success:
            analysis_results['protections'] = checksec_result.stdout
            result.raw_output += f"保护机制:\n{checksec_result.stdout}\n"

            # 解析保护
            protections = {
                "RELRO": "No RELRO" not in checksec_result.stdout,
                "Canary": "No canary" not in checksec_result.stdout,
                "NX": "NX disabled" not in checksec_result.stdout,
                "PIE": "No PIE" not in checksec_result.stdout,
            }
            analysis_results['protection_status'] = protections

        # 2. 漏洞检测
        result.raw_output += "\n" + "=" * 50 + "\n"
        result.raw_output += "阶段2: 漏洞检测\n"
        result.raw_output += "=" * 50 + "\n\n"

        # 危险函数
        dangerous_result = await executor.run_command(
            f"objdump -t {binary_path} 2>/dev/null | grep -E 'gets|strcpy|sprintf|scanf|strcat|read'"
        )
        dangerous_funcs = []
        if dangerous_result.success and dangerous_result.stdout.strip():
            for func in ['gets', 'strcpy', 'sprintf', 'scanf', 'strcat', 'read']:
                if func in dangerous_result.stdout:
                    dangerous_funcs.append(func)
            result.raw_output += f"危险函数: {', '.join(dangerous_funcs)}\n"
            for func in dangerous_funcs:
                result.add_finding(
                    finding_type="dangerous_function",
                    value=func,
                    severity="high"
                )

        # 堆函数
        heap_result = await executor.run_command(
            f"objdump -t {binary_path} 2>/dev/null | grep -E 'malloc|free|realloc'"
        )
        heap_funcs = []
        if heap_result.success and heap_result.stdout.strip():
            for func in ['malloc', 'free', 'realloc']:
                if func in heap_result.stdout:
                    heap_funcs.append(func)
            if heap_funcs:
                result.raw_output += f"堆函数: {', '.join(heap_funcs)}\n"
                result.add_finding(
                    finding_type="heap_usage",
                    value=', '.join(heap_funcs),
                    severity="medium"
                )

        # 3. ROP Gadgets
        result.raw_output += "\n" + "=" * 50 + "\n"
        result.raw_output += "阶段3: ROP Gadget搜索\n"
        result.raw_output += "=" * 50 + "\n\n"

        gadgets_result = await executor.run_command(
            f"ropper --file {binary_path} --search 'pop' 2>/dev/null | head -15"
        )
        if gadgets_result.success:
            result.raw_output += f"常用Gadgets:\n{gadgets_result.stdout}\n"

        # 4. 字符串分析
        result.raw_output += "\n" + "=" * 50 + "\n"
        result.raw_output += "阶段4: 字符串分析\n"
        result.raw_output += "=" * 50 + "\n\n"

        strings_result = await executor.run_command(
            f"strings {binary_path} | grep -iE 'flag|password|secret|shell|bin/sh|system' | head -20"
        )
        if strings_result.success and strings_result.stdout.strip():
            result.raw_output += f"关键字符串:\n{strings_result.stdout}\n"
            result.flags_found.extend(result.extract_flags(strings_result.stdout))

        # 5. 生成攻击建议
        result.raw_output += "\n" + "=" * 50 + "\n"
        result.raw_output += "阶段5: 攻击建议\n"
        result.raw_output += "=" * 50 + "\n\n"

        attack_suggestions = []

        if 'protection_status' in analysis_results:
            prots = analysis_results['protection_status']

            if not prots.get('Canary') and dangerous_funcs:
                attack_suggestions.append("栈溢出 (无Canary + 危险函数)")

            if not prots.get('NX'):
                attack_suggestions.append("Shellcode注入 (NX禁用)")

            if not prots.get('PIE'):
                attack_suggestions.append("ROP Chain (无PIE)")

            if prots.get('Canary') and 'scanf' in dangerous_funcs:
                attack_suggestions.append("格式化字符串泄露Canary")

        if heap_funcs:
            attack_suggestions.append("堆漏洞利用 (检测到堆操作)")

        if '/bin/sh' in (strings_result.stdout if strings_result.success else ''):
            attack_suggestions.append("ret2system (发现/bin/sh)")

        for sug in attack_suggestions:
            result.add_finding(
                finding_type="attack_suggestion",
                value=sug,
                severity="medium"
            )
            result.raw_output += f"  - {sug}\n"

        # 总结
        disabled_prots = [p for p, e in analysis_results.get('protection_status', {}).items() if not e]
        result.summary = f"禁用保护: {', '.join(disabled_prots) if disabled_prots else '无'}, 建议: {len(attack_suggestions)}种攻击方式"

        if auto_exploit:
            result.suggest_next_step("使用 pwnpasi_auto_pwn 自动利用", "pwnpasi_auto_pwn")
        else:
            result.suggest_next_step("分析完成，可使用 pwnpasi_auto_pwn 进行自动利用")

        return result


@tool(
    name="auto_fuzz_check",
    category=ToolCategory.PWN,
    description="自动Fuzzing检查 - 快速检测溢出和格式化字符串漏洞",
    risk_level=RiskLevel.MEDIUM,
    timeout=120
)
class AutoFuzzCheck(BaseTool):
    """自动Fuzzing检查工具"""

    async def execute(
        self,
        binary_path: str,
        iterations: int = 100,
        **kwargs
    ) -> ToolResult:
        """
        执行自动Fuzzing检查

        Args:
            binary_path: 二进制文件路径
            iterations: Fuzzing迭代次数
        """
        result = ToolResult(
            success=True,
            tool_name="auto_fuzz_check",
            target=binary_path
        )

        # 构建Fuzzing脚本
        fuzz_script = f'''
import sys
sys.path.insert(0, "/home/zss/MCP-Kali-Server-main/pwnpasi")

try:
    from auto_fuzzing import quick_fuzz_check, SimpleFuzzer

    print("=== 快速Fuzzing检查 ===")
    results = quick_fuzz_check("{binary_path}")

    print(f"\\n溢出检测: {{'是' if results.get('overflow_detected') else '否'}}")
    print(f"格式化字符串: {{'是' if results.get('format_string_detected') else '否'}}")
    print(f"总崩溃数: {{len(results.get('crashes', []))}}")

    if results.get('crashes'):
        print("\\n崩溃详情:")
        for i, crash in enumerate(results['crashes'][:5], 1):
            print(f"  {{i}}. {{crash.get('crash_type', 'Unknown')}}")
            if 'likely_cause' in crash:
                print(f"     可能原因: {{crash['likely_cause']}}")

except ImportError as e:
    print(f"导入错误: {{e}}")
except Exception as e:
    print(f"Fuzzing错误: {{e}}")
'''

        executor = get_executor()
        exec_result = await executor.run_command(
            f"python3 -c '{fuzz_script}'",
            timeout=self.default_timeout
        )

        result.raw_output = exec_result.stdout + exec_result.stderr

        # 解析结果
        if "溢出检测: 是" in exec_result.stdout:
            result.add_finding(
                finding_type="overflow",
                value="检测到栈溢出漏洞",
                severity="high"
            )

        if "格式化字符串: 是" in exec_result.stdout:
            result.add_finding(
                finding_type="format_string",
                value="检测到格式化字符串漏洞",
                severity="high"
            )

        # 提取崩溃数量
        import re
        crash_match = re.search(r'总崩溃数: (\d+)', exec_result.stdout)
        if crash_match:
            crash_count = int(crash_match.group(1))
            if crash_count > 0:
                result.add_finding(
                    finding_type="crashes",
                    value=f"发现 {crash_count} 个崩溃",
                    severity="medium"
                )

        vulnerabilities = [f for f in result.findings if f.severity == "high"]
        if vulnerabilities:
            result.summary = f"Fuzzing发现 {len(vulnerabilities)} 个高危漏洞!"
            result.suggest_next_step("使用 pwnpasi_auto_pwn 进行自动利用", "pwnpasi_auto_pwn")
        else:
            result.summary = "Fuzzing完成，未发现明显漏洞"

        return result


@tool(
    name="pwn_suite_analyze",
    category=ToolCategory.PWN,
    description="PWN Suite综合分析 - 一站式二进制漏洞分析和利用建议",
    risk_level=RiskLevel.MEDIUM,
    timeout=300
)
class PwnSuiteAnalyze(BaseTool):
    """PWN Suite综合分析工具"""

    async def execute(
        self,
        binary_path: str,
        auto_exploit: bool = False,
        run_symbolic: bool = False,
        **kwargs
    ) -> ToolResult:
        """
        执行PWN Suite综合分析

        Args:
            binary_path: 二进制文件路径
            auto_exploit: 是否自动尝试利用
            run_symbolic: 是否运行符号执行
        """
        result = ToolResult(
            success=True,
            tool_name="pwn_suite_analyze",
            target=binary_path
        )

        # 构建分析脚本
        suite_script = f'''
import sys
sys.path.insert(0, "/home/zss/MCP-Kali-Server-main/pwnpasi")

try:
    from pwn_suite import PwnSuite

    suite = PwnSuite("{binary_path}")

    # 检测漏洞
    vulns = suite.detect_vulnerabilities()

    # 获取建议方法
    methods = suite.suggest_exploit_methods()

    print("\\n=== 建议利用方法 ===")
    for m in methods:
        print(f"  - {{m}}")

    {"# 符号执行" if run_symbolic else ""}
    {"suite.run_symbolic_analysis()" if run_symbolic else ""}

    {"# 自动利用" if auto_exploit else ""}
    {"suite.auto_exploit()" if auto_exploit else ""}

    # 生成报告
    print(suite.generate_report())

except ImportError as e:
    print(f"导入错误: {{e}}")
except Exception as e:
    print(f"分析错误: {{e}}")
    import traceback
    traceback.print_exc()
'''

        executor = get_executor()
        exec_result = await executor.run_command(
            f"python3 -c '{suite_script}'",
            timeout=self.default_timeout
        )

        result.raw_output = exec_result.stdout + exec_result.stderr

        # 解析关键信息
        if "检测到的漏洞:" in exec_result.stdout:
            result.add_finding(
                finding_type="analysis",
                value="PWN Suite分析完成",
                severity="info"
            )

        # 提取建议方法
        if "建议利用方法" in exec_result.stdout:
            methods_section = exec_result.stdout.split("建议利用方法")[1].split("===")[0]
            for line in methods_section.split('\n'):
                if line.strip().startswith('-'):
                    result.add_finding(
                        finding_type="exploit_method",
                        value=line.strip()[2:],
                        severity="medium"
                    )

        result.summary = "PWN Suite综合分析完成"

        if auto_exploit and "成功" in exec_result.stdout:
            result.summary += " - 自动利用成功!"

        result.suggest_next_step("查看详细报告获取具体利用步骤")

        return result


__all__ = [
    "QuickPwnCheck",
    "PwnpasiAutoPwn",
    "Radare2AnalyzeBinary",
    "BinwalkAnalysis",
    "AutoReverseAnalyze",
    "HeapExploitAnalyze",
    "AdvancedRopAnalyze",
    "SymbolicCtfSolve",
    "MultiArchAnalyze",
    "PwnComprehensive",
    "AutoFuzzCheck",
    "PwnSuiteAnalyze",
]
