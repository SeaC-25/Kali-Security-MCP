#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PWN Suite - 统一的PWN分析和利用框架

整合所有PWN模块:
- pwnpasi: 基础PWN自动化
- heap_exploit: 堆漏洞利用
- advanced_rop: 高级ROP技术
- symbolic_analysis: 符号执行
- auto_fuzzing: 自动Fuzzing

用于CTF竞赛和授权的安全评估
"""

import os
import sys
import subprocess
import json
from typing import Optional, Dict, List, Any
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 颜色定义
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                     {Colors.BOLD}PWN Suite v2.0{Colors.END}{Colors.CYAN}                            ║
║          统一的二进制漏洞分析和利用框架                        ║
║          适用于CTF竞赛和授权安全评估                          ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.END} {msg}")

def print_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[-]{Colors.END} {msg}")


class VulnType(Enum):
    """漏洞类型"""
    STACK_OVERFLOW = "stack_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    INTEGER_OVERFLOW = "integer_overflow"
    OFF_BY_ONE = "off_by_one"
    UNKNOWN = "unknown"


class Architecture(Enum):
    """支持的架构"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "aarch64"
    MIPS = "mips"
    MIPS64 = "mips64"
    RISCV = "riscv"
    PPC = "ppc"


@dataclass
class BinaryInfo:
    """二进制信息"""
    path: str
    arch: Architecture = Architecture.X86_64
    bits: int = 64
    endian: str = "little"
    pie: bool = False
    canary: bool = False
    nx: bool = True
    relro: str = "Partial"
    stripped: bool = False
    statically_linked: bool = False
    libc_version: tuple = (2, 31)


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    vuln_type: VulnType
    confidence: float  # 0.0 - 1.0
    offset: Optional[int] = None
    address: Optional[int] = None
    description: str = ""
    exploit_method: Optional[str] = None


@dataclass
class ExploitResult:
    """利用结果"""
    success: bool
    method: str
    payload: Optional[bytes] = None
    shell_obtained: bool = False
    flag: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class PwnSuite:
    """PWN Suite主类"""

    def __init__(self, binary_path: str, remote: str = None):
        """
        初始化PWN Suite

        Args:
            binary_path: 目标二进制文件路径
            remote: 远程地址 (格式: ip:port)
        """
        self.binary_path = binary_path
        self.remote = remote
        self.binary_info: Optional[BinaryInfo] = None
        self.vulnerabilities: List[VulnerabilityInfo] = []
        self.exploit_results: List[ExploitResult] = []

        # 检查文件存在
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # 初始化分析
        self._analyze_binary()

    def _analyze_binary(self):
        """分析二进制文件"""
        print_info(f"分析二进制: {self.binary_path}")

        # 获取文件信息
        file_result = subprocess.run(
            ['file', self.binary_path],
            capture_output=True, text=True
        )
        file_output = file_result.stdout.lower()

        # 检测架构
        arch = Architecture.X86_64
        bits = 64
        endian = "little"

        if "x86-64" in file_output or "x86_64" in file_output:
            arch = Architecture.X86_64
            bits = 64
        elif "intel 80386" in file_output or "i386" in file_output:
            arch = Architecture.X86
            bits = 32
        elif "aarch64" in file_output:
            arch = Architecture.ARM64
            bits = 64
        elif "arm" in file_output:
            arch = Architecture.ARM
            bits = 32
        elif "mips64" in file_output:
            arch = Architecture.MIPS64
            bits = 64
        elif "mips" in file_output:
            arch = Architecture.MIPS
            bits = 32
        elif "riscv" in file_output:
            arch = Architecture.RISCV
            bits = 64 if "64" in file_output else 32

        if "msb" in file_output or "big endian" in file_output:
            endian = "big"

        # 获取保护信息
        checksec_result = subprocess.run(
            ['checksec', '--file', self.binary_path],
            capture_output=True, text=True
        )
        checksec_output = checksec_result.stdout + checksec_result.stderr

        pie = "PIE enabled" in checksec_output
        canary = "Canary found" in checksec_output
        nx = "NX enabled" in checksec_output
        relro = "Full RELRO" if "Full RELRO" in checksec_output else \
                "Partial RELRO" if "Partial RELRO" in checksec_output else "No RELRO"

        # 检测libc版本
        libc_version = (2, 31)  # 默认
        try:
            ldd_result = subprocess.run(
                ['ldd', self.binary_path],
                capture_output=True, text=True
            )
            import re
            match = re.search(r'libc.*?(\d+)\.(\d+)', ldd_result.stdout)
            if match:
                libc_version = (int(match.group(1)), int(match.group(2)))
        except:
            pass

        self.binary_info = BinaryInfo(
            path=self.binary_path,
            arch=arch,
            bits=bits,
            endian=endian,
            pie=pie,
            canary=canary,
            nx=nx,
            relro=relro,
            libc_version=libc_version
        )

        print_success(f"架构: {arch.value} ({bits}位, {endian}端)")
        print_info(f"保护: PIE={pie}, Canary={canary}, NX={nx}, RELRO={relro}")

    def detect_vulnerabilities(self) -> List[VulnerabilityInfo]:
        """检测漏洞"""
        print_info("开始漏洞检测...")

        # 1. 检测危险函数
        objdump_result = subprocess.run(
            ['objdump', '-t', self.binary_path],
            capture_output=True, text=True
        )

        dangerous_funcs = {
            'gets': VulnType.STACK_OVERFLOW,
            'strcpy': VulnType.STACK_OVERFLOW,
            'strcat': VulnType.STACK_OVERFLOW,
            'sprintf': VulnType.STACK_OVERFLOW,
            'scanf': VulnType.STACK_OVERFLOW,
            'printf': VulnType.FORMAT_STRING,
            'fprintf': VulnType.FORMAT_STRING,
        }

        for func, vuln_type in dangerous_funcs.items():
            if func in objdump_result.stdout:
                self.vulnerabilities.append(VulnerabilityInfo(
                    vuln_type=vuln_type,
                    confidence=0.7,
                    description=f"发现危险函数: {func}"
                ))
                print_warning(f"发现危险函数: {func} -> {vuln_type.value}")

        # 2. 检测堆函数
        heap_funcs = ['malloc', 'free', 'realloc', 'calloc']
        has_heap = any(f in objdump_result.stdout for f in heap_funcs)

        if has_heap:
            self.vulnerabilities.append(VulnerabilityInfo(
                vuln_type=VulnType.HEAP_OVERFLOW,
                confidence=0.5,
                description="使用堆函数，可能存在堆漏洞"
            ))
            print_warning("检测到堆操作，可能存在堆漏洞")

        # 3. 快速Fuzzing检测
        try:
            from auto_fuzzing import quick_fuzz_check
            fuzz_results = quick_fuzz_check(self.binary_path)

            if fuzz_results.get('overflow_detected'):
                self.vulnerabilities.append(VulnerabilityInfo(
                    vuln_type=VulnType.STACK_OVERFLOW,
                    confidence=0.9,
                    description="Fuzzing确认存在栈溢出"
                ))
                print_success("Fuzzing确认: 栈溢出")

            if fuzz_results.get('format_string_detected'):
                self.vulnerabilities.append(VulnerabilityInfo(
                    vuln_type=VulnType.FORMAT_STRING,
                    confidence=0.9,
                    description="Fuzzing确认存在格式化字符串漏洞"
                ))
                print_success("Fuzzing确认: 格式化字符串漏洞")

        except ImportError:
            print_warning("auto_fuzzing模块不可用")
        except Exception as e:
            print_warning(f"Fuzzing检测失败: {e}")

        print_success(f"检测完成，发现 {len(self.vulnerabilities)} 个潜在漏洞")
        return self.vulnerabilities

    def suggest_exploit_methods(self) -> List[str]:
        """建议利用方法"""
        methods = []

        if not self.binary_info:
            return methods

        bi = self.binary_info

        # 基于保护状态建议
        if not bi.canary:
            methods.append("栈溢出 (无Canary保护)")

        if not bi.nx:
            methods.append("Shellcode注入 (NX禁用)")

        if not bi.pie:
            methods.append("ROP Chain (无PIE)")
            methods.append("ret2plt")

        if bi.relro != "Full RELRO":
            methods.append("GOT覆盖")

        # 基于漏洞类型建议
        vuln_types = [v.vuln_type for v in self.vulnerabilities]

        if VulnType.STACK_OVERFLOW in vuln_types:
            if not bi.canary:
                methods.append("ret2libc")
                methods.append("ret2system")
            else:
                methods.append("Canary泄露 + ROP")

        if VulnType.FORMAT_STRING in vuln_types:
            methods.append("格式化字符串任意写")
            if bi.canary:
                methods.append("格式化字符串泄露Canary")

        if VulnType.HEAP_OVERFLOW in vuln_types or VulnType.USE_AFTER_FREE in vuln_types:
            major, minor = bi.libc_version
            if (major, minor) < (2, 26):
                methods.append("Fastbin Attack")
            elif (major, minor) < (2, 32):
                methods.append("Tcache Poisoning")
            else:
                methods.append("Tcache (Safe Linking绕过)")

        # 高级技术
        if bi.arch in [Architecture.X86_64, Architecture.X86]:
            methods.append("SROP (如果有sigreturn)")
            methods.append("ret2csu (通用gadget)")
            methods.append("ret2dlresolve (无libc泄露)")

        return list(set(methods))  # 去重

    def auto_exploit(self) -> Optional[ExploitResult]:
        """自动利用"""
        print_info("开始自动利用...")

        if not self.vulnerabilities:
            self.detect_vulnerabilities()

        if not self.vulnerabilities:
            print_error("未检测到漏洞")
            return None

        # 按置信度排序
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: v.confidence,
            reverse=True
        )

        # 尝试利用最高置信度的漏洞
        for vuln in sorted_vulns:
            result = self._try_exploit(vuln)
            if result and result.success:
                self.exploit_results.append(result)
                return result

        print_warning("自动利用未成功，请尝试手动利用")
        return None

    def _try_exploit(self, vuln: VulnerabilityInfo) -> Optional[ExploitResult]:
        """尝试利用特定漏洞"""
        print_info(f"尝试利用: {vuln.vuln_type.value}")

        if vuln.vuln_type == VulnType.STACK_OVERFLOW:
            return self._exploit_stack_overflow()
        elif vuln.vuln_type == VulnType.FORMAT_STRING:
            return self._exploit_format_string()
        elif vuln.vuln_type in [VulnType.HEAP_OVERFLOW, VulnType.USE_AFTER_FREE]:
            return self._exploit_heap()

        return None

    def _exploit_stack_overflow(self) -> Optional[ExploitResult]:
        """利用栈溢出"""
        try:
            # 使用pwnpasi
            from pwnpasi import main as pwnpasi_main
            # pwnpasi需要命令行参数，这里简化处理
            print_info("调用pwnpasi自动利用...")

            result = subprocess.run(
                ['python3', '-c', f'''
import sys
sys.path.insert(0, "{os.path.dirname(os.path.abspath(__file__))}")
from pwnpasi import Information_Collection, find_rop_gadgets_x64, ret2libc_write_x64
try:
    info = Information_Collection("{self.binary_path}")
    print("分析完成")
except Exception as e:
    print(f"错误: {{e}}")
'''],
                capture_output=True, text=True, timeout=60
            )

            if "shell" in result.stdout.lower() or "成功" in result.stdout:
                return ExploitResult(
                    success=True,
                    method="ret2libc",
                    shell_obtained=True,
                    details={'output': result.stdout}
                )

        except Exception as e:
            print_error(f"栈溢出利用失败: {e}")

        return None

    def _exploit_format_string(self) -> Optional[ExploitResult]:
        """利用格式化字符串"""
        print_info("尝试格式化字符串利用...")
        # 简化实现
        return None

    def _exploit_heap(self) -> Optional[ExploitResult]:
        """利用堆漏洞"""
        print_info("尝试堆漏洞利用...")

        try:
            from heap_exploit import detect_heap_vulnerability
            heap_info = detect_heap_vulnerability(self.binary_path)
            print_info(f"建议技术: {heap_info.get('suggested_technique')}")
        except:
            pass

        return None

    def run_symbolic_analysis(self) -> Dict:
        """运行符号执行分析"""
        print_info("启动符号执行分析...")

        try:
            from symbolic_analysis import quick_symbolic_analysis, CTFSolver

            # 快速分析
            analysis = quick_symbolic_analysis(self.binary_path)

            if analysis.get('available'):
                print_success(f"架构: {analysis.get('arch')}")
                print_success(f"函数数量: {analysis.get('functions_count')}")

                if analysis.get('dangerous_functions'):
                    print_warning(f"危险函数: {analysis.get('dangerous_functions')}")

                # 尝试自动求解
                solver = CTFSolver(self.binary_path)
                result = solver.auto_solve()

                if result.get('solved'):
                    print_success("符号执行成功找到解!")
                    return result

            return analysis

        except ImportError:
            print_warning("symbolic_analysis模块需要angr: pip install angr")
            return {'available': False, 'error': 'angr not installed'}
        except Exception as e:
            return {'available': False, 'error': str(e)}

    def generate_report(self) -> str:
        """生成分析报告"""
        report = []
        report.append("=" * 60)
        report.append(f"PWN Suite 分析报告")
        report.append("=" * 60)

        # 二进制信息
        if self.binary_info:
            bi = self.binary_info
            report.append(f"\n目标: {bi.path}")
            report.append(f"架构: {bi.arch.value} ({bi.bits}位)")
            report.append(f"字节序: {bi.endian}")
            report.append(f"\n保护机制:")
            report.append(f"  PIE: {'启用' if bi.pie else '禁用'}")
            report.append(f"  Canary: {'启用' if bi.canary else '禁用'}")
            report.append(f"  NX: {'启用' if bi.nx else '禁用'}")
            report.append(f"  RELRO: {bi.relro}")
            report.append(f"  Libc: {bi.libc_version[0]}.{bi.libc_version[1]}")

        # 漏洞信息
        if self.vulnerabilities:
            report.append(f"\n检测到的漏洞: {len(self.vulnerabilities)}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"  {i}. {vuln.vuln_type.value} (置信度: {vuln.confidence:.0%})")
                report.append(f"     {vuln.description}")

        # 建议方法
        methods = self.suggest_exploit_methods()
        if methods:
            report.append(f"\n建议利用方法:")
            for method in methods:
                report.append(f"  - {method}")

        # 利用结果
        if self.exploit_results:
            report.append(f"\n利用结果:")
            for result in self.exploit_results:
                status = "成功" if result.success else "失败"
                report.append(f"  {result.method}: {status}")
                if result.shell_obtained:
                    report.append(f"    获得Shell!")
                if result.flag:
                    report.append(f"    Flag: {result.flag}")

        report.append("\n" + "=" * 60)
        return '\n'.join(report)


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='PWN Suite - 统一的PWN分析和利用框架')
    parser.add_argument('binary', help='目标二进制文件')
    parser.add_argument('-r', '--remote', help='远程地址 (ip:port)')
    parser.add_argument('-a', '--auto', action='store_true', help='自动利用')
    parser.add_argument('-s', '--symbolic', action='store_true', help='运行符号执行')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')

    args = parser.parse_args()

    print_banner()

    try:
        suite = PwnSuite(args.binary, args.remote)

        # 检测漏洞
        suite.detect_vulnerabilities()

        # 显示建议
        methods = suite.suggest_exploit_methods()
        if methods:
            print_info("建议利用方法:")
            for m in methods:
                print(f"  - {m}")

        # 符号执行
        if args.symbolic:
            suite.run_symbolic_analysis()

        # 自动利用
        if args.auto:
            suite.auto_exploit()

        # 生成报告
        print("\n" + suite.generate_report())

    except Exception as e:
        print_error(f"错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
