#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动Fuzzing模块 - CTF和漏洞研究

支持的Fuzzing技术:
- 基于变异的Fuzzing
- 基于生成的Fuzzing
- 智能输入生成
- 崩溃分析和分类

用于CTF竞赛和授权的安全评估
"""

import os
import sys
import subprocess
import time
import signal
import struct
import random
import string
from typing import Optional, List, Dict, Tuple, Any
from pathlib import Path

# 颜色定义
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.END} {msg}")

def print_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[-]{Colors.END} {msg}")


class MutationEngine:
    """变异引擎 - 生成各种变异输入"""

    def __init__(self):
        self.interesting_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
        self.interesting_16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
        self.interesting_32 = [0, 1, 32768, 65535, 65536, 100663045, 2147483647, 4294967295]

    def bit_flip(self, data: bytes, probability: float = 0.01) -> bytes:
        """位翻转变异"""
        result = bytearray(data)
        for i in range(len(result)):
            for bit in range(8):
                if random.random() < probability:
                    result[i] ^= (1 << bit)
        return bytes(result)

    def byte_flip(self, data: bytes, count: int = 1) -> bytes:
        """字节翻转变异"""
        result = bytearray(data)
        for _ in range(count):
            if len(result) > 0:
                pos = random.randint(0, len(result) - 1)
                result[pos] ^= 0xFF
        return bytes(result)

    def insert_interesting(self, data: bytes) -> bytes:
        """插入有趣的值"""
        result = bytearray(data)
        if len(result) < 4:
            return data

        pos = random.randint(0, len(result) - 4)

        # 随机选择插入类型
        choice = random.randint(0, 2)
        if choice == 0:
            # 8位
            value = random.choice(self.interesting_8)
            result[pos] = value
        elif choice == 1:
            # 16位
            value = random.choice(self.interesting_16)
            result[pos:pos+2] = struct.pack('<H', value)
        else:
            # 32位
            value = random.choice(self.interesting_32)
            result[pos:pos+4] = struct.pack('<I', value)

        return bytes(result)

    def arithmetic_mutation(self, data: bytes) -> bytes:
        """算术变异 - 对数值进行加减"""
        result = bytearray(data)
        if len(result) < 4:
            return data

        pos = random.randint(0, len(result) - 4)
        delta = random.randint(-35, 35)

        # 32位算术
        value = struct.unpack('<I', result[pos:pos+4])[0]
        value = (value + delta) & 0xFFFFFFFF
        result[pos:pos+4] = struct.pack('<I', value)

        return bytes(result)

    def havoc(self, data: bytes, rounds: int = 5) -> bytes:
        """混沌模式 - 多种变异组合"""
        result = data
        mutations = [
            self.bit_flip,
            self.byte_flip,
            self.insert_interesting,
            self.arithmetic_mutation,
            lambda d: self.extend(d, random.randint(1, 32)),
            lambda d: self.truncate(d, random.randint(1, min(len(d), 32))),
        ]

        for _ in range(rounds):
            mutation = random.choice(mutations)
            try:
                result = mutation(result)
            except:
                pass

        return result

    def extend(self, data: bytes, length: int) -> bytes:
        """扩展数据"""
        extension = bytes([random.randint(0, 255) for _ in range(length)])
        pos = random.randint(0, len(data))
        return data[:pos] + extension + data[pos:]

    def truncate(self, data: bytes, length: int) -> bytes:
        """截断数据"""
        if length >= len(data):
            return data
        pos = random.randint(0, len(data) - length)
        return data[:pos] + data[pos + length:]


class InputGenerator:
    """智能输入生成器"""

    def __init__(self):
        self.format_strings = [
            b"%s" * 100,
            b"%x" * 100,
            b"%n" * 50,
            b"%p" * 100,
            b"AAAA" + b"%08x." * 50,
            b"%s%s%s%s%s%s%s%s%s%s",
            b"%n%n%n%n%n%n%n%n%n%n",
        ]

        self.overflow_patterns = [
            b"A" * 100,
            b"A" * 500,
            b"A" * 1000,
            b"A" * 5000,
            b"A" * 10000,
        ]

        self.special_chars = [
            b"\x00",  # Null byte
            b"\x0a",  # Newline
            b"\x0d",  # Carriage return
            b"\xff",  # 0xFF
            b"\x7f",  # DEL
        ]

    def generate_overflow_input(self, length: int = 1000, pattern: str = "cyclic") -> bytes:
        """生成溢出测试输入"""
        if pattern == "cyclic":
            return self._generate_cyclic_pattern(length)
        elif pattern == "repeated":
            return b"A" * length
        else:
            return bytes([random.randint(0, 255) for _ in range(length)])

    def _generate_cyclic_pattern(self, length: int) -> bytes:
        """生成循环模式用于定位偏移"""
        pattern = []
        for upper in string.ascii_uppercase:
            for lower in string.ascii_lowercase:
                for digit in string.digits:
                    pattern.append(f"{upper}{lower}{digit}".encode())
                    if len(b''.join(pattern)) >= length:
                        return b''.join(pattern)[:length]
        return b''.join(pattern)[:length]

    def generate_format_string_input(self) -> bytes:
        """生成格式化字符串测试输入"""
        return random.choice(self.format_strings)

    def generate_integer_overflow_input(self) -> bytes:
        """生成整数溢出测试输入"""
        values = [
            struct.pack('<i', -1),
            struct.pack('<i', 0x7FFFFFFF),
            struct.pack('<I', 0xFFFFFFFF),
            struct.pack('<q', -1),
            struct.pack('<Q', 0xFFFFFFFFFFFFFFFF),
        ]
        return random.choice(values)

    def generate_smart_input(self, seed: bytes = None) -> bytes:
        """智能输入生成"""
        if seed:
            mutator = MutationEngine()
            return mutator.havoc(seed)
        else:
            # 生成随机类型的输入
            generators = [
                lambda: self.generate_overflow_input(random.randint(100, 2000)),
                self.generate_format_string_input,
                self.generate_integer_overflow_input,
            ]
            return random.choice(generators)()


class CrashAnalyzer:
    """崩溃分析器"""

    def __init__(self):
        self.crashes = []

    def analyze_crash(self, binary_path: str, input_data: bytes,
                     returncode: int, stderr: str) -> Dict:
        """分析崩溃"""
        crash_info = {
            'binary': binary_path,
            'input': input_data[:100],  # 只保存前100字节
            'input_hex': input_data[:100].hex(),
            'returncode': returncode,
            'signal': self._returncode_to_signal(returncode),
            'stderr': stderr[:500],
            'crash_type': 'unknown',
            'severity': 'unknown',
        }

        # 分析崩溃类型
        if returncode == -11:  # SIGSEGV
            crash_info['crash_type'] = 'Segmentation Fault'
            crash_info['severity'] = 'high'
            if b'%' in input_data:
                crash_info['likely_cause'] = 'Format String'
            elif len(input_data) > 100:
                crash_info['likely_cause'] = 'Buffer Overflow'
        elif returncode == -6:  # SIGABRT
            crash_info['crash_type'] = 'Abort'
            crash_info['severity'] = 'medium'
            crash_info['likely_cause'] = 'Assertion/Heap Corruption'
        elif returncode == -4:  # SIGILL
            crash_info['crash_type'] = 'Illegal Instruction'
            crash_info['severity'] = 'high'
            crash_info['likely_cause'] = 'Code Execution'
        elif returncode == -8:  # SIGFPE
            crash_info['crash_type'] = 'Floating Point Exception'
            crash_info['severity'] = 'low'
            crash_info['likely_cause'] = 'Division by Zero'

        self.crashes.append(crash_info)
        return crash_info

    def _returncode_to_signal(self, returncode: int) -> str:
        """将返回码转换为信号名"""
        signals = {
            -1: 'SIGHUP',
            -2: 'SIGINT',
            -3: 'SIGQUIT',
            -4: 'SIGILL',
            -6: 'SIGABRT',
            -8: 'SIGFPE',
            -9: 'SIGKILL',
            -11: 'SIGSEGV',
            -13: 'SIGPIPE',
            -14: 'SIGALRM',
            -15: 'SIGTERM',
        }
        return signals.get(returncode, f'Signal {-returncode}' if returncode < 0 else 'Normal')

    def get_unique_crashes(self) -> List[Dict]:
        """获取去重后的崩溃"""
        seen = set()
        unique = []
        for crash in self.crashes:
            key = (crash['crash_type'], crash.get('likely_cause', ''))
            if key not in seen:
                seen.add(key)
                unique.append(crash)
        return unique

    def generate_report(self) -> str:
        """生成崩溃报告"""
        report = []
        report.append("=" * 60)
        report.append("Fuzzing 崩溃报告")
        report.append("=" * 60)
        report.append(f"\n总崩溃数: {len(self.crashes)}")

        unique = self.get_unique_crashes()
        report.append(f"唯一崩溃类型: {len(unique)}\n")

        for i, crash in enumerate(unique, 1):
            report.append(f"\n--- 崩溃 #{i} ---")
            report.append(f"类型: {crash['crash_type']}")
            report.append(f"信号: {crash['signal']}")
            report.append(f"严重程度: {crash['severity']}")
            if 'likely_cause' in crash:
                report.append(f"可能原因: {crash['likely_cause']}")
            report.append(f"输入(hex): {crash['input_hex'][:50]}...")

        return '\n'.join(report)


class SimpleFuzzer:
    """简单Fuzzer - 用于CTF和快速测试"""

    def __init__(self, binary_path: str, timeout: int = 1):
        self.binary = binary_path
        self.timeout = timeout
        self.mutator = MutationEngine()
        self.generator = InputGenerator()
        self.analyzer = CrashAnalyzer()
        self.iterations = 0
        self.crashes_found = 0

    def run_target(self, input_data: bytes) -> Tuple[int, str, str]:
        """运行目标程序"""
        try:
            proc = subprocess.Popen(
                [self.binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(input=input_data, timeout=self.timeout)
            return proc.returncode, stdout.decode(errors='ignore'), stderr.decode(errors='ignore')
        except subprocess.TimeoutExpired:
            proc.kill()
            return 0, '', 'Timeout'
        except Exception as e:
            return 0, '', str(e)

    def fuzz(self, iterations: int = 1000, seed: bytes = None,
            callback=None) -> List[Dict]:
        """执行Fuzzing"""
        print_info(f"开始Fuzzing: {self.binary}")
        print_info(f"迭代次数: {iterations}")

        crashes = []

        for i in range(iterations):
            self.iterations = i + 1

            # 生成输入
            if seed and random.random() < 0.7:
                # 70%概率使用变异
                input_data = self.mutator.havoc(seed)
            else:
                # 30%概率生成新输入
                input_data = self.generator.generate_smart_input(seed)

            # 运行目标
            returncode, stdout, stderr = self.run_target(input_data)

            # 检查崩溃
            if returncode < 0:
                self.crashes_found += 1
                crash_info = self.analyzer.analyze_crash(
                    self.binary, input_data, returncode, stderr
                )
                crashes.append(crash_info)

                print_success(f"发现崩溃 #{self.crashes_found}: {crash_info['crash_type']}")

                if callback:
                    callback(crash_info)

            # 进度报告
            if (i + 1) % 100 == 0:
                print_info(f"进度: {i+1}/{iterations}, 崩溃: {self.crashes_found}")

        print_success(f"Fuzzing完成! 总崩溃: {self.crashes_found}")
        return crashes

    def quick_overflow_test(self) -> Optional[Dict]:
        """快速溢出测试"""
        print_info("执行快速溢出测试...")

        test_sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192]

        for size in test_sizes:
            input_data = b"A" * size
            returncode, _, stderr = self.run_target(input_data)

            if returncode == -11:  # SIGSEGV
                crash_info = self.analyzer.analyze_crash(
                    self.binary, input_data, returncode, stderr
                )
                print_success(f"在 {size} 字节处发现溢出!")
                return crash_info

        print_warning("未发现简单溢出")
        return None

    def find_overflow_offset(self, max_length: int = 2000) -> Optional[int]:
        """查找溢出偏移"""
        print_info("查找精确溢出偏移...")

        # 使用循环模式
        pattern = self.generator.generate_overflow_input(max_length, "cyclic")

        returncode, stdout, stderr = self.run_target(pattern)

        if returncode != -11:
            print_warning("未触发崩溃")
            return None

        # 这里需要结合GDB获取EIP/RIP值来计算偏移
        # 简化版本：使用二分搜索
        low, high = 0, max_length

        while high - low > 4:
            mid = (low + high) // 2
            test_input = b"A" * mid
            returncode, _, _ = self.run_target(test_input)

            if returncode == -11:
                high = mid
            else:
                low = mid

        print_success(f"溢出偏移约在: {low} - {high} 字节")
        return low


class AFLWrapper:
    """AFL Fuzzer包装器"""

    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.afl_path = self._find_afl()

    def _find_afl(self) -> Optional[str]:
        """查找AFL安装路径"""
        paths = [
            '/usr/bin/afl-fuzz',
            '/usr/local/bin/afl-fuzz',
            os.path.expanduser('~/AFLplusplus/afl-fuzz'),
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def is_available(self) -> bool:
        """检查AFL是否可用"""
        return self.afl_path is not None

    def run(self, input_dir: str, output_dir: str, timeout: int = 3600) -> Dict:
        """运行AFL"""
        if not self.is_available():
            return {'success': False, 'error': 'AFL not found'}

        print_info(f"启动AFL fuzzing...")
        print_info(f"输入目录: {input_dir}")
        print_info(f"输出目录: {output_dir}")

        cmd = [
            self.afl_path,
            '-i', input_dir,
            '-o', output_dir,
            '-t', '1000',  # 超时1秒
            '--', self.binary
        ]

        try:
            # AFL需要交互式运行，这里只是示例
            print_warning("AFL需要交互式终端运行")
            print_info(f"请手动运行: {' '.join(cmd)}")

            return {
                'success': True,
                'command': ' '.join(cmd),
                'output_dir': output_dir
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}


def quick_fuzz_check(binary_path: str) -> Dict:
    """
    快速Fuzzing检查

    执行快速的溢出和格式化字符串测试
    """
    results = {
        'binary': binary_path,
        'crashes': [],
        'overflow_detected': False,
        'format_string_detected': False,
    }

    try:
        fuzzer = SimpleFuzzer(binary_path, timeout=2)

        # 1. 快速溢出测试
        overflow_result = fuzzer.quick_overflow_test()
        if overflow_result:
            results['overflow_detected'] = True
            results['crashes'].append(overflow_result)

        # 2. 格式化字符串测试
        format_inputs = [
            b"%x" * 50,
            b"%s%s%s%s%s",
            b"%n%n%n%n",
        ]

        for fmt_input in format_inputs:
            returncode, _, stderr = fuzzer.run_target(fmt_input)
            if returncode < 0:
                crash_info = fuzzer.analyzer.analyze_crash(
                    binary_path, fmt_input, returncode, stderr
                )
                results['format_string_detected'] = True
                results['crashes'].append(crash_info)
                break

        # 3. 简单Fuzzing (100次)
        fuzzer.fuzz(iterations=100)
        results['crashes'].extend(fuzzer.analyzer.get_unique_crashes())

        return results

    except Exception as e:
        results['error'] = str(e)
        return results


if __name__ == "__main__":
    if len(sys.argv) > 1:
        binary = sys.argv[1]
        iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 1000

        print(f"\n{Colors.BOLD}自动Fuzzing分析{Colors.END}")
        print("=" * 50)

        results = quick_fuzz_check(binary)

        print(f"\n{Colors.BOLD}结果摘要:{Colors.END}")
        print(f"  溢出检测: {'是' if results['overflow_detected'] else '否'}")
        print(f"  格式化字符串: {'是' if results['format_string_detected'] else '否'}")
        print(f"  总崩溃数: {len(results['crashes'])}")

        if results['crashes']:
            print(f"\n{Colors.BOLD}崩溃详情:{Colors.END}")
            for i, crash in enumerate(results['crashes'][:5], 1):
                print(f"  {i}. {crash['crash_type']} - {crash.get('likely_cause', 'Unknown')}")
