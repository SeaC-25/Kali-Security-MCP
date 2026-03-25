#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
符号执行分析模块 - CTF自动化解题

使用angr进行:
- 自动路径探索
- 约束求解
- 漏洞点定位
- 输入生成

用于CTF竞赛和授权的安全评估
"""

import os
import sys
import subprocess
from typing import Optional, List, Dict, Tuple, Any

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


# 检查angr是否可用
ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    print_warning("angr未安装,符号执行功能不可用")
    print_info("安装命令: pip install angr")


class SymbolicExplorer:
    """符号执行探索器"""

    def __init__(self, binary_path: str):
        if not ANGR_AVAILABLE:
            raise ImportError("需要安装angr: pip install angr")

        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)
        print_success(f"加载二进制文件: {binary_path}")
        print_info(f"架构: {self.project.arch.name}")

    def find_path_to_address(self, target_addr: int,
                             avoid_addrs: List[int] = None,
                             max_time: int = 300) -> Optional[bytes]:
        """
        查找到达目标地址的路径

        常用于CTF: 找到打印flag的路径
        """
        print_info(f"搜索到达 {hex(target_addr)} 的路径...")

        # 创建初始状态
        state = self.project.factory.entry_state(
            stdin=angr.SimFile
        )

        # 创建模拟管理器
        simgr = self.project.factory.simulation_manager(state)

        # 设置避免地址
        avoid = avoid_addrs if avoid_addrs else []

        # 探索
        try:
            simgr.explore(
                find=target_addr,
                avoid=avoid,
                timeout=max_time
            )

            if simgr.found:
                found_state = simgr.found[0]

                # 获取到达该状态的输入
                stdin_data = found_state.posix.dumps(0)
                print_success(f"找到路径!")
                print_info(f"所需输入: {stdin_data}")
                return stdin_data
            else:
                print_warning("未找到路径")
                return None

        except Exception as e:
            print_error(f"探索失败: {e}")
            return None

    def find_flag_path(self, flag_prefix: str = "flag{",
                       max_time: int = 300) -> Optional[bytes]:
        """
        自动查找打印flag的路径

        通过查找输出包含flag前缀的状态
        """
        print_info(f"搜索包含 '{flag_prefix}' 的输出路径...")

        state = self.project.factory.entry_state(
            stdin=angr.SimFile
        )

        simgr = self.project.factory.simulation_manager(state)

        def check_output(state):
            """检查输出是否包含flag"""
            output = state.posix.dumps(1)  # stdout
            return flag_prefix.encode() in output

        try:
            # 使用DFS探索
            simgr.use_technique(angr.exploration_techniques.DFS())

            while simgr.active:
                simgr.step()

                # 检查是否找到flag
                for state in simgr.active:
                    if check_output(state):
                        stdin_data = state.posix.dumps(0)
                        stdout_data = state.posix.dumps(1)
                        print_success("找到flag路径!")
                        print_info(f"输入: {stdin_data}")
                        print_info(f"输出: {stdout_data}")
                        return stdin_data

                if simgr.deadended:
                    for state in simgr.deadended:
                        if check_output(state):
                            stdin_data = state.posix.dumps(0)
                            stdout_data = state.posix.dumps(1)
                            print_success("找到flag路径!")
                            return stdin_data

        except Exception as e:
            print_error(f"探索失败: {e}")

        return None

    def solve_crackme(self, success_addr: int = None,
                      success_string: str = None,
                      max_time: int = 300) -> Optional[bytes]:
        """
        自动解决crackme类题目

        通过约束求解找到正确的输入
        """
        print_info("解决 crackme 题目...")

        state = self.project.factory.entry_state(
            stdin=angr.SimFile
        )

        simgr = self.project.factory.simulation_manager(state)

        if success_addr:
            # 寻找到达成功地址的路径
            simgr.explore(find=success_addr, timeout=max_time)

        elif success_string:
            # 寻找输出成功字符串的路径
            def check_success(state):
                output = state.posix.dumps(1)
                return success_string.encode() in output

            while simgr.active and not simgr.found:
                simgr.step()
                for s in simgr.active:
                    if check_success(s):
                        simgr.found.append(s)
                        break

        if simgr.found:
            found = simgr.found[0]
            solution = found.posix.dumps(0)
            print_success(f"找到解: {solution}")
            return solution

        print_warning("未找到解")
        return None


class VulnerabilityFinder:
    """漏洞自动发现"""

    def __init__(self, binary_path: str):
        if not ANGR_AVAILABLE:
            raise ImportError("需要安装angr")

        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)

    def find_buffer_overflow(self) -> List[Dict]:
        """
        查找缓冲区溢出漏洞

        检测写入操作超过分配大小的情况
        """
        print_info("搜索缓冲区溢出漏洞...")
        vulnerabilities = []

        # 使用符号化输入
        state = self.project.factory.entry_state(
            stdin=angr.SimFile
        )

        simgr = self.project.factory.simulation_manager(state)

        # 设置内存访问检测
        def check_overflow(state):
            # 检测RIP是否被符号化输入控制
            if state.regs.rip.symbolic:
                return True
            return False

        try:
            step_count = 0
            max_steps = 1000

            while simgr.active and step_count < max_steps:
                simgr.step()
                step_count += 1

                for s in simgr.active:
                    if check_overflow(s):
                        vuln = {
                            'type': 'buffer_overflow',
                            'pc_controlled': True,
                            'input': s.posix.dumps(0),
                        }
                        vulnerabilities.append(vuln)
                        print_success("发现缓冲区溢出!")

        except Exception as e:
            print_error(f"分析失败: {e}")

        return vulnerabilities

    def find_format_string(self) -> List[Dict]:
        """
        查找格式化字符串漏洞

        检测printf类函数的危险调用
        """
        print_info("搜索格式化字符串漏洞...")
        vulnerabilities = []

        # 分析危险函数调用
        cfg = self.project.analyses.CFGFast()

        dangerous_funcs = ['printf', 'sprintf', 'fprintf', 'snprintf']

        for func_name in dangerous_funcs:
            try:
                func = self.project.loader.find_symbol(func_name)
                if func:
                    # 找到对该函数的所有调用
                    for node in cfg.nodes():
                        for succ in cfg.successors(node):
                            if succ.addr == func.rebased_addr:
                                vuln = {
                                    'type': 'format_string',
                                    'function': func_name,
                                    'call_site': hex(node.addr),
                                }
                                vulnerabilities.append(vuln)
            except:
                pass

        if vulnerabilities:
            print_success(f"发现 {len(vulnerabilities)} 个潜在格式化字符串漏洞")
        else:
            print_warning("未发现格式化字符串漏洞")

        return vulnerabilities


class ConstraintSolver:
    """约束求解器"""

    def __init__(self):
        if not ANGR_AVAILABLE:
            raise ImportError("需要安装angr")

    def solve_equation(self, equation_func, input_size: int = 32) -> Optional[bytes]:
        """
        求解方程约束

        equation_func: 接受符号变量返回约束的函数
        """
        print_info("求解约束方程...")

        # 创建符号变量
        sym_input = claripy.BVS('input', input_size * 8)

        # 获取约束
        constraint = equation_func(sym_input)

        # 创建求解器
        solver = claripy.Solver()
        solver.add(constraint)

        if solver.satisfiable():
            solution = solver.eval(sym_input, 1)[0]
            solution_bytes = solution.to_bytes(input_size, 'little')
            print_success(f"找到解: {solution_bytes}")
            return solution_bytes
        else:
            print_warning("无解")
            return None

    def solve_xor_check(self, target: bytes, key: bytes = None) -> Optional[bytes]:
        """
        求解XOR加密检查

        常见CTF场景: input ^ key == target
        """
        print_info("求解XOR检查...")

        if key:
            # 已知key, 直接计算
            result = bytes(a ^ b for a, b in zip(target, key * (len(target) // len(key) + 1)))
            print_success(f"解: {result}")
            return result
        else:
            print_warning("需要提供key或使用符号执行")
            return None


class CTFSolver:
    """CTF自动解题器"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        if ANGR_AVAILABLE:
            self.explorer = SymbolicExplorer(binary_path)
            self.vuln_finder = VulnerabilityFinder(binary_path)
        else:
            self.explorer = None
            self.vuln_finder = None

    def auto_solve(self) -> Dict[str, Any]:
        """
        自动分析并尝试解决CTF题目
        """
        result = {
            'solved': False,
            'flag': None,
            'vulnerabilities': [],
            'solution_input': None,
        }

        if not ANGR_AVAILABLE:
            print_error("angr未安装,无法进行符号执行分析")
            return result

        print_info("开始自动分析...")

        # 1. 查找漏洞
        print_info("步骤1: 漏洞扫描")
        bof_vulns = self.vuln_finder.find_buffer_overflow()
        fmt_vulns = self.vuln_finder.find_format_string()
        result['vulnerabilities'] = bof_vulns + fmt_vulns

        # 2. 尝试找flag
        print_info("步骤2: 搜索flag路径")
        for prefix in ['flag{', 'FLAG{', 'ctf{', 'CTF{']:
            solution = self.explorer.find_flag_path(prefix)
            if solution:
                result['solved'] = True
                result['solution_input'] = solution
                break

        # 3. 尝试crackme求解
        if not result['solved']:
            print_info("步骤3: 尝试crackme求解")
            for success_str in ['Correct', 'Success', 'Win', 'Good']:
                solution = self.explorer.solve_crackme(success_string=success_str)
                if solution:
                    result['solved'] = True
                    result['solution_input'] = solution
                    break

        return result


def quick_symbolic_analysis(binary_path: str) -> Dict:
    """
    快速符号执行分析

    返回分析结果摘要
    """
    if not ANGR_AVAILABLE:
        return {
            'available': False,
            'error': 'angr未安装',
            'install_command': 'pip install angr'
        }

    try:
        project = angr.Project(binary_path, auto_load_libs=False)

        result = {
            'available': True,
            'arch': project.arch.name,
            'entry_point': hex(project.entry),
            'base_addr': hex(project.loader.main_object.min_addr),
        }

        # 快速CFG分析
        cfg = project.analyses.CFGFast()
        result['functions_count'] = len(list(cfg.functions.values()))

        # 检测危险函数
        dangerous = []
        for func in ['gets', 'strcpy', 'sprintf', 'scanf', 'printf']:
            if project.loader.find_symbol(func):
                dangerous.append(func)
        result['dangerous_functions'] = dangerous

        return result

    except Exception as e:
        return {
            'available': True,
            'error': str(e)
        }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = quick_symbolic_analysis(sys.argv[1])
        print(f"\n{Colors.BOLD}符号执行分析结果:{Colors.END}")
        for key, value in result.items():
            print(f"  {key}: {value}")

        if ANGR_AVAILABLE and len(sys.argv) > 2 and sys.argv[2] == '--solve':
            solver = CTFSolver(sys.argv[1])
            solve_result = solver.auto_solve()
            print(f"\n{Colors.BOLD}自动求解结果:{Colors.END}")
            print(f"  已解决: {solve_result['solved']}")
            if solve_result['solution_input']:
                print(f"  解: {solve_result['solution_input']}")
