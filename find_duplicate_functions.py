#!/usr/bin/env python3
"""查找重复函数的准确范围"""

import re

def find_function_end(lines, start_line):
    """找到函数结束的行号（下一个@mcp.tool()或文件结束）"""
    indent_level = None
    for i in range(start_line, len(lines)):
        line = lines[i]

        # 检查是否是下一个装饰器
        if i > start_line and line.strip().startswith('@mcp.tool()'):
            return i - 1

        # 检查缩进确定函数结束
        if indent_level is None and line.strip() and not line.strip().startswith('#'):
            # 获取函数定义行的缩进
            if 'def ' in line:
                indent_level = len(line) - len(line.lstrip())

        # 如果遇到同级别或更低级别的缩进（非空行），可能是函数结束
        if indent_level is not None and line.strip():
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= indent_level and i > start_line + 2 and not line.strip().startswith(('#', '"""', "'''")):
                # 检查是否是装饰器
                if line.strip().startswith('@'):
                    return i - 1

    return len(lines) - 1

def main():
    with open('mcp_server.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 要检查的重复函数
    duplicates = {
        'radare2_analyze_binary': [],
        'pwnpasi_auto_pwn': [],
        'pwn_comprehensive_attack': [],
        'ctf_pwn_solver': []
    }

    # 查找所有函数定义
    for i, line in enumerate(lines, 1):
        for func_name in duplicates.keys():
            if f'def {func_name}(' in line:
                # 查找对应的@mcp.tool()装饰器
                decorator_line = i - 1
                while decorator_line > 0 and lines[decorator_line - 1].strip() in ['', '@mcp.tool()']:
                    if '@mcp.tool()' in lines[decorator_line - 1]:
                        break
                    decorator_line -= 1

                # 检查函数使用的是什么实现
                func_content = []
                for j in range(i, min(i + 100, len(lines))):
                    func_content.append(lines[j])
                    if j > i + 5 and (lines[j].strip().startswith('@') or lines[j].strip().startswith('def ')):
                        break

                func_text = ''.join(func_content)

                info = {
                    'line': i,
                    'decorator_line': decorator_line,
                    'has_executor': 'executor.' in func_text,
                    'has_windows_path': 'F:\\\\kali' in func_text or 'F:/kali' in func_text,
                    'has_start_attack_session': 'start_attack_session' in func_text,
                    'signature': line.strip()
                }
                duplicates[func_name].append(info)

    # 打印分析结果
    print("=" * 80)
    print("重复函数分析")
    print("=" * 80)

    for func_name, instances in duplicates.items():
        if len(instances) > 1:
            print(f"\n【{func_name}】- 找到 {len(instances)} 个定义:")
            for idx, info in enumerate(instances, 1):
                print(f"\n  版本{idx} (行{info['line']}):")
                print(f"    签名: {info['signature'][:80]}")
                print(f"    使用executor: {info['has_executor']}")
                print(f"    有Windows路径: {info['has_windows_path']}")
                print(f"    调用start_attack_session: {info['has_start_attack_session']}")

                # 判断是否应该删除
                should_delete = False
                reason = ""

                if info['has_windows_path']:
                    should_delete = True
                    reason = "有Windows硬编码路径"
                elif info['has_start_attack_session']:
                    should_delete = True
                    reason = "调用未定义的start_attack_session"
                elif not info['has_executor'] and any(i['has_executor'] for i in instances):
                    should_delete = True
                    reason = "未使用executor（有其他版本使用）"

                if should_delete:
                    print(f"    ⚠️  建议删除: {reason}")
                else:
                    print(f"    ✅ 保留此版本")

if __name__ == "__main__":
    main()
