#!/usr/bin/env python3
"""
增强CTF求解和逆向工程工具

从 mcp_server.py setup_mcp_server() 提取
"""

import logging
import re as _re
import subprocess
import os
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def register_advanced_ctf_tools(mcp, executor, adapter=None):
    """增强CTF求解和逆向工程工具注册"""

    def _detect_flags(text):
        """检测输出中的flag"""
        if not text:
            return []
        flags = []
        for pat in [r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}', r'DASCTF\{[^}]+\}']:
            flags.extend(_re.findall(pat, text, _re.IGNORECASE))
        return list(set(flags))

    def _run_tool(tool_name, params):
        """安全执行工具并返回结果（支持适配器路由）"""
        try:
            # 如果有适配器且工具应该走代理路径
            if adapter and adapter.should_use_agent(tool_name, params):
                return adapter.execute_via_agent(tool_name, params)
            return executor.execute_tool_with_data(tool_name, params)
        except Exception as e:
            logger.warning(f"工具 {tool_name} 执行失败: {e}")
            return {"success": False, "error": str(e)}

    def _get_output(result):
        """从工具结果提取输出文本"""
        return result.get("output", "") or result.get("stdout", "")

    # ==================== 逆向工程工具 ====================

    @mcp.tool()
    def reverse_tool_check() -> Dict[str, Any]:
        """
        检查可用的逆向分析工具 - 检测本机逆向工程工具

        Returns:
            可用的逆向分析工具状态
        """
        available_tools = {}

        # 检查Radare2
        try:
            result = subprocess.run(["r2", "-version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                available_tools["radare2"] = {
                    "available": True,
                    "version": result.stdout.strip()
                }
            else:
                available_tools["radare2"] = {"available": False}
        except:
            available_tools["radare2"] = {"available": False}

        # 检查Ghidra
        try:
            ghidra_paths = [
                "/usr/bin/ghidra",
                "/opt/ghidra/support/analyzeHeadless",
                "/usr/share/ghidra/support/analyzeHeadless"
            ]
            ghidra_available = any(os.path.exists(path) for path in ghidra_paths)
            available_tools["ghidra"] = {"available": ghidra_available}
        except:
            available_tools["ghidra"] = {"available": False}

        # 检查checksec
        try:
            result = subprocess.run(["checksec", "--version"], capture_output=True, text=True, timeout=5)
            available_tools["checksec"] = {"available": result.returncode == 0}
        except:
            available_tools["checksec"] = {"available": False}

        return {
            "success": True,
            "available_tools": available_tools,
            "recommendation": "radare2" if available_tools.get("radare2", {}).get("available")
                           else "ghidra" if available_tools.get("ghidra", {}).get("available")
                           else "请安装逆向分析工具 (apt install radare2)"
        }

    @mcp.tool()
    def radare2_analyze_binary(binary_path: str) -> Dict[str, Any]:
        """
        使用Radare2分析二进制文件 - 开源逆向分析工具

        Args:
            binary_path: 二进制文件路径

        Returns:
            Radare2分析结果，包含函数、字符串、导入导出等信息
        """
        import json

        results = {
            "binary_path": binary_path,
            "functions": [],
            "strings": [],
            "imports": []
        }

        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}

        # 使用executor调用r2（已在_build_tool_command中配置非交互模式）
        # 基础信息分析
        info_result = _run_tool("r2", {"target": binary_path, "additional_args": "ij"})
        info_output = _get_output(info_result)
        try:
            results["binary_info"] = json.loads(info_output)
        except:
            results["binary_info"] = {"raw": info_output[:2000]}

        # 函数列表
        func_result = _run_tool("execute_command", {
            "command": f"r2 -q -A -e scr.color=0 -c 'afl' '{binary_path}'"
        })
        results["functions_raw"] = _get_output(func_result)[:5000]

        # 字符串提取
        str_result = _run_tool("r2", {"target": binary_path, "additional_args": "izz"})
        results["strings_raw"] = _get_output(str_result)[:5000]

        # 导入函数
        imp_result = _run_tool("r2", {"target": binary_path, "additional_args": "ii"})
        results["imports_raw"] = _get_output(imp_result)[:3000]

        results["success"] = True
        results["tool"] = "radare2"
        return results

    @mcp.tool()
    def ghidra_analyze_binary(binary_path: str) -> Dict[str, Any]:
        """
        使用Ghidra分析二进制文件 - NSA开源逆向分析工具

        Args:
            binary_path: 二进制文件路径

        Returns:
            Ghidra分析结果
        """
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}

        try:
            import tempfile

            with tempfile.TemporaryDirectory() as temp_dir:
                project_dir = os.path.join(temp_dir, "ghidra_project")

                ghidra_paths = [
                    "/opt/ghidra/support/analyzeHeadless",
                    "/usr/share/ghidra/support/analyzeHeadless"
                ]

                ghidra_cmd = None
                for path in ghidra_paths:
                    if os.path.exists(path):
                        ghidra_cmd = path
                        break

                if not ghidra_cmd:
                    return {
                        "success": False,
                        "error": "Ghidra未找到",
                        "suggestion": "请安装Ghidra: apt install ghidra"
                    }

                cmd = [
                    ghidra_cmd,
                    project_dir,
                    "temp_project",
                    "-import", binary_path,
                    "-postScript", "ListFunctionsScript.java"
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                return {
                    "success": result.returncode == 0,
                    "tool": "ghidra",
                    "binary_path": binary_path,
                    "output": result.stdout[:10000],
                    "error": result.stderr[:3000] if result.returncode != 0 else None
                }

        except Exception as e:
            return {"success": False, "error": f"Ghidra分析失败: {str(e)}"}

    @mcp.tool()
    def auto_reverse_analyze(binary_path: str) -> Dict[str, Any]:
        """
        自动选择可用工具进行逆向分析 - 智能工具选择

        Args:
            binary_path: 二进制文件路径

        Returns:
            自动分析结果，使用最佳可用工具
        """
        if not os.path.exists(binary_path):
            return {"success": False, "error": f"文件不存在: {binary_path}"}

        tool_status = reverse_tool_check()
        available = tool_status.get("available_tools", {})

        results = {
            "binary_path": binary_path,
            "attempted_tools": [],
            "successful_analysis": None,
            "all_results": {}
        }

        # 优先级：Radare2 > Ghidra
        if available.get("radare2", {}).get("available"):
            try:
                r2_result = radare2_analyze_binary(binary_path)
                results["attempted_tools"].append("radare2")
                results["all_results"]["radare2"] = r2_result
                if r2_result.get("success"):
                    results["successful_analysis"] = "radare2"
                    results["primary_result"] = r2_result
                    results["success"] = True
                    return results
            except Exception as e:
                logger.warning(f"Radare2 分析失败: {e}")

        if available.get("ghidra", {}).get("available"):
            try:
                ghidra_result = ghidra_analyze_binary(binary_path)
                results["attempted_tools"].append("ghidra")
                results["all_results"]["ghidra"] = ghidra_result
                if ghidra_result.get("success"):
                    results["successful_analysis"] = "ghidra"
                    results["primary_result"] = ghidra_result
                    results["success"] = True
                    return results
            except Exception as e:
                logger.warning(f"Ghidra 分析失败: {e}")

        # 如果专用工具都不可用，使用基础命令
        results["attempted_tools"].append("basic_tools")
        basic_results = {}

        file_result = _run_tool("execute_command", {"command": f"file {binary_path}"})
        basic_results["file_type"] = _get_output(file_result)

        strings_result = _run_tool("execute_command", {"command": f"strings {binary_path} | head -200"})
        basic_results["strings"] = _get_output(strings_result)[:5000]

        objdump_result = _run_tool("execute_command", {"command": f"objdump -d {binary_path} | head -300"})
        basic_results["disassembly"] = _get_output(objdump_result)[:5000]

        results["all_results"]["basic_tools"] = basic_results
        results["successful_analysis"] = "basic_tools"
        results["primary_result"] = basic_results
        results["success"] = True
        return results

