#!/usr/bin/env python3
"""
输出格式化模块

统一工具输出格式:
- JSON格式化
- 表格格式化
- Markdown格式化
- 终端彩色输出
"""

import json
import logging
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class OutputFormat(Enum):
    """输出格式"""
    JSON = "json"
    TABLE = "table"
    MARKDOWN = "markdown"
    TEXT = "text"
    HTML = "html"


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ANSI颜色代码
class Colors:
    """终端颜色"""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class OutputFormatter:
    """输出格式化器"""

    # 严重程度颜色映射
    SEVERITY_COLORS = {
        Severity.CRITICAL: Colors.RED + Colors.BOLD,
        Severity.HIGH: Colors.RED,
        Severity.MEDIUM: Colors.YELLOW,
        Severity.LOW: Colors.BLUE,
        Severity.INFO: Colors.CYAN,
    }

    def __init__(self, default_format: OutputFormat = OutputFormat.TEXT):
        """
        初始化格式化器

        Args:
            default_format: 默认输出格式
        """
        self.default_format = default_format
        self.use_colors = True

    def format(
        self,
        data: Dict[str, Any],
        output_format: Optional[OutputFormat] = None
    ) -> str:
        """
        格式化数据

        Args:
            data: 要格式化的数据
            output_format: 输出格式

        Returns:
            格式化后的字符串
        """
        fmt = output_format or self.default_format

        formatters = {
            OutputFormat.JSON: self._format_json,
            OutputFormat.TABLE: self._format_table,
            OutputFormat.MARKDOWN: self._format_markdown,
            OutputFormat.TEXT: self._format_text,
            OutputFormat.HTML: self._format_html,
        }

        formatter = formatters.get(fmt, self._format_text)
        return formatter(data)

    def _format_json(self, data: Dict[str, Any]) -> str:
        """JSON格式"""
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _format_table(self, data: Dict[str, Any]) -> str:
        """表格格式"""
        lines = []

        # 标题
        if "tool_name" in data:
            lines.append(f"┌{'─' * 60}┐")
            lines.append(f"│ {data['tool_name']:^58} │")
            lines.append(f"├{'─' * 60}┤")

        # 摘要
        if "summary" in data:
            lines.append(f"│ 摘要: {data['summary']:<51} │")

        # 目标
        if "target" in data:
            lines.append(f"│ 目标: {data['target']:<51} │")

        # 发现
        if "findings" in data and data["findings"]:
            lines.append(f"├{'─' * 60}┤")
            lines.append(f"│ {'发现':^57} │")
            lines.append(f"├{'─' * 60}┤")

            for finding in data["findings"][:10]:  # 限制显示数量
                finding_type = finding.get("type", "unknown")
                value = str(finding.get("value", ""))[:45]
                severity = finding.get("severity", "info")
                lines.append(f"│ [{severity:^8}] {finding_type}: {value:<35} │")

            if len(data["findings"]) > 10:
                lines.append(f"│ ... 还有 {len(data['findings']) - 10} 个发现 ... │")

        # 下一步建议
        if "next_steps" in data and data["next_steps"]:
            lines.append(f"├{'─' * 60}┤")
            lines.append(f"│ {'下一步建议':^54} │")
            for step in data["next_steps"][:5]:
                step_text = str(step)[:56]
                lines.append(f"│ • {step_text:<55} │")

        # Flag
        if "flags_found" in data and data["flags_found"]:
            lines.append(f"├{'─' * 60}┤")
            lines.append(f"│ {'🚩 发现的Flag':^54} │")
            for flag in data["flags_found"]:
                lines.append(f"│ {flag:<58} │")

        lines.append(f"└{'─' * 60}┘")

        return "\n".join(lines)

    def _format_markdown(self, data: Dict[str, Any]) -> str:
        """Markdown格式"""
        lines = []

        # 标题
        tool_name = data.get("tool_name", "Unknown Tool")
        lines.append(f"## {tool_name}")
        lines.append("")

        # 基本信息
        if "target" in data:
            lines.append(f"**目标**: `{data['target']}`")
        if "summary" in data:
            lines.append(f"**摘要**: {data['summary']}")
        if "success" in data:
            status = "✅ 成功" if data["success"] else "❌ 失败"
            lines.append(f"**状态**: {status}")

        lines.append("")

        # 发现
        if "findings" in data and data["findings"]:
            lines.append("### 发现")
            lines.append("")
            lines.append("| 类型 | 值 | 严重程度 |")
            lines.append("|------|-----|----------|")

            for finding in data["findings"]:
                finding_type = finding.get("type", "unknown")
                value = str(finding.get("value", ""))[:50]
                severity = finding.get("severity", "info")
                lines.append(f"| {finding_type} | {value} | {severity} |")

            lines.append("")

        # 下一步建议
        if "next_steps" in data and data["next_steps"]:
            lines.append("### 建议的下一步")
            lines.append("")
            for step in data["next_steps"]:
                lines.append(f"- {step}")
            lines.append("")

        # Flag
        if "flags_found" in data and data["flags_found"]:
            lines.append("### 🚩 发现的Flag")
            lines.append("")
            for flag in data["flags_found"]:
                lines.append(f"```")
                lines.append(flag)
                lines.append(f"```")
            lines.append("")

        # 原始输出
        if "raw_output" in data and data.get("include_raw", False):
            lines.append("### 原始输出")
            lines.append("")
            lines.append("```")
            lines.append(data["raw_output"][:2000])
            if len(data["raw_output"]) > 2000:
                lines.append("... (输出已截断)")
            lines.append("```")

        return "\n".join(lines)

    def _format_text(self, data: Dict[str, Any]) -> str:
        """纯文本格式"""
        lines = []

        # 标题
        tool_name = data.get("tool_name", "Unknown")
        lines.append(f"{'=' * 60}")
        lines.append(f" {tool_name}")
        lines.append(f"{'=' * 60}")

        # 基本信息
        if "target" in data:
            lines.append(f"目标: {data['target']}")
        if "summary" in data:
            lines.append(f"摘要: {data['summary']}")
        if "success" in data:
            status = "成功" if data["success"] else "失败"
            lines.append(f"状态: {status}")

        lines.append("")

        # 发现
        if "findings" in data and data["findings"]:
            lines.append("发现:")
            for finding in data["findings"]:
                finding_type = finding.get("type", "unknown")
                value = finding.get("value", "")
                severity = finding.get("severity", "info")
                lines.append(f"  [{severity}] {finding_type}: {value}")
            lines.append("")

        # 下一步建议
        if "next_steps" in data and data["next_steps"]:
            lines.append("下一步建议:")
            for step in data["next_steps"]:
                lines.append(f"  - {step}")
            lines.append("")

        # Flag
        if "flags_found" in data and data["flags_found"]:
            lines.append("发现的Flag:")
            for flag in data["flags_found"]:
                lines.append(f"  🚩 {flag}")

        return "\n".join(lines)

    def _format_html(self, data: Dict[str, Any]) -> str:
        """HTML格式"""
        lines = []

        lines.append("<div class='tool-result'>")

        # 标题
        tool_name = data.get("tool_name", "Unknown")
        lines.append(f"<h2>{tool_name}</h2>")

        # 基本信息
        lines.append("<div class='info'>")
        if "target" in data:
            lines.append(f"<p><strong>目标:</strong> <code>{data['target']}</code></p>")
        if "summary" in data:
            lines.append(f"<p><strong>摘要:</strong> {data['summary']}</p>")
        if "success" in data:
            status_class = "success" if data["success"] else "failure"
            status_text = "成功" if data["success"] else "失败"
            lines.append(f"<p><strong>状态:</strong> <span class='{status_class}'>{status_text}</span></p>")
        lines.append("</div>")

        # 发现
        if "findings" in data and data["findings"]:
            lines.append("<div class='findings'>")
            lines.append("<h3>发现</h3>")
            lines.append("<table>")
            lines.append("<tr><th>类型</th><th>值</th><th>严重程度</th></tr>")

            for finding in data["findings"]:
                finding_type = finding.get("type", "unknown")
                value = finding.get("value", "")
                severity = finding.get("severity", "info")
                lines.append(f"<tr class='severity-{severity}'>")
                lines.append(f"<td>{finding_type}</td>")
                lines.append(f"<td>{value}</td>")
                lines.append(f"<td>{severity}</td>")
                lines.append("</tr>")

            lines.append("</table>")
            lines.append("</div>")

        # Flag
        if "flags_found" in data and data["flags_found"]:
            lines.append("<div class='flags'>")
            lines.append("<h3>🚩 发现的Flag</h3>")
            for flag in data["flags_found"]:
                lines.append(f"<pre class='flag'>{flag}</pre>")
            lines.append("</div>")

        lines.append("</div>")

        return "\n".join(lines)

    def colorize(self, text: str, severity: Severity) -> str:
        """
        给文本添加颜色

        Args:
            text: 文本
            severity: 严重程度

        Returns:
            带颜色的文本
        """
        if not self.use_colors:
            return text

        color = self.SEVERITY_COLORS.get(severity, Colors.WHITE)
        return f"{color}{text}{Colors.RESET}"

    def format_finding(self, finding: Dict[str, Any]) -> str:
        """格式化单个发现"""
        finding_type = finding.get("type", "unknown")
        value = finding.get("value", "")
        severity_str = finding.get("severity", "info")

        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        text = f"[{severity_str.upper()}] {finding_type}: {value}"
        return self.colorize(text, severity)

    def format_progress(
        self,
        current: int,
        total: int,
        width: int = 40
    ) -> str:
        """
        格式化进度条

        Args:
            current: 当前进度
            total: 总数
            width: 进度条宽度

        Returns:
            进度条字符串
        """
        if total == 0:
            percentage = 0
        else:
            percentage = current / total

        filled = int(width * percentage)
        empty = width - filled

        bar = f"[{'█' * filled}{'░' * empty}] {percentage:.1%}"
        return bar


# 全局格式化器
_global_formatter: Optional[OutputFormatter] = None


def get_formatter() -> OutputFormatter:
    """获取全局格式化器"""
    global _global_formatter
    if _global_formatter is None:
        _global_formatter = OutputFormatter()
    return _global_formatter
