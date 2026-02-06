#!/usr/bin/env python3
"""
报告生成模块

生成渗透测试报告和CTF WriteUp:
- Markdown报告
- HTML报告
- CTF解题报告
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """报告格式"""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    TEXT = "text"


class ReportType(Enum):
    """报告类型"""
    PENTEST = "pentest"
    CTF_WRITEUP = "ctf_writeup"
    VULNERABILITY = "vulnerability"
    SUMMARY = "summary"


@dataclass
class ReportSection:
    """报告章节"""
    title: str
    content: str
    level: int = 2
    subsections: List['ReportSection'] = field(default_factory=list)


@dataclass
class ReportData:
    """报告数据"""
    title: str
    target: str
    report_type: ReportType
    start_time: datetime
    end_time: Optional[datetime] = None
    author: str = "Kali MCP"
    executive_summary: str = ""
    sections: List[ReportSection] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    flags_found: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReportGenerator:
    """报告生成器"""

    def __init__(self, output_dir: Optional[str] = None):
        """
        初始化报告生成器

        Args:
            output_dir: 报告输出目录
        """
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"ReportGenerator 初始化，输出目录: {self.output_dir}")

    def generate(
        self,
        data: ReportData,
        report_format: ReportFormat = ReportFormat.MARKDOWN
    ) -> str:
        """
        生成报告

        Args:
            data: 报告数据
            report_format: 报告格式

        Returns:
            报告内容
        """
        generators = {
            ReportFormat.MARKDOWN: self._generate_markdown,
            ReportFormat.HTML: self._generate_html,
            ReportFormat.JSON: self._generate_json,
            ReportFormat.TEXT: self._generate_text,
        }

        generator = generators.get(report_format, self._generate_markdown)
        return generator(data)

    def generate_and_save(
        self,
        data: ReportData,
        report_format: ReportFormat = ReportFormat.MARKDOWN,
        filename: Optional[str] = None
    ) -> Path:
        """
        生成并保存报告

        Args:
            data: 报告数据
            report_format: 报告格式
            filename: 文件名

        Returns:
            报告文件路径
        """
        content = self.generate(data, report_format)

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = {
                ReportFormat.MARKDOWN: "md",
                ReportFormat.HTML: "html",
                ReportFormat.JSON: "json",
                ReportFormat.TEXT: "txt",
            }.get(report_format, "txt")
            filename = f"report_{data.report_type.value}_{timestamp}.{ext}"

        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"报告已保存: {filepath}")
        return filepath

    def _generate_markdown(self, data: ReportData) -> str:
        """生成Markdown报告"""
        lines = []

        # 标题
        lines.append(f"# {data.title}")
        lines.append("")

        # 元数据
        lines.append("---")
        lines.append(f"**目标**: `{data.target}`")
        lines.append(f"**类型**: {data.report_type.value}")
        lines.append(f"**作者**: {data.author}")
        lines.append(f"**开始时间**: {data.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if data.end_time:
            lines.append(f"**结束时间**: {data.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            duration = data.end_time - data.start_time
            lines.append(f"**持续时间**: {duration}")
        lines.append("---")
        lines.append("")

        # 执行摘要
        if data.executive_summary:
            lines.append("## 执行摘要")
            lines.append("")
            lines.append(data.executive_summary)
            lines.append("")

        # Flag（CTF模式优先显示）
        if data.flags_found:
            lines.append("## 🚩 发现的Flag")
            lines.append("")
            for flag in data.flags_found:
                lines.append(f"```")
                lines.append(flag)
                lines.append(f"```")
            lines.append("")

        # 发现汇总
        if data.findings:
            lines.append("## 发现汇总")
            lines.append("")

            # 按严重程度分组
            severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for finding in data.findings:
                severity = finding.get("severity", "info")
                if severity in severity_groups:
                    severity_groups[severity].append(finding)

            for severity, findings in severity_groups.items():
                if findings:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "")
                    lines.append(f"### {emoji} {severity.upper()} ({len(findings)})")
                    lines.append("")
                    for finding in findings:
                        lines.append(f"- **{finding.get('type', 'Unknown')}**: {finding.get('value', '')}")
                    lines.append("")

        # 详细章节
        for section in data.sections:
            lines.extend(self._render_section(section))

        # 使用的工具
        if data.tools_used:
            lines.append("## 使用的工具")
            lines.append("")
            for tool in data.tools_used:
                lines.append(f"- `{tool}`")
            lines.append("")

        # 建议
        if data.recommendations:
            lines.append("## 安全建议")
            lines.append("")
            for i, rec in enumerate(data.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # 页脚
        lines.append("---")
        lines.append(f"*报告由 Kali MCP 自动生成 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)

    def _render_section(self, section: ReportSection, base_level: int = 0) -> List[str]:
        """渲染章节"""
        lines = []
        level = section.level + base_level
        prefix = "#" * min(level, 6)

        lines.append(f"{prefix} {section.title}")
        lines.append("")
        lines.append(section.content)
        lines.append("")

        for subsection in section.subsections:
            lines.extend(self._render_section(subsection, base_level + 1))

        return lines

    def _generate_html(self, data: ReportData) -> str:
        """生成HTML报告"""
        css = """
        <style>
            body { font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
            h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
            h2 { color: #555; margin-top: 30px; }
            .meta { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .meta p { margin: 5px 0; }
            .finding { padding: 10px; margin: 10px 0; border-radius: 5px; }
            .critical { background: #ffebee; border-left: 4px solid #f44336; }
            .high { background: #fff3e0; border-left: 4px solid #ff9800; }
            .medium { background: #fffde7; border-left: 4px solid #ffeb3b; }
            .low { background: #e3f2fd; border-left: 4px solid #2196f3; }
            .info { background: #f5f5f5; border-left: 4px solid #9e9e9e; }
            .flag { background: #e8f5e9; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 1.2em; }
            code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background: #f5f5f5; }
            .footer { margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #888; font-size: 0.9em; }
        </style>
        """

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{data.title}</title>
    {css}
</head>
<body>
    <h1>{data.title}</h1>

    <div class="meta">
        <p><strong>目标:</strong> <code>{data.target}</code></p>
        <p><strong>类型:</strong> {data.report_type.value}</p>
        <p><strong>作者:</strong> {data.author}</p>
        <p><strong>时间:</strong> {data.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""

        # 执行摘要
        if data.executive_summary:
            html += f"""
    <h2>执行摘要</h2>
    <p>{data.executive_summary}</p>
"""

        # Flag
        if data.flags_found:
            html += """
    <h2>🚩 发现的Flag</h2>
"""
            for flag in data.flags_found:
                html += f'    <div class="flag">{flag}</div>\n'

        # 发现
        if data.findings:
            html += """
    <h2>发现汇总</h2>
    <table>
        <tr><th>类型</th><th>值</th><th>严重程度</th></tr>
"""
            for finding in data.findings:
                severity = finding.get("severity", "info")
                html += f"""        <tr class="{severity}">
            <td>{finding.get('type', 'Unknown')}</td>
            <td>{finding.get('value', '')}</td>
            <td>{severity.upper()}</td>
        </tr>
"""
            html += "    </table>\n"

        # 工具
        if data.tools_used:
            html += """
    <h2>使用的工具</h2>
    <ul>
"""
            for tool in data.tools_used:
                html += f"        <li><code>{tool}</code></li>\n"
            html += "    </ul>\n"

        # 建议
        if data.recommendations:
            html += """
    <h2>安全建议</h2>
    <ol>
"""
            for rec in data.recommendations:
                html += f"        <li>{rec}</li>\n"
            html += "    </ol>\n"

        # 页脚
        html += f"""
    <div class="footer">
        <p>报告由 Kali MCP 自动生成 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>
"""

        return html

    def _generate_json(self, data: ReportData) -> str:
        """生成JSON报告"""
        report_dict = {
            "title": data.title,
            "target": data.target,
            "report_type": data.report_type.value,
            "author": data.author,
            "start_time": data.start_time.isoformat(),
            "end_time": data.end_time.isoformat() if data.end_time else None,
            "executive_summary": data.executive_summary,
            "findings": data.findings,
            "tools_used": data.tools_used,
            "flags_found": data.flags_found,
            "recommendations": data.recommendations,
            "metadata": data.metadata,
            "sections": [
                {
                    "title": s.title,
                    "content": s.content,
                    "level": s.level
                }
                for s in data.sections
            ]
        }

        return json.dumps(report_dict, indent=2, ensure_ascii=False)

    def _generate_text(self, data: ReportData) -> str:
        """生成纯文本报告"""
        lines = []

        # 标题
        lines.append("=" * 60)
        lines.append(data.title.center(60))
        lines.append("=" * 60)
        lines.append("")

        # 元数据
        lines.append(f"目标: {data.target}")
        lines.append(f"类型: {data.report_type.value}")
        lines.append(f"作者: {data.author}")
        lines.append(f"时间: {data.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # 执行摘要
        if data.executive_summary:
            lines.append("-" * 40)
            lines.append("执行摘要")
            lines.append("-" * 40)
            lines.append(data.executive_summary)
            lines.append("")

        # Flag
        if data.flags_found:
            lines.append("-" * 40)
            lines.append("发现的Flag")
            lines.append("-" * 40)
            for flag in data.flags_found:
                lines.append(f"  {flag}")
            lines.append("")

        # 发现
        if data.findings:
            lines.append("-" * 40)
            lines.append("发现汇总")
            lines.append("-" * 40)
            for finding in data.findings:
                severity = finding.get("severity", "info").upper()
                lines.append(f"  [{severity}] {finding.get('type', '')}: {finding.get('value', '')}")
            lines.append("")

        # 工具
        if data.tools_used:
            lines.append("-" * 40)
            lines.append("使用的工具")
            lines.append("-" * 40)
            for tool in data.tools_used:
                lines.append(f"  - {tool}")
            lines.append("")

        # 建议
        if data.recommendations:
            lines.append("-" * 40)
            lines.append("安全建议")
            lines.append("-" * 40)
            for i, rec in enumerate(data.recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")

        lines.append("=" * 60)
        lines.append(f"报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        return "\n".join(lines)

    def generate_ctf_writeup(
        self,
        target: str,
        challenge_name: str,
        category: str,
        flags: List[str],
        steps: List[Dict[str, Any]],
        tools_used: List[str]
    ) -> str:
        """
        生成CTF WriteUp

        Args:
            target: 目标地址
            challenge_name: 题目名称
            category: 题目类别
            flags: 获取的Flag
            steps: 解题步骤
            tools_used: 使用的工具

        Returns:
            WriteUp内容
        """
        data = ReportData(
            title=f"CTF WriteUp: {challenge_name}",
            target=target,
            report_type=ReportType.CTF_WRITEUP,
            start_time=datetime.now(),
            executive_summary=f"成功解决 {category} 类型的挑战",
            flags_found=flags,
            tools_used=tools_used
        )

        # 添加解题步骤
        for i, step in enumerate(steps, 1):
            section = ReportSection(
                title=f"步骤 {i}: {step.get('title', '操作')}",
                content=step.get('description', ''),
                level=3
            )
            data.sections.append(section)

        return self.generate(data, ReportFormat.MARKDOWN)


# 全局报告生成器
_global_reporter: Optional[ReportGenerator] = None


def get_reporter() -> ReportGenerator:
    """获取全局报告生成器"""
    global _global_reporter
    if _global_reporter is None:
        _global_reporter = ReportGenerator()
    return _global_reporter
