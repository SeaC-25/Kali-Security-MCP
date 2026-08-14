#!/usr/bin/env python3
"""回归测试：_auto_discover_findings 否定上下文门（XSS clean 误报修复）。

背景: fastsec -xss 的 clean 输出 "[xss] 0/0 params XSS reflected ... clean"
含 "XSS" 子串，修复前被 _auto_discover_findings 判成 HIGH "XSS detected" 误报。
修复后: 含否定上下文标记（0/N、clean、未发现匹配、无匹配、not vulnerable、
no match 等）的行不产 finding；真实命中行（[!] XSS reflected: <payload>）仍产。
"""

from __future__ import annotations

import unittest

from kali_mcp.core.result_aggregator import (
    AgentResult,
    Finding,
    ResultAggregator,
)


def _make_result(output: str, tool_name: str = "intelligent_xss_payloads") -> AgentResult:
    return AgentResult(
        agent_id="web_vuln_agent",
        task_id="t1",
        tool_name=tool_name,
        target="http://localhost:8000/",
        success=True,
        execution_time=0.1,
        output=output,
    )


class TestAutoDiscoverNegativeContext(unittest.TestCase):
    """_auto_discover_findings 否定上下文门。"""

    def setUp(self):
        self.agg = ResultAggregator()

    def test_xss_clean_zero_hit_no_finding(self):
        """fastsec -xss clean 输出（0/0 + clean）→ 0 finding（原误报场景）。"""
        output = (
            "[xss] 0/0 params XSS reflected\n"
            "  (URL 无 query 参数且未指定 -xss 参数名 → 无参数可测，clean)\n"
        )
        findings = self.agg._auto_discover_findings(_make_result(output))
        self.assertEqual(findings, [])

    def test_xss_real_hit_produces_finding(self):
        """真实命中输出（[!] 行，1/1）→ 1 个 XSS finding。"""
        output = (
            "[xss] 1/1 params XSS reflected\n"
            "  [!] name XSS reflected: <script>alert(1)</script>\n"
        )
        findings = self.agg._auto_discover_findings(_make_result(output))
        xss = [f for f in findings if f.title == "XSS detected"]
        self.assertEqual(len(xss), 1)
        self.assertEqual(xss[0].severity.value, "high")
        self.assertIn("<script>alert(1)</script>", xss[0].evidence[0])

    def test_templates_no_match_no_finding(self):
        """fastsec 模板扫描 '未发现匹配' 输出 → 0 finding。"""
        output = (
            "=== http://localhost:8000/ ===\n"
            "[-] 未发现匹配\n"
            "[fastsec] 完成: 0 匹配 / 1 目标 / 1931 模板\n"
        )
        findings = self.agg._auto_discover_findings(
            _make_result(output, tool_name="nuclei_scan")
        )
        self.assertEqual(findings, [])

    def test_negative_marker_suppresses_any_keyword(self):
        """含 'not vulnerable' 的行即使带关键字也不产 finding（SQL injection 同门槛）。"""
        output = (
            "[-] SQL injection check: not vulnerable\n"
            "No injection points found, scan clean\n"
        )
        findings = self.agg._auto_discover_findings(
            _make_result(output, tool_name="sqlmap_scan")
        )
        self.assertEqual(findings, [])

    def test_keyword_on_plain_line_still_detected(self):
        """无否定标记的正常命中行仍产 finding（RCE 关键字）。"""
        output = "nuclei: [critical] http://localhost:8000/cmd.php (rce-command-injection)"
        findings = self.agg._auto_discover_findings(
            _make_result(output, tool_name="nuclei_scan")
        )
        rce = [f for f in findings if f.title == "RCE detected"]
        self.assertEqual(len(rce), 1)

    def test_open_port_detection_unchanged(self):
        """开放端口资产发现不受影响。"""
        output = "80/tcp open  http\n443/tcp open  https"
        findings = self.agg._auto_discover_findings(
            _make_result(output, tool_name="nmap_scan")
        )
        ports = [f for f in findings if f.title.startswith("Open port")]
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0].severity.value, "info")

    def test_clean_line_skipped_but_hit_line_kept(self):
        """混合输出：clean 行被跳过、真实命中行仍产 finding（逐行门，不整体丢弃）。"""
        output = (
            "[xss] 1/2 params XSS reflected\n"
            "  [!] q XSS reflected: <script>alert(document.domain)</script>\n"
            "  [!] name XSS reflected: (URL 无 query 参数且未指定 -xss 参数名 → clean)\n"
        )
        findings = self.agg._auto_discover_findings(_make_result(output))
        xss = [f for f in findings if f.title == "XSS detected"]
        # 只有无否定标记的命中行产 finding；clean 行被门过滤
        self.assertEqual(len(xss), 1)
        self.assertIn("alert(document.domain)", xss[0].evidence[0])


if __name__ == "__main__":
    unittest.main()
