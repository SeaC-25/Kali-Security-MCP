"""
响应智能分析器
==============

AI驱动的响应分析，支持：
- SQL注入检测（基于错误信息和行为差异）
- XSS反射检测
- 命令注入检测
- 信息泄露检测
- 技术指纹识别
- 盲注差异检测
- 敏感数据提取
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from difflib import SequenceMatcher
import hashlib

from .models import (
    HTTPResponse,
    VulnerabilityIndicator,
    ResponseDiff,
    BlindDetectionResult,
    SensitiveDataMatch,
    TargetProfile
)

logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    """
    AI驱动的响应分析器

    功能：
    - 漏洞指标检测
    - 盲注差异分析
    - 技术指纹识别
    - 敏感数据提取
    - 端点发现
    """

    # ==================== SQL注入检测模式 ====================

    SQL_ERROR_PATTERNS = [
        # MySQL
        (r"SQL syntax.*MySQL", "mysql", 0.95),
        (r"Warning.*mysql_", "mysql", 0.85),
        (r"MySQLSyntaxErrorException", "mysql", 0.95),
        (r"valid MySQL result", "mysql", 0.80),
        (r"check the manual that corresponds to your MySQL", "mysql", 0.90),
        (r"MySqlClient\.", "mysql", 0.85),
        (r"com\.mysql\.jdbc", "mysql", 0.90),
        (r"Unclosed quotation mark after the character string", "mssql", 0.90),

        # PostgreSQL
        (r"PostgreSQL.*ERROR", "postgresql", 0.95),
        (r"Warning.*\Wpg_", "postgresql", 0.85),
        (r"valid PostgreSQL result", "postgresql", 0.80),
        (r"Npgsql\.", "postgresql", 0.85),
        (r"PG::SyntaxError:", "postgresql", 0.90),
        (r"org\.postgresql\.util\.PSQLException", "postgresql", 0.90),
        (r"ERROR:\s+syntax error at or near", "postgresql", 0.90),

        # Microsoft SQL Server
        (r"Driver.*SQL[\-\_\ ]*Server", "mssql", 0.90),
        (r"OLE DB.*SQL Server", "mssql", 0.85),
        (r"\bSQL Server[^&lt;&quot;]+Driver", "mssql", 0.85),
        (r"Warning.*mssql_", "mssql", 0.80),
        (r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}", "mssql", 0.80),
        (r"System\.Data\.SqlClient\.SqlException", "mssql", 0.95),
        (r"Exception.*\WRoadhouse\.Cms\.", "mssql", 0.80),
        (r"Microsoft SQL Native Client error", "mssql", 0.90),
        (r"ODBC SQL Server Driver", "mssql", 0.85),

        # Oracle
        (r"\bORA-\d{5}", "oracle", 0.95),
        (r"Oracle error", "oracle", 0.85),
        (r"Oracle.*Driver", "oracle", 0.80),
        (r"Warning.*\Woci_", "oracle", 0.80),
        (r"Warning.*\Wora_", "oracle", 0.80),
        (r"oracle\.jdbc\.driver", "oracle", 0.90),
        (r"quoted string not properly terminated", "oracle", 0.85),

        # SQLite
        (r"SQLite/JDBCDriver", "sqlite", 0.85),
        (r"SQLite\.Exception", "sqlite", 0.90),
        (r"System\.Data\.SQLite\.SQLiteException", "sqlite", 0.95),
        (r"Warning.*sqlite_", "sqlite", 0.80),
        (r"Warning.*SQLite3::", "sqlite", 0.85),
        (r"\[SQLITE_ERROR\]", "sqlite", 0.90),
        (r"SQLite error \d+:", "sqlite", 0.90),
        (r"sqlite3\.OperationalError:", "sqlite", 0.90),
        (r"SQLite3::SQLException", "sqlite", 0.90),

        # 通用SQL错误
        (r"SQL syntax.*", "unknown", 0.70),
        (r"syntax error.*SQL", "unknown", 0.70),
        (r"SQL command not properly ended", "unknown", 0.75),
        (r"Incorrect syntax near", "unknown", 0.80),
        (r"Unexpected end of command", "unknown", 0.70),
        (r"The used SELECT statements have a different number of columns", "unknown", 0.85),
        (r"Unknown column '[^']+' in", "unknown", 0.80),
    ]

    # ==================== XSS检测模式 ====================

    XSS_REFLECTION_PATTERNS = [
        (r"<script[^>]*>.*?</script>", "script_tag", 0.95),
        (r"<script[^>]*>", "script_open", 0.85),
        (r"javascript:", "js_protocol", 0.80),
        (r"on\w+\s*=\s*['\"]", "event_handler", 0.75),
        (r"<img[^>]+onerror\s*=", "img_onerror", 0.90),
        (r"<svg[^>]+onload\s*=", "svg_onload", 0.90),
        (r"<body[^>]+onload\s*=", "body_onload", 0.85),
        (r"<iframe[^>]+src\s*=", "iframe_src", 0.70),
        (r"expression\s*\(", "css_expression", 0.75),
        (r"url\s*\(\s*['\"]?javascript:", "css_js", 0.80),
    ]

    # ==================== 命令注入检测模式 ====================

    COMMAND_INJECTION_PATTERNS = [
        # Linux
        (r"root:.*:0:0:", "linux_passwd", 0.95),
        (r"uid=\d+.*gid=\d+", "linux_id", 0.90),
        (r"Linux version \d+\.\d+", "linux_version", 0.85),
        (r"/bin/(ba)?sh", "linux_shell", 0.80),
        (r"drwx[-rwx]{9}", "linux_ls", 0.85),
        (r"total \d+\n", "linux_ls_total", 0.70),

        # Windows
        (r"Volume Serial Number is", "windows_vol", 0.90),
        (r"Directory of [A-Z]:\\", "windows_dir", 0.90),
        (r"Windows IP Configuration", "windows_ipconfig", 0.90),
        (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*Subnet Mask", "windows_ipconfig2", 0.85),
        (r"Microsoft Windows \[Version", "windows_version", 0.90),
        (r"The syntax of the command is incorrect", "windows_error", 0.70),

        # 通用
        (r"Command not found", "cmd_not_found", 0.65),
        (r"sh: \d+: .*: not found", "sh_error", 0.75),
        (r"bash: .*: command not found", "bash_error", 0.80),
    ]

    # ==================== 信息泄露检测模式 ====================

    INFO_DISCLOSURE_PATTERNS = [
        # 技术栈信息
        (r"PHP/[\d.]+", "php_version", 0.70),
        (r"Apache/[\d.]+", "apache_version", 0.70),
        (r"nginx/[\d.]+", "nginx_version", 0.70),
        (r"X-Powered-By:\s*(.+)", "powered_by", 0.65),

        # 调试信息
        (r"Stack trace:", "stack_trace", 0.85),
        (r"Traceback \(most recent call last\):", "python_traceback", 0.90),
        (r"at [\w.]+\([\w.]+:\d+\)", "java_stacktrace", 0.85),
        (r"File \"[^\"]+\", line \d+", "python_error", 0.80),

        # 文件路径
        (r"[A-Z]:\\[\w\\]+\.\w+", "windows_path", 0.75),
        (r"/var/www/[^\s<\"']+", "linux_path", 0.75),
        (r"/home/[\w]+/[^\s<\"']+", "home_path", 0.70),

        # 配置信息
        (r"DB_PASSWORD\s*[=:]\s*['\"]?[\w]+", "db_password", 0.95),
        (r"API[_-]?KEY\s*[=:]\s*['\"]?[\w-]+", "api_key", 0.90),
        (r"SECRET[_-]?KEY\s*[=:]\s*['\"]?[\w-]+", "secret_key", 0.90),
    ]

    # ==================== 敏感数据模式 ====================

    SENSITIVE_DATA_PATTERNS = [
        (r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "email", 0.80),
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone", 0.70),
        (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "credit_card", 0.85),
        (r"\b\d{3}-\d{2}-\d{4}\b", "ssn", 0.90),
        (r"\b[A-Za-z0-9+/]{40,}={0,2}\b", "base64", 0.60),
        (r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "jwt", 0.95),
        (r"\bghp_[A-Za-z0-9]{36}\b", "github_token", 0.95),
        (r"\bsk-[A-Za-z0-9]{48}\b", "stripe_key", 0.95),
        (r"\bAKIA[A-Z0-9]{16}\b", "aws_key", 0.95),
        (r"password['\"]?\s*[:=]\s*['\"]?[^'\"<>\s]+", "password", 0.85),
    ]

    # ==================== 技术指纹模式 ====================

    TECHNOLOGY_PATTERNS = {
        'server': [
            (r"Server:\s*([^\r\n]+)", None),
        ],
        'framework': [
            (r"X-Powered-By:\s*([^\r\n]+)", None),
            (r"X-AspNet-Version:\s*([^\r\n]+)", "ASP.NET"),
            (r"laravel_session", "Laravel"),
            (r"PHPSESSID", "PHP"),
            (r"JSESSIONID", "Java"),
            (r"rack\.session", "Ruby"),
            (r"connect\.sid", "Node.js/Express"),
            (r"_rails_session", "Ruby on Rails"),
            (r"csrftoken.*django", "Django"),
            (r"wp-content", "WordPress"),
            (r"Drupal", "Drupal"),
            (r"Joomla", "Joomla"),
        ],
        'cms': [
            (r"/wp-content/", "WordPress"),
            (r"/wp-includes/", "WordPress"),
            (r"Drupal\.settings", "Drupal"),
            (r"/sites/default/files/", "Drupal"),
            (r"/media/com_", "Joomla"),
            (r"/administrator/", "Joomla"),
        ],
        'waf': [
            (r"cloudflare", "Cloudflare"),
            (r"__cfduid", "Cloudflare"),
            (r"akamai", "Akamai"),
            (r"incapsula", "Incapsula"),
            (r"mod_security", "ModSecurity"),
            (r"X-Sucuri-ID", "Sucuri"),
            (r"X-WAF-", "Generic WAF"),
        ]
    }

    def __init__(self):
        """初始化响应分析器"""
        # 编译正则表达式以提高性能
        self._compiled_patterns = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """预编译正则表达式"""
        for pattern, db_type, confidence in self.SQL_ERROR_PATTERNS:
            self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)

        for pattern, match_type, confidence in self.XSS_REFLECTION_PATTERNS:
            self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE | re.DOTALL)

        for pattern, match_type, confidence in self.COMMAND_INJECTION_PATTERNS:
            self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)

    def analyze_for_sql_injection(
        self,
        response: HTTPResponse,
        payload_used: str = ""
    ) -> List[VulnerabilityIndicator]:
        """
        分析响应中的SQL注入指标

        Args:
            response: HTTP响应
            payload_used: 使用的payload

        Returns:
            List[VulnerabilityIndicator]: 发现的漏洞指标
        """
        indicators = []
        text = response.text

        for pattern, db_type, confidence in self.SQL_ERROR_PATTERNS:
            regex = self._compiled_patterns.get(pattern) or re.compile(pattern, re.IGNORECASE)
            match = regex.search(text)
            if match:
                indicators.append(VulnerabilityIndicator(
                    type="sql_injection_error",
                    confidence=confidence,
                    evidence=match.group(0)[:200],
                    location="body",
                    payload_used=payload_used,
                    database_type=db_type,
                    details={
                        'pattern_matched': pattern,
                        'full_match': match.group(0)
                    }
                ))

        return indicators

    def analyze_for_xss(
        self,
        response: HTTPResponse,
        payload_used: str = ""
    ) -> List[VulnerabilityIndicator]:
        """
        分析响应中的XSS指标

        Args:
            response: HTTP响应
            payload_used: 使用的payload

        Returns:
            List[VulnerabilityIndicator]: 发现的漏洞指标
        """
        indicators = []
        text = response.text

        # 检查payload是否被反射
        if payload_used and payload_used in text:
            # 检查是否被编码/转义
            escaped_payload = (
                payload_used
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
            )

            if payload_used in text and escaped_payload not in text:
                # 未转义反射
                indicators.append(VulnerabilityIndicator(
                    type="xss_reflected",
                    confidence=0.90,
                    evidence=f"Payload reflected without encoding: {payload_used[:100]}",
                    location="body",
                    payload_used=payload_used,
                    details={'reflection_type': 'unencoded'}
                ))

        # 检查XSS模式
        for pattern, match_type, confidence in self.XSS_REFLECTION_PATTERNS:
            regex = self._compiled_patterns.get(pattern) or re.compile(pattern, re.IGNORECASE | re.DOTALL)
            match = regex.search(text)
            if match:
                indicators.append(VulnerabilityIndicator(
                    type=f"xss_{match_type}",
                    confidence=confidence,
                    evidence=match.group(0)[:200],
                    location="body",
                    payload_used=payload_used,
                    details={
                        'pattern_matched': pattern,
                        'match_type': match_type
                    }
                ))

        return indicators

    def analyze_for_command_injection(
        self,
        response: HTTPResponse,
        payload_used: str = "",
        expected_output: str = ""
    ) -> List[VulnerabilityIndicator]:
        """
        分析响应中的命令注入指标

        Args:
            response: HTTP响应
            payload_used: 使用的payload
            expected_output: 预期输出

        Returns:
            List[VulnerabilityIndicator]: 发现的漏洞指标
        """
        indicators = []
        text = response.text

        # 检查预期输出
        if expected_output and expected_output in text:
            indicators.append(VulnerabilityIndicator(
                type="command_injection",
                confidence=0.95,
                evidence=f"Expected output found: {expected_output[:100]}",
                location="body",
                payload_used=payload_used,
                details={'expected_output': expected_output}
            ))

        # 检查命令注入模式
        for pattern, match_type, confidence in self.COMMAND_INJECTION_PATTERNS:
            regex = self._compiled_patterns.get(pattern) or re.compile(pattern, re.IGNORECASE)
            match = regex.search(text)
            if match:
                os_type = "linux" if "linux" in match_type or "sh" in match_type else "windows"
                indicators.append(VulnerabilityIndicator(
                    type="command_injection",
                    confidence=confidence,
                    evidence=match.group(0)[:200],
                    location="body",
                    payload_used=payload_used,
                    os_type=os_type,
                    details={
                        'pattern_matched': pattern,
                        'match_type': match_type
                    }
                ))

        return indicators

    def detect_blind_sql_injection(
        self,
        baseline: HTTPResponse,
        true_response: HTTPResponse,
        false_response: HTTPResponse
    ) -> BlindDetectionResult:
        """
        检测布尔盲注

        Args:
            baseline: 基线响应
            true_response: TRUE条件响应
            false_response: FALSE条件响应

        Returns:
            BlindDetectionResult: 检测结果
        """
        result = BlindDetectionResult(injection_type="boolean")

        # 计算内容差异
        true_text = true_response.text
        false_text = false_response.text

        matcher = SequenceMatcher(None, true_text, false_text)
        result.content_diff_ratio = 1.0 - matcher.ratio()

        # 如果TRUE和FALSE响应有显著差异，可能存在盲注
        if result.content_diff_ratio > 0.1:  # 超过10%差异
            # 验证TRUE响应与基线相似
            baseline_true_match = SequenceMatcher(None, baseline.text, true_text).ratio()
            baseline_false_match = SequenceMatcher(None, baseline.text, false_text).ratio()

            if baseline_true_match > baseline_false_match:
                result.detected = True
                result.confidence = min(result.content_diff_ratio * 2, 0.95)
                result.true_condition_response = true_response
                result.false_condition_response = false_response

        return result

    def detect_time_based_blind(
        self,
        baseline: HTTPResponse,
        delayed_response: HTTPResponse,
        delay_seconds: float = 5.0
    ) -> BlindDetectionResult:
        """
        检测时间盲注

        Args:
            baseline: 基线响应
            delayed_response: 延迟响应
            delay_seconds: 预期延迟时间

        Returns:
            BlindDetectionResult: 检测结果
        """
        result = BlindDetectionResult(injection_type="time")
        result.baseline_time_ms = baseline.elapsed_time
        result.delayed_time_ms = delayed_response.elapsed_time
        result.delay_threshold_ms = delay_seconds * 1000

        # 计算时间差
        time_diff = delayed_response.elapsed_time - baseline.elapsed_time

        # 如果延迟时间接近或超过预期延迟
        if time_diff >= (delay_seconds * 1000 * 0.8):  # 80%容差
            result.detected = True
            # 置信度基于实际延迟与预期延迟的比例
            ratio = time_diff / (delay_seconds * 1000)
            result.confidence = min(ratio * 0.8, 0.95)

        return result

    def analyze_information_disclosure(
        self,
        response: HTTPResponse
    ) -> List[VulnerabilityIndicator]:
        """
        分析信息泄露

        Args:
            response: HTTP响应

        Returns:
            List[VulnerabilityIndicator]: 发现的漏洞指标
        """
        indicators = []
        text = response.text
        headers = response.headers

        # 检查响应体
        for pattern, disclosure_type, confidence in self.INFO_DISCLOSURE_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                indicators.append(VulnerabilityIndicator(
                    type="information_disclosure",
                    confidence=confidence,
                    evidence=match.group(0)[:200],
                    location="body",
                    details={
                        'disclosure_type': disclosure_type,
                        'pattern': pattern
                    }
                ))

        # 检查响应头
        sensitive_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-Debug']
        for header in sensitive_headers:
            if header in headers:
                indicators.append(VulnerabilityIndicator(
                    type="information_disclosure",
                    confidence=0.60,
                    evidence=f"{header}: {headers[header]}",
                    location="header",
                    details={
                        'disclosure_type': 'header_disclosure',
                        'header_name': header
                    }
                ))

        return indicators

    def extract_sensitive_data(
        self,
        response: HTTPResponse
    ) -> List[SensitiveDataMatch]:
        """
        从响应中提取敏感数据

        Args:
            response: HTTP响应

        Returns:
            List[SensitiveDataMatch]: 发现的敏感数据
        """
        matches = []
        text = response.text

        for pattern, data_type, confidence in self.SENSITIVE_DATA_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                # 获取上下文
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                matches.append(SensitiveDataMatch(
                    data_type=data_type,
                    value=match.group(0),
                    location="body",
                    context=context,
                    confidence=confidence
                ))

        return matches

    def fingerprint_technology(
        self,
        response: HTTPResponse
    ) -> Dict[str, Any]:
        """
        识别目标技术栈

        Args:
            response: HTTP响应

        Returns:
            Dict: 技术指纹信息
        """
        fingerprint = {
            'server': '',
            'framework': '',
            'cms': '',
            'waf': '',
            'technologies': [],
            'headers': {}
        }

        text = response.text
        headers_str = '\n'.join(f"{k}: {v}" for k, v in response.headers.items())
        combined = headers_str + '\n' + text

        for category, patterns in self.TECHNOLOGY_PATTERNS.items():
            for item in patterns:
                pattern = item[0]
                tech_name = item[1] if len(item) > 1 else None

                match = re.search(pattern, combined, re.IGNORECASE)
                if match:
                    detected = tech_name or match.group(1) if match.groups() else match.group(0)
                    if category in ['server', 'framework', 'cms', 'waf']:
                        fingerprint[category] = detected
                    if detected not in fingerprint['technologies']:
                        fingerprint['technologies'].append(detected)

        # 提取重要headers
        important_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'Set-Cookie']
        for header in important_headers:
            if header in response.headers:
                fingerprint['headers'][header] = response.headers[header]

        return fingerprint

    def extract_endpoints(
        self,
        response: HTTPResponse
    ) -> List[str]:
        """
        从响应中提取端点

        Args:
            response: HTTP响应

        Returns:
            List[str]: 发现的端点列表
        """
        endpoints = set()
        text = response.text

        # URL模式
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']/(api|v\d+)/[^"\']+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                endpoint = match.group(1)
                # 过滤无效端点
                if endpoint and not endpoint.startswith(('javascript:', 'data:', '#', 'mailto:')):
                    # 标准化
                    if not endpoint.startswith(('http://', 'https://', '/')):
                        endpoint = '/' + endpoint
                    endpoints.add(endpoint)

        return list(endpoints)

    def extract_parameters(
        self,
        response: HTTPResponse
    ) -> List[str]:
        """
        从响应中提取参数名

        Args:
            response: HTTP响应

        Returns:
            List[str]: 发现的参数列表
        """
        parameters = set()
        text = response.text

        # 表单参数
        form_patterns = [
            r'name=["\']([^"\']+)["\']',
            r'id=["\']([^"\']+)["\']',
            r'for=["\']([^"\']+)["\']',
        ]

        for pattern in form_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                param = match.group(1)
                # 过滤常见非参数ID
                if param and not param.startswith(('_', 'js-', 'css-')):
                    parameters.add(param)

        # URL参数
        url_param_pattern = r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)='
        for match in re.finditer(url_param_pattern, text):
            parameters.add(match.group(1))

        # JSON键名
        json_key_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]*)":'
        for match in re.finditer(json_key_pattern, text):
            param = match.group(1)
            if len(param) > 2:
                parameters.add(param)

        return list(parameters)

    def infer_potential_vulnerabilities(
        self,
        profile: TargetProfile
    ) -> List[str]:
        """
        根据目标画像推断潜在漏洞

        Args:
            profile: 目标画像

        Returns:
            List[str]: 潜在漏洞类型列表
        """
        vulns = []

        # 基于技术栈推断
        tech_lower = [t.lower() for t in profile.technologies]

        if any('php' in t for t in tech_lower):
            vulns.extend(['sql_injection', 'lfi', 'rfi', 'deserialization'])

        if any('mysql' in t or 'postgresql' in t or 'oracle' in t for t in tech_lower):
            vulns.append('sql_injection')

        if any('wordpress' in t for t in tech_lower):
            vulns.extend(['sql_injection', 'xss', 'file_upload', 'authentication_bypass'])

        if any('drupal' in t for t in tech_lower):
            vulns.extend(['sql_injection', 'xss', 'deserialization'])

        if any('java' in t or 'tomcat' in t for t in tech_lower):
            vulns.extend(['deserialization', 'ssti', 'xxe'])

        if any('python' in t or 'django' in t or 'flask' in t for t in tech_lower):
            vulns.extend(['ssti', 'command_injection'])

        if any('node' in t or 'express' in t for t in tech_lower):
            vulns.extend(['ssti', 'prototype_pollution', 'ssrf'])

        # 基于参数推断
        for param in profile.parameters:
            param_lower = param.lower()
            if any(kw in param_lower for kw in ['id', 'user', 'uid', 'num', 'page']):
                if 'sql_injection' not in vulns:
                    vulns.append('sql_injection')
            if any(kw in param_lower for kw in ['file', 'path', 'dir', 'page', 'include']):
                if 'lfi' not in vulns:
                    vulns.append('lfi')
            if any(kw in param_lower for kw in ['url', 'link', 'redirect', 'next', 'return']):
                if 'ssrf' not in vulns:
                    vulns.append('ssrf')
                if 'open_redirect' not in vulns:
                    vulns.append('open_redirect')
            if any(kw in param_lower for kw in ['search', 'query', 'q', 'name', 'content']):
                if 'xss' not in vulns:
                    vulns.append('xss')
            if any(kw in param_lower for kw in ['cmd', 'exec', 'command', 'run', 'ping']):
                if 'command_injection' not in vulns:
                    vulns.append('command_injection')

        return list(set(vulns))

    def compare_responses(
        self,
        response1: HTTPResponse,
        response2: HTTPResponse
    ) -> ResponseDiff:
        """
        比较两个响应的差异

        Args:
            response1: 第一个响应
            response2: 第二个响应

        Returns:
            ResponseDiff: 差异分析结果
        """
        diff = ResponseDiff()

        # 状态码差异
        diff.status_changed = response1.status_code != response2.status_code
        diff.baseline_status = response1.status_code
        diff.test_status = response2.status_code

        # 时间差异
        diff.baseline_time_ms = response1.elapsed_time
        diff.test_time_ms = response2.elapsed_time
        diff.time_diff_ms = response2.elapsed_time - response1.elapsed_time

        # 内容差异
        matcher = SequenceMatcher(None, response1.text, response2.text)
        diff.content_diff_ratio = 1.0 - matcher.ratio()

        # Header差异
        all_headers = set(response1.headers.keys()) | set(response2.headers.keys())
        for header in all_headers:
            v1 = response1.headers.get(header)
            v2 = response2.headers.get(header)
            if v1 != v2:
                diff.header_diffs[header] = (v1, v2)

        # 判断是否可能存在漏洞
        if diff.status_changed:
            diff.indicates_vulnerability = True
            diff.diff_type = "status"
            diff.confidence = 0.70
        elif diff.time_diff_ms > 5000:  # 5秒以上延迟
            diff.indicates_vulnerability = True
            diff.diff_type = "timing"
            diff.confidence = min(diff.time_diff_ms / 10000, 0.90)
        elif diff.content_diff_ratio > 0.2:  # 20%以上差异
            diff.indicates_vulnerability = True
            diff.diff_type = "content"
            diff.confidence = min(diff.content_diff_ratio, 0.80)

        return diff
