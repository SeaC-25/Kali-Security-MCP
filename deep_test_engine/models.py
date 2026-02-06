"""
数据模型定义
============

定义深度测试引擎使用的所有数据结构
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
import uuid


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sql_injection"
    SQL_INJECTION_BLIND_BOOLEAN = "sql_injection_blind_boolean"
    SQL_INJECTION_BLIND_TIME = "sql_injection_blind_time"
    SQL_INJECTION_ERROR = "sql_injection_error"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    COMMAND_INJECTION = "command_injection"
    COMMAND_INJECTION_BLIND = "command_injection_blind"
    LFI = "lfi"
    RFI = "rfi"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    DESERIALIZATION = "deserialization"
    FILE_UPLOAD = "file_upload"
    IDOR = "idor"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    INFORMATION_DISCLOSURE = "information_disclosure"


class HTTPMethod(Enum):
    """HTTP方法枚举"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


class InjectionContext(Enum):
    """注入上下文"""
    URL_PARAMETER = "url_parameter"
    BODY_PARAMETER = "body_parameter"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    MULTIPART = "multipart"


@dataclass
class HTTPRequest:
    """完整的HTTP请求对象"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    raw: bytes = b""  # 原始请求数据

    # 额外元数据
    timeout: float = 30.0
    follow_redirects: bool = True
    verify_ssl: bool = False
    proxy: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'body': self.body.decode('utf-8', errors='replace') if self.body else None,
            'cookies': self.cookies,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class HTTPResponse:
    """完整的HTTP响应对象"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    cookies: Dict[str, str] = field(default_factory=dict)
    elapsed_time: float = 0.0  # 响应时间(ms)
    timestamp: datetime = field(default_factory=datetime.now)
    raw: bytes = b""  # 原始响应数据

    # 重定向相关
    final_url: str = ""  # 最终URL (跟随重定向后)
    redirect_count: int = 0  # 重定向次数
    redirect_history: List[str] = field(default_factory=list)  # 重定向历史

    # 解析后的内容
    content_type: str = ""
    encoding: str = "utf-8"

    @property
    def text(self) -> str:
        """获取响应文本"""
        try:
            return self.body.decode(self.encoding, errors='replace')
        except:
            return self.body.decode('utf-8', errors='replace')

    @property
    def content_length(self) -> int:
        return len(self.body)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'request_id': self.request_id,
            'status_code': self.status_code,
            'headers': self.headers,
            'body_length': len(self.body),
            'body_preview': self.text[:500] if self.body else None,
            'cookies': self.cookies,
            'elapsed_time': self.elapsed_time,
            'content_type': self.content_type,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class WSMessage:
    """WebSocket消息"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    connection_id: str = ""
    direction: str = "send"  # "send" or "receive"
    message_type: str = "text"  # "text" or "binary"
    data: bytes = b""
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def text(self) -> str:
        if self.message_type == "text":
            return self.data.decode('utf-8', errors='replace')
        return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'connection_id': self.connection_id,
            'direction': self.direction,
            'message_type': self.message_type,
            'data': self.text if self.message_type == "text" else f"<binary:{len(self.data)} bytes>",
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class GRPCCall:
    """gRPC调用记录"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host: str = ""
    port: int = 443
    service: str = ""
    method: str = ""
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    elapsed_time: float = 0.0
    status_code: int = 0
    status_message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'endpoint': f"{self.host}:{self.port}",
            'service': self.service,
            'method': self.method,
            'request_data': self.request_data,
            'response_data': self.response_data,
            'status': f"{self.status_code}: {self.status_message}",
            'elapsed_time': self.elapsed_time,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class VulnerabilityIndicator:
    """漏洞指标"""
    type: str  # VulnerabilityType value
    confidence: float = 0.0  # 0.0-1.0
    evidence: str = ""
    location: str = ""  # header, body, timing, behavior
    parameter: str = ""
    payload_used: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    # 额外信息
    database_type: Optional[str] = None  # for SQL injection
    os_type: Optional[str] = None  # for command injection
    extracted_data: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'location': self.location,
            'parameter': self.parameter,
            'payload_used': self.payload_used,
            'details': self.details,
            'database_type': self.database_type,
            'os_type': self.os_type,
            'extracted_data': self.extracted_data
        }


@dataclass
class TestResult:
    """测试结果"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    test_type: str = ""
    target: str = ""
    parameter: str = ""
    vulnerable: bool = False
    vulnerability_type: Optional[str] = None
    confidence: float = 0.0

    # 测试详情
    payloads_tested: int = 0
    successful_payload: Optional[str] = None
    baseline_response: Optional[HTTPResponse] = None
    vulnerable_response: Optional[HTTPResponse] = None

    # 提取的数据
    extracted_data: Optional[Any] = None

    # POC信息
    poc_request: Optional[HTTPRequest] = None
    poc_command: Optional[str] = None

    # 时间信息
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # 错误信息
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'test_type': self.test_type,
            'target': self.target,
            'parameter': self.parameter,
            'vulnerable': self.vulnerable,
            'vulnerability_type': self.vulnerability_type,
            'confidence': self.confidence,
            'payloads_tested': self.payloads_tested,
            'successful_payload': self.successful_payload,
            'extracted_data': self.extracted_data,
            'poc_command': self.poc_command,
            'error': self.error
        }


@dataclass
class WorkflowStep:
    """工作流步骤"""
    name: str
    action: str  # http_request, extract, assert, wait, conditional, etc.
    params: Dict[str, Any] = field(default_factory=dict)

    # 流程控制
    on_success: Optional[str] = None  # next step name
    on_failure: Optional[str] = None
    condition: Optional[str] = None  # 条件表达式

    # 变量提取
    extract_vars: Dict[str, str] = field(default_factory=dict)  # var_name -> extraction_pattern

    # 状态
    executed: bool = False
    result: Optional[Any] = None
    error: Optional[str] = None


@dataclass
class WorkflowDefinition:
    """工作流定义"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    author: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class SessionState:
    """会话状态"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""

    # 会话数据
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)  # CSRF tokens, JWT, etc.
    variables: Dict[str, Any] = field(default_factory=dict)

    # 认证状态
    authenticated: bool = False
    auth_method: Optional[str] = None  # basic, bearer, cookie, etc.
    auth_credentials: Optional[Dict[str, str]] = None

    # 历史记录
    request_history: List[HTTPRequest] = field(default_factory=list)
    response_history: List[HTTPResponse] = field(default_factory=list)

    # 发现的信息
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_parameters: List[Dict[str, str]] = field(default_factory=list)
    discovered_vulnerabilities: List[VulnerabilityIndicator] = field(default_factory=list)

    # 时间戳
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)

    def add_request(self, request: HTTPRequest):
        self.request_history.append(request)
        self.last_activity = datetime.now()

    def add_response(self, response: HTTPResponse):
        self.response_history.append(response)
        self.last_activity = datetime.now()

    def update_cookies(self, cookies: Dict[str, str]):
        self.cookies.update(cookies)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'target': self.target,
            'authenticated': self.authenticated,
            'cookies_count': len(self.cookies),
            'tokens_count': len(self.tokens),
            'requests_count': len(self.request_history),
            'discovered_endpoints': len(self.discovered_endpoints),
            'discovered_vulns': len(self.discovered_vulnerabilities),
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat()
        }


@dataclass
class TargetProfile:
    """目标特征画像"""
    target: str = ""
    is_web: bool = False

    # 技术栈
    technologies: List[str] = field(default_factory=list)
    server: str = ""
    framework: str = ""
    language: str = ""
    database: str = ""
    cms: str = ""
    waf: str = ""

    # 端点和参数
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)

    # 安全特征
    has_csrf_protection: bool = False
    has_rate_limiting: bool = False
    has_waf: bool = False
    security_headers: Dict[str, str] = field(default_factory=dict)

    # 潜在漏洞
    potential_vulns: List[str] = field(default_factory=list)

    # 额外信息
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)

    # 错误信息
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'is_web': self.is_web,
            'technologies': self.technologies,
            'server': self.server,
            'framework': self.framework,
            'endpoints_count': len(self.endpoints),
            'parameters_count': len(self.parameters),
            'potential_vulns': self.potential_vulns,
            'has_waf': self.has_waf,
            'waf': self.waf
        }


@dataclass
class AttackVector:
    """攻击向量"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    vulnerability_type: str = ""
    target_parameter: str = ""
    injection_context: str = ""  # InjectionContext value

    # Payload信息
    payloads: List[str] = field(default_factory=list)
    current_payload_index: int = 0

    # 执行状态
    status: str = "pending"  # pending, running, success, failed
    attempts: int = 0
    max_attempts: int = 100

    # 结果
    successful_payload: Optional[str] = None
    vulnerability_confirmed: bool = False
    extracted_data: Optional[Any] = None

    # 优先级和评分
    priority: int = 5  # 1-10, 10最高
    success_probability: float = 0.5

    def get_next_payload(self) -> Optional[str]:
        if self.current_payload_index < len(self.payloads):
            payload = self.payloads[self.current_payload_index]
            self.current_payload_index += 1
            self.attempts += 1
            return payload
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'vulnerability_type': self.vulnerability_type,
            'target_parameter': self.target_parameter,
            'status': self.status,
            'attempts': self.attempts,
            'vulnerability_confirmed': self.vulnerability_confirmed,
            'priority': self.priority,
            'success_probability': self.success_probability
        }


@dataclass
class ResponseDiff:
    """响应差异分析结果"""
    indicates_vulnerability: bool = False
    diff_type: str = ""  # content, timing, status, header

    # 内容差异
    content_diff_ratio: float = 0.0
    added_content: List[str] = field(default_factory=list)
    removed_content: List[str] = field(default_factory=list)

    # 时间差异
    time_diff_ms: float = 0.0
    baseline_time_ms: float = 0.0
    test_time_ms: float = 0.0

    # 状态差异
    status_changed: bool = False
    baseline_status: int = 0
    test_status: int = 0

    # Header差异
    header_diffs: Dict[str, tuple] = field(default_factory=dict)  # header_name -> (baseline, test)

    # 置信度
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'indicates_vulnerability': self.indicates_vulnerability,
            'diff_type': self.diff_type,
            'content_diff_ratio': self.content_diff_ratio,
            'time_diff_ms': self.time_diff_ms,
            'status_changed': self.status_changed,
            'confidence': self.confidence
        }


@dataclass
class BlindDetectionResult:
    """盲注检测结果"""
    detected: bool = False
    injection_type: str = ""  # boolean, time

    # Boolean盲注
    true_condition_response: Optional[HTTPResponse] = None
    false_condition_response: Optional[HTTPResponse] = None
    content_diff_ratio: float = 0.0

    # Time盲注
    baseline_time_ms: float = 0.0
    delayed_time_ms: float = 0.0
    delay_threshold_ms: float = 5000.0

    # 通用
    confidence: float = 0.0
    payload_used: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'detected': self.detected,
            'injection_type': self.injection_type,
            'content_diff_ratio': self.content_diff_ratio,
            'time_diff_ms': self.delayed_time_ms - self.baseline_time_ms if self.injection_type == "time" else 0,
            'confidence': self.confidence,
            'payload_used': self.payload_used
        }


@dataclass
class SensitiveDataMatch:
    """敏感数据匹配"""
    data_type: str = ""  # email, phone, credit_card, ssn, api_key, password, token, etc.
    value: str = ""
    location: str = ""  # body, header, url
    line_number: int = 0
    context: str = ""  # 周围的文本
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        # 对敏感数据进行脱敏处理
        masked_value = self.value[:3] + "***" + self.value[-3:] if len(self.value) > 6 else "***"
        return {
            'data_type': self.data_type,
            'value_masked': masked_value,
            'location': self.location,
            'confidence': self.confidence
        }
