"""
深度测试引擎 (Deep Test Engine) v2.0
=====================================

类Burp Suite的HTTP交互引擎，支持：
- 动态HTTP请求/响应交互
- WebSocket和gRPC协议
- 智能响应分析
- 自适应Payload测试
- 多步骤工作流
- 基于结果的学习优化

Author: Kali MCP Team
Version: 2.0.0
"""

from .models import (
    HTTPRequest,
    HTTPResponse,
    WSMessage,
    GRPCCall,
    VulnerabilityIndicator,
    TestResult,
    WorkflowStep,
    SessionState,
    TargetProfile,
    AttackVector
)

from .http_engine import HTTPInteractionEngine
from .response_analyzer import ResponseAnalyzer
from .dynamic_fuzzer import DynamicFuzzer

try:
    from .websocket_engine import WebSocketEngine
except Exception:
    WebSocketEngine = None

try:
    from .grpc_engine import GRPCEngine
except Exception:
    GRPCEngine = None

try:
    from .proxy_interceptor import ProxyInterceptor
except Exception:
    ProxyInterceptor = None

try:
    from .workflow_engine import WorkflowEngine
except Exception:
    WorkflowEngine = None

try:
    from .learning_engine import LearningEngine
except Exception:
    LearningEngine = None

# 延迟导入可选模块
def get_websocket_engine():
    from .websocket_engine import WebSocketEngine
    return WebSocketEngine

def get_grpc_engine():
    from .grpc_engine import GRPCEngine
    return GRPCEngine

def get_proxy_interceptor():
    from .proxy_interceptor import ProxyInterceptor
    return ProxyInterceptor

def get_workflow_engine():
    from .workflow_engine import WorkflowEngine
    return WorkflowEngine

def get_learning_engine():
    from .learning_engine import LearningEngine
    return LearningEngine


class DeepTestEngine:
    """
    深度测试引擎主类

    整合所有子模块，提供统一的测试接口
    """

    def __init__(self, proxy: str = None, timeout: float = 30.0):
        self.http = HTTPInteractionEngine(proxy=proxy, timeout=timeout)
        self.analyzer = ResponseAnalyzer()
        self.fuzzer = DynamicFuzzer(self.http, self.analyzer)

        # 可选模块延迟初始化
        self._ws_engine = None
        self._grpc_engine = None
        self._proxy = None
        self._workflow = None
        self._learner = None

    @property
    def websocket(self):
        if self._ws_engine is None:
            WSEngine = get_websocket_engine()
            self._ws_engine = WSEngine()
        return self._ws_engine

    @property
    def grpc(self):
        if self._grpc_engine is None:
            GRPCEngine = get_grpc_engine()
            self._grpc_engine = GRPCEngine()
        return self._grpc_engine

    @property
    def proxy(self):
        if self._proxy is None:
            Proxy = get_proxy_interceptor()
            self._proxy = Proxy()
        return self._proxy

    @property
    def workflow(self):
        if self._workflow is None:
            WF = get_workflow_engine()
            self._workflow = WF(self.http)
        return self._workflow

    @property
    def learner(self):
        if self._learner is None:
            LE = get_learning_engine()
            self._learner = LE()
        return self._learner

    async def analyze_target(self, target: str) -> TargetProfile:
        """
        智能目标分析

        Args:
            target: 目标URL或IP

        Returns:
            TargetProfile: 目标特征画像
        """
        from urllib.parse import urlparse

        # 解析目标
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            is_web = True
        else:
            parsed = None
            is_web = False

        profile = TargetProfile(
            target=target,
            is_web=is_web,
            technologies=[],
            endpoints=[],
            parameters=[],
            potential_vulns=[]
        )

        if is_web:
            # 发送探测请求
            try:
                response = await self.http.send_request(target)

                # 技术指纹识别
                tech_fp = self.analyzer.fingerprint_technology(response)
                profile.technologies = tech_fp.get('technologies', [])
                profile.server = tech_fp.get('server', '')
                profile.framework = tech_fp.get('framework', '')

                # 端点提取
                endpoints = self.analyzer.extract_endpoints(response)
                profile.endpoints = endpoints

                # 参数识别
                params = self.analyzer.extract_parameters(response)
                profile.parameters = params

                # 潜在漏洞推断
                vulns = self.analyzer.infer_potential_vulnerabilities(profile)
                profile.potential_vulns = vulns

            except Exception as e:
                profile.error = str(e)

        return profile

    async def execute_adaptive_attacks(self, profile: TargetProfile) -> list:
        """
        执行自适应攻击

        根据目标画像选择最佳攻击向量并执行
        """
        results = []

        for vuln_type in profile.potential_vulns:
            if vuln_type == 'sql_injection':
                for param in profile.parameters:
                    result = await self.fuzzer.adaptive_sql_injection(
                        profile.target, param
                    )
                    results.append(result)

            elif vuln_type == 'xss':
                for param in profile.parameters:
                    result = await self.fuzzer.adaptive_xss_test(
                        profile.target, param
                    )
                    results.append(result)

            elif vuln_type == 'command_injection':
                for param in profile.parameters:
                    result = await self.fuzzer.adaptive_command_injection(
                        profile.target, param
                    )
                    results.append(result)

        return results

    async def analyze_responses(self, attack_results: list) -> dict:
        """
        分析攻击结果
        """
        analysis = {
            'total_tests': len(attack_results),
            'vulnerabilities_found': [],
            'successful_attacks': [],
            'failed_attacks': [],
            'recommendations': []
        }

        for result in attack_results:
            if result.get('vulnerable'):
                analysis['vulnerabilities_found'].append({
                    'type': result.get('vulnerability_type'),
                    'parameter': result.get('parameter'),
                    'payload': result.get('poc_payload'),
                    'confidence': result.get('confidence', 0.0)
                })
                analysis['successful_attacks'].append(result)
            else:
                analysis['failed_attacks'].append(result)

        # 生成建议
        if analysis['vulnerabilities_found']:
            analysis['recommendations'].append(
                "发现漏洞，建议进一步验证并尝试数据提取"
            )
        else:
            analysis['recommendations'].append(
                "未发现明显漏洞，建议尝试更多攻击向量或深度测试"
            )

        return analysis


# 引擎可用性标志
ENGINES_AVAILABLE = {
    'http': True,
    'websocket': True,
    'grpc': True,
    'proxy': True,
    'workflow': True,
    'learning': True,
    'fuzzer': True,
    'analyzer': True
}

__all__ = [
    'DeepTestEngine',
    'HTTPInteractionEngine',
    'ResponseAnalyzer',
    'DynamicFuzzer',
    'WebSocketEngine',
    'GRPCEngine',
    'ProxyInterceptor',
    'WorkflowEngine',
    'LearningEngine',
    'HTTPRequest',
    'HTTPResponse',
    'WSMessage',
    'GRPCCall',
    'VulnerabilityIndicator',
    'TestResult',
    'WorkflowStep',
    'SessionState',
    'TargetProfile',
    'AttackVector',
    'ENGINES_AVAILABLE',
    'get_websocket_engine',
    'get_grpc_engine',
    'get_proxy_interceptor',
    'get_workflow_engine',
    'get_learning_engine'
]
