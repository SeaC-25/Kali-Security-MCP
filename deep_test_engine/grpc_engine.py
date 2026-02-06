"""
gRPC交互引擎
============

gRPC协议交互支持：
- 服务反射
- 方法调用
- 流式通信
- 模糊测试
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
import json

try:
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

from .models import GRPCCall

logger = logging.getLogger(__name__)


class GRPCEngine:
    """
    gRPC交互引擎

    功能：
    - 服务反射（获取服务定义）
    - 方法调用
    - 模糊测试
    """

    def __init__(self, timeout: float = 30.0):
        """
        初始化gRPC引擎

        Args:
            timeout: 默认超时时间
        """
        if not GRPC_AVAILABLE:
            logger.warning("grpc库未安装，gRPC功能不可用")

        self.timeout = timeout
        self.channels: Dict[str, grpc.Channel] = {}
        self.call_history: List[GRPCCall] = []

        # 统计
        self.stats = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0
        }

    async def connect(
        self,
        host: str,
        port: int,
        use_ssl: bool = False,
        credentials: Optional[Any] = None
    ) -> str:
        """
        创建gRPC连接

        Args:
            host: 主机名
            port: 端口
            use_ssl: 是否使用SSL
            credentials: SSL凭据

        Returns:
            str: 连接ID
        """
        if not GRPC_AVAILABLE:
            raise ImportError("grpc库未安装")

        connection_id = f"{host}:{port}"

        if connection_id in self.channels:
            return connection_id

        target = f"{host}:{port}"

        if use_ssl:
            if credentials is None:
                credentials = grpc.ssl_channel_credentials()
            channel = grpc.aio.secure_channel(target, credentials)
        else:
            channel = grpc.aio.insecure_channel(target)

        self.channels[connection_id] = channel
        logger.info(f"[gRPC] 连接创建: {connection_id}")

        return connection_id

    async def reflect_services(
        self,
        host: str,
        port: int,
        use_ssl: bool = False
    ) -> Dict[str, Any]:
        """
        通过反射获取服务定义

        Args:
            host: 主机名
            port: 端口
            use_ssl: 是否使用SSL

        Returns:
            Dict: 服务定义信息
        """
        if not GRPC_AVAILABLE:
            return {"error": "grpc库未安装"}

        result = {
            'services': [],
            'methods': {},
            'success': False,
            'error': None
        }

        try:
            connection_id = await self.connect(host, port, use_ssl)
            channel = self.channels[connection_id]

            # 使用反射服务
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            # 列出服务
            request = reflection_pb2.ServerReflectionRequest(
                list_services=""
            )

            async def get_services():
                responses = []
                async for response in stub.ServerReflectionInfo(iter([request])):
                    responses.append(response)
                return responses

            responses = await asyncio.wait_for(get_services(), timeout=self.timeout)

            for response in responses:
                if response.HasField('list_services_response'):
                    for service in response.list_services_response.service:
                        service_name = service.name
                        result['services'].append(service_name)

                        # 获取服务的方法
                        result['methods'][service_name] = await self._get_service_methods(
                            stub, service_name
                        )

            result['success'] = True
            logger.info(f"[gRPC] 反射成功，发现 {len(result['services'])} 个服务")

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"[gRPC] 反射失败: {e}")

        return result

    async def _get_service_methods(
        self,
        stub,
        service_name: str
    ) -> List[Dict[str, str]]:
        """获取服务的方法列表"""
        methods = []

        try:
            request = reflection_pb2.ServerReflectionRequest(
                file_containing_symbol=service_name
            )

            async def get_file_descriptor():
                responses = []
                async for response in stub.ServerReflectionInfo(iter([request])):
                    responses.append(response)
                return responses

            responses = await asyncio.wait_for(get_file_descriptor(), timeout=10)

            for response in responses:
                if response.HasField('file_descriptor_response'):
                    for fd_bytes in response.file_descriptor_response.file_descriptor_proto:
                        # 解析文件描述符
                        from google.protobuf import descriptor_pb2
                        fd = descriptor_pb2.FileDescriptorProto()
                        fd.ParseFromString(fd_bytes)

                        for service in fd.service:
                            if service.name in service_name or service_name.endswith(service.name):
                                for method in service.method:
                                    methods.append({
                                        'name': method.name,
                                        'input_type': method.input_type,
                                        'output_type': method.output_type,
                                        'client_streaming': method.client_streaming,
                                        'server_streaming': method.server_streaming
                                    })

        except Exception as e:
            logger.debug(f"获取方法失败: {service_name} - {e}")

        return methods

    async def call_method(
        self,
        host: str,
        port: int,
        service: str,
        method: str,
        request_data: Dict[str, Any],
        use_ssl: bool = False,
        metadata: Optional[List[tuple]] = None
    ) -> GRPCCall:
        """
        调用gRPC方法

        Args:
            host: 主机名
            port: 端口
            service: 服务名
            method: 方法名
            request_data: 请求数据
            use_ssl: 是否使用SSL
            metadata: 元数据

        Returns:
            GRPCCall: 调用记录
        """
        call = GRPCCall(
            host=host,
            port=port,
            service=service,
            method=method,
            request_data=request_data,
            metadata=dict(metadata) if metadata else {}
        )

        if not GRPC_AVAILABLE:
            call.status_code = -1
            call.status_message = "grpc库未安装"
            return call

        import time
        start_time = time.time()

        try:
            connection_id = await self.connect(host, port, use_ssl)
            channel = self.channels[connection_id]

            # 构建完整方法路径
            full_method = f"/{service}/{method}"

            # 序列化请求
            request_bytes = json.dumps(request_data).encode('utf-8')

            # 创建通用调用
            response = await asyncio.wait_for(
                channel.unary_unary(
                    full_method,
                    request_serializer=lambda x: x,
                    response_deserializer=lambda x: x
                )(request_bytes, metadata=metadata),
                timeout=self.timeout
            )

            call.response_data = {'raw': response.decode('utf-8', errors='replace')}
            call.status_code = 0
            call.status_message = "OK"
            self.stats['successful_calls'] += 1

        except grpc.RpcError as e:
            call.status_code = e.code().value[0]
            call.status_message = e.details()
            self.stats['failed_calls'] += 1

        except Exception as e:
            call.status_code = -1
            call.status_message = str(e)
            self.stats['failed_calls'] += 1

        call.elapsed_time = (time.time() - start_time) * 1000
        self.stats['total_calls'] += 1
        self.call_history.append(call)

        return call

    async def fuzz_grpc(
        self,
        host: str,
        port: int,
        service: str,
        method: str,
        payloads: List[Dict[str, Any]],
        use_ssl: bool = False
    ) -> List[Dict[str, Any]]:
        """
        gRPC模糊测试

        Args:
            host: 主机名
            port: 端口
            service: 服务名
            method: 方法名
            payloads: Payload列表
            use_ssl: 是否使用SSL

        Returns:
            List[Dict]: 测试结果
        """
        results = []

        for payload in payloads:
            call = await self.call_method(
                host, port, service, method, payload, use_ssl
            )

            result = {
                'payload': payload,
                'status_code': call.status_code,
                'status_message': call.status_message,
                'response': call.response_data,
                'elapsed_time': call.elapsed_time,
                'success': call.status_code == 0
            }

            # 分析响应
            if call.response_data:
                result['analysis'] = self._analyze_grpc_response(call)

            results.append(result)

        return results

    def _analyze_grpc_response(self, call: GRPCCall) -> Dict[str, Any]:
        """分析gRPC响应"""
        analysis = {
            'interesting': False,
            'indicators': []
        }

        # 检查错误状态
        if call.status_code != 0:
            analysis['interesting'] = True
            analysis['indicators'].append(f'error_code_{call.status_code}')

        # 检查响应内容
        response_str = str(call.response_data)
        import re

        error_patterns = [
            (r'exception', 'exception'),
            (r'error', 'error'),
            (r'unauthorized', 'unauthorized'),
            (r'permission', 'permission_issue'),
            (r'denied', 'access_denied'),
        ]

        for pattern, indicator in error_patterns:
            if re.search(pattern, response_str, re.IGNORECASE):
                analysis['interesting'] = True
                analysis['indicators'].append(indicator)

        return analysis

    def get_history(self, limit: int = 50) -> List[GRPCCall]:
        """获取调用历史"""
        return self.call_history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.stats.copy()

    async def close_all(self):
        """关闭所有连接"""
        for connection_id, channel in list(self.channels.items()):
            try:
                await channel.close()
            except:
                pass
        self.channels.clear()
