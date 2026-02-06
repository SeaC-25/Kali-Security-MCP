"""
代理和流量拦截器
================

类似mitmproxy的流量拦截功能：
- HTTP/HTTPS代理服务器
- 请求/响应拦截
- 自动修改规则
- 流量记录和回放
"""

import asyncio
import logging
import ssl
import re
import json
from typing import Dict, List, Optional, Any, Callable, Tuple
from datetime import datetime
import uuid
from dataclasses import dataclass, field
import socket
import threading

from .models import HTTPRequest, HTTPResponse

logger = logging.getLogger(__name__)


@dataclass
class InterceptRule:
    """拦截规则"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    url_pattern: str = ""
    method: str = ""
    header_contains: Dict[str, str] = field(default_factory=dict)
    body_contains: str = ""
    enabled: bool = True
    action: str = "capture"  # capture, drop, modify


@dataclass
class ModifyRule:
    """修改规则"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    match_pattern: str = ""
    action: str = "replace"  # replace, add_header, remove_header, modify_body
    target: str = ""  # header name or body
    old_value: str = ""
    new_value: str = ""
    enabled: bool = True


@dataclass
class InterceptedRequest:
    """被拦截的请求"""
    id: str
    timestamp: datetime
    method: str
    url: str
    headers: Dict[str, str]
    body: bytes
    client_address: Tuple[str, int]
    forwarded: bool = False
    response: Optional['InterceptedResponse'] = None


@dataclass
class InterceptedResponse:
    """被拦截的响应"""
    status_code: int
    headers: Dict[str, str]
    body: bytes
    elapsed_time: float


class ProxyInterceptor:
    """
    HTTP/HTTPS代理拦截器

    功能：
    - 启动代理服务器
    - 拦截和记录流量
    - 自动修改请求/响应
    - 请求转发和回放
    """

    def __init__(self, listen_host: str = "127.0.0.1", listen_port: int = 8080):
        """
        初始化代理拦截器

        Args:
            listen_host: 监听地址
            listen_port: 监听端口
        """
        self.listen_host = listen_host
        self.listen_port = listen_port

        # 拦截规则
        self.intercept_rules: List[InterceptRule] = []
        self.modify_rules: List[ModifyRule] = []

        # 拦截的请求
        self.intercepted_requests: Dict[str, InterceptedRequest] = {}
        self.request_queue: asyncio.Queue = None

        # 代理服务器状态
        self.server = None
        self.running = False

        # 统计
        self.stats = {
            'total_requests': 0,
            'intercepted_requests': 0,
            'modified_requests': 0,
            'dropped_requests': 0
        }

        # 回调函数
        self.on_request_callback: Optional[Callable] = None
        self.on_response_callback: Optional[Callable] = None

    async def start(self) -> Dict[str, Any]:
        """
        启动代理服务器

        Returns:
            Dict: 启动结果
        """
        if self.running:
            return {
                "success": False,
                "error": "代理已在运行",
                "address": f"{self.listen_host}:{self.listen_port}"
            }

        try:
            self.request_queue = asyncio.Queue()

            # 创建代理服务器
            self.server = await asyncio.start_server(
                self._handle_client,
                self.listen_host,
                self.listen_port
            )

            self.running = True

            logger.info(f"[Proxy] 代理服务器启动: {self.listen_host}:{self.listen_port}")

            return {
                "success": True,
                "address": f"{self.listen_host}:{self.listen_port}",
                "message": "代理服务器已启动"
            }

        except Exception as e:
            logger.error(f"[Proxy] 启动失败: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def stop(self):
        """停止代理服务器"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False
            logger.info("[Proxy] 代理服务器已停止")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """处理客户端连接"""
        client_address = writer.get_extra_info('peername')

        try:
            # 读取请求行
            request_line = await reader.readline()
            if not request_line:
                return

            request_line = request_line.decode('utf-8', errors='replace').strip()
            parts = request_line.split(' ')

            if len(parts) < 3:
                return

            method, url, version = parts[0], parts[1], parts[2]

            # 读取请求头
            headers = {}
            while True:
                line = await reader.readline()
                if line in (b'\r\n', b'\n', b''):
                    break
                line = line.decode('utf-8', errors='replace').strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            # 读取请求体
            body = b''
            content_length = int(headers.get('Content-Length', 0))
            if content_length > 0:
                body = await reader.read(content_length)

            # 创建拦截记录
            request_id = str(uuid.uuid4())[:12]
            intercepted = InterceptedRequest(
                id=request_id,
                timestamp=datetime.now(),
                method=method,
                url=url,
                headers=headers,
                body=body,
                client_address=client_address
            )

            self.stats['total_requests'] += 1

            # 检查拦截规则
            action = self._check_intercept_rules(intercepted)

            if action == "drop":
                self.stats['dropped_requests'] += 1
                logger.debug(f"[Proxy] 请求被丢弃: {method} {url}")
                return

            if action == "capture":
                self.intercepted_requests[request_id] = intercepted
                self.stats['intercepted_requests'] += 1

                # 调用回调
                if self.on_request_callback:
                    await self.on_request_callback(intercepted)

            # 应用修改规则
            modified_request = self._apply_modify_rules(intercepted)
            if modified_request != intercepted:
                self.stats['modified_requests'] += 1

            # 处理CONNECT请求 (HTTPS隧道)
            if method == 'CONNECT':
                await self._handle_connect(reader, writer, url)
                return

            # 转发请求
            response = await self._forward_request(modified_request)

            if response:
                intercepted.response = response
                intercepted.forwarded = True

                # 发送响应给客户端
                await self._send_response(writer, response)

                # 调用响应回调
                if self.on_response_callback:
                    await self.on_response_callback(intercepted, response)

        except Exception as e:
            logger.error(f"[Proxy] 处理请求错误: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str
    ):
        """处理HTTPS CONNECT请求"""
        try:
            # 解析目标地址
            if ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 443

            # 连接目标服务器
            try:
                target_reader, target_writer = await asyncio.open_connection(host, port)
            except Exception as e:
                # 返回连接失败
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
                return

            # 返回连接成功
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            # 双向转发数据
            await asyncio.gather(
                self._pipe(reader, target_writer),
                self._pipe(target_reader, writer),
                return_exceptions=True
            )

        except Exception as e:
            logger.debug(f"[Proxy] CONNECT处理错误: {e}")

    async def _pipe(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """管道转发数据"""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except:
            pass
        finally:
            writer.close()

    async def _forward_request(
        self,
        request: InterceptedRequest
    ) -> Optional[InterceptedResponse]:
        """转发请求到目标服务器"""
        import time

        try:
            # 解析URL
            from urllib.parse import urlparse
            parsed = urlparse(request.url)

            host = parsed.hostname or request.headers.get('Host', '')
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query

            # 连接目标服务器
            use_ssl = parsed.scheme == 'https'

            if use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.open_connection(
                    host, port, ssl=ssl_context
                )
            else:
                reader, writer = await asyncio.open_connection(host, port)

            start_time = time.time()

            # 构建请求
            request_line = f"{request.method} {path} HTTP/1.1\r\n"
            headers = request.headers.copy()
            headers['Host'] = host

            request_data = request_line.encode()
            for key, value in headers.items():
                request_data += f"{key}: {value}\r\n".encode()
            request_data += b"\r\n"
            if request.body:
                request_data += request.body

            # 发送请求
            writer.write(request_data)
            await writer.drain()

            # 读取响应
            response_line = await reader.readline()
            if not response_line:
                return None

            response_line = response_line.decode('utf-8', errors='replace').strip()
            parts = response_line.split(' ', 2)
            status_code = int(parts[1]) if len(parts) > 1 else 0

            # 读取响应头
            response_headers = {}
            while True:
                line = await reader.readline()
                if line in (b'\r\n', b'\n', b''):
                    break
                line = line.decode('utf-8', errors='replace').strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    response_headers[key.strip()] = value.strip()

            # 读取响应体
            response_body = b''
            content_length = int(response_headers.get('Content-Length', 0))
            if content_length > 0:
                response_body = await reader.read(content_length)
            elif response_headers.get('Transfer-Encoding') == 'chunked':
                # 简化的chunked处理
                while True:
                    chunk_size_line = await reader.readline()
                    chunk_size = int(chunk_size_line.strip(), 16)
                    if chunk_size == 0:
                        break
                    chunk_data = await reader.read(chunk_size)
                    response_body += chunk_data
                    await reader.readline()  # CRLF

            elapsed_time = (time.time() - start_time) * 1000

            writer.close()

            return InterceptedResponse(
                status_code=status_code,
                headers=response_headers,
                body=response_body,
                elapsed_time=elapsed_time
            )

        except Exception as e:
            logger.error(f"[Proxy] 转发请求错误: {e}")
            return None

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        response: InterceptedResponse
    ):
        """发送响应给客户端"""
        try:
            # 响应行
            response_line = f"HTTP/1.1 {response.status_code} OK\r\n"
            writer.write(response_line.encode())

            # 响应头
            for key, value in response.headers.items():
                writer.write(f"{key}: {value}\r\n".encode())
            writer.write(b"\r\n")

            # 响应体
            if response.body:
                writer.write(response.body)

            await writer.drain()

        except Exception as e:
            logger.error(f"[Proxy] 发送响应错误: {e}")

    def _check_intercept_rules(self, request: InterceptedRequest) -> str:
        """
        检查拦截规则

        Returns:
            str: 动作 (capture, drop, forward)
        """
        for rule in self.intercept_rules:
            if not rule.enabled:
                continue

            # URL模式匹配
            if rule.url_pattern:
                if not re.search(rule.url_pattern, request.url, re.IGNORECASE):
                    continue

            # 方法匹配
            if rule.method and rule.method.upper() != request.method.upper():
                continue

            # 头部包含匹配
            if rule.header_contains:
                match = True
                for key, value in rule.header_contains.items():
                    if key not in request.headers or value not in request.headers[key]:
                        match = False
                        break
                if not match:
                    continue

            # 体内容匹配
            if rule.body_contains:
                body_str = request.body.decode('utf-8', errors='replace')
                if rule.body_contains not in body_str:
                    continue

            # 规则匹配，返回动作
            return rule.action

        return "forward"

    def _apply_modify_rules(
        self,
        request: InterceptedRequest
    ) -> InterceptedRequest:
        """应用修改规则"""
        modified = request

        for rule in self.modify_rules:
            if not rule.enabled:
                continue

            # URL匹配
            if rule.match_pattern:
                if not re.search(rule.match_pattern, request.url, re.IGNORECASE):
                    continue

            if rule.action == "add_header":
                modified.headers[rule.target] = rule.new_value

            elif rule.action == "remove_header":
                if rule.target in modified.headers:
                    del modified.headers[rule.target]

            elif rule.action == "replace":
                if rule.target == "body":
                    body_str = modified.body.decode('utf-8', errors='replace')
                    body_str = body_str.replace(rule.old_value, rule.new_value)
                    modified.body = body_str.encode()
                elif rule.target in modified.headers:
                    modified.headers[rule.target] = modified.headers[rule.target].replace(
                        rule.old_value, rule.new_value
                    )

        return modified

    def add_intercept_rule(
        self,
        url_pattern: str = "",
        method: str = "",
        header_contains: Dict[str, str] = None,
        body_contains: str = "",
        action: str = "capture",
        name: str = ""
    ) -> str:
        """
        添加拦截规则

        Returns:
            str: 规则ID
        """
        rule = InterceptRule(
            name=name or f"Rule_{len(self.intercept_rules) + 1}",
            url_pattern=url_pattern,
            method=method,
            header_contains=header_contains or {},
            body_contains=body_contains,
            action=action
        )

        self.intercept_rules.append(rule)
        logger.info(f"[Proxy] 添加拦截规则: {rule.name}")

        return rule.id

    def add_modify_rule(
        self,
        match_pattern: str,
        action: str,
        target: str,
        old_value: str = "",
        new_value: str = "",
        name: str = ""
    ) -> str:
        """
        添加修改规则

        Returns:
            str: 规则ID
        """
        rule = ModifyRule(
            name=name or f"ModifyRule_{len(self.modify_rules) + 1}",
            match_pattern=match_pattern,
            action=action,
            target=target,
            old_value=old_value,
            new_value=new_value
        )

        self.modify_rules.append(rule)
        logger.info(f"[Proxy] 添加修改规则: {rule.name}")

        return rule.id

    def remove_rule(self, rule_id: str) -> bool:
        """删除规则"""
        for i, rule in enumerate(self.intercept_rules):
            if rule.id == rule_id:
                del self.intercept_rules[i]
                return True

        for i, rule in enumerate(self.modify_rules):
            if rule.id == rule_id:
                del self.modify_rules[i]
                return True

        return False

    def get_intercepted_requests(
        self,
        filter_url: str = "",
        filter_method: str = "",
        limit: int = 50
    ) -> List[Dict]:
        """获取被拦截的请求"""
        results = []

        for req_id, req in list(self.intercepted_requests.items())[-limit:]:
            # 应用过滤
            if filter_url and filter_url not in req.url:
                continue
            if filter_method and filter_method.upper() != req.method.upper():
                continue

            result = {
                'id': req.id,
                'timestamp': req.timestamp.isoformat(),
                'method': req.method,
                'url': req.url,
                'headers': req.headers,
                'body_length': len(req.body),
                'forwarded': req.forwarded
            }

            if req.response:
                result['response'] = {
                    'status_code': req.response.status_code,
                    'headers': req.response.headers,
                    'body_length': len(req.response.body),
                    'elapsed_time': req.response.elapsed_time
                }

            results.append(result)

        return results

    def get_request_detail(self, request_id: str) -> Optional[Dict]:
        """获取请求详情"""
        req = self.intercepted_requests.get(request_id)
        if not req:
            return None

        result = {
            'id': req.id,
            'timestamp': req.timestamp.isoformat(),
            'method': req.method,
            'url': req.url,
            'headers': req.headers,
            'body': req.body.decode('utf-8', errors='replace'),
            'client_address': req.client_address,
            'forwarded': req.forwarded
        }

        if req.response:
            result['response'] = {
                'status_code': req.response.status_code,
                'headers': req.response.headers,
                'body': req.response.body.decode('utf-8', errors='replace'),
                'elapsed_time': req.response.elapsed_time
            }

        return result

    async def forward_modified(
        self,
        request_id: str,
        modifications: Dict[str, Any] = None
    ) -> Optional[Dict]:
        """
        修改后转发请求

        Args:
            request_id: 请求ID
            modifications: 修改内容

        Returns:
            Dict: 响应结果
        """
        req = self.intercepted_requests.get(request_id)
        if not req:
            return {"error": "请求不存在"}

        # 应用修改
        if modifications:
            if 'method' in modifications:
                req.method = modifications['method']
            if 'url' in modifications:
                req.url = modifications['url']
            if 'headers' in modifications:
                req.headers.update(modifications['headers'])
            if 'body' in modifications:
                req.body = modifications['body'].encode() if isinstance(modifications['body'], str) else modifications['body']

        # 转发
        response = await self._forward_request(req)

        if response:
            req.response = response
            req.forwarded = True

            return {
                'success': True,
                'status_code': response.status_code,
                'headers': response.headers,
                'body': response.body.decode('utf-8', errors='replace'),
                'elapsed_time': response.elapsed_time
            }

        return {"error": "转发失败"}

    def get_rules(self) -> Dict[str, List[Dict]]:
        """获取所有规则"""
        return {
            'intercept_rules': [
                {
                    'id': r.id,
                    'name': r.name,
                    'url_pattern': r.url_pattern,
                    'method': r.method,
                    'action': r.action,
                    'enabled': r.enabled
                }
                for r in self.intercept_rules
            ],
            'modify_rules': [
                {
                    'id': r.id,
                    'name': r.name,
                    'match_pattern': r.match_pattern,
                    'action': r.action,
                    'target': r.target,
                    'enabled': r.enabled
                }
                for r in self.modify_rules
            ]
        }

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            'running': self.running,
            'address': f"{self.listen_host}:{self.listen_port}",
            'intercept_rules_count': len(self.intercept_rules),
            'modify_rules_count': len(self.modify_rules),
            'captured_requests_count': len(self.intercepted_requests)
        }

    def clear_captured(self):
        """清除已捕获的请求"""
        self.intercepted_requests.clear()
        logger.info("[Proxy] 已清除捕获的请求")

    def export_requests(self, output_file: str, format: str = "json"):
        """
        导出捕获的请求

        Args:
            output_file: 输出文件路径
            format: 格式 (json, har)
        """
        if format == "json":
            requests = self.get_intercepted_requests(limit=10000)
            with open(output_file, 'w') as f:
                json.dump(requests, f, indent=2)

        elif format == "har":
            # HAR格式导出
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "Kali MCP Proxy", "version": "1.0"},
                    "entries": []
                }
            }

            for req_id, req in self.intercepted_requests.items():
                entry = {
                    "startedDateTime": req.timestamp.isoformat(),
                    "request": {
                        "method": req.method,
                        "url": req.url,
                        "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                        "bodySize": len(req.body)
                    }
                }

                if req.response:
                    entry["response"] = {
                        "status": req.response.status_code,
                        "headers": [{"name": k, "value": v} for k, v in req.response.headers.items()],
                        "bodySize": len(req.response.body)
                    }
                    entry["time"] = req.response.elapsed_time

                har["log"]["entries"].append(entry)

            with open(output_file, 'w') as f:
                json.dump(har, f, indent=2)

        logger.info(f"[Proxy] 导出请求到: {output_file}")
