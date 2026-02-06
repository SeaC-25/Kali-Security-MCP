"""
HTTP交互引擎
============

类Burp Suite的HTTP交互引擎，支持：
- 发送自定义HTTP请求
- 完整响应捕获（包括原始数据）
- 请求历史管理
- 请求重放与修改
- 代理支持
- 原始请求发送（类似Burp Repeater）
"""

import aiohttp
import asyncio
import ssl
import socket
import time
import logging
from typing import Dict, List, Optional, Any, Tuple, Union
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from datetime import datetime
import uuid

from .models import HTTPRequest, HTTPResponse, SessionState

logger = logging.getLogger(__name__)


class HTTPInteractionEngine:
    """
    类Burp Suite的HTTP交互引擎

    功能：
    - 发送自定义HTTP请求
    - 捕获完整响应（包括headers、body、timing）
    - 请求历史管理和重放
    - 代理支持
    - 原始请求发送
    - Cookie和Session管理
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = False,
        max_history: int = 1000
    ):
        """
        初始化HTTP引擎

        Args:
            proxy: 代理服务器URL (e.g., "http://127.0.0.1:8080")
            timeout: 默认超时时间（秒）
            verify_ssl: 是否验证SSL证书
            max_history: 最大历史记录数
        """
        self.proxy = proxy
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_history = max_history

        # 请求/响应历史
        self.history: List[Tuple[HTTPRequest, HTTPResponse]] = []

        # 会话管理
        self.sessions: Dict[str, SessionState] = {}
        self.default_session_id: Optional[str] = None

        # 默认headers
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        }

        # 统计
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'total_time_ms': 0.0
        }

    async def send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[bytes, str, Dict]] = None,
        cookies: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
        capture_raw: bool = True,
        session_id: Optional[str] = None
    ) -> HTTPResponse:
        """
        发送HTTP请求，返回完整响应

        Args:
            url: 请求URL
            method: HTTP方法
            headers: 请求头
            body: 请求体（支持bytes、str、dict）
            cookies: Cookies
            follow_redirects: 是否跟随重定向
            timeout: 超时时间
            capture_raw: 是否捕获原始数据
            session_id: 会话ID（用于复用cookies/headers）

        Returns:
            HTTPResponse: 完整响应对象
        """
        # 创建请求对象
        request = HTTPRequest(
            url=url,
            method=method.upper(),
            headers={**self.default_headers, **(headers or {})},
            cookies=cookies or {},
            timeout=timeout or self.timeout,
            follow_redirects=follow_redirects
        )

        # 处理请求体
        if body is not None:
            if isinstance(body, dict):
                # JSON或表单数据
                if request.headers.get('Content-Type', '').startswith('application/json'):
                    import json
                    request.body = json.dumps(body).encode('utf-8')
                else:
                    request.body = urlencode(body).encode('utf-8')
                    if 'Content-Type' not in request.headers:
                        request.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            elif isinstance(body, str):
                request.body = body.encode('utf-8')
            else:
                request.body = body

        # 合并会话数据
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            # 合并cookies
            merged_cookies = {**session.cookies, **request.cookies}
            request.cookies = merged_cookies
            # 合并headers（会话headers优先级低）
            for k, v in session.headers.items():
                if k not in request.headers:
                    request.headers[k] = v

        # 发送请求
        start_time = time.time()
        response = HTTPResponse(request_id=request.id)

        try:
            # SSL上下文
            ssl_context = None
            if not self.verify_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            # aiohttp配置
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=100,
                ttl_dns_cache=300
            )

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    data=request.body,
                    cookies=request.cookies,
                    allow_redirects=request.follow_redirects,
                    timeout=aiohttp.ClientTimeout(total=request.timeout),
                    proxy=self.proxy
                ) as resp:
                    # 捕获响应
                    response.status_code = resp.status
                    response.headers = dict(resp.headers)
                    response.body = await resp.read()
                    response.cookies = {k: v.value for k, v in resp.cookies.items()}
                    response.content_type = resp.content_type or ""

                    # 捕获重定向信息
                    response.final_url = str(resp.url)
                    if resp.history:
                        response.redirect_count = len(resp.history)
                        response.redirect_history = [str(h.url) for h in resp.history]
                    else:
                        response.redirect_count = 0
                        response.redirect_history = []

                    # 计算时间
                    response.elapsed_time = (time.time() - start_time) * 1000

                    # 捕获原始响应
                    if capture_raw:
                        response.raw = self._build_raw_response(response)

            # 更新统计
            self.stats['total_requests'] += 1
            self.stats['successful_requests'] += 1
            self.stats['total_time_ms'] += response.elapsed_time

            # 捕获原始请求
            if capture_raw:
                request.raw = self._build_raw_request(request)

            # 保存历史
            self._add_to_history(request, response)

            # 更新会话
            if session_id and session_id in self.sessions:
                self.sessions[session_id].add_request(request)
                self.sessions[session_id].add_response(response)
                self.sessions[session_id].update_cookies(response.cookies)

            logger.debug(f"HTTP {request.method} {request.url} -> {response.status_code} ({response.elapsed_time:.2f}ms)")

        except asyncio.TimeoutError:
            response.status_code = 0
            response.headers = {'X-Error': 'Timeout'}
            response.body = b'Request timed out'
            response.elapsed_time = (time.time() - start_time) * 1000
            self.stats['failed_requests'] += 1
            logger.warning(f"Request timeout: {url}")

        except aiohttp.ClientError as e:
            response.status_code = 0
            response.headers = {'X-Error': str(type(e).__name__)}
            response.body = str(e).encode('utf-8')
            response.elapsed_time = (time.time() - start_time) * 1000
            self.stats['failed_requests'] += 1
            logger.warning(f"Request error: {url} - {e}")

        except Exception as e:
            response.status_code = 0
            response.headers = {'X-Error': 'Unknown'}
            response.body = str(e).encode('utf-8')
            response.elapsed_time = (time.time() - start_time) * 1000
            self.stats['failed_requests'] += 1
            logger.error(f"Unexpected error: {url} - {e}")

        return response

    async def replay_request(
        self,
        request_id: str,
        modifications: Optional[Dict[str, Any]] = None
    ) -> HTTPResponse:
        """
        重放历史请求，可选修改参数

        Args:
            request_id: 请求ID
            modifications: 修改项 {
                'url': '...',
                'method': '...',
                'headers': {...},
                'body': '...',
                'cookies': {...},
                'params': {...}  # URL参数
            }

        Returns:
            HTTPResponse: 重放的响应
        """
        # 查找原始请求
        original_request = None
        for req, _ in self.history:
            if req.id == request_id:
                original_request = req
                break

        if original_request is None:
            response = HTTPResponse()
            response.status_code = 0
            response.body = f"Request {request_id} not found in history".encode('utf-8')
            return response

        # 应用修改
        mods = modifications or {}

        url = mods.get('url', original_request.url)
        method = mods.get('method', original_request.method)
        headers = {**original_request.headers, **mods.get('headers', {})}
        body = mods.get('body', original_request.body)
        cookies = {**original_request.cookies, **mods.get('cookies', {})}

        # 修改URL参数
        if 'params' in mods:
            parsed = urlparse(url)
            existing_params = parse_qs(parsed.query)
            # 合并参数
            for k, v in mods['params'].items():
                existing_params[k] = [v] if isinstance(v, str) else v
            new_query = urlencode(existing_params, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))

        # 重放请求
        return await self.send_request(
            url=url,
            method=method,
            headers=headers,
            body=body,
            cookies=cookies
        )

    async def send_raw_request(
        self,
        raw_request: Union[bytes, str],
        host: str,
        port: int = 443,
        use_ssl: bool = True,
        timeout: Optional[float] = None
    ) -> HTTPResponse:
        """
        发送原始HTTP请求（类似Burp Repeater）

        Args:
            raw_request: 原始HTTP请求数据
            host: 目标主机
            port: 目标端口
            use_ssl: 是否使用SSL
            timeout: 超时时间

        Returns:
            HTTPResponse: 响应对象
        """
        if isinstance(raw_request, str):
            raw_request = raw_request.encode('utf-8')

        # 确保请求以\r\n\r\n结尾
        if not raw_request.endswith(b'\r\n\r\n'):
            if raw_request.endswith(b'\r\n'):
                raw_request += b'\r\n'
            else:
                raw_request += b'\r\n\r\n'

        response = HTTPResponse()
        start_time = time.time()

        try:
            # 创建连接
            if use_ssl:
                ssl_context = ssl.create_default_context()
                if not self.verify_ssl:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context),
                    timeout=timeout or self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout or self.timeout
                )

            # 发送请求
            writer.write(raw_request)
            await writer.drain()

            # 读取响应
            raw_response = b''
            try:
                while True:
                    chunk = await asyncio.wait_for(
                        reader.read(8192),
                        timeout=timeout or self.timeout
                    )
                    if not chunk:
                        break
                    raw_response += chunk
            except asyncio.TimeoutError:
                pass  # 读取超时，使用已读取的数据

            # 关闭连接
            writer.close()
            await writer.wait_closed()

            # 解析响应
            response = self._parse_raw_response(raw_response)
            response.raw = raw_response
            response.elapsed_time = (time.time() - start_time) * 1000

            self.stats['total_requests'] += 1
            self.stats['successful_requests'] += 1

        except Exception as e:
            response.status_code = 0
            response.body = str(e).encode('utf-8')
            response.elapsed_time = (time.time() - start_time) * 1000
            self.stats['failed_requests'] += 1

        return response

    def create_session(self, target: str, session_id: Optional[str] = None) -> str:
        """
        创建新的HTTP会话

        Args:
            target: 目标URL
            session_id: 自定义会话ID

        Returns:
            str: 会话ID
        """
        sid = session_id or str(uuid.uuid4())
        self.sessions[sid] = SessionState(id=sid, target=target)
        if self.default_session_id is None:
            self.default_session_id = sid
        return sid

    def get_session(self, session_id: str) -> Optional[SessionState]:
        """获取会话状态"""
        return self.sessions.get(session_id)

    def set_session_auth(
        self,
        session_id: str,
        auth_method: str,
        credentials: Dict[str, str]
    ):
        """
        设置会话认证

        Args:
            session_id: 会话ID
            auth_method: 认证方式 (basic, bearer, cookie)
            credentials: 凭据
        """
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]
        session.auth_method = auth_method
        session.auth_credentials = credentials
        session.authenticated = True

        # 设置认证header
        if auth_method == 'basic':
            import base64
            cred = base64.b64encode(
                f"{credentials['username']}:{credentials['password']}".encode()
            ).decode()
            session.headers['Authorization'] = f'Basic {cred}'
        elif auth_method == 'bearer':
            session.headers['Authorization'] = f'Bearer {credentials["token"]}'
        elif auth_method == 'cookie':
            session.cookies.update(credentials)

    def get_history(
        self,
        filter_url: Optional[str] = None,
        filter_method: Optional[str] = None,
        filter_status: Optional[int] = None,
        limit: int = 50
    ) -> List[Tuple[HTTPRequest, HTTPResponse]]:
        """
        获取请求历史

        Args:
            filter_url: URL过滤（包含匹配）
            filter_method: 方法过滤
            filter_status: 状态码过滤
            limit: 返回数量限制

        Returns:
            List[Tuple[HTTPRequest, HTTPResponse]]: 历史记录
        """
        results = []
        for req, resp in reversed(self.history):
            # 应用过滤
            if filter_url and filter_url not in req.url:
                continue
            if filter_method and req.method != filter_method.upper():
                continue
            if filter_status and resp.status_code != filter_status:
                continue

            results.append((req, resp))
            if len(results) >= limit:
                break

        return results

    def compare_responses(
        self,
        response1: HTTPResponse,
        response2: HTTPResponse
    ) -> Dict[str, Any]:
        """
        比较两个响应的差异

        Args:
            response1: 第一个响应
            response2: 第二个响应

        Returns:
            Dict: 差异分析结果
        """
        from difflib import SequenceMatcher

        diff = {
            'status_diff': response1.status_code != response2.status_code,
            'status_codes': (response1.status_code, response2.status_code),
            'time_diff_ms': abs(response1.elapsed_time - response2.elapsed_time),
            'size_diff': abs(len(response1.body) - len(response2.body)),
            'sizes': (len(response1.body), len(response2.body)),
            'header_diffs': {},
            'content_similarity': 0.0
        }

        # Header差异
        all_headers = set(response1.headers.keys()) | set(response2.headers.keys())
        for header in all_headers:
            v1 = response1.headers.get(header)
            v2 = response2.headers.get(header)
            if v1 != v2:
                diff['header_diffs'][header] = (v1, v2)

        # 内容相似度
        text1 = response1.text
        text2 = response2.text
        matcher = SequenceMatcher(None, text1, text2)
        diff['content_similarity'] = matcher.ratio()

        return diff

    def inject_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        injection_point: str = "url"
    ) -> Tuple[str, Optional[Dict], Optional[Dict]]:
        """
        在指定位置注入payload

        Args:
            url: 原始URL
            parameter: 参数名
            payload: 要注入的payload
            injection_point: 注入点 (url, body, header, cookie)

        Returns:
            Tuple[str, Dict, Dict]: (修改后的URL, body, headers)
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        modified_url = url
        body = None
        headers = None

        if injection_point == "url":
            # URL参数注入
            params[parameter] = [payload]
            new_query = urlencode(params, doseq=True)
            modified_url = urlunparse(parsed._replace(query=new_query))

        elif injection_point == "body":
            # POST body注入
            body = {parameter: payload}

        elif injection_point == "header":
            # Header注入
            headers = {parameter: payload}

        elif injection_point == "cookie":
            # Cookie注入 - 添加到URL以便后续处理
            # 实际cookies通过send_request的cookies参数传递
            pass

        return modified_url, body, headers

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        avg_time = (
            self.stats['total_time_ms'] / self.stats['total_requests']
            if self.stats['total_requests'] > 0 else 0
        )
        return {
            **self.stats,
            'average_time_ms': avg_time,
            'history_size': len(self.history),
            'active_sessions': len(self.sessions)
        }

    def clear_history(self):
        """清除历史记录"""
        self.history.clear()

    def _add_to_history(self, request: HTTPRequest, response: HTTPResponse):
        """添加到历史记录"""
        self.history.append((request, response))
        # 限制历史大小
        while len(self.history) > self.max_history:
            self.history.pop(0)

    def _build_raw_request(self, request: HTTPRequest) -> bytes:
        """构建原始请求数据"""
        parsed = urlparse(request.url)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        lines = [
            f"{request.method} {path} HTTP/1.1",
            f"Host: {parsed.netloc}"
        ]

        for key, value in request.headers.items():
            if key.lower() != 'host':
                lines.append(f"{key}: {value}")

        if request.cookies:
            cookie_str = '; '.join(f"{k}={v}" for k, v in request.cookies.items())
            lines.append(f"Cookie: {cookie_str}")

        if request.body:
            lines.append(f"Content-Length: {len(request.body)}")

        raw = '\r\n'.join(lines) + '\r\n\r\n'
        if request.body:
            return raw.encode('utf-8') + request.body
        return raw.encode('utf-8')

    def _build_raw_response(self, response: HTTPResponse) -> bytes:
        """构建原始响应数据"""
        lines = [f"HTTP/1.1 {response.status_code} OK"]

        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")

        raw = '\r\n'.join(lines) + '\r\n\r\n'
        return raw.encode('utf-8') + response.body

    def _parse_raw_response(self, raw: bytes) -> HTTPResponse:
        """解析原始响应数据"""
        response = HTTPResponse()

        try:
            # 分离header和body
            if b'\r\n\r\n' in raw:
                header_part, body = raw.split(b'\r\n\r\n', 1)
            else:
                header_part = raw
                body = b''

            response.body = body

            # 解析header
            lines = header_part.decode('utf-8', errors='replace').split('\r\n')

            # 状态行
            if lines:
                status_line = lines[0]
                parts = status_line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        response.status_code = int(parts[1])
                    except ValueError:
                        pass

            # Headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    response.headers[key.strip()] = value.strip()

            # Content-Type
            response.content_type = response.headers.get('Content-Type', '')

        except Exception as e:
            logger.warning(f"Failed to parse raw response: {e}")

        return response
