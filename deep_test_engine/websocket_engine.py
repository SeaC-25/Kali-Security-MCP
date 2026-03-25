"""
WebSocket交互引擎
=================

WebSocket协议交互支持：
- 连接管理
- 消息发送/接收
- 消息历史
- 模糊测试
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import uuid

try:
    import websockets
    try:
        from websockets.asyncio.client import ClientConnection as WebSocketClientProtocol
    except ImportError:
        from websockets.client import WebSocketClientProtocol  # type: ignore[no-redef]
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

from .models import WSMessage

logger = logging.getLogger(__name__)


class WebSocketEngine:
    """
    WebSocket交互引擎

    功能：
    - 建立/关闭WebSocket连接
    - 发送/接收消息
    - 消息历史管理
    - WebSocket模糊测试
    """

    def __init__(self, timeout: float = 30.0):
        """
        初始化WebSocket引擎

        Args:
            timeout: 默认超时时间
        """
        if not WEBSOCKETS_AVAILABLE:
            logger.warning("websockets库未安装，WebSocket功能不可用")

        self.timeout = timeout
        self.connections: Dict[str, WebSocketClientProtocol] = {}
        self.message_history: Dict[str, List[WSMessage]] = {}

        # 统计
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'messages_sent': 0,
            'messages_received': 0
        }

    async def connect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        subprotocols: Optional[List[str]] = None,
        ssl_context: Optional[Any] = None
    ) -> str:
        """
        建立WebSocket连接

        Args:
            url: WebSocket URL (ws:// 或 wss://)
            headers: 自定义头
            subprotocols: 子协议列表
            ssl_context: SSL上下文

        Returns:
            str: 连接ID
        """
        if not WEBSOCKETS_AVAILABLE:
            raise ImportError("websockets库未安装")

        connection_id = str(uuid.uuid4())

        try:
            # 创建连接
            extra_headers = headers or {}

            if url.startswith('wss://') and ssl_context is None:
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            ws = await asyncio.wait_for(
                websockets.connect(
                    url,
                    extra_headers=extra_headers,
                    subprotocols=subprotocols,
                    ssl=ssl_context if url.startswith('wss://') else None
                ),
                timeout=self.timeout
            )

            self.connections[connection_id] = ws
            self.message_history[connection_id] = []

            self.stats['total_connections'] += 1
            self.stats['active_connections'] += 1

            logger.info(f"[WS] 连接建立: {connection_id} -> {url}")

            return connection_id

        except Exception as e:
            logger.error(f"[WS] 连接失败: {url} - {e}")
            raise

    async def disconnect(self, connection_id: str):
        """
        关闭WebSocket连接

        Args:
            connection_id: 连接ID
        """
        if connection_id in self.connections:
            try:
                await self.connections[connection_id].close()
            except:
                pass
            del self.connections[connection_id]
            self.stats['active_connections'] -= 1
            logger.info(f"[WS] 连接关闭: {connection_id}")

    async def send_message(
        self,
        connection_id: str,
        message: Any,
        message_type: str = "text"
    ) -> WSMessage:
        """
        发送WebSocket消息

        Args:
            connection_id: 连接ID
            message: 消息内容
            message_type: 消息类型 (text/binary)

        Returns:
            WSMessage: 发送的消息对象
        """
        if connection_id not in self.connections:
            raise ValueError(f"连接不存在: {connection_id}")

        ws = self.connections[connection_id]

        # 转换消息格式
        if isinstance(message, dict):
            data = json.dumps(message).encode('utf-8')
        elif isinstance(message, str):
            data = message.encode('utf-8')
        else:
            data = message

        # 创建消息对象
        msg = WSMessage(
            connection_id=connection_id,
            direction="send",
            message_type=message_type,
            data=data
        )

        # 发送
        if message_type == "text":
            await ws.send(data.decode('utf-8'))
        else:
            await ws.send(data)

        # 记录历史
        self.message_history[connection_id].append(msg)
        self.stats['messages_sent'] += 1

        logger.debug(f"[WS] 发送消息: {connection_id} - {len(data)} bytes")

        return msg

    async def receive_message(
        self,
        connection_id: str,
        timeout: Optional[float] = None
    ) -> Optional[WSMessage]:
        """
        接收WebSocket消息

        Args:
            connection_id: 连接ID
            timeout: 超时时间

        Returns:
            WSMessage: 接收的消息对象
        """
        if connection_id not in self.connections:
            raise ValueError(f"连接不存在: {connection_id}")

        ws = self.connections[connection_id]

        try:
            raw = await asyncio.wait_for(
                ws.recv(),
                timeout=timeout or self.timeout
            )

            # 确定消息类型
            if isinstance(raw, bytes):
                data = raw
                msg_type = "binary"
            else:
                data = raw.encode('utf-8')
                msg_type = "text"

            # 创建消息对象
            msg = WSMessage(
                connection_id=connection_id,
                direction="receive",
                message_type=msg_type,
                data=data
            )

            # 记录历史
            self.message_history[connection_id].append(msg)
            self.stats['messages_received'] += 1

            logger.debug(f"[WS] 收到消息: {connection_id} - {len(data)} bytes")

            return msg

        except asyncio.TimeoutError:
            logger.debug(f"[WS] 接收超时: {connection_id}")
            return None

    async def send_and_receive(
        self,
        connection_id: str,
        message: Any,
        timeout: Optional[float] = None
    ) -> Optional[WSMessage]:
        """
        发送消息并等待响应

        Args:
            connection_id: 连接ID
            message: 消息内容
            timeout: 超时时间

        Returns:
            WSMessage: 响应消息
        """
        await self.send_message(connection_id, message)
        return await self.receive_message(connection_id, timeout)

    async def fuzz_websocket(
        self,
        connection_id: str,
        payloads: List[Any],
        analyze_responses: bool = True,
        delay_between: float = 0.1
    ) -> List[Dict[str, Any]]:
        """
        WebSocket模糊测试

        Args:
            connection_id: 连接ID
            payloads: Payload列表
            analyze_responses: 是否分析响应
            delay_between: 消息间延迟

        Returns:
            List[Dict]: 测试结果
        """
        results = []

        for payload in payloads:
            try:
                # 发送payload
                sent = await self.send_message(connection_id, payload)

                # 等待响应
                await asyncio.sleep(delay_between)
                received = await self.receive_message(connection_id, timeout=5.0)

                result = {
                    'payload': payload if isinstance(payload, str) else str(payload),
                    'sent': sent.to_dict(),
                    'received': received.to_dict() if received else None,
                    'success': received is not None
                }

                # 分析响应
                if analyze_responses and received:
                    result['analysis'] = self._analyze_ws_response(received, payload)

                results.append(result)

            except Exception as e:
                results.append({
                    'payload': payload if isinstance(payload, str) else str(payload),
                    'error': str(e),
                    'success': False
                })

        return results

    def _analyze_ws_response(
        self,
        response: WSMessage,
        payload: Any
    ) -> Dict[str, Any]:
        """分析WebSocket响应"""
        analysis = {
            'interesting': False,
            'indicators': []
        }

        text = response.text

        # 检查错误信息
        error_patterns = [
            (r'error', 'error_keyword'),
            (r'exception', 'exception_keyword'),
            (r'invalid', 'invalid_keyword'),
            (r'unauthorized', 'unauthorized'),
            (r'forbidden', 'forbidden'),
        ]

        import re
        for pattern, indicator in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                analysis['interesting'] = True
                analysis['indicators'].append(indicator)

        # 检查payload反射
        payload_str = payload if isinstance(payload, str) else str(payload)
        if payload_str in text:
            analysis['interesting'] = True
            analysis['indicators'].append('payload_reflected')

        return analysis

    def get_history(
        self,
        connection_id: str,
        limit: int = 50
    ) -> List[WSMessage]:
        """
        获取消息历史

        Args:
            connection_id: 连接ID
            limit: 返回数量限制

        Returns:
            List[WSMessage]: 消息历史
        """
        if connection_id not in self.message_history:
            return []

        return self.message_history[connection_id][-limit:]

    def get_all_connections(self) -> Dict[str, Dict]:
        """获取所有连接信息"""
        return {
            conn_id: {
                'active': conn_id in self.connections,
                'messages': len(self.message_history.get(conn_id, []))
            }
            for conn_id in set(list(self.connections.keys()) + list(self.message_history.keys()))
        }

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.stats.copy()

    async def close_all(self):
        """关闭所有连接"""
        for conn_id in list(self.connections.keys()):
            await self.disconnect(conn_id)
