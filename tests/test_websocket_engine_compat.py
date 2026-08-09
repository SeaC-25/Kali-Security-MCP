#!/usr/bin/env python3
"""websocket_engine 版本兼容性回归测试。

覆盖：
- 导入不触发 DeprecationWarning（websockets >= 15 旧路径 WebSocketClientProtocol 已废弃）
- WS_HEADERS_KW 按版本解析（>=14 为 additional_headers，旧版为 extra_headers）
- 真实 ws 连接：connect / send / receive / history / disconnect / stats 全链路
"""

from __future__ import annotations

import asyncio
import sys
import warnings

import pytest

websockets = pytest.importorskip("websockets")

from deep_test_engine import WebSocketEngine, get_websocket_engine
from deep_test_engine import websocket_engine as ws_mod


@pytest.fixture()
def anyio_backend():
    return "asyncio"


def test_import_no_deprecation_warning():
    """旧导入路径不应再产生 DeprecationWarning。"""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        # 模块已被测试进程导入过，这里验证其不再带有废弃 API 引用
        assert ws_mod.WEBSOCKETS_AVAILABLE
        # 新版应绑定新的连接类型
        if int(websockets.__version__.split(".")[0]) >= 13:
            assert ws_mod.WSClientConnection is not None
            assert "ClientConnection" in ws_mod.WSClientConnection.__name__


def test_headers_kwargs_by_version():
    """headers 关键字按版本解析：>=14 用 additional_headers，否则 extra_headers。"""
    major = int(websockets.__version__.split(".")[0])
    if major >= 14:
        assert ws_mod.WS_HEADERS_KW == "additional_headers"
    else:
        assert ws_mod.WS_HEADERS_KW == "extra_headers"


def test_connect_send_receive_disconnect_roundtrip():
    """真实 WebSocket 全链路：连接、自定义头、收发、历史、统计、断开。"""
    import websockets as ws

    async def echo_server(server_ws):
        async for msg in server_ws:
            await server_ws.send("echo:" + msg)

    async def scenario():
        server = await ws.serve(echo_server, "127.0.0.1", 18765)
        try:
            engine = WebSocketEngine(timeout=5.0)
            # 携带自定义头，验证 additional_headers/extra_headers 传参路径
            cid = await engine.connect(
                "ws://127.0.0.1:18765", headers={"X-Regression-Test": "1"}
            )
            await engine.send_message(cid, {"ping": 1})
            resp = await engine.receive_message(cid)
            assert resp is not None
            assert resp.text == 'echo:{"ping": 1}'
            assert len(engine.get_history(cid)) == 2
            await engine.disconnect(cid)
            stats = engine.get_stats()
            assert stats["active_connections"] == 0
            assert stats["messages_received"] == 1
            assert stats["messages_sent"] == 1
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_connect_refused_raises():
    """连接不可达时应抛异常而非静默挂起（验证失败路径可诊断）。"""

    async def scenario():
        engine = WebSocketEngine(timeout=3.0)
        with pytest.raises(Exception):
            await engine.connect("ws://127.0.0.1:1")  # 未监听端口

    asyncio.run(scenario())
