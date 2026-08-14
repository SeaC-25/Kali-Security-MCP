"""search_backends 单元测试（架构设计 §8 决策七）。

覆盖：
- WebSearchBackend 接口形状：search/fetch 返回结构化 dict，永不抛异常
- 异常兜底：_do_* 抛异常 → 空结果 + 错误信息（LLM 循环不崩溃）
- 后端选择：WEB_SEARCH_BACKEND=ddg|tavily，默认 ddg，未知值回退 ddg
- DuckDuckGo 字段映射 / Tavily 缺 key 降级
- clean_html_text 清洗逻辑
- ToolBridge 集成：web_search/web_fetch 进入注册表与 catalog，走标准 call_tool 路径
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from kali_mcp.core.search_backends import (
    DuckDuckGoBackend,
    MAX_FETCH_CHARS,
    TavilyBackend,
    WebSearchBackend,
    clean_html_text,
    get_search_backend,
)


class FakeBackend(WebSearchBackend):
    """可控的后端桩：可注入结果或让 _do_* 抛异常。"""

    name = "fake"

    def __init__(self, results: List[Dict[str, Any]] | None = None,
                 text: str = "", search_error: Exception | None = None,
                 fetch_error: Exception | None = None):
        self.results = results or []
        self.text = text
        self.search_error = search_error
        self.fetch_error = fetch_error

    def _do_search(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        if self.search_error:
            raise self.search_error
        return self.results

    def _do_fetch(self, url: str) -> str:
        if self.fetch_error:
            raise self.fetch_error
        return self.text


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 接口形状
# ---------------------------------------------------------------------------

class TestBackendInterface:
    def test_search_returns_structured_dict(self):
        backend = FakeBackend(results=[{"title": "t", "url": "u", "snippet": "s"}])
        data = backend.search("CVE-2024-27348", max_results=5)
        assert data["error"] is None
        assert data["results"] == [{"title": "t", "url": "u", "snippet": "s"}]

    def test_fetch_returns_structured_dict(self):
        backend = FakeBackend(text="hello world")
        data = backend.fetch("http://example.com")
        assert data["error"] is None
        assert data["text"] == "hello world"

    def test_abstract_base_cannot_instantiate(self):
        with pytest.raises(TypeError):
            WebSearchBackend()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# 异常兜底（LLM 循环安全）
# ---------------------------------------------------------------------------

class TestExceptionFallback:
    def test_search_exception_returns_empty_results_with_error(self):
        backend = FakeBackend(search_error=RuntimeError("network down"))
        data = backend.search("query")
        assert data["results"] == []
        assert isinstance(data["error"], str)
        assert "network down" in data["error"]

    def test_fetch_exception_returns_empty_text_with_error(self):
        backend = FakeBackend(fetch_error=RuntimeError("timeout"))
        data = backend.fetch("http://example.com")
        assert data["text"] == ""
        assert isinstance(data["error"], str)
        assert "timeout" in data["error"]

    def test_search_never_raises_on_failure(self):
        """任何异常都被吞掉，绝不向上抛（搜索不能打断 LLM 决策循环）。"""
        backend = FakeBackend(search_error=Exception("boom"))
        for _ in range(3):
            data = backend.search("query")
            assert data["results"] == []

    def test_fetch_never_raises_on_failure(self):
        backend = FakeBackend(fetch_error=Exception("boom"))
        for _ in range(3):
            data = backend.fetch("http://example.com")
            assert data["text"] == ""


# ---------------------------------------------------------------------------
# 后端选择
# ---------------------------------------------------------------------------

class TestBackendSelection:
    def test_default_is_ddg(self, monkeypatch):
        monkeypatch.delenv("WEB_SEARCH_BACKEND", raising=False)
        assert isinstance(get_search_backend(), DuckDuckGoBackend)

    def test_tavily_when_env_set(self, monkeypatch):
        monkeypatch.setenv("WEB_SEARCH_BACKEND", "tavily")
        assert isinstance(get_search_backend(), TavilyBackend)

    def test_unknown_env_falls_back_to_ddg(self, monkeypatch):
        monkeypatch.setenv("WEB_SEARCH_BACKEND", "weird-backend")
        assert isinstance(get_search_backend(), DuckDuckGoBackend)

    def test_env_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("WEB_SEARCH_BACKEND", "DDG")
        assert isinstance(get_search_backend(), DuckDuckGoBackend)


# ---------------------------------------------------------------------------
# 具体后端
# ---------------------------------------------------------------------------

class TestDuckDuckGo:
    def test_search_maps_fields(self, monkeypatch):
        """mock DDG 客户端：raw 结果映射为 title/url/snippet。"""
        class FakeDDGS:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def text(self, query, max_results=None):
                assert query == "CVE-2024-27348"
                assert max_results == 3
                return [{"title": "T", "href": "http://x", "body": "B"}]

        monkeypatch.setattr(DuckDuckGoBackend, "_get_client_cls",
                            staticmethod(lambda: FakeDDGS))
        data = DuckDuckGoBackend().search("CVE-2024-27348", max_results=3)
        assert data["error"] is None
        assert data["results"] == [{"title": "T", "url": "http://x", "snippet": "B"}]

    def test_search_degrades_when_client_missing(self, monkeypatch):
        """库未安装/客户端异常 → 空结果 + 错误，不抛异常。"""
        def raise_on_new():
            raise ImportError("no duckduckgo_search")

        monkeypatch.setattr(DuckDuckGoBackend, "_get_client_cls",
                            staticmethod(raise_on_new))
        data = DuckDuckGoBackend().search("query")
        assert data["results"] == []
        assert isinstance(data["error"], str)


class TestTavily:
    def test_without_key_degrades(self, monkeypatch):
        """缺 TAVILY_API_KEY → 空结果 + 错误说明，不抛异常。"""
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        backend = TavilyBackend(api_key="")
        data = backend.search("query")
        assert data["results"] == []
        assert "TAVILY_API_KEY" in data["error"]

    def test_env_key_picked_up(self, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "sk-test")
        assert TavilyBackend().api_key == "sk-test"


# ---------------------------------------------------------------------------
# 清洗逻辑
# ---------------------------------------------------------------------------

class TestCleanHtml:
    def test_strips_scripts_styles_and_tags(self):
        raw = ("<html><head><style>body{}</style></head><body>"
               "<script>alert(1)</script><p>Hi  there</p></body></html>")
        assert clean_html_text(raw) == "Hi there"

    def test_unescapes_entities(self):
        assert clean_html_text("<p>Hello &amp; welcome &lt;x&gt;</p>") == \
            "Hello & welcome <x>"

    def test_collapses_blank_lines(self):
        assert clean_html_text("<div>a</div>\n\n\n<div>b</div>") == "a\nb"

    def test_truncates_long_text(self):
        text = clean_html_text("x" * 20000)
        assert len(text) == MAX_FETCH_CHARS + 1
        assert text.endswith("…")

    def test_empty_input(self):
        assert clean_html_text("") == ""
        assert clean_html_text(None) == ""


# ---------------------------------------------------------------------------
# ToolBridge 集成（标准 call_tool 路径）
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bridge_and_backend():
    """构造一个 ToolBridge，其 web 工具使用可控的 FakeBackend。"""
    from kali_mcp.core import search_backends as sb_mod
    from kali_mcp.core.tool_bridge import ToolBridge

    backend = FakeBackend(
        results=[
            {"title": "CVE-2024-27348", "url": "http://nvd.example/cve",
             "snippet": "RCE in Apache HugeGraph"},
            {"title": "PoC", "url": "http://poc.example", "snippet": "exploit"},
        ],
        text="Apache HugeGraph RCE advisory",
    )
    original = sb_mod.get_search_backend
    sb_mod.get_search_backend = lambda: backend
    try:
        yield ToolBridge(MagicMock()), backend
    finally:
        sb_mod.get_search_backend = original


class TestToolBridgeIntegration:
    def test_web_tools_registered(self, bridge_and_backend):
        bridge, _ = bridge_and_backend
        assert "web_search" in bridge.registry.tools
        assert "web_fetch" in bridge.registry.tools

    def test_catalog_contains_web_tools(self, bridge_and_backend):
        bridge, _ = bridge_and_backend
        catalog = bridge.get_catalog_prompt()
        assert "- web_search:" in catalog
        assert "query(必填)" in catalog
        assert "- web_fetch:" in catalog
        assert "url(必填)" in catalog

    def test_call_tool_web_search_standard_path(self, bridge_and_backend):
        bridge, _ = bridge_and_backend
        out = _run(bridge.call_tool("web_search", {"query": "CVE-2024-27348",
                                                   "max_results": 3}))
        assert "1. CVE-2024-27348" in out
        assert "http://nvd.example/cve" in out
        assert "2. PoC" in out

    def test_call_tool_web_fetch_returns_backend_text(self, bridge_and_backend):
        """web_fetch 透传后端抓取并清洗后的正文（清洗在真实 fetch_text 里）。"""
        bridge, _ = bridge_and_backend
        out = _run(bridge.call_tool("web_fetch", {"url": "http://nvd.example"}))
        assert out == "Apache HugeGraph RCE advisory"

    def test_call_tool_web_search_degrades_on_error(self, bridge_and_backend):
        """后端网络失败 → call_tool 返回空结果 + 错误说明，不抛异常不阻塞。"""
        bridge, backend = bridge_and_backend
        backend.search_error = RuntimeError("connection refused")
        try:
            out = _run(bridge.call_tool("web_search", {"query": "CVE"}))
            assert "[web_search 不可用]" in out
            assert "connection refused" in out
        finally:
            backend.search_error = None

    def test_call_tool_web_fetch_degrades_on_error(self, bridge_and_backend):
        bridge, backend = bridge_and_backend
        backend.fetch_error = RuntimeError("timeout")
        try:
            out = _run(bridge.call_tool("web_fetch", {"url": "http://x"}))
            assert "[web_fetch 不可用]" in out
        finally:
            backend.fetch_error = None

    def test_call_tool_unknown_params_clamped(self, bridge_and_backend):
        """max_results 非法/越界 → 钳制到 [1,10]，不抛异常。"""
        bridge, _ = bridge_and_backend
        out = _run(bridge.call_tool("web_search", {"query": "q",
                                                   "max_results": 999}))
        assert out  # 正常格式化输出（钳制为 10 条以内）
