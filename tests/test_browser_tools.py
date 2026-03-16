"""
Comprehensive unit tests for kali_mcp/mcp_tools/browser_tools.py

Tests cover:
  - register_browser_tools() registration logic (all 12 tools)
  - Early return when engine not available
  - Lazy engine initialization via _get_engine()
  - Session management tools (start, close, list)
  - Navigation and interaction tools (navigate, click, type_text, execute_js)
  - Data extraction tools (extract_content, screenshot, get_network_log)
  - Advanced features (heartbeat_status, intercept_request)
  - Error handling for all tools
"""

import json
import os
import time
import pytest
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
    PropertyMock,
)
from typing import Dict, Any


# ---------------------------------------------------------------------------
# Helpers to capture tools registered via @mcp.tool()
# ---------------------------------------------------------------------------

class MockMCP:
    """Mock MCP server that captures tool registrations."""

    def __init__(self):
        self._registered_tools: Dict[str, Any] = {}

    def tool(self):
        """Decorator that records the function under its name."""
        def decorator(fn):
            self._registered_tools[fn.__name__] = fn
            return fn
        return decorator

    def get_tool(self, name: str):
        return self._registered_tools.get(name)

    @property
    def registered_tool_names(self):
        return set(self._registered_tools.keys())


def _make_mock_session(
    session_id: str = "test-session",
    page_title: str = "Test Page",
    current_url: str = "http://example.com",
    cookies: list = None,
    has_heartbeat: bool = True,
    heartbeat_status: dict = None,
    network_log: list = None,
    created_at: float = None,
):
    """Build a fully-mocked BrowserSession-like object."""
    session = MagicMock()
    session.session_id = session_id
    session.created_at = created_at or time.time()

    # --- page mock ---
    page = AsyncMock()
    page.url = current_url
    page.title = AsyncMock(return_value=page_title)
    page.is_closed = MagicMock(return_value=False)

    # page.content() for full HTML extraction
    page.content = AsyncMock(return_value="<html><body>test</body></html>")

    # page.evaluate — return value can be overridden per test
    page.evaluate = AsyncMock(return_value={})

    # page.inner_text
    page.inner_text = AsyncMock(return_value="body text")

    # locator mock
    locator = AsyncMock()
    locator.inner_text = AsyncMock(return_value="element text")
    locator.inner_html = AsyncMock(return_value="<div>html</div>")
    locator.wait_for = AsyncMock()
    locator.click = AsyncMock()
    locator.type = AsyncMock()
    locator.screenshot = AsyncMock()
    page.locator = MagicMock(return_value=locator)

    # page.screenshot
    page.screenshot = AsyncMock()

    # page.wait_for_timeout
    page.wait_for_timeout = AsyncMock()

    # page.keyboard
    keyboard = AsyncMock()
    keyboard.press = AsyncMock()
    page.keyboard = keyboard

    # page.route
    page.route = AsyncMock()

    # context.cookies
    _cookies = cookies if cookies is not None else [
        {"name": "session", "value": "abc123", "domain": ".example.com"}
    ]
    context = AsyncMock()
    context.cookies = AsyncMock(return_value=_cookies)
    page.context = context

    session.page = page

    # --- navigate mock ---
    session.navigate = AsyncMock()

    # --- heartbeat ---
    session.start_heartbeat_monitor = AsyncMock()
    if has_heartbeat:
        _hb = heartbeat_status or {"status": "active"}
        session.get_heartbeat_status = MagicMock(return_value=_hb)
    else:
        # Simulate object without get_heartbeat_status
        if hasattr(session, "get_heartbeat_status"):
            del session.get_heartbeat_status

    # --- network_log ---
    if network_log is not None:
        session.network_log = network_log

    return session


def _make_mock_engine(sessions: dict = None):
    """Build a fully-mocked StealthBrowserEngine-like object."""
    engine = AsyncMock()
    _sessions = sessions or {}

    engine.create_session = AsyncMock()
    engine.get_session = MagicMock()  # called without await in browser_tools.py
    engine.close_session = AsyncMock()
    engine.list_sessions = MagicMock(return_value=_sessions)  # called without await
    engine.start = AsyncMock()

    return engine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_mcp():
    return MockMCP()


@pytest.fixture
def mock_executor():
    return MagicMock()


@pytest.fixture
def mock_engine():
    return _make_mock_engine()


@pytest.fixture
def mock_session():
    return _make_mock_session()


# ---------------------------------------------------------------------------
# Registration Tests
# ---------------------------------------------------------------------------

EXPECTED_TOOLS = {
    "browser_start_session",
    "browser_close_session",
    "browser_list_sessions",
    "browser_navigate",
    "browser_click",
    "browser_type_text",
    "browser_execute_js",
    "browser_extract_content",
    "browser_screenshot",
    "browser_get_network_log",
    "browser_heartbeat_status",
    "browser_intercept_request",
}


class TestRegistration:
    """Tests for register_browser_tools() registration logic."""

    def test_all_12_tools_registered_when_engine_available(self, mock_mcp, mock_executor):
        """When engine is available, all 12 tools should be registered."""
        with patch("kali_mcp.mcp_tools.browser_tools._BROWSER_IMPORT_OK", True):
            from kali_mcp.mcp_tools.browser_tools import register_browser_tools
            register_browser_tools(mock_mcp, mock_executor, BROWSER_ENGINE_AVAILABLE=True)

        assert mock_mcp.registered_tool_names == EXPECTED_TOOLS

    def test_no_tools_registered_when_engine_not_available(self, mock_mcp, mock_executor):
        """When BROWSER_ENGINE_AVAILABLE is False, nothing should be registered."""
        with patch("kali_mcp.mcp_tools.browser_tools._BROWSER_IMPORT_OK", True):
            from kali_mcp.mcp_tools.browser_tools import register_browser_tools
            register_browser_tools(mock_mcp, mock_executor, BROWSER_ENGINE_AVAILABLE=False)

        assert len(mock_mcp.registered_tool_names) == 0

    def test_no_tools_registered_when_import_failed(self, mock_mcp, mock_executor):
        """When _BROWSER_IMPORT_OK is False, nothing should be registered."""
        with patch("kali_mcp.mcp_tools.browser_tools._BROWSER_IMPORT_OK", False):
            from kali_mcp.mcp_tools.browser_tools import register_browser_tools
            register_browser_tools(mock_mcp, mock_executor, BROWSER_ENGINE_AVAILABLE=True)

        assert len(mock_mcp.registered_tool_names) == 0


# ---------------------------------------------------------------------------
# Helper to get registered tool functions
# ---------------------------------------------------------------------------

def _register_tools(mock_mcp, mock_executor):
    """Register tools with mocks and return the MockMCP with captured tools."""
    with patch("kali_mcp.mcp_tools.browser_tools._BROWSER_IMPORT_OK", True):
        from kali_mcp.mcp_tools.browser_tools import register_browser_tools
        register_browser_tools(mock_mcp, mock_executor, BROWSER_ENGINE_AVAILABLE=True)
    return mock_mcp


# ---------------------------------------------------------------------------
# Lazy Engine Initialization Tests
# ---------------------------------------------------------------------------

class TestLazyEngineInit:
    """Tests for _get_engine() lazy initialization."""

    @pytest.mark.asyncio
    async def test_get_engine_creates_engine_on_first_call(self):
        """_get_engine() should create and start a StealthBrowserEngine on first call."""
        import kali_mcp.mcp_tools.browser_tools as bt

        mock_eng_cls = MagicMock()
        mock_eng_instance = AsyncMock()
        mock_eng_instance.start = AsyncMock()
        mock_eng_cls.return_value = mock_eng_instance

        original = bt._browser_engine
        try:
            bt._browser_engine = None
            # Patch at the source module since _get_engine does a fresh import
            with patch("kali_mcp.core.browser_engine.StealthBrowserEngine", mock_eng_cls):
                engine = await bt._get_engine()

            mock_eng_cls.assert_called_once()
            mock_eng_instance.start.assert_awaited_once()
            assert engine is mock_eng_instance
        finally:
            bt._browser_engine = original

    @pytest.mark.asyncio
    async def test_get_engine_returns_cached_on_subsequent_calls(self):
        """_get_engine() should reuse the existing engine instance."""
        import kali_mcp.mcp_tools.browser_tools as bt

        mock_eng = AsyncMock()
        original = bt._browser_engine
        try:
            bt._browser_engine = mock_eng
            engine = await bt._get_engine()
            assert engine is mock_eng
        finally:
            bt._browser_engine = original


# ---------------------------------------------------------------------------
# Session Management Tests
# ---------------------------------------------------------------------------

class TestBrowserStartSession:

    @pytest.mark.asyncio
    async def test_start_session_success(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_start_session")

        session = _make_mock_session(
            session_id="s1",
            page_title="Login Page",
            current_url="http://target.com/login",
        )
        engine = _make_mock_engine()
        engine.create_session = AsyncMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(url="http://target.com/login", session_id="s1", headless=True)

        assert result["success"] is True
        assert result["session_id"] == "s1"
        assert result["page_title"] == "Login Page"
        assert result["current_url"] == "http://target.com/login"
        assert "cookies" in result
        assert result["cookies_count"] == 1
        assert result["headless"] is True

    @pytest.mark.asyncio
    async def test_start_session_with_proxy_and_user_agent(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_start_session")

        session = _make_mock_session(session_id="s2")
        engine = _make_mock_engine()
        engine.create_session = AsyncMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                url="http://target.com",
                proxy="http://127.0.0.1:8080",
                user_agent="CustomUA/1.0",
            )

        assert result["success"] is True
        assert result["proxy"] == "http://127.0.0.1:8080"
        # Verify create_session was called with proxy and user_agent in kwargs
        call_kwargs = engine.create_session.call_args
        assert call_kwargs.kwargs.get("proxy") == "http://127.0.0.1:8080"
        assert call_kwargs.kwargs.get("user_agent") == "CustomUA/1.0"

    @pytest.mark.asyncio
    async def test_start_session_auto_generates_session_id(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_start_session")

        session = _make_mock_session(session_id="auto-id")
        engine = _make_mock_engine()
        engine.create_session = AsyncMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(url="http://target.com", session_id="")

        assert result["success"] is True
        # When session_id is empty, None should be passed
        call_kwargs = engine.create_session.call_args
        assert call_kwargs.kwargs.get("session_id") is None

    @pytest.mark.asyncio
    async def test_start_session_without_heartbeat_method(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_start_session")

        session = _make_mock_session(session_id="s3", has_heartbeat=False)
        engine = _make_mock_engine()
        engine.create_session = AsyncMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(url="http://target.com")

        assert result["success"] is True
        assert result["heartbeat_status"] == {"status": "monitor_started"}

    @pytest.mark.asyncio
    async def test_start_session_error(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_start_session")

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(side_effect=RuntimeError("no browser"))):
            result = await tool(url="http://target.com")

        assert result["success"] is False
        assert "no browser" in result["error"]


class TestBrowserCloseSession:

    @pytest.mark.asyncio
    async def test_close_session_success(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_close_session")

        session = _make_mock_session(session_id="s1")
        # Make page.evaluate return storage data
        session.page.evaluate = AsyncMock(return_value={
            "localStorage": {"token": "abc"},
            "sessionStorage": {"tab": "1"},
        })
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["session_id"] == "s1"
        assert result["cookies_saved"] == 1
        assert result["local_storage_keys"] == 1
        assert result["session_storage_keys"] == 1
        engine.close_session.assert_awaited_once_with("s1")

    @pytest.mark.asyncio
    async def test_close_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_close_session")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="nonexistent")

        assert result["success"] is False
        assert "nonexistent" in result["error"]

    @pytest.mark.asyncio
    async def test_close_session_storage_eval_fails(self, mock_mcp, mock_executor):
        """When page.evaluate fails for storage, it should still close gracefully."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_close_session")

        session = _make_mock_session(session_id="s1")
        session.page.evaluate = AsyncMock(side_effect=Exception("eval failed"))
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["local_storage_keys"] == 0
        assert result["session_storage_keys"] == 0

    @pytest.mark.asyncio
    async def test_close_session_error(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_close_session")

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(side_effect=RuntimeError("engine dead"))):
            result = await tool(session_id="s1")

        assert result["success"] is False
        assert "engine dead" in result["error"]


class TestBrowserListSessions:

    @pytest.mark.asyncio
    async def test_list_sessions_empty(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_list_sessions")

        engine = _make_mock_engine(sessions={})

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool()

        assert result["success"] is True
        assert result["total_sessions"] == 0
        assert result["sessions"] == []

    @pytest.mark.asyncio
    async def test_list_sessions_with_entries(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_list_sessions")

        s1 = _make_mock_session(session_id="s1", page_title="Page 1", current_url="http://a.com")
        s2 = _make_mock_session(session_id="s2", page_title="Page 2", current_url="http://b.com")
        engine = _make_mock_engine(sessions={"s1": s1, "s2": s2})

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool()

        assert result["success"] is True
        assert result["total_sessions"] == 2
        session_ids = {s["session_id"] for s in result["sessions"]}
        assert session_ids == {"s1", "s2"}

    @pytest.mark.asyncio
    async def test_list_sessions_with_closed_page(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_list_sessions")

        session = _make_mock_session(session_id="s1")
        session.page.is_closed = MagicMock(return_value=True)
        engine = _make_mock_engine(sessions={"s1": session})

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool()

        assert result["success"] is True
        assert result["sessions"][0]["status"] == "closed"

    @pytest.mark.asyncio
    async def test_list_sessions_error(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_list_sessions")

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(side_effect=RuntimeError("boom"))):
            result = await tool()

        assert result["success"] is False
        assert "boom" in result["error"]


# ---------------------------------------------------------------------------
# Navigation & Interaction Tests
# ---------------------------------------------------------------------------

class TestBrowserNavigate:

    @pytest.mark.asyncio
    async def test_navigate_success(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_navigate")

        session = _make_mock_session(
            session_id="s1",
            page_title="New Page",
            current_url="http://target.com/new",
            heartbeat_status={"status": "active"},
        )
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", url="http://target.com/new")

        assert result["success"] is True
        assert result["page_title"] == "New Page"
        assert result["heartbeat_detected"] is True
        session.navigate.assert_awaited_once_with("http://target.com/new", wait_until="networkidle")

    @pytest.mark.asyncio
    async def test_navigate_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_navigate")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad", url="http://x.com")

        assert result["success"] is False
        assert "bad" in result["error"]

    @pytest.mark.asyncio
    async def test_navigate_heartbeat_inactive(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_navigate")

        session = _make_mock_session(
            heartbeat_status={"status": "inactive"},
        )
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", url="http://x.com")

        assert result["success"] is True
        assert result["heartbeat_detected"] is False

    @pytest.mark.asyncio
    async def test_navigate_custom_wait_until(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_navigate")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", url="http://x.com", wait_until="domcontentloaded")

        session.navigate.assert_awaited_once_with("http://x.com", wait_until="domcontentloaded")


class TestBrowserClick:

    @pytest.mark.asyncio
    async def test_click_css_selector(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_click")

        session = _make_mock_session(current_url="http://a.com")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="#btn-submit")

        assert result["success"] is True
        assert result["selector"] == "#btn-submit"
        session.page.locator.assert_called_with("#btn-submit")

    @pytest.mark.asyncio
    async def test_click_xpath_selector(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_click")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="//button[@id='login']")

        assert result["success"] is True
        session.page.locator.assert_called_with("xpath=//button[@id='login']")

    @pytest.mark.asyncio
    async def test_click_xpath_grouped(self, mock_mcp, mock_executor):
        """XPath starting with (//) should also be recognized."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_click")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="(//div)[1]")

        assert result["success"] is True
        session.page.locator.assert_called_with("xpath=(//div)[1]")

    @pytest.mark.asyncio
    async def test_click_url_change_detection(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_click")

        session = _make_mock_session(current_url="http://a.com")
        # Simulate URL change after click
        type(session.page).url = PropertyMock(side_effect=["http://a.com", "http://b.com", "http://b.com"])
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="#link")

        assert result["success"] is True
        assert result["url_changed"] is True

    @pytest.mark.asyncio
    async def test_click_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_click")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad", selector="#x")

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_click_no_wait_after(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_click")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="#x", wait_after=0)

        assert result["success"] is True
        session.page.wait_for_timeout.assert_not_awaited()


class TestBrowserTypeText:

    @pytest.mark.asyncio
    async def test_type_text_success(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_type_text")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="#username", text="admin")

        assert result["success"] is True
        assert result["text_length"] == 5
        assert result["cleared_first"] is True
        assert result["delay_per_char_ms"] == 80

    @pytest.mark.asyncio
    async def test_type_text_without_clear(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_type_text")

        session = _make_mock_session()
        locator = session.page.locator.return_value
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="#input", text="hello", clear_first=False)

        assert result["success"] is True
        assert result["cleared_first"] is False
        # Should not have called keyboard.press for Ctrl+A / Backspace
        session.page.keyboard.press.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_type_text_xpath(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_type_text")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="//input[@name='q']", text="test")

        session.page.locator.assert_called_with("xpath=//input[@name='q']")

    @pytest.mark.asyncio
    async def test_type_text_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_type_text")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad", selector="#x", text="test")

        assert result["success"] is False


class TestBrowserExecuteJs:

    @pytest.mark.asyncio
    async def test_execute_js_success_dict_result(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_execute_js")

        session = _make_mock_session()
        session.page.evaluate = AsyncMock(return_value={"key": "value"})
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", script="return {key: 'value'}")

        assert result["success"] is True
        assert result["result"] == {"key": "value"}
        assert result["result_type"] == "dict"

    @pytest.mark.asyncio
    async def test_execute_js_success_null_result(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_execute_js")

        session = _make_mock_session()
        session.page.evaluate = AsyncMock(return_value=None)
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", script="void 0")

        assert result["success"] is True
        assert result["result"] is None
        assert result["result_type"] == "null"
        assert result["result_preview"] is None

    @pytest.mark.asyncio
    async def test_execute_js_truncation(self, mock_mcp, mock_executor):
        """When result string exceeds 50000 chars, it should be truncated."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_execute_js")

        huge_result = "x" * 60000
        session = _make_mock_session()
        session.page.evaluate = AsyncMock(return_value=huge_result)
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", script="return bigstring")

        assert result["success"] is True
        # The result_preview is capped at 5000 chars
        assert len(result["result_preview"]) <= 5000

    @pytest.mark.asyncio
    async def test_execute_js_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_execute_js")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad", script="1+1")

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_execute_js_error(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_execute_js")

        session = _make_mock_session()
        session.page.evaluate = AsyncMock(side_effect=Exception("JS error"))
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", script="bad()")

        assert result["success"] is False
        assert "JS error" in result["error"]


# ---------------------------------------------------------------------------
# Data Extraction Tests
# ---------------------------------------------------------------------------

class TestBrowserExtractContent:

    @pytest.mark.asyncio
    async def test_extract_text_full_page(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        session = _make_mock_session()
        session.page.inner_text = AsyncMock(return_value="hello world")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", extract_type="text")

        assert result["success"] is True
        assert result["data"]["text"] == "hello world"
        assert result["selector"] == "(entire page)"

    @pytest.mark.asyncio
    async def test_extract_text_with_selector(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="#main", extract_type="text")

        assert result["success"] is True
        assert result["data"]["text"] == "element text"

    @pytest.mark.asyncio
    async def test_extract_html_full_page(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", extract_type="html")

        assert result["success"] is True
        assert "<html>" in result["data"]["html"]

    @pytest.mark.asyncio
    async def test_extract_html_with_selector(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", selector="#content", extract_type="html")

        assert result["success"] is True
        assert result["data"]["html"] == "<div>html</div>"

    @pytest.mark.asyncio
    async def test_extract_links(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        links_data = [
            {"href": "http://a.com", "text": "Link A", "target": "_self"},
            {"href": "http://b.com", "text": "Link B", "target": "_blank"},
        ]
        session = _make_mock_session()
        session.page.evaluate = AsyncMock(return_value=links_data)
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", extract_type="links")

        assert result["success"] is True
        assert result["data"]["total"] == 2

    @pytest.mark.asyncio
    async def test_extract_forms(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        forms_data = [
            {"id": "login-form", "action": "/login", "method": "POST", "inputs": [
                {"name": "username", "type": "text", "value": "", "id": "user", "required": True}
            ]}
        ]
        session = _make_mock_session()
        session.page.evaluate = AsyncMock(return_value=forms_data)
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", extract_type="forms")

        assert result["success"] is True
        assert result["data"]["total"] == 1

    @pytest.mark.asyncio
    async def test_extract_cookies(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        cookies = [
            {"name": "sid", "value": "abc", "domain": ".test.com", "path": "/",
             "httpOnly": True, "secure": True, "sameSite": "Lax", "expires": 9999}
        ]
        session = _make_mock_session(cookies=cookies)
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", extract_type="cookies")

        assert result["success"] is True
        assert result["data"]["total"] == 1
        cookie = result["data"]["cookies"][0]
        assert cookie["name"] == "sid"
        assert cookie["httpOnly"] is True

    @pytest.mark.asyncio
    async def test_extract_storage(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        storage_data = {
            "localStorage": {"token": "jwt123"},
            "localStorageCount": 1,
            "sessionStorage": {},
            "sessionStorageCount": 0,
        }
        session = _make_mock_session()
        session.page.evaluate = AsyncMock(return_value=storage_data)
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", extract_type="storage")

        assert result["success"] is True
        assert result["data"]["localStorageCount"] == 1

    @pytest.mark.asyncio
    async def test_extract_unsupported_type(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        session = _make_mock_session()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", extract_type="invalid_type")

        assert result["success"] is False
        assert "invalid_type" in result["error"]

    @pytest.mark.asyncio
    async def test_extract_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_extract_content")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="x")

        assert result["success"] is False


class TestBrowserScreenshot:

    @pytest.mark.asyncio
    async def test_screenshot_viewport(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_screenshot")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)), \
             patch("os.makedirs") as mock_makedirs, \
             patch("os.path.getsize", return_value=12345):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["file_size_bytes"] == 12345
        assert result["full_page"] is False
        assert result["selector"] == "(viewport)"
        mock_makedirs.assert_called_once()

    @pytest.mark.asyncio
    async def test_screenshot_full_page(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_screenshot")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)), \
             patch("os.makedirs"), \
             patch("os.path.getsize", return_value=99999):
            result = await tool(session_id="s1", full_page=True)

        assert result["success"] is True
        assert result["full_page"] is True
        session.page.screenshot.assert_awaited_once()
        call_kwargs = session.page.screenshot.call_args.kwargs
        assert call_kwargs["full_page"] is True

    @pytest.mark.asyncio
    async def test_screenshot_element(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_screenshot")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)), \
             patch("os.makedirs"), \
             patch("os.path.getsize", return_value=5000):
            result = await tool(session_id="s1", selector="#main-content")

        assert result["success"] is True
        assert result["selector"] == "#main-content"
        locator = session.page.locator.return_value
        locator.screenshot.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_screenshot_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_screenshot")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad")

        assert result["success"] is False


class TestBrowserGetNetworkLog:

    @pytest.mark.asyncio
    async def test_network_log_no_filter(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_get_network_log")

        log_entries = [
            {"url": "http://a.com/api/heartbeat", "resource_type": "xmlhttprequest", "method": "GET"},
            {"url": "http://a.com/page.js", "resource_type": "script", "method": "GET"},
        ]
        session = _make_mock_session()
        session.network_log = log_entries
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["total_requests"] == 2
        assert result["returned_requests"] == 2

    @pytest.mark.asyncio
    async def test_network_log_filter_url(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_get_network_log")

        log_entries = [
            {"url": "http://a.com/api/heartbeat", "resource_type": "xmlhttprequest"},
            {"url": "http://a.com/page.js", "resource_type": "script"},
        ]
        session = _make_mock_session()
        session.network_log = log_entries
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", filter_url="heartbeat")

        assert result["success"] is True
        assert result["total_requests"] == 1

    @pytest.mark.asyncio
    async def test_network_log_filter_type(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_get_network_log")

        log_entries = [
            {"url": "http://a.com/api/data", "resource_type": "xmlhttprequest"},
            {"url": "http://a.com/page.js", "resource_type": "script"},
        ]
        session = _make_mock_session()
        session.network_log = log_entries
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1", filter_type="xhr")

        assert result["success"] is True
        assert result["total_requests"] == 1
        assert result["requests"][0]["url"] == "http://a.com/api/data"

    @pytest.mark.asyncio
    async def test_network_log_truncation(self, mock_mcp, mock_executor):
        """When there are >500 entries, only the last 500 should be returned."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_get_network_log")

        log_entries = [{"url": f"http://a.com/{i}", "resource_type": "fetch"} for i in range(600)]
        session = _make_mock_session()
        session.network_log = log_entries
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["total_requests"] == 600
        assert result["returned_requests"] == 500

    @pytest.mark.asyncio
    async def test_network_log_get_network_log_method(self, mock_mcp, mock_executor):
        """When session has get_network_log() method instead of network_log attribute."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_get_network_log")

        log_entries = [{"url": "http://a.com/api", "resource_type": "fetch"}]
        session = MagicMock()
        session.page = MagicMock()
        # Remove network_log attribute, add get_network_log method
        session.configure_mock(**{"network_log": MagicMock(side_effect=AttributeError)})
        del session.network_log
        session.get_network_log = MagicMock(return_value=log_entries)
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["total_requests"] == 1

    @pytest.mark.asyncio
    async def test_network_log_no_log_available(self, mock_mcp, mock_executor):
        """When session has neither network_log nor get_network_log."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_get_network_log")

        session = MagicMock(spec=[])  # empty spec = no attributes
        session.page = MagicMock()
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["total_requests"] == 0

    @pytest.mark.asyncio
    async def test_network_log_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_get_network_log")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad")

        assert result["success"] is False


# ---------------------------------------------------------------------------
# Advanced Feature Tests
# ---------------------------------------------------------------------------

class TestBrowserHeartbeatStatus:

    @pytest.mark.asyncio
    async def test_heartbeat_status_active(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_heartbeat_status")

        session = _make_mock_session(
            session_id="s1",
            heartbeat_status={
                "status": "active",
                "detected_heartbeats": [{"type": "ws", "url": "ws://a.com"}],
                "websocket_connections": [{"url": "ws://a.com"}],
                "xhr_polling": [],
                "uptime_seconds": 120,
            },
            created_at=time.time() - 120,
        )
        session.page.evaluate = AsyncMock(return_value={
            "performance_entries": [{"name": "http://a.com/poll", "type": "fetch"}],
            "ws_connections": [],
        })
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["status"] == "active"
        assert len(result["detected_heartbeats"]) == 1

    @pytest.mark.asyncio
    async def test_heartbeat_status_no_heartbeat_method(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_heartbeat_status")

        session = _make_mock_session(session_id="s1", has_heartbeat=False)
        session.page.evaluate = AsyncMock(return_value={})
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["status"] == "unknown"

    @pytest.mark.asyncio
    async def test_heartbeat_status_js_eval_fails(self, mock_mcp, mock_executor):
        """When JS evaluation for WS info fails, it should still return heartbeat data."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_heartbeat_status")

        session = _make_mock_session(
            session_id="s1",
            heartbeat_status={"status": "active"},
        )
        session.page.evaluate = AsyncMock(side_effect=Exception("JS failed"))
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        assert result["status"] == "active"

    @pytest.mark.asyncio
    async def test_heartbeat_status_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_heartbeat_status")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad")

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_heartbeat_uptime_calculation(self, mock_mcp, mock_executor):
        """When session has created_at, uptime_seconds should be calculated."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_heartbeat_status")

        created = time.time() - 300  # 5 minutes ago
        session = _make_mock_session(
            session_id="s1",
            heartbeat_status={"status": "active"},
            created_at=created,
        )
        session.page.evaluate = AsyncMock(return_value={})
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="s1")

        assert result["success"] is True
        # Uptime should be approximately 300 seconds
        assert result["uptime_seconds"] >= 299


class TestBrowserInterceptRequest:

    @pytest.mark.asyncio
    async def test_intercept_log_action(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                session_id="s1",
                url_pattern="*/api/*",
                action="log",
            )

        assert result["success"] is True
        assert result["action"] == "log"
        assert result["url_pattern"] == "*/api/*"
        session.page.route.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_intercept_block_action(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                session_id="s1",
                url_pattern="*.png",
                action="block",
            )

        assert result["success"] is True
        assert result["action"] == "block"

    @pytest.mark.asyncio
    async def test_intercept_modify_action_with_headers(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        headers_json = json.dumps({"X-Custom": "test-value"})
        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                session_id="s1",
                url_pattern="*/api/*",
                action="modify",
                modify_headers=headers_json,
                modify_body='{"key": "val"}',
            )

        assert result["success"] is True
        assert result["action"] == "modify"
        assert result["modify_headers"] == {"X-Custom": "test-value"}
        assert result["modify_body"] == '{"key": "val"}'

    @pytest.mark.asyncio
    async def test_intercept_invalid_headers_json(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                session_id="s1",
                url_pattern="*/api/*",
                action="modify",
                modify_headers="not-valid-json",
            )

        assert result["success"] is False
        assert "JSON" in result["error"]

    @pytest.mark.asyncio
    async def test_intercept_session_not_found(self, mock_mcp, mock_executor):
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=None)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(session_id="bad", url_pattern="*")

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_intercept_wildcard_to_regex(self, mock_mcp, mock_executor):
        """Verify the wildcard pattern is correctly converted to regex."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                session_id="s1",
                url_pattern="http://example.com/api/*",
                action="log",
            )

        assert result["success"] is True
        assert result["regex_pattern"] == "http://example.com/api/.*"

    @pytest.mark.asyncio
    async def test_intercept_empty_headers(self, mock_mcp, mock_executor):
        """Empty modify_headers should be treated as no modification."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        session = _make_mock_session(session_id="s1")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                session_id="s1",
                url_pattern="*",
                action="modify",
                modify_headers="{}",
            )

        assert result["success"] is True
        assert result["modify_headers"] is None

    @pytest.mark.asyncio
    async def test_intercept_sets_intercept_logs_on_session(self, mock_mcp, mock_executor):
        """The tool should attach _intercept_logs dict to the session."""
        mcp = _register_tools(mock_mcp, mock_executor)
        tool = mcp.get_tool("browser_intercept_request")

        session = _make_mock_session(session_id="s1")
        # Ensure _intercept_logs doesn't exist yet
        if hasattr(session, "_intercept_logs"):
            delattr(session, "_intercept_logs")
        engine = _make_mock_engine()
        engine.get_session = MagicMock(return_value=session)

        with patch("kali_mcp.mcp_tools.browser_tools._get_engine", AsyncMock(return_value=engine)):
            result = await tool(
                session_id="s1",
                url_pattern="*/track/*",
                action="log",
            )

        assert result["success"] is True
        assert hasattr(session, "_intercept_logs")
        assert "*/track/*" in session._intercept_logs


# ---------------------------------------------------------------------------
# Error Handling Edge Cases
# ---------------------------------------------------------------------------

class TestErrorHandling:

    @pytest.mark.asyncio
    async def test_all_tools_return_error_dict_on_exception(self, mock_mcp, mock_executor):
        """Every tool should return {success: False, error: ...} when an exception occurs."""
        mcp = _register_tools(mock_mcp, mock_executor)
        engine_error = AsyncMock(side_effect=RuntimeError("engine crash"))

        for tool_name in EXPECTED_TOOLS:
            tool = mcp.get_tool(tool_name)
            with patch("kali_mcp.mcp_tools.browser_tools._get_engine", engine_error):
                # Build minimal arguments
                if tool_name == "browser_start_session":
                    result = await tool(url="http://x.com")
                elif tool_name == "browser_list_sessions":
                    result = await tool()
                elif tool_name == "browser_close_session":
                    result = await tool(session_id="s1")
                elif tool_name == "browser_navigate":
                    result = await tool(session_id="s1", url="http://x.com")
                elif tool_name == "browser_click":
                    result = await tool(session_id="s1", selector="#x")
                elif tool_name == "browser_type_text":
                    result = await tool(session_id="s1", selector="#x", text="t")
                elif tool_name == "browser_execute_js":
                    result = await tool(session_id="s1", script="1")
                elif tool_name == "browser_extract_content":
                    result = await tool(session_id="s1")
                elif tool_name == "browser_screenshot":
                    result = await tool(session_id="s1")
                elif tool_name == "browser_get_network_log":
                    result = await tool(session_id="s1")
                elif tool_name == "browser_heartbeat_status":
                    result = await tool(session_id="s1")
                elif tool_name == "browser_intercept_request":
                    result = await tool(session_id="s1", url_pattern="*")
                else:
                    continue

                assert result["success"] is False, f"{tool_name} did not return success=False on error"
                assert "error" in result, f"{tool_name} did not include error key"
