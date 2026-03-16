"""
Tests for browser_engine module (kali_mcp/core/browser_engine.py)

Covers:
- _humanize_delay: random delay generation within bounds
- _get_stealth_scripts: anti-detection JS script list
- SessionMetadata: creation, to_dict, from_dict round-trip
- NetworkLogEntry: dataclass creation with defaults
- HeartbeatMonitor: init, start, stop, get_status, event handlers, analysis
- BrowserSession: navigation, interaction, extraction, cookies, state,
                  heartbeat, intercept, network log, _ensure_playwright
- StealthBrowserEngine: init, start, stop, create_session, get_session,
                        close_session, list_sessions, _ensure_running,
                        _build_launch_args, async context manager
- get_engine_status: with and without engine instance
- HAS_PLAYWRIGHT flag behaviour
"""

import asyncio
import json
import os
import tempfile
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import (
    AsyncMock,
    MagicMock,
    Mock,
    patch,
    PropertyMock,
    call,
)

import pytest

# ---------------------------------------------------------------------------
# Import the module under test — playwright may not be installed, but the
# module is designed to handle that gracefully via HAS_PLAYWRIGHT.
# ---------------------------------------------------------------------------
from kali_mcp.core.browser_engine import (
    _humanize_delay,
    _get_stealth_scripts,
    SessionMetadata,
    NetworkLogEntry,
    HeartbeatMonitor,
    BrowserSession,
    StealthBrowserEngine,
    get_engine_status,
    HAS_PLAYWRIGHT,
    DEFAULT_STORAGE_DIR,
    DEFAULT_USER_AGENT,
    DEFAULT_VIEWPORT,
    HEARTBEAT_URL_PATTERNS,
    HEARTBEAT_MIN_SAMPLES,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _make_mock_page():
    """Create a fully mocked Playwright Page object."""
    page = AsyncMock()
    page.title = AsyncMock(return_value="Test Page")
    page.content = AsyncMock(return_value="<html><body>test</body></html>")
    page.evaluate = AsyncMock(return_value=None)
    page.query_selector = AsyncMock(return_value=None)
    page.wait_for_selector = AsyncMock()
    page.click = AsyncMock()
    page.screenshot = AsyncMock(return_value=b"\x89PNG")
    page.goto = AsyncMock()
    page.route = AsyncMock()

    # Mouse mock
    page.mouse = AsyncMock()
    page.mouse.move = AsyncMock()
    page.mouse.wheel = AsyncMock()

    # Keyboard mock
    page.keyboard = AsyncMock()
    page.keyboard.type = AsyncMock()

    # Event registration (sync methods)
    page.on = MagicMock()

    return page


def _make_mock_context():
    """Create a fully mocked Playwright BrowserContext object."""
    context = AsyncMock()
    context.cookies = AsyncMock(return_value=[])
    context.add_cookies = AsyncMock()
    context.storage_state = AsyncMock()
    context.add_init_script = AsyncMock()
    context.new_page = AsyncMock()
    context.close = AsyncMock()
    return context


def _make_mock_browser():
    """Create a fully mocked Playwright Browser object."""
    browser = AsyncMock()
    browser.new_context = AsyncMock()
    browser.close = AsyncMock()
    return browser


# ═══════════════════════════════════════════════════════════════════════════
# _humanize_delay
# ═══════════════════════════════════════════════════════════════════════════

class TestHumanizeDelay:
    def test_returns_float(self):
        result = _humanize_delay()
        assert isinstance(result, float)

    def test_default_range(self):
        """Default range is 100–500ms → 0.1–0.5s."""
        for _ in range(100):
            val = _humanize_delay()
            assert 0.1 <= val <= 0.5

    def test_custom_range(self):
        for _ in range(100):
            val = _humanize_delay(200, 300)
            assert 0.2 <= val <= 0.3

    def test_exact_range(self):
        """When min == max, result is deterministic."""
        val = _humanize_delay(500, 500)
        assert val == 0.5

    def test_zero_delay(self):
        val = _humanize_delay(0, 0)
        assert val == 0.0


# ═══════════════════════════════════════════════════════════════════════════
# _get_stealth_scripts
# ═══════════════════════════════════════════════════════════════════════════

class TestGetStealthScripts:
    def test_returns_list(self):
        scripts = _get_stealth_scripts()
        assert isinstance(scripts, list)

    def test_returns_five_scripts(self):
        scripts = _get_stealth_scripts()
        assert len(scripts) == 5

    def test_all_items_are_strings(self):
        scripts = _get_stealth_scripts()
        for s in scripts:
            assert isinstance(s, str)
            assert len(s) > 10  # non-trivial content

    def test_contains_webdriver_override(self):
        scripts = _get_stealth_scripts()
        combined = "\n".join(scripts)
        assert "webdriver" in combined
        assert "navigator" in combined

    def test_contains_webgl_override(self):
        scripts = _get_stealth_scripts()
        combined = "\n".join(scripts)
        assert "WebGL" in combined or "webgl" in combined

    def test_contains_canvas_fingerprint(self):
        scripts = _get_stealth_scripts()
        combined = "\n".join(scripts)
        assert "Canvas" in combined or "canvas" in combined

    def test_contains_iframe_protection(self):
        scripts = _get_stealth_scripts()
        combined = "\n".join(scripts)
        assert "iframe" in combined.lower()

    def test_idempotent(self):
        """Multiple calls return same content."""
        a = _get_stealth_scripts()
        b = _get_stealth_scripts()
        assert a == b


# ═══════════════════════════════════════════════════════════════════════════
# SessionMetadata
# ═══════════════════════════════════════════════════════════════════════════

class TestSessionMetadata:
    def test_creation_with_required_fields(self):
        md = SessionMetadata(session_id="sess1")
        assert md.session_id == "sess1"
        assert md.url == ""
        assert md.heartbeat_active is False
        assert md.heartbeat_count == 0
        assert md.page_title == ""
        assert md.status == "active"

    def test_creation_with_all_fields(self):
        md = SessionMetadata(
            session_id="s2",
            url="http://example.com",
            created_at="2026-01-01T00:00:00",
            last_access="2026-01-01T00:01:00",
            heartbeat_active=True,
            heartbeat_count=42,
            page_title="Example",
            status="closed",
        )
        assert md.url == "http://example.com"
        assert md.heartbeat_count == 42
        assert md.status == "closed"

    def test_created_at_defaults_to_now(self):
        before = datetime.now().isoformat()
        md = SessionMetadata(session_id="ts")
        after = datetime.now().isoformat()
        assert before <= md.created_at <= after

    def test_to_dict(self):
        md = SessionMetadata(session_id="td", url="http://x.com", page_title="X")
        d = md.to_dict()
        assert isinstance(d, dict)
        assert d["session_id"] == "td"
        assert d["url"] == "http://x.com"
        assert d["page_title"] == "X"
        assert d["heartbeat_active"] is False
        assert d["heartbeat_count"] == 0
        assert d["status"] == "active"
        assert "created_at" in d
        assert "last_access" in d

    def test_from_dict(self):
        data = {
            "session_id": "fd",
            "url": "http://y.com",
            "created_at": "2026-01-01T00:00:00",
            "last_access": "2026-01-01T01:00:00",
            "heartbeat_active": True,
            "heartbeat_count": 10,
            "page_title": "Y",
            "status": "error",
        }
        md = SessionMetadata.from_dict(data)
        assert md.session_id == "fd"
        assert md.url == "http://y.com"
        assert md.heartbeat_active is True
        assert md.heartbeat_count == 10
        assert md.status == "error"

    def test_round_trip(self):
        original = SessionMetadata(
            session_id="rt", url="http://rt.com",
            heartbeat_active=True, heartbeat_count=7,
            page_title="RT", status="active",
        )
        restored = SessionMetadata.from_dict(original.to_dict())
        assert original.to_dict() == restored.to_dict()

    def test_from_dict_ignores_extra_keys(self):
        data = {
            "session_id": "extra",
            "unknown_field": "should_be_ignored",
        }
        md = SessionMetadata.from_dict(data)
        assert md.session_id == "extra"
        assert not hasattr(md, "unknown_field")


# ═══════════════════════════════════════════════════════════════════════════
# NetworkLogEntry
# ═══════════════════════════════════════════════════════════════════════════

class TestNetworkLogEntry:
    def test_creation_required_fields(self):
        entry = NetworkLogEntry(
            timestamp=1234567890.0,
            method="GET",
            url="http://example.com/api",
        )
        assert entry.timestamp == 1234567890.0
        assert entry.method == "GET"
        assert entry.url == "http://example.com/api"

    def test_default_optional_fields(self):
        entry = NetworkLogEntry(
            timestamp=0.0, method="POST", url="http://x.com"
        )
        assert entry.status is None
        assert entry.resource_type == ""
        assert entry.response_size == 0
        assert entry.duration_ms == 0.0
        assert entry.is_heartbeat is False

    def test_creation_all_fields(self):
        entry = NetworkLogEntry(
            timestamp=1.0,
            method="POST",
            url="http://x.com/heartbeat",
            status=200,
            resource_type="xhr",
            response_size=128,
            duration_ms=45.5,
            is_heartbeat=True,
        )
        assert entry.status == 200
        assert entry.resource_type == "xhr"
        assert entry.response_size == 128
        assert entry.duration_ms == 45.5
        assert entry.is_heartbeat is True


# ═══════════════════════════════════════════════════════════════════════════
# HeartbeatMonitor
# ═══════════════════════════════════════════════════════════════════════════

class TestHeartbeatMonitor:
    def test_init(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        assert hm.page is page
        assert hm.active is False
        assert hm.heartbeat_count == 0
        assert len(hm.ws_heartbeats) == 0
        assert len(hm.http_heartbeats) == 0

    @pytest.mark.asyncio
    async def test_start(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        # Patch asyncio.create_task to avoid actually running the loop
        with patch("asyncio.create_task") as mock_create_task:
            mock_create_task.return_value = AsyncMock()
            await hm.start()

        assert hm.active is True
        # Should register websocket and request listeners
        assert page.on.call_count >= 2
        event_names = [c.args[0] for c in page.on.call_args_list]
        assert "websocket" in event_names
        assert "request" in event_names

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        with patch("asyncio.create_task") as mock_ct:
            mock_ct.return_value = AsyncMock()
            await hm.start()
            call_count_1 = page.on.call_count
            await hm.start()  # second call should be no-op
            assert page.on.call_count == call_count_1

    @pytest.mark.asyncio
    async def test_stop_when_not_active(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        await hm.stop()  # should not error
        assert hm.active is False

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = True

        # Create a real coroutine-based task mock
        cancel_called = False

        async def fake_task_coro():
            await asyncio.sleep(100)

        loop = asyncio.get_event_loop()
        real_task = asyncio.ensure_future(fake_task_coro())
        hm._monitor_task = real_task

        await hm.stop()

        assert hm.active is False
        assert real_task.cancelled()
        assert hm._monitor_task is None

    def test_get_status(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = True
        hm.ws_heartbeats.add("ws://example.com/ws")
        hm.http_heartbeats.add("http://example.com/ping")
        hm.heartbeat_count = 5
        hm._ws_connections["ws://example.com/ws"] = Mock()

        status = hm.get_status()

        assert status["active"] is True
        assert status["ws_connections"] == 1
        assert "ws://example.com/ws" in status["ws_heartbeats"]
        assert "http://example.com/ping" in status["http_heartbeats"]
        assert status["total_heartbeat_events"] == 5
        assert isinstance(status["recent_log"], list)

    def test_on_websocket_when_inactive(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = False

        ws = Mock()
        ws.url = "ws://test.com"
        hm._on_websocket(ws)

        # Should not register anything
        assert len(hm._ws_connections) == 0

    def test_on_websocket_when_active(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = True

        ws = Mock()
        ws.url = "ws://test.com/ws"
        ws.on = MagicMock()

        hm._on_websocket(ws)

        assert "ws://test.com/ws" in hm._ws_connections
        assert "ws://test.com/ws" in hm._ws_frame_times
        # Should register framereceived, framesent, close handlers
        assert ws.on.call_count == 3

    def test_on_request_heartbeat_url(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = True

        request = Mock()
        request.url = "http://example.com/api/heartbeat"
        request.resource_type = "xhr"

        hm._on_request(request)

        assert "http://example.com/api/heartbeat" in hm._http_request_times

    def test_on_request_xhr(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = True

        request = Mock()
        request.url = "http://example.com/api/data"
        request.resource_type = "xhr"

        hm._on_request(request)

        assert "http://example.com/api/data" in hm._http_request_times

    def test_on_request_non_xhr_non_heartbeat(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = True

        request = Mock()
        request.url = "http://example.com/style.css"
        request.resource_type = "stylesheet"

        hm._on_request(request)

        assert "http://example.com/style.css" not in hm._http_request_times

    def test_on_request_inactive(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)
        hm.active = False

        request = Mock()
        request.url = "http://example.com/api/heartbeat"
        request.resource_type = "xhr"

        hm._on_request(request)
        assert len(hm._http_request_times) == 0

    def test_analyze_http_patterns_detects_heartbeat(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        url = "http://example.com/api/poll"
        now = time.time()
        # Simulate regular 5-second intervals (well within tolerance)
        hm._http_request_times[url] = [now + i * 5.0 for i in range(5)]

        hm._analyze_http_patterns()

        assert url in hm.http_heartbeats

    def test_analyze_http_patterns_ignores_irregular(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        url = "http://example.com/random"
        now = time.time()
        # Highly irregular intervals
        hm._http_request_times[url] = [now, now + 1, now + 50, now + 51, now + 200]

        hm._analyze_http_patterns()

        assert url not in hm.http_heartbeats

    def test_analyze_http_patterns_needs_min_samples(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        url = "http://example.com/poll"
        now = time.time()
        hm._http_request_times[url] = [now, now + 5]  # only 2 samples

        hm._analyze_http_patterns()

        assert url not in hm.http_heartbeats

    def test_analyze_ws_patterns_detects_heartbeat(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        ws_url = "ws://example.com/ws"
        now = time.time()
        hm._ws_frame_times[ws_url] = [now + i * 3.0 for i in range(5)]

        hm._analyze_ws_patterns()

        assert ws_url in hm.ws_heartbeats

    def test_analyze_http_trims_old_data(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        url = "http://example.com/poll"
        now = time.time()
        # 35 timestamps — should be trimmed to 30
        hm._http_request_times[url] = [now + i * 5.0 for i in range(35)]

        hm._analyze_http_patterns()

        assert len(hm._http_request_times[url]) <= 30

    def test_log_heartbeat(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        hm._log_heartbeat("http_poll", "http://example.com/ping", "interval=5.0s")

        assert len(hm._heartbeat_log) == 1
        entry = hm._heartbeat_log[0]
        assert entry["type"] == "http_poll"
        assert "example.com" in entry["url"]

    def test_log_heartbeat_trims_at_500(self):
        page = _make_mock_page()
        hm = HeartbeatMonitor(page)

        for i in range(510):
            hm._log_heartbeat("test", f"http://x.com/{i}")

        assert len(hm._heartbeat_log) <= 500


# ═══════════════════════════════════════════════════════════════════════════
# BrowserSession
# ═══════════════════════════════════════════════════════════════════════════

class TestBrowserSession:
    """Tests for BrowserSession with fully mocked playwright objects."""

    @pytest.fixture
    def tmp_storage(self, tmp_path):
        return str(tmp_path)

    @pytest.fixture
    def session(self, tmp_storage):
        """Create a BrowserSession with mocked page/context."""
        page = _make_mock_page()
        context = _make_mock_context()
        return BrowserSession(
            session_id="test-session",
            context=context,
            page=page,
            storage_dir=tmp_storage,
        )

    def test_init(self, session, tmp_storage):
        assert session.session_id == "test-session"
        assert session.metadata.session_id == "test-session"
        assert session.metadata.status == "active"
        storage_path = Path(tmp_storage) / "test-session"
        assert storage_path.exists()

    def test_init_creates_storage_dir(self, tmp_storage):
        page = _make_mock_page()
        context = _make_mock_context()
        s = BrowserSession("new-sess", context, page, tmp_storage)
        assert (Path(tmp_storage) / "new-sess").is_dir()

    # -- _ensure_playwright ---

    def test_ensure_playwright_raises_when_not_installed(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", False):
            with pytest.raises(RuntimeError, match="playwright 未安装"):
                session._ensure_playwright()

    def test_ensure_playwright_passes_when_installed(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session._ensure_playwright()  # should not raise

    # -- navigate ---

    @pytest.mark.asyncio
    async def test_navigate(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            mock_response = Mock()
            mock_response.status = 200
            session.page.goto.return_value = mock_response
            session.page.title.return_value = "Login Page"

            result = await session.navigate("http://target.com/login")

            session.page.goto.assert_called_once()
            assert result["url"] == "http://target.com/login"
            assert result["title"] == "Login Page"
            assert result["status"] == 200
            assert session.metadata.url == "http://target.com/login"

    @pytest.mark.asyncio
    async def test_navigate_none_response(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.goto.return_value = None
            session.page.title.return_value = "Empty"

            result = await session.navigate("http://target.com")

            assert result["status"] is None

    # -- wait_for_selector ---

    @pytest.mark.asyncio
    async def test_wait_for_selector_found(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.wait_for_selector.return_value = Mock()

            result = await session.wait_for_selector("#login-btn")

            assert result is True
            session.page.wait_for_selector.assert_called_once_with(
                "#login-btn", timeout=30000
            )

    @pytest.mark.asyncio
    async def test_wait_for_selector_timeout(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.wait_for_selector.side_effect = TimeoutError("timeout")

            result = await session.wait_for_selector("#missing", timeout=1000)

            assert result is False

    # -- click ---

    @pytest.mark.asyncio
    async def test_click(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.evaluate.return_value = {"x": 100, "y": 200}

            await session.click("#btn")

            session.page.click.assert_called_once_with("#btn")

    # -- type_text ---

    @pytest.mark.asyncio
    async def test_type_text(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.evaluate.return_value = {"x": 50, "y": 50}

            await session.type_text("#user", "admin")

            session.page.click.assert_called_once_with("#user")
            assert session.page.keyboard.type.call_count == 5  # 'a','d','m','i','n'

    # -- scroll ---

    @pytest.mark.asyncio
    async def test_scroll_down(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            with patch("kali_mcp.core.browser_engine.random") as mock_random:
                mock_random.randint.return_value = 3
                mock_random.uniform.return_value = 0.0

                await session.scroll("down", 300)

                assert session.page.mouse.wheel.call_count == 3

    @pytest.mark.asyncio
    async def test_scroll_directions(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            for direction in ["down", "up", "left", "right"]:
                session.page.mouse.wheel.reset_mock()
                await session.scroll(direction, 100)
                assert session.page.mouse.wheel.call_count > 0

    # -- extract_text ---

    @pytest.mark.asyncio
    async def test_extract_text_found(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            mock_element = AsyncMock()
            mock_element.text_content.return_value = "Hello World"
            session.page.query_selector.return_value = mock_element

            result = await session.extract_text("#content")

            assert result == "Hello World"

    @pytest.mark.asyncio
    async def test_extract_text_not_found(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.query_selector.return_value = None

            result = await session.extract_text("#missing")

            assert result == ""

    @pytest.mark.asyncio
    async def test_extract_text_none_content(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            mock_element = AsyncMock()
            mock_element.text_content.return_value = None
            session.page.query_selector.return_value = mock_element

            result = await session.extract_text("#empty")

            assert result == ""

    # -- extract_html ---

    @pytest.mark.asyncio
    async def test_extract_html_with_selector(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            mock_element = AsyncMock()
            mock_element.inner_html.return_value = "<p>test</p>"
            session.page.query_selector.return_value = mock_element

            result = await session.extract_html("#content")

            assert result == "<p>test</p>"

    @pytest.mark.asyncio
    async def test_extract_html_no_selector(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.content.return_value = "<html><body>full</body></html>"

            result = await session.extract_html()

            assert "full" in result

    @pytest.mark.asyncio
    async def test_extract_html_element_not_found(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.query_selector.return_value = None

            result = await session.extract_html("#nope")

            assert result == ""

    # -- extract_links ---

    @pytest.mark.asyncio
    async def test_extract_links(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.evaluate.return_value = [
                {"href": "http://example.com/a", "text": "Link A"},
                {"href": "http://example.com/b", "text": "Link B"},
            ]

            links = await session.extract_links()

            assert len(links) == 2
            assert links[0]["href"] == "http://example.com/a"

    @pytest.mark.asyncio
    async def test_extract_links_empty(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.evaluate.return_value = None

            links = await session.extract_links()

            assert links == []

    # -- extract_forms ---

    @pytest.mark.asyncio
    async def test_extract_forms(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.evaluate.return_value = [
                {
                    "action": "/login",
                    "method": "POST",
                    "id": "login-form",
                    "name": "",
                    "inputs": [
                        {"tag": "input", "type": "text", "name": "user",
                         "id": "", "value": "", "placeholder": "Username",
                         "required": True},
                    ],
                }
            ]

            forms = await session.extract_forms()

            assert len(forms) == 1
            assert forms[0]["action"] == "/login"
            assert forms[0]["method"] == "POST"

    # -- screenshot ---

    @pytest.mark.asyncio
    async def test_screenshot_default_path(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.screenshot.return_value = b"\x89PNG_DATA"

            result = await session.screenshot()

            assert result == b"\x89PNG_DATA"
            session.page.screenshot.assert_called_once()
            call_kwargs = session.page.screenshot.call_args
            assert "screenshot_" in call_kwargs.kwargs.get("path", call_kwargs[1].get("path", ""))

    @pytest.mark.asyncio
    async def test_screenshot_custom_path(self, session, tmp_path):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            custom_path = str(tmp_path / "custom.png")
            session.page.screenshot.return_value = b"\x89PNG"

            await session.screenshot(path=custom_path)

            session.page.screenshot.assert_called_once_with(
                path=custom_path, full_page=True
            )

    # -- execute_js ---

    @pytest.mark.asyncio
    async def test_execute_js(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.page.evaluate.return_value = {"result": 42}

            result = await session.execute_js("return 42")

            assert result == {"result": 42}

    # -- get_cookies / set_cookies ---

    @pytest.mark.asyncio
    async def test_get_cookies(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.context.cookies.return_value = [
                {"name": "session", "value": "abc123", "domain": "example.com"}
            ]

            cookies = await session.get_cookies()

            assert len(cookies) == 1
            assert cookies[0]["name"] == "session"

    @pytest.mark.asyncio
    async def test_set_cookies(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            new_cookies = [{"name": "token", "value": "xyz", "url": "http://example.com"}]

            await session.set_cookies(new_cookies)

            session.context.add_cookies.assert_called_once_with(new_cookies)

    # -- save_state ---

    @pytest.mark.asyncio
    async def test_save_state(self, session, tmp_storage):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session.context.cookies.return_value = [
                {"name": "sid", "value": "123"}
            ]

            result = await session.save_state()

            assert isinstance(result, str)
            session.context.storage_state.assert_called_once()

            # Check cookie file was written
            cookies_path = Path(tmp_storage) / "test-session" / "cookies.json"
            assert cookies_path.exists()
            with open(cookies_path) as f:
                saved = json.load(f)
            assert saved[0]["name"] == "sid"

            # Check metadata file was written
            meta_path = Path(tmp_storage) / "test-session" / "metadata.json"
            assert meta_path.exists()

    # -- load_state ---

    @pytest.mark.asyncio
    async def test_load_state_with_cookies(self, session, tmp_storage):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            # Write cookies file
            cookies_path = Path(tmp_storage) / "test-session" / "cookies.json"
            cookies_data = [{"name": "auth", "value": "tok", "url": "http://x.com"}]
            with open(cookies_path, "w") as f:
                json.dump(cookies_data, f)

            # Write metadata file
            meta_path = Path(tmp_storage) / "test-session" / "metadata.json"
            meta_data = SessionMetadata(
                session_id="test-session", url="http://old.com", status="closed"
            ).to_dict()
            with open(meta_path, "w") as f:
                json.dump(meta_data, f)

            result = await session.load_state()

            assert result is True
            session.context.add_cookies.assert_called_once_with(cookies_data)
            assert session.metadata.url == "http://old.com"
            assert session.metadata.status == "active"  # reset to active

    @pytest.mark.asyncio
    async def test_load_state_no_files(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            result = await session.load_state()
            assert result is False

    @pytest.mark.asyncio
    async def test_load_state_corrupt_cookies(self, session, tmp_storage):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            cookies_path = Path(tmp_storage) / "test-session" / "cookies.json"
            cookies_path.write_text("INVALID JSON{{{")

            result = await session.load_state()
            # Should handle gracefully — no crash
            assert result is False

    # -- heartbeat methods ---

    @pytest.mark.asyncio
    async def test_start_heartbeat_monitor(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            with patch.object(session._heartbeat_monitor, "start", new_callable=AsyncMock) as mock_start:
                await session.start_heartbeat_monitor()
                mock_start.assert_called_once()
                assert session.metadata.heartbeat_active is True

    @pytest.mark.asyncio
    async def test_stop_heartbeat_monitor(self, session):
        with patch.object(session._heartbeat_monitor, "stop", new_callable=AsyncMock) as mock_stop:
            session._heartbeat_monitor.heartbeat_count = 10
            await session.stop_heartbeat_monitor()
            mock_stop.assert_called_once()
            assert session.metadata.heartbeat_active is False
            assert session.metadata.heartbeat_count == 10

    def test_get_heartbeat_status(self, session):
        status = session.get_heartbeat_status()
        assert isinstance(status, dict)
        assert "active" in status
        assert "ws_connections" in status
        assert "total_heartbeat_events" in status

    # -- intercept_requests ---

    @pytest.mark.asyncio
    async def test_intercept_requests(self, session):
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            handler = AsyncMock()
            await session.intercept_requests("**/api/**", handler)

            session.page.route.assert_called_once_with("**/api/**", handler)
            assert "**/api/**" in session._interceptors

    # -- get_network_log ---

    @pytest.mark.asyncio
    async def test_get_network_log(self, session):
        session._network_log = [
            NetworkLogEntry(
                timestamp=1.0, method="GET", url="http://x.com",
                status=200, resource_type="xhr", is_heartbeat=False,
            ),
            NetworkLogEntry(
                timestamp=2.0, method="POST", url="http://x.com/ping",
                status=200, resource_type="xhr", is_heartbeat=True,
            ),
        ]

        log = await session.get_network_log()

        assert len(log) == 2
        assert log[0]["method"] == "GET"
        assert log[1]["is_heartbeat"] is True
        assert "timestamp" in log[0]
        assert "response_size" in log[0]

    # -- _on_request_for_log ---

    def test_on_request_for_log(self, session):
        request = Mock()
        request.url = "http://example.com/api/data"
        request.method = "GET"
        request.resource_type = "xhr"

        session._on_request_for_log(request)

        assert len(session._network_log) == 1
        assert session._network_log[0].url == "http://example.com/api/data"
        assert session._network_log[0].method == "GET"

    def test_on_request_for_log_heartbeat_detection(self, session):
        request = Mock()
        request.url = "http://example.com/heartbeat"
        request.method = "GET"
        request.resource_type = "xhr"

        session._on_request_for_log(request)

        assert session._network_log[0].is_heartbeat is True

    def test_on_request_for_log_trims_at_2000(self, session):
        for i in range(2010):
            req = Mock()
            req.url = f"http://example.com/{i}"
            req.method = "GET"
            req.resource_type = "document"
            session._on_request_for_log(req)

        assert len(session._network_log) <= 2000

    # -- _on_response_for_log ---

    def test_on_response_for_log(self, session):
        request = Mock()
        request.url = "http://example.com/data"
        request.method = "GET"
        request.resource_type = "xhr"

        session._on_request_for_log(request)

        response = Mock()
        response.request = request
        response.status = 200

        # The key uses id(request) so we need to match it
        key = request.url + str(id(request))
        session._request_timings[key] = time.time() - 0.05

        session._on_response_for_log(response)

        # The entry should now have status updated
        matching = [e for e in session._network_log if e.url == "http://example.com/data"]
        assert len(matching) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# StealthBrowserEngine
# ═══════════════════════════════════════════════════════════════════════════

class TestStealthBrowserEngine:
    @pytest.fixture
    def tmp_storage(self, tmp_path):
        return str(tmp_path / "browser_sessions")

    def test_init_default(self):
        with patch("kali_mcp.core.browser_engine.Path.mkdir"):
            engine = StealthBrowserEngine()
        assert engine._storage_dir == DEFAULT_STORAGE_DIR
        assert engine._headless is True
        assert engine._proxy is None
        assert engine._locale == "zh-CN"
        assert engine._timezone == "Asia/Shanghai"
        assert engine._started is False
        assert engine._sessions == {}

    def test_init_custom(self, tmp_storage):
        engine = StealthBrowserEngine(
            storage_dir=tmp_storage,
            headless=False,
            proxy="http://proxy:8080",
            locale="en-US",
            timezone="America/New_York",
        )
        assert engine._storage_dir == tmp_storage
        assert engine._headless is False
        assert engine._proxy == "http://proxy:8080"
        assert engine._locale == "en-US"
        assert engine._timezone == "America/New_York"

    def test_init_creates_storage_dir(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        assert Path(tmp_storage).exists()

    # -- _build_launch_args ---

    def test_build_launch_args(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        args = engine._build_launch_args()

        assert isinstance(args, list)
        assert "--no-sandbox" in args
        assert "--disable-blink-features=AutomationControlled" in args
        assert any("window-size" in a for a in args)

    # -- _ensure_running ---

    def test_ensure_running_raises_when_not_started(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        with pytest.raises(RuntimeError, match="浏览器引擎未启动"):
            engine._ensure_running()

    def test_ensure_running_raises_when_no_browser(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True
        engine._browser = None
        with pytest.raises(RuntimeError, match="浏览器引擎未启动"):
            engine._ensure_running()

    def test_ensure_running_passes(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True
        engine._browser = Mock()
        engine._ensure_running()  # should not raise

    # -- start ---

    @pytest.mark.asyncio
    async def test_start_no_playwright(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", False):
            with pytest.raises(RuntimeError, match="playwright 未安装"):
                await engine.start()

    @pytest.mark.asyncio
    async def test_start_already_running(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True

        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            await engine.start()  # should return early without error
            assert engine._started is True

    @pytest.mark.asyncio
    async def test_start_success(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        mock_pw = AsyncMock()
        mock_browser = _make_mock_browser()
        mock_pw.chromium.launch.return_value = mock_browser

        mock_async_pw = MagicMock()
        mock_async_pw.return_value.start = AsyncMock(return_value=mock_pw)

        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            with patch("kali_mcp.core.browser_engine.async_playwright", mock_async_pw, create=True):
                await engine.start()

        assert engine._started is True
        assert engine._browser is mock_browser
        assert engine._playwright is mock_pw
        assert engine._start_time is not None

    @pytest.mark.asyncio
    async def test_start_with_string_proxy(self, tmp_storage):
        engine = StealthBrowserEngine(
            storage_dir=tmp_storage, proxy="http://proxy:8080"
        )
        mock_pw = AsyncMock()
        mock_browser = _make_mock_browser()
        mock_pw.chromium.launch.return_value = mock_browser

        mock_async_pw = MagicMock()
        mock_async_pw.return_value.start = AsyncMock(return_value=mock_pw)

        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            with patch("kali_mcp.core.browser_engine.async_playwright", mock_async_pw, create=True):
                await engine.start()

        launch_call = mock_pw.chromium.launch.call_args
        assert launch_call.kwargs["proxy"] == {"server": "http://proxy:8080"}

    @pytest.mark.asyncio
    async def test_start_with_dict_proxy(self, tmp_storage):
        proxy_config = {"server": "socks5://proxy:1080", "username": "u", "password": "p"}
        engine = StealthBrowserEngine(
            storage_dir=tmp_storage, proxy=proxy_config
        )
        mock_pw = AsyncMock()
        mock_browser = _make_mock_browser()
        mock_pw.chromium.launch.return_value = mock_browser

        mock_async_pw = MagicMock()
        mock_async_pw.return_value.start = AsyncMock(return_value=mock_pw)

        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            with patch("kali_mcp.core.browser_engine.async_playwright", mock_async_pw, create=True):
                await engine.start()

        launch_call = mock_pw.chromium.launch.call_args
        assert launch_call.kwargs["proxy"] == proxy_config

    @pytest.mark.asyncio
    async def test_start_browser_launch_failure(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        mock_pw = AsyncMock()
        mock_pw.chromium.launch.side_effect = Exception("browser launch failed")
        mock_pw.stop = AsyncMock()

        mock_async_pw = MagicMock()
        mock_async_pw.return_value.start = AsyncMock(return_value=mock_pw)

        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            with patch("kali_mcp.core.browser_engine.async_playwright", mock_async_pw, create=True):
                with pytest.raises(RuntimeError, match="浏览器启动失败"):
                    await engine.start()

        assert engine._playwright is None
        assert engine._started is False

    # -- stop ---

    @pytest.mark.asyncio
    async def test_stop_empty_engine(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        await engine.stop()  # should not error
        assert engine._started is False

    @pytest.mark.asyncio
    async def test_stop_with_browser(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True
        mock_browser = AsyncMock()
        mock_playwright = AsyncMock()
        engine._browser = mock_browser
        engine._playwright = mock_playwright

        await engine.stop()

        mock_browser.close.assert_called_once()
        mock_playwright.stop.assert_called_once()
        assert engine._browser is None
        assert engine._playwright is None
        assert engine._started is False

    @pytest.mark.asyncio
    async def test_stop_closes_sessions(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True
        engine._browser = AsyncMock()
        engine._playwright = AsyncMock()

        # Add a mock session
        mock_session = AsyncMock()
        mock_session.metadata = SessionMetadata(session_id="s1")
        mock_session._heartbeat_monitor = Mock()
        mock_session._heartbeat_monitor.stop = AsyncMock()
        mock_session._heartbeat_monitor.heartbeat_count = 0
        mock_session.context = AsyncMock()
        mock_session._metadata_file = str(Path(tmp_storage) / "s1" / "metadata.json")
        engine._sessions["s1"] = mock_session

        # Patch close_session to just clear the session
        original_sessions = engine._sessions.copy()
        with patch.object(engine, "close_session", new_callable=AsyncMock) as mock_close:
            await engine.stop()
            mock_close.assert_called_once_with("s1")

    # -- get_session ---

    @pytest.mark.asyncio
    async def test_get_session_exists(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        mock_session = Mock()
        engine._sessions["s1"] = mock_session

        result = await engine.get_session("s1")
        assert result is mock_session

    @pytest.mark.asyncio
    async def test_get_session_not_exists(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        result = await engine.get_session("nonexistent")
        assert result is None

    # -- create_session ---

    @pytest.mark.asyncio
    async def test_create_session_not_running(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        with pytest.raises(RuntimeError, match="浏览器引擎未启动"):
            await engine.create_session("test")

    @pytest.mark.asyncio
    async def test_create_session_duplicate(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True
        engine._browser = Mock()
        engine._sessions["existing"] = Mock()

        with pytest.raises(RuntimeError, match="已存在"):
            await engine.create_session("existing")

    @pytest.mark.asyncio
    async def test_create_session_success(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True

        mock_page = _make_mock_page()
        mock_context = _make_mock_context()
        mock_context.new_page.return_value = mock_page

        mock_browser = _make_mock_browser()
        mock_browser.new_context.return_value = mock_context
        engine._browser = mock_browser

        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session = await engine.create_session("new-session")

        assert isinstance(session, BrowserSession)
        assert session.session_id == "new-session"
        assert "new-session" in engine._sessions

        # Should have injected stealth scripts
        assert mock_context.add_init_script.call_count == 5

    @pytest.mark.asyncio
    async def test_create_session_with_url(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        engine._started = True

        mock_page = _make_mock_page()
        mock_response = Mock()
        mock_response.status = 200
        mock_page.goto.return_value = mock_response
        mock_page.title.return_value = "Target"

        mock_context = _make_mock_context()
        mock_context.new_page.return_value = mock_page

        mock_browser = _make_mock_browser()
        mock_browser.new_context.return_value = mock_context
        engine._browser = mock_browser

        with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
            session = await engine.create_session("url-sess", url="http://target.com")

        mock_page.goto.assert_called_once()

    # -- close_session ---

    @pytest.mark.asyncio
    async def test_close_session_not_exists(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        await engine.close_session("nonexistent")  # should not error

    @pytest.mark.asyncio
    async def test_close_session_success(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)

        # Create storage dir for metadata
        sess_dir = Path(tmp_storage) / "cs1"
        sess_dir.mkdir(parents=True, exist_ok=True)

        mock_page = _make_mock_page()
        mock_context = _make_mock_context()
        session = BrowserSession("cs1", mock_context, mock_page, tmp_storage)

        with patch.object(session._heartbeat_monitor, "stop", new_callable=AsyncMock):
            with patch("kali_mcp.core.browser_engine.HAS_PLAYWRIGHT", True):
                session.context.cookies = AsyncMock(return_value=[])
                engine._sessions["cs1"] = session

                await engine.close_session("cs1")

        assert "cs1" not in engine._sessions
        assert session.metadata.status == "closed"
        mock_context.close.assert_called_once()

    # -- list_sessions ---

    @pytest.mark.asyncio
    async def test_list_sessions_empty(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)
        result = await engine.list_sessions()
        assert result == []

    @pytest.mark.asyncio
    async def test_list_sessions_with_sessions(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)

        mock_page = _make_mock_page()
        mock_context = _make_mock_context()
        session = BrowserSession("ls1", mock_context, mock_page, tmp_storage)
        session.metadata.url = "http://example.com"
        session.metadata.page_title = "Example"

        engine._sessions["ls1"] = session

        result = await engine.list_sessions()

        assert len(result) == 1
        assert result[0]["session_id"] == "ls1"
        assert result[0]["url"] == "http://example.com"
        assert "heartbeat_ws_count" in result[0]
        assert "heartbeat_http_count" in result[0]
        assert "network_log_size" in result[0]

    # -- async context manager ---

    @pytest.mark.asyncio
    async def test_async_context_manager(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)

        with patch.object(engine, "start", new_callable=AsyncMock) as mock_start:
            with patch.object(engine, "stop", new_callable=AsyncMock) as mock_stop:
                async with engine as eng:
                    assert eng is engine
                    mock_start.assert_called_once()

                mock_stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_context_manager_stop_on_exception(self, tmp_storage):
        engine = StealthBrowserEngine(storage_dir=tmp_storage)

        with patch.object(engine, "start", new_callable=AsyncMock):
            with patch.object(engine, "stop", new_callable=AsyncMock) as mock_stop:
                try:
                    async with engine:
                        raise ValueError("test error")
                except ValueError:
                    pass

                mock_stop.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════
# get_engine_status
# ═══════════════════════════════════════════════════════════════════════════

class TestGetEngineStatus:
    def test_no_engine(self):
        status = get_engine_status()

        assert status["engine_running"] is False
        assert status["active_sessions"] == 0
        assert status["sessions"] == []
        assert status["uptime_seconds"] == 0.0
        assert status["storage_dir"] == DEFAULT_STORAGE_DIR
        assert status["headless"] is True
        assert status["proxy_configured"] is False
        assert "playwright_available" in status

    def test_with_stopped_engine(self, tmp_path):
        engine = StealthBrowserEngine(storage_dir=str(tmp_path))
        status = get_engine_status(engine)

        assert status["engine_running"] is False
        assert status["storage_dir"] == str(tmp_path)

    def test_with_running_engine(self, tmp_path):
        engine = StealthBrowserEngine(
            storage_dir=str(tmp_path),
            headless=False,
            proxy="http://proxy:8080",
        )
        engine._started = True
        engine._start_time = time.time() - 60

        status = get_engine_status(engine)

        assert status["engine_running"] is True
        assert status["headless"] is False
        assert status["proxy_configured"] is True
        assert status["uptime_seconds"] >= 59.0
        assert status["storage_dir"] == str(tmp_path)

    def test_with_sessions(self, tmp_path):
        engine = StealthBrowserEngine(storage_dir=str(tmp_path))
        engine._started = True
        engine._start_time = time.time()

        mock_page = _make_mock_page()
        mock_context = _make_mock_context()
        session = BrowserSession("status-sess", mock_context, mock_page, str(tmp_path))
        session.metadata.url = "http://target.com"
        session.metadata.page_title = "Target"
        session.metadata.heartbeat_active = True

        engine._sessions["status-sess"] = session

        status = get_engine_status(engine)

        assert status["active_sessions"] == 1
        assert len(status["sessions"]) == 1
        sess_info = status["sessions"][0]
        assert sess_info["session_id"] == "status-sess"
        assert sess_info["url"] == "http://target.com"
        assert sess_info["heartbeat_active"] is True


# ═══════════════════════════════════════════════════════════════════════════
# HEARTBEAT_URL_PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

class TestHeartbeatUrlPatterns:
    @pytest.mark.parametrize("url", [
        "http://example.com/api/heartbeat",
        "http://example.com/ping",
        "http://example.com/pong",
        "http://example.com/keepalive",
        "http://example.com/health",
        "http://example.com/poll",
        "http://example.com/beacon",
        "http://example.com/__refresh",
        "http://example.com/_poll",
        "http://example.com/longpoll",
        "http://example.com/sse",
        "http://example.com/event-stream",
        "http://example.com/alive",
    ])
    def test_matches_heartbeat_urls(self, url):
        assert HEARTBEAT_URL_PATTERNS.search(url) is not None

    @pytest.mark.parametrize("url", [
        "http://example.com/api/users",
        "http://example.com/login",
        "http://example.com/static/style.css",
        "http://example.com/data/export",
    ])
    def test_no_match_non_heartbeat_urls(self, url):
        assert HEARTBEAT_URL_PATTERNS.search(url) is None


# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

class TestConstants:
    def test_default_storage_dir(self):
        assert DEFAULT_STORAGE_DIR == "/tmp/kali_mcp_browser_sessions"

    def test_default_user_agent(self):
        assert "Mozilla" in DEFAULT_USER_AGENT
        assert "Chrome" in DEFAULT_USER_AGENT

    def test_default_viewport(self):
        assert DEFAULT_VIEWPORT["width"] == 1920
        assert DEFAULT_VIEWPORT["height"] == 1080

    def test_heartbeat_min_samples(self):
        assert HEARTBEAT_MIN_SAMPLES == 3
