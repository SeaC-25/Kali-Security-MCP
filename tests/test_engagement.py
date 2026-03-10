"""
Tests for EngagementManager (kali_mcp/security/engagement.py)

Covers:
- EngagementContext creation and validation
- Scope checking (IP, CIDR, domain, wildcard, out-of-scope)
- Target validation
- Tool allowance by profile
- Context lifecycle (set, get, clear, active check)
- Environment variable loading
- Target extraction from text
"""

import os
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

from kali_mcp.security.engagement import (
    EngagementManager,
    EngagementContext,
    _to_list,
    _parse_dt,
    TARGET_PATTERN,
)


class TestToList:
    """Test _to_list helper."""

    def test_none_returns_empty(self):
        assert _to_list(None) == []

    def test_empty_string_returns_empty(self):
        assert _to_list("") == []

    def test_single_string(self):
        assert _to_list("10.0.0.1") == ["10.0.0.1"]

    def test_comma_separated(self):
        assert _to_list("10.0.0.1, 10.0.0.2") == ["10.0.0.1", "10.0.0.2"]

    def test_list_input(self):
        assert _to_list(["a", "b"]) == ["a", "b"]

    def test_list_strips_whitespace(self):
        assert _to_list(["  a ", " b  "]) == ["a", "b"]

    def test_list_filters_empty(self):
        assert _to_list(["a", "", "  ", "b"]) == ["a", "b"]


class TestParseDt:
    """Test _parse_dt helper."""

    def test_iso_format(self):
        dt = _parse_dt("2026-01-01T00:00:00+00:00")
        assert dt is not None
        assert dt.year == 2026

    def test_date_only(self):
        dt = _parse_dt("2026-06-15")
        assert dt is not None
        assert dt.month == 6

    def test_z_suffix(self):
        dt = _parse_dt("2026-01-01T12:00:00Z")
        assert dt is not None

    def test_invalid_returns_none(self):
        assert _parse_dt("not-a-date") is None

    def test_empty_returns_none(self):
        assert _parse_dt("") is None


class TestEngagementManagerInit:
    """Test EngagementManager initialization."""

    @patch.dict(os.environ, {"KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0"}, clear=False)
    def test_require_context_false(self):
        mgr = EngagementManager()
        assert mgr.require_context is False

    @patch.dict(os.environ, {"KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "1"}, clear=False)
    def test_require_context_true(self):
        mgr = EngagementManager()
        assert mgr.require_context is True

    @patch.dict(os.environ, {
        "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
        "KALI_MCP_ENGAGEMENT_JSON": "",
        "KALI_MCP_ENGAGEMENT_FILE": "",
    }, clear=False)
    def test_no_context_by_default(self):
        mgr = EngagementManager()
        assert mgr.context is None


class TestSetContext:
    """Test setting engagement context."""

    def _make_mgr(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            return EngagementManager()

    def _valid_data(self, **overrides):
        data = {
            "authorization_id": "AUTH-001",
            "client": "TestCorp",
            "authorized_by": "Admin",
            "valid_from": "2020-01-01",
            "valid_until": "2030-12-31",
            "target_scope": ["10.0.0.0/8", "*.example.com"],
        }
        data.update(overrides)
        return data

    def test_set_valid_context(self):
        mgr = self._make_mgr()
        result = mgr.set_context(self._valid_data())
        assert result["authorization_id"] == "AUTH-001"
        assert mgr.context is not None

    def test_missing_required_field_raises(self):
        mgr = self._make_mgr()
        with pytest.raises(ValueError, match="Missing required fields"):
            mgr.set_context({"authorization_id": "AUTH-001"})

    def test_clear_context(self):
        mgr = self._make_mgr()
        mgr.set_context(self._valid_data())
        mgr.clear_context()
        assert mgr.context is None

    def test_get_context_empty(self):
        mgr = self._make_mgr()
        assert mgr.get_context() == {}

    def test_get_context_includes_active(self):
        mgr = self._make_mgr()
        mgr.set_context(self._valid_data())
        ctx = mgr.get_context()
        assert "active" in ctx


class TestIsContextActive:
    """Test time-based context activation."""

    def _make_mgr_with_context(self, valid_from, valid_until):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        mgr.set_context({
            "authorization_id": "AUTH-001",
            "client": "Test",
            "authorized_by": "Admin",
            "valid_from": valid_from,
            "valid_until": valid_until,
            "target_scope": ["10.0.0.0/8"],
        })
        return mgr

    def test_active_context(self):
        mgr = self._make_mgr_with_context("2020-01-01", "2030-12-31")
        assert mgr.is_context_active() is True

    def test_expired_context(self):
        mgr = self._make_mgr_with_context("2020-01-01", "2020-12-31")
        assert mgr.is_context_active() is False

    def test_future_context(self):
        mgr = self._make_mgr_with_context("2030-01-01", "2030-12-31")
        assert mgr.is_context_active() is False

    def test_no_context(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        assert mgr.is_context_active() is False


class TestScopeValidation:
    """Test _in_scope for various target types."""

    def _make_mgr(self, scope, out_of_scope=None):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        mgr.set_context({
            "authorization_id": "AUTH-001",
            "client": "Test",
            "authorized_by": "Admin",
            "valid_from": "2020-01-01",
            "valid_until": "2030-12-31",
            "target_scope": scope,
            "out_of_scope": out_of_scope or [],
        })
        return mgr

    def test_ip_in_cidr(self):
        mgr = self._make_mgr(["10.0.0.0/8"])
        assert mgr._in_scope("10.1.2.3") is True

    def test_ip_not_in_cidr(self):
        mgr = self._make_mgr(["10.0.0.0/8"])
        assert mgr._in_scope("192.168.1.1") is False

    def test_exact_domain_match(self):
        mgr = self._make_mgr(["example.com"])
        assert mgr._in_scope("example.com") is True

    def test_subdomain_match(self):
        mgr = self._make_mgr(["example.com"])
        assert mgr._in_scope("sub.example.com") is True

    def test_wildcard_domain(self):
        mgr = self._make_mgr(["*.example.com"])
        assert mgr._in_scope("sub.example.com") is True
        assert mgr._in_scope("example.com") is True

    def test_url_normalized(self):
        mgr = self._make_mgr(["example.com"])
        assert mgr._in_scope("http://example.com/path") is True

    def test_out_of_scope_blocks(self):
        mgr = self._make_mgr(["*.example.com"], ["admin.example.com"])
        assert mgr._in_scope("admin.example.com") is False
        assert mgr._in_scope("other.example.com") is True

    def test_empty_host_allowed(self):
        mgr = self._make_mgr(["10.0.0.0/8"])
        assert mgr._in_scope("") is True

    def test_no_context_require_false(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        assert mgr._in_scope("anything") is True

    def test_no_context_require_true(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "1",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        assert mgr._in_scope("anything") is False


class TestValidateTargets:
    """Test validate_targets method."""

    def _make_mgr(self, scope):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        mgr.set_context({
            "authorization_id": "AUTH-001",
            "client": "Test",
            "authorized_by": "Admin",
            "valid_from": "2020-01-01",
            "valid_until": "2030-12-31",
            "target_scope": scope,
        })
        return mgr

    def test_in_scope_target(self):
        mgr = self._make_mgr(["10.0.0.0/8"])
        ok, msg = mgr.validate_targets(["10.1.2.3"])
        assert ok is True

    def test_out_of_scope_target(self):
        mgr = self._make_mgr(["10.0.0.0/8"])
        ok, msg = mgr.validate_targets(["192.168.1.1"])
        assert ok is False
        assert "out of scope" in msg.lower()

    def test_no_context_require_true(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "1",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        ok, msg = mgr.validate_targets(["10.0.0.1"])
        assert ok is False

    def test_empty_targets_allowed(self):
        mgr = self._make_mgr(["10.0.0.0/8"])
        ok, msg = mgr.validate_targets([])
        assert ok is True


class TestToolAllowed:
    """Test is_tool_allowed method."""

    def test_full_profile_allows_all(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_TOOL_PROFILE": "full",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        ok, _ = mgr.is_tool_allowed("nmap")
        assert ok is True

    def test_compliance_profile_allows_normal_tools(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_TOOL_PROFILE": "compliance",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        ok, _ = mgr.is_tool_allowed("nmap")
        assert ok is True


class TestExtractTargets:
    """Test extract_targets static method."""

    def test_extract_ips(self):
        targets = EngagementManager.extract_targets("scan 10.0.0.1 and 192.168.1.1")
        assert "10.0.0.1" in targets
        assert "192.168.1.1" in targets

    def test_extract_domains(self):
        targets = EngagementManager.extract_targets("check https://example.com/path")
        assert any("example.com" in t for t in targets)

    def test_empty_input(self):
        assert EngagementManager.extract_targets("") == []
        assert EngagementManager.extract_targets(None) == []


class TestRenderContextBlock:
    """Test render_context_block method."""

    def test_no_context(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        assert "No engagement" in mgr.render_context_block()

    def test_with_context(self):
        with patch.dict(os.environ, {
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": "0",
            "KALI_MCP_ENGAGEMENT_JSON": "",
            "KALI_MCP_ENGAGEMENT_FILE": "",
        }):
            mgr = EngagementManager()
        mgr.set_context({
            "authorization_id": "AUTH-001",
            "client": "TestCorp",
            "authorized_by": "Admin",
            "valid_from": "2020-01-01",
            "valid_until": "2030-12-31",
            "target_scope": ["10.0.0.0/8"],
        })
        block = mgr.render_context_block()
        assert "AUTH-001" in block
        assert "TestCorp" in block
