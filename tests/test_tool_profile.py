"""
Tests for ToolProfile (kali_mcp/security/tool_profile.py)

Covers:
- Profile loading (strict, compliance, full)
- Module allow/deny logic
- Force enable/disable overrides
- Environment variable configuration
"""

import os
from unittest.mock import patch

import pytest

from kali_mcp.security.tool_profile import (
    ToolProfile,
    load_tool_profile,
    SUPPORTED_PROFILES,
    ALL_MODULE_KEYS,
    DEFAULT_DISABLED_BY_PROFILE,
    _norm_set,
    _env_csv,
)


class TestNormSet:
    """Test _norm_set helper."""

    def test_basic(self):
        assert _norm_set(["A", "B"]) == {"a", "b"}

    def test_strips_whitespace(self):
        assert _norm_set(["  foo  ", "BAR"]) == {"foo", "bar"}

    def test_filters_empty(self):
        assert _norm_set(["", "  ", "valid"]) == {"valid"}

    def test_handles_none_values(self):
        assert _norm_set([None, "ok"]) == {"ok"}


class TestEnvCsv:
    """Test _env_csv helper."""

    @patch.dict(os.environ, {"TEST_VAR": "a,b,c"})
    def test_comma_separated(self):
        assert _env_csv("TEST_VAR") == {"a", "b", "c"}

    @patch.dict(os.environ, {"TEST_VAR": ""})
    def test_empty(self):
        assert _env_csv("TEST_VAR") == set()

    def test_missing_var(self):
        assert _env_csv("NONEXISTENT_VAR_XYZ") == set()


class TestToolProfile:
    """Test ToolProfile dataclass."""

    def test_allows_enabled_module(self):
        profile = ToolProfile(name="test", disabled=set(), force_enabled=set())
        assert profile.allows("recon") is True

    def test_denies_disabled_module(self):
        profile = ToolProfile(name="test", disabled={"recon"}, force_enabled=set())
        assert profile.allows("recon") is False

    def test_force_enable_overrides_disable(self):
        profile = ToolProfile(name="test", disabled={"recon"}, force_enabled={"recon"})
        assert profile.allows("recon") is True

    def test_empty_key_denied(self):
        profile = ToolProfile(name="test", disabled=set(), force_enabled=set())
        assert profile.allows("") is False
        assert profile.allows(None) is False

    def test_summary(self):
        profile = ToolProfile(name="test", disabled={"apt", "pwn"}, force_enabled={"ctf"})
        s = profile.summary()
        assert s["profile"] == "test"
        assert "apt" in s["disabled_modules"]
        assert "ctf" in s["force_enabled_modules"]


class TestLoadToolProfile:
    """Test load_tool_profile function."""

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_default_compliance(self):
        profile = load_tool_profile()
        assert profile.name == "compliance"
        assert profile.disabled == set()

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_strict_profile(self):
        profile = load_tool_profile("strict")
        assert profile.name == "strict"
        assert len(profile.disabled) > 0
        # assessment is NOT disabled in strict
        assert profile.allows("assessment") is True
        # v2 should be disabled
        assert profile.allows("v2") is False

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_full_profile(self):
        profile = load_tool_profile("full")
        assert profile.name == "full"
        assert profile.disabled == set()

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_invalid_profile_fallback(self):
        profile = load_tool_profile("nonexistent")
        assert profile.name == "compliance"

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_force_enable_parameter(self):
        profile = load_tool_profile("strict", force_enable=["v2"])
        assert profile.allows("v2") is True

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_force_disable_parameter(self):
        profile = load_tool_profile("full", force_disable=["apt"])
        assert profile.allows("apt") is False

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "strict",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "ctf,pwn",
    })
    def test_env_force_enable(self):
        profile = load_tool_profile()
        assert profile.allows("ctf") is True
        assert profile.allows("pwn") is True

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "full",
        "KALI_MCP_FORCE_DISABLE_MODULES": "apt,ctf",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_env_force_disable(self):
        profile = load_tool_profile()
        assert profile.allows("apt") is False
        assert profile.allows("ctf") is False

    @patch.dict(os.environ, {
        "KALI_MCP_TOOL_PROFILE": "",
        "KALI_MCP_FORCE_DISABLE_MODULES": "",
        "KALI_MCP_FORCE_ENABLE_MODULES": "",
    })
    def test_unknown_module_filtered(self):
        """Force enabling unknown module key is silently ignored."""
        profile = load_tool_profile("full", force_disable=["totally_unknown_module"])
        # Should not crash, unknown key just gets filtered out
        assert profile.name == "full"


class TestProfileConstants:
    """Test module-level constants."""

    def test_supported_profiles(self):
        assert "strict" in SUPPORTED_PROFILES
        assert "compliance" in SUPPORTED_PROFILES
        assert "full" in SUPPORTED_PROFILES

    def test_all_module_keys_non_empty(self):
        assert len(ALL_MODULE_KEYS) > 10

    def test_strict_disables_most(self):
        strict_disabled = DEFAULT_DISABLED_BY_PROFILE["strict"]
        assert len(strict_disabled) > 10
