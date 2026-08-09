"""Test security layer: engagement scope guard + tool profile control."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from kali_mcp.security.engagement import (
    EngagementContext,
    EngagementManager,
    _parse_dt,
    _to_list,
)
from kali_mcp.security.tool_profile import (
    ALL_MODULE_KEYS,
    SUPPORTED_PROFILES,
    ToolProfile,
    load_tool_profile,
    _norm_set,
)


class TestEngagementHelpers(unittest.TestCase):
    """Pure helpers."""

    def test_to_list_none(self):
        self.assertEqual(_to_list(None), [])

    def test_to_list_empty(self):
        self.assertEqual(_to_list(""), [])

    def test_to_list_single(self):
        self.assertEqual(_to_list("http://a/"), ["http://a/"])

    def test_to_list_comma(self):
        self.assertEqual(_to_list("a, b ,c"), ["a", "b", "c"])

    def test_to_list_list_input(self):
        self.assertEqual(_to_list(["x", "", " y "]), ["x", "y"])

    def test_parse_dt_iso_with_t(self):
        self.assertIsNotNone(_parse_dt("2026-01-01T00:00:00Z"))

    def test_parse_dt_date_only(self):
        self.assertIsNotNone(_parse_dt("2026-01-01"))

    def test_parse_dt_invalid(self):
        self.assertIsNone(_parse_dt("not-a-date"))


class TestEngagementManager(unittest.TestCase):
    """Context set/clear/validate + render."""

    def setUp(self):
        self.mgr = EngagementManager()
        self.valid = {
            "authorization_id": "AUTH-001",
            "client": "Internal",
            "authorized_by": "CISO",
            "valid_from": "2026-01-01",
            "valid_until": "2026-12-31",
            "target_scope": ["example.com", "10.0.0.0/8"],
        }

    def test_default_no_context(self):
        self.assertEqual(self.mgr.get_context(), {})

    def test_set_profile(self):
        self.assertEqual(self.mgr.set_profile("strict"), "strict")

    def test_set_profile_default(self):
        self.assertEqual(self.mgr.set_profile(""), "compliance")

    def test_set_context_valid(self):
        out = self.mgr.set_context(self.valid)
        self.assertEqual(out.get("authorization_id"), "AUTH-001")
        self.assertEqual(out.get("target_scope"), ["example.com", "10.0.0.0/8"])
        self.assertIn("active", out)

    def test_set_context_missing_fields_raises(self):
        bad = dict(self.valid)
        del bad["target_scope"]
        with self.assertRaises(ValueError):
            self.mgr.set_context(bad)

    def test_clear_context(self):
        self.mgr.set_context(self.valid)
        self.mgr.clear_context()
        self.assertEqual(self.mgr.get_context(), {})

    def test_render_no_context(self):
        self.assertEqual(self.mgr.render_context_block(), "No engagement context configured")

    def test_render_with_context(self):
        self.mgr.set_context(self.valid)
        block = self.mgr.render_context_block()
        self.assertIn("AUTH-001", block)
        self.assertIn("Target Scope", block)

    def test_extract_targets(self):
        out = self.mgr.extract_targets("scan example.com and 10.0.0.5, skip 8.8.8.8")
        self.assertIn("example.com", out)
        self.assertIn("10.0.0.5", out)

    def test_extract_targets_empty(self):
        self.assertEqual(self.mgr.extract_targets(""), [])

    def test_scope_check_in_scope(self):
        self.mgr.set_context(self.valid)
        self.assertTrue(self.mgr._in_scope("http://example.com/admin"))

    def test_scope_check_subdomain_in_scope(self):
        self.mgr.set_context(self.valid)
        self.assertTrue(self.mgr._in_scope("http://sub.example.com/x"))

    def test_scope_check_out_of_scope(self):
        self.mgr.set_context(self.valid)
        self.assertFalse(self.mgr._in_scope("http://evil.org/"))

    def test_scope_check_suffix_confusion(self):
        self.mgr.set_context(self.valid)
        self.assertFalse(self.mgr._in_scope("http://notexample.com/"))

    def test_scope_check_no_context_default_allow(self):
        self.assertFalse(self.mgr.require_context)
        self.assertTrue(self.mgr._in_scope("http://example.com/"))

    def test_scope_check_cidr_in_scope(self):
        self.mgr.set_context(self.valid)
        self.assertTrue(self.mgr._in_scope("10.1.2.3"))

    def test_scope_check_cidr_out_of_scope(self):
        self.mgr.set_context(self.valid)
        self.assertFalse(self.mgr._in_scope("192.168.1.1"))

    def test_scope_check_oos_override(self):
        data = dict(self.valid)
        data["out_of_scope"] = ["example.com"]
        self.mgr.set_context(data)
        self.assertFalse(self.mgr._in_scope("http://example.com/x"))

    def test_scope_check_wildcard(self):
        data = dict(self.valid)
        data["target_scope"] = ["*.example.com"]
        self.mgr.set_context(data)
        self.assertTrue(self.mgr._in_scope("http://a.example.com/"))
        self.assertTrue(self.mgr._in_scope("http://example.com/"))

    def test_validate_targets_stub(self):
        ok, msg = self.mgr.validate_targets(["http://a/"])
        self.assertTrue(ok)
        self.assertIn("delegated", msg.lower())

    def test_is_tool_allowed_stub(self):
        ok, msg = self.mgr.is_tool_allowed("nmap")
        self.assertTrue(ok)
        self.assertIn("delegated", msg.lower())

    def test_load_from_env_json(self):
        with patch.dict(os.environ, {"KALI_MCP_ENGAGEMENT_JSON": json.dumps(self.valid)}):
            mgr = EngagementManager()
            self.assertEqual(mgr.get_context().get("authorization_id"), "AUTH-001")


class TestToolProfile(unittest.TestCase):
    """Profile allows/summary/load."""

    def test_supported_profiles(self):
        self.assertEqual(SUPPORTED_PROFILES, {"harness", "strict", "compliance", "full"})

    def test_allows_force_enabled(self):
        p = ToolProfile(name="test", disabled={"recon"}, force_enabled={"recon"})
        self.assertTrue(p.allows("recon"))

    def test_allows_not_disabled(self):
        p = ToolProfile(name="test", disabled={"recon"}, force_enabled=set())
        self.assertTrue(p.allows("harness"))

    def test_allows_disabled(self):
        p = ToolProfile(name="test", disabled={"recon"}, force_enabled=set())
        self.assertFalse(p.allows("recon"))

    def test_allows_empty_key_false(self):
        p = ToolProfile(name="test", disabled=set(), force_enabled=set())
        self.assertFalse(p.allows(""))

    def test_summary_shape(self):
        p = ToolProfile(name="strict", disabled={"apt"}, force_enabled={"harness"})
        s = p.summary()
        self.assertEqual(s["profile"], "strict")
        self.assertIn("apt", s["disabled_modules"])
        self.assertIn("harness", s["force_enabled_modules"])

    def test_load_harness_disables_all_but_harness(self):
        p = load_tool_profile("harness")
        self.assertEqual(p.name, "harness")
        self.assertTrue(p.allows("harness"))
        self.assertFalse(p.allows("recon"))
        self.assertFalse(p.allows("pwn"))

    def test_load_full_allows_all(self):
        p = load_tool_profile("full")
        self.assertTrue(p.allows("recon"))
        self.assertTrue(p.allows("pwn"))
        self.assertTrue(p.allows("apt"))

    def test_load_invalid_profile_falls_back_harness(self):
        p = load_tool_profile("bogus")
        self.assertEqual(p.name, "harness")

    def test_load_force_disable(self):
        p = load_tool_profile("full", force_disable=["pwn"])
        self.assertFalse(p.allows("pwn"))

    def test_load_force_enable_wins(self):
        p = load_tool_profile("harness", force_enable=["recon"])
        self.assertTrue(p.allows("recon"))

    def test_env_csv_empty(self):
        with patch.dict(os.environ, {}, clear=False):
            from kali_mcp.security.tool_profile import _env_csv
            self.assertEqual(_env_csv("KALI_MCP_FORCE_DISABLE_MODULES"), set())

    def test_env_csv_values(self):
        with patch.dict(os.environ, {"KALI_MCP_FORCE_DISABLE_MODULES": "apt,pwn, apt"}):
            from kali_mcp.security.tool_profile import _env_csv
            self.assertEqual(_env_csv("KALI_MCP_FORCE_DISABLE_MODULES"), {"apt", "pwn"})

    def test_norm_set(self):
        self.assertEqual(_norm_set(["A", " b ", "", None]), {"a", "b"})

    def test_load_unknown_keys_ignored(self):
        p = load_tool_profile("full", force_disable=["not_a_module"])
        self.assertEqual(p.disabled, set())


if __name__ == "__main__":
    unittest.main()
