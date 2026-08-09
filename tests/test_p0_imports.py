"""Verify key modules import cleanly (no missing deps, no top-level crashes)."""
from __future__ import annotations

import unittest


class TestModuleImports(unittest.TestCase):
    """Import-level smoke tests for modules with recent changes or high churn risk."""

    def test_chain_module_import(self):
        """kali_mcp.core.playbooks.chain imports without error."""
        import kali_mcp.core.playbooks.chain  # noqa: F811

    def test_chain_logger_present(self):
        """chain module has a logger configured."""
        from kali_mcp.core.playbooks.chain import logger
        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, "kali_mcp.core.playbooks.chain")

    def test_sql_injection_digger_removed(self):
        """sql_injection_digger was dead code (0 refs) and removed; spec is None or ModuleNotFoundError."""
        import importlib
        spec = None
        try:
            spec = importlib.util.find_spec("kali_mcp.diggers.sql_injection_digger")
        except ModuleNotFoundError:
            spec = None
        self.assertIsNone(spec, "diggers/ was deleted — find_spec must be None or raise ModuleNotFoundError")

    def test_harness_tools_import(self):
        """harness_tools MC tools module imports without error."""
        import kali_mcp.mcp_tools.harness_tools  # noqa: F811

    def test_report_export_import(self):
        """report_export module imports without error."""
        import kali_mcp.core.report_export  # noqa: F811

    def test_findings_store_import(self):
        """findings_store module imports without error."""
        import kali_mcp.core.findings_store  # noqa: F811

    def test_verifier_import(self):
        """verifier module imports without error."""
        import kali_mcp.core.verifier  # noqa: F811

    def test_observer_import(self):
        """observer module imports without error."""
        import kali_mcp.core.observer  # noqa: F811

    def test_insight_bridge_import(self):
        """insight_bridge module imports without error."""
        import kali_mcp.core.insight_bridge  # noqa: F811

    def test_tool_registry_import(self):
        """tool_registry module imports without error."""
        import kali_mcp.core.tool_registry  # noqa: F811

    def test_recipe_loader_import(self):
        """recipe_loader module imports without error."""
        import kali_mcp.core.recipe_loader  # noqa: F811

    def test_action_log_import(self):
        """action_log module imports without error."""
        import kali_mcp.core.action_log  # noqa: F811

    def test_harness_tools_package_import(self):
        """register_harness_tools accessible from package level."""
        from kali_mcp.mcp_tools import register_harness_tools
        self.assertTrue(callable(register_harness_tools))

    def test_harness_module_key_in_profile(self):
        """'harness' module key is defined in tool_profile ALL_MODULE_KEYS."""
        from kali_mcp.security.tool_profile import ALL_MODULE_KEYS
        self.assertIn("harness", ALL_MODULE_KEYS)
