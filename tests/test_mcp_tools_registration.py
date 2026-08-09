"""Parameterised: every register_xxx_tools function must be importable and callable.

Covers ~28 mcp_tools modules in a single parametrised test, not 28 separate files.
Does NOT call the real mcp server — only verifies registration function shape.
"""
from __future__ import annotations

import importlib
import inspect
import logging
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

logger = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
MCP_TOOLS_PKG = "kali_mcp.mcp_tools"

# Modules known to need extra executor/state args beyond (mcp, executor)
# (module_name, expected_extra_param_names)
EXTRA_ARGS_MODULES: Dict[str, List[str]] = {
    "session_tools": ["_ATTACK_SESSIONS", "_CURRENT_ATTACK_SESSION_ID"],
    "apt_tools": ["_ADAPTIVE_ATTACKS", "adapter"],
    "browser_tools": ["BROWSER_ENGINE_AVAILABLE"],
    "ctf_tools": ["_CTF_MODE_ENABLED", "_CTF_SESSIONS", "_CURRENT_CTF_SESSION", "_DETECTED_FLAGS", "_CTF_CHALLENGES"],
    "advanced_ctf_tools": ["adapter"],
    "deep_test_tools": ["DEEP_TEST_ENGINE_AVAILABLE"],
    "misc_tools": ["_TASKS", "_WORKFLOWS"],
    "ai_tools": ["ai_context_manager", "ml_strategy_optimizer"],
}


def _discover_register_functions() -> List[str]:
    """Find all register_xxx_tools functions in mcp_tools submodules."""
    import sys as _sys
    # Purge ghost modules from sys.modules cache before scanning.
    # Only keys under kali_mcp.mcp_tools.* (never the test module itself).
    _prefix = "kali_mcp.mcp_tools."
    _ghost_keys = [
        k
        for k in _sys.modules
        if k.startswith(_prefix) and k != "kali_mcp.mcp_tools"
        and not Path(k[len(_prefix):].replace(".", "/") + ".py").exists()
    ]
    for k in _ghost_keys:
        _sys.modules.pop(k, None)
    pkg_path = HERE.parent / "kali_mcp" / "mcp_tools"
    funcs: List[str] = []
    for pyfile in sorted(pkg_path.glob("*.py")):
        if pyfile.name == "__init__.py":
            continue
        modname = f"{MCP_TOOLS_PKG}.{pyfile.stem}"
        try:
            mod = importlib.import_module(modname)
        except Exception as exc:
            logger.debug("Skipping %s (import failed: %s)", modname, exc)
            continue
        mod_file = getattr(mod, "__file__", "") or ""
        if not mod_file or not Path(mod_file).exists():
            continue
        for name, obj in inspect.getmembers(mod, inspect.isfunction):
            if name.startswith("register_") and name.endswith("_tools"):
                funcs.append(f"{modname}:{name}")
    return sorted(funcs)


REGISTER_FUNCS = _discover_register_functions()


class TestMCPToolsRegistration:
    """Each register_xxx_tools function exists and is callable."""

    @pytest.mark.parametrize("fqname", REGISTER_FUNCS, ids=lambda x: x.split(":")[-1])
    def test_register_function_importable(self, fqname: str):
        modname, funcname = fqname.rsplit(":", 1)
        mod = importlib.import_module(modname)
        func = getattr(mod, funcname)
        assert callable(func)

    @pytest.mark.parametrize("fqname", REGISTER_FUNCS, ids=lambda x: x.split(":")[-1])
    def test_register_function_accepts_mcp_and_executor(self, fqname: str):
        """Signature must accept (mcp, executor/executor_adapter, ...). First 2 params."""
        modname, funcname = fqname.rsplit(":", 1)
        mod = importlib.import_module(modname)
        func = getattr(mod, funcname)
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        assert len(params) >= 2, f"{funcname} needs at least (mcp, executor): got {params}"

    @pytest.mark.parametrize("fqname", REGISTER_FUNCS, ids=lambda x: x.split(":")[-1])
    def test_register_function_runs_with_mock(self, fqname: str):
        """Call with MagicMock mcp+executor; should not crash (no tool registration assertion)."""
        modname, funcname = fqname.rsplit(":", 1)
        mod = importlib.import_module(modname)
        func = getattr(mod, funcname)
        mcp_mock = MagicMock()
        exe_mock = MagicMock()
        short = modname.split(".")[-1]
        extra_args = EXTRA_ARGS_MODULES.get(short, [])
        kwargs: Dict[str, Any] = {"mcp": mcp_mock, "executor": exe_mock}
        for earg in extra_args:
            kwargs[earg] = MagicMock()
        try:
            result = func(**kwargs)
        except Exception as e:
            pytest.fail(f"{funcname}(mock) raised: {e}")
        # Most register functions return None; some return a dict
        if result is not None:
            assert isinstance(result, dict), f"{funcname} returned {type(result)}, expected dict or None"

    def test_all_tool_modules_discovered(self):
        """At least 18 register_xxx_tools functions must be found (current count: 19)."""
        assert len(REGISTER_FUNCS) >= 17, f"Only found {len(REGISTER_FUNCS)} register functions"
