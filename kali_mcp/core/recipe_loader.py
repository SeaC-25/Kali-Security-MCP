#!/usr/bin/env python3
"""YAML tool recipe loader and command renderer (Phase3 pilot)."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from kali_mcp.core.shell_utils import sanitize_shell_arg, sanitize_shell_fragment

logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

_RECIPE_CACHE: Dict[str, Dict[str, Any]] = {}
_LOADED = False


def recipes_dir() -> Path:
    env = (os.environ.get("KALI_MCP_RECIPES_DIR") or "").strip()
    if env:
        return Path(env).expanduser().resolve()
    # kali_mcp/core -> repo root
    return Path(__file__).resolve().parents[2] / "tools_recipes"


def _load_all() -> None:
    global _LOADED, _RECIPE_CACHE
    if _LOADED:
        return
    _RECIPE_CACHE = {}
    root = recipes_dir()
    if yaml is None:
        logger.debug("PyYAML not available; recipes disabled")
        _LOADED = True
        return
    if not root.is_dir():
        _LOADED = True
        return
    for path in sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            tool = str(data.get("tool") or data.get("id") or path.stem).strip()
            if not tool:
                continue
            data["_path"] = str(path)
            _RECIPE_CACHE[tool] = data
            rid = str(data.get("id") or "").strip()
            if rid and rid != tool:
                _RECIPE_CACHE[rid] = data
        except Exception as e:
            logger.warning("recipe load failed %s: %s", path, e)
    _LOADED = True


def reset_recipes() -> None:
    global _LOADED, _RECIPE_CACHE
    _LOADED = False
    _RECIPE_CACHE = {}


def list_recipes() -> List[str]:
    _load_all()
    tools = sorted({str(v.get("tool") or k) for k, v in _RECIPE_CACHE.items() if isinstance(v, dict)})
    return tools


def get_recipe(tool_or_id: str) -> Optional[Dict[str, Any]]:
    _load_all()
    return _RECIPE_CACHE.get((tool_or_id or "").strip())


def _pick_target(data: Dict[str, Any], keys: List[str]) -> str:
    for k in keys:
        v = data.get(k)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            for item in v:
                s = str(item).strip()
                if s:
                    return s
        s = str(v).strip()
        if s:
            # multi-token: first
            return s.split()[0]
    return ""


def render_recipe_command(tool_name: str, data: Dict[str, Any]) -> str:
    """
    Render shell command from YAML recipe if present.
    Returns "" when no recipe or render fails (caller falls back to registry).
    """
    if data.get("no_recipe") or data.get("skip_recipe"):
        return ""
    recipe = get_recipe(str(data.get("recipe_id") or tool_name))
    if not recipe:
        return ""
    params = recipe.get("params") or {}
    defaults = dict(params.get("defaults") or {})
    target_keys = list(params.get("target_keys") or ["target", "url", "host"])
    target = _pick_target(data, target_keys)
    # also accept url as url field for gobuster-style templates
    url = str(data.get("url") or data.get("target") or target or "").strip()
    if url and "://" not in url and tool_name in {"gobuster", "whatweb", "httpx", "nuclei"}:
        # leave as-is; recipe consumers may pass host-only for nmap
        pass
    if not target and not url:
        logger.debug("recipe %s missing target", tool_name)
        return ""

    ctx: Dict[str, Any] = dict(defaults)
    # overlay data keys that match template fields
    for k, v in data.items():
        if k in {"additional_args", "recipe_id", "no_recipe", "skip_recipe", "task_id", "phase"}:
            continue
        if v is None:
            continue
        ctx[k] = v
    ctx["target"] = sanitize_shell_arg(target or url)
    ctx["url"] = sanitize_shell_arg(url or target)
    ctx["host"] = sanitize_shell_arg(str(data.get("host") or target or url).split("://")[-1].split("/")[0])

    # binary overrides (httpx go binary)
    binary = str(data.get("binary") or recipe.get("binary") or tool_name)
    if tool_name == "httpx":
        try:
            from kali_mcp.core.tool_registry import _resolve_projectdiscovery_httpx

            binary = _resolve_projectdiscovery_httpx()
        except Exception:
            pass
    if binary != tool_name and binary not in {"httpx", "nmap", "gobuster", "whatweb", "nuclei"}:
        ctx["binary"] = sanitize_shell_arg(binary)
    else:
        ctx["binary"] = binary if binary == tool_name else sanitize_shell_arg(binary)

    # sanitize string defaults used in template
    for key in (
        "scan_type",
        "ports",
        "mode",
        "wordlist",
        "threads",
        "severity",
        "aggression",
        "timeout",
        "retries",
        "rate_limit",
        "maxtime",
        "depth",
        "level",
        "risk",
    ):
        if key in ctx and ctx[key] is not None:
            val = str(ctx[key])
            if key in {"scan_type"}:
                ctx[key] = sanitize_shell_fragment(val)
            elif key in {
                "ports",
                "severity",
                "mode",
                "threads",
                "aggression",
                "timeout",
                "retries",
                "rate_limit",
                "maxtime",
                "depth",
                "level",
                "risk",
            }:
                # keep simple tokens
                ctx[key] = sanitize_shell_arg(val) if " " in val else val
            else:
                ctx[key] = sanitize_shell_arg(val)

    cmd_spec = recipe.get("command") or {}
    template = str(cmd_spec.get("template") or "").strip()
    if not template:
        return ""
    try:
        cmd = template.format(**ctx)
    except Exception as e:
        logger.warning("recipe render failed tool=%s: %s", tool_name, e)
        return ""

    extra_key = str(cmd_spec.get("extra_args_key") or "additional_args")
    extra = data.get(extra_key) or ""
    if extra:
        cmd = f"{cmd} {sanitize_shell_fragment(str(extra))}"
    return cmd.strip()
