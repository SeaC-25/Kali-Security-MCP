#!/usr/bin/env python3
"""Playbook registry."""

from .web_surface import run_web_surface
from .api_surface import run_api_surface
from .auth_surface import run_auth_surface
from .svc_surface import run_svc_surface
from .internal_lateral import run_internal_lateral
from .stealth import run_stealth_scan, check_ai_fingerprint
from .chain import (
    DEFAULT_DEPTHS,
    DEFAULT_SURFACE_ORDER,
    run_surface_chain,
)


def _resolve_target(target):
    """target 可能是 str 或 dict（来自 task workspace），统一转 str URL。"""
    if isinstance(target, dict):
        return str(target.get("url") or target.get("target") or target.get("host") or "")
    return str(target or "")


def _run_internal_lateral_playbook(task_id, target, executor, depth="standard", **kwargs):
    """internal_lateral playbook 适配器：符合 run_playbook 标准签名。"""
    from urllib.parse import urlparse
    t = _resolve_target(target)
    host = urlparse(t).netloc.split(":")[0] if "://" in t else t
    out = run_internal_lateral(
        executor=executor, target=host, depth=depth,
        domain=kwargs.get("domain", ""),
        user=kwargs.get("user", ""),
        password=kwargs.get("password", ""),
        userlist=kwargs.get("userlist", ""),
        passlist=kwargs.get("passlist", ""),
    )
    return {
        "ok": out.get("steps_ok", 0) > 0 or not out.get("steps_run"),
        "playbook": "internal_lateral",
        "depth": depth,
        "steps": out.get("steps", []),
        "findings": out.get("findings", []),
    }


def _run_stealth_playbook(task_id, target, executor, depth="standard", **kwargs):
    """stealth playbook 适配器：符合 run_playbook 标准签名。"""
    url = _resolve_target(target)
    out = run_stealth_scan(executor, url, tool="curl", use_proxy=True)
    fp = check_ai_fingerprint(executor, url)
    return {
        "ok": bool(out.get("success")),
        "playbook": "stealth",
        "depth": depth,
        "steps": [{"tool": "stealth_scan", "success": out.get("success")},
                  {"tool": "fingerprint_probe", "success": True}],
        "fingerprint_probe": fp.get("fingerprint_probe"),
    }


PLAYBOOKS = {
    "web_surface": run_web_surface,
    "api_surface": run_api_surface,
    "auth_surface": run_auth_surface,
    "svc_surface": run_svc_surface,
    "internal_lateral": _run_internal_lateral_playbook,
    "stealth": _run_stealth_playbook,
}


def list_playbooks():
    return sorted(PLAYBOOKS.keys())


def run_playbook(name: str, task_id: str, target: str, executor, depth: str = "standard", **kwargs):
    key = (name or "").strip().lower()
    fn = PLAYBOOKS.get(key)
    if not fn:
        return {"ok": False, "error": f"unknown playbook: {name}", "available": list_playbooks()}
    return fn(task_id=task_id, target=target, executor=executor, depth=depth, **kwargs)


__all__ = [
    "PLAYBOOKS",
    "DEFAULT_SURFACE_ORDER",
    "DEFAULT_DEPTHS",
    "list_playbooks",
    "run_playbook",
    "run_surface_chain",
]
