#!/usr/bin/env python3
"""Playbook registry."""

from .web_surface import run_web_surface
from .api_surface import run_api_surface
from .auth_surface import run_auth_surface
from .svc_surface import run_svc_surface
from .internal_lateral import run_internal_lateral
from .stealth import run_stealth_scan, check_ai_fingerprint
from .ai_guided import run_ai_guided
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


def _run_ai_guided_playbook(task_id, target, executor, depth="standard", **kwargs):
    """ai_guided 适配器：符合 run_playbook 标准签名 (task_id, target, executor, depth)。

    支持多目标：target 为 list 时透传给 run_ai_guided 的 targets 参数。
    """
    if isinstance(target, list):
        out = run_ai_guided(
            executor=executor, target=str(target[0]) if target else "", depth=depth,
            params=kwargs.get("params", ""),
            headers=kwargs.get("headers", ""),
            seq_file=kwargs.get("seq_file", ""),
            targets=target,
            task_id=task_id,
        )
    else:
        t = _resolve_target(target)
        out = run_ai_guided(
            executor=executor, target=t, depth=depth,
            params=kwargs.get("params", ""),
            headers=kwargs.get("headers", ""),
            seq_file=kwargs.get("seq_file", ""),
            task_id=task_id,
        )
    return {
        "ok": out.get("stages_ok", 0) > 0,
        "playbook": "ai_guided",
        "depth": depth,
        "stages": out.get("phases", []),
        "findings": out.get("findings", []),
    }


PLAYBOOKS = {
    "web_surface": run_web_surface,
    "api_surface": run_api_surface,
    "auth_surface": run_auth_surface,
    "svc_surface": run_svc_surface,
    "internal_lateral": _run_internal_lateral_playbook,
    "stealth": _run_stealth_playbook,
    "ai_guided": _run_ai_guided_playbook,
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
