#!/usr/bin/env python3
"""Playbook registry."""

from .web_surface import run_web_surface
from .api_surface import run_api_surface
from .auth_surface import run_auth_surface
from .svc_surface import run_svc_surface
from .chain import (
    DEFAULT_DEPTHS,
    DEFAULT_SURFACE_ORDER,
    run_surface_chain,
)

PLAYBOOKS = {
    "web_surface": run_web_surface,
    "api_surface": run_api_surface,
    "auth_surface": run_auth_surface,
    "svc_surface": run_svc_surface,
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
