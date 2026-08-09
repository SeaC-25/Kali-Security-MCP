#!/usr/bin/env python3
"""Process-local active task context for executor graph/log hooks."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

_active_task_id: ContextVar[Optional[str]] = ContextVar("kali_mcp_active_task_id", default=None)


def set_active_task(task_id: Optional[str]) -> None:
    _active_task_id.set((task_id or "").strip() or None)


def get_active_task() -> Optional[str]:
    return _active_task_id.get()


def clear_active_task() -> None:
    _active_task_id.set(None)
