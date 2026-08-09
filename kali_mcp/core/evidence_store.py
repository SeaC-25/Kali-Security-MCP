#!/usr/bin/env python3
"""Evidence store: keep raw outputs as-is (no redaction by default)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

from kali_mcp.core.task_workspace import get_workspace, utc_now_iso

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe(name: str) -> str:
    text = _SAFE_NAME.sub("_", (name or "evidence").strip())[:80]
    return text or "evidence"


def save_evidence(
    task_id: str,
    *,
    name: str,
    content: str,
    meta: Optional[Dict[str, Any]] = None,
    suffix: str = ".txt",
) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    ts = utc_now_iso().replace(":", "").replace("+00:00", "Z")
    base = f"{ts}_{_safe(name)}"
    body_path = ws.evidence_dir / f"{base}{suffix}"
    meta_path = ws.evidence_dir / f"{base}.meta.json"
    body_path.write_text(content if content is not None else "", encoding="utf-8", errors="replace")
    payload = {
        "task_id": ws.task_id,
        "name": name,
        "path": str(body_path),
        "created_at": utc_now_iso(),
        "bytes": body_path.stat().st_size,
        "meta": meta or {},
    }
    meta_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def save_json_evidence(task_id: str, name: str, data: Any, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return save_evidence(
        task_id,
        name=name,
        content=json.dumps(data, ensure_ascii=False, indent=2, default=str),
        meta=meta,
        suffix=".json",
    )
