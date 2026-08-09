#!/usr/bin/env python3
"""Finding store with candidate -> verified gate."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from kali_mcp.core.task_workspace import get_workspace, utc_now_iso

VALID_STATUS = {"candidate", "verified", "false_positive", "blocked"}


def _load(path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            return data["findings"]
    except Exception:
        return []
    return []


def _save(path, items: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"updated_at": utc_now_iso(), "findings": items}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def list_findings(task_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    ws = get_workspace(task_id, create=True)
    items = _load(ws.findings_path)
    if status:
        items = [x for x in items if x.get("status") == status]
    return items


def _normalize_url_path(value: str) -> str:
    """Collapse trailing-slash variants so /login and /login/ share one key."""
    text = (value or "").strip()
    if not text:
        return ""
    # split scheme/host/path-ish titles like auth_entry:http://x/login/
    prefix = ""
    body = text
    for sep in (":",):
        if sep in text and not text.startswith("http"):
            # only split first colon for type:url titles
            left, right = text.split(sep, 1)
            if right.startswith("//") or right.startswith("http"):
                prefix = left.lower() + ":"
                body = right
            elif "://" in right:
                prefix = left.lower() + ":"
                body = right
    lower = body.strip().lower()
    # keep scheme/host; normalize path trailing slash (except bare origin "/")
    if "://" in lower:
        scheme, rest = lower.split("://", 1)
        if "/" in rest:
            host, path = rest.split("/", 1)
            path = path.rstrip("/")
            body_n = f"{scheme}://{host}" + (f"/{path}" if path else "")
        else:
            body_n = f"{scheme}://{rest.rstrip('/')}"
    else:
        body_n = lower.rstrip("/") if lower != "/" else lower
    return f"{prefix}{body_n}"


def _norm_key(title: str, target: str) -> str:
    return f"{_normalize_url_path(title)}||{_normalize_url_path(target)}"


def upsert_finding(task_id: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    ws = get_workspace(task_id, create=True)
    items = _load(ws.findings_path)
    finding = dict(finding)
    title = str(finding.get("title") or "")
    target = str(finding.get("target") or finding.get("asset") or "")
    # store canonical forms so lists do not keep trailing-slash display forks
    title_n = _normalize_url_path(title)
    target_n = _normalize_url_path(target)
    if title_n:
        finding["title"] = title_n
        title = title_n
    if target_n:
        finding["target"] = target_n
        target = target_n
    key = _norm_key(title, target)

    # prefer explicit id; else reuse same title+target
    fid = str(finding.get("finding_id") or "").strip()
    if not fid and key != "||":
        for old in items:
            if _norm_key(str(old.get("title") or ""), str(old.get("target") or old.get("asset") or "")) == key:
                fid = str(old.get("finding_id") or "")
                break
    if not fid:
        fid = uuid.uuid4().hex[:12]

    finding["finding_id"] = fid
    finding.setdefault("status", "candidate")
    if finding["status"] not in VALID_STATUS:
        finding["status"] = "candidate"
    finding.setdefault("created_at", utc_now_iso())
    finding["updated_at"] = utc_now_iso()
    finding.setdefault("technique_ids", finding.get("technique_ids") or [])
    finding.setdefault("source", finding.get("source") or "scan")

    # Only protect verified from silent demotion by non-forced candidate re-registers.
    # Explicit force_status (verify path) always wins.
    rank = {"verified": 3, "candidate": 2, "blocked": 1, "false_positive": 0}
    force = bool(finding.pop("force_status", False))
    replaced = False
    for i, old in enumerate(items):
        same_id = old.get("finding_id") == fid
        same_key = key != "||" and _norm_key(
            str(old.get("title") or ""), str(old.get("target") or old.get("asset") or "")
        ) == key
        if same_id or same_key:
            merged = dict(old)
            new_status = finding.get("status") or "candidate"
            old_status = old.get("status") or "candidate"
            if (
                not force
                and str(old_status) == "verified"
                and str(new_status) != "verified"
            ):
                finding = dict(finding)
                finding["status"] = "verified"
            # merge evidence paths
            paths = list(old.get("evidence_paths") or [])
            for p in finding.get("evidence_paths") or []:
                if p and p not in paths:
                    paths.append(p)
            finding["evidence_paths"] = paths
            merged.update(finding)
            merged["finding_id"] = str(old.get("finding_id") or fid)
            merged["updated_at"] = utc_now_iso()
            items[i] = merged
            finding = merged
            replaced = True
            break
    if not replaced:
        items.append(finding)
    # collapse any residual duplicates by title+target
    items = _dedupe_items(items)
    _save(ws.findings_path, items)
    return finding


def _dedupe_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rank = {"verified": 3, "candidate": 2, "blocked": 1, "false_positive": 0}
    by_key: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for item in items:
        key = _norm_key(str(item.get("title") or ""), str(item.get("target") or item.get("asset") or ""))
        if key == "||":
            key = f"id:{item.get('finding_id') or uuid.uuid4().hex[:12]}"
        if key not in by_key:
            by_key[key] = item
            order.append(key)
            continue
        cur = by_key[key]
        if rank.get(str(item.get("status") or "candidate"), 0) > rank.get(str(cur.get("status") or "candidate"), 0):
            # keep stronger status, merge paths
            paths = list(cur.get("evidence_paths") or [])
            for p in item.get("evidence_paths") or []:
                if p and p not in paths:
                    paths.append(p)
            item = dict(item)
            item["evidence_paths"] = paths
            item["finding_id"] = cur.get("finding_id") or item.get("finding_id")
            by_key[key] = item
        else:
            paths = list(cur.get("evidence_paths") or [])
            for p in item.get("evidence_paths") or []:
                if p and p not in paths:
                    paths.append(p)
            cur = dict(cur)
            cur["evidence_paths"] = paths
            by_key[key] = cur
    return [by_key[k] for k in order]


def get_finding(task_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
    for item in list_findings(task_id):
        if item.get("finding_id") == finding_id:
            return item
    return None


def set_status(
    task_id: str,
    finding_id: str,
    status: str,
    **extra: Any,
) -> Optional[Dict[str, Any]]:
    item = get_finding(task_id, finding_id)
    if not item:
        return None
    if status not in VALID_STATUS:
        raise ValueError(f"invalid status: {status}")
    item = dict(item)
    item.update(extra)
    item["status"] = status
    item["force_status"] = True
    return upsert_finding(task_id, item)
