#!/usr/bin/env python3
"""ATT&CK technique coverage stats (label layer only; not a runtime scheduler)."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from kali_mcp.core.findings_store import list_findings


# Coarse tactic buckets for reporting (optional grouping)
TECHNIQUE_TACTIC_HINT = {
    "T1595": "Reconnaissance",
    "T1046": "Discovery",
    "T1190": "Initial Access",
    "T1078": "Initial Access",
    "T1068": "Privilege Escalation",
    "T1187": "Credential Access",
    "T1195": "Initial Access",
}


def coverage_from_findings(
    findings: List[Dict[str, Any]],
    *,
    status_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute technique_id coverage from findings list."""
    items = findings
    if status_filter:
        items = [f for f in findings if f.get("status") == status_filter]

    technique_counter: Counter = Counter()
    by_status: Dict[str, Counter] = defaultdict(Counter)
    labeled = 0
    unlabeled = 0
    for f in items:
        tids = f.get("technique_ids") or []
        if not isinstance(tids, list):
            tids = []
        tids = [str(t).strip() for t in tids if str(t).strip()]
        status = f.get("status") or "candidate"
        if tids:
            labeled += 1
            for t in tids:
                technique_counter[t] += 1
                by_status[status][t] += 1
        else:
            unlabeled += 1

    techniques = sorted(technique_counter.keys())
    tactics = sorted(
        {
            TECHNIQUE_TACTIC_HINT.get(t, "Unmapped")
            for t in techniques
        }
    )

    total = len(items)
    labeled_ratio = (labeled / total) if total else 0.0

    return {
        "findings_total": total,
        "labeled_count": labeled,
        "unlabeled_count": unlabeled,
        "labeled_ratio": round(labeled_ratio, 4),
        "techniques": techniques,
        "technique_counts": dict(technique_counter),
        "tactics_present": tactics,
        "by_status": {k: dict(v) for k, v in by_status.items()},
        "note": "ATT&CK is label-only; empty technique_ids preferred over wrong tags",
    }


def task_attack_coverage(task_id: str) -> Dict[str, Any]:
    findings = list_findings(task_id)
    all_cov = coverage_from_findings(findings)
    verified_cov = coverage_from_findings(findings, status_filter="verified")
    return {
        "ok": True,
        "task_id": task_id,
        "all": all_cov,
        "verified_only": verified_cov,
    }
