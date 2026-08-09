#!/usr/bin/env python3
"""Single source of truth for non-delivery (probe/debug) task-id rules.

Used by:
  * utils/isolate_non_delivery_tasks.py   — workspace/tasks cleanup
  * utils/lab/e2e_checklist.py            — acceptance task-id validation

Keeping the rules here (instead of duplicated literals) guarantees the
acceptance gate and the isolation tool can never drift apart again.
"""
from __future__ import annotations

# Exact task ids that must never be used as delivery/acceptance evidence.
NON_DELIVERY_EXACT = frozenset({"rpt_probe", "probe", "rpt-probe", "chain_clear_dbg", "dbg_next"})
# Lowercased prefix markers (safety net, e.g. "rpt_probe_20260727").
NON_DELIVERY_PREFIX = ("rpt_probe", "probe")
# Lowercased suffix markers (safety net, e.g. "recon_dbg").
NON_DELIVERY_SUFFIX = ("_dbg", "_debug", "_probe")
# Test-namespace prefixes: task ids created by the test suite (fixed ids or
# id()-based like "cnt_1400..."), never delivery artifacts. Kept in sync with
# tests/ usage (test_p0_chain_errors, test_handoff, test_task_workspace, ...).
TEST_NAMESPACE_PREFIXES = ("chain_err_", "cnt_", "hnd_", "wst_", "xd_")


def is_non_delivery(task_id: str | None) -> bool:
    """True if a task id is a probe/debug/test artifact (never delivery evidence)."""
    if not task_id:
        return False
    low = task_id.strip().lower()
    if low in NON_DELIVERY_EXACT:
        return True
    if any(low.startswith(p) for p in NON_DELIVERY_PREFIX):
        return True
    if any(low.startswith(p) for p in TEST_NAMESPACE_PREFIXES):
        return True
    if any(low.endswith(s) for s in NON_DELIVERY_SUFFIX):
        return True
    return False
