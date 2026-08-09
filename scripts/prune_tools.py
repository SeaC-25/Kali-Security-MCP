#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
K5 pruning tool — bottom-decile usage -> drop from the K1 keep-set.

Reads K0-5 usage telemetry (data/usage.sqlite: tool, args_hash, duration_s,
timed_out, success, cache_hit, target, ts), aggregates per-tool call counts,
success rate and average duration, prints a usage ranking, and (with
--apply) removes bottom-decile tools from K1_KEEP_TOOLS in
kali_mcp/mcp_tools/meta_tools.py.

Rules (defensive by design — pruning keeps the surface STABLE over time):
  * Candidates are keep-set tools with at least one recorded call
    (registry names in the DB are mapped to MCP tool names via
    _MCP_TO_REGISTRY). A tool with zero recorded calls has no usage
    evidence, so it is never pruned on absence of evidence.
  * Bottom decile = call counts at/below the 10th percentile of the
    candidate pool. A pool smaller than --min-pool (default 10) is
    statistically meaningless -> no pruning (printed as the verdict).
  * Guards: kali_run is never dropped; the keep-set never falls below
    15 tools — pruning below that is refused.
  * Idempotent: a dropped tool leaves K1_KEEP_TOOLS, so a re-run has no
    candidate to drop again and the file is left untouched.

Usage:
    py scripts/prune_tools.py                  # dry-run (default)
    py scripts/prune_tools.py --apply          # edit K1_KEEP_TOOLS
"""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import math
import re
import sqlite3
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DB_PATH = REPO_ROOT / "data" / "usage.sqlite"
META_TOOLS = REPO_ROOT / "kali_mcp" / "mcp_tools" / "meta_tools.py"

MIN_POOL_DEFAULT = 10  # decile needs a meaningful candidate pool
MIN_KEEP = 15  # never prune the keep-set below this
NEVER_DROP = {"kali_run"}  # meta fallback must always stay registered


def load_keep_set() -> Tuple[set, Dict[str, str]]:
    """Return (K1_KEEP_TOOLS, registry_name -> mcp_name) from meta_tools."""
    from kali_mcp.mcp_tools.meta_tools import K1_KEEP_TOOLS, _MCP_TO_REGISTRY

    registry_to_mcp = {v: k for k, v in _MCP_TO_REGISTRY.items()}
    return set(K1_KEEP_TOOLS), registry_to_mcp


def load_usage(db_path: Path) -> List[Dict]:
    """Aggregate usage.sqlite per tool: calls, success_rate, avg_duration."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        rows = conn.execute(
            "SELECT tool, COUNT(*), "
            "CASE WHEN COUNT(*) > 0 THEN 100.0 * SUM(success) / COUNT(*) ELSE 0 END, "
            "AVG(duration_s) "
            "FROM usage GROUP BY tool ORDER BY COUNT(*) ASC, tool ASC"
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "tool": r[0],
            "calls": int(r[1]),
            "success_rate": round(float(r[2]), 1),
            "avg_duration_s": round(float(r[3]), 3) if r[3] is not None else 0.0,
        }
        for r in rows
    ]


def tenth_percentile(sorted_calls: List[int]) -> int:
    """10th percentile of the (ascending) candidate call counts."""
    n = len(sorted_calls)
    idx = max(0, math.ceil(n * 0.10) - 1)
    return sorted_calls[idx]


def compute_drops(
    keep_set: set, usage: List[Dict], registry_to_mcp: Dict[str, str], min_pool: int
) -> Tuple[List[Dict], List[str]]:
    """Return (candidates, drops). candidates = keep-set tools with usage;
    drops = bottom-decile candidates after guards (never kali_run, keep >=
    MIN_KEEP). Notes explain refusals."""
    pool = []
    for u in usage:
        mcp_name = registry_to_mcp.get(u["tool"], u["tool"])
        if mcp_name in keep_set:
            pool.append({**u, "mcp_tool": mcp_name})
    if len(pool) < min_pool:
        return pool, []
    threshold = tenth_percentile(sorted(c["calls"] for c in pool))
    drops = [c for c in pool if c["calls"] <= threshold]
    drops = [d for d in drops if d["mcp_tool"] not in NEVER_DROP]
    # guard: never prune below MIN_KEEP tools
    max_drops = len(keep_set) - MIN_KEEP
    if max_drops < 1:
        return pool, []
    if len(drops) > max_drops:
        # keep only the most-justified (fewest calls) drops
        drops = sorted(drops, key=lambda d: (d["calls"], d["mcp_tool"]))[:max_drops]
    return pool, drops


def rewrite_keep_set(text: str, drops: Iterable[str]) -> str:
    """Remove dropped tool names from the K1_KEEP_TOOLS frozenset block,
    preserving comments and surrounding formatting. Raises if the block or a
    name is not found as expected."""
    start_marker = "K1_KEEP_TOOLS = frozenset({"
    start = text.find(start_marker)
    if start < 0:
        raise RuntimeError("K1_KEEP_TOOLS block not found in meta_tools.py")
    i = start + len(start_marker)
    depth = 1
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    block = text[start:i]
    for name in sorted(drops):
        pat = re.compile(r'"%s"\s*,\s*' % re.escape(name))
        new_block = pat.sub("", block)
        if new_block == block:
            # last entry before the closing brace (no trailing comma)
            new_block = re.sub(
                r'"%s"\s*(?=\s*\})' % re.escape(name), "", block
            )
        if new_block == block:
            raise RuntimeError(f"tool '{name}' not found inside K1_KEEP_TOOLS block")
        block = new_block
    # tidy: drop blank lines inside the block, collapse 3+ newlines
    lines = block.split("\n")
    kept = []
    for ln in lines:
        if ln.strip():
            kept.append(ln)
    block = "\n".join(kept)
    block = re.sub(r"\n{3,}", "\n\n", block)
    return text[:start] + block + text[i:]


def apply_prune(drops: List[Dict]) -> Dict:
    """Edit K1_KEEP_TOOLS in meta_tools.py. Verifies the result by fresh
    import; restores the original on verification failure."""
    original = META_TOOLS.read_text(encoding="utf-8")
    new_text = rewrite_keep_set(original, [d["mcp_tool"] for d in drops])
    # syntax check before writing
    ast.parse(new_text)
    META_TOOLS.write_text(new_text, encoding="utf-8")
    try:
        import kali_mcp.mcp_tools.meta_tools as meta_mod

        importlib.reload(meta_mod)
        new_keep = set(meta_mod.K1_KEEP_TOOLS)
        assert all(d["mcp_tool"] not in new_keep for d in drops), "drop not effective"
        assert len(new_keep) >= MIN_KEEP, "keep-set fell below MIN_KEEP"
        assert "kali_run" in new_keep, "kali_run dropped"
    except Exception as exc:  # noqa: BLE001 — restore on verification failure
        META_TOOLS.write_text(original, encoding="utf-8")
        raise RuntimeError(f"post-write verification failed, restored: {exc}") from exc
    return {"file": str(META_TOOLS), "removed": [d["mcp_tool"] for d in drops],
            "keep_set_size_after": len(new_keep)}


def print_ranking(pool: List[Dict], usage: List[Dict], keep_set: set) -> None:
    print(f"[K5 prune] usage DB: {DB_PATH}")
    print(f"[K5 prune] keep-set: {len(keep_set)} tools | rows: {len(usage)}")
    print()
    if not pool:
        print("[K5 prune] ranking: (no keep-set tool has recorded usage)")
    else:
        print(f"{'#':<3} {'tool':<24} {'calls':>6} {'success%':>9} {'avg_dur_s':>10}")
        for rank, c in enumerate(sorted(pool, key=lambda c: (c["calls"], c["mcp_tool"])), 1):
            print(
                f"{rank:<3} {c['mcp_tool']:<24} {c['calls']:>6} "
                f"{c['success_rate']:>9} {c['avg_duration_s']:>10}"
            )
    archived = len(usage) - len(pool)
    if archived:
        print(f"[K5 prune] {archived} row(s) reference archived (non keep-set) tools — ignored")


def print_verdict(pool: List[Dict], drops: List[Dict], dry_run: bool) -> None:
    action = "would drop" if dry_run else "dropped"
    if not drops:
        reason = (
            f"candidate pool {len(pool)} < min_pool"
            if len(pool) < MIN_POOL_DEFAULT
            else "no bottom-decile candidates after guards"
        )
        print(f"[K5 prune] {action}: (none) — {reason}")
        return
    for d in sorted(drops, key=lambda d: (d["calls"], d["mcp_tool"])):
        print(f"[K5 prune] {action}: {d['mcp_tool']} (bottom decile, {d['calls']} calls)")
    if dry_run:
        print(f"[K5 prune] dry-run: meta_tools.py NOT modified (use --apply to prune)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="K5 bottom-decile pruning of the K1 keep-set "
        "(usage.sqlite -> K1_KEEP_TOOLS)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="print ranking + verdict without modifying meta_tools.py (default)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="edit K1_KEEP_TOOLS in meta_tools.py (removes bottom-decile tools)",
    )
    parser.add_argument(
        "--min-pool",
        type=int,
        default=MIN_POOL_DEFAULT,
        help=f"minimum used keep-set tools for a meaningful decile (default {MIN_POOL_DEFAULT})",
    )
    args = parser.parse_args()

    keep_set, registry_to_mcp = load_keep_set()
    usage = load_usage(DB_PATH)
    pool, drops = compute_drops(keep_set, usage, registry_to_mcp, args.min_pool)

    print_ranking(pool, usage, keep_set)
    print()
    print_verdict(pool, drops, dry_run=not args.apply)

    if args.apply and drops:
        try:
            result = apply_prune(drops)
        except Exception as exc:  # noqa: BLE001
            print(f"[K5 prune] ERROR: {exc}")
            return 1
        print(
            f"[K5 prune] applied: removed {len(result['removed'])} tool(s) "
            f"from K1_KEEP_TOOLS -> {result['keep_set_size_after']} tools remain "
            f"({result['file']})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
