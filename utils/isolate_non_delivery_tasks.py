#!/usr/bin/env python3
"""Isolate non-delivery tasks (probe/debug) out of workspace/tasks/.

Closes the last open item in 交付文件/06-待完善项.md:
  "Kali 侧 workspace/tasks 若仍含 probe/debug，按同规则隔离（本机已清）"

Rules (kept identical to the manual isolation done on 2026-07-27):
  * Non-delivery task ids: rpt_probe, chain_clear_dbg, dbg_next (+ probe aliases).
  * Destination: workspace/archive_non_delivery/isolated_YYYYMMDD/<task_id>/
  * A README.md is written into each isolation batch directory.
  * Never deletes anything: tasks are MOVED, never removed.

Safety:
  * Default is dry-run: only prints the plan, moves nothing.
  * Use --apply to actually move.
  * --workspace overrides the task root (safe for testing against a scratch dir).
  * Idempotent: re-running with an already-isolated workspace reports clean.

Usage:
    python utils/isolate_non_delivery_tasks.py                 # dry-run
    python utils/isolate_non_delivery_tasks.py --apply         # move for real
    python utils/isolate_non_delivery_tasks.py --workspace TMP # scan a scratch dir
"""
from __future__ import annotations

import argparse
import datetime as _dt
import shutil
import sys
from pathlib import Path

# Shared non-delivery rules (single source of truth, also used by e2e_checklist).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from non_delivery_rules import (  # noqa: E402
    is_non_delivery,
)

ARCHIVE_DIRNAME = "archive_non_delivery"
ISOLATED_PREFIX = "isolated_"


def _batch_dir(archive_root: Path, stamp: str) -> Path:
    """Isolated batch dir: archive_non_delivery/isolated_YYYYMMDD."""
    return archive_root / f"{ISOLATED_PREFIX}{stamp}"


def _is_isolated(task_dir: Path) -> bool:
    """True if the task dir already lives under an isolated_ batch."""
    return ISOLATED_PREFIX in task_dir.parent.name or ISOLATED_PREFIX in task_dir.name


def scan_tasks(tasks_root: Path) -> list[Path]:
    """Return non-delivery task dirs under tasks_root, skipping already-isolated ones."""
    if not tasks_root.is_dir():
        return []
    found: list[Path] = []
    for entry in sorted(tasks_root.iterdir()):
        if not entry.is_dir() or _is_isolated(entry):
            continue
        if is_non_delivery(entry.name):
            found.append(entry)
    return found


def _write_batch_readme(batch: Path, moved: list[Path], stamp: str) -> None:
    lines = [
        f"# Isolated non-delivery tasks ({stamp})",
        "",
        "These task dirs were moved out of workspace/tasks because they are",
        "probe/debug artifacts and MUST NOT be used as acceptance evidence.",
        f"Moved: {len(moved)} task(s)",
        "",
    ]
    for src in moved:
        lines.append(f"- `{src.name}` (from `{src.parent}`)")
    lines.append("")
    lines.append("Rule reference: 交付文件/06-待完善项.md; e2e_checklist.FORBIDDEN_TASK_IDS.")
    batch.joinpath("README.md").write_text("\n".join(lines), encoding="utf-8")


def run(tasks_root: Path, apply: bool) -> int:
    found = scan_tasks(tasks_root)
    if not found:
        print(f"[OK]  No non-delivery tasks under {tasks_root}")
        return 0

    stamp = _dt.date.today().strftime("%Y%m%d")
    batch = _batch_dir(tasks_root.parent / ARCHIVE_DIRNAME, stamp)

    print(f"[!]  Found {len(found)} non-delivery task(s):")
    for src in found:
        print(f"    - {src.name}")
    print(f"    -> destination: {batch}")

    if not apply:
        print("[i]  Dry-run: nothing moved. Re-run with --apply to isolate.")
        return 2

    batch.mkdir(parents=True, exist_ok=True)
    moved: list[Path] = []
    for src in found:
        dest = batch / src.name
        if dest.exists():
            print(f"[!]  {dest} already exists, skipping (idempotent)")
            continue
        shutil.move(str(src), str(dest))
        moved.append(src)
        print(f"[+]  moved {src.name} -> {dest.relative_to(tasks_root.parent)}")

    if moved:
        _write_batch_readme(batch, moved, stamp)
    print(f"[OK]  Isolated {len(moved)} task(s) into {batch}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually move tasks (default is dry-run)",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="task root to scan (default: <repo>/workspace)",
    )
    args = parser.parse_args(argv)

    if args.workspace is not None:
        tasks_root = args.workspace
    else:
        repo_root = Path(__file__).resolve().parent.parent
        tasks_root = repo_root / "workspace" / "tasks"

    return run(tasks_root, args.apply)


if __name__ == "__main__":
    sys.exit(main())
