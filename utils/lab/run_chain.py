#!/usr/bin/env python3
"""Manual sequential playbook chain against research lab (no run_goal).

Delegates to kali_mcp.core.playbooks.run_surface_chain for a single code path
with MCP tool run_surface_chain.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# repo root: utils/lab -> utils -> repo
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_TARGET = os.environ.get("LAB_URL", "http://127.0.0.1:18081/")
DEFAULT_TASK = os.environ.get("LAB_CHAIN_TASK", "lab_chain_manual")


def main() -> int:
    from kali_mcp.core.local_executor import LocalCommandExecutor
    from kali_mcp.core.playbooks import run_surface_chain

    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    task_id = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_TASK

    ex = LocalCommandExecutor(timeout=180)
    summary = run_surface_chain(
        task_id=task_id,
        target=target,
        executor=ex,
        depth="mixed",
        seed_task=True,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("REPORT", summary.get("report_path"))
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
