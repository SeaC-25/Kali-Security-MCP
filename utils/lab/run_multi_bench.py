#!/usr/bin/env python3
"""Measured multi-target chain bench (sequential vs optional parallel).

Writes JSON under doc/lab-acceptance/. Numbers only from this run — no invented throughput.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_URL = os.environ.get("LAB_URL", "http://127.0.0.1:18081/")


def main() -> int:
    from kali_mcp.core.local_executor import LocalCommandExecutor
    from kali_mcp.core.playbooks.chain import run_surface_chain

    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    # two logical targets (same host OK for wall-time compare; separate task ids)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    depth = sys.argv[3] if len(sys.argv) > 3 else "quick"
    playbooks = sys.argv[4] if len(sys.argv) > 4 else "web_surface"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"lab_multi_bench_{stamp}"
    targets = [url] * max(1, n)
    ex = LocalCommandExecutor(timeout=180)

    def run_mode(parallel: bool) -> dict:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        t0 = time.perf_counter()
        results = []
        if parallel and len(targets) > 1:
            with ThreadPoolExecutor(max_workers=min(2, len(targets))) as pool:
                futs = {}
                for i, t in enumerate(targets):
                    tid = f"{base}_p{i + 1}" if parallel else base
                    futs[
                        pool.submit(
                            run_surface_chain,
                            task_id=tid,
                            target=t,
                            executor=ex,
                            depth=depth,
                            playbooks=playbooks,
                            seed_task=True,
                        )
                    ] = tid
                for fut in as_completed(futs):
                    tid = futs[fut]
                    try:
                        out = fut.result()
                    except Exception as e:
                        out = {"ok": False, "error": str(e)[:300], "task_id": tid}
                    results.append(
                        {
                            "task_id": out.get("task_id") or tid,
                            "ok": out.get("ok"),
                            "error": out.get("error"),
                            "verified": (out.get("by_status") or {}).get("verified", 0),
                        }
                    )
            mode = "parallel"
        else:
            for i, t in enumerate(targets):
                tid = f"{base}_s{i + 1}" if n > 1 else base
                out = run_surface_chain(
                    task_id=tid,
                    target=t,
                    executor=ex,
                    depth=depth,
                    playbooks=playbooks,
                    seed_task=True,
                )
                results.append(
                    {
                        "task_id": out.get("task_id") or tid,
                        "ok": out.get("ok"),
                        "error": out.get("error"),
                        "verified": (out.get("by_status") or {}).get("verified", 0),
                    }
                )
            mode = "sequential"
        elapsed = round(time.perf_counter() - t0, 3)
        return {
            "mode": mode,
            "elapsed_sec": elapsed,
            "ok": all(r.get("ok") for r in results) if results else False,
            "per_target": results,
            "depth": depth,
            "playbooks": playbooks,
            "target_count": len(targets),
            "url": url,
        }

    sequential = run_mode(False)
    parallel = run_mode(True) if n > 1 else None
    payload = {
        "ok": sequential.get("ok") and (parallel is None or parallel.get("ok")),
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "host_note": "wall times from this process only; not a capacity claim",
        "sequential": sequential,
        "parallel": parallel,
    }
    out_dir = ROOT / "doc" / "lab-acceptance"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"multi_bench_{stamp}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print("WROTE", path)
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
