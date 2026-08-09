"""MCP tools wrapping the orchestrate workflow-state contract.

State file lives at ``<repo root>/workspace/workflow-state.json`` (created on
first ``wf_init``). Every tool returns a dict and never raises; failures are
surfaced as ``{"ok": False, "error": "..."}``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from kali_orch import wf  # noqa: E402

STATE_FILE: Path = _REPO_ROOT / "workspace" / "workflow-state.json"


def wf_init(
    goal: str,
    success_criteria: Optional[List[str]] = None,
    deliverables: Optional[List[str]] = None,
    constraints: Optional[List[str]] = None,
    complexity: str = "medium",
) -> Dict[str, Any]:
    """Create the workflow state file (fails if one already exists)."""
    try:
        with wf.state_lock(STATE_FILE):
            if STATE_FILE.exists():
                return {
                    "ok": False,
                    "error": f"workflow state already exists at {STATE_FILE}; "
                    "use wf_status to inspect it",
                }
            state = wf.create_state(
                goal=goal,
                success_criteria=success_criteria,
                deliverables=deliverables,
                constraints=constraints,
                complexity=complexity,
            )
            wf.write_state(STATE_FILE, state)
        return {
            "ok": True,
            "message": "workflow state initialized",
            "stage": state["stage"],
            "state": state,
        }
    except Exception as exc:  # pragma: no cover - defensive catch-all
        return {"ok": False, "error": f"wf_init failed: {exc}"}


def wf_transition(to_stage: str) -> Dict[str, Any]:
    """Advance the workflow to ``to_stage`` (illegal moves are rejected)."""
    try:
        with wf.state_lock(STATE_FILE):
            state, err = _read_state()
            if err:
                return {"ok": False, "error": err}
            updated = wf.transition(state, to_stage)
            wf.write_state(STATE_FILE, updated)
        return {
            "ok": True,
            "stage": updated["stage"],
            "message": f"transitioned to {updated['stage']}",
            "state": updated,
        }
    except Exception as exc:
        return {"ok": False, "error": f"wf_transition failed: {exc}"}


def wf_record_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a result envelope and append it to the state's results."""
    try:
        with wf.state_lock(STATE_FILE):
            state, err = _read_state()
            if err:
                return {"ok": False, "error": err}
            updated = wf.record_result(state, result)
            wf.write_state(STATE_FILE, updated)
        return {
            "ok": True,
            "message": "result recorded",
            "results_count": len(updated["results"]),
            "state": updated,
        }
    except Exception as exc:
        return {"ok": False, "error": f"wf_record_result failed: {exc}"}


def wf_record_issue(
    issue: Dict[str, Any], change_type: Optional[str] = None
) -> Dict[str, Any]:
    """Route an issue to its responsible stage and record it in the state."""
    try:
        with wf.state_lock(STATE_FILE):
            state, err = _read_state()
            if err:
                return {"ok": False, "error": err}
            updated = wf.record_issue(state, issue, change_type=change_type)
            wf.write_state(STATE_FILE, updated)
        return {
            "ok": True,
            "message": "issue recorded",
            "routed_stage": updated["stage"],
            "state": updated,
        }
    except Exception as exc:
        return {"ok": False, "error": f"wf_record_issue failed: {exc}"}


def wf_status() -> Dict[str, Any]:
    """Return a compact summary of the current workflow state."""
    try:
        state, err = _read_state()
        if err:
            return {"ok": False, "error": err}
        stage = state["stage"]
        progress = round(wf.STAGES.index(stage) / (len(wf.STAGES) - 1) * 100)
        return {
            "ok": True,
            "stage": stage,
            "progress": progress,
            "open_items": len(state.get("issues", [])),
            "next_stages": wf.next_stages(stage),
            "goal": state.get("contract", {}).get("goal"),
        }
    except Exception as exc:  # pragma: no cover - defensive catch-all
        return {"ok": False, "error": f"wf_status failed: {exc}"}


def _read_state() -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (state, None) or (None, error message)."""
    if not STATE_FILE.exists():
        return None, f"no workflow state at {STATE_FILE}; call wf_init first"
    try:
        return wf.load_state(STATE_FILE), None
    except Exception as exc:
        return None, f"failed to load {STATE_FILE}: {exc}"


def register_wf_tools(mcp: Any, *args: Any, **kwargs: Any) -> None:
    """Register the wf_* workflow-state tools on a FastMCP instance."""
    mcp.tool()(wf_init)
    mcp.tool()(wf_transition)
    mcp.tool()(wf_record_result)
    mcp.tool()(wf_record_issue)
    mcp.tool()(wf_status)
