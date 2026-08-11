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
            state, err = _ensure_state()
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
            state, err = _ensure_state()
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
            state, err = _ensure_state()
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
        state, err = _ensure_state()
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



def _ensure_state(goal_hint: str = "autonomous pentest workflow") -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """K3-3 auto-init: return current state; create one (zero-friction) if missing.

    不加内部锁——调用方（wf_transition 等）已持 state_lock；pack/status 的
    只读路径用原子写足够（write_state 内部 tempfile+os.replace）。
    """
    state, err = _read_state()
    if err:
        # state 文件缺失是唯一可自动修复的错误
        if "no workflow state at" in err:
            try:
                if STATE_FILE.exists():
                    return wf.load_state(STATE_FILE), None
                st = wf.create_state(
                    goal=goal_hint,
                    success_criteria=[],
                    complexity="medium",
                )
                wf.write_state(STATE_FILE, st)
                return st, None
            except Exception as exc:
                return None, "auto-init failed: " + str(exc)
        return None, err
    return state, None



def wf_pack_turn(max_chars: int = 900) -> Dict[str, Any]:
    """Assemble a compact <=1KB turn summary from the workflow state.

    Outputs stage / progress / open issues / recent results / recommended next
    action, enough for the model to resume without loading the whole state.
    """
    try:
        state, err = _ensure_state()
        if err:
            return {"ok": False, "error": err}
        if state is None:
            return {"ok": True, "pack": {"stage": None, "note": "no workflow state yet; call wf_init"}}
        contract = state.get("contract", {})
        results = state.get("results", [])
        issues = state.get("issues", [])
        last = results[-1] if results else None
        pack = {
            "stage": state.get("stage"),
            "goal": contract.get("goal", ""),
            "progress": str(len(results)) + " result(s)",
            "open_issues": [str(i.get("summary", i.get("description", "")))[:60] for i in issues][:3],
            "recent_result": {
                "task": last.get("task") if last else None,
                "outcome": last.get("outcome") if last else None,
                "summary": (last.get("summary") or "")[:120] if last else None,
            },
            "next": last.get("recommended_next_action") if last else (wf.next_stages(state.get("stage"))[0] if state.get("stage") else None),
        }
        return {"ok": True, "pack": pack}
    except Exception as exc:
        return {"ok": False, "error": "wf_pack_turn failed: " + str(exc)}


def register_wf_tools(mcp: Any, *args: Any, **kwargs: Any) -> None:
    """Register the wf_* workflow-state tools on a FastMCP instance."""
    mcp.tool()(wf_init)
    mcp.tool()(wf_transition)
    mcp.tool()(wf_record_result)
    mcp.tool()(wf_record_issue)
    mcp.tool()(wf_status)
    mcp.tool()(wf_pack_turn)
