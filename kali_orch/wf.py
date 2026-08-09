"""Orchestrate workflow-state contract (minimal Python port).

Self-contained port of the orchestrate-work workflow-state semantics:
an 11-stage forward-only state machine with result-envelope validation and
issue routing. No SKILL.md dependency; the canonical state is a JSON document
described by the helpers below.

State shape::

    {
        "schema_version": 1,
        "stage": "intake",
        "contract": {
            "goal": "<non-empty str>",
            "success_criteria": ["..."],
            "deliverables": ["..."],
            "constraints": ["..."]
        },
        "complexity": "low | medium | high",
        "issues": [{"issue_id", "type", "summary", "change_type?", "routed_stage"}],
        "results": [result envelope]
    }

Result envelope (required keys)::

    summary, evidence[], artifacts[], risks[], unresolved[], recommended_next_action
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

SCHEMA_VERSION = 1

STAGES = [
    "intake",
    "context",
    "candidates",
    "review",
    "plan",
    "execute",
    "integrate",
    "check",
    "optimize",
    "package",
    "done",
]

# Forward-only adjacency; check branches to optimize/package; optimize may
# return to any earlier responsible stage.
_TRANSITIONS = {
    "intake": frozenset({"context"}),
    "context": frozenset({"candidates"}),
    "candidates": frozenset({"review"}),
    "review": frozenset({"plan"}),
    "plan": frozenset({"execute"}),
    "execute": frozenset({"integrate"}),
    "integrate": frozenset({"check"}),
    "check": frozenset({"optimize", "package"}),
    "optimize": frozenset(
        {"context", "candidates", "plan", "execute", "integrate", "check", "package"}
    ),
    "package": frozenset({"done"}),
    "done": frozenset(),
}

_ISSUE_ROUTES = {
    "evidence": "context",
    "approach": "candidates",
    "decomposition": "plan",
    "execution": "execute",
    "integration": "integrate",
    "artifact": "package",
}

_CHANGE_TYPES = frozenset(
    {"hypothesis", "data_source", "implementation", "agent_assignment", "tool"}
)

_RESULT_FIELDS = (
    "summary",
    "evidence",
    "artifacts",
    "risks",
    "unresolved",
    "recommended_next_action",
)


def create_state(
    goal: str,
    success_criteria: Sequence[str] | None = None,
    deliverables: Sequence[str] | None = None,
    constraints: Sequence[str] | None = None,
    complexity: str = "medium",
) -> dict[str, Any]:
    """Return a new canonical workflow state at stage ``intake``."""
    state = {
        "schema_version": SCHEMA_VERSION,
        "stage": "intake",
        "contract": {
            "goal": goal,
            "success_criteria": list(success_criteria or []),
            "deliverables": list(deliverables or []),
            "constraints": list(constraints or []),
        },
        "complexity": complexity,
        "issues": [],
        "results": [],
    }
    _raise_for_invalid_state(state)
    return state


def validate_state(state: Any) -> list[str]:
    """Return all detected state-contract violations."""
    if not isinstance(state, dict):
        return ["state must be an object"]

    errors: list[str] = []
    if state.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must equal {SCHEMA_VERSION}")

    stage = state.get("stage")
    if stage not in STAGES:
        errors.append(f"stage must be one of: {', '.join(STAGES)}")

    contract = state.get("contract")
    if not isinstance(contract, dict):
        errors.append("contract must be an object")
    else:
        if not _nonempty_string(contract.get("goal")):
            errors.append("contract.goal must be a non-empty string")
        for field in ("success_criteria", "deliverables", "constraints"):
            errors.extend(_validate_string_list(contract.get(field), f"contract.{field}"))

    if state.get("complexity") not in ("low", "medium", "high"):
        errors.append("complexity must be low, medium, or high")

    issues = state.get("issues")
    if not isinstance(issues, list):
        errors.append("issues must be an array")
    else:
        seen_issue_ids: set[str] = set()
        for index, issue in enumerate(issues):
            errors.extend(f"issues[{index}].{e}" for e in _validate_issue(issue))
            issue_id = issue.get("issue_id") if isinstance(issue, Mapping) else None
            if _nonempty_string(issue_id):
                if issue_id in seen_issue_ids:
                    errors.append(f"issues[{index}].issue_id is a duplicate: {issue_id}")
                else:
                    seen_issue_ids.add(issue_id)

    results = state.get("results")
    if not isinstance(results, list):
        errors.append("results must be an array")
    else:
        for index, result in enumerate(results):
            errors.extend(f"results[{index}].{e}" for e in _validate_result_envelope(result))

    return errors


def transition(state: Mapping[str, Any], to_stage: str) -> dict[str, Any]:
    """Return state advanced along an allowed edge of the workflow graph."""
    _raise_for_invalid_state(state)
    if to_stage not in STAGES:
        raise ValueError(f"Unknown stage: {to_stage!r}")

    current = state["stage"]
    if to_stage not in _TRANSITIONS[current]:
        raise ValueError(f"Illegal stage transition: {current} -> {to_stage}")

    updated = copy.deepcopy(dict(state))
    updated["stage"] = to_stage
    _raise_for_invalid_state(updated)
    return updated


def next_stages(stage: str) -> list[str]:
    """Return the stages reachable in one transition from ``stage``."""
    if stage not in _TRANSITIONS:
        raise ValueError(f"Unknown stage: {stage!r}")
    return sorted(_TRANSITIONS[stage])


def record_result(
    state: Mapping[str, Any], result: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate the result envelope and append it to ``state["results"]``."""
    _raise_for_invalid_state(state)
    errors = _validate_result_envelope(result)
    if errors:
        raise ValueError("Invalid result envelope: " + "; ".join(errors))

    updated = copy.deepcopy(dict(state))
    updated.setdefault("results", []).append(copy.deepcopy(dict(result)))
    _raise_for_invalid_state(updated)
    return updated


def route_issue(issue_type: str) -> str:
    """Return the narrowest workflow stage responsible for an issue type."""
    try:
        return _ISSUE_ROUTES[issue_type]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"Unknown issue type: {issue_type!r}") from exc


def record_issue(
    state: Mapping[str, Any],
    issue: Mapping[str, Any],
    change_type: str | None = None,
) -> dict[str, Any]:
    """Route an issue to its responsible stage and record it (upsert by id)."""
    _raise_for_invalid_state(state)
    if not isinstance(issue, Mapping):
        raise ValueError("Invalid issue: issue must be an object")

    issue_record = copy.deepcopy(dict(issue))
    if change_type is not None:
        issue_record["change_type"] = change_type
    issue_record["routed_stage"] = route_issue(issue_record.get("type"))

    errors = _validate_issue(issue_record)
    if errors:
        raise ValueError("Invalid issue: " + "; ".join(errors))

    updated = copy.deepcopy(dict(state))
    updated["stage"] = issue_record["routed_stage"]
    issue_id = issue_record["issue_id"]
    existing_index = next(
        (
            index
            for index, existing in enumerate(updated["issues"])
            if isinstance(existing, Mapping) and existing.get("issue_id") == issue_id
        ),
        None,
    )
    if existing_index is None:
        updated["issues"].append(issue_record)
    else:
        updated["issues"][existing_index] = issue_record
    _raise_for_invalid_state(updated)
    return updated


def load_state(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and validate workflow state from JSON."""
    data = _read_json(path)
    _raise_for_invalid_state(data)
    return data


def write_state(path: str | os.PathLike[str], state: Mapping[str, Any]) -> None:
    """Validate and atomically replace a workflow-state JSON file."""
    _raise_for_invalid_state(state)
    _atomic_write_json(path, state)


@contextmanager
def state_lock(
    path: str | os.PathLike[str],
    timeout: float = 10.0,
    stale_after: float = 300.0,
) -> Iterator[None]:
    """Hold an exclusive same-directory lock for one state-file transaction.

    Simple best-effort lock: an O_EXCL marker file with pid/token metadata and
    mtime-based staleness reclamation. Failures degrade to best-effort on
    platforms where the primitives misbehave (e.g. Windows).
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(f".{target.name}.lock")
    deadline = time.monotonic() + timeout
    owner_token = uuid.uuid4().hex
    acquired = False

    try:
        while True:
            try:
                descriptor = os.open(
                    lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
            except FileExistsError:
                if _lock_is_abandoned(lock_path, stale_after):
                    try:
                        lock_path.unlink()
                    except OSError:
                        pass
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"Timed out waiting for state lock: {lock_path}")
                time.sleep(min(0.05, remaining))
                continue
            try:
                with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
                    stream.write(f"pid={os.getpid()}\ntoken={owner_token}\n")
            except BaseException:
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
                raise
            acquired = True
            break
        yield
    finally:
        if acquired:
            try:
                if _read_lock_metadata(lock_path).get("token") == owner_token:
                    lock_path.unlink()
            except OSError:
                # Best-effort: a surviving owned lock is reclaimed by staleness.
                pass


def _validate_result_envelope(result: Any) -> list[str]:
    if not isinstance(result, Mapping):
        return ["result must be an object"]
    errors = _missing_fields(result, _RESULT_FIELDS, "result")
    if not _nonempty_string(result.get("summary")):
        errors.append("summary must be a non-empty string")
    for field in ("evidence", "artifacts", "risks", "unresolved"):
        if not isinstance(result.get(field), list):
            errors.append(f"{field} must be an array")
    if not _nonempty_string(result.get("recommended_next_action")):
        errors.append("recommended_next_action must be a non-empty string")
    return errors


def _validate_issue(issue: Any) -> list[str]:
    if not isinstance(issue, Mapping):
        return ["issue must be an object"]
    errors = _missing_fields(issue, ("issue_id", "type", "summary"), "issue")
    if not _nonempty_string(issue.get("issue_id")):
        errors.append("issue_id must be a non-empty string")
    issue_type = issue.get("type")
    if not _nonempty_string(issue_type) or issue_type not in _ISSUE_ROUTES:
        errors.append(f"type must be one of: {', '.join(sorted(_ISSUE_ROUTES))}")
    if not _nonempty_string(issue.get("summary")):
        errors.append("summary must be a non-empty string")
    if "change_type" in issue and issue["change_type"] not in _CHANGE_TYPES:
        errors.append(
            f"change_type must be one of: {', '.join(sorted(_CHANGE_TYPES))}"
        )
    return errors


def _raise_for_invalid_state(state: Any) -> None:
    errors = validate_state(state)
    if errors:
        raise ValueError("Invalid workflow state: " + "; ".join(errors))


def _missing_fields(value: Mapping[str, Any], fields: Sequence[str], label: str) -> list[str]:
    return [f"{label}.{field} is required" for field in fields if field not in value]


def _validate_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        return [f"{label} must be an array"]
    return [f"{label}[{index}] must be a string" for index, item in enumerate(value) if not _nonempty_string(item)]


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _read_json(path: str | os.PathLike[str]) -> Any:
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _atomic_write_json(path: str | os.PathLike[str], data: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _lock_is_abandoned(lock_path: Path, stale_after: float) -> bool:
    try:
        return time.time() - lock_path.stat().st_mtime > stale_after
    except OSError:
        return True


def _read_lock_metadata(lock_path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    try:
        with lock_path.open("r", encoding="ascii") as stream:
            for line in stream:
                if "=" in line:
                    key, _, value = line.partition("=")
                    metadata[key.strip()] = value.strip()
    except OSError:
        pass
    return metadata
