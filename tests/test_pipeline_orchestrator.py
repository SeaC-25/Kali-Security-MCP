"""
Tests for pipeline_orchestrator module (kali_mcp/core/pipeline_orchestrator.py)

Comprehensive coverage:
- PipelineMode enum: all members, values, membership, iteration, invalid values
- StageStatus enum: all members, values, membership, iteration, invalid values
- PipelineStage dataclass: creation, defaults, to_dict, mutable default isolation
- Pipeline dataclass: creation, defaults, to_dict, findings structure, mutable defaults
- PipelineOrchestrator:
    - __init__ (empty state, class constants)
    - PENTEST_STAGES, CTF_STAGES, AUDIT_STAGES (contents, counts, structure)
    - create_pipeline (all modes, invalid mode, config, no config, id format, storage)
    - get_pipeline (existing, missing)
    - list_pipelines (empty, multiple)
    - advance_stage (normal flow, completion, collect findings, missing pipeline, already done)
    - skip_stage (skippable, non-skippable, missing pipeline, already done, completion via skip)
    - start_pipeline (created state, already running, missing pipeline)
    - get_status (existing, missing)
    - get_recommendations (per-stage recs, completed pipeline, with vulns, missing pipeline)
    - _collect_findings (vulns, fragments, chains, flags, empty, partial, accumulation)
    - _get_stage_recommendations (all mapped stages, unmapped stages, vuln-enhanced exploitation)

130+ tests, pure unit tests, no subprocess, no network.
"""

import copy
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

from kali_mcp.core.pipeline_orchestrator import (
    PipelineMode,
    StageStatus,
    PipelineStage,
    Pipeline,
    PipelineOrchestrator,
)


# ===================== PipelineMode Enum =====================


class TestPipelineMode:
    """Full coverage for PipelineMode enum."""

    def test_pentest_value(self):
        assert PipelineMode.PENTEST.value == "pentest"

    def test_ctf_value(self):
        assert PipelineMode.CTF.value == "ctf"

    def test_audit_value(self):
        assert PipelineMode.AUDIT.value == "audit"

    def test_member_count(self):
        assert len(PipelineMode) == 3

    def test_enum_from_value_pentest(self):
        assert PipelineMode("pentest") is PipelineMode.PENTEST

    def test_enum_from_value_ctf(self):
        assert PipelineMode("ctf") is PipelineMode.CTF

    def test_enum_from_value_audit(self):
        assert PipelineMode("audit") is PipelineMode.AUDIT

    def test_enum_invalid_value(self):
        with pytest.raises(ValueError):
            PipelineMode("nonexistent")

    def test_is_str_subclass(self):
        assert isinstance(PipelineMode.PENTEST, str)

    def test_str_comparison(self):
        assert PipelineMode.PENTEST == "pentest"

    def test_isinstance_check(self):
        assert isinstance(PipelineMode.CTF, PipelineMode)

    def test_all_members_iterable(self):
        names = [m.name for m in PipelineMode]
        assert "PENTEST" in names
        assert "CTF" in names
        assert "AUDIT" in names

    def test_values_list(self):
        values = [m.value for m in PipelineMode]
        assert values == ["pentest", "ctf", "audit"]


# ===================== StageStatus Enum =====================


class TestStageStatus:
    """Full coverage for StageStatus enum."""

    def test_pending_value(self):
        assert StageStatus.PENDING.value == "pending"

    def test_running_value(self):
        assert StageStatus.RUNNING.value == "running"

    def test_completed_value(self):
        assert StageStatus.COMPLETED.value == "completed"

    def test_skipped_value(self):
        assert StageStatus.SKIPPED.value == "skipped"

    def test_failed_value(self):
        assert StageStatus.FAILED.value == "failed"

    def test_member_count(self):
        assert len(StageStatus) == 5

    def test_enum_from_value(self):
        assert StageStatus("pending") is StageStatus.PENDING

    def test_enum_invalid_value(self):
        with pytest.raises(ValueError):
            StageStatus("invalid")

    def test_is_str_subclass(self):
        assert isinstance(StageStatus.RUNNING, str)

    def test_str_comparison(self):
        assert StageStatus.COMPLETED == "completed"

    def test_isinstance_check(self):
        assert isinstance(StageStatus.FAILED, StageStatus)

    def test_all_members_iterable(self):
        names = [m.name for m in StageStatus]
        assert len(names) == 5
        assert "PENDING" in names
        assert "FAILED" in names

    def test_all_values(self):
        values = [m.value for m in StageStatus]
        assert values == ["pending", "running", "completed", "skipped", "failed"]


# ===================== PipelineStage Dataclass =====================


class TestPipelineStage:
    """Full coverage for PipelineStage dataclass."""

    def test_basic_creation(self):
        stage = PipelineStage(name="recon", description="Reconnaissance")
        assert stage.name == "recon"
        assert stage.description == "Reconnaissance"

    def test_default_status(self):
        stage = PipelineStage(name="s", description="d")
        assert stage.status is StageStatus.PENDING

    def test_default_result(self):
        stage = PipelineStage(name="s", description="d")
        assert stage.result == {}

    def test_default_started_at(self):
        stage = PipelineStage(name="s", description="d")
        assert stage.started_at is None

    def test_default_completed_at(self):
        stage = PipelineStage(name="s", description="d")
        assert stage.completed_at is None

    def test_default_skippable(self):
        stage = PipelineStage(name="s", description="d")
        assert stage.skippable is False

    def test_custom_skippable_true(self):
        stage = PipelineStage(name="s", description="d", skippable=True)
        assert stage.skippable is True

    def test_custom_status(self):
        stage = PipelineStage(name="s", description="d", status=StageStatus.RUNNING)
        assert stage.status is StageStatus.RUNNING

    def test_custom_result(self):
        stage = PipelineStage(name="s", description="d", result={"key": "val"})
        assert stage.result == {"key": "val"}

    def test_mutable_default_isolation(self):
        """Verify each instance gets its own result dict."""
        s1 = PipelineStage(name="s1", description="d1")
        s2 = PipelineStage(name="s2", description="d2")
        s1.result["x"] = 1
        assert "x" not in s2.result

    def test_to_dict_keys(self):
        stage = PipelineStage(name="recon", description="desc")
        d = stage.to_dict()
        expected_keys = {"name", "description", "status", "result",
                         "started_at", "completed_at", "skippable"}
        assert set(d.keys()) == expected_keys

    def test_to_dict_status_value(self):
        stage = PipelineStage(name="s", description="d", status=StageStatus.COMPLETED)
        d = stage.to_dict()
        assert d["status"] == "completed"

    def test_to_dict_name(self):
        stage = PipelineStage(name="recon", description="desc")
        d = stage.to_dict()
        assert d["name"] == "recon"

    def test_to_dict_description(self):
        stage = PipelineStage(name="s", description="my desc")
        d = stage.to_dict()
        assert d["description"] == "my desc"

    def test_to_dict_skippable_true(self):
        stage = PipelineStage(name="s", description="d", skippable=True)
        d = stage.to_dict()
        assert d["skippable"] is True

    def test_to_dict_skippable_false(self):
        stage = PipelineStage(name="s", description="d", skippable=False)
        d = stage.to_dict()
        assert d["skippable"] is False

    def test_to_dict_result_empty(self):
        stage = PipelineStage(name="s", description="d")
        d = stage.to_dict()
        assert d["result"] == {}

    def test_to_dict_result_populated(self):
        stage = PipelineStage(name="s", description="d", result={"a": 1})
        d = stage.to_dict()
        assert d["result"] == {"a": 1}

    def test_to_dict_timestamps_none(self):
        stage = PipelineStage(name="s", description="d")
        d = stage.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None

    def test_to_dict_timestamps_set(self):
        stage = PipelineStage(name="s", description="d",
                              started_at="2025-01-01T00:00:00",
                              completed_at="2025-01-01T01:00:00")
        d = stage.to_dict()
        assert d["started_at"] == "2025-01-01T00:00:00"
        assert d["completed_at"] == "2025-01-01T01:00:00"


# ===================== Pipeline Dataclass =====================


class TestPipeline:
    """Full coverage for Pipeline dataclass."""

    def test_basic_creation(self):
        p = Pipeline(pipeline_id="PL-TEST", mode=PipelineMode.PENTEST,
                     target="10.0.0.1")
        assert p.pipeline_id == "PL-TEST"
        assert p.mode is PipelineMode.PENTEST
        assert p.target == "10.0.0.1"

    def test_default_stages(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        assert p.stages == []

    def test_default_status(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        assert p.status == "created"

    def test_default_current_stage_idx(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        assert p.current_stage_idx == 0

    def test_default_config(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        assert p.config == {}

    def test_default_findings_structure(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        assert "vulns" in p.findings
        assert "fragments" in p.findings
        assert "chains" in p.findings
        assert "flags" in p.findings
        assert p.findings["vulns"] == []
        assert p.findings["fragments"] == []
        assert p.findings["chains"] == []
        assert p.findings["flags"] == []

    def test_mutable_stages_isolation(self):
        p1 = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        p2 = Pipeline(pipeline_id="PL-2", mode=PipelineMode.CTF, target="t")
        p1.stages.append(PipelineStage(name="s", description="d"))
        assert len(p2.stages) == 0

    def test_mutable_findings_isolation(self):
        p1 = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        p2 = Pipeline(pipeline_id="PL-2", mode=PipelineMode.CTF, target="t")
        p1.findings["vulns"].append({"x": 1})
        assert len(p2.findings["vulns"]) == 0

    def test_mutable_config_isolation(self):
        p1 = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        p2 = Pipeline(pipeline_id="PL-2", mode=PipelineMode.CTF, target="t")
        p1.config["k"] = "v"
        assert "k" not in p2.config

    def test_created_at_is_set(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        assert p.created_at is not None
        # Should be a valid ISO format
        datetime.fromisoformat(p.created_at)

    def test_to_dict_keys(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.PENTEST, target="t",
                     stages=[PipelineStage(name="s", description="d")])
        d = p.to_dict()
        expected_keys = {"pipeline_id", "mode", "target", "status", "created_at",
                         "current_stage", "progress", "stages", "findings_summary"}
        assert set(d.keys()) == expected_keys

    def test_to_dict_mode_value(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t",
                     stages=[PipelineStage(name="s", description="d")])
        d = p.to_dict()
        assert d["mode"] == "ctf"

    def test_to_dict_current_stage_normal(self):
        s = PipelineStage(name="recon", description="d")
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.PENTEST, target="t",
                     stages=[s])
        d = p.to_dict()
        assert d["current_stage"] == "recon"

    def test_to_dict_current_stage_done(self):
        """When current_stage_idx >= len(stages), current_stage is 'done'."""
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.PENTEST, target="t",
                     stages=[PipelineStage(name="s", description="d")])
        p.current_stage_idx = 1  # past the only stage
        d = p.to_dict()
        assert d["current_stage"] == "done"

    def test_to_dict_progress(self):
        stages = [PipelineStage(name=f"s{i}", description="d") for i in range(3)]
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t",
                     stages=stages)
        p.current_stage_idx = 1
        d = p.to_dict()
        assert d["progress"] == "1/3"

    def test_to_dict_stages_serialized(self):
        stages = [PipelineStage(name="s1", description="d1")]
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t",
                     stages=stages)
        d = p.to_dict()
        assert len(d["stages"]) == 1
        assert d["stages"][0]["name"] == "s1"

    def test_to_dict_findings_summary(self):
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t",
                     stages=[PipelineStage(name="s", description="d")])
        p.findings["vulns"].append({"type": "sqli"})
        p.findings["flags"].extend(["flag1", "flag2"])
        d = p.to_dict()
        assert d["findings_summary"]["vulns"] == 1
        assert d["findings_summary"]["flags"] == 2
        assert d["findings_summary"]["fragments"] == 0
        assert d["findings_summary"]["chains"] == 0

    def test_to_dict_empty_stages_done(self):
        """Pipeline with no stages and idx=0 should show 'done'."""
        p = Pipeline(pipeline_id="PL-1", mode=PipelineMode.CTF, target="t")
        # current_stage_idx=0 >= len(stages)=0, so should be 'done'
        d = p.to_dict()
        assert d["current_stage"] == "done"
        assert d["progress"] == "0/0"


# ===================== PipelineOrchestrator Class Constants =====================


class TestOrchestratorConstants:
    """Coverage for class-level stage definitions."""

    def test_pentest_stages_count(self):
        assert len(PipelineOrchestrator.PENTEST_STAGES) == 9

    def test_ctf_stages_count(self):
        assert len(PipelineOrchestrator.CTF_STAGES) == 6

    def test_audit_stages_count(self):
        assert len(PipelineOrchestrator.AUDIT_STAGES) == 6

    def test_pentest_stages_tuple_structure(self):
        for entry in PipelineOrchestrator.PENTEST_STAGES:
            assert len(entry) == 3
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], str)
            assert isinstance(entry[2], bool)

    def test_ctf_stages_tuple_structure(self):
        for entry in PipelineOrchestrator.CTF_STAGES:
            assert len(entry) == 3
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], str)
            assert isinstance(entry[2], bool)

    def test_audit_stages_tuple_structure(self):
        for entry in PipelineOrchestrator.AUDIT_STAGES:
            assert len(entry) == 3
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], str)
            assert isinstance(entry[2], bool)

    def test_pentest_first_stage_is_recon(self):
        assert PipelineOrchestrator.PENTEST_STAGES[0][0] == "recon"

    def test_pentest_last_stage_is_reporting(self):
        assert PipelineOrchestrator.PENTEST_STAGES[-1][0] == "reporting"

    def test_ctf_first_stage_is_quick_scan(self):
        assert PipelineOrchestrator.CTF_STAGES[0][0] == "quick_scan"

    def test_ctf_last_stage_is_flag_capture(self):
        assert PipelineOrchestrator.CTF_STAGES[-1][0] == "flag_capture"

    def test_audit_first_stage_is_source_analysis(self):
        assert PipelineOrchestrator.AUDIT_STAGES[0][0] == "source_analysis"

    def test_audit_last_stage_is_audit_report(self):
        assert PipelineOrchestrator.AUDIT_STAGES[-1][0] == "audit_report"

    def test_pentest_recon_not_skippable(self):
        assert PipelineOrchestrator.PENTEST_STAGES[0][2] is False

    def test_pentest_source_acquisition_skippable(self):
        assert PipelineOrchestrator.PENTEST_STAGES[1][2] is True

    def test_ctf_quick_scan_not_skippable(self):
        assert PipelineOrchestrator.CTF_STAGES[0][2] is False

    def test_audit_auto_verify_skippable(self):
        # auto_verify is at index 4 in AUDIT_STAGES
        assert PipelineOrchestrator.AUDIT_STAGES[4][0] == "auto_verify"
        assert PipelineOrchestrator.AUDIT_STAGES[4][2] is True

    def test_pentest_stage_names(self):
        names = [s[0] for s in PipelineOrchestrator.PENTEST_STAGES]
        expected = ["recon", "source_acquisition", "code_audit", "vuln_scan",
                    "cross_validation", "exploitation", "privilege_escalation",
                    "chain_building", "reporting"]
        assert names == expected

    def test_ctf_stage_names(self):
        names = [s[0] for s in PipelineOrchestrator.CTF_STAGES]
        expected = ["quick_scan", "source_acquisition", "code_audit",
                    "vuln_discovery", "payload_craft", "flag_capture"]
        assert names == expected

    def test_audit_stage_names(self):
        names = [s[0] for s in PipelineOrchestrator.AUDIT_STAGES]
        expected = ["source_analysis", "pattern_scan", "deep_audit",
                    "candidate_vulns", "auto_verify", "audit_report"]
        assert names == expected


# ===================== PipelineOrchestrator.__init__ =====================


class TestOrchestratorInit:
    """Coverage for __init__."""

    def test_init_creates_empty_pipelines(self):
        orch = PipelineOrchestrator()
        assert orch._pipelines == {}

    def test_init_pipelines_is_dict(self):
        orch = PipelineOrchestrator()
        assert isinstance(orch._pipelines, dict)


# ===================== create_pipeline =====================


class TestCreatePipeline:
    """Coverage for create_pipeline method."""

    def test_create_pentest_pipeline(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "10.0.0.1")
        assert p.mode is PipelineMode.PENTEST
        assert p.target == "10.0.0.1"

    def test_create_ctf_pipeline(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "http://ctf.example.com")
        assert p.mode is PipelineMode.CTF

    def test_create_audit_pipeline(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("audit", "/src/app")
        assert p.mode is PipelineMode.AUDIT

    def test_invalid_mode_raises(self):
        orch = PipelineOrchestrator()
        with pytest.raises(ValueError, match="不支持的流水线模式"):
            orch.create_pipeline("invalid_mode", "target")

    def test_pipeline_id_format(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        assert p.pipeline_id.startswith("PL-")
        assert len(p.pipeline_id) == 11  # "PL-" + 8 hex chars

    def test_pipeline_stored_in_dict(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        assert p.pipeline_id in orch._pipelines
        assert orch._pipelines[p.pipeline_id] is p

    def test_pipeline_config_none_default(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        assert p.config == {}

    def test_pipeline_config_provided(self):
        orch = PipelineOrchestrator()
        cfg = {"aggressive": True, "timeout": 60}
        p = orch.create_pipeline("pentest", "t", config=cfg)
        assert p.config == cfg

    def test_pentest_pipeline_stage_count(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        assert len(p.stages) == 9

    def test_ctf_pipeline_stage_count(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        assert len(p.stages) == 6

    def test_audit_pipeline_stage_count(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("audit", "t")
        assert len(p.stages) == 6

    def test_stages_are_pipeline_stage_instances(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        for s in p.stages:
            assert isinstance(s, PipelineStage)

    def test_stages_have_correct_names(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        names = [s.name for s in p.stages]
        expected = ["quick_scan", "source_acquisition", "code_audit",
                    "vuln_discovery", "payload_craft", "flag_capture"]
        assert names == expected

    def test_stages_skippable_flags_match(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        expected_skippable = [s[2] for s in PipelineOrchestrator.PENTEST_STAGES]
        actual_skippable = [s.skippable for s in p.stages]
        assert actual_skippable == expected_skippable

    def test_all_stages_start_pending(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        for s in p.stages:
            assert s.status is StageStatus.PENDING

    def test_pipeline_status_is_created(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        assert p.status == "created"

    def test_multiple_pipelines_unique_ids(self):
        orch = PipelineOrchestrator()
        ids = set()
        for _ in range(20):
            p = orch.create_pipeline("ctf", "t")
            ids.add(p.pipeline_id)
        assert len(ids) == 20


# ===================== get_pipeline =====================


class TestGetPipeline:
    """Coverage for get_pipeline method."""

    def test_get_existing(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        result = orch.get_pipeline(p.pipeline_id)
        assert result is p

    def test_get_missing(self):
        orch = PipelineOrchestrator()
        result = orch.get_pipeline("PL-NOTEXIST")
        assert result is None


# ===================== list_pipelines =====================


class TestListPipelines:
    """Coverage for list_pipelines method."""

    def test_list_empty(self):
        orch = PipelineOrchestrator()
        assert orch.list_pipelines() == []

    def test_list_single(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        result = orch.list_pipelines()
        assert len(result) == 1
        assert result[0]["pipeline_id"] == p.pipeline_id

    def test_list_multiple(self):
        orch = PipelineOrchestrator()
        orch.create_pipeline("pentest", "t1")
        orch.create_pipeline("ctf", "t2")
        orch.create_pipeline("audit", "t3")
        result = orch.list_pipelines()
        assert len(result) == 3

    def test_list_returns_dicts(self):
        orch = PipelineOrchestrator()
        orch.create_pipeline("ctf", "t")
        result = orch.list_pipelines()
        assert isinstance(result[0], dict)
        assert "pipeline_id" in result[0]


# ===================== start_pipeline =====================


class TestStartPipeline:
    """Coverage for start_pipeline method."""

    def test_start_success(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "10.0.0.1")
        result = orch.start_pipeline(p.pipeline_id)
        assert result["status"] == "started"
        assert result["pipeline_id"] == p.pipeline_id
        assert result["mode"] == "pentest"
        assert result["target"] == "10.0.0.1"
        assert result["first_stage"] == "recon"
        assert result["total_stages"] == 9

    def test_start_sets_first_stage_running(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        assert p.stages[0].status is StageStatus.RUNNING

    def test_start_sets_first_stage_started_at(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        assert p.stages[0].started_at is not None

    def test_start_sets_pipeline_running(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        assert p.status == "running"

    def test_start_missing_pipeline(self):
        orch = PipelineOrchestrator()
        result = orch.start_pipeline("PL-NOTEXIST")
        assert "error" in result

    def test_start_already_running(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        result = orch.start_pipeline(p.pipeline_id)
        assert "error" in result
        assert "running" in result["error"]

    def test_start_completed_pipeline(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        p.status = "completed"
        result = orch.start_pipeline(p.pipeline_id)
        assert "error" in result

    def test_start_ctf_first_stage(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        result = orch.start_pipeline(p.pipeline_id)
        assert result["first_stage"] == "quick_scan"
        assert result["total_stages"] == 6

    def test_start_audit_first_stage(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("audit", "t")
        result = orch.start_pipeline(p.pipeline_id)
        assert result["first_stage"] == "source_analysis"
        assert result["total_stages"] == 6


# ===================== advance_stage =====================


class TestAdvanceStage:
    """Coverage for advance_stage method."""

    def test_advance_missing_pipeline(self):
        orch = PipelineOrchestrator()
        result = orch.advance_stage("PL-NOTEXIST")
        assert "error" in result

    def test_advance_normal(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        result = orch.advance_stage(p.pipeline_id, result={"info": "done"})
        assert result["status"] == "stage_advanced"
        assert result["completed_stage"] == "recon"
        assert result["next_stage"] == "source_acquisition"

    def test_advance_sets_current_completed(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        assert p.stages[0].status is StageStatus.COMPLETED

    def test_advance_sets_completed_at(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        assert p.stages[0].completed_at is not None

    def test_advance_stores_result(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id, result={"ports": [80, 443]})
        assert p.stages[0].result == {"ports": [80, 443]}

    def test_advance_none_result_becomes_empty_dict(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        assert p.stages[0].result == {}

    def test_advance_sets_next_running(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        assert p.stages[1].status is StageStatus.RUNNING

    def test_advance_sets_next_started_at(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        assert p.stages[1].started_at is not None

    def test_advance_increments_idx(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        assert p.current_stage_idx == 0
        orch.advance_stage(p.pipeline_id)
        assert p.current_stage_idx == 1

    def test_advance_progress_string(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        result = orch.advance_stage(p.pipeline_id)
        assert result["progress"] == "1/9"

    def test_advance_to_completion(self):
        """Advance through all stages of CTF pipeline to completion."""
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        # CTF has 6 stages, advance through all
        for i in range(5):
            result = orch.advance_stage(p.pipeline_id)
            assert result["status"] == "stage_advanced"
        # Last advance completes the pipeline
        result = orch.advance_stage(p.pipeline_id)
        assert result["status"] == "pipeline_completed"
        assert p.status == "completed"

    def test_advance_already_completed(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        for _ in range(6):
            orch.advance_stage(p.pipeline_id)
        result = orch.advance_stage(p.pipeline_id)
        assert "error" in result

    def test_advance_pipeline_status_running(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        assert p.status == "running"

    def test_advance_completion_returns_findings(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        # Add a finding
        for i in range(5):
            orch.advance_stage(p.pipeline_id)
        result = orch.advance_stage(p.pipeline_id,
                                     result={"flags": ["flag{test}"]})
        assert result["status"] == "pipeline_completed"
        assert "findings" in result


# ===================== skip_stage =====================


class TestSkipStage:
    """Coverage for skip_stage method."""

    def test_skip_missing_pipeline(self):
        orch = PipelineOrchestrator()
        result = orch.skip_stage("PL-NOTEXIST")
        assert "error" in result

    def test_skip_non_skippable_stage(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        # First stage (recon) is not skippable
        result = orch.skip_stage(p.pipeline_id)
        assert "error" in result
        assert "不可跳过" in result["error"]

    def test_skip_skippable_stage(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        # Advance past recon to source_acquisition (skippable)
        orch.advance_stage(p.pipeline_id)
        result = orch.skip_stage(p.pipeline_id)
        assert result["status"] == "stage_skipped"
        assert result["skipped_stage"] == "source_acquisition"
        assert result["next_stage"] == "code_audit"

    def test_skip_sets_status_skipped(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)  # past recon
        orch.skip_stage(p.pipeline_id)
        assert p.stages[1].status is StageStatus.SKIPPED

    def test_skip_sets_completed_at(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        orch.skip_stage(p.pipeline_id)
        assert p.stages[1].completed_at is not None

    def test_skip_increments_idx(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)  # idx=1
        orch.skip_stage(p.pipeline_id)  # idx=2
        assert p.current_stage_idx == 2

    def test_skip_sets_next_running(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        orch.skip_stage(p.pipeline_id)
        assert p.stages[2].status is StageStatus.RUNNING

    def test_skip_sets_next_started_at(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        orch.skip_stage(p.pipeline_id)
        assert p.stages[2].started_at is not None

    def test_skip_completed_pipeline(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        # Complete all stages
        for _ in range(6):
            orch.advance_stage(p.pipeline_id)
        result = orch.skip_stage(p.pipeline_id)
        assert "error" in result

    def test_skip_to_completion(self):
        """Skip the last skippable stage that happens to be the final stage."""
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        # Advance to chain_building (index 7, skippable=True)
        for i in range(7):
            orch.advance_stage(p.pipeline_id)
        # Now at chain_building, skip it
        result = orch.skip_stage(p.pipeline_id)
        assert result["status"] == "stage_skipped"
        assert result["next_stage"] == "reporting"

    def test_skip_final_skippable_to_completion(self):
        """Create a scenario where skipping the last stage completes the pipeline."""
        orch = PipelineOrchestrator()
        # Use audit pipeline: last stage is audit_report (not skippable),
        # but auto_verify (index 4) is skippable.
        # We need to get to the last stage. Let's manipulate directly.
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        # Make last stage skippable for testing
        p.stages[-1].skippable = True
        # Advance to the last stage
        for i in range(len(p.stages) - 1):
            orch.advance_stage(p.pipeline_id)
        result = orch.skip_stage(p.pipeline_id)
        assert result["status"] == "pipeline_completed"
        assert result["skipped"] == p.stages[-1].name


# ===================== get_status =====================


class TestGetStatus:
    """Coverage for get_status method."""

    def test_get_status_existing(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        result = orch.get_status(p.pipeline_id)
        assert result["pipeline_id"] == p.pipeline_id
        assert result["mode"] == "ctf"

    def test_get_status_missing(self):
        orch = PipelineOrchestrator()
        result = orch.get_status("PL-NOTEXIST")
        assert "error" in result

    def test_get_status_returns_to_dict(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        result = orch.get_status(p.pipeline_id)
        expected = p.to_dict()
        assert result == expected


# ===================== get_recommendations =====================


class TestGetRecommendations:
    """Coverage for get_recommendations method."""

    def test_recommendations_missing_pipeline(self):
        orch = PipelineOrchestrator()
        result = orch.get_recommendations("PL-NOTEXIST")
        assert "error" in result

    def test_recommendations_completed_pipeline(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        for _ in range(6):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["recommendations"] == []
        assert "已完成" in result["reason"]

    def test_recommendations_recon_stage(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "10.0.0.1")
        orch.start_pipeline(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "recon"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "nmap_scan" in tools
        assert "whatweb_scan" in tools

    def test_recommendations_quick_scan_stage(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "http://target.com")
        orch.start_pipeline(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "quick_scan"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "nmap_scan" in tools
        assert "gobuster_scan" in tools

    def test_recommendations_source_acquisition(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "source_acquisition"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "execute_command" in tools

    def test_recommendations_code_audit(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)  # past recon
        orch.advance_stage(p.pipeline_id)  # past source_acquisition
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "code_audit"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "code_audit_comprehensive" in tools

    def test_recommendations_vuln_scan(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        for _ in range(3):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "vuln_scan"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "nuclei_web_scan" in tools
        assert "sqlmap_scan" in tools

    def test_recommendations_exploitation_without_vulns(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        for _ in range(5):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "exploitation"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "searchsploit_search" in tools

    def test_recommendations_exploitation_with_vulns(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        # Add vulns to findings
        p.findings["vulns"] = [
            {"type": "sqli", "url": "/login"},
            {"type": "xss", "url": "/search"},
        ]
        for _ in range(5):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        tools = [r["tool"] for r in result["recommendations"]]
        assert "verify_vulnerability" in tools

    def test_recommendations_exploitation_with_many_vulns_caps_at_3(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        p.findings["vulns"] = [{"type": f"vuln{i}"} for i in range(10)]
        for _ in range(5):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        verify_recs = [r for r in result["recommendations"]
                       if r["tool"] == "verify_vulnerability"]
        assert len(verify_recs) == 3

    def test_recommendations_unmapped_stage(self):
        """Stages not in rec_map should return empty base recommendations."""
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        # Advance to cross_validation (index 4) which is not in rec_map
        for _ in range(4):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "cross_validation"
        # No vulns, no mapping -> empty recommendations
        assert result["recommendations"] == []

    def test_recommendations_payload_craft(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)
        for _ in range(4):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "payload_craft"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "intelligent_sql_injection_payloads" in tools

    def test_recommendations_source_analysis_audit(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("audit", "t")
        orch.start_pipeline(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "source_analysis"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "whatweb_scan" in tools

    def test_recommendations_pattern_scan_audit(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("audit", "t")
        orch.start_pipeline(p.pipeline_id)
        orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        assert result["current_stage"] == "pattern_scan"
        tools = [r["tool"] for r in result["recommendations"]]
        assert "semgrep_scan" in tools

    def test_recommendations_target_in_args(self):
        """Verify target is embedded in recommendation args."""
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "192.168.1.1")
        orch.start_pipeline(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        for rec in result["recommendations"]:
            if rec["tool"] == "nmap_scan":
                assert "192.168.1.1" in rec["args"]

    def test_recommendations_vuln_type_in_reason(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        p.findings["vulns"] = [{"type": "rce"}]
        for _ in range(5):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        verify_recs = [r for r in result["recommendations"]
                       if r["tool"] == "verify_vulnerability"]
        assert len(verify_recs) == 1
        assert "rce" in verify_recs[0]["reason"]

    def test_recommendations_vuln_without_type_key(self):
        """Vulns without 'type' key should use 'unknown' as default."""
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)
        p.findings["vulns"] = [{"url": "/test"}]  # no 'type' key
        for _ in range(5):
            orch.advance_stage(p.pipeline_id)
        result = orch.get_recommendations(p.pipeline_id)
        verify_recs = [r for r in result["recommendations"]
                       if r["tool"] == "verify_vulnerability"]
        assert len(verify_recs) == 1
        assert "unknown" in verify_recs[0]["args"]


# ===================== _collect_findings =====================


class TestCollectFindings:
    """Coverage for _collect_findings private method."""

    def test_collect_vulns(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {"vulns": [{"type": "sqli"}]})
        assert len(p.findings["vulns"]) == 1
        assert p.findings["vulns"][0]["type"] == "sqli"

    def test_collect_fragments(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {"fragments": ["frag1", "frag2"]})
        assert p.findings["fragments"] == ["frag1", "frag2"]

    def test_collect_chains(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {"chains": [{"steps": [1, 2]}]})
        assert len(p.findings["chains"]) == 1

    def test_collect_flags(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {"flags": ["flag{test123}"]})
        assert p.findings["flags"] == ["flag{test123}"]

    def test_collect_empty_result(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {})
        assert p.findings["vulns"] == []
        assert p.findings["fragments"] == []
        assert p.findings["chains"] == []
        assert p.findings["flags"] == []

    def test_collect_partial_keys(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {"vulns": [{"a": 1}]})
        assert len(p.findings["vulns"]) == 1
        assert p.findings["fragments"] == []

    def test_collect_accumulation(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {"vulns": [{"type": "sqli"}]})
        orch._collect_findings(p, stage, {"vulns": [{"type": "xss"}]})
        assert len(p.findings["vulns"]) == 2

    def test_collect_ignores_unknown_keys(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        orch._collect_findings(p, stage, {"unknown_key": [1, 2, 3]})
        assert "unknown_key" not in p.findings

    def test_collect_all_keys_at_once(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = p.stages[0]
        result = {
            "vulns": [{"type": "sqli"}],
            "fragments": ["f1"],
            "chains": [{"c": 1}],
            "flags": ["flag{a}"],
        }
        orch._collect_findings(p, stage, result)
        assert len(p.findings["vulns"]) == 1
        assert len(p.findings["fragments"]) == 1
        assert len(p.findings["chains"]) == 1
        assert len(p.findings["flags"]) == 1


# ===================== _get_stage_recommendations =====================


class TestGetStageRecommendations:
    """Coverage for _get_stage_recommendations private method."""

    def test_recon_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "10.0.0.1")
        stage = PipelineStage(name="recon", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "nmap_scan" in tools
        assert "whatweb_scan" in tools

    def test_quick_scan_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "http://t.com")
        stage = PipelineStage(name="quick_scan", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "nmap_scan" in tools
        assert "gobuster_scan" in tools

    def test_source_acquisition_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = PipelineStage(name="source_acquisition", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "execute_command" in tools

    def test_code_audit_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = PipelineStage(name="code_audit", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "code_audit_comprehensive" in tools

    def test_vuln_scan_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = PipelineStage(name="vuln_scan", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "nuclei_web_scan" in tools
        assert "sqlmap_scan" in tools

    def test_vuln_discovery_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        stage = PipelineStage(name="vuln_discovery", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "nuclei_web_scan" in tools

    def test_exploitation_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = PipelineStage(name="exploitation", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "searchsploit_search" in tools

    def test_payload_craft_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        stage = PipelineStage(name="payload_craft", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "intelligent_sql_injection_payloads" in tools

    def test_source_analysis_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("audit", "t")
        stage = PipelineStage(name="source_analysis", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "whatweb_scan" in tools

    def test_pattern_scan_recommendations(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("audit", "t")
        stage = PipelineStage(name="pattern_scan", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "semgrep_scan" in tools

    def test_unmapped_stage_empty(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = PipelineStage(name="nonexistent_stage", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        assert recs == []

    def test_exploitation_with_vulns_prepends_verify(self):
        """Verify that vuln-based recs come before rec_map recs."""
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        p.findings["vulns"] = [{"type": "sqli"}]
        stage = PipelineStage(name="exploitation", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        # verify_vulnerability should appear before searchsploit_search
        tools = [r["tool"] for r in recs]
        verify_idx = tools.index("verify_vulnerability")
        search_idx = tools.index("searchsploit_search")
        assert verify_idx < search_idx

    def test_exploitation_without_vulns_no_verify(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = PipelineStage(name="exploitation", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "verify_vulnerability" not in tools

    def test_recommendation_has_tool_args_reason(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        stage = PipelineStage(name="recon", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        for rec in recs:
            assert "tool" in rec
            assert "args" in rec
            assert "reason" in rec

    def test_non_exploitation_stage_ignores_vulns(self):
        """Vulns should only enhance exploitation stage, not others."""
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        p.findings["vulns"] = [{"type": "sqli"}]
        stage = PipelineStage(name="recon", description="d")
        recs = orch._get_stage_recommendations(p, stage)
        tools = [r["tool"] for r in recs]
        assert "verify_vulnerability" not in tools


# ===================== Integration: Full Pipeline Flow =====================


class TestFullPipelineFlow:
    """Integration tests covering complete pipeline lifecycle."""

    def test_pentest_full_flow(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "10.0.0.1")
        assert p.status == "created"

        # Start
        result = orch.start_pipeline(p.pipeline_id)
        assert result["status"] == "started"
        assert p.status == "running"

        # Advance through all 9 stages
        for i in range(9):
            result = orch.advance_stage(p.pipeline_id,
                                         result={"info": f"stage_{i}"})
            if i < 8:
                assert result["status"] == "stage_advanced"
            else:
                assert result["status"] == "pipeline_completed"

        assert p.status == "completed"

    def test_ctf_flow_with_skip(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "http://ctf.com")

        orch.start_pipeline(p.pipeline_id)

        # Advance past quick_scan
        orch.advance_stage(p.pipeline_id)

        # Skip source_acquisition (skippable)
        result = orch.skip_stage(p.pipeline_id)
        assert result["status"] == "stage_skipped"

        # Skip code_audit (skippable)
        result = orch.skip_stage(p.pipeline_id)
        assert result["status"] == "stage_skipped"

        # Continue with remaining stages
        for _ in range(3):
            result = orch.advance_stage(p.pipeline_id)

        assert p.status == "completed"

    def test_findings_accumulate_across_stages(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)

        orch.advance_stage(p.pipeline_id,
                           result={"vulns": [{"type": "sqli"}]})
        orch.advance_stage(p.pipeline_id,
                           result={"vulns": [{"type": "xss"}]})
        assert len(p.findings["vulns"]) == 2

    def test_pipeline_status_after_multiple_advances(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)

        # Verify each advance keeps pipeline running
        for i in range(5):
            orch.advance_stage(p.pipeline_id)
            assert p.status == "running"

        # Final advance completes
        orch.advance_stage(p.pipeline_id)
        assert p.status == "completed"

    def test_list_reflects_state_changes(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")

        listing = orch.list_pipelines()
        assert listing[0]["status"] == "created"

        orch.start_pipeline(p.pipeline_id)
        listing = orch.list_pipelines()
        assert listing[0]["status"] == "running"

    def test_get_recommendations_changes_per_stage(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("pentest", "t")
        orch.start_pipeline(p.pipeline_id)

        rec1 = orch.get_recommendations(p.pipeline_id)
        assert rec1["current_stage"] == "recon"

        orch.advance_stage(p.pipeline_id)
        rec2 = orch.get_recommendations(p.pipeline_id)
        assert rec2["current_stage"] == "source_acquisition"

    def test_multiple_pipelines_independent(self):
        orch = PipelineOrchestrator()
        p1 = orch.create_pipeline("pentest", "t1")
        p2 = orch.create_pipeline("ctf", "t2")

        orch.start_pipeline(p1.pipeline_id)
        assert p1.status == "running"
        assert p2.status == "created"

        orch.advance_stage(p1.pipeline_id)
        assert p1.current_stage_idx == 1
        assert p2.current_stage_idx == 0

    def test_advance_with_flags_in_ctf(self):
        orch = PipelineOrchestrator()
        p = orch.create_pipeline("ctf", "t")
        orch.start_pipeline(p.pipeline_id)

        # Advance through stages, capturing a flag in the last one
        for i in range(5):
            orch.advance_stage(p.pipeline_id)

        result = orch.advance_stage(p.pipeline_id,
                                     result={"flags": ["flag{w1nn3r}"]})
        assert result["status"] == "pipeline_completed"
        assert "flag{w1nn3r}" in p.findings["flags"]
