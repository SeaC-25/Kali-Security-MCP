"""
Comprehensive unit tests for kali_mcp.core.result_aggregator

Covers:
- Enums: ResultSeverity, ResultType
- Dataclasses: AgentResult, Finding, AggregatedResult, CorrelatedFinding
- Class: ResultAggregator (all public and private methods)
- Report generation (markdown, json, html)
- Flag extraction patterns
- Auto-discovery of findings from tool output
- Deduplication, categorization, correlation
- Edge cases and boundary values
"""

import asyncio
import json
import re
import tempfile
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from kali_mcp.core.result_aggregator import (
    ResultSeverity,
    ResultType,
    AgentResult,
    Finding,
    AggregatedResult,
    CorrelatedFinding,
    ResultAggregator,
)
from kali_mcp.core.intent_analyzer import (
    IntentAnalysis,
    AttackIntent,
    TargetInfo,
    TargetType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target_info(value="http://example.com", ttype=TargetType.URL):
    return TargetInfo(original=value, type=ttype, value=value)


def _make_intent_analysis(
    user_input="scan target",
    intent=AttackIntent.RECONNAISSANCE,
    targets=None,
):
    if targets is None:
        targets = [_make_target_info()]
    return IntentAnalysis(
        user_input=user_input,
        intent=intent,
        targets=targets,
        constraints=[],
    )


def _make_agent_result(
    agent_id="agent_1",
    task_id="task_1",
    tool_name="nmap",
    target="192.168.1.1",
    success=True,
    execution_time=5.0,
    output="",
    parsed_data=None,
    findings=None,
    errors=None,
    metadata=None,
):
    return AgentResult(
        agent_id=agent_id,
        task_id=task_id,
        tool_name=tool_name,
        target=target,
        success=success,
        execution_time=execution_time,
        output=output,
        parsed_data=parsed_data or {},
        findings=findings or [],
        errors=errors or [],
        metadata=metadata or {},
    )


def _make_finding(
    finding_type=ResultType.VULNERABILITY,
    severity=ResultSeverity.HIGH,
    title="Test Finding",
    description="A test finding",
    evidence=None,
    source="agent_1",
    confidence=0.7,
    cve_id=None,
    cvss_score=None,
    poc_available=False,
    flag_content=None,
):
    return Finding(
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence or [],
        source=source,
        confidence=confidence,
        cve_id=cve_id,
        cvss_score=cvss_score,
        poc_available=poc_available,
        flag_content=flag_content,
    )


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ===========================================================================
# 1. Enum Tests
# ===========================================================================


class TestResultSeverity:
    def test_all_members_exist(self):
        assert ResultSeverity.CRITICAL.value == "critical"
        assert ResultSeverity.HIGH.value == "high"
        assert ResultSeverity.MEDIUM.value == "medium"
        assert ResultSeverity.LOW.value == "low"
        assert ResultSeverity.INFO.value == "info"

    def test_member_count(self):
        assert len(ResultSeverity) == 5

    def test_from_value(self):
        assert ResultSeverity("critical") == ResultSeverity.CRITICAL
        assert ResultSeverity("info") == ResultSeverity.INFO

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ResultSeverity("unknown")

    def test_identity(self):
        assert ResultSeverity.HIGH is ResultSeverity.HIGH

    def test_inequality(self):
        assert ResultSeverity.HIGH != ResultSeverity.LOW


class TestResultType:
    def test_all_members_exist(self):
        assert ResultType.VULNERABILITY.value == "vulnerability"
        assert ResultType.ASSET.value == "asset"
        assert ResultType.CREDENTIAL.value == "credential"
        assert ResultType.FLAG.value == "flag"
        assert ResultType.ERROR.value == "error"
        assert ResultType.INFO.value == "info"
        assert ResultType.METADATA.value == "metadata"

    def test_member_count(self):
        assert len(ResultType) == 7

    def test_from_value(self):
        assert ResultType("flag") == ResultType.FLAG

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ResultType("nonexistent")


# ===========================================================================
# 2. Dataclass Tests
# ===========================================================================


class TestAgentResult:
    def test_basic_creation(self):
        r = _make_agent_result()
        assert r.agent_id == "agent_1"
        assert r.task_id == "task_1"
        assert r.success is True
        assert r.execution_time == 5.0

    def test_default_timestamp_is_datetime(self):
        r = _make_agent_result()
        assert isinstance(r.timestamp, datetime)

    def test_default_output_empty_string(self):
        r = AgentResult(
            agent_id="a", task_id="t", tool_name="x",
            target="y", success=True, execution_time=1.0,
        )
        assert r.output == ""

    def test_mutable_defaults_isolation(self):
        r1 = _make_agent_result()
        r2 = _make_agent_result()
        r1.parsed_data["key"] = "val"
        assert "key" not in r2.parsed_data

    def test_errors_list_isolation(self):
        r1 = _make_agent_result()
        r2 = _make_agent_result()
        r1.errors.append("err")
        assert len(r2.errors) == 0

    def test_metadata_isolation(self):
        r1 = _make_agent_result()
        r2 = _make_agent_result()
        r1.metadata["k"] = 1
        assert "k" not in r2.metadata

    def test_findings_field_isolation(self):
        r1 = _make_agent_result()
        r2 = _make_agent_result()
        r1.findings.append(_make_finding())
        assert len(r2.findings) == 0

    def test_with_custom_fields(self):
        r = _make_agent_result(
            output="test output",
            parsed_data={"a": 1},
            errors=["err1"],
        )
        assert r.output == "test output"
        assert r.parsed_data == {"a": 1}
        assert r.errors == ["err1"]


class TestFinding:
    def test_basic_creation(self):
        f = _make_finding()
        assert f.finding_type == ResultType.VULNERABILITY
        assert f.severity == ResultSeverity.HIGH
        assert f.title == "Test Finding"

    def test_default_confidence(self):
        f = Finding(
            finding_type=ResultType.INFO,
            severity=ResultSeverity.INFO,
            title="t", description="d",
        )
        assert f.confidence == 0.5

    def test_default_optionals(self):
        f = _make_finding()
        assert f.cve_id is None
        assert f.cvss_score is None
        assert f.poc_available is False
        assert f.flag_content is None

    def test_evidence_isolation(self):
        f1 = _make_finding()
        f2 = _make_finding()
        f1.evidence.append("ev")
        assert len(f2.evidence) == 0

    def test_with_cve(self):
        f = _make_finding(cve_id="CVE-2024-1234", cvss_score=9.8)
        assert f.cve_id == "CVE-2024-1234"
        assert f.cvss_score == 9.8

    def test_with_flag_content(self):
        f = _make_finding(flag_content="flag{test}")
        assert f.flag_content == "flag{test}"


class TestAggregatedResult:
    def test_basic_creation(self):
        ia = _make_intent_analysis()
        ar = AggregatedResult(
            intent_analysis=ia,
            agent_results=[],
        )
        assert ar.total_execution_time == 0
        assert ar.success_rate == 0
        assert ar.extracted_flags == []

    def test_mutable_defaults_isolation(self):
        ia = _make_intent_analysis()
        ar1 = AggregatedResult(intent_analysis=ia, agent_results=[])
        ar2 = AggregatedResult(intent_analysis=ia, agent_results=[])
        ar1.all_findings.append(_make_finding())
        assert len(ar2.all_findings) == 0

    def test_extracted_flags_isolation(self):
        ia = _make_intent_analysis()
        ar1 = AggregatedResult(intent_analysis=ia, agent_results=[])
        ar2 = AggregatedResult(intent_analysis=ia, agent_results=[])
        ar1.extracted_flags.append("flag{a}")
        assert len(ar2.extracted_flags) == 0

    def test_findings_by_type_isolation(self):
        ia = _make_intent_analysis()
        ar1 = AggregatedResult(intent_analysis=ia, agent_results=[])
        ar2 = AggregatedResult(intent_analysis=ia, agent_results=[])
        ar1.findings_by_type[ResultType.FLAG] = [_make_finding()]
        assert ResultType.FLAG not in ar2.findings_by_type

    def test_aggregation_time_is_datetime(self):
        ia = _make_intent_analysis()
        ar = AggregatedResult(intent_analysis=ia, agent_results=[])
        assert isinstance(ar.aggregation_time, datetime)


class TestCorrelatedFinding:
    def test_basic_creation(self):
        f1 = _make_finding(title="F1")
        f2 = _make_finding(title="F2")
        cf = CorrelatedFinding(
            correlation_id="corr_0",
            title="Multiple findings",
            description="2 findings",
            findings=[f1, f2],
            correlation_type="same_target",
            confidence=0.8,
            severity=ResultSeverity.HIGH,
        )
        assert cf.correlation_id == "corr_0"
        assert len(cf.findings) == 2
        assert cf.confidence == 0.8


# ===========================================================================
# 3. ResultAggregator Initialization
# ===========================================================================


class TestResultAggregatorInit:
    def test_instantiation(self):
        agg = ResultAggregator()
        assert isinstance(agg, ResultAggregator)

    def test_flag_patterns_count(self):
        agg = ResultAggregator()
        assert len(agg.flag_patterns) == 7

    def test_flag_patterns_are_compiled_regex(self):
        agg = ResultAggregator()
        for p in agg.flag_patterns:
            assert isinstance(p, re.Pattern)


# ===========================================================================
# 4. _parse_agent_result
# ===========================================================================


class TestParseAgentResult:
    def test_with_parsed_data_findings(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            parsed_data={
                "findings": [
                    {
                        "type": "vulnerability",
                        "severity": "high",
                        "title": "SQLi",
                        "description": "SQL Injection found",
                        "evidence": ["some evidence"],
                        "confidence": 0.9,
                    }
                ]
            }
        )
        findings = agg._parse_agent_result(result)
        assert len(findings) == 1
        assert findings[0].title == "SQLi"
        assert findings[0].severity == ResultSeverity.HIGH
        assert findings[0].source == "agent_1"
        assert findings[0].confidence == 0.9

    def test_with_parsed_data_defaults(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            parsed_data={"findings": [{}]}
        )
        findings = agg._parse_agent_result(result)
        assert len(findings) == 1
        assert findings[0].finding_type == ResultType.INFO
        assert findings[0].severity == ResultSeverity.MEDIUM
        assert findings[0].confidence == 0.5

    def test_parsed_data_empty_findings_list(self):
        agg = ResultAggregator()
        result = _make_agent_result(parsed_data={"findings": []})
        findings = agg._parse_agent_result(result)
        assert len(findings) == 0

    def test_fallback_to_auto_discover(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            output="Found SQL injection vulnerability",
        )
        findings = agg._parse_agent_result(result)
        assert any("SQL injection" in f.title for f in findings)

    def test_no_parsed_data_no_output(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="")
        findings = agg._parse_agent_result(result)
        assert len(findings) == 0

    def test_parsed_data_without_findings_key_falls_through(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            parsed_data={"other": "data"},
            output="80/tcp open http",
        )
        findings = agg._parse_agent_result(result)
        assert any("Open port: 80" in f.title for f in findings)

    def test_multiple_parsed_findings(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            parsed_data={
                "findings": [
                    {"type": "vulnerability", "severity": "critical", "title": "RCE"},
                    {"type": "asset", "severity": "info", "title": "Port 80"},
                ]
            }
        )
        findings = agg._parse_agent_result(result)
        assert len(findings) == 2


# ===========================================================================
# 5. _auto_discover_findings
# ===========================================================================


class TestAutoDiscoverFindings:
    def test_empty_output(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="")
        assert agg._auto_discover_findings(result) == []

    def test_none_output(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="")
        result.output = None
        assert agg._auto_discover_findings(result) == []

    def test_sql_injection_keyword(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="sql injection detected in param id")
        findings = agg._auto_discover_findings(result)
        titles = [f.title for f in findings]
        assert "SQL injection detected" in titles

    def test_xss_keyword(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="Found XSS vulnerability")
        findings = agg._auto_discover_findings(result)
        titles = [f.title for f in findings]
        assert "XSS detected" in titles

    def test_rce_keyword(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="RCE possible via deserialization")
        findings = agg._auto_discover_findings(result)
        assert any("RCE" in f.title for f in findings)

    def test_lfi_keyword(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="LFI found at /page?file=")
        findings = agg._auto_discover_findings(result)
        assert any("LFI" in f.title for f in findings)

    def test_csrf_keyword(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="CSRF token missing")
        findings = agg._auto_discover_findings(result)
        assert any("CSRF" in f.title for f in findings)

    def test_case_insensitive_keywords(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="sql INJECTION found")
        findings = agg._auto_discover_findings(result)
        assert len(findings) >= 1

    def test_nmap_port_format(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="80/tcp open http\n443/tcp open https")
        findings = agg._auto_discover_findings(result)
        port_titles = [f.title for f in findings if "Open port" in f.title]
        assert "Open port: 80" in port_titles
        assert "Open port: 443" in port_titles

    def test_udp_port(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="53/udp open domain")
        findings = agg._auto_discover_findings(result)
        assert any("Open port: 53" in f.title for f in findings)

    def test_alternative_port_format(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="Port 8080/tcp is open")
        findings = agg._auto_discover_findings(result)
        assert any("Open port: 8080" in f.title for f in findings)

    def test_port_finding_metadata(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="22/tcp open ssh")
        findings = agg._auto_discover_findings(result)
        port_findings = [f for f in findings if "Open port" in f.title]
        assert len(port_findings) >= 1
        pf = port_findings[0]
        assert pf.finding_type == ResultType.ASSET
        assert pf.severity == ResultSeverity.INFO
        assert pf.confidence == 0.9

    def test_vuln_finding_metadata(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            agent_id="scanner_1",
            tool_name="sqlmap",
            target="10.0.0.1",
            output="SQL injection found",
        )
        findings = agg._auto_discover_findings(result)
        vuln = [f for f in findings if "SQL injection" in f.title][0]
        assert vuln.finding_type == ResultType.VULNERABILITY
        assert vuln.severity == ResultSeverity.HIGH
        assert vuln.confidence == 0.7
        assert vuln.source == "scanner_1"
        assert "Tool: sqlmap" in vuln.evidence
        assert "Target: 10.0.0.1" in vuln.evidence

    def test_multiple_keywords_in_one_output(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            output="Found SQL injection and XSS and RCE"
        )
        findings = agg._auto_discover_findings(result)
        titles = [f.title for f in findings]
        assert "SQL injection detected" in titles
        assert "XSS detected" in titles
        assert "RCE detected" in titles

    def test_no_findings_in_clean_output(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="All checks passed. No issues.")
        findings = agg._auto_discover_findings(result)
        assert len(findings) == 0

    def test_port_closed_not_detected(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="80/tcp closed http")
        findings = agg._auto_discover_findings(result)
        assert not any("Open port" in f.title for f in findings)


# ===========================================================================
# 6. _deduplicate_findings
# ===========================================================================


class TestDeduplicateFindings:
    def test_no_duplicates(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", description="desc A")
        f2 = _make_finding(title="B", description="desc B")
        result = agg._deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_exact_duplicates_removed(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", description="desc A")
        f2 = _make_finding(title="A", description="desc A")
        result = agg._deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_same_title_different_description(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", description="desc X")
        f2 = _make_finding(title="A", description="desc Y")
        result = agg._deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_same_title_description_different_type(self):
        agg = ResultAggregator()
        f1 = _make_finding(
            finding_type=ResultType.VULNERABILITY,
            title="A", description="d",
        )
        f2 = _make_finding(
            finding_type=ResultType.ASSET,
            title="A", description="d",
        )
        result = agg._deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        agg = ResultAggregator()
        assert agg._deduplicate_findings([]) == []

    def test_description_truncation_at_100(self):
        """Two findings with same first 100 chars but different after should dedup."""
        agg = ResultAggregator()
        common = "x" * 100
        f1 = _make_finding(title="A", description=common + " AAA")
        f2 = _make_finding(title="A", description=common + " BBB")
        result = agg._deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_preserves_first_occurrence(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", description="d", source="src1")
        f2 = _make_finding(title="A", description="d", source="src2")
        result = agg._deduplicate_findings([f1, f2])
        assert result[0].source == "src1"

    def test_triple_duplicates(self):
        agg = ResultAggregator()
        f = _make_finding(title="Same", description="Same")
        result = agg._deduplicate_findings([f, f, f])
        assert len(result) == 1


# ===========================================================================
# 7. _categorize_by_type / _categorize_by_severity
# ===========================================================================


class TestCategorization:
    def test_categorize_by_type_empty(self):
        agg = ResultAggregator()
        result = agg._categorize_by_type([])
        assert result == {}

    def test_categorize_by_type_single(self):
        agg = ResultAggregator()
        f = _make_finding(finding_type=ResultType.VULNERABILITY)
        result = agg._categorize_by_type([f])
        assert ResultType.VULNERABILITY in result
        assert len(result[ResultType.VULNERABILITY]) == 1

    def test_categorize_by_type_multiple_types(self):
        agg = ResultAggregator()
        f1 = _make_finding(finding_type=ResultType.VULNERABILITY)
        f2 = _make_finding(finding_type=ResultType.ASSET)
        f3 = _make_finding(finding_type=ResultType.VULNERABILITY)
        result = agg._categorize_by_type([f1, f2, f3])
        assert len(result[ResultType.VULNERABILITY]) == 2
        assert len(result[ResultType.ASSET]) == 1

    def test_categorize_by_severity_empty(self):
        agg = ResultAggregator()
        result = agg._categorize_by_severity([])
        assert result == {}

    def test_categorize_by_severity_single(self):
        agg = ResultAggregator()
        f = _make_finding(severity=ResultSeverity.CRITICAL)
        result = agg._categorize_by_severity([f])
        assert ResultSeverity.CRITICAL in result
        assert len(result[ResultSeverity.CRITICAL]) == 1

    def test_categorize_by_severity_mixed(self):
        agg = ResultAggregator()
        f1 = _make_finding(severity=ResultSeverity.HIGH)
        f2 = _make_finding(severity=ResultSeverity.LOW)
        f3 = _make_finding(severity=ResultSeverity.HIGH)
        result = agg._categorize_by_severity([f1, f2, f3])
        assert len(result[ResultSeverity.HIGH]) == 2
        assert len(result[ResultSeverity.LOW]) == 1


# ===========================================================================
# 8. _extract_flags
# ===========================================================================


class TestExtractFlags:
    def test_no_flags(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="nothing here")
        assert agg._extract_flags([result]) == []

    def test_flag_curly_brace_format(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="You got flag{test_flag_123}")
        flags = agg._extract_flags([result])
        assert "flag{test_flag_123}" in flags

    def test_FLAG_uppercase_format(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="FLAG{HELLO_WORLD}")
        flags = agg._extract_flags([result])
        assert any("FLAG{HELLO_WORLD}" in f for f in flags)

    def test_dasctf_format(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="DASCTF{some_value}")
        flags = agg._extract_flags([result])
        assert any("DASCTF{some_value}" in f for f in flags)

    def test_ctf_format(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="ctf{easy_challenge}")
        flags = agg._extract_flags([result])
        assert "ctf{easy_challenge}" in flags

    def test_md5_hash(self):
        agg = ResultAggregator()
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = _make_agent_result(output=f"hash: {md5}")
        flags = agg._extract_flags([result])
        assert md5 in flags

    def test_sha1_hash(self):
        agg = ResultAggregator()
        sha1 = "a" * 40
        result = _make_agent_result(output=f"sha1: {sha1}")
        flags = agg._extract_flags([result])
        assert sha1 in flags

    def test_sha256_hash(self):
        agg = ResultAggregator()
        sha256 = "b" * 64
        result = _make_agent_result(output=f"sha256: {sha256}")
        flags = agg._extract_flags([result])
        assert sha256 in flags

    def test_multiple_flags_in_one_result(self):
        agg = ResultAggregator()
        result = _make_agent_result(
            output="flag{first} and flag{second}"
        )
        flags = agg._extract_flags([result])
        assert "flag{first}" in flags
        assert "flag{second}" in flags

    def test_multiple_results(self):
        agg = ResultAggregator()
        r1 = _make_agent_result(output="flag{one}")
        r2 = _make_agent_result(output="flag{two}")
        flags = agg._extract_flags([r1, r2])
        assert "flag{one}" in flags
        assert "flag{two}" in flags

    def test_deduplication(self):
        agg = ResultAggregator()
        r1 = _make_agent_result(output="flag{same}")
        r2 = _make_agent_result(output="flag{same}")
        flags = agg._extract_flags([r1, r2])
        assert flags.count("flag{same}") == 1

    def test_empty_results_list(self):
        agg = ResultAggregator()
        assert agg._extract_flags([]) == []

    def test_empty_output_in_result(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="")
        assert agg._extract_flags([result]) == []

    def test_flag_case_insensitive_dasctf(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="dasctf{lower_case}")
        flags = agg._extract_flags([result])
        assert len(flags) >= 1


# ===========================================================================
# 9. _get_max_severity
# ===========================================================================


class TestGetMaxSeverity:
    def test_single_severity(self):
        agg = ResultAggregator()
        assert agg._get_max_severity([ResultSeverity.HIGH]) == ResultSeverity.HIGH

    def test_info_and_critical(self):
        agg = ResultAggregator()
        assert agg._get_max_severity(
            [ResultSeverity.INFO, ResultSeverity.CRITICAL]
        ) == ResultSeverity.CRITICAL

    def test_all_same(self):
        agg = ResultAggregator()
        assert agg._get_max_severity(
            [ResultSeverity.MEDIUM, ResultSeverity.MEDIUM]
        ) == ResultSeverity.MEDIUM

    def test_ordering_all_levels(self):
        agg = ResultAggregator()
        all_sevs = [
            ResultSeverity.LOW,
            ResultSeverity.INFO,
            ResultSeverity.MEDIUM,
            ResultSeverity.HIGH,
            ResultSeverity.CRITICAL,
        ]
        assert agg._get_max_severity(all_sevs) == ResultSeverity.CRITICAL

    def test_empty_list_returns_info(self):
        agg = ResultAggregator()
        assert agg._get_max_severity([]) == ResultSeverity.INFO

    def test_low_and_medium(self):
        agg = ResultAggregator()
        assert agg._get_max_severity(
            [ResultSeverity.LOW, ResultSeverity.MEDIUM]
        ) == ResultSeverity.MEDIUM

    def test_high_beats_medium(self):
        agg = ResultAggregator()
        assert agg._get_max_severity(
            [ResultSeverity.MEDIUM, ResultSeverity.HIGH]
        ) == ResultSeverity.HIGH


# ===========================================================================
# 10. _correlate_findings (async)
# ===========================================================================


class TestCorrelateFindings:
    def test_empty_findings(self):
        agg = ResultAggregator()
        result = _run(agg._correlate_findings([]))
        assert result == []

    def test_no_evidence_no_correlation(self):
        agg = ResultAggregator()
        f = _make_finding(evidence=[])
        result = _run(agg._correlate_findings([f]))
        assert result == []

    def test_single_finding_per_target_no_correlation(self):
        agg = ResultAggregator()
        f = _make_finding(evidence=["target: 10.0.0.1"])
        result = _run(agg._correlate_findings([f]))
        assert len(result) == 0

    def test_two_findings_same_target_creates_correlation(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", evidence=["target: 10.0.0.1"])
        f2 = _make_finding(title="B", evidence=["target: 10.0.0.1"])
        result = _run(agg._correlate_findings([f1, f2]))
        assert len(result) == 1
        assert result[0].correlation_type == "same_target"
        assert len(result[0].findings) == 2

    def test_correlation_with_http_evidence(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", evidence=["http://example.com"])
        f2 = _make_finding(title="B", evidence=["http://example.com"])
        result = _run(agg._correlate_findings([f1, f2]))
        assert len(result) == 1

    def test_correlation_with_ip_evidence(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", evidence=["192.168.1.1 port 80"])
        f2 = _make_finding(title="B", evidence=["192.168.1.1 port 80"])
        result = _run(agg._correlate_findings([f1, f2]))
        assert len(result) == 1

    def test_correlation_id_format(self):
        agg = ResultAggregator()
        f1 = _make_finding(evidence=["target: x"])
        f2 = _make_finding(evidence=["target: x"])
        result = _run(agg._correlate_findings([f1, f2]))
        assert result[0].correlation_id == "corr_0"

    def test_multiple_correlation_groups(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="A", evidence=["http://a.com"])
        f2 = _make_finding(title="B", evidence=["http://a.com"])
        f3 = _make_finding(title="C", evidence=["http://b.com"])
        f4 = _make_finding(title="D", evidence=["http://b.com"])
        result = _run(agg._correlate_findings([f1, f2, f3, f4]))
        assert len(result) == 2

    def test_correlation_severity_is_max(self):
        agg = ResultAggregator()
        f1 = _make_finding(
            title="A",
            severity=ResultSeverity.LOW,
            evidence=["target: same"],
        )
        f2 = _make_finding(
            title="B",
            severity=ResultSeverity.CRITICAL,
            evidence=["target: same"],
        )
        result = _run(agg._correlate_findings([f1, f2]))
        assert result[0].severity == ResultSeverity.CRITICAL

    def test_non_matching_evidence_no_correlation(self):
        agg = ResultAggregator()
        f1 = _make_finding(evidence=["something random"])
        f2 = _make_finding(evidence=["another random thing"])
        result = _run(agg._correlate_findings([f1, f2]))
        assert len(result) == 0


# ===========================================================================
# 11. aggregate_results (async, integration-style unit test)
# ===========================================================================


class TestAggregateResults:
    def test_empty_results(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        result = _run(agg.aggregate_results(ia, []))
        assert isinstance(result, AggregatedResult)
        assert result.success_rate == 0
        assert result.total_execution_time == 0
        assert len(result.all_findings) == 0

    def test_single_successful_result(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        ar = _make_agent_result(success=True, execution_time=10.0, output="80/tcp open http")
        result = _run(agg.aggregate_results(ia, [ar]))
        assert result.success_rate == 1.0
        assert result.total_execution_time == 10.0
        assert len(result.all_findings) >= 1

    def test_mixed_success_failure(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        r1 = _make_agent_result(success=True, execution_time=5.0)
        r2 = _make_agent_result(success=False, execution_time=3.0)
        result = _run(agg.aggregate_results(ia, [r1, r2]))
        assert result.success_rate == 0.5
        assert result.total_execution_time == 8.0

    def test_all_failed(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        r1 = _make_agent_result(success=False, execution_time=1.0)
        r2 = _make_agent_result(success=False, execution_time=2.0)
        result = _run(agg.aggregate_results(ia, [r1, r2]))
        assert result.success_rate == 0.0

    def test_flags_extracted_during_aggregation(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        ar = _make_agent_result(output="flag{found_it}")
        result = _run(agg.aggregate_results(ia, [ar]))
        assert "flag{found_it}" in result.extracted_flags

    def test_deduplication_happens(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        r1 = _make_agent_result(
            agent_id="a1",
            output="SQL injection detected",
        )
        r2 = _make_agent_result(
            agent_id="a1",
            output="SQL injection detected",
        )
        result = _run(agg.aggregate_results(ia, [r1, r2]))
        # Findings come from same agent_id, same output -> should dedup
        assert len(result.unique_findings) <= len(result.all_findings)

    def test_categorization_populated(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        ar = _make_agent_result(output="22/tcp open ssh\n80/tcp open http")
        result = _run(agg.aggregate_results(ia, [ar]))
        assert ResultType.ASSET in result.findings_by_type
        assert ResultSeverity.INFO in result.findings_by_severity

    def test_intent_analysis_preserved(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis(intent=AttackIntent.CTF_SOLVING)
        result = _run(agg.aggregate_results(ia, []))
        assert result.intent_analysis.intent == AttackIntent.CTF_SOLVING


# ===========================================================================
# 12. Report Generation - Markdown
# ===========================================================================


class TestMarkdownReport:
    def _make_aggregated(self, **kwargs):
        ia = _make_intent_analysis()
        defaults = dict(
            intent_analysis=ia,
            agent_results=[_make_agent_result()],
            all_findings=[],
            unique_findings=[],
            correlated_findings=[],
            findings_by_type={},
            findings_by_severity={},
            extracted_flags=[],
            total_execution_time=10.0,
            success_rate=0.85,
        )
        defaults.update(kwargs)
        return AggregatedResult(**defaults)

    def test_contains_header(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "markdown")
        assert "# 安全测试报告" in report

    def test_contains_execution_stats(self):
        agg = ResultAggregator()
        ar = self._make_aggregated(success_rate=0.85, total_execution_time=10.0)
        report = agg.generate_report(ar, "markdown")
        assert "10.00秒" in report
        assert "85.0%" in report

    def test_contains_flags_section(self):
        agg = ResultAggregator()
        ar = self._make_aggregated(extracted_flags=["flag{test}"])
        report = agg.generate_report(ar, "markdown")
        assert "Flag" in report
        assert "`flag{test}`" in report

    def test_no_flags_section_when_empty(self):
        agg = ResultAggregator()
        ar = self._make_aggregated(extracted_flags=[])
        report = agg.generate_report(ar, "markdown")
        assert "提取的Flag" not in report

    def test_findings_by_severity_section(self):
        agg = ResultAggregator()
        f = _make_finding(severity=ResultSeverity.CRITICAL, title="CriticalBug")
        ar = self._make_aggregated(
            findings_by_severity={ResultSeverity.CRITICAL: [f]},
            unique_findings=[f],
        )
        report = agg.generate_report(ar, "markdown")
        assert "CRITICAL" in report
        assert "CriticalBug" in report

    def test_findings_by_type_section(self):
        agg = ResultAggregator()
        f = _make_finding(finding_type=ResultType.VULNERABILITY)
        ar = self._make_aggregated(
            findings_by_type={ResultType.VULNERABILITY: [f]},
        )
        report = agg.generate_report(ar, "markdown")
        assert "vulnerability" in report

    def test_correlated_findings_section(self):
        agg = ResultAggregator()
        f1 = _make_finding(title="F1")
        cf = CorrelatedFinding(
            correlation_id="corr_0",
            title="Corr Title",
            description="desc",
            findings=[f1],
            correlation_type="same_target",
            confidence=0.8,
            severity=ResultSeverity.HIGH,
        )
        ar = self._make_aggregated(correlated_findings=[cf])
        report = agg.generate_report(ar, "markdown")
        assert "关联发现" in report
        assert "Corr Title" in report

    def test_truncates_findings_at_10(self):
        agg = ResultAggregator()
        findings = [
            _make_finding(
                severity=ResultSeverity.HIGH,
                title=f"Finding_{i}",
                description=f"desc_{i}",
            )
            for i in range(15)
        ]
        ar = self._make_aggregated(
            findings_by_severity={ResultSeverity.HIGH: findings},
        )
        report = agg.generate_report(ar, "markdown")
        assert "还有 5 个" in report

    def test_evidence_in_markdown(self):
        agg = ResultAggregator()
        f = _make_finding(
            severity=ResultSeverity.HIGH,
            evidence=["ev1", "ev2"],
        )
        ar = self._make_aggregated(
            findings_by_severity={ResultSeverity.HIGH: [f]},
        )
        report = agg.generate_report(ar, "markdown")
        assert "`ev1`" in report


# ===========================================================================
# 13. Report Generation - JSON
# ===========================================================================


class TestJsonReport:
    def _make_aggregated(self, **kwargs):
        ia = _make_intent_analysis()
        defaults = dict(
            intent_analysis=ia,
            agent_results=[],
            all_findings=[],
            unique_findings=[],
            correlated_findings=[],
            findings_by_type={},
            findings_by_severity={},
            extracted_flags=[],
            total_execution_time=5.0,
            success_rate=1.0,
        )
        defaults.update(kwargs)
        return AggregatedResult(**defaults)

    def test_valid_json(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert "metadata" in data
        assert "statistics" in data

    def test_metadata_fields(self):
        agg = ResultAggregator()
        ar = self._make_aggregated(
            total_execution_time=12.5,
            success_rate=0.75,
        )
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert data["metadata"]["total_execution_time"] == 12.5
        assert data["metadata"]["success_rate"] == 0.75

    def test_statistics_counts(self):
        agg = ResultAggregator()
        f = _make_finding()
        ar = self._make_aggregated(
            agent_results=[_make_agent_result()],
            all_findings=[f, f],
            unique_findings=[f],
            extracted_flags=["flag{x}"],
        )
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert data["statistics"]["total_agents"] == 1
        assert data["statistics"]["total_findings"] == 2
        assert data["statistics"]["unique_findings"] == 1
        assert data["statistics"]["extracted_flags"] == 1

    def test_flags_in_json(self):
        agg = ResultAggregator()
        ar = self._make_aggregated(extracted_flags=["flag{a}", "flag{b}"])
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert "flag{a}" in data["flags"]
        assert "flag{b}" in data["flags"]

    def test_findings_serialized(self):
        agg = ResultAggregator()
        f = _make_finding(
            finding_type=ResultType.VULNERABILITY,
            severity=ResultSeverity.CRITICAL,
            title="SQLi",
            confidence=0.95,
        )
        ar = self._make_aggregated(unique_findings=[f])
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["type"] == "vulnerability"
        assert data["findings"][0]["severity"] == "critical"
        assert data["findings"][0]["title"] == "SQLi"
        assert data["findings"][0]["confidence"] == 0.95

    def test_correlated_findings_in_json(self):
        agg = ResultAggregator()
        cf = CorrelatedFinding(
            correlation_id="corr_0",
            title="Multi",
            description="d",
            findings=[_make_finding(), _make_finding()],
            correlation_type="same_target",
            confidence=0.8,
            severity=ResultSeverity.HIGH,
        )
        ar = self._make_aggregated(correlated_findings=[cf])
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert len(data["correlated_findings"]) == 1
        assert data["correlated_findings"][0]["finding_count"] == 2

    def test_intent_in_json(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis(intent=AttackIntent.EXPLOITATION)
        ar = self._make_aggregated()
        ar.intent_analysis = ia
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert data["metadata"]["intent"] == "exploitation"


# ===========================================================================
# 14. Report Generation - HTML
# ===========================================================================


class TestHtmlReport:
    def _make_aggregated(self, **kwargs):
        ia = _make_intent_analysis()
        defaults = dict(
            intent_analysis=ia,
            agent_results=[],
            all_findings=[],
            unique_findings=[],
            correlated_findings=[],
            findings_by_type={},
            findings_by_severity={},
            extracted_flags=[],
            total_execution_time=0,
            success_rate=0,
        )
        defaults.update(kwargs)
        return AggregatedResult(**defaults)

    def test_contains_html_tags(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "html")
        assert "<html>" in report
        assert "</html>" in report
        assert "<body>" in report

    def test_contains_title(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "html")
        assert "安全测试报告" in report

    def test_flags_in_html(self):
        agg = ResultAggregator()
        ar = self._make_aggregated(extracted_flags=["flag{html_test}"])
        report = agg.generate_report(ar, "html")
        assert "flag{html_test}" in report
        assert "Flag" in report

    def test_no_flags_section_when_empty_html(self):
        agg = ResultAggregator()
        ar = self._make_aggregated(extracted_flags=[])
        report = agg.generate_report(ar, "html")
        assert "提取的Flag" not in report

    def test_findings_in_html(self):
        agg = ResultAggregator()
        f = _make_finding(title="HTMLFinding", severity=ResultSeverity.HIGH)
        ar = self._make_aggregated(unique_findings=[f])
        report = agg.generate_report(ar, "html")
        assert "HTMLFinding" in report
        assert "high" in report

    def test_html_truncates_at_20_findings(self):
        agg = ResultAggregator()
        findings = [
            _make_finding(title=f"F_{i}", description=f"D_{i}")
            for i in range(25)
        ]
        ar = self._make_aggregated(unique_findings=findings)
        report = agg.generate_report(ar, "html")
        assert "F_19" in report
        assert "F_20" not in report

    def test_css_classes_present(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "html")
        assert ".critical" in report
        assert ".high" in report
        assert ".medium" in report
        assert ".low" in report
        assert ".info" in report


# ===========================================================================
# 15. generate_report dispatch
# ===========================================================================


class TestGenerateReportDispatch:
    def _make_aggregated(self):
        ia = _make_intent_analysis()
        return AggregatedResult(intent_analysis=ia, agent_results=[])

    def test_default_is_markdown(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar)
        assert "# 安全测试报告" in report

    def test_explicit_markdown(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "markdown")
        assert "# 安全测试报告" in report

    def test_json_dispatch(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "json")
        data = json.loads(report)
        assert "metadata" in data

    def test_html_dispatch(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "html")
        assert "<html>" in report

    def test_unknown_format_falls_back_to_markdown(self):
        agg = ResultAggregator()
        ar = self._make_aggregated()
        report = agg.generate_report(ar, "xml")
        assert "# 安全测试报告" in report


# ===========================================================================
# 16. save_report
# ===========================================================================


class TestSaveReport:
    def test_save_creates_file(self, tmp_path):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        ar = AggregatedResult(intent_analysis=ia, agent_results=[])
        filepath = str(tmp_path / "report.md")
        agg.save_report(ar, filepath, format="markdown")
        assert os.path.exists(filepath)
        content = Path(filepath).read_text(encoding="utf-8")
        assert "安全测试报告" in content

    def test_save_creates_parent_directories(self, tmp_path):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        ar = AggregatedResult(intent_analysis=ia, agent_results=[])
        filepath = str(tmp_path / "sub" / "dir" / "report.json")
        agg.save_report(ar, filepath, format="json")
        assert os.path.exists(filepath)
        content = Path(filepath).read_text(encoding="utf-8")
        data = json.loads(content)
        assert "metadata" in data

    def test_save_html(self, tmp_path):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        ar = AggregatedResult(intent_analysis=ia, agent_results=[])
        filepath = str(tmp_path / "report.html")
        agg.save_report(ar, filepath, format="html")
        content = Path(filepath).read_text(encoding="utf-8")
        assert "<html>" in content

    def test_save_overwrites_existing(self, tmp_path):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        ar = AggregatedResult(intent_analysis=ia, agent_results=[])
        filepath = str(tmp_path / "report.md")
        Path(filepath).write_text("old content", encoding="utf-8")
        agg.save_report(ar, filepath, format="markdown")
        content = Path(filepath).read_text(encoding="utf-8")
        assert "old content" not in content
        assert "安全测试报告" in content


# ===========================================================================
# 17. __all__ exports
# ===========================================================================


class TestModuleExports:
    def test_all_exports(self):
        from kali_mcp.core import result_aggregator
        expected = [
            'ResultAggregator',
            'AgentResult',
            'Finding',
            'AggregatedResult',
            'CorrelatedFinding',
            'ResultSeverity',
            'ResultType',
        ]
        for name in expected:
            assert name in result_aggregator.__all__

    def test_all_exports_count(self):
        from kali_mcp.core import result_aggregator
        assert len(result_aggregator.__all__) == 7


# ===========================================================================
# 18. Edge Cases and Integration-style
# ===========================================================================


class TestEdgeCases:
    def test_very_long_output(self):
        agg = ResultAggregator()
        long_output = "x" * 100_000 + " flag{hidden_in_long}"
        result = _make_agent_result(output=long_output)
        flags = agg._extract_flags([result])
        assert "flag{hidden_in_long}" in flags

    def test_unicode_in_output(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="漏洞: SQL injection in 参数")
        findings = agg._auto_discover_findings(result)
        assert any("SQL injection" in f.title for f in findings)

    def test_newlines_in_output(self):
        agg = ResultAggregator()
        output = "Line1\n22/tcp open ssh\nLine3\n80/tcp open http\n"
        result = _make_agent_result(output=output)
        findings = agg._auto_discover_findings(result)
        port_titles = [f.title for f in findings if "Open port" in f.title]
        assert "Open port: 22" in port_titles
        assert "Open port: 80" in port_titles

    def test_special_regex_chars_in_output(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="output with (parens) and [brackets]")
        # Should not crash
        findings = agg._auto_discover_findings(result)
        assert isinstance(findings, list)

    def test_flag_at_boundary(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="flag{}")
        # flag{} has empty content inside braces - the regex [^}]+ requires at least 1 char
        flags = agg._extract_flags([result])
        assert "flag{}" not in flags

    def test_nested_braces_in_flag(self):
        agg = ResultAggregator()
        # flag{abc{def}} - the regex stops at first }
        result = _make_agent_result(output="flag{abc")
        flags = agg._extract_flags([result])
        # Incomplete flag should not match
        assert len([f for f in flags if f.startswith("flag{")]) == 0

    def test_aggregate_with_parsed_and_auto_discover_results(self):
        """Mix of parsed_data results and auto-discovery results."""
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        r1 = _make_agent_result(
            agent_id="a1",
            parsed_data={
                "findings": [
                    {"type": "vulnerability", "severity": "critical", "title": "Parsed"}
                ]
            }
        )
        r2 = _make_agent_result(
            agent_id="a2",
            output="80/tcp open http\nXSS vulnerability found",
        )
        result = _run(agg.aggregate_results(ia, [r1, r2]))
        titles = [f.title for f in result.all_findings]
        assert "Parsed" in titles
        assert any("XSS" in t for t in titles)
        assert any("Open port: 80" in t for t in titles)

    def test_finding_with_long_description_dedup(self):
        """Dedup uses first 100 chars of description."""
        agg = ResultAggregator()
        desc_prefix = "A" * 99
        f1 = _make_finding(title="T", description=desc_prefix + "X" + "extra1")
        f2 = _make_finding(title="T", description=desc_prefix + "Y" + "extra2")
        result = agg._deduplicate_findings([f1, f2])
        # First 100 chars differ at position 99 (X vs Y)
        assert len(result) == 2

    def test_correlation_confidence(self):
        agg = ResultAggregator()
        f1 = _make_finding(evidence=["http://target.com/path"])
        f2 = _make_finding(evidence=["http://target.com/path"])
        result = _run(agg._correlate_findings([f1, f2]))
        assert result[0].confidence == 0.8

    def test_many_agents_aggregation(self):
        agg = ResultAggregator()
        ia = _make_intent_analysis()
        results = [
            _make_agent_result(
                agent_id=f"agent_{i}",
                success=(i % 2 == 0),
                execution_time=float(i),
                output=f"{i * 100}/tcp open service_{i}" if i < 5 else "",
            )
            for i in range(10)
        ]
        aggregated = _run(agg.aggregate_results(ia, results))
        assert aggregated.success_rate == 0.5
        assert aggregated.total_execution_time == sum(range(10))


# ===========================================================================
# 19. Flag Pattern Specificity Tests
# ===========================================================================


class TestFlagPatternSpecificity:
    def test_dasctf_takes_precedence_over_ctf(self):
        """DASCTF{} should match DASCTF pattern, not be split by ctf pattern."""
        agg = ResultAggregator()
        result = _make_agent_result(output="DASCTF{hello_world}")
        flags = agg._extract_flags([result])
        assert any("DASCTF{hello_world}" in f for f in flags)

    def test_flag_uppercase_match(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="FLAG{UPPER}")
        flags = agg._extract_flags([result])
        assert any("FLAG{UPPER}" in f for f in flags)

    def test_mixed_case_flag(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="Flag{MixedCase}")
        flags = agg._extract_flags([result])
        # FLAG pattern is case insensitive, should match
        assert any("Flag{MixedCase}" in f for f in flags)

    def test_hex_string_shorter_than_32_not_matched(self):
        agg = ResultAggregator()
        result = _make_agent_result(output="abc123")
        flags = agg._extract_flags([result])
        assert "abc123" not in flags

    def test_hex_string_exactly_32_matched(self):
        agg = ResultAggregator()
        hex32 = "a" * 32
        result = _make_agent_result(output=hex32)
        flags = agg._extract_flags([result])
        assert hex32 in flags

    def test_hex_40_but_not_32_substring(self):
        agg = ResultAggregator()
        hex40 = "a" * 40
        result = _make_agent_result(output=hex40)
        flags = agg._extract_flags([result])
        # Should match SHA1 (40) pattern; also MD5 (32) may match substring
        assert hex40 in flags
