"""
Tests for ReAct Engine (kali_mcp/core/react_engine.py)

Covers:
- StepType enum: all 5 members, str subclass behavior
- ReActStep dataclass: construction, defaults, to_dict
- ReActResult dataclass: construction, defaults, to_dict with nested steps
- TaskHandoff dataclass: construction, to_dict, to_prompt_context full coverage
- ReActConfig dataclass: defaults, custom values
- ReActParser: parse() classmethod, _parse_json_input() staticmethod
- DefaultToolExecutor: execute (sync/async), get_available_tools, get_tool_description
- ReActEngine: _extract_flags, _reset_state, _build_initial_messages,
               _create_result, cancel, _default_system_prompt
- run_react convenience function
"""

import asyncio
import json
import time
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kali_mcp.core.react_engine import (
    DefaultToolExecutor,
    ReActConfig,
    ReActEngine,
    ReActParser,
    ReActResult,
    ReActStep,
    StepType,
    TaskHandoff,
    ToolExecutor,
    run_react,
)


# ================================================================
# StepType Enum
# ================================================================

class TestStepType:
    """StepType(str, Enum) with 5 members."""

    def test_thought_value(self):
        assert StepType.THOUGHT.value == "thought"

    def test_action_value(self):
        assert StepType.ACTION.value == "action"

    def test_observation_value(self):
        assert StepType.OBSERVATION.value == "observation"

    def test_final_answer_value(self):
        assert StepType.FINAL_ANSWER.value == "final_answer"

    def test_error_value(self):
        assert StepType.ERROR.value == "error"

    def test_member_count(self):
        assert len(StepType) == 5

    def test_is_str_subclass(self):
        """StepType inherits from str, so members are strings."""
        assert isinstance(StepType.THOUGHT, str)
        assert StepType.ACTION == "action"

    def test_enum_from_value(self):
        assert StepType("thought") is StepType.THOUGHT
        assert StepType("error") is StepType.ERROR

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            StepType("nonexistent")


# ================================================================
# ReActStep Dataclass
# ================================================================

class TestReActStep:
    """ReActStep dataclass with to_dict()."""

    def test_minimal_construction(self):
        step = ReActStep(step_type=StepType.THOUGHT, content="thinking")
        assert step.step_type == StepType.THOUGHT
        assert step.content == "thinking"

    def test_default_fields(self):
        step = ReActStep(step_type=StepType.THOUGHT, content="x")
        assert step.action is None
        assert step.action_input is None
        assert step.observation is None
        assert step.tool_duration_ms is None
        assert step.iteration == 0
        assert step.metadata == {}

    def test_timestamp_auto_generated(self):
        before = time.time()
        step = ReActStep(step_type=StepType.THOUGHT, content="x")
        after = time.time()
        assert before <= step.timestamp <= after

    def test_action_step_fields(self):
        step = ReActStep(
            step_type=StepType.ACTION,
            content="do scan",
            action="nmap_scan",
            action_input={"target": "10.0.0.1"},
        )
        assert step.action == "nmap_scan"
        assert step.action_input == {"target": "10.0.0.1"}

    def test_observation_step_fields(self):
        step = ReActStep(
            step_type=StepType.OBSERVATION,
            content="port 80 open",
            observation="port 80 open",
            tool_duration_ms=150,
        )
        assert step.observation == "port 80 open"
        assert step.tool_duration_ms == 150

    def test_to_dict_keys(self):
        step = ReActStep(step_type=StepType.ERROR, content="bad")
        d = step.to_dict()
        expected_keys = {
            "step_type", "content", "timestamp", "action",
            "action_input", "observation", "tool_duration_ms",
            "iteration", "metadata",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_step_type_is_value(self):
        step = ReActStep(step_type=StepType.FINAL_ANSWER, content="done")
        d = step.to_dict()
        assert d["step_type"] == "final_answer"

    def test_to_dict_preserves_metadata(self):
        step = ReActStep(
            step_type=StepType.THOUGHT,
            content="x",
            metadata={"key": "val"},
        )
        assert step.to_dict()["metadata"] == {"key": "val"}

    def test_to_dict_preserves_action_input(self):
        inp = {"url": "http://x.com", "depth": 3}
        step = ReActStep(
            step_type=StepType.ACTION, content="", action="scan", action_input=inp
        )
        assert step.to_dict()["action_input"] == inp

    def test_iteration_field(self):
        step = ReActStep(step_type=StepType.THOUGHT, content="x", iteration=5)
        assert step.iteration == 5
        assert step.to_dict()["iteration"] == 5


# ================================================================
# ReActResult Dataclass
# ================================================================

class TestReActResult:
    """ReActResult dataclass with to_dict()."""

    def test_minimal_success(self):
        result = ReActResult(success=True)
        assert result.success is True
        assert result.final_answer is None
        assert result.error is None

    def test_default_fields(self):
        result = ReActResult(success=False)
        assert result.iterations == 0
        assert result.tool_calls == 0
        assert result.total_duration_ms == 0
        assert result.steps == []
        assert result.findings == []
        assert result.flags == []
        assert result.metadata == {}

    def test_full_construction(self):
        steps = [ReActStep(step_type=StepType.THOUGHT, content="t")]
        result = ReActResult(
            success=True,
            final_answer="Found vuln",
            iterations=3,
            tool_calls=2,
            total_duration_ms=5000,
            steps=steps,
            findings=[{"type": "sqli"}],
            flags=["flag{abc}"],
            metadata={"mode": "ctf"},
        )
        assert result.final_answer == "Found vuln"
        assert result.iterations == 3
        assert len(result.steps) == 1
        assert result.flags == ["flag{abc}"]

    def test_to_dict_keys(self):
        result = ReActResult(success=True)
        d = result.to_dict()
        expected = {
            "success", "final_answer", "error", "iterations",
            "tool_calls", "total_duration_ms", "steps",
            "findings", "flags", "metadata",
        }
        assert set(d.keys()) == expected

    def test_to_dict_nested_steps(self):
        steps = [
            ReActStep(step_type=StepType.THOUGHT, content="a"),
            ReActStep(step_type=StepType.ACTION, content="b", action="scan"),
        ]
        result = ReActResult(success=True, steps=steps)
        d = result.to_dict()
        assert len(d["steps"]) == 2
        assert d["steps"][0]["step_type"] == "thought"
        assert d["steps"][1]["action"] == "scan"

    def test_to_dict_error_result(self):
        result = ReActResult(success=False, error="timeout")
        d = result.to_dict()
        assert d["success"] is False
        assert d["error"] == "timeout"


# ================================================================
# TaskHandoff Dataclass
# ================================================================

class TestTaskHandoff:
    """TaskHandoff dataclass with to_dict() and to_prompt_context()."""

    def test_minimal_construction(self):
        h = TaskHandoff(from_phase="recon", to_phase="exploit", summary="done recon")
        assert h.from_phase == "recon"
        assert h.to_phase == "exploit"
        assert h.summary == "done recon"

    def test_default_fields(self):
        h = TaskHandoff(from_phase="a", to_phase="b", summary="s")
        assert h.work_completed == []
        assert h.key_findings == []
        assert h.insights == []
        assert h.suggested_actions == []
        assert h.attention_points == []
        assert h.priority_areas == []
        assert h.target_info == {}
        assert h.confidence == 0.8

    def test_timestamp_auto(self):
        before = datetime.now()
        h = TaskHandoff(from_phase="a", to_phase="b", summary="s")
        after = datetime.now()
        assert before <= h.timestamp <= after

    def test_to_dict_keys(self):
        h = TaskHandoff(from_phase="a", to_phase="b", summary="s")
        d = h.to_dict()
        expected = {
            "from_phase", "to_phase", "summary", "work_completed",
            "key_findings", "insights", "suggested_actions",
            "attention_points", "priority_areas", "target_info",
            "confidence", "timestamp",
        }
        assert set(d.keys()) == expected

    def test_to_dict_timestamp_isoformat(self):
        h = TaskHandoff(from_phase="a", to_phase="b", summary="s")
        d = h.to_dict()
        # Should be a parseable ISO format string
        datetime.fromisoformat(d["timestamp"])

    def test_to_dict_confidence(self):
        h = TaskHandoff(from_phase="a", to_phase="b", summary="s", confidence=0.95)
        assert h.to_dict()["confidence"] == 0.95


class TestTaskHandoffPromptContext:
    """TaskHandoff.to_prompt_context() markdown generation."""

    def test_minimal_prompt_context(self):
        h = TaskHandoff(from_phase="recon", to_phase="exploit", summary="scan done")
        ctx = h.to_prompt_context()
        assert "## 来自 recon 阶段的任务交接" in ctx
        assert "### 工作摘要" in ctx
        assert "scan done" in ctx

    def test_work_completed_section(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            work_completed=["nmap scan", "gobuster scan"],
        )
        ctx = h.to_prompt_context()
        assert "### 已完成的工作" in ctx
        assert "- nmap scan" in ctx
        assert "- gobuster scan" in ctx

    def test_key_findings_section(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            key_findings=[
                {"severity": "high", "title": "SQLi found", "description": "Injection in login"},
            ],
        )
        ctx = h.to_prompt_context()
        assert "### 关键发现" in ctx
        assert "[HIGH] SQLi found" in ctx
        assert "描述: Injection in login" in ctx

    def test_key_findings_default_severity(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            key_findings=[{"title": "Something"}],
        )
        ctx = h.to_prompt_context()
        assert "[MEDIUM] Something" in ctx

    def test_key_findings_no_title(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            key_findings=[{"severity": "low"}],
        )
        ctx = h.to_prompt_context()
        assert "[LOW] Unknown" in ctx

    def test_key_findings_limited_to_15(self):
        findings = [{"title": f"Finding {i}"} for i in range(20)]
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            key_findings=findings,
        )
        ctx = h.to_prompt_context()
        assert "Finding 14" in ctx
        assert "Finding 15" not in ctx  # 0-indexed, [:15] stops at index 14

    def test_key_findings_description_truncated_to_100(self):
        long_desc = "A" * 200
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            key_findings=[{"title": "T", "description": long_desc}],
        )
        ctx = h.to_prompt_context()
        # The description line should have at most 100 chars of the description
        assert "A" * 100 in ctx
        assert "A" * 101 not in ctx

    def test_key_findings_no_description(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            key_findings=[{"title": "T"}],
        )
        ctx = h.to_prompt_context()
        assert "描述:" not in ctx

    def test_insights_section(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            insights=["Target uses WAF", "PHP backend detected"],
        )
        ctx = h.to_prompt_context()
        assert "### 洞察和分析" in ctx
        assert "- Target uses WAF" in ctx

    def test_suggested_actions_section(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            suggested_actions=[
                {"type": "sqli", "description": "test login", "priority": "high"},
            ],
        )
        ctx = h.to_prompt_context()
        assert "### 建议的下一步行动" in ctx
        assert "[HIGH] sqli: test login" in ctx

    def test_suggested_actions_defaults(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            suggested_actions=[{}],
        )
        ctx = h.to_prompt_context()
        assert "[MEDIUM] general:" in ctx

    def test_attention_points_section(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            attention_points=["WAF active on /admin"],
        )
        ctx = h.to_prompt_context()
        assert "### ⚠️ 需要特别关注" in ctx
        assert "- WAF active on /admin" in ctx

    def test_target_info_section(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            target_info={"ip": "10.0.0.1", "os": "Linux"},
        )
        ctx = h.to_prompt_context()
        assert "### 目标信息" in ctx
        assert "- ip: 10.0.0.1" in ctx
        assert "- os: Linux" in ctx

    def test_empty_sections_omitted(self):
        h = TaskHandoff(from_phase="a", to_phase="b", summary="s")
        ctx = h.to_prompt_context()
        assert "### 已完成的工作" not in ctx
        assert "### 关键发现" not in ctx
        assert "### 洞察和分析" not in ctx
        assert "### 建议的下一步行动" not in ctx
        assert "### ⚠️ 需要特别关注" not in ctx
        assert "### 目标信息" not in ctx

    def test_all_sections_present(self):
        h = TaskHandoff(
            from_phase="recon", to_phase="exploit", summary="done",
            work_completed=["scan"],
            key_findings=[{"title": "F1"}],
            insights=["I1"],
            suggested_actions=[{"type": "t1", "description": "d1", "priority": "low"}],
            attention_points=["Watch out"],
            target_info={"host": "x"},
        )
        ctx = h.to_prompt_context()
        assert "### 工作摘要" in ctx
        assert "### 已完成的工作" in ctx
        assert "### 关键发现" in ctx
        assert "### 洞察和分析" in ctx
        assert "### 建议的下一步行动" in ctx
        assert "### ⚠️ 需要特别关注" in ctx
        assert "### 目标信息" in ctx

    def test_numbered_key_findings(self):
        findings = [{"title": f"F{i}"} for i in range(3)]
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            key_findings=findings,
        )
        ctx = h.to_prompt_context()
        assert "1. [MEDIUM] F0" in ctx
        assert "2. [MEDIUM] F1" in ctx
        assert "3. [MEDIUM] F2" in ctx


# ================================================================
# ReActConfig Dataclass
# ================================================================

class TestReActConfig:
    """ReActConfig default and custom values."""

    def test_defaults(self):
        cfg = ReActConfig()
        assert cfg.max_iterations == 20
        assert cfg.timeout_seconds == 600
        assert cfg.temperature == 0.1
        assert cfg.mode == "security"
        assert cfg.on_thought is None
        assert cfg.on_action is None
        assert cfg.on_observation is None
        assert cfg.enable_circuit_breaker is True
        assert cfg.failure_threshold == 3

    def test_custom_values(self):
        cb = lambda s, i: None
        cfg = ReActConfig(
            max_iterations=5,
            timeout_seconds=30,
            temperature=0.7,
            mode="ctf",
            on_thought=cb,
            enable_circuit_breaker=False,
            failure_threshold=10,
        )
        assert cfg.max_iterations == 5
        assert cfg.mode == "ctf"
        assert cfg.on_thought is cb
        assert cfg.enable_circuit_breaker is False


# ================================================================
# ReActParser._parse_json_input
# ================================================================

class TestParseJsonInput:
    """ReActParser._parse_json_input() 4-stage parsing."""

    def test_valid_json(self):
        result = ReActParser._parse_json_input('{"target": "10.0.0.1"}')
        assert result == {"target": "10.0.0.1"}

    def test_json_with_whitespace(self):
        result = ReActParser._parse_json_input('  {"a": 1}  ')
        assert result == {"a": 1}

    def test_markdown_code_block_json(self):
        text = '```json\n{"key": "val"}\n```'
        result = ReActParser._parse_json_input(text)
        assert result == {"key": "val"}

    def test_markdown_code_block_no_lang(self):
        text = '```\n{"key": "val"}\n```'
        result = ReActParser._parse_json_input(text)
        assert result == {"key": "val"}

    def test_single_quote_fix(self):
        result = ReActParser._parse_json_input("{'target': '10.0.0.1'}")
        assert result == {"target": "10.0.0.1"}

    def test_extract_json_object_from_text(self):
        text = 'some preamble {"url": "http://x.com"} trailing stuff'
        result = ReActParser._parse_json_input(text)
        assert result == {"url": "http://x.com"}

    def test_completely_unparseable_returns_empty_dict(self):
        result = ReActParser._parse_json_input("not json at all")
        assert result == {}

    def test_empty_string_returns_empty_dict(self):
        result = ReActParser._parse_json_input("")
        assert result == {}

    def test_nested_json_parsed(self):
        text = '{"target": "x", "options": {"deep": true}}'
        result = ReActParser._parse_json_input(text)
        assert result == {"target": "x", "options": {"deep": True}}

    def test_markdown_block_with_extra_whitespace(self):
        text = '```python\n  {"a": "b"}  \n```'
        result = ReActParser._parse_json_input(text)
        assert result == {"a": "b"}

    def test_json_with_numbers(self):
        result = ReActParser._parse_json_input('{"port": 8080, "timeout": 30.5}')
        assert result == {"port": 8080, "timeout": 30.5}

    def test_json_with_null(self):
        result = ReActParser._parse_json_input('{"key": null}')
        assert result == {"key": None}

    def test_json_array_top_level(self):
        """Top-level arrays are valid JSON but not dicts. Stage 1 returns list."""
        result = ReActParser._parse_json_input('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_regex_extract_skips_nested_braces(self):
        """Regex r'\\{[^{}]*\\}' only matches non-nested objects."""
        text = 'prefix {"a": "b"} suffix'
        result = ReActParser._parse_json_input(text)
        assert result == {"a": "b"}

    def test_invalid_json_with_embedded_object(self):
        text = 'Error happened: {"error": "timeout"} end'
        result = ReActParser._parse_json_input(text)
        assert result == {"error": "timeout"}


# ================================================================
# ReActParser.parse
# ================================================================

class TestReActParserParse:
    """ReActParser.parse() classmethod."""

    def test_parse_final_answer(self):
        text = "Thought: all done\nFinal Answer: The flag is flag{abc123}"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.FINAL_ANSWER
        assert "flag{abc123}" in step.content

    def test_parse_final_answer_priority_over_action(self):
        """Final Answer is checked first, even if Action is also present."""
        text = "Thought: x\nAction: nmap\nFinal Answer: done"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.FINAL_ANSWER

    def test_parse_action_with_input(self):
        text = 'Thought: need to scan\nAction: nmap_scan\nAction Input: {"target": "10.0.0.1"}'
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action == "nmap_scan"
        assert step.action_input == {"target": "10.0.0.1"}
        assert "need to scan" in step.content

    def test_parse_action_without_input(self):
        text = "Thought: let's scan\nAction: gobuster_scan"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action == "gobuster_scan"
        assert step.action_input == {}

    def test_parse_thought_only(self):
        text = "Thought: I need to think more about this"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.THOUGHT
        assert "think more" in step.content

    def test_parse_error_on_empty(self):
        step = ReActParser.parse("")
        assert step.step_type == StepType.ERROR

    def test_parse_error_on_gibberish(self):
        step = ReActParser.parse("random text without any markers")
        assert step.step_type == StepType.ERROR
        assert "无法解析" in step.content

    def test_parse_error_stores_raw_response(self):
        step = ReActParser.parse("gibberish")
        assert step.metadata.get("raw_response") == "gibberish"

    def test_parse_markdown_bold_thought(self):
        text = "**Thought:** analyzing target\n**Action:** nmap_scan"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action == "nmap_scan"

    def test_parse_markdown_bold_final_answer(self):
        text = "**Final Answer:** vulnerability confirmed"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.FINAL_ANSWER
        assert "vulnerability confirmed" in step.content

    def test_parse_markdown_bold_action_input(self):
        text = '**Thought:** scan\n**Action:** sqlmap_scan\n**Action Input:** {"url": "http://x"}'
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action_input == {"url": "http://x"}

    def test_parse_action_with_text_before_thought(self):
        """When no Thought: label, text before Action: is used as thought."""
        text = "I should check the ports.\nAction: nmap_scan"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action == "nmap_scan"
        assert "check the ports" in step.content

    def test_parse_case_insensitive_thought(self):
        text = "thought: lower case works\naction: test_tool"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION

    def test_parse_multiline_thought(self):
        text = "Thought: first line\nsecond line\nthird line\nAction: scan"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert "first line" in step.content

    def test_parse_final_answer_multiline(self):
        text = "Final Answer: line1\nline2\nline3"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.FINAL_ANSWER
        assert "line1" in step.content
        assert "line3" in step.content

    def test_parse_markdown_observation_cleaned(self):
        text = "**Observation:** result data\n**Thought:** analyzing\n**Action:** next_tool"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action == "next_tool"

    def test_parse_action_input_with_code_block(self):
        text = 'Thought: test\nAction: tool\nAction Input: ```json\n{"a": 1}\n```'
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action_input == {"a": 1}

    def test_parse_long_response_truncated_in_error(self):
        long_text = "x" * 500
        step = ReActParser.parse(long_text)
        assert step.step_type == StepType.ERROR
        # Error content should include truncated version
        assert len(step.content) < len(long_text) + 100


# ================================================================
# DefaultToolExecutor
# ================================================================

class TestDefaultToolExecutor:
    """DefaultToolExecutor wrapping a tools dict."""

    def test_get_available_tools(self):
        tools = {"nmap": lambda: None, "gobuster": lambda: None}
        executor = DefaultToolExecutor(tools)
        assert set(executor.get_available_tools()) == {"nmap", "gobuster"}

    def test_get_available_tools_empty(self):
        executor = DefaultToolExecutor({})
        assert executor.get_available_tools() == []

    def test_get_tool_description_with_docstring(self):
        def my_tool():
            """Scan the target"""
            pass
        executor = DefaultToolExecutor({"my_tool": my_tool})
        assert executor.get_tool_description("my_tool") == "Scan the target"

    def test_get_tool_description_no_docstring(self):
        def my_tool():
            pass
        my_tool.__doc__ = None
        executor = DefaultToolExecutor({"my_tool": my_tool})
        assert executor.get_tool_description("my_tool") == "工具: my_tool"

    def test_get_tool_description_missing_tool(self):
        executor = DefaultToolExecutor({})
        assert executor.get_tool_description("missing") == "工具: missing"

    @pytest.mark.asyncio
    async def test_execute_missing_tool(self):
        executor = DefaultToolExecutor({"a": lambda: None})
        result = await executor.execute("nonexistent", {})
        assert "不存在" in result
        assert "nonexistent" in result

    @pytest.mark.asyncio
    async def test_execute_sync_tool_returns_dict(self):
        def my_tool(target=""):
            return {"status": "ok", "target": target}
        executor = DefaultToolExecutor({"my_tool": my_tool})
        result = await executor.execute("my_tool", {"target": "10.0.0.1"})
        parsed = json.loads(result)
        assert parsed["status"] == "ok"
        assert parsed["target"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_execute_sync_tool_returns_string(self):
        def my_tool():
            return "scan complete"
        executor = DefaultToolExecutor({"my_tool": my_tool})
        result = await executor.execute("my_tool", {})
        assert result == "scan complete"

    @pytest.mark.asyncio
    async def test_execute_async_tool(self):
        async def my_async_tool(target=""):
            return {"async": True, "target": target}
        executor = DefaultToolExecutor({"my_async_tool": my_async_tool})
        result = await executor.execute("my_async_tool", {"target": "x"})
        parsed = json.loads(result)
        assert parsed["async"] is True

    @pytest.mark.asyncio
    async def test_execute_tool_raises_exception(self):
        def bad_tool():
            raise ValueError("tool broke")
        executor = DefaultToolExecutor({"bad": bad_tool})
        result = await executor.execute("bad", {})
        assert "工具执行错误" in result
        assert "tool broke" in result

    @pytest.mark.asyncio
    async def test_execute_tool_returns_non_dict_non_str(self):
        def my_tool():
            return 42
        executor = DefaultToolExecutor({"my_tool": my_tool})
        result = await executor.execute("my_tool", {})
        assert result == "42"

    @pytest.mark.asyncio
    async def test_execute_lists_available_tools_on_missing(self):
        executor = DefaultToolExecutor({"tool_a": lambda: None, "tool_b": lambda: None})
        result = await executor.execute("tool_c", {})
        assert "tool_a" in result
        assert "tool_b" in result


# ================================================================
# ReActEngine._extract_flags
# ================================================================

class TestExtractFlags:
    """ReActEngine._extract_flags() - 7 flag patterns."""

    def _make_engine(self):
        executor = DefaultToolExecutor({})
        llm = MagicMock()
        engine = ReActEngine(executor, llm)
        engine._reset_state()
        return engine

    def test_flag_lowercase(self):
        engine = self._make_engine()
        engine._extract_flags("Found flag{test_flag_123}")
        assert "flag{test_flag_123}" in engine._flags

    def test_flag_uppercase(self):
        engine = self._make_engine()
        engine._extract_flags("Result: FLAG{UPPER_CASE}")
        assert "FLAG{UPPER_CASE}" in engine._flags

    def test_ctf_lowercase(self):
        engine = self._make_engine()
        engine._extract_flags("ctf{my_ctf_flag}")
        assert "ctf{my_ctf_flag}" in engine._flags

    def test_ctf_uppercase(self):
        engine = self._make_engine()
        engine._extract_flags("CTF{UPPERCASE_CTF}")
        assert "CTF{UPPERCASE_CTF}" in engine._flags

    def test_dasctf(self):
        engine = self._make_engine()
        engine._extract_flags("DASCTF{dasctf_flag}")
        assert "DASCTF{dasctf_flag}" in engine._flags

    def test_hctf(self):
        engine = self._make_engine()
        engine._extract_flags("HCTF{hctf_value}")
        assert "HCTF{hctf_value}" in engine._flags

    def test_nctf(self):
        engine = self._make_engine()
        engine._extract_flags("NCTF{nctf_value}")
        assert "NCTF{nctf_value}" in engine._flags

    def test_no_flag_in_text(self):
        engine = self._make_engine()
        engine._extract_flags("nothing here")
        assert engine._flags == []

    def test_multiple_flags_in_one_text(self):
        engine = self._make_engine()
        engine._extract_flags("flag{a} and FLAG{b} and ctf{c}")
        assert len(engine._flags) == 3

    def test_duplicate_flag_not_added(self):
        engine = self._make_engine()
        engine._extract_flags("flag{dup}")
        engine._extract_flags("flag{dup}")
        assert engine._flags.count("flag{dup}") == 1

    def test_flag_with_special_chars(self):
        engine = self._make_engine()
        engine._extract_flags("flag{h3ll0_w0rld_!@#$%}")
        assert len(engine._flags) == 1

    def test_flag_case_insensitive_matching(self):
        """Patterns use re.IGNORECASE, so 'Flag{x}' matches 'flag' pattern."""
        engine = self._make_engine()
        engine._extract_flags("Flag{MiXeD_CaSe}")
        assert len(engine._flags) == 1

    def test_empty_text(self):
        engine = self._make_engine()
        engine._extract_flags("")
        assert engine._flags == []

    def test_flag_embedded_in_json(self):
        engine = self._make_engine()
        engine._extract_flags('{"result": "flag{in_json}"}')
        assert "flag{in_json}" in engine._flags


# ================================================================
# ReActEngine._reset_state
# ================================================================

class TestResetState:
    """ReActEngine._reset_state() clears all state."""

    def test_reset_clears_all(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        engine._cancelled = True
        engine._steps = [ReActStep(step_type=StepType.THOUGHT, content="x")]
        engine._findings = [{"a": 1}]
        engine._flags = ["flag{x}"]
        engine._consecutive_failures = 5

        engine._reset_state()

        assert engine._cancelled is False
        assert engine._steps == []
        assert engine._findings == []
        assert engine._flags == []
        assert engine._consecutive_failures == 0


# ================================================================
# ReActEngine._build_initial_messages
# ================================================================

class TestBuildInitialMessages:
    """ReActEngine._build_initial_messages()."""

    def _make_engine(self, system_prompt="sys prompt"):
        executor = DefaultToolExecutor({})
        return ReActEngine(executor, MagicMock(), system_prompt=system_prompt)

    def test_task_only(self):
        engine = self._make_engine()
        msgs = engine._build_initial_messages("scan target", None, None)
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == "sys prompt"
        assert msgs[1]["role"] == "user"
        assert "scan target" in msgs[1]["content"]

    def test_with_context(self):
        engine = self._make_engine()
        msgs = engine._build_initial_messages("task", "extra context", None)
        assert len(msgs) == 3
        assert msgs[1]["role"] == "user"
        assert "extra context" in msgs[1]["content"]
        assert "## 背景信息" in msgs[1]["content"]

    def test_with_handoff(self):
        engine = self._make_engine()
        handoff = TaskHandoff(from_phase="recon", to_phase="exploit", summary="done")
        msgs = engine._build_initial_messages("task", None, handoff)
        assert len(msgs) == 3
        assert msgs[1]["role"] == "user"
        assert "来自 recon 阶段" in msgs[1]["content"]

    def test_with_handoff_and_context(self):
        engine = self._make_engine()
        handoff = TaskHandoff(from_phase="a", to_phase="b", summary="s")
        msgs = engine._build_initial_messages("task", "ctx", handoff)
        assert len(msgs) == 4
        # Order: system, handoff, context, task
        assert msgs[0]["role"] == "system"
        assert "来自 a 阶段" in msgs[1]["content"]
        assert "## 背景信息" in msgs[2]["content"]
        assert "## 任务" in msgs[3]["content"]

    def test_task_message_includes_instruction(self):
        engine = self._make_engine()
        msgs = engine._build_initial_messages("my task", None, None)
        assert "请开始分析" in msgs[-1]["content"]


# ================================================================
# ReActEngine._create_result
# ================================================================

class TestCreateResult:
    """ReActEngine._create_result()."""

    def _make_engine(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        engine._reset_state()
        return engine

    def test_success_result(self):
        engine = self._make_engine()
        start = time.time()
        result = engine._create_result(True, start, final_answer="done")
        assert result.success is True
        assert result.final_answer == "done"
        assert result.error is None
        assert result.total_duration_ms >= 0

    def test_error_result(self):
        engine = self._make_engine()
        result = engine._create_result(False, time.time(), error="failed")
        assert result.success is False
        assert result.error == "failed"

    def test_counts_tool_calls(self):
        engine = self._make_engine()
        engine._steps = [
            ReActStep(step_type=StepType.ACTION, content="", action="a"),
            ReActStep(step_type=StepType.OBSERVATION, content="obs"),
            ReActStep(step_type=StepType.ACTION, content="", action="b"),
            ReActStep(step_type=StepType.THOUGHT, content="think"),
        ]
        result = engine._create_result(True, time.time())
        assert result.tool_calls == 2

    def test_counts_iterations(self):
        engine = self._make_engine()
        engine._steps = [
            ReActStep(step_type=StepType.THOUGHT, content="t"),
            ReActStep(step_type=StepType.ACTION, content="a", action="x"),
            ReActStep(step_type=StepType.OBSERVATION, content="o"),
        ]
        result = engine._create_result(True, time.time())
        # iterations = THOUGHT + ACTION count
        assert result.iterations == 2

    def test_copies_flags(self):
        engine = self._make_engine()
        engine._flags = ["flag{a}", "CTF{b}"]
        result = engine._create_result(True, time.time())
        assert result.flags == ["flag{a}", "CTF{b}"]
        # Verify it's a copy
        engine._flags.append("flag{c}")
        assert "flag{c}" not in result.flags

    def test_copies_findings(self):
        engine = self._make_engine()
        engine._findings = [{"vuln": "sqli"}]
        result = engine._create_result(True, time.time())
        assert result.findings == [{"vuln": "sqli"}]
        engine._findings.append({"vuln": "xss"})
        assert len(result.findings) == 1

    def test_copies_steps(self):
        engine = self._make_engine()
        step = ReActStep(step_type=StepType.THOUGHT, content="t")
        engine._steps = [step]
        result = engine._create_result(True, time.time())
        assert len(result.steps) == 1
        engine._steps.append(ReActStep(step_type=StepType.ERROR, content="e"))
        assert len(result.steps) == 1

    def test_duration_positive(self):
        engine = self._make_engine()
        start = time.time() - 1.0  # 1 second ago
        result = engine._create_result(True, start)
        assert result.total_duration_ms >= 900  # at least ~1000ms


# ================================================================
# ReActEngine.cancel
# ================================================================

class TestCancel:
    """ReActEngine.cancel() sets the cancelled flag."""

    def test_cancel_sets_flag(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        assert engine._cancelled is False
        engine.cancel()
        assert engine._cancelled is True

    def test_cancel_idempotent(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        engine.cancel()
        engine.cancel()
        assert engine._cancelled is True


# ================================================================
# ReActEngine._default_system_prompt
# ================================================================

class TestDefaultSystemPrompt:
    """ReActEngine._default_system_prompt() generates a prompt with tool info."""

    def test_contains_tool_list(self):
        def scan_tool():
            """Scan a target"""
            pass
        executor = DefaultToolExecutor({"scan_tool": scan_tool})
        engine = ReActEngine(executor, MagicMock())
        prompt = engine._default_system_prompt()
        assert "scan_tool" in prompt
        assert "Scan a target" in prompt

    def test_contains_format_instructions(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        prompt = engine._default_system_prompt()
        assert "Thought:" in prompt
        assert "Action:" in prompt
        assert "Action Input:" in prompt
        assert "Final Answer:" in prompt

    def test_limits_tools_to_20(self):
        tools = {f"tool_{i}": lambda: None for i in range(30)}
        executor = DefaultToolExecutor(tools)
        engine = ReActEngine(executor, MagicMock())
        prompt = engine._default_system_prompt()
        # Should contain at most 20 tool lines
        tool_lines = [l for l in prompt.split("\n") if l.startswith("- tool_")]
        assert len(tool_lines) <= 20

    def test_custom_system_prompt_overrides_default(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock(), system_prompt="CUSTOM")
        assert engine.system_prompt == "CUSTOM"


# ================================================================
# ReActEngine constructor
# ================================================================

class TestReActEngineInit:
    """ReActEngine constructor."""

    def test_default_config(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        assert engine.config.max_iterations == 20

    def test_custom_config(self):
        cfg = ReActConfig(max_iterations=5)
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock(), config=cfg)
        assert engine.config.max_iterations == 5

    def test_initial_state(self):
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        assert engine._cancelled is False
        assert engine._steps == []
        assert engine._flags == []
        assert engine._findings == []
        assert engine._consecutive_failures == 0


# ================================================================
# ReActEngine.run (async) - basic behavior via mocking
# ================================================================

class TestReActEngineRun:
    """ReActEngine.run() async method - test via mocked LLM."""

    @pytest.mark.asyncio
    async def test_run_final_answer_immediately(self):
        """LLM returns Final Answer on first call."""
        executor = DefaultToolExecutor({})
        llm = AsyncMock(return_value="Final Answer: All done, no vulns found.")
        engine = ReActEngine(executor, llm, config=ReActConfig(max_iterations=5))

        result = await engine.run("test task")
        assert result.success is True
        assert "All done" in result.final_answer

    @pytest.mark.asyncio
    async def test_run_with_action_then_answer(self):
        """LLM does one action then final answer."""
        def scan_tool(target=""):
            return {"ports": [80, 443]}

        executor = DefaultToolExecutor({"scan_tool": scan_tool})
        responses = [
            'Thought: need scan\nAction: scan_tool\nAction Input: {"target": "x"}',
            "Final Answer: Found ports 80 and 443",
        ]
        llm = AsyncMock(side_effect=responses)
        engine = ReActEngine(executor, llm, config=ReActConfig(max_iterations=5))

        result = await engine.run("scan x")
        assert result.success is True
        assert result.tool_calls == 1
        assert "ports" in result.final_answer.lower() or "80" in result.final_answer

    @pytest.mark.asyncio
    async def test_run_max_iterations_reached(self):
        """LLM never gives Final Answer."""
        executor = DefaultToolExecutor({})
        llm = AsyncMock(return_value="Thought: still thinking...")
        engine = ReActEngine(executor, llm, config=ReActConfig(max_iterations=2))

        result = await engine.run("infinite task")
        assert result.success is False
        assert "最大迭代次数" in result.error

    @pytest.mark.asyncio
    async def test_run_cancelled(self):
        """Engine cancelled during execution returns failure."""
        executor = DefaultToolExecutor({})

        async def llm_that_cancels(messages):
            # Cancel the engine when LLM is called, simulating mid-run cancel
            engine.cancel()
            return "Thought: thinking..."

        engine = ReActEngine(executor, llm_that_cancels, config=ReActConfig(max_iterations=5))

        result = await engine.run("task")
        assert result.success is False
        assert "取消" in result.error

    @pytest.mark.asyncio
    async def test_run_circuit_breaker(self):
        """Circuit breaker triggers after consecutive failures."""
        executor = DefaultToolExecutor({})
        # Return empty string to trigger failure path
        llm = AsyncMock(return_value="")
        engine = ReActEngine(
            executor, llm,
            config=ReActConfig(max_iterations=10, failure_threshold=3)
        )

        result = await engine.run("task")
        assert result.success is False
        assert "连续失败" in result.error

    @pytest.mark.asyncio
    async def test_run_extracts_flag_from_final_answer(self):
        executor = DefaultToolExecutor({})
        llm = AsyncMock(return_value="Final Answer: The flag is flag{got_it_123}")
        engine = ReActEngine(executor, llm)

        result = await engine.run("find flag")
        assert result.success is True
        assert "flag{got_it_123}" in result.flags

    @pytest.mark.asyncio
    async def test_run_extracts_flag_from_observation(self):
        def leak_tool():
            return "secret: flag{from_tool}"

        executor = DefaultToolExecutor({"leak": leak_tool})
        responses = [
            "Thought: try leak\nAction: leak\nAction Input: {}",
            "Final Answer: found the flag",
        ]
        llm = AsyncMock(side_effect=responses)
        engine = ReActEngine(executor, llm, config=ReActConfig(max_iterations=5))

        result = await engine.run("find flag")
        assert "flag{from_tool}" in result.flags

    @pytest.mark.asyncio
    async def test_run_handles_parse_error(self):
        """Unparseable response increments consecutive failures."""
        executor = DefaultToolExecutor({})
        responses = [
            "totally random gibberish",
            "Final Answer: recovered",
        ]
        llm = AsyncMock(side_effect=responses)
        engine = ReActEngine(executor, llm, config=ReActConfig(max_iterations=5))

        result = await engine.run("task")
        assert result.success is True

    @pytest.mark.asyncio
    async def test_run_with_sync_llm(self):
        """run() works with a synchronous llm_caller."""
        executor = DefaultToolExecutor({})

        def sync_llm(messages):
            return "Final Answer: sync result"

        engine = ReActEngine(executor, sync_llm)
        result = await engine.run("task")
        assert result.success is True
        assert "sync result" in result.final_answer

    @pytest.mark.asyncio
    async def test_run_with_handoff(self):
        executor = DefaultToolExecutor({})
        llm = AsyncMock(return_value="Final Answer: continued from recon")
        engine = ReActEngine(executor, llm)
        handoff = TaskHandoff(from_phase="recon", to_phase="exploit", summary="ports found")

        result = await engine.run("exploit", handoff=handoff)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_run_with_context(self):
        executor = DefaultToolExecutor({})
        llm = AsyncMock(return_value="Final Answer: used context")
        engine = ReActEngine(executor, llm)

        result = await engine.run("task", context="additional info")
        assert result.success is True


# ================================================================
# run_react convenience function
# ================================================================

class TestRunReact:
    """run_react() global convenience function."""

    @pytest.mark.asyncio
    async def test_basic_run_react(self):
        tools = {"my_tool": lambda: "result"}
        llm = AsyncMock(return_value="Final Answer: complete")

        result = await run_react("test", tools, llm)
        assert result.success is True
        assert "complete" in result.final_answer

    @pytest.mark.asyncio
    async def test_run_react_with_context(self):
        tools = {}
        llm = AsyncMock(return_value="Final Answer: done")

        result = await run_react("test", tools, llm, context="extra info")
        assert result.success is True

    @pytest.mark.asyncio
    async def test_run_react_custom_max_iterations(self):
        tools = {}
        llm = AsyncMock(return_value="Thought: still going")

        result = await run_react("test", tools, llm, max_iterations=2)
        assert result.success is False
        assert "最大迭代次数" in result.error

    @pytest.mark.asyncio
    async def test_run_react_creates_default_executor(self):
        """Verify it wires up tools through DefaultToolExecutor."""
        def my_tool(target=""):
            return {"found": True}

        responses = [
            'Thought: scan\nAction: my_tool\nAction Input: {"target": "x"}',
            "Final Answer: done",
        ]
        llm = AsyncMock(side_effect=responses)
        result = await run_react("scan x", {"my_tool": my_tool}, llm, max_iterations=5)
        assert result.success is True
        assert result.tool_calls == 1


# ================================================================
# ToolExecutor ABC
# ================================================================

class TestToolExecutorABC:
    """ToolExecutor is abstract and cannot be instantiated directly."""

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            ToolExecutor()


# ================================================================
# Edge cases and integration-style sync tests
# ================================================================

class TestEdgeCases:
    """Miscellaneous edge cases."""

    def test_react_step_to_dict_none_fields(self):
        step = ReActStep(step_type=StepType.THOUGHT, content="t")
        d = step.to_dict()
        assert d["action"] is None
        assert d["action_input"] is None
        assert d["observation"] is None
        assert d["tool_duration_ms"] is None

    def test_react_result_to_dict_empty_steps(self):
        result = ReActResult(success=True)
        d = result.to_dict()
        assert d["steps"] == []

    def test_task_handoff_to_dict_preserves_all_lists(self):
        h = TaskHandoff(
            from_phase="a", to_phase="b", summary="s",
            work_completed=["w1"],
            key_findings=[{"title": "f1"}],
            insights=["i1"],
            suggested_actions=[{"type": "a1"}],
            attention_points=["ap1"],
            priority_areas=["pa1"],
        )
        d = h.to_dict()
        assert d["work_completed"] == ["w1"]
        assert d["key_findings"] == [{"title": "f1"}]
        assert d["insights"] == ["i1"]
        assert d["suggested_actions"] == [{"type": "a1"}]
        assert d["attention_points"] == ["ap1"]
        assert d["priority_areas"] == ["pa1"]

    def test_parse_json_input_with_boolean_values(self):
        result = ReActParser._parse_json_input('{"verbose": true, "dry_run": false}')
        assert result == {"verbose": True, "dry_run": False}

    def test_parse_json_input_with_unicode(self):
        result = ReActParser._parse_json_input('{"name": "测试目标"}')
        assert result == {"name": "测试目标"}

    def test_multiple_flag_patterns_in_same_text(self):
        engine = ReActEngine(DefaultToolExecutor({}), MagicMock())
        engine._reset_state()
        text = "flag{a} FLAG{b} ctf{c} CTF{d} DASCTF{e} HCTF{f} NCTF{g}"
        engine._extract_flags(text)
        # re.IGNORECASE causes ctf{} pattern to also match CTF-prefixed flags,
        # so DASCTF{e}->CTF{e}, HCTF{f}->CTF{f}, NCTF{g}->CTF{g} also match.
        # Total unique flags: 10 (7 explicit + 3 extra from case-insensitive overlap)
        assert len(engine._flags) == 10
        # All 7 original flag strings should be present
        for expected in ["flag{a}", "FLAG{b}", "ctf{c}", "CTF{d}",
                         "DASCTF{e}", "HCTF{f}", "NCTF{g}"]:
            assert expected in engine._flags

    def test_parser_handles_only_action_no_thought(self):
        text = "Action: quick_scan\nAction Input: {}"
        step = ReActParser.parse(text)
        assert step.step_type == StepType.ACTION
        assert step.action == "quick_scan"

    def test_react_config_callbacks_are_callable(self):
        thought_cb = MagicMock()
        action_cb = MagicMock()
        obs_cb = MagicMock()
        cfg = ReActConfig(
            on_thought=thought_cb,
            on_action=action_cb,
            on_observation=obs_cb,
        )
        assert callable(cfg.on_thought)
        assert callable(cfg.on_action)
        assert callable(cfg.on_observation)

    @pytest.mark.asyncio
    async def test_execute_action_no_action_name(self):
        """_execute_action with step.action=None returns error string."""
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock())
        step = ReActStep(step_type=StepType.ACTION, content="x", action=None)
        result = await engine._execute_action(step)
        assert "没有指定工具名称" in result

    @pytest.mark.asyncio
    async def test_execute_action_truncates_long_output(self):
        """Output > 4000 chars gets truncated."""
        def verbose_tool():
            return "A" * 5000

        executor = DefaultToolExecutor({"verbose": verbose_tool})
        engine = ReActEngine(executor, MagicMock())
        step = ReActStep(
            step_type=StepType.ACTION, content="", action="verbose", action_input={}
        )
        result = await engine._execute_action(step)
        assert len(result) < 5000
        assert "输出已截断" in result

    @pytest.mark.asyncio
    async def test_execute_action_records_duration(self):
        def slow_tool():
            return "ok"

        executor = DefaultToolExecutor({"slow": slow_tool})
        engine = ReActEngine(executor, MagicMock())
        step = ReActStep(
            step_type=StepType.ACTION, content="", action="slow", action_input={}
        )
        await engine._execute_action(step)
        assert step.tool_duration_ms is not None
        assert step.tool_duration_ms >= 0

    @pytest.mark.asyncio
    async def test_execute_action_handles_timeout(self):
        """TimeoutError from tool_executor.execute is caught by _execute_action.

        DefaultToolExecutor catches generic Exception internally, so to test
        the _execute_action timeout path we use a mock executor whose execute()
        raises asyncio.TimeoutError directly.
        """
        mock_executor = MagicMock(spec=ToolExecutor)
        mock_executor.execute = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_executor.get_available_tools.return_value = []
        mock_executor.get_tool_description.return_value = ""

        engine = ReActEngine(mock_executor, MagicMock())
        step = ReActStep(
            step_type=StepType.ACTION, content="", action="timeout_tool", action_input={}
        )
        result = await engine._execute_action(step)
        assert "超时" in result

    @pytest.mark.asyncio
    async def test_execute_action_handles_generic_exception(self):
        async def crash_tool():
            raise RuntimeError("crash")

        executor = DefaultToolExecutor({"crash": crash_tool})
        engine = ReActEngine(executor, MagicMock())
        step = ReActStep(
            step_type=StepType.ACTION, content="", action="crash", action_input={}
        )
        result = await engine._execute_action(step)
        assert "执行错误" in result

    @pytest.mark.asyncio
    async def test_trigger_callbacks_thought(self):
        cb = MagicMock()
        cfg = ReActConfig(on_thought=cb)
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock(), config=cfg)

        step = ReActStep(step_type=StepType.THOUGHT, content="thinking", iteration=1)
        await engine._trigger_callbacks(step)
        cb.assert_called_once_with("thinking", 1)

    @pytest.mark.asyncio
    async def test_trigger_callbacks_action(self):
        cb = MagicMock()
        cfg = ReActConfig(on_action=cb)
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock(), config=cfg)

        step = ReActStep(
            step_type=StepType.ACTION, content="", action="tool", action_input={"a": 1}, iteration=2
        )
        await engine._trigger_callbacks(step)
        cb.assert_called_once_with("tool", {"a": 1}, 2)

    @pytest.mark.asyncio
    async def test_trigger_callbacks_observation(self):
        cb = MagicMock()
        cfg = ReActConfig(on_observation=cb)
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock(), config=cfg)

        step = ReActStep(
            step_type=StepType.OBSERVATION, content="obs", observation="obs data", iteration=3
        )
        await engine._trigger_callbacks(step)
        cb.assert_called_once_with("obs data", 3)

    @pytest.mark.asyncio
    async def test_trigger_callbacks_handles_exception(self):
        """Callback exceptions are swallowed (logged)."""
        def bad_cb(*args):
            raise ValueError("cb broke")

        cfg = ReActConfig(on_thought=bad_cb)
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock(), config=cfg)

        step = ReActStep(step_type=StepType.THOUGHT, content="t", iteration=1)
        # Should not raise
        await engine._trigger_callbacks(step)

    @pytest.mark.asyncio
    async def test_trigger_callbacks_async(self):
        cb = AsyncMock()
        cfg = ReActConfig(on_thought=cb)
        executor = DefaultToolExecutor({})
        engine = ReActEngine(executor, MagicMock(), config=cfg)

        step = ReActStep(step_type=StepType.THOUGHT, content="async t", iteration=1)
        await engine._trigger_callbacks(step)
        cb.assert_called_once_with("async t", 1)

    def test_task_handoff_prompt_context_returns_string(self):
        h = TaskHandoff(from_phase="a", to_phase="b", summary="s")
        ctx = h.to_prompt_context()
        assert isinstance(ctx, str)

    def test_react_result_flags_default_empty(self):
        r = ReActResult(success=True)
        assert r.flags == []
        r.flags.append("flag{x}")
        # Verify default factory gives a new list each time
        r2 = ReActResult(success=True)
        assert r2.flags == []
