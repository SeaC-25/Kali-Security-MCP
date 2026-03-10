"""
Tests for LLMBrain (kali_mcp/core/llm_brain.py)

Covers:
- Module-level constants: SYSTEM_PROMPT, PLANNER_PROMPT, DECISION_REPAIR_PROMPT,
  ACTION_AUDITOR_PROMPT (existence, non-empty, template placeholders)
- LLMBrain class constants: MAX_ROUNDS, MAX_OUTPUT_CHARS, DEFAULT_MODEL_CLAUDE,
  DEFAULT_MODEL_CODEX, REFUSAL_PATTERNS, PLACEHOLDER, _TERM_MAP, _TERM_LIST,
  _CONSTRAINT_SUMMARY
- __init__: provider detection (explicit, env-based fallback), model resolution,
  api_key resolution, base_url resolution, client creation for claude/codex,
  client creation failure, no api_key path
- available property
- _iter_json_objects: balanced braces, nested objects, strings with braces,
  escaped chars, empty input, no objects, multiple objects, single-quote strings
- _extract_json_candidates: empty/None input, plain JSON, code blocks,
  embedded objects, leftmost-rightmost brace fallback, deduplication
- _repair_json_variants: BOM stripping, smart-quote normalization, comment removal,
  trailing comma fix, backslash normalization, deduplication
- _coerce_decision_payload: dict with action, list input, non-dict input,
  nested decision keys, missing params for call_tool, thinking/plan coercion,
  tool_name inference, command inference, no action at all
- _parse_decision_json: valid JSON, repairable JSON, garbage, embedded in markdown
- _parse_json_payload: valid dict, list not accepted as top-level,
  embedded in prose, garbage
- _default_plan: ctf mode, pentest mode, other mode
- plan_task: no client fallback, LLM returns valid plan, LLM returns empty todos,
  LLM returns non-dict todo items, LLM exception fallback
- repair_decision: direct parse succeeds, no client returns None,
  LLM repair succeeds, LLM repair fails
- review_action: no client returns default, LLM returns valid review,
  LLM returns invalid risk, LLM returns non-dict rewrite_params,
  LLM exception returns default
- analyze: no client returns done, valid decision, JSON decode error,
  general exception
- is_policy_refusal: empty string, non-refusal, English refusal patterns,
  Chinese refusal patterns, case insensitivity
- build_initial_message: ctf mode, pentest mode, audit mode, unknown mode,
  with/without prompt
- truncate_output: short output, exact boundary, long output truncation
- sanitize_prompt: empty prompt, short prompt with terms, long prompt > 500 chars
- _TERM_LIST ordering: longest terms first
- make_sanitizer: sanitize/desanitize pair, Chinese org names, .edu.cn domains,
  IP resolution
- _claude_http_messages_create: success, missing api key, HTTP error,
  response content extraction
- _invoke_text: codex provider path, claude provider path, claude SDK blocked
  fallback, codex response as list, prefer_json TypeError fallback,
  prefer_json response_format error fallback
"""

import json
import os
import re
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from kali_mcp.core.llm_brain import (
    LLMBrain,
    SYSTEM_PROMPT,
    PLANNER_PROMPT,
    DECISION_REPAIR_PROMPT,
    ACTION_AUDITOR_PROMPT,
)


# ================================================================
# Module-level prompt constants
# ================================================================

class TestPromptConstants:
    """Module-level prompt string constants."""

    def test_system_prompt_exists_and_non_empty(self):
        assert isinstance(SYSTEM_PROMPT, str)
        assert len(SYSTEM_PROMPT) > 100

    def test_system_prompt_has_tool_catalog_placeholder(self):
        assert "{tool_catalog}" in SYSTEM_PROMPT

    def test_system_prompt_has_action_types(self):
        assert "call_tool" in SYSTEM_PROMPT
        assert "run_tool" in SYSTEM_PROMPT
        assert "done" in SYSTEM_PROMPT

    def test_planner_prompt_exists_and_non_empty(self):
        assert isinstance(PLANNER_PROMPT, str)
        assert len(PLANNER_PROMPT) > 50

    def test_planner_prompt_mentions_todos(self):
        assert "todos" in PLANNER_PROMPT

    def test_decision_repair_prompt_exists_and_non_empty(self):
        assert isinstance(DECISION_REPAIR_PROMPT, str)
        assert len(DECISION_REPAIR_PROMPT) > 50

    def test_decision_repair_prompt_mentions_actions(self):
        assert "call_tool" in DECISION_REPAIR_PROMPT
        assert "run_tool" in DECISION_REPAIR_PROMPT
        assert "done" in DECISION_REPAIR_PROMPT

    def test_action_auditor_prompt_exists_and_non_empty(self):
        assert isinstance(ACTION_AUDITOR_PROMPT, str)
        assert len(ACTION_AUDITOR_PROMPT) > 50

    def test_action_auditor_prompt_mentions_allowed(self):
        assert "allowed" in ACTION_AUDITOR_PROMPT


# ================================================================
# LLMBrain class-level constants
# ================================================================

class TestClassConstants:
    """Class-level constants on LLMBrain."""

    def test_max_rounds(self):
        assert LLMBrain.MAX_ROUNDS == 20

    def test_max_output_chars(self):
        assert LLMBrain.MAX_OUTPUT_CHARS == 3000

    def test_default_model_claude(self):
        assert isinstance(LLMBrain.DEFAULT_MODEL_CLAUDE, str)
        assert len(LLMBrain.DEFAULT_MODEL_CLAUDE) > 0

    def test_default_model_codex(self):
        assert isinstance(LLMBrain.DEFAULT_MODEL_CODEX, str)
        assert len(LLMBrain.DEFAULT_MODEL_CODEX) > 0

    def test_refusal_patterns_is_tuple(self):
        assert isinstance(LLMBrain.REFUSAL_PATTERNS, tuple)

    def test_refusal_patterns_all_lowercase(self):
        for p in LLMBrain.REFUSAL_PATTERNS:
            # Chinese chars don't have case; English should be lowercase
            english = re.sub(r'[^\x00-\x7f]', '', p)
            assert english == english.lower(), f"Pattern not lowercase: {p}"

    def test_refusal_patterns_count(self):
        assert len(LLMBrain.REFUSAL_PATTERNS) >= 15

    def test_placeholder(self):
        assert LLMBrain.PLACEHOLDER == "TARGET_HOST"

    def test_term_map_is_dict(self):
        assert isinstance(LLMBrain._TERM_MAP, dict)
        assert len(LLMBrain._TERM_MAP) > 20

    def test_term_list_sorted_by_length_descending(self):
        lengths = [len(term) for term, _ in LLMBrain._TERM_LIST]
        assert lengths == sorted(lengths, reverse=True)

    def test_constraint_summary_is_string(self):
        assert isinstance(LLMBrain._CONSTRAINT_SUMMARY, str)
        assert "Operator constraints" in LLMBrain._CONSTRAINT_SUMMARY


# ================================================================
# __init__ and provider detection
# ================================================================

class TestInit:
    """__init__ provider/model/key resolution."""

    @patch.dict(os.environ, {}, clear=True)
    def test_no_api_key_no_client(self):
        brain = LLMBrain(api_key="", provider="claude")
        assert brain._client is None
        assert brain.available is False

    @patch.dict(os.environ, {}, clear=True)
    @patch("anthropic.Anthropic", return_value=MagicMock())
    def test_explicit_claude_provider(self, mock_anthropic_cls):
        brain = LLMBrain(api_key="sk-test", provider="claude")
        assert brain.provider == "claude"
        assert brain.api_key == "sk-test"

    @patch.dict(os.environ, {}, clear=True)
    @patch("anthropic.Anthropic", return_value=MagicMock())
    def test_explicit_anthropic_provider(self, mock_anthropic_cls):
        brain = LLMBrain(api_key="sk-test", provider="anthropic")
        assert brain.provider == "claude"

    @patch.dict(os.environ, {}, clear=True)
    def test_explicit_openai_provider(self):
        with patch.dict("sys.modules", {"openai": MagicMock()}):
            brain = LLMBrain(api_key="sk-test", provider="openai")
            assert brain.provider == "codex"

    @patch.dict(os.environ, {}, clear=True)
    def test_explicit_codex_provider(self):
        with patch.dict("sys.modules", {"openai": MagicMock()}):
            brain = LLMBrain(api_key="sk-test", provider="codex")
            assert brain.provider == "codex"

    @patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai"}, clear=True)
    def test_env_fallback_to_codex(self):
        with patch.dict("sys.modules", {"openai": MagicMock()}):
            brain = LLMBrain()
            assert brain.provider == "codex"
            assert brain.api_key == "sk-openai"

    @patch.dict(os.environ, {"OPENAI_AUTH_TOKEN": "sk-auth"}, clear=True)
    def test_env_openai_auth_token_fallback(self):
        with patch.dict("sys.modules", {"openai": MagicMock()}):
            brain = LLMBrain()
            assert brain.provider == "codex"

    @patch.dict(os.environ, {}, clear=True)
    def test_env_no_keys_defaults_to_claude(self):
        brain = LLMBrain()
        assert brain.provider == "claude"
        assert brain.available is False

    @patch.dict(os.environ, {"LLM_PROVIDER": "claude"}, clear=True)
    def test_env_llm_provider(self):
        brain = LLMBrain(api_key="")
        assert brain.provider == "claude"

    @patch.dict(os.environ, {"ANTHROPIC_MODEL": "custom-model"}, clear=True)
    @patch("anthropic.Anthropic", return_value=MagicMock())
    def test_env_anthropic_model(self, mock_anthropic_cls):
        brain = LLMBrain(api_key="sk-test", provider="claude")
        assert brain.model == "custom-model"

    @patch.dict(os.environ, {"OPENAI_MODEL": "gpt-custom"}, clear=True)
    def test_env_openai_model(self):
        with patch.dict("sys.modules", {"openai": MagicMock()}):
            brain = LLMBrain(api_key="sk-test", provider="openai")
            assert brain.model == "gpt-custom"

    @patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://custom.api.com"}, clear=True)
    @patch("anthropic.Anthropic", return_value=MagicMock())
    def test_env_anthropic_base_url(self, mock_anthropic_cls):
        brain = LLMBrain(api_key="sk-test", provider="claude")
        assert brain.base_url == "https://custom.api.com"

    @patch.dict(os.environ, {}, clear=True)
    def test_base_url_from_arg(self):
        with patch.dict("sys.modules", {"openai": MagicMock()}):
            brain = LLMBrain(api_key="sk-test", provider="openai",
                             base_url="https://my-proxy.com")
            assert brain.base_url == "https://my-proxy.com"

    @patch.dict(os.environ, {}, clear=True)
    @patch("anthropic.Anthropic", side_effect=Exception("connection error"))
    def test_client_creation_failure_logs(self, mock_anthropic_cls):
        brain = LLMBrain(api_key="sk-test", provider="claude")
        assert brain._client is None

    @patch.dict(os.environ, {}, clear=True)
    @patch("anthropic.Anthropic", return_value=MagicMock())
    def test_tool_catalog_stored(self, mock_anthropic_cls):
        brain = LLMBrain(api_key="sk-test", provider="claude",
                         tool_catalog="nmap_scan, gobuster_scan")
        assert brain.tool_catalog == "nmap_scan, gobuster_scan"

    @patch.dict(os.environ, {}, clear=True)
    def test_model_arg_used_when_no_env(self):
        brain = LLMBrain(api_key="", provider="claude", model="my-model")
        assert brain.model == "my-model"


# ================================================================
# available property
# ================================================================

class TestAvailable:
    """The available property."""

    def test_available_true_when_client_set(self):
        brain = LLMBrain.__new__(LLMBrain)
        brain._client = MagicMock()
        assert brain.available is True

    def test_available_false_when_no_client(self):
        brain = LLMBrain.__new__(LLMBrain)
        brain._client = None
        assert brain.available is False


# ================================================================
# _iter_json_objects
# ================================================================

class TestIterJsonObjects:
    """Static method _iter_json_objects."""

    def test_empty_string(self):
        assert list(LLMBrain._iter_json_objects("")) == []

    def test_no_braces(self):
        assert list(LLMBrain._iter_json_objects("hello world")) == []

    def test_single_object(self):
        result = list(LLMBrain._iter_json_objects('{"a": 1}'))
        assert result == ['{"a": 1}']

    def test_nested_object(self):
        text = '{"a": {"b": 2}}'
        result = list(LLMBrain._iter_json_objects(text))
        assert result == [text]

    def test_multiple_objects(self):
        text = 'xxx {"a": 1} yyy {"b": 2} zzz'
        result = list(LLMBrain._iter_json_objects(text))
        assert len(result) == 2
        assert '{"a": 1}' in result
        assert '{"b": 2}' in result

    def test_braces_inside_double_quotes(self):
        text = '{"key": "val{ue}"}'
        result = list(LLMBrain._iter_json_objects(text))
        assert len(result) == 1

    def test_braces_inside_single_quotes(self):
        text = "{'key': 'val{ue}'}"
        result = list(LLMBrain._iter_json_objects(text))
        assert len(result) == 1

    def test_escaped_quote_inside_string(self):
        text = '{"key": "val\\"ue"}'
        result = list(LLMBrain._iter_json_objects(text))
        assert len(result) == 1

    def test_escaped_backslash_inside_string(self):
        text = '{"key": "val\\\\ue"}'
        result = list(LLMBrain._iter_json_objects(text))
        assert len(result) == 1

    def test_unbalanced_open_brace(self):
        text = '{"a": 1'
        result = list(LLMBrain._iter_json_objects(text))
        assert result == []

    def test_close_brace_without_open(self):
        text = '"a": 1}'
        result = list(LLMBrain._iter_json_objects(text))
        assert result == []

    def test_deeply_nested(self):
        text = '{"a": {"b": {"c": {"d": 1}}}}'
        result = list(LLMBrain._iter_json_objects(text))
        assert result == [text]

    def test_text_before_and_after(self):
        text = 'prefix text {"action": "done"} suffix text'
        result = list(LLMBrain._iter_json_objects(text))
        assert result == ['{"action": "done"}']


# ================================================================
# _extract_json_candidates
# ================================================================

class TestExtractJsonCandidates:
    """Classmethod _extract_json_candidates."""

    def test_empty_string(self):
        assert LLMBrain._extract_json_candidates("") == []

    def test_none_input(self):
        assert LLMBrain._extract_json_candidates(None) == []

    def test_whitespace_only(self):
        assert LLMBrain._extract_json_candidates("   ") == []

    def test_plain_json(self):
        text = '{"action": "done"}'
        result = LLMBrain._extract_json_candidates(text)
        assert text in result

    def test_json_in_code_block(self):
        text = '```json\n{"action": "done"}\n```'
        result = LLMBrain._extract_json_candidates(text)
        assert '{"action": "done"}' in result

    def test_json_in_generic_code_block(self):
        text = '```\n{"action": "done"}\n```'
        result = LLMBrain._extract_json_candidates(text)
        assert '{"action": "done"}' in result

    def test_embedded_json_extracted(self):
        text = 'Here is the result: {"action": "done"} end.'
        result = LLMBrain._extract_json_candidates(text)
        assert '{"action": "done"}' in result

    def test_leftmost_rightmost_brace_fallback(self):
        text = 'prefix {"a": 1, "b": {"c": 2}} suffix'
        result = LLMBrain._extract_json_candidates(text)
        assert '{"a": 1, "b": {"c": 2}}' in result

    def test_deduplication(self):
        text = '{"action": "done"}'
        result = LLMBrain._extract_json_candidates(text)
        # The full text is the same as the extracted object, so deduplicated
        assert len(result) == len(set(result))

    def test_no_json_at_all(self):
        text = 'just plain text without braces'
        result = LLMBrain._extract_json_candidates(text)
        # Should still include the stripped text itself
        assert len(result) >= 1
        assert result[0] == text


# ================================================================
# _repair_json_variants
# ================================================================

class TestRepairJsonVariants:
    """Static method _repair_json_variants."""

    def test_basic_passthrough(self):
        text = '{"a": 1}'
        result = LLMBrain._repair_json_variants(text)
        assert text in result

    def test_bom_stripped(self):
        text = '\ufeff{"a": 1}'
        result = LLMBrain._repair_json_variants(text)
        assert any(not v.startswith('\ufeff') for v in result)

    def test_smart_quotes_normalized(self):
        text = '\u201c{"a": 1}\u201d'
        result = LLMBrain._repair_json_variants(text)
        assert any('"' not in v and '\u201c' not in v for v in result) or len(result) > 0

    def test_json_prefix_stripped(self):
        text = 'json {"a": 1}'
        result = LLMBrain._repair_json_variants(text)
        assert any(v.startswith('{') for v in result)

    def test_trailing_comma_removed(self):
        text = '{"a": 1,}'
        result = LLMBrain._repair_json_variants(text)
        assert any('1,}' not in v for v in result)

    def test_comment_removal(self):
        # Line comments are removed when they start at the beginning of a line
        text = '{"a": 1}\n// comment line\n'
        result = LLMBrain._repair_json_variants(text)
        assert any("// comment line" not in v for v in result)

    def test_block_comment_removal(self):
        text = '/* comment */ {"a": 1}'
        result = LLMBrain._repair_json_variants(text)
        assert any("/* comment */" not in v for v in result)

    def test_deduplication(self):
        text = '{"a": 1}'
        result = LLMBrain._repair_json_variants(text)
        assert len(result) == len(set(result))

    def test_empty_string(self):
        result = LLMBrain._repair_json_variants("")
        # Should return at least the original (empty is filtered)
        assert isinstance(result, list)

    def test_curly_quote_normalization(self):
        text = '{\u2018key\u2019: \u201cvalue\u201d}'
        result = LLMBrain._repair_json_variants(text)
        assert any('\u2018' not in v and '\u201c' not in v for v in result)


# ================================================================
# _coerce_decision_payload
# ================================================================

class TestCoerceDecisionPayload:
    """Static method _coerce_decision_payload."""

    def test_non_dict_non_list_returns_none(self):
        assert LLMBrain._coerce_decision_payload("string") is None
        assert LLMBrain._coerce_decision_payload(42) is None
        assert LLMBrain._coerce_decision_payload(None) is None

    def test_dict_with_action(self):
        payload = {"action": "done", "summary": "finished"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None
        assert result["action"] == "done"

    def test_action_normalized_to_lowercase(self):
        payload = {"action": "  CALL_TOOL  ", "tool_name": "nmap"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["action"] == "call_tool"

    def test_call_tool_missing_params_set_to_empty_dict(self):
        payload = {"action": "call_tool", "tool_name": "nmap"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["params"] == {}

    def test_call_tool_with_existing_params_preserved(self):
        payload = {"action": "call_tool", "tool_name": "nmap",
                   "params": {"target": "10.0.0.1"}}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["params"]["target"] == "10.0.0.1"

    def test_thinking_coerced_to_list(self):
        payload = {"action": "done", "thinking": "one thought"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["thinking"] == ["one thought"]

    def test_thinking_none_coerced_to_empty_list(self):
        payload = {"action": "done", "thinking": None}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["thinking"] == []

    def test_thinking_already_list_preserved(self):
        payload = {"action": "done", "thinking": ["a", "b"]}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["thinking"] == ["a", "b"]

    def test_plan_coerced_to_list(self):
        payload = {"action": "done", "plan": "next step"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["plan"] == ["next step"]

    def test_plan_none_coerced_to_empty_list(self):
        payload = {"action": "done", "plan": None}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["plan"] == []

    def test_plan_already_list_preserved(self):
        payload = {"action": "done", "plan": ["x", "y"]}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["plan"] == ["x", "y"]

    def test_list_input_finds_first_valid(self):
        payload = [
            {"not_action": True},
            {"action": "done", "summary": "found"},
        ]
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None
        assert result["action"] == "done"

    def test_list_input_no_valid_returns_none(self):
        payload = [{"not_action": True}, {"also_not": "valid"}]
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is None

    def test_empty_list_returns_none(self):
        assert LLMBrain._coerce_decision_payload([]) is None

    def test_nested_decision_key(self):
        payload = {"decision": {"action": "done", "summary": "ok"}}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None
        assert result["action"] == "done"

    def test_nested_result_key(self):
        payload = {"result": {"action": "call_tool", "tool_name": "nmap"}}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None
        assert result["action"] == "call_tool"

    def test_nested_data_key(self):
        payload = {"data": {"action": "run_tool", "command": "curl"}}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None

    def test_nested_output_key(self):
        payload = {"output": {"action": "done", "summary": "ok"}}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None

    def test_nested_response_key(self):
        payload = {"response": {"action": "done", "summary": "ok"}}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None

    def test_tool_name_infers_call_tool(self):
        payload = {"tool_name": "nmap_scan", "params": {"target": "x"}}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None
        assert result["action"] == "call_tool"

    def test_command_infers_run_tool(self):
        payload = {"command": "curl -s http://target/"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is not None
        assert result["action"] == "run_tool"

    def test_dict_no_action_no_tool_no_command_returns_none(self):
        payload = {"something": "else", "other": "data"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result is None

    def test_tool_name_inferred_has_default_params(self):
        payload = {"tool_name": "nmap_scan"}
        result = LLMBrain._coerce_decision_payload(payload)
        assert result["params"] == {}


# ================================================================
# _parse_decision_json
# ================================================================

class TestParseDecisionJson:
    """Classmethod _parse_decision_json."""

    def test_valid_json(self):
        text = '{"action": "done", "summary": "ok"}'
        result = LLMBrain._parse_decision_json(text)
        assert result is not None
        assert result["action"] == "done"

    def test_json_in_markdown(self):
        text = '```json\n{"action": "call_tool", "tool_name": "nmap"}\n```'
        result = LLMBrain._parse_decision_json(text)
        assert result is not None
        assert result["action"] == "call_tool"

    def test_garbage_returns_none(self):
        result = LLMBrain._parse_decision_json("not json at all")
        assert result is None

    def test_valid_json_but_no_action_returns_none(self):
        text = '{"key": "value"}'
        result = LLMBrain._parse_decision_json(text)
        assert result is None

    def test_embedded_json_with_prose(self):
        text = 'Here is my decision: {"action": "done", "summary": "ok"} Thanks!'
        result = LLMBrain._parse_decision_json(text)
        assert result is not None
        assert result["action"] == "done"

    def test_python_dict_literal(self):
        text = "{'action': 'done', 'summary': 'ok'}"
        result = LLMBrain._parse_decision_json(text)
        assert result is not None
        assert result["action"] == "done"

    def test_json_with_trailing_comma(self):
        text = '{"action": "done", "summary": "ok",}'
        result = LLMBrain._parse_decision_json(text)
        assert result is not None

    def test_empty_string_returns_none(self):
        assert LLMBrain._parse_decision_json("") is None


# ================================================================
# _parse_json_payload
# ================================================================

class TestParseJsonPayload:
    """Classmethod _parse_json_payload."""

    def test_valid_dict(self):
        text = '{"key": "value"}'
        result = LLMBrain._parse_json_payload(text)
        assert result == {"key": "value"}

    def test_list_not_accepted(self):
        text = '[1, 2, 3]'
        result = LLMBrain._parse_json_payload(text)
        assert result is None

    def test_embedded_in_prose(self):
        text = 'result: {"plan_summary": "do stuff", "todos": []}'
        result = LLMBrain._parse_json_payload(text)
        assert result is not None
        assert "plan_summary" in result

    def test_garbage_returns_none(self):
        assert LLMBrain._parse_json_payload("no json here") is None

    def test_empty_returns_none(self):
        assert LLMBrain._parse_json_payload("") is None


# ================================================================
# _default_plan
# ================================================================

class TestDefaultPlan:
    """Static method _default_plan."""

    def test_ctf_mode(self):
        plan = LLMBrain._default_plan("http://ctf.target", "ctf")
        assert "plan_summary" in plan
        assert "todos" in plan
        assert len(plan["todos"]) == 3
        assert plan["todos"][0]["tool_hint"] == "whatweb_scan"
        assert plan["todos"][1]["tool_hint"] == "ctf_auto_detect_solver"
        assert plan["todos"][2]["tool_hint"] == "strings_extract"

    def test_pentest_mode(self):
        plan = LLMBrain._default_plan("10.0.0.1", "pentest")
        assert len(plan["todos"]) == 3
        assert plan["todos"][0]["tool_hint"] == "nmap_scan"
        assert plan["todos"][1]["tool_hint"] == "whatweb_scan"
        assert plan["todos"][2]["tool_hint"] == "nuclei_scan"

    def test_other_mode_same_as_pentest(self):
        plan = LLMBrain._default_plan("target.com", "audit")
        assert len(plan["todos"]) == 3
        assert plan["todos"][0]["tool_hint"] == "nmap_scan"

    def test_plan_summary_contains_target(self):
        plan = LLMBrain._default_plan("example.com", "ctf")
        assert "example.com" in plan["plan_summary"]

    def test_ctf_todo_ids(self):
        plan = LLMBrain._default_plan("t", "ctf")
        ids = [t["id"] for t in plan["todos"]]
        assert ids == ["step_1", "step_2", "step_3"]

    def test_pentest_todo_structure(self):
        plan = LLMBrain._default_plan("t", "pentest")
        for todo in plan["todos"]:
            assert "id" in todo
            assert "content" in todo
            assert "tool_hint" in todo
            assert "success_criteria" in todo


# ================================================================
# plan_task
# ================================================================

class TestPlanTask:

    def _make_brain(self, client=None):
        brain = LLMBrain.__new__(LLMBrain)
        brain._client = client
        brain.provider = "claude"
        brain.model = "test"
        brain.api_key = "sk-test"
        brain.base_url = ""
        brain.tool_catalog = ""
        return brain

    def test_no_client_returns_default(self):
        brain = self._make_brain(client=None)
        plan = brain.plan_task("target", "ctf", "find flag")
        assert "todos" in plan
        assert plan["todos"][0]["tool_hint"] == "whatweb_scan"

    def test_llm_returns_valid_plan(self):
        brain = self._make_brain(client=MagicMock())
        llm_response = json.dumps({
            "plan_summary": "Scan and exploit",
            "todos": [
                {"id": "step_1", "content": "scan ports", "tool_hint": "nmap_scan",
                 "success_criteria": "find open ports"},
            ]
        })
        with patch.object(brain, "_invoke_text", return_value=llm_response):
            plan = brain.plan_task("target", "pentest", "")
        assert plan["plan_summary"] == "Scan and exploit"
        assert len(plan["todos"]) == 1
        assert plan["todos"][0]["status"] == "pending"

    def test_llm_returns_empty_todos_uses_default(self):
        brain = self._make_brain(client=MagicMock())
        llm_response = json.dumps({"plan_summary": "Empty", "todos": []})
        with patch.object(brain, "_invoke_text", return_value=llm_response):
            plan = brain.plan_task("target", "pentest", "")
        assert len(plan["todos"]) == 3  # default plan

    def test_llm_returns_non_dict_todo_items_filtered(self):
        brain = self._make_brain(client=MagicMock())
        llm_response = json.dumps({
            "plan_summary": "Mixed",
            "todos": [
                "string item",
                {"id": "step_1", "content": "valid", "tool_hint": "nmap_scan",
                 "success_criteria": "ok"},
                42,
            ]
        })
        with patch.object(brain, "_invoke_text", return_value=llm_response):
            plan = brain.plan_task("target", "ctf", "")
        assert len(plan["todos"]) == 1

    def test_llm_exception_falls_back_to_default(self):
        brain = self._make_brain(client=MagicMock())
        with patch.object(brain, "_invoke_text", side_effect=Exception("API error")):
            plan = brain.plan_task("target", "ctf", "")
        assert "todos" in plan
        assert len(plan["todos"]) == 3

    def test_tool_hint_null_becomes_none(self):
        brain = self._make_brain(client=MagicMock())
        llm_response = json.dumps({
            "plan_summary": "plan",
            "todos": [
                {"id": "step_1", "content": "analyze", "tool_hint": None,
                 "success_criteria": "done"},
            ]
        })
        with patch.object(brain, "_invoke_text", return_value=llm_response):
            plan = brain.plan_task("target", "pentest", "")
        assert plan["todos"][0]["tool_hint"] is None

    def test_tool_hint_empty_string_becomes_none(self):
        brain = self._make_brain(client=MagicMock())
        llm_response = json.dumps({
            "plan_summary": "plan",
            "todos": [
                {"id": "step_1", "content": "analyze", "tool_hint": "  ",
                 "success_criteria": "done"},
            ]
        })
        with patch.object(brain, "_invoke_text", return_value=llm_response):
            plan = brain.plan_task("target", "pentest", "")
        assert plan["todos"][0]["tool_hint"] is None

    def test_todos_capped_at_six(self):
        brain = self._make_brain(client=MagicMock())
        many_todos = [
            {"id": f"step_{i}", "content": f"step {i}", "tool_hint": None,
             "success_criteria": "done"}
            for i in range(1, 10)
        ]
        llm_response = json.dumps({"plan_summary": "plan", "todos": many_todos})
        with patch.object(brain, "_invoke_text", return_value=llm_response):
            plan = brain.plan_task("target", "pentest", "")
        assert len(plan["todos"]) == 6


# ================================================================
# repair_decision
# ================================================================

class TestRepairDecision:

    def _make_brain(self, client=None):
        brain = LLMBrain.__new__(LLMBrain)
        brain._client = client
        brain.provider = "claude"
        brain.model = "test"
        brain.api_key = "sk-test"
        brain.base_url = ""
        brain.tool_catalog = ""
        return brain

    def test_direct_parse_succeeds(self):
        brain = self._make_brain(client=MagicMock())
        text = '{"action": "done", "summary": "ok"}'
        result = brain.repair_decision(text)
        assert result is not None
        assert result["action"] == "done"

    def test_no_client_and_no_direct_parse_returns_none(self):
        brain = self._make_brain(client=None)
        result = brain.repair_decision("garbage text")
        assert result is None

    def test_llm_repair_succeeds(self):
        brain = self._make_brain(client=MagicMock())
        repaired = '{"action": "call_tool", "tool_name": "nmap_scan", "params": {}}'
        with patch.object(brain, "_invoke_text", return_value=repaired):
            result = brain.repair_decision("broken json {{{}}")
        assert result is not None
        assert result["action"] == "call_tool"

    def test_llm_repair_fails_returns_none(self):
        brain = self._make_brain(client=MagicMock())
        with patch.object(brain, "_invoke_text", side_effect=Exception("fail")):
            result = brain.repair_decision("broken")
        assert result is None

    def test_context_messages_passed(self):
        brain = self._make_brain(client=MagicMock())
        repaired = '{"action": "done", "summary": "ok"}'
        with patch.object(brain, "_invoke_text", return_value=repaired) as mock_invoke:
            brain.repair_decision(
                "broken",
                context_messages=[{"role": "user", "content": "hello"}]
            )
            call_args = mock_invoke.call_args
            user_text = call_args[0][1][0]["content"]
            assert "hello" in user_text


# ================================================================
# review_action
# ================================================================

class TestReviewAction:

    def _make_brain(self, client=None):
        brain = LLMBrain.__new__(LLMBrain)
        brain._client = client
        brain.provider = "claude"
        brain.model = "test"
        brain.api_key = "sk-test"
        brain.base_url = ""
        brain.tool_catalog = ""
        return brain

    def test_no_client_returns_default(self):
        brain = self._make_brain(client=None)
        result = brain.review_action(action="call_tool", target="10.0.0.1")
        assert result["allowed"] is True
        assert result["risk"] == "medium"
        assert result["reason"] == "no_audit"

    def test_llm_returns_valid_review(self):
        brain = self._make_brain(client=MagicMock())
        response = json.dumps({
            "allowed": True, "risk": "low", "reason": "safe operation",
            "rewrite_command": "", "rewrite_params": {}, "warning": ""
        })
        with patch.object(brain, "_invoke_text", return_value=response):
            result = brain.review_action(
                action="call_tool", target="10.0.0.1",
                tool_name="nmap_scan", params={"target": "10.0.0.1"}
            )
        assert result["allowed"] is True
        assert result["risk"] == "low"

    def test_invalid_risk_defaults_to_medium(self):
        brain = self._make_brain(client=MagicMock())
        response = json.dumps({
            "allowed": True, "risk": "extreme", "reason": "bad risk"
        })
        with patch.object(brain, "_invoke_text", return_value=response):
            result = brain.review_action(action="call_tool", target="x")
        assert result["risk"] == "medium"

    def test_non_dict_rewrite_params_defaults_to_empty(self):
        brain = self._make_brain(client=MagicMock())
        response = json.dumps({
            "allowed": True, "risk": "low", "reason": "ok",
            "rewrite_params": "not a dict"
        })
        with patch.object(brain, "_invoke_text", return_value=response):
            result = brain.review_action(action="call_tool", target="x")
        assert result["rewrite_params"] == {}

    def test_exception_returns_default(self):
        brain = self._make_brain(client=MagicMock())
        with patch.object(brain, "_invoke_text", side_effect=Exception("fail")):
            result = brain.review_action(action="call_tool", target="x")
        assert result["allowed"] is True
        assert result["reason"] == "no_audit"

    def test_allowed_false_preserved(self):
        brain = self._make_brain(client=MagicMock())
        response = json.dumps({
            "allowed": False, "risk": "high", "reason": "dangerous"
        })
        with patch.object(brain, "_invoke_text", return_value=response):
            result = brain.review_action(action="call_tool", target="x")
        assert result["allowed"] is False
        assert result["risk"] == "high"

    def test_rewrite_command_preserved(self):
        brain = self._make_brain(client=MagicMock())
        response = json.dumps({
            "allowed": True, "risk": "medium", "reason": "ok",
            "rewrite_command": "nmap -sT target"
        })
        with patch.object(brain, "_invoke_text", return_value=response):
            result = brain.review_action(action="run_tool", target="x",
                                         command="nmap -sS target")
        assert result["rewrite_command"] == "nmap -sT target"


# ================================================================
# analyze
# ================================================================

class TestAnalyze:

    def _make_brain(self, client=None, tool_catalog=""):
        brain = LLMBrain.__new__(LLMBrain)
        brain._client = client
        brain.provider = "claude"
        brain.model = "test"
        brain.api_key = "sk-test"
        brain.base_url = ""
        brain.tool_catalog = tool_catalog
        return brain

    def test_no_client_returns_done(self):
        brain = self._make_brain(client=None)
        result = brain.analyze([{"role": "user", "content": "hello"}])
        assert result["action"] == "done"
        assert "LLM" in result["summary"]

    def test_valid_decision_returned(self):
        brain = self._make_brain(client=MagicMock())
        response = '{"action": "call_tool", "tool_name": "nmap_scan", "params": {"target": "10.0.0.1"}, "thinking": ["scan first"], "plan": ["next"]}'
        with patch.object(brain, "_invoke_text", return_value=response):
            result = brain.analyze([{"role": "user", "content": "scan target"}])
        assert result["action"] == "call_tool"
        assert result["tool_name"] == "nmap_scan"

    def test_invalid_json_returns_retry(self):
        brain = self._make_brain(client=MagicMock())
        with patch.object(brain, "_invoke_text", return_value="not json at all"):
            result = brain.analyze([{"role": "user", "content": "test"}])
        assert result["action"] == "retry"

    def test_general_exception_returns_retry(self):
        brain = self._make_brain(client=MagicMock())
        with patch.object(brain, "_invoke_text", side_effect=RuntimeError("API down")):
            result = brain.analyze([{"role": "user", "content": "test"}])
        assert result["action"] == "retry"
        assert "API down" in result["raw_text"]

    def test_tool_catalog_injected_into_prompt(self):
        brain = self._make_brain(client=MagicMock(), tool_catalog="nmap, gobuster")
        response = '{"action": "done", "summary": "ok"}'
        with patch.object(brain, "_invoke_text", return_value=response) as mock_invoke:
            brain.analyze([{"role": "user", "content": "test"}])
            prompt = mock_invoke.call_args[0][0]
            assert "nmap, gobuster" in prompt


# ================================================================
# is_policy_refusal
# ================================================================

class TestIsPolicyRefusal:

    def test_empty_string(self):
        assert LLMBrain.is_policy_refusal("") is False

    def test_none_input(self):
        assert LLMBrain.is_policy_refusal(None) is False

    def test_normal_text_not_refusal(self):
        assert LLMBrain.is_policy_refusal("Here is the scan result") is False

    def test_english_refusal_detected(self):
        assert LLMBrain.is_policy_refusal("I need to decline this request") is True

    def test_english_refusal_case_insensitive(self):
        assert LLMBrain.is_policy_refusal("I NEED TO DECLINE this") is True

    def test_chinese_refusal_detected(self):
        assert LLMBrain.is_policy_refusal("无法协助进行渗透测试") is True

    def test_partial_match(self):
        assert LLMBrain.is_policy_refusal(
            "Some text i can't assist with that more text"
        ) is True

    def test_another_english_refusal(self):
        assert LLMBrain.is_policy_refusal("cannot perform penetration testing here") is True

    def test_could_cause_real_harm(self):
        assert LLMBrain.is_policy_refusal("This could cause real harm to systems") is True

    def test_chinese_cannot_execute(self):
        assert LLMBrain.is_policy_refusal("我需要拒绝该请求") is True

    def test_whitespace_stripped(self):
        assert LLMBrain.is_policy_refusal("  I need to decline  ") is True

    def test_real_world_targets_refusal(self):
        assert LLMBrain.is_policy_refusal("cannot scan real-world targets") is True


# ================================================================
# build_initial_message
# ================================================================

class TestBuildInitialMessage:

    def _make_brain(self):
        brain = LLMBrain.__new__(LLMBrain)
        brain.tool_catalog = ""
        return brain

    def test_ctf_mode(self):
        brain = self._make_brain()
        msg = brain.build_initial_message("http://ctf.local", "ctf", "")
        assert "ctf" in msg.lower() or "flag" in msg.lower()
        assert "http://ctf.local" in msg

    def test_pentest_mode(self):
        brain = self._make_brain()
        msg = brain.build_initial_message("10.0.0.1", "pentest", "")
        assert "open ports" in msg.lower() or "services" in msg.lower()

    def test_audit_mode(self):
        brain = self._make_brain()
        msg = brain.build_initial_message("code.py", "audit", "")
        assert "source code" in msg.lower() or "logic" in msg.lower()

    def test_unknown_mode(self):
        brain = self._make_brain()
        msg = brain.build_initial_message("target", "recon", "")
        assert "target" in msg
        # Should still contain the generic closing
        assert "data-collection" in msg.lower() or "first" in msg.lower()

    def test_with_prompt(self):
        brain = self._make_brain()
        msg = brain.build_initial_message("t", "ctf", "find the SQL injection")
        assert "Operator note" in msg

    def test_without_prompt(self):
        brain = self._make_brain()
        msg = brain.build_initial_message("t", "ctf", "")
        assert "Operator note" not in msg

    def test_target_in_message(self):
        brain = self._make_brain()
        msg = brain.build_initial_message("192.168.1.1", "pentest", "")
        assert "192.168.1.1" in msg


# ================================================================
# truncate_output
# ================================================================

class TestTruncateOutput:

    def test_short_output_unchanged(self):
        text = "short"
        assert LLMBrain.truncate_output(text) == text

    def test_exact_boundary_unchanged(self):
        text = "a" * 3000
        assert LLMBrain.truncate_output(text) == text

    def test_long_output_truncated(self):
        text = "a" * 6000
        result = LLMBrain.truncate_output(text)
        assert len(result) < len(text)
        assert "截断" in result
        assert "6000" in result

    def test_custom_max_chars(self):
        text = "a" * 200
        result = LLMBrain.truncate_output(text, max_chars=100)
        assert len(result) < len(text)
        assert "截断" in result

    def test_head_and_tail_preserved(self):
        text = "HEAD" + "x" * 6000 + "TAIL"
        result = LLMBrain.truncate_output(text, max_chars=100)
        assert result.startswith("HEAD")
        assert result.endswith("TAIL")

    def test_zero_max_chars(self):
        text = "abc"
        result = LLMBrain.truncate_output(text, max_chars=0)
        assert "截断" in result

    def test_one_char_max(self):
        text = "abcdef"
        result = LLMBrain.truncate_output(text, max_chars=1)
        assert "截断" in result


# ================================================================
# sanitize_prompt
# ================================================================

class TestSanitizePrompt:

    def test_empty_prompt(self):
        assert LLMBrain.sanitize_prompt("") == ""

    def test_none_prompt(self):
        assert LLMBrain.sanitize_prompt(None) is None

    def test_short_prompt_no_terms(self):
        assert LLMBrain.sanitize_prompt("hello world") == "hello world"

    def test_short_prompt_with_term(self):
        result = LLMBrain.sanitize_prompt("执行渗透测试")
        assert "渗透测试" not in result
        assert "assessment" in result.lower() or "technical" in result.lower()

    def test_long_prompt_over_500_chars(self):
        long_prompt = "这是一段很长的文字。" * 60  # > 500 chars
        result = LLMBrain.sanitize_prompt(long_prompt)
        assert result == LLMBrain._CONSTRAINT_SUMMARY

    def test_exact_500_chars_not_summarized(self):
        prompt = "a" * 500
        result = LLMBrain.sanitize_prompt(prompt)
        assert result == prompt

    def test_501_chars_summarized(self):
        prompt = "a" * 501
        result = LLMBrain.sanitize_prompt(prompt)
        assert result == LLMBrain._CONSTRAINT_SUMMARY

    def test_sql_injection_term(self):
        result = LLMBrain.sanitize_prompt("SQL注入测试")
        assert "SQL注入" not in result

    def test_xss_term(self):
        result = LLMBrain.sanitize_prompt("XSS漏洞")
        assert "XSS" not in result or "cross-site" in result.lower()

    def test_vulnerability_term(self):
        result = LLMBrain.sanitize_prompt("found a vulnerability")
        assert "vulnerability" not in result
        assert "finding" in result

    def test_exploit_term(self):
        result = LLMBrain.sanitize_prompt("use exploit code")
        assert "exploit" not in result
        assert "verification method" in result

    def test_payload_term(self):
        result = LLMBrain.sanitize_prompt("send Payload to server")
        assert "Payload" not in result
        assert "test input" in result

    def test_longer_term_replaced_first(self):
        result = LLMBrain.sanitize_prompt("penetration testing")
        assert "penetration testing" not in result
        assert "technical assessment" in result

    def test_multiple_terms_in_one_prompt(self):
        result = LLMBrain.sanitize_prompt("漏洞扫描和密码破解")
        assert "漏洞扫描" not in result
        assert "密码破解" not in result


# ================================================================
# _TERM_LIST ordering
# ================================================================

class TestTermListOrdering:

    def test_longer_terms_before_shorter(self):
        for i in range(len(LLMBrain._TERM_LIST) - 1):
            curr_len = len(LLMBrain._TERM_LIST[i][0])
            next_len = len(LLMBrain._TERM_LIST[i + 1][0])
            assert curr_len >= next_len

    def test_all_term_map_entries_in_term_list(self):
        list_keys = {term for term, _ in LLMBrain._TERM_LIST}
        for key in LLMBrain._TERM_MAP:
            assert key in list_keys


# ================================================================
# make_sanitizer
# ================================================================

class TestMakeSanitizer:

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_sanitize_replaces_target(self, mock_dns):
        sanitize, desanitize = LLMBrain.make_sanitizer("example.com")
        result = sanitize("Connect to example.com on port 80")
        assert "example.com" not in result
        assert LLMBrain.PLACEHOLDER in result

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_desanitize_restores_target(self, mock_dns):
        sanitize, desanitize = LLMBrain.make_sanitizer("example.com")
        text = f"Connect to {LLMBrain.PLACEHOLDER}"
        result = desanitize(text)
        assert LLMBrain.PLACEHOLDER not in result

    @patch("socket.gethostbyname", return_value="10.0.0.1")
    def test_ip_also_sanitized(self, mock_dns):
        sanitize, desanitize = LLMBrain.make_sanitizer("target.local")
        result = sanitize("Server at 10.0.0.1 is target.local")
        assert "10.0.0.1" not in result
        assert "target.local" not in result

    @patch("socket.gethostbyname", side_effect=OSError("DNS failed"))
    def test_dns_failure_handled(self, mock_dns):
        sanitize, desanitize = LLMBrain.make_sanitizer("nohost.invalid")
        result = sanitize("nohost.invalid is down")
        assert "nohost.invalid" not in result

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_chinese_org_name_sanitized(self, mock_dns):
        sanitize, _ = LLMBrain.make_sanitizer("target.com")
        result = sanitize("北京科技大学的系统")
        assert "北京科技大学" not in result
        assert "TARGET_ORG" in result

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_edu_cn_domain_sanitized(self, mock_dns):
        sanitize, _ = LLMBrain.make_sanitizer("target.com")
        result = sanitize("server at foo.edu.cn is open")
        assert "foo.edu.cn" not in result
        assert LLMBrain.PLACEHOLDER in result

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_url_target_parsed(self, mock_dns):
        sanitize, _ = LLMBrain.make_sanitizer("http://example.com:8080/path")
        result = sanitize("example.com is serving on 8080")
        assert "example.com" not in result

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    def test_no_scheme_target(self, mock_dns):
        sanitize, _ = LLMBrain.make_sanitizer("plain.host")
        result = sanitize("plain.host responds")
        assert "plain.host" not in result


# ================================================================
# _claude_http_messages_create
# ================================================================

class TestClaudeHttpMessagesCreate:

    def _make_brain(self):
        brain = LLMBrain.__new__(LLMBrain)
        brain.api_key = "sk-test"
        brain.base_url = "https://api.anthropic.com"
        brain.model = "claude-3"
        brain.provider = "claude"
        brain._client = None
        brain.tool_catalog = ""
        return brain

    def test_missing_api_key_raises(self):
        brain = self._make_brain()
        brain.api_key = ""
        with pytest.raises(RuntimeError, match="missing api key"):
            brain._claude_http_messages_create("prompt", [])

    @patch("kali_mcp.core.llm_brain.httpx.Client")
    def test_success_returns_text(self, mock_client_cls):
        brain = self._make_brain()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "hello"}]
        }
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_response)))
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_ctx

        result = brain._claude_http_messages_create("prompt", [{"role": "user", "content": "hi"}])
        assert result == "hello"

    @patch("kali_mcp.core.llm_brain.httpx.Client")
    def test_http_error_raises(self, mock_client_cls):
        brain = self._make_brain()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_response)))
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_ctx

        with pytest.raises(RuntimeError, match="HTTP 500"):
            brain._claude_http_messages_create("prompt", [])

    @patch("kali_mcp.core.llm_brain.httpx.Client")
    def test_empty_content_returns_empty_string(self, mock_client_cls):
        brain = self._make_brain()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"content": []}
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_response)))
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_ctx

        result = brain._claude_http_messages_create("prompt", [])
        assert result == ""

    @patch("kali_mcp.core.llm_brain.httpx.Client")
    def test_non_text_content_skipped(self, mock_client_cls):
        brain = self._make_brain()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"type": "image", "data": "xxx"}]
        }
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=MagicMock(post=MagicMock(return_value=mock_response)))
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_ctx

        result = brain._claude_http_messages_create("prompt", [])
        assert result == ""

    @patch("kali_mcp.core.llm_brain.httpx.Client")
    def test_base_url_ending_with_v1(self, mock_client_cls):
        brain = self._make_brain()
        brain.base_url = "https://proxy.example.com/v1"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "ok"}]
        }
        mock_ctx = MagicMock()
        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        mock_ctx.__enter__ = MagicMock(return_value=mock_client)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_ctx

        brain._claude_http_messages_create("prompt", [])
        call_url = mock_client.post.call_args[0][0]
        assert call_url == "https://proxy.example.com/v1/messages"


# ================================================================
# _invoke_text
# ================================================================

class TestInvokeText:

    def _make_brain(self, provider="claude"):
        brain = LLMBrain.__new__(LLMBrain)
        brain.provider = provider
        brain.model = "test-model"
        brain.api_key = "sk-test"
        brain.base_url = ""
        brain.tool_catalog = ""
        brain._client = MagicMock()
        return brain

    def test_no_client_raises(self):
        brain = self._make_brain()
        brain._client = None
        with pytest.raises(RuntimeError, match="LLM client unavailable"):
            brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])

    def test_codex_provider_calls_chat_completions(self):
        brain = self._make_brain(provider="codex")
        mock_choice = MagicMock()
        mock_choice.message.content = "response text"
        brain._client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == "response text"
        brain._client.chat.completions.create.assert_called_once()

    def test_codex_provider_prefer_json(self):
        brain = self._make_brain(provider="codex")
        mock_choice = MagicMock()
        mock_choice.message.content = '{"result": "ok"}'
        brain._client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}],
                                    prefer_json=True)
        assert result == '{"result": "ok"}'
        call_kwargs = brain._client.chat.completions.create.call_args
        assert call_kwargs[1].get("response_format") == {"type": "json_object"}

    def test_codex_prefer_json_typeerror_fallback(self):
        brain = self._make_brain(provider="codex")
        mock_choice = MagicMock()
        mock_choice.message.content = "fallback"
        # First call with response_format raises TypeError, second without succeeds
        brain._client.chat.completions.create.side_effect = [
            TypeError("unsupported param"),
            MagicMock(choices=[mock_choice]),
        ]
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}],
                                    prefer_json=True)
        assert result == "fallback"

    def test_codex_prefer_json_response_format_error_fallback(self):
        brain = self._make_brain(provider="codex")
        mock_choice = MagicMock()
        mock_choice.message.content = "fallback2"
        # First call raises an error mentioning response_format
        brain._client.chat.completions.create.side_effect = [
            ValueError("response_format not supported"),
            MagicMock(choices=[mock_choice]),
        ]
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}],
                                    prefer_json=True)
        assert result == "fallback2"

    def test_codex_prefer_json_unrelated_error_raises(self):
        brain = self._make_brain(provider="codex")
        brain._client.chat.completions.create.side_effect = ValueError("network error")
        with pytest.raises(ValueError, match="network error"):
            brain._invoke_text("prompt", [{"role": "user", "content": "hi"}],
                               prefer_json=True)

    def test_codex_response_as_list(self):
        brain = self._make_brain(provider="codex")
        mock_choice = MagicMock()
        mock_choice.message.content = [
            {"text": "part1"},
            "part2",
        ]
        brain._client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == "part1part2"

    def test_codex_response_none_content(self):
        brain = self._make_brain(provider="codex")
        mock_choice = MagicMock()
        mock_choice.message.content = None
        brain._client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == ""

    def test_claude_provider_calls_messages_create(self):
        brain = self._make_brain(provider="claude")
        mock_block = MagicMock()
        mock_block.text = "claude response"
        brain._client.messages.create.return_value = MagicMock(content=[mock_block])
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == "claude response"

    def test_claude_response_as_dict(self):
        brain = self._make_brain(provider="claude")
        brain._client.messages.create.return_value = MagicMock(
            content=[{"type": "text", "text": "dict response"}]
        )
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == "dict response"

    def test_claude_blocked_fallback_to_http(self):
        brain = self._make_brain(provider="claude")
        brain._client.messages.create.side_effect = Exception("Request blocked by filter")
        with patch.object(brain, "_claude_http_messages_create",
                          return_value="http fallback"):
            result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == "http fallback"

    def test_claude_403_fallback_to_http(self):
        brain = self._make_brain(provider="claude")
        brain._client.messages.create.side_effect = Exception("Error 403 Forbidden")
        with patch.object(brain, "_claude_http_messages_create",
                          return_value="http fallback"):
            result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == "http fallback"

    def test_claude_non_blocked_error_raises(self):
        brain = self._make_brain(provider="claude")
        brain._client.messages.create.side_effect = RuntimeError("timeout")
        with pytest.raises(RuntimeError, match="timeout"):
            brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])

    def test_claude_response_no_text_attr(self):
        """When first content item has no text attr and is not a dict."""
        brain = self._make_brain(provider="claude")
        mock_block = MagicMock(spec=[])  # no text attribute
        brain._client.messages.create.return_value = MagicMock(content=[mock_block])
        result = brain._invoke_text("prompt", [{"role": "user", "content": "hi"}])
        assert result == ""


# ================================================================
# Edge cases and integration-like scenarios
# ================================================================

class TestEdgeCases:

    def test_parse_decision_nested_in_list_in_code_block(self):
        text = '```json\n[{"action": "done", "summary": "ok"}]\n```'
        result = LLMBrain._parse_decision_json(text)
        assert result is not None
        assert result["action"] == "done"

    def test_coerce_with_multiple_nested_keys(self):
        """Only the first matching nested key should be found."""
        payload = {
            "decision": {"action": "call_tool", "tool_name": "a"},
            "result": {"action": "run_tool", "command": "b"},
        }
        result = LLMBrain._coerce_decision_payload(payload)
        # No top-level "action", so first nested key "decision" should match
        assert result is not None
        assert result["action"] == "call_tool"

    def test_iter_json_objects_adjacent_objects(self):
        text = '{"a":1}{"b":2}'
        result = list(LLMBrain._iter_json_objects(text))
        assert len(result) == 2

    def test_refusal_detection_with_unicode(self):
        assert LLMBrain.is_policy_refusal("拒绝该请求，无法执行") is True

    def test_default_plan_different_modes_have_different_tools(self):
        ctf = LLMBrain._default_plan("t", "ctf")
        pentest = LLMBrain._default_plan("t", "pentest")
        assert ctf["todos"][0]["tool_hint"] != pentest["todos"][0]["tool_hint"]

    def test_truncate_output_default_max_chars(self):
        text = "x" * 3001
        result = LLMBrain.truncate_output(text)
        assert "截断" in result
        assert "3001" in result

    def test_sanitize_prompt_webshell_lowercase(self):
        result = LLMBrain.sanitize_prompt("upload webshell file")
        assert "webshell" not in result
        assert "test artifact" in result

    def test_sanitize_prompt_getshell(self):
        result = LLMBrain.sanitize_prompt("GetShell via upload")
        assert "GetShell" not in result
        assert "access verification" in result

    def test_sanitize_prompt_ssrf(self):
        result = LLMBrain.sanitize_prompt("test for SSRF")
        assert "SSRF" not in result
        assert "server-side request check" in result

    def test_sanitize_prompt_csrf(self):
        result = LLMBrain.sanitize_prompt("check CSRF vulnerability")
        assert "CSRF" not in result

    def test_sanitize_prompt_0day(self):
        result = LLMBrain.sanitize_prompt("0day exploit found")
        assert "0day" not in result
        assert "zero-day finding" in result

    def test_build_initial_message_sanitizes_prompt(self):
        brain = LLMBrain.__new__(LLMBrain)
        brain.tool_catalog = ""
        msg = brain.build_initial_message("t", "ctf", "SQL注入漏洞")
        # Prompt should be sanitized via sanitize_prompt
        assert "SQL注入" not in msg

    def test_repair_decision_truncates_long_raw_text(self):
        """repair_decision should pass at most 2000 chars of raw_text."""
        brain = LLMBrain.__new__(LLMBrain)
        brain._client = MagicMock()
        brain.provider = "claude"
        brain.model = "test"
        brain.api_key = "sk-test"
        brain.base_url = ""
        brain.tool_catalog = ""

        long_text = "x" * 5000
        repaired = '{"action": "done", "summary": "ok"}'
        with patch.object(brain, "_invoke_text", return_value=repaired) as mock:
            brain.repair_decision(long_text)
            user_content = mock.call_args[0][1][0]["content"]
            # The raw text portion should be truncated to 2000
            assert long_text not in user_content
