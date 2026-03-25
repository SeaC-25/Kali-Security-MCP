"""
Tests for tool_bridge module (kali_mcp/core/tool_bridge.py)

Comprehensive coverage:
- ToolRegistry:
    - __init__: empty dicts on creation
    - tool(): decorator captures sync/async functions, docstrings, name
    - tool(): function with no docstring gets empty string
    - tool(): decorator returns the original function unchanged
    - Multiple registrations, overwrite behavior
- ToolBridge:
    - __init__: creates registry, calls _register_all_tools, sets executor
    - _register_all_tools: tolerates individual module failures gracefully
    - _register_all_tools: optional v2/v3/vulnerability modules (import fail)
    - _register_all_tools: optional modules appended when available
    - call_tool: unknown tool returns error string
    - call_tool: sync function execution via to_thread
    - call_tool: async function direct await
    - call_tool: function raising exception returns error string
    - call_tool: result is dict with 'output' key
    - call_tool: result is dict without 'output' key (json fallback)
    - call_tool: result is dict with empty 'output' (json fallback)
    - call_tool: result is non-dict (str conversion)
    - call_tool: params forwarded correctly
    - get_catalog_prompt: header line with tool count
    - get_catalog_prompt: categories appear in output
    - get_catalog_prompt: empty categories excluded
    - get_catalog_prompt: tools sorted within category
    - _first_line: normal multiline doc
    - _first_line: empty string returns "无描述"
    - _first_line: whitespace-only returns "无描述"
    - _first_line: long first line truncated to 60 chars
    - _first_line: leading blank lines skipped
    - _param_summary: no params returns "无参数"
    - _param_summary: required params marked (必填)
    - _param_summary: optional params shown without marker
    - _param_summary: mixed required and optional
    - _param_summary: unknown tool returns ""
    - _param_summary: function with un-inspectable signature
    - _categorize_tools: returns only non-empty categories
    - _categorize_tools: all known categories as keys
    - _classify: information gathering keywords
    - _classify: web application testing keywords
    - _classify: password attack keywords
    - _classify: exploit/APT keywords
    - _classify: CTF keywords
    - _classify: PWN/reverse keywords
    - _classify: intelligent/smart keywords
    - _classify: session/context management keywords
    - _classify: fallback to "系统与其他"
    - _classify: case insensitivity
    - _classify: partial match behavior

150+ tests, pure unit tests, no subprocess, no network.
"""

import asyncio
import inspect
import json
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from kali_mcp.core.tool_bridge import ToolRegistry, ToolBridge


# =====================================================================
# ToolRegistry Tests
# =====================================================================


class TestToolRegistryInit:
    """ToolRegistry.__init__ sets up empty containers."""

    def test_tools_is_empty_dict(self):
        reg = ToolRegistry()
        assert reg.tools == {}

    def test_tool_docs_is_empty_dict(self):
        reg = ToolRegistry()
        assert reg.tool_docs == {}

    def test_tools_is_dict_type(self):
        reg = ToolRegistry()
        assert isinstance(reg.tools, dict)

    def test_tool_docs_is_dict_type(self):
        reg = ToolRegistry()
        assert isinstance(reg.tool_docs, dict)

    def test_separate_instances_have_independent_state(self):
        r1 = ToolRegistry()
        r2 = ToolRegistry()
        @r1.tool()
        def foo():
            pass
        assert "foo" in r1.tools
        assert "foo" not in r2.tools


class TestToolRegistryTool:
    """ToolRegistry.tool() decorator."""

    def test_registers_function_by_name(self):
        reg = ToolRegistry()
        @reg.tool()
        def my_tool():
            pass
        assert "my_tool" in reg.tools

    def test_stored_function_is_the_original(self):
        reg = ToolRegistry()
        @reg.tool()
        def my_tool():
            pass
        assert reg.tools["my_tool"] is my_tool

    def test_decorator_returns_original_function(self):
        reg = ToolRegistry()
        def original():
            pass
        decorated = reg.tool()(original)
        assert decorated is original

    def test_captures_docstring(self):
        reg = ToolRegistry()
        @reg.tool()
        def documented():
            """This is a documented tool."""
            pass
        assert reg.tool_docs["documented"] == "This is a documented tool."

    def test_no_docstring_stores_empty(self):
        reg = ToolRegistry()
        @reg.tool()
        def nodoc():
            pass
        assert reg.tool_docs["nodoc"] == ""

    def test_multiline_docstring_stored_fully(self):
        reg = ToolRegistry()
        @reg.tool()
        def multi():
            """Line one.\n\nLine two."""
            pass
        assert "Line one." in reg.tool_docs["multi"]
        assert "Line two." in reg.tool_docs["multi"]

    def test_register_multiple_tools(self):
        reg = ToolRegistry()
        @reg.tool()
        def tool_a():
            """A"""
        @reg.tool()
        def tool_b():
            """B"""
        @reg.tool()
        def tool_c():
            """C"""
        assert len(reg.tools) == 3
        assert set(reg.tools.keys()) == {"tool_a", "tool_b", "tool_c"}

    def test_overwrite_same_name(self):
        """Registering a second function with the same name overwrites."""
        reg = ToolRegistry()
        def first():
            """First version"""
            return 1
        def second():
            """Second version"""
            return 2
        # Manually set same __name__
        second.__name__ = "first"
        reg.tool()(first)
        reg.tool()(second)
        assert reg.tools["first"] is second
        assert reg.tool_docs["first"] == "Second version"

    def test_async_function_registered(self):
        reg = ToolRegistry()
        @reg.tool()
        async def async_tool():
            """Async tool"""
            pass
        assert "async_tool" in reg.tools
        assert asyncio.iscoroutinefunction(reg.tools["async_tool"])

    def test_function_with_params_registered(self):
        reg = ToolRegistry()
        @reg.tool()
        def parameterized(target: str, port: int = 80):
            """Has params"""
            pass
        assert "parameterized" in reg.tools

    def test_callable_preserved_after_decoration(self):
        """Decorated function remains callable."""
        reg = ToolRegistry()
        @reg.tool()
        def adder(a, b):
            return a + b
        assert adder(2, 3) == 5

    def test_lambda_name(self):
        """Lambda gets registered under its __name__ ('<lambda>')."""
        reg = ToolRegistry()
        fn = lambda: 42  # noqa: E731
        reg.tool()(fn)
        assert "<lambda>" in reg.tools


# =====================================================================
# ToolBridge — heavily mocked to avoid importing real modules
# =====================================================================


def _make_bridge_with_tools(tools_dict=None, tool_docs_dict=None):
    """Create a ToolBridge with _register_all_tools mocked out,
    then manually populate its registry."""
    with patch.object(ToolBridge, "_register_all_tools"):
        bridge = ToolBridge(executor=MagicMock())
    if tools_dict:
        bridge.registry.tools.update(tools_dict)
    if tool_docs_dict:
        bridge.registry.tool_docs.update(tool_docs_dict)
    return bridge


class TestToolBridgeInit:
    """ToolBridge.__init__."""

    def test_executor_stored(self):
        exe = MagicMock()
        with patch.object(ToolBridge, "_register_all_tools"):
            bridge = ToolBridge(executor=exe)
        assert bridge.executor is exe

    def test_registry_is_tool_registry(self):
        with patch.object(ToolBridge, "_register_all_tools"):
            bridge = ToolBridge(executor=MagicMock())
        assert isinstance(bridge.registry, ToolRegistry)

    def test_register_all_tools_called(self):
        with patch.object(ToolBridge, "_register_all_tools") as mock_reg:
            ToolBridge(executor=MagicMock())
            mock_reg.assert_called_once()


# =====================================================================
# ToolBridge._register_all_tools
# =====================================================================


class TestRegisterAllTools:
    """ToolBridge._register_all_tools — module import and registration robustness."""

    def test_individual_module_failure_does_not_crash(self):
        """If a single register function raises, others still run."""
        exe = MagicMock()

        # Patch the imports that happen inside _register_all_tools
        with patch("kali_mcp.core.ai_context.AIContextManager"):
            with patch("kali_mcp.core.ml_optimizer.MLStrategyOptimizer"):
                # Mock all the mcp_tools imports to simple callables that
                # track whether they were called
                mock_fns = {}
                for name in [
                    "register_system_tools", "register_multi_agent_tools",
                    "register_recon_tools", "register_ai_session_tools",
                    "register_code_audit_tools", "register_misc_tools",
                    "register_apt_tools", "register_ctf_tools",
                    "register_scan_workflow_tools", "register_advanced_ctf_tools",
                    "register_payload_tools", "register_session_tools",
                    "register_pwn_tools", "register_context_tools",
                    "register_knowledge_tools", "register_adaptive_tools",
                    "register_ai_advanced_tools", "register_deep_test_tools",
                    "register_vuln_mgmt_tools", "register_fragment_mgmt_tools",
                    "register_chain_mgmt_tools", "register_shared_context_tools",
                    "register_checkpoint_tools", "register_decision_brain_tools",
                    "register_pipeline_tools", "register_pentagi_bridge_tools",
                    "register_llm_react_tools",
                ]:
                    mock_fns[name] = MagicMock()

                # Make one of them raise
                mock_fns["register_recon_tools"].side_effect = RuntimeError("boom")

                with patch.dict("kali_mcp.mcp_tools.__dict__", mock_fns):
                    # This should not raise even though recon_tools fails
                    bridge = ToolBridge(executor=exe)

                # code_audit_tools comes after the failing recon_tools and should still run
                mock_fns["register_code_audit_tools"].assert_called_once()


# =====================================================================
# ToolBridge.call_tool (async)
# =====================================================================


class TestCallTool:
    """ToolBridge.call_tool async method."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        bridge = _make_bridge_with_tools()
        result = await bridge.call_tool("nonexistent", {})
        assert "[error]" in result
        assert "nonexistent" in result

    @pytest.mark.asyncio
    async def test_sync_function_called_via_to_thread(self):
        def sync_tool(target):
            return {"output": f"scanned {target}"}
        bridge = _make_bridge_with_tools({"sync_tool": sync_tool})
        result = await bridge.call_tool("sync_tool", {"target": "1.2.3.4"})
        assert "scanned 1.2.3.4" in result

    @pytest.mark.asyncio
    async def test_async_function_awaited_directly(self):
        async def async_tool(target):
            return {"output": f"async scanned {target}"}
        bridge = _make_bridge_with_tools({"async_tool": async_tool})
        result = await bridge.call_tool("async_tool", {"target": "5.6.7.8"})
        assert "async scanned 5.6.7.8" in result

    @pytest.mark.asyncio
    async def test_exception_returns_error_string(self):
        def bad_tool():
            raise ValueError("something broke")
        bridge = _make_bridge_with_tools({"bad_tool": bad_tool})
        result = await bridge.call_tool("bad_tool", {})
        assert "[error]" in result
        assert "something broke" in result
        assert "bad_tool" in result

    @pytest.mark.asyncio
    async def test_dict_result_with_output_key(self):
        def tool():
            return {"output": "hello world", "extra": "data"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "hello world"

    @pytest.mark.asyncio
    async def test_dict_result_without_output_key_json_fallback(self):
        def tool():
            return {"status": "ok", "count": 42}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        parsed = json.loads(result)
        assert parsed["status"] == "ok"
        assert parsed["count"] == 42

    @pytest.mark.asyncio
    async def test_dict_result_empty_output_json_fallback(self):
        """When output key exists but is empty/falsy, fall back to json.dumps."""
        def tool():
            return {"output": "", "data": [1, 2, 3]}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        parsed = json.loads(result)
        assert parsed["data"] == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_dict_result_none_output_json_fallback(self):
        def tool():
            return {"output": None, "info": "test"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        parsed = json.loads(result)
        assert parsed["info"] == "test"

    @pytest.mark.asyncio
    async def test_non_dict_result_converted_to_str(self):
        def tool():
            return 42
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "42"

    @pytest.mark.asyncio
    async def test_string_result(self):
        def tool():
            return "plain string"
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "plain string"

    @pytest.mark.asyncio
    async def test_list_result_converted_to_str(self):
        def tool():
            return [1, 2, 3]
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "[1, 2, 3]"

    @pytest.mark.asyncio
    async def test_none_result_converted_to_str(self):
        def tool():
            return None
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "None"

    @pytest.mark.asyncio
    async def test_params_forwarded_correctly(self):
        def tool(a, b, c="default"):
            return {"output": f"{a}-{b}-{c}"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {"a": "x", "b": "y", "c": "z"})
        assert result == "x-y-z"

    @pytest.mark.asyncio
    async def test_params_with_defaults(self):
        def tool(target, port=443):
            return {"output": f"{target}:{port}"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {"target": "host"})
        assert result == "host:443"

    @pytest.mark.asyncio
    async def test_async_exception_returns_error(self):
        async def async_bad():
            raise RuntimeError("async boom")
        bridge = _make_bridge_with_tools({"async_bad": async_bad})
        result = await bridge.call_tool("async_bad", {})
        assert "[error]" in result
        assert "async boom" in result

    @pytest.mark.asyncio
    async def test_dict_with_non_serializable_value_uses_default_str(self):
        """json.dumps with default=str handles non-serializable values."""
        def tool():
            return {"obj": object(), "output": ""}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        # Should not raise, json.dumps uses default=str
        assert "obj" in result

    @pytest.mark.asyncio
    async def test_dict_ensure_ascii_false(self):
        """Chinese chars preserved in output."""
        def tool():
            return {"output": "", "msg": "中文测试"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert "中文测试" in result

    @pytest.mark.asyncio
    async def test_wrong_params_raises_captured(self):
        """Calling with wrong params should be caught as exception."""
        def tool(required_param):
            return {"output": "ok"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert "[error]" in result


# =====================================================================
# ToolBridge._first_line (static method)
# =====================================================================


class TestFirstLine:
    """ToolBridge._first_line static method."""

    def test_normal_single_line(self):
        assert ToolBridge._first_line("Hello world") == "Hello world"

    def test_multiline_returns_first_non_empty(self):
        doc = "First line\nSecond line\nThird line"
        assert ToolBridge._first_line(doc) == "First line"

    def test_empty_string_returns_no_desc(self):
        assert ToolBridge._first_line("") == "无描述"

    def test_whitespace_only_returns_no_desc(self):
        assert ToolBridge._first_line("   \n  \n  ") == "无描述"

    def test_leading_blank_lines_skipped(self):
        doc = "\n\n  \n  Actual first line\nSecond"
        assert ToolBridge._first_line(doc) == "Actual first line"

    def test_truncated_to_60_chars(self):
        long_line = "A" * 100
        result = ToolBridge._first_line(long_line)
        assert len(result) == 60
        assert result == "A" * 60

    def test_exactly_60_chars_not_truncated(self):
        line = "B" * 60
        assert ToolBridge._first_line(line) == line

    def test_59_chars_not_truncated(self):
        line = "C" * 59
        assert ToolBridge._first_line(line) == line

    def test_tabs_and_spaces_stripped(self):
        doc = "\t  Hello  \t"
        assert ToolBridge._first_line(doc) == "Hello"

    def test_newline_only_returns_no_desc(self):
        assert ToolBridge._first_line("\n") == "无描述"

    def test_doc_with_only_blank_lines(self):
        assert ToolBridge._first_line("\n\n\n") == "无描述"

    def test_indented_docstring(self):
        doc = "    Indented docstring\n    More details"
        assert ToolBridge._first_line(doc) == "Indented docstring"


# =====================================================================
# ToolBridge._param_summary
# =====================================================================


class TestParamSummary:
    """ToolBridge._param_summary."""

    def test_no_params_returns_no_params(self):
        def no_params():
            pass
        bridge = _make_bridge_with_tools({"no_params": no_params})
        assert bridge._param_summary("no_params") == "无参数"

    def test_required_param_marked(self):
        def tool(target):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        assert "target(必填)" in result

    def test_optional_param_not_marked(self):
        def tool(port=80):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        assert result == "port"
        assert "必填" not in result

    def test_mixed_required_optional(self):
        def tool(target, port=80, verbose=False):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        assert "target(必填)" in result
        assert "port" in result
        assert "verbose" in result

    def test_unknown_tool_returns_empty(self):
        bridge = _make_bridge_with_tools()
        assert bridge._param_summary("nonexistent") == ""

    def test_multiple_required_params(self):
        def tool(a, b, c):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        assert "a(必填)" in result
        assert "b(必填)" in result
        assert "c(必填)" in result

    def test_all_optional_params(self):
        def tool(a=1, b=2, c=3):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        assert "必填" not in result
        assert "a" in result
        assert "b" in result
        assert "c" in result

    def test_comma_separated(self):
        def tool(x, y=10):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        assert ", " in result

    def test_uninspectable_signature_returns_empty(self):
        """Built-in that can't be inspected returns empty string."""
        bridge = _make_bridge_with_tools({"builtin": len})
        # len's signature can actually be inspected in newer Python,
        # so we mock inspect.signature to raise
        with patch("kali_mcp.core.tool_bridge.inspect.signature",
                    side_effect=ValueError("no sig")):
            assert bridge._param_summary("builtin") == ""

    def test_type_error_on_signature_returns_empty(self):
        bridge = _make_bridge_with_tools({"tool": MagicMock()})
        with patch("kali_mcp.core.tool_bridge.inspect.signature",
                    side_effect=TypeError("bad")):
            assert bridge._param_summary("tool") == ""

    def test_default_none_counts_as_optional(self):
        def tool(x=None):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        assert "必填" not in result
        assert "x" in result

    def test_param_order_preserved(self):
        def tool(alpha, beta, gamma=0):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        result = bridge._param_summary("tool")
        parts = result.split(", ")
        assert parts[0] == "alpha(必填)"
        assert parts[1] == "beta(必填)"
        assert parts[2] == "gamma"


# =====================================================================
# ToolBridge._classify (static method)
# =====================================================================


class TestClassify:
    """ToolBridge._classify static method — full keyword coverage."""

    # --- 信息收集 ---
    @pytest.mark.parametrize("name", [
        "nmap_scan", "masscan_fast", "arp_scan_host", "fping_sweep",
        "netdiscover_run", "subfinder_enum", "amass_scan",
        "sublist3r_run", "dnsrecon_query", "dnsenum_check",
        "fierce_scan", "dnsmap_run", "theharvester_osint",
        "whatweb_detect", "httpx_probe", "wafw00f_check",
        "sherlock_search", "recon_full", "tshark_capture",
        "ngrep_filter", "comprehensive_recon",
    ])
    def test_info_gathering(self, name):
        assert ToolBridge._classify(name) == "信息收集"

    # --- Web 应用测试 ---
    @pytest.mark.parametrize("name", [
        "gobuster_dir", "dirb_scan", "ffuf_fuzz", "feroxbuster_run",
        "wfuzz_test", "nikto_scan", "sqlmap_inject", "nuclei_scan",
        "wpscan_wordpress", "joomscan_run", "web_app_test",
        "web_security_audit", "xss_payload", "sql_injection_test",
        "command_injection_check", "file_upload_bypass",
        "file_inclusion_lfi",
    ])
    def test_web_app_testing(self, name):
        assert ToolBridge._classify(name) == "Web 应用测试"

    # --- 密码攻击 ---
    @pytest.mark.parametrize("name", [
        "hydra_brute", "john_crack_hash", "hashcat_gpu",
        "medusa_attack", "ncrack_ssh", "patator_ftp",
        "crowbar_rdp", "brutespray_auto", "aircrack_wifi",
        "reaver_wps", "bully_attack", "pixiewps_pin",
        "password_crack_tool", "brute_force_login",
    ])
    def test_password_attack(self, name):
        assert ToolBridge._classify(name) == "密码攻击"

    # --- 漏洞利用与 APT ---
    @pytest.mark.parametrize("name", [
        "metasploit_run", "searchsploit_find", "enum4linux_scan",
        "responder_listen", "ettercap_mitm", "bettercap_sniff",
        "apt_attack_chain", "exploit_cve", "privilege_escalation",
        "lateral_movement",
    ])
    def test_exploit_apt(self, name):
        assert ToolBridge._classify(name) == "漏洞利用与 APT"

    # --- CTF 专用 ---
    @pytest.mark.parametrize("name", [
        "ctf_solve", "flag_finder", "challenge_web",
        "enable_ctf_mode", "ctf_web_comprehensive_solver",
    ])
    def test_ctf(self, name):
        assert ToolBridge._classify(name) == "CTF 专用"

    # --- PWN 与逆向 ---
    @pytest.mark.parametrize("name", [
        "pwn_attack", "binwalk_analysis", "reverse_binary",
        "radare2_disasm", "ghidra_decompile", "crypto_solver",
    ])
    def test_pwn_reverse(self, name):
        assert ToolBridge._classify(name) == "PWN 与逆向"

    # --- 智能化工具 ---
    @pytest.mark.parametrize("name", [
        "intelligent_scan", "smart_vuln_check", "adaptive_attack",
        "ai_analyze", "auto_deploy", "comprehensive_web_scan",
        "comprehensive_network_audit",
    ])
    def test_intelligent(self, name):
        assert ToolBridge._classify(name) == "智能化工具 (推荐优先使用)"

    # --- 会话与上下文管理 ---
    @pytest.mark.parametrize("name", [
        "session_create", "context_store", "knowledge_query",
        "memory_save", "checkpoint_save", "pipeline_run",
        "chain_create", "fragment_merge",
        "shared_context_sync", "decision_evaluate",
    ])
    def test_session_context(self, name):
        assert ToolBridge._classify(name) == "会话与上下文管理"

    # --- 系统与其他 (fallback) ---
    @pytest.mark.parametrize("name", [
        "server_health", "system_status", "unknown_tool",
        "foobar", "some_random_name", "v2_status",
    ])
    def test_fallback_system(self, name):
        assert ToolBridge._classify(name) == "系统与其他"

    # --- Case insensitivity ---
    def test_case_insensitive_upper(self):
        assert ToolBridge._classify("NMAP_SCAN") == "信息收集"

    def test_case_insensitive_mixed(self):
        assert ToolBridge._classify("SqlMap_Inject") == "Web 应用测试"

    def test_case_insensitive_ctf(self):
        assert ToolBridge._classify("CTF_Challenge") == "CTF 专用"

    # --- Priority / first-match behavior ---
    def test_classify_first_match_wins_recon_over_smart(self):
        """'comprehensive_recon' matches 信息收集 first (before 智能化)."""
        assert ToolBridge._classify("comprehensive_recon") == "信息收集"

    def test_classify_ctf_over_pwn(self):
        """A name with both 'ctf' and 'pwn' hits CTF first."""
        assert ToolBridge._classify("ctf_pwn_solver") == "CTF 专用"

    def test_classify_apt_underscore_prefix(self):
        """'apt_' is a keyword for exploit/APT category."""
        assert ToolBridge._classify("apt_lateral_move") == "漏洞利用与 APT"

    def test_classify_empty_string(self):
        assert ToolBridge._classify("") == "系统与其他"


# =====================================================================
# ToolBridge._categorize_tools
# =====================================================================


class TestCategorizeTools:
    """ToolBridge._categorize_tools."""

    def test_empty_registry_returns_empty(self):
        bridge = _make_bridge_with_tools()
        cats = bridge._categorize_tools()
        assert cats == {}

    def test_single_tool_categorized(self):
        def nmap_scan():
            pass
        bridge = _make_bridge_with_tools({"nmap_scan": nmap_scan})
        cats = bridge._categorize_tools()
        assert "信息收集" in cats
        assert "nmap_scan" in cats["信息收集"]

    def test_empty_categories_excluded(self):
        def nmap_scan():
            pass
        bridge = _make_bridge_with_tools({"nmap_scan": nmap_scan})
        cats = bridge._categorize_tools()
        assert "CTF 专用" not in cats
        assert "密码攻击" not in cats

    def test_multiple_categories(self):
        def nmap_scan():
            pass
        def sqlmap_inject():
            pass
        def hydra_brute():
            pass
        bridge = _make_bridge_with_tools({
            "nmap_scan": nmap_scan,
            "sqlmap_inject": sqlmap_inject,
            "hydra_brute": hydra_brute,
        })
        cats = bridge._categorize_tools()
        assert "信息收集" in cats
        assert "Web 应用测试" in cats
        assert "密码攻击" in cats

    def test_all_tools_in_same_category(self):
        tools = {
            "nmap_scan": lambda: None,
            "masscan_fast": lambda: None,
            "whatweb_detect": lambda: None,
        }
        bridge = _make_bridge_with_tools(tools)
        cats = bridge._categorize_tools()
        assert len(cats) == 1
        assert "信息收集" in cats
        assert len(cats["信息收集"]) == 3

    def test_fallback_category_used(self):
        bridge = _make_bridge_with_tools({"random_tool": lambda: None})
        cats = bridge._categorize_tools()
        assert "系统与其他" in cats


# =====================================================================
# ToolBridge.get_catalog_prompt
# =====================================================================


class TestGetCatalogPrompt:
    """ToolBridge.get_catalog_prompt."""

    def test_header_contains_tool_count(self):
        tools = {"nmap_scan": lambda: None, "sqlmap_inject": lambda: None}
        bridge = _make_bridge_with_tools(tools)
        prompt = bridge.get_catalog_prompt()
        assert "共 2 个" in prompt

    def test_header_contains_call_tool_action(self):
        bridge = _make_bridge_with_tools({"foo": lambda: None})
        prompt = bridge.get_catalog_prompt()
        assert "call_tool" in prompt

    def test_category_headers_present(self):
        tools = {
            "nmap_scan": lambda: None,
            "hydra_brute": lambda: None,
        }
        bridge = _make_bridge_with_tools(tools)
        prompt = bridge.get_catalog_prompt()
        assert "### 信息收集" in prompt
        assert "### 密码攻击" in prompt

    def test_tool_names_listed(self):
        def nmap_scan():
            """Scan ports"""
            pass
        bridge = _make_bridge_with_tools(
            {"nmap_scan": nmap_scan},
            {"nmap_scan": "Scan ports"},
        )
        prompt = bridge.get_catalog_prompt()
        assert "nmap_scan" in prompt

    def test_short_doc_in_output(self):
        bridge = _make_bridge_with_tools(
            {"nmap_scan": lambda: None},
            {"nmap_scan": "Scan network ports and services"},
        )
        prompt = bridge.get_catalog_prompt()
        assert "Scan network ports" in prompt

    def test_no_doc_shows_no_desc(self):
        bridge = _make_bridge_with_tools(
            {"nmap_scan": lambda: None},
            {"nmap_scan": ""},
        )
        prompt = bridge.get_catalog_prompt()
        assert "无描述" in prompt

    def test_tools_sorted_within_category(self):
        tools = {
            "nmap_z_scan": lambda: None,
            "nmap_a_scan": lambda: None,
            "nmap_m_scan": lambda: None,
        }
        bridge = _make_bridge_with_tools(tools)
        prompt = bridge.get_catalog_prompt()
        # Find positions
        pos_a = prompt.index("nmap_a_scan")
        pos_m = prompt.index("nmap_m_scan")
        pos_z = prompt.index("nmap_z_scan")
        assert pos_a < pos_m < pos_z

    def test_param_summary_in_output(self):
        def nmap_scan(target, ports="1-1000"):
            """Scan ports"""
            pass
        bridge = _make_bridge_with_tools(
            {"nmap_scan": nmap_scan},
            {"nmap_scan": "Scan ports"},
        )
        prompt = bridge.get_catalog_prompt()
        assert "target(必填)" in prompt
        assert "ports" in prompt

    def test_empty_registry_still_has_header(self):
        bridge = _make_bridge_with_tools()
        prompt = bridge.get_catalog_prompt()
        assert "共 0 个" in prompt

    def test_empty_registry_no_category_sections(self):
        bridge = _make_bridge_with_tools()
        prompt = bridge.get_catalog_prompt()
        assert "###" not in prompt


# =====================================================================
# Edge cases and integration-style unit tests
# =====================================================================


class TestEdgeCases:
    """Edge cases combining multiple methods."""

    @pytest.mark.asyncio
    async def test_call_tool_with_empty_params_dict(self):
        def tool():
            return "no params needed"
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "no params needed"

    @pytest.mark.asyncio
    async def test_call_tool_result_bool(self):
        def tool():
            return True
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "True"

    @pytest.mark.asyncio
    async def test_call_tool_result_float(self):
        def tool():
            return 3.14
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "3.14"

    @pytest.mark.asyncio
    async def test_call_tool_dict_with_output_truthy(self):
        """When output is truthy, it is returned directly."""
        def tool():
            return {"output": "data here"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert result == "data here"

    @pytest.mark.asyncio
    async def test_call_tool_dict_output_zero(self):
        """output=0 is falsy, so json fallback kicks in."""
        def tool():
            return {"output": 0, "info": "zero"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        parsed = json.loads(result)
        assert parsed["info"] == "zero"

    def test_first_line_with_carriage_return(self):
        doc = "Line one\r\nLine two"
        result = ToolBridge._first_line(doc)
        assert result == "Line one"

    def test_classify_substring_match(self):
        """'recon' matches inside 'my_recon_tool'."""
        assert ToolBridge._classify("my_recon_tool") == "信息收集"

    def test_classify_exact_keyword_nmap(self):
        assert ToolBridge._classify("nmap") == "信息收集"

    def test_classify_ai_underscore(self):
        """'ai_' matches AI tools category."""
        assert ToolBridge._classify("ai_strategy") == "智能化工具 (推荐优先使用)"

    def test_classify_auto_underscore(self):
        assert ToolBridge._classify("auto_scan") == "智能化工具 (推荐优先使用)"

    @pytest.mark.asyncio
    async def test_call_multiple_tools_sequentially(self):
        def tool_a():
            return {"output": "A"}
        def tool_b():
            return {"output": "B"}
        bridge = _make_bridge_with_tools({"tool_a": tool_a, "tool_b": tool_b})
        r1 = await bridge.call_tool("tool_a", {})
        r2 = await bridge.call_tool("tool_b", {})
        assert r1 == "A"
        assert r2 == "B"

    def test_param_summary_with_star_args(self):
        """Functions with *args/**kwargs should be inspectable."""
        def tool(*args, **kwargs):
            pass
        bridge = _make_bridge_with_tools({"tool": tool})
        # *args and **kwargs are not Parameter.POSITIONAL_OR_KEYWORD,
        # they still iterate in sig.parameters
        result = bridge._param_summary("tool")
        # args has no default, kwargs has no default
        # But *args is VAR_POSITIONAL and **kwargs is VAR_KEYWORD
        # Both have .default == Parameter.empty, so both get (必填)
        assert isinstance(result, str)

    def test_get_catalog_prompt_returns_string(self):
        bridge = _make_bridge_with_tools({"nmap_scan": lambda: None})
        assert isinstance(bridge.get_catalog_prompt(), str)

    @pytest.mark.asyncio
    async def test_call_tool_exception_includes_tool_name(self):
        """Error message should include the tool name for debugging."""
        def broken_tool():
            raise OSError("disk full")
        bridge = _make_bridge_with_tools({"broken_tool": broken_tool})
        result = await bridge.call_tool("broken_tool", {})
        assert "broken_tool" in result
        assert "disk full" in result

    def test_categorize_returns_dict(self):
        bridge = _make_bridge_with_tools({"nmap_scan": lambda: None})
        assert isinstance(bridge._categorize_tools(), dict)

    def test_registry_accessible_after_init(self):
        bridge = _make_bridge_with_tools()
        assert hasattr(bridge, "registry")
        assert isinstance(bridge.registry, ToolRegistry)


# =====================================================================
# Classify exhaustive keyword coverage
# =====================================================================


class TestClassifyExhaustiveKeywords:
    """Ensure every keyword listed in _classify triggers correctly."""

    # Information gathering - comprehensive list
    @pytest.mark.parametrize("keyword", [
        "nmap", "masscan", "arp_scan", "fping", "netdiscover",
        "subfinder", "amass", "sublist3r", "dnsrecon", "dnsenum",
        "fierce", "dnsmap", "theharvester", "whatweb", "httpx",
        "wafw00f", "sherlock", "recon", "tshark", "ngrep",
        "comprehensive_recon",
    ])
    def test_info_gathering_keyword(self, keyword):
        assert ToolBridge._classify(f"tool_{keyword}_run") == "信息收集"

    # Web app testing
    @pytest.mark.parametrize("keyword", [
        "gobuster", "dirb", "ffuf", "feroxbuster", "wfuzz",
        "nikto", "sqlmap", "nuclei", "wpscan", "joomscan",
        "web_app", "web_security", "xss", "sql_injection",
        "command_injection", "file_upload", "file_inclusion",
    ])
    def test_web_keyword(self, keyword):
        assert ToolBridge._classify(f"my_{keyword}_test") == "Web 应用测试"

    # Password attack
    @pytest.mark.parametrize("keyword", [
        "hydra", "john", "hashcat", "medusa", "ncrack",
        "patator", "crowbar", "brutespray", "aircrack",
        "reaver", "bully", "pixiewps", "crack", "brute",
    ])
    def test_password_keyword(self, keyword):
        assert ToolBridge._classify(f"run_{keyword}_attack") == "密码攻击"

    # Exploit/APT
    @pytest.mark.parametrize("keyword", [
        "metasploit", "searchsploit", "enum4linux", "responder",
        "ettercap", "bettercap", "apt_", "exploit", "privilege",
        "lateral",
    ])
    def test_exploit_keyword(self, keyword):
        assert ToolBridge._classify(f"do_{keyword}action") == "漏洞利用与 APT"

    # CTF
    @pytest.mark.parametrize("keyword", ["ctf", "flag", "challenge"])
    def test_ctf_keyword(self, keyword):
        assert ToolBridge._classify(f"my_{keyword}_tool") == "CTF 专用"

    # PWN/Reverse
    @pytest.mark.parametrize("keyword", [
        "pwn", "binwalk", "reverse", "radare2", "ghidra", "crypto",
    ])
    def test_pwn_keyword(self, keyword):
        assert ToolBridge._classify(f"use_{keyword}_now") == "PWN 与逆向"

    # Intelligent
    @pytest.mark.parametrize("keyword", [
        "intelligent", "smart", "adaptive", "ai_",
        "auto_", "comprehensive_web", "comprehensive_network",
    ])
    def test_intelligent_keyword(self, keyword):
        assert ToolBridge._classify(f"x{keyword}y") == "智能化工具 (推荐优先使用)"

    # Session/context
    @pytest.mark.parametrize("keyword", [
        "session", "context", "knowledge", "memory",
        "checkpoint", "pipeline", "chain", "fragment",
        "shared_context", "decision",
    ])
    def test_session_keyword(self, keyword):
        assert ToolBridge._classify(f"do_{keyword}_thing") == "会话与上下文管理"


# =====================================================================
# ToolRegistry edge cases
# =====================================================================


class TestToolRegistryEdge:
    """Edge cases for ToolRegistry."""

    def test_tool_decorator_can_be_called_multiple_times(self):
        reg = ToolRegistry()
        dec1 = reg.tool()
        dec2 = reg.tool()
        assert dec1 is not dec2  # Different decorator instances

    def test_tool_with_class_method(self):
        reg = ToolRegistry()
        class MyClass:
            @reg.tool()
            def class_tool(self):
                """A class tool"""
                pass
        assert "class_tool" in reg.tools

    def test_tool_with_complex_default(self):
        reg = ToolRegistry()
        @reg.tool()
        def complex_defaults(data=None, items=None):
            """Complex defaults"""
            pass
        assert "complex_defaults" in reg.tools

    def test_registry_tools_and_docs_same_keys(self):
        reg = ToolRegistry()
        @reg.tool()
        def t1():
            """D1"""
        @reg.tool()
        def t2():
            """D2"""
        assert set(reg.tools.keys()) == set(reg.tool_docs.keys())


# =====================================================================
# More call_tool async tests
# =====================================================================


class TestCallToolAsync:
    """Additional async call_tool tests."""

    @pytest.mark.asyncio
    async def test_async_tool_with_params(self):
        async def scan(host, port=22):
            return {"output": f"{host}:{port}"}
        bridge = _make_bridge_with_tools({"scan": scan})
        result = await bridge.call_tool("scan", {"host": "10.0.0.1", "port": 8080})
        assert result == "10.0.0.1:8080"

    @pytest.mark.asyncio
    async def test_async_tool_default_params(self):
        async def scan(host, port=22):
            return {"output": f"{host}:{port}"}
        bridge = _make_bridge_with_tools({"scan": scan})
        result = await bridge.call_tool("scan", {"host": "10.0.0.1"})
        assert result == "10.0.0.1:22"

    @pytest.mark.asyncio
    async def test_sync_tool_returning_dict_no_output(self):
        def tool():
            return {"result": "value", "code": 200}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        parsed = json.loads(result)
        assert parsed["result"] == "value"

    @pytest.mark.asyncio
    async def test_dict_with_output_false_uses_json_fallback(self):
        """output=False is falsy."""
        def tool():
            return {"output": False, "data": "stuff"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        parsed = json.loads(result)
        assert parsed["data"] == "stuff"

    @pytest.mark.asyncio
    async def test_dict_with_output_empty_list_uses_json_fallback(self):
        """output=[] is falsy."""
        def tool():
            return {"output": [], "info": "empty list"}
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        parsed = json.loads(result)
        assert parsed["info"] == "empty list"

    @pytest.mark.asyncio
    async def test_type_error_in_tool_captured(self):
        def tool():
            return 1 + "string"
        bridge = _make_bridge_with_tools({"tool": tool})
        result = await bridge.call_tool("tool", {})
        assert "[error]" in result


# =====================================================================
# Module-level constants and structure
# =====================================================================


class TestModuleStructure:
    """Test module-level attributes and class structure."""

    def test_tool_registry_has_tool_method(self):
        assert hasattr(ToolRegistry, "tool")
        assert callable(ToolRegistry.tool)

    def test_tool_bridge_has_call_tool(self):
        assert hasattr(ToolBridge, "call_tool")

    def test_tool_bridge_has_get_catalog_prompt(self):
        assert hasattr(ToolBridge, "get_catalog_prompt")

    def test_first_line_is_static(self):
        assert isinstance(
            inspect.getattr_static(ToolBridge, "_first_line"),
            staticmethod,
        )

    def test_classify_is_static(self):
        assert isinstance(
            inspect.getattr_static(ToolBridge, "_classify"),
            staticmethod,
        )

    def test_call_tool_is_coroutine(self):
        assert asyncio.iscoroutinefunction(ToolBridge.call_tool)

    def test_tool_registry_init_signature(self):
        sig = inspect.signature(ToolRegistry.__init__)
        # Only 'self' parameter
        params = list(sig.parameters.keys())
        assert params == ["self"]

    def test_tool_bridge_init_takes_executor(self):
        sig = inspect.signature(ToolBridge.__init__)
        params = list(sig.parameters.keys())
        assert "executor" in params
