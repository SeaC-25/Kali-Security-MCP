"""
Tests for ToolChain (kali_mcp/core/tool_chain.py)

Covers:
- Factory chain creation (web, network, CTF, full pentest)
- Chain execution with mocked executor
- Step condition filtering
- Step failure and continuation
- Decision hooks inserting dynamic steps
- Context data flow between steps
- Flag detection in output
"""

from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from kali_mcp.core.tool_chain import (
    ToolChain, ToolChainStep, ChainContext,
    create_web_recon_chain, create_network_recon_chain,
    create_ctf_speed_chain, create_full_pentest_chain,
    BUILTIN_DECISION_HOOKS,
    _hook_cms_deep_scan, _hook_smb_enumeration,
)
from kali_mcp.core.result_parser import NmapResult, PortInfo, GobusterResult, PathInfo


class TestChainCreation:
    """Test factory functions create chains with expected steps."""

    def test_create_web_chain(self, mock_executor):
        """Web recon chain has expected steps."""
        chain = create_web_recon_chain(mock_executor)

        assert isinstance(chain, ToolChain)
        step_names = [s.name for s in chain.steps]
        assert "port_scan" in step_names
        assert "tech_fingerprint" in step_names
        assert "dir_scan" in step_names
        assert "vuln_scan" in step_names
        assert len(chain.steps) == 7  # port, tech, waf, dir, vuln, wordpress, sqli

    def test_create_network_chain(self, mock_executor):
        """Network chain has expected steps."""
        chain = create_network_recon_chain(mock_executor)

        step_names = [s.name for s in chain.steps]
        assert "fast_port_scan" in step_names
        assert "service_scan" in step_names
        assert len(chain.steps) == 4  # masscan, nmap, nuclei, enum4linux

    def test_create_ctf_chain(self, mock_executor):
        """CTF speed chain has expected steps."""
        chain = create_ctf_speed_chain(mock_executor)

        step_names = [s.name for s in chain.steps]
        assert "fast_scan" in step_names
        assert "dir_scan" in step_names
        assert len(chain.steps) == 4  # nmap, gobuster, nuclei, sqlmap

    def test_create_full_pentest_chain(self, mock_executor):
        """Full pentest chain is the most comprehensive."""
        chain = create_full_pentest_chain(mock_executor)

        assert len(chain.steps) == 9  # full_port, tech, waf, dir, vuln, nikto, sqli, cms, smb

    def test_chains_have_decision_hooks(self, mock_executor):
        """All predefined chains include decision hooks."""
        chain = create_web_recon_chain(mock_executor)

        assert len(chain._decision_hooks) == len(BUILTIN_DECISION_HOOKS)


class TestChainExecution:
    """Test chain.execute() with mocked executor."""

    def test_chain_execute_success(self, mock_executor):
        """Mock executor chain runs all non-conditional steps."""
        # Build nmap-like output so the parser recognizes ports
        nmap_output = "80/tcp   open  http    Apache httpd 2.4.41\n"
        mock_executor.execute_tool_with_data.return_value = {
            "success": True,
            "output": nmap_output,
        }

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(
            name="scan",
            tool_name="nmap",
            params={"target": "10.0.0.1"},
        ))

        results = chain.execute("10.0.0.1")

        assert results["success"] is True
        assert results["target"] == "10.0.0.1"
        assert "scan" in results["steps"]
        assert results["steps"]["scan"]["status"] == "success"
        mock_executor.execute_tool_with_data.assert_called_once()

    def test_chain_step_failure_continues(self, mock_executor):
        """Non-required failed step doesn't stop chain."""
        mock_executor.execute_tool_with_data.side_effect = [
            {"success": False, "output": "", "error": "tool not found"},
            {"success": True, "output": "second step ok"},
        ]

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="step1", tool_name="nmap", required=False))
        chain.add_step(ToolChainStep(name="step2", tool_name="whatweb"))

        results = chain.execute("10.0.0.1")

        # Chain should continue despite step1 failure
        assert results["success"] is True
        assert "step1" in results["steps"]
        assert "step2" in results["steps"]

    def test_chain_required_step_failure_stops(self, mock_executor):
        """Required step failure stops the chain."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": False, "output": "", "error": "failed",
        }

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="critical", tool_name="nmap", required=True))
        chain.add_step(ToolChainStep(name="next", tool_name="whatweb"))

        results = chain.execute("10.0.0.1")

        assert results["success"] is False
        assert "critical" in results["steps"]
        assert "next" not in results["steps"]

    def test_chain_condition_skips_step(self, mock_executor):
        """Step with false condition is skipped."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": True, "output": "ok",
        }

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(
            name="conditional",
            tool_name="wpscan",
            condition=lambda ctx: ctx.has_web_service,  # False by default
        ))

        results = chain.execute("10.0.0.1")

        assert results["steps"]["conditional"]["status"] == "skipped"
        mock_executor.execute_tool_with_data.assert_not_called()


class TestChainContextDataFlow:
    """Test that results from one step flow to the next."""

    def test_nmap_result_updates_context(self, mock_executor):
        """Nmap output parsed and available to subsequent steps via context."""
        nmap_output = """\
80/tcp   open  http    Apache httpd 2.4.41
22/tcp   open  ssh     OpenSSH 8.2p1
"""
        call_count = [0]

        def mock_execute(tool_name, params):
            call_count[0] += 1
            if tool_name == "nmap":
                return {"success": True, "output": nmap_output}
            return {"success": True, "output": "ok"}

        mock_executor.execute_tool_with_data.side_effect = mock_execute

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="scan", tool_name="nmap"))

        # Step 2 should only run if web service was detected
        chain.add_step(ToolChainStep(
            name="web_check",
            tool_name="whatweb",
            condition=lambda ctx: ctx.has_web_service,
            params_builder=lambda ctx: {"target": ctx.web_urls[0]} if ctx.web_urls else None,
        ))

        results = chain.execute("10.0.0.1")

        # Nmap found port 80 → has_web_service should be True → whatweb should execute
        assert results["steps"]["scan"]["status"] == "success"
        assert results["steps"]["web_check"]["status"] == "success"
        assert call_count[0] == 2

    def test_context_summary(self):
        """ChainContext.to_summary() produces valid dict."""
        ctx = ChainContext(target="10.0.0.1")
        ctx.open_ports = [80, 443]
        ctx.discovered_vulns = [{"type": "sqli"}]

        summary = ctx.to_summary()

        assert summary["target"] == "10.0.0.1"
        assert summary["open_ports"] == [80, 443]
        assert summary["vulns_found"] == 1


class TestDecisionHooks:
    """Test decision hooks that dynamically insert steps."""

    def test_hook_inserts_step(self, mock_executor):
        """Decision hook can insert a new step into the queue."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": True, "output": "ok",
        }

        inserted = []

        def my_hook(ctx, step, result, queue):
            if step.name == "first":
                new_step = ToolChainStep(name="injected", tool_name="nuclei")
                queue.appendleft(new_step)
                inserted.append(True)

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="first", tool_name="nmap"))
        chain.add_step(ToolChainStep(name="last", tool_name="whatweb"))
        chain.add_decision_hook(my_hook)

        results = chain.execute("10.0.0.1")

        assert len(inserted) == 1
        assert "injected" in results["steps"]
        # Execution order should be: first, injected, last
        step_order = list(results["steps"].keys())
        assert step_order.index("injected") < step_order.index("last")

    def test_cms_hook_wordpress(self):
        """CMS hook inserts wpscan when WordPress detected."""
        ctx = ChainContext(target="10.0.0.1")
        ctx.cms_type = "WordPress"
        ctx.web_urls = ["http://10.0.0.1"]

        step = ToolChainStep(name="tech", tool_name="whatweb")
        queue = deque()

        _hook_cms_deep_scan(ctx, step, {}, queue)

        assert len(queue) == 1
        assert queue[0].name == "auto_wpscan"
        assert queue[0].tool_name == "wpscan"

    def test_cms_hook_ignores_non_whatweb(self):
        """CMS hook only triggers for whatweb steps."""
        ctx = ChainContext(target="10.0.0.1")
        ctx.cms_type = "WordPress"

        step = ToolChainStep(name="scan", tool_name="nmap")
        queue = deque()

        _hook_cms_deep_scan(ctx, step, {}, queue)

        assert len(queue) == 0

    def test_smb_hook_inserts_enum4linux(self):
        """SMB hook inserts enum4linux when port 445 found."""
        ctx = ChainContext(target="10.0.0.1")
        ctx.open_ports = [22, 445]

        step = ToolChainStep(name="scan", tool_name="nmap")
        queue = deque()

        _hook_smb_enumeration(ctx, step, {}, queue)

        assert len(queue) == 1
        assert queue[0].tool_name == "enum4linux"

    def test_smb_hook_no_smb_ports(self):
        """SMB hook does nothing when no SMB ports."""
        ctx = ChainContext(target="10.0.0.1")
        ctx.open_ports = [22, 80]

        step = ToolChainStep(name="scan", tool_name="nmap")
        queue = deque()

        _hook_smb_enumeration(ctx, step, {}, queue)

        assert len(queue) == 0

    def test_duplicate_step_prevention(self, mock_executor):
        """Same-named step is not executed twice."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": True, "output": "ok",
        }

        def dupe_hook(ctx, step, result, queue):
            # Try to insert a step with the same name as an already-executed step
            queue.appendleft(ToolChainStep(name="scan", tool_name="nuclei"))

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="scan", tool_name="nmap"))
        chain.add_decision_hook(dupe_hook)

        results = chain.execute("10.0.0.1")

        # "scan" should only appear once (nmap, not nuclei)
        assert results["steps"]["scan"]["tool"] == "nmap"


class TestFlagDetection:
    """Test flag detection in tool output."""

    def test_flag_detected_in_output(self, mock_executor):
        """Flags in tool output are extracted."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": True,
            "output": "Congratulations! flag{this_is_a_test_flag_123}",
        }

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="scan", tool_name="nmap"))

        results = chain.execute("10.0.0.1")

        assert "flag{this_is_a_test_flag_123}" in results["flags"]

    def test_multiple_flag_formats(self, mock_executor):
        """Different flag formats are all detected."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": True,
            "output": "flag{abc} FLAG{DEF} ctf{ghi} CTF{JKL} DASCTF{mno}",
        }

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="scan", tool_name="nmap"))

        results = chain.execute("10.0.0.1")

        # DASCTF{mno} also matches CTF{mno} pattern, so 6 raw matches
        assert len(results["flags"]) >= 5

    def test_no_flag_in_output(self, mock_executor):
        """No flags in normal output."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": True,
            "output": "Normal scan output with no flags",
        }

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(name="scan", tool_name="nmap"))

        results = chain.execute("10.0.0.1")

        assert results["flags"] == []


class TestFallbackTools:
    """Test fallback tool mechanism."""

    def test_fallback_on_failure(self, mock_executor):
        """When primary tool fails, fallback tool is tried."""
        call_count = [0]

        def mock_execute(tool_name, params):
            call_count[0] += 1
            if tool_name == "gobuster":
                return {"success": False, "output": "", "error": "not found"}
            elif tool_name == "ffuf":
                return {"success": True, "output": "/admin (Status: 200)"}
            return {"success": True, "output": "ok"}

        mock_executor.execute_tool_with_data.side_effect = mock_execute

        chain = ToolChain(mock_executor)
        chain.add_step(ToolChainStep(
            name="dir_scan",
            tool_name="gobuster",
            fallback_tools=["ffuf", "dirb"],
        ))

        results = chain.execute("10.0.0.1")

        assert results["steps"]["dir_scan"]["status"] == "success"
        # gobuster + ffuf = 2 calls
        assert call_count[0] == 2


class TestEventBusIntegration:
    """Test chain integration with EventBus."""

    def test_chain_emits_tool_result_events(self, mock_executor, event_bus):
        """Chain emits tool.result events through the event bus."""
        mock_executor.execute_tool_with_data.return_value = {
            "success": True, "output": "ok",
        }

        handler = MagicMock()
        event_bus.subscribe("tool.result", handler, "test_sub")

        chain = ToolChain(mock_executor, event_bus)
        chain.add_step(ToolChainStep(name="scan", tool_name="nmap"))

        chain.execute("10.0.0.1")

        handler.assert_called_once()
        event = handler.call_args[0][0]
        assert event.data["tool_name"] == "nmap"
        assert event.data["target"] == "10.0.0.1"
