"""
Tests for LocalCommandExecutor (kali_mcp/core/local_executor.py)

Covers:
- ALLOWED_TOOLS whitelist contents
- Tool name validation
- Argument sanitization
- Command building for nmap, gobuster, and other tools
- Timeout handling
- EventBus integration
- execute_with_retry behavior

All tests mock subprocess.run to avoid requiring actual Kali tools.
"""

import shlex
from unittest.mock import MagicMock, patch

import pytest

from kali_mcp.core.local_executor import (
    ALLOWED_TOOLS, validate_tool_name, sanitize_shell_arg,
    sanitize_shell_fragment, LocalCommandExecutor, EXEC_CONFIG,
    set_event_bus, _event_bus,
)


class TestAllowedToolsWhitelist:
    """Test ALLOWED_TOOLS set contents."""

    def test_contains_core_scanning_tools(self):
        """Core scanning tools are in whitelist."""
        core_tools = {"nmap", "gobuster", "sqlmap", "nikto", "nuclei", "masscan"}
        assert core_tools.issubset(ALLOWED_TOOLS)

    def test_contains_password_tools(self):
        """Password cracking tools are in whitelist."""
        pw_tools = {"hydra", "john", "hashcat"}
        assert pw_tools.issubset(ALLOWED_TOOLS)

    def test_contains_dns_tools(self):
        """DNS tools are in whitelist."""
        dns_tools = {"dnsrecon", "subfinder", "dig", "host", "whois"}
        assert dns_tools.issubset(ALLOWED_TOOLS)

    def test_contains_web_tools(self):
        """Web tools are in whitelist."""
        web_tools = {"whatweb", "wpscan", "ffuf", "feroxbuster", "wafw00f"}
        assert web_tools.issubset(ALLOWED_TOOLS)

    def test_contains_forensic_tools(self):
        """Forensic/stego tools from v5.1 are in whitelist."""
        forensic_tools = {"steghide", "zsteg", "exiftool", "foremost", "strings"}
        assert forensic_tools.issubset(ALLOWED_TOOLS)

    def test_contains_basic_unix_tools(self):
        """Basic unix tools from v5.1 are in whitelist."""
        unix_tools = {"curl", "wget", "grep", "awk", "sed", "jq"}
        assert unix_tools.issubset(ALLOWED_TOOLS)

    def test_does_not_contain_dangerous_tools(self):
        """Dangerous/unrestricted tools are NOT in whitelist."""
        assert "rm" not in ALLOWED_TOOLS
        assert "dd" not in ALLOWED_TOOLS
        assert "mkfs" not in ALLOWED_TOOLS
        assert "shutdown" not in ALLOWED_TOOLS


class TestValidateToolName:
    """Test validate_tool_name function."""

    def test_valid_tool_names(self):
        """Known tools pass validation."""
        assert validate_tool_name("nmap") is True
        assert validate_tool_name("gobuster") is True
        assert validate_tool_name("sqlmap") is True
        assert validate_tool_name("nuclei") is True

    def test_invalid_tool_names(self):
        """Unknown/dangerous tools are rejected."""
        assert validate_tool_name("rm") is False
        assert validate_tool_name("not_a_tool") is False
        assert validate_tool_name("") is False
        assert validate_tool_name("../etc/passwd") is False


class TestSanitizeShellArg:
    """Test shell argument sanitization."""

    def test_sanitize_normal_string(self):
        """Normal strings are quoted."""
        result = sanitize_shell_arg("192.168.1.1")
        # shlex.quote wraps in quotes only if needed
        assert "192.168.1.1" in result

    def test_sanitize_dangerous_input(self):
        """Dangerous shell metacharacters are neutralized."""
        result = sanitize_shell_arg("; rm -rf /")
        # The result should be safely quoted
        assert result == shlex.quote("; rm -rf /")
        # The semicolon should not be a command separator
        assert not result.startswith(";")

    def test_sanitize_empty_string(self):
        """Empty string returns empty string."""
        assert sanitize_shell_arg("") == ""

    def test_sanitize_shell_fragment_multiple_args(self):
        """Fragment sanitization preserves multiple args."""
        result = sanitize_shell_fragment("-sV -sC -T3")
        # Each token should be individually quoted
        assert "-sV" in result
        assert "-sC" in result
        assert "-T3" in result


class TestBuildToolCommand:
    """Test _build_tool_command for various tools."""

    @pytest.fixture
    def executor(self):
        """Create executor without mocking subprocess (commands built but not run)."""
        return LocalCommandExecutor(timeout=30)

    def test_build_nmap_command(self, executor):
        """Build correct nmap command."""
        cmd = executor._build_tool_command("nmap", {
            "target": "192.168.1.1",
            "scan_type": "-sV",
            "ports": "80,443",
        })

        assert cmd is not None
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd
        assert "-sV" in cmd
        assert "-p" in cmd
        assert "80,443" in cmd

    def test_build_nmap_command_with_additional_args(self, executor):
        """Nmap command includes additional args."""
        cmd = executor._build_tool_command("nmap", {
            "target": "10.0.0.1",
            "additional_args": "-T4 --open",
        })

        assert "-T4" in cmd
        assert "--open" in cmd

    def test_build_gobuster_command(self, executor):
        """Build correct gobuster command."""
        cmd = executor._build_tool_command("gobuster", {
            "url": "http://target.com",
            "mode": "dir",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
        })

        assert "gobuster" in cmd
        assert "dir" in cmd
        assert "-u" in cmd
        assert "http://target.com" in cmd
        assert "-w" in cmd
        assert "common.txt" in cmd

    def test_build_sqlmap_command(self, executor):
        """Build correct sqlmap command."""
        cmd = executor._build_tool_command("sqlmap", {
            "url": "http://target.com/page?id=1",
        })

        assert "sqlmap" in cmd
        assert "-u" in cmd
        assert "--batch" in cmd

    def test_build_sqlmap_command_with_post_data(self, executor):
        """Sqlmap command includes POST data."""
        cmd = executor._build_tool_command("sqlmap", {
            "url": "http://target.com/login",
            "data": "user=admin&pass=test",
        })

        assert "--data=" in cmd

    def test_build_nuclei_command(self, executor):
        """Build correct nuclei command."""
        cmd = executor._build_tool_command("nuclei", {
            "target": "http://target.com",
            "severity": "critical,high",
        })

        assert "nuclei" in cmd
        assert "-u" in cmd
        assert "-s" in cmd

    def test_build_hydra_command(self, executor):
        """Build correct hydra command."""
        cmd = executor._build_tool_command("hydra", {
            "target": "10.0.0.1",
            "service": "ssh",
            "username": "admin",
            "password_file": "/usr/share/wordlists/rockyou.txt",
        })

        assert "hydra" in cmd
        assert "-l" in cmd
        assert "admin" in cmd
        assert "-P" in cmd
        assert "ssh" in cmd

    def test_build_unknown_tool_in_whitelist(self, executor):
        """Tool in whitelist but without explicit route uses catch-all."""
        cmd = executor._build_tool_command("strings", {
            "target": "/tmp/testfile",
        })

        assert cmd is not None
        assert "strings" in cmd

    def test_build_unknown_tool_not_in_whitelist(self, executor):
        """Tool NOT in whitelist returns empty string."""
        cmd = executor._build_tool_command("totally_fake_tool", {
            "target": "10.0.0.1",
        })

        assert cmd == ""

    def test_build_whatweb_command(self, executor):
        """Build correct whatweb command."""
        cmd = executor._build_tool_command("whatweb", {
            "target": "http://target.com",
            "aggression": "3",
        })

        assert "whatweb" in cmd
        assert "-a" in cmd
        assert "3" in cmd

    def test_build_curl_command(self, executor):
        """Build correct curl command."""
        cmd = executor._build_tool_command("curl", {
            "url": "http://target.com/api",
            "method": "POST",
            "data": '{"key":"value"}',
        })

        assert "curl" in cmd
        assert "-X" in cmd
        assert "POST" in cmd
        assert "-d" in cmd


class TestExecuteCommand:
    """Test command execution with mocked subprocess."""

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_execute_command_success(self, mock_run):
        """Successful command execution."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="scan complete",
            stderr="",
        )

        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_command("echo test")

        assert result["success"] is True
        assert result["output"] == "scan complete"
        assert result["return_code"] == 0

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_execute_command_failure(self, mock_run):
        """Failed command execution."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="command not found",
        )

        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_command("bad_command")

        assert result["success"] is False
        assert result["return_code"] == 1

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_command_timeout(self, mock_run):
        """Command timeout produces expected error."""
        import subprocess as sp
        mock_run.side_effect = sp.TimeoutExpired(cmd="slow_cmd", timeout=30)

        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_command("slow_cmd")

        assert result["success"] is False
        assert "timeout" in result["error"].lower()
        assert result["return_code"] == -1

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_command_exception(self, mock_run):
        """General exception during execution."""
        mock_run.side_effect = OSError("Permission denied")

        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_command("restricted_cmd")

        assert result["success"] is False
        assert "Permission denied" in result["error"]


class TestExecuteToolWithData:
    """Test execute_tool_with_data method."""

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_execute_tool_with_data_nmap(self, mock_run):
        """Execute nmap through execute_tool_with_data."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="80/tcp open http",
            stderr="",
        )

        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_tool_with_data("nmap", {
            "target": "192.168.1.1",
            "scan_type": "-sV",
            "ports": "80",
        })

        assert result["success"] is True
        assert "80/tcp" in result["output"]
        assert result["tool_name"] == "nmap"
        assert "duration" in result

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_execute_tool_with_data_unknown_tool(self, mock_run):
        """Unknown tool returns error without executing."""
        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_tool_with_data("unknown_tool_xyz", {
            "target": "10.0.0.1",
        })

        assert result["success"] is False
        mock_run.assert_not_called()


class TestEventBusIntegration:
    """Test EventBus integration in executor."""

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_event_bus_receives_tool_result(self, mock_run):
        """When event bus is set, tool results are emitted."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="scan results",
            stderr="",
        )

        bus = MagicMock()
        handler = MagicMock()

        # Save the original value and restore after test
        import kali_mcp.core.local_executor as le_module
        original_bus = le_module._event_bus

        try:
            le_module._event_bus = bus

            executor = LocalCommandExecutor(timeout=30)
            executor.execute_tool_with_data("nmap", {"target": "10.0.0.1"})

            bus.emit.assert_called_once()
            call_args = bus.emit.call_args
            assert call_args[0][0] == "tool.result"
            assert call_args[0][1]["tool_name"] == "nmap"
        finally:
            le_module._event_bus = original_bus

    def test_set_event_bus(self):
        """set_event_bus correctly sets the module-level variable."""
        import kali_mcp.core.local_executor as le_module
        original = le_module._event_bus

        try:
            mock_bus = MagicMock()
            set_event_bus(mock_bus)
            assert le_module._event_bus is mock_bus
        finally:
            le_module._event_bus = original


class TestExecConfig:
    """Test EXEC_CONFIG defaults."""

    def test_default_timeout(self):
        """Default timeout is 300 seconds."""
        assert EXEC_CONFIG["default_timeout"] == 300

    def test_tool_specific_timeouts(self):
        """Tool-specific timeouts are configured."""
        assert "nmap" in EXEC_CONFIG["tool_timeouts"]
        assert "sqlmap" in EXEC_CONFIG["tool_timeouts"]
        assert EXEC_CONFIG["tool_timeouts"]["nmap"] == 600

    def test_retry_config(self):
        """Retry configuration exists."""
        assert EXEC_CONFIG["retry_count"] >= 1
        assert EXEC_CONFIG["retry_delay"] >= 1


class TestExecuteWithRetry:
    """Test execute_with_retry behavior."""

    @patch("kali_mcp.core.local_executor.subprocess.run")
    @patch("kali_mcp.core.local_executor.time.sleep")  # Skip actual sleeping
    def test_retry_on_failure(self, mock_sleep, mock_run):
        """Failed execution is retried."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="error"),
            MagicMock(returncode=0, stdout="success", stderr=""),
        ]

        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_with_retry("nmap", {"target": "10.0.0.1"}, retry_count=1, retry_delay=0)

        assert result["success"] is True
        assert mock_run.call_count == 2

    @patch("kali_mcp.core.local_executor.subprocess.run")
    def test_no_retry_on_success(self, mock_run):
        """Successful execution does not retry."""
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")

        executor = LocalCommandExecutor(timeout=30)
        result = executor.execute_with_retry("nmap", {"target": "10.0.0.1"}, retry_count=2)

        assert result["success"] is True
        assert mock_run.call_count == 1
