"""
Shared fixtures for Kali MCP test suite.

All tests use mocked executors and dependencies so they run
without any real Kali tools installed.
"""

import pytest
import sys
import os
from unittest.mock import patch

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Disable engagement context requirement for all tests.
# The EngagementManager defaults to require_context=True which blocks every
# command when no engagement JSON is supplied.  In tests we want to exercise
# the executor's subprocess path, so we patch the module-level singleton to
# None so the guard clause (`if engagement_manager is not None`) is skipped.
@pytest.fixture(autouse=True)
def _disable_engagement_check():
    """Patch engagement_manager to None so executor tests aren't scope-blocked."""
    with patch("kali_mcp.core.local_executor.engagement_manager", None):
        yield


@pytest.fixture
def mock_executor():
    """Mock LocalCommandExecutor for testing without real tool execution."""
    from unittest.mock import MagicMock
    executor = MagicMock()
    executor.execute_tool.return_value = {"success": True, "output": "mock output"}
    executor.execute_tool_with_data.return_value = {"success": True, "output": "mock output"}
    return executor


@pytest.fixture
def event_bus():
    """Create a fresh EventBus instance for each test."""
    from kali_mcp.core.event_bus import EventBus
    return EventBus()


@pytest.fixture
def decision_brain():
    """Create a fresh DecisionBrain instance for each test."""
    from kali_mcp.core.decision_brain import DecisionBrain
    return DecisionBrain()


@pytest.fixture
def nmap_output_with_ports():
    """Sample nmap output with several open ports."""
    return """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-03-09 12:00 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0012s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1
80/tcp   open  http        Apache httpd 2.4.41
443/tcp  open  ssl/http    nginx 1.18.0
3306/tcp open  mysql       MySQL 5.7.32
8080/tcp open  http-proxy  Squid http proxy

OS details: Linux 5.4.0

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""


@pytest.fixture
def nmap_output_empty():
    """Sample nmap output with no open ports."""
    return """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-03-09 12:00 UTC
Nmap scan report for 192.168.1.200
Host seems down.

Nmap done: 1 IP address (0 hosts up) scanned in 5.00 seconds
"""


@pytest.fixture
def gobuster_output():
    """Sample gobuster output."""
    return """\
/admin                (Status: 200) [Size: 1234]
/login                (Status: 302) [Size: 0] [--> /auth/login]
/api/v1               (Status: 200) [Size: 567]
/upload               (Status: 200) [Size: 890]
/static               (Status: 403) [Size: 123]
/robots.txt           (Status: 200) [Size: 45]
/index.php            (Status: 200) [Size: 4567]
"""


@pytest.fixture
def nuclei_output():
    """Sample nuclei text output."""
    return """\
[critical] [CVE-2021-44228] [http] http://192.168.1.100/api
[high] [apache-struts-rce] [http] http://192.168.1.100/struts
[medium] [x-frame-options] [http] http://192.168.1.100/
[info] [tech-detect:apache] [http] http://192.168.1.100/
"""


@pytest.fixture
def whatweb_output():
    """Sample whatweb output."""
    return """\
http://192.168.1.100 [200 OK] Apache[2.4.41], PHP[7.4.3], WordPress[5.7], jQuery[3.5.1], Country[RESERVED][ZZ]
"""
