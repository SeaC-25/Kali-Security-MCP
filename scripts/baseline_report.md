# Kali MCP Baseline Report

- Generated (UTC): 2026-08-09T05:17:05+00:00
- Repo root: `F:/springInFer-skill/Kali-Security-MCP-main/Kali-Security-MCP-main`

## Registered tools

- Tool count (`@mcp.tool()` in `kali_mcp/mcp_tools/*.py`): **192**
- Schema byte estimate (signature + docstring): **86110** bytes across 192 tools

### Per-module breakdown

| Module | Tools | Schema bytes |
|---|---|---|
| __init__.py | 0 | 0 |
| adaptive_tools.py | 5 | 1689 |
| advanced_ctf_tools.py | 4 | 1102 |
| ai_tools.py | 21 | 9860 |
| apt_tools.py | 12 | 6201 |
| assessment_tools.py | 11 | 2926 |
| browser_tools.py | 12 | 7875 |
| chain_mgmt_tools.py | 4 | 1629 |
| code_audit_tools.py | 6 | 3330 |
| ctf_tools.py | 8 | 3006 |
| deep_test_tools.py | 28 | 14932 |
| harness_tools.py | 18 | 5301 |
| llm_react_tools.py | 1 | 984 |
| misc_tools.py | 19 | 8496 |
| pentagi_bridge_tools.py | 9 | 1785 |
| pwn_tools.py | 12 | 6995 |
| recon_tools.py | 9 | 4806 |
| session_tools.py | 8 | 2738 |
| vuln_mgmt_tools.py | 5 | 2455 |

## Instructions block

- `instructions="..."` in `mcp_server.py`: **933 bytes** (559 chars, 20 lines)

## Timeout inventory (`EXEC_CONFIG` in `kali_mcp/core/shell_utils.py`)

| Setting | Value |
|---|---|
| default_timeout | {'default': 60, 'env_var': 'KALI_MCP_TIMEOUT'} |
| retry_count | {'default': 2, 'env_var': 'KALI_MCP_RETRY_COUNT'} |
| retry_delay | {'default': 3, 'env_var': 'KALI_MCP_RETRY_DELAY'} |
| tool_timeouts entries | 13 |
| max tool timeout | 300s |
| max config value | 300s |

### Tool timeouts

| Tool | Seconds |
|---|---|
| amass | 120 |
| ffuf | 90 |
| gobuster | 90 |
| httpx | 30 |
| hydra | 300 |
| masscan | 120 |
| nikto | 120 |
| nmap | 180 |
| nuclei | 90 |
| sqlmap | 300 |
| subfinder | 60 |
| whatweb | 30 |
| wpscan | 120 |

## LLM-key dependency files

- Files referencing `anthropic`/`openai`/`api_key`: **6**
- `kali_mcp/agents/specialized/code_analyze_agent.py`
- `kali_mcp/agents/specialized/code_audit_agent.py`
- `kali_mcp/core/llm_brain.py`
- `kali_mcp/core/result_parser.py`
- `kali_mcp/mcp_tools/llm_react_tools.py`
- `kali_mcp/tools/mobile.py`

## Backend reachability

- Check: `where nmap`
- nmap: **not-found**
