#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali MCP 系统状态诊断工具
System Status Diagnostic Tool for Kali MCP

快速检测当前配置模式、系统健康状态，以及 harness 任务工作区摘要
（图规模、阶段、verified 数、日志路径）。
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Windows 控制台常见 GBK：强制 stdout/stderr 尽量用 UTF-8，失败则回退替换
def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


_configure_stdio()


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


# 纯 ASCII 符号，避免 GBK 控制台崩溃
_OK = "[OK]"
_BAD = "[X]"
_INFO = "[i]"
_WARN = "[!]"


def check_file_config() -> Dict[str, Any]:
    """检查 mcp_server.py 的配置。"""
    try:
        with open("mcp_server.py", "r", encoding="utf-8") as f:
            content = f.read()

        optimization_match = re.search(r"OPTIMIZATION_ENABLED\s*=\s*(True|False)", content)
        optimization_enabled = (
            optimization_match.group(1) == "True" if optimization_match else None
        )

        local_mode_found = (
            "LocalCommandExecutor" in content
            or "本地执行模式" in content
            or "LOCAL EXECUTION MODE" in content
        )

        return {
            "file_exists": True,
            "optimization_enabled": optimization_enabled,
            "local_mode_found": local_mode_found,
            "mode": "local" if local_mode_found else "unknown",
        }
    except FileNotFoundError:
        return {
            "file_exists": False,
            "optimization_enabled": None,
            "local_mode_found": False,
            "mode": "unknown",
        }


def check_env_variables() -> Dict[str, str]:
    """检查环境变量配置（含 harness 关键项）。"""
    return {
        "KALI_API_URL": os.environ.get("KALI_API_URL", ""),
        "KALI_MCP_TOOL_PROFILE": os.environ.get("KALI_MCP_TOOL_PROFILE", "harness"),
        "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT": os.environ.get(
            "KALI_MCP_REQUIRE_ENGAGEMENT_CONTEXT", "0"
        ),
        "KALI_MCP_WORKSPACE": os.environ.get("KALI_MCP_WORKSPACE", ""),
        "KALI_MCP_HTTPX_BIN": os.environ.get("KALI_MCP_HTTPX_BIN", ""),
        "CTF_PARALLEL_ATTACKS": os.environ.get("CTF_PARALLEL_ATTACKS", ""),
        "CTF_LEARNING_MODE": os.environ.get("CTF_LEARNING_MODE", ""),
        "API_PORT": os.environ.get("API_PORT", ""),
    }


def _process_running(pattern: str) -> bool:
    """跨平台粗检进程是否存在（仅匹配 python* 命令行中的脚本名）。"""
    system = platform.system().lower()
    try:
        if system == "windows":
            # 避免把编辑器/资源管理器路径误判为服务进程
            script = pattern.replace("'", "").replace('"', "")
            ps = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
                        "Where-Object { "
                        "  $_.Name -match 'python|py.exe' -and "
                        f"  $_.CommandLine -and ($_.CommandLine -like '*{script}*') "
                        "}; "
                        "if ($procs) { ($procs | Select-Object -First 1).ProcessId } "
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            out = (ps.stdout or "").strip()
            return bool(out and out.isdigit())
        result = subprocess.run(
            ["pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def check_process_status() -> Dict[str, Any]:
    """检查相关进程状态。"""
    try:
        return {
            "mcp_server": _process_running("mcp_server.py"),
            "kali_server": _process_running("kali_server.py"),
        }
    except Exception as e:
        return {
            "mcp_server": False,
            "kali_server": False,
            "error": str(e),
        }


def check_security_tools() -> List[Tuple[str, bool]]:
    """检查关键安全工具是否可用（which / where / PATH）。"""
    critical_tools = [
        "nmap",
        "gobuster",
        "sqlmap",
        "nikto",
        "nuclei",
        "httpx",
        "masscan",
        "ffuf",
        "feroxbuster",
        "whatweb",
        "wpscan",
        "hydra",
        "john",
        "curl",
    ]

    results: List[Tuple[str, bool]] = []
    for tool in critical_tools:
        available = shutil.which(tool) is not None
        if not available and tool == "httpx":
            httpx_bin = os.environ.get("KALI_MCP_HTTPX_BIN", "").strip()
            if httpx_bin and Path(httpx_bin).is_file():
                available = True
        results.append((tool, available))
    return results


# (tool, argv for version probe, optional env path override key)
_TOOL_VERSION_SPECS: List[Tuple[str, List[str], str]] = [
    ("nmap", ["nmap", "--version"], ""),
    ("nuclei", ["nuclei", "-version"], ""),
    ("httpx", ["httpx", "-version"], "KALI_MCP_HTTPX_BIN"),
    ("sqlmap", ["sqlmap", "--version"], ""),
    ("ffuf", ["ffuf", "-V"], ""),
    ("feroxbuster", ["feroxbuster", "-V"], ""),
    ("gobuster", ["gobuster", "version"], ""),
    ("nikto", ["nikto", "-Version"], ""),
    ("whatweb", ["whatweb", "--version"], ""),
    ("curl", ["curl", "--version"], ""),
]


def _resolve_tool_path(tool: str, env_key: str = "") -> str:
    if env_key:
        override = (os.environ.get(env_key) or "").strip()
        if override and Path(override).is_file():
            return override
    found = shutil.which(tool)
    return found or ""


def _clean_version_line(raw: str, tool: str) -> str:
    text = (raw or "").replace("\r", "\n")
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    if not lines:
        return ""
    # Prefer a line that looks like a version string
    for ln in lines[:8]:
        low = ln.lower()
        if any(k in low for k in ("version", "v3.", "v2.", "nmap ", "ffuf ", "ferox", "sqlmap", "nikto", "whatweb", "curl ")):
            # strip ANSI
            ln = re.sub(r"\x1b\[[0-9;]*m", "", ln)
            return ln[:160]
    first = re.sub(r"\x1b\[[0-9;]*m", "", lines[0])
    # httpx -version often prints banner first; keep first non-empty short line
    if tool == "httpx" and len(first) < 8 and len(lines) > 1:
        for ln in lines[1:6]:
            ln2 = re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
            if ln2 and not ln2.startswith("/"):
                return ln2[:160]
    return first[:160]


def probe_tool_versions(timeout: float = 4.0) -> List[Dict[str, Any]]:
    """Probe harness-critical tools: path + version string (best-effort, non-fatal)."""
    rows: List[Dict[str, Any]] = []
    for tool, argv, env_key in _TOOL_VERSION_SPECS:
        path = _resolve_tool_path(tool, env_key)
        available = bool(path)
        version = ""
        probe_ok = False
        error = ""
        if available:
            run_argv = list(argv)
            # replace binary with resolved path when absolute
            if path and (os.path.isabs(path) or path != tool):
                run_argv[0] = path
            try:
                proc = subprocess.run(
                    run_argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env={**os.environ, "http_proxy": "", "https_proxy": "", "HTTP_PROXY": "", "HTTPS_PROXY": ""},
                )
                blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
                version = _clean_version_line(blob, tool)
                # gobuster "version" subcommand may fail on some builds — still report path
                probe_ok = bool(version) or proc.returncode == 0
                if not version and proc.returncode != 0:
                    error = (proc.stderr or proc.stdout or "")[:120]
            except Exception as e:
                error = str(e)[:120]
                probe_ok = False
        rows.append(
            {
                "tool": tool,
                "available": available,
                "path": path,
                "version": version,
                "probe_ok": probe_ok,
                "error": error,
            }
        )
    return rows


def check_os_info() -> Dict[str, Any]:
    """检查操作系统信息（Linux 读 os-release，Windows 回退 platform）。"""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            content = f.read()

        name_match = re.search(r'PRETTY_NAME="([^"]+)"', content)
        version_match = re.search(r'VERSION="([^"]+)"', content)

        return {
            "name": name_match.group(1) if name_match else "Unknown",
            "version": version_match.group(1) if version_match else "Unknown",
            "is_kali": "kali" in content.lower(),
            "platform": platform.system(),
        }
    except Exception:
        return {
            "name": f"{platform.system()} {platform.release()}",
            "version": platform.version(),
            "is_kali": False,
            "platform": platform.system(),
        }


def _safe_json_load(path: Path) -> Any:
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _count_jsonl_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        n = 0
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    n += 1
        return n
    except Exception:
        return 0


def summarize_task_dir(task_dir: Path) -> Dict[str, Any]:
    """汇总单个 harness 任务目录：图规模、阶段、verified、日志路径。"""
    task_id = task_dir.name
    meta = _safe_json_load(task_dir / "task.json") or {}
    graph = _safe_json_load(task_dir / "graph" / "graph.json") or {}
    findings_blob = _safe_json_load(task_dir / "findings" / "findings.json")
    findings: List[Dict[str, Any]] = []
    if isinstance(findings_blob, dict) and isinstance(findings_blob.get("findings"), list):
        findings = findings_blob["findings"]
    elif isinstance(findings_blob, list):
        findings = findings_blob

    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    edges = graph.get("edges") if isinstance(graph, dict) else None
    node_count = len(nodes) if isinstance(nodes, list) else int(graph.get("node_count") or 0) if isinstance(graph, dict) else 0
    edge_count = len(edges) if isinstance(edges, list) else int(graph.get("edge_count") or 0) if isinstance(graph, dict) else 0
    if isinstance(nodes, dict):
        node_count = len(nodes)
    if isinstance(edges, dict):
        edge_count = len(edges)

    verified = sum(1 for f in findings if isinstance(f, dict) and f.get("status") == "verified")
    candidates = sum(1 for f in findings if isinstance(f, dict) and f.get("status") == "candidate")
    actions_path = task_dir / "logs" / "actions.jsonl"
    handoff_path = task_dir / "handoff" / "handoff.json"
    report_md = task_dir / "report" / "report.md"
    actions_count = _count_jsonl_lines(actions_path)
    duration_ms_sum = 0.0
    duration_ms_known_count = 0
    if actions_path.is_file():
        try:
            with actions_path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    d = row.get("duration_ms") if isinstance(row, dict) else None
                    if isinstance(d, (int, float)):
                        duration_ms_sum += float(d)
                        duration_ms_known_count += 1
        except Exception:
            pass
    duration_ms_sum = round(duration_ms_sum, 3)

    return {
        "task_id": task_id,
        "phase": meta.get("phase") or "unknown",
        "status": meta.get("status") or "unknown",
        "targets": meta.get("targets") or [],
        "depth": meta.get("depth") or "",
        "nodes": node_count,
        "edges": edge_count,
        "findings_total": len(findings),
        "verified": verified,
        "candidates": candidates,
        "actions_log": str(actions_path) if actions_path.exists() else "",
        "actions_count": actions_count,
        "duration_ms_sum": duration_ms_sum,
        "duration_ms_known_count": duration_ms_known_count,
        "handoff": str(handoff_path) if handoff_path.exists() else "",
        "report_md": str(report_md) if report_md.exists() else "",
        "root": str(task_dir),
    }


def collect_workspace_summaries(limit: int = 20) -> Dict[str, Any]:
    """扫描 workspace/tasks 下任务摘要。"""
    # 优先环境变量；否则相对当前工作目录 / 脚本旁仓库
    env_ws = os.environ.get("KALI_MCP_WORKSPACE", "").strip()
    if env_ws:
        root = Path(env_ws).expanduser().resolve()
    else:
        # status_check.py 在仓库根
        root = Path(__file__).resolve().parent / "workspace"
    tasks_dir = root / "tasks"
    if not tasks_dir.is_dir():
        return {
            "workspace_root": str(root),
            "tasks_dir": str(tasks_dir),
            "task_count": 0,
            "tasks": [],
            "error": "tasks directory not found",
        }

    dirs = sorted([p for p in tasks_dir.iterdir() if p.is_dir()], key=lambda p: p.name)
    # 最近修改优先展示
    dirs_sorted = sorted(dirs, key=lambda p: p.stat().st_mtime, reverse=True)
    selected = dirs_sorted[: max(1, limit)] if dirs_sorted else []
    summaries = [summarize_task_dir(p) for p in selected]
    return {
        "workspace_root": str(root),
        "tasks_dir": str(tasks_dir),
        "task_count": len(dirs),
        "shown": len(summaries),
        "tasks": summaries,
    }


def print_banner() -> None:
    banner = f"""
{Colors.BOLD}{Colors.BLUE}+===============================================================+
|          Kali MCP System Status Diagnostic Tool               |
|          (harness workspace + local executor)                 |
+===============================================================+{Colors.END}
"""
    print(banner)


def print_section(title: str) -> None:
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'-' * 60}")
    print(f"  {title}")
    print(f"{'-' * 60}{Colors.END}\n")


def print_status(label: str, value: Any, is_good: Optional[bool] = None) -> None:
    if is_good is None:
        color = Colors.BLUE
        symbol = _INFO
    elif is_good:
        color = Colors.GREEN
        symbol = _OK
    else:
        color = Colors.RED
        symbol = _BAD

    # 值侧避免异常控制字符
    text = str(value).replace("\r", " ").replace("\n", " ")
    try:
        print(f"{symbol} {label:.<40} {color}{text}{Colors.END}")
    except UnicodeEncodeError:
        safe = text.encode("ascii", errors="replace").decode("ascii")
        print(f"{symbol} {label:.<40} {safe}")


def main() -> int:
    print_banner()

    # 1. OS
    print_section("1. Operating System")
    os_info = check_os_info()
    print_status("OS", os_info["name"], os_info["is_kali"] or os_info.get("platform") == "Windows")
    print_status("Version", os_info["version"], True)
    print_status("Platform", os_info.get("platform") or platform.system(), True)
    if not os_info["is_kali"]:
        print(f"\n{Colors.YELLOW}{_WARN} Not Kali Linux (dev host is OK for harness unit tests){Colors.END}")

    # 2. Config
    print_section("2. Config Mode")
    config = check_file_config()
    if not config["file_exists"]:
        print_status("mcp_server.py", "missing", False)
        return 1

    mode_name = {
        "local": "LOCAL (subprocess executor)",
        "remote": "REMOTE",
        "unknown": "UNKNOWN",
    }
    print_status("Mode", mode_name.get(config["mode"], "UNKNOWN"), config["mode"] == "local")
    print_status(
        "OPTIMIZATION_ENABLED",
        config["optimization_enabled"],
        config["optimization_enabled"] is not None,
    )
    if config["mode"] == "local":
        print(f"\n{Colors.GREEN}{_OK} Local executor mode: no kali_server.py required{Colors.END}")

    # 3. Env
    print_section("3. Environment")
    env_vars = check_env_variables()
    for key, value in env_vars.items():
        if value:
            print_status(key, value, True)
        else:
            # 本地模式可不设 KALI_API_URL；engagement 默认 0 也合理
            is_ok = key in (
                "KALI_API_URL",
                "CTF_PARALLEL_ATTACKS",
                "CTF_LEARNING_MODE",
                "API_PORT",
                "KALI_MCP_HTTPX_BIN",
                "KALI_MCP_WORKSPACE",
            )
            print_status(key, "(unset)", is_ok)

    # 4. Processes
    print_section("4. Processes")
    processes = check_process_status()
    print_status(
        "mcp_server.py",
        "running" if processes.get("mcp_server") else "stopped",
        bool(processes.get("mcp_server")),
    )
    print_status(
        "kali_server.py",
        "running" if processes.get("kali_server") else "stopped",
        config["mode"] == "local" or bool(processes.get("kali_server")),
    )

    # 5. Tools
    print_section("5. Security Tools (PATH + version probe)")
    tools = check_security_tools()
    available_count = sum(1 for _, available in tools if available)
    total_count = len(tools)
    for tool, available in tools:
        print_status(tool, "available" if available else "missing", available)
    print(f"\n{Colors.BOLD}Tools available: {available_count}/{total_count}{Colors.END}")
    print(f"\n{Colors.BOLD}Version inventory (measured on this host only):{Colors.END}")
    for row in probe_tool_versions():
        if not row.get("available"):
            print_status(str(row.get("tool")), "missing", False)
            continue
        ver = (row.get("version") or "").strip() or "(no version string)"
        mark = bool(row.get("probe_ok")) or bool(ver and ver != "(no version string)")
        detail = f"{ver} | path={row.get('path') or ''}"
        if row.get("error") and not row.get("version"):
            detail = f"{detail} | err={row.get('error')}"
        print_status(str(row.get("tool")), detail, mark)
    print(
        f"\n{_INFO} Recipe YAML is command template layer; binary age is this inventory, "
        f"not tools_recipes mtime."
    )

    # 6. Harness workspace (Phase4)
    print_section("6. Harness Workspace (graph / phase / verified / logs)")
    ws_summary = collect_workspace_summaries(limit=15)
    print_status("workspace_root", ws_summary.get("workspace_root"), True)
    print_status("tasks_dir", ws_summary.get("tasks_dir"), True)
    print_status("task_count", ws_summary.get("task_count", 0), True)
    if ws_summary.get("error"):
        print_status("scan", ws_summary["error"], False)
    else:
        for t in ws_summary.get("tasks") or []:
            line = (
                f"phase={t.get('phase')} status={t.get('status')} "
                f"nodes={t.get('nodes')} edges={t.get('edges')} "
                f"verified={t.get('verified')}/{t.get('findings_total')} "
                f"actions={t.get('actions_count')} "
                f"duration_ms_sum={t.get('duration_ms_sum')} "
                f"duration_known={t.get('duration_ms_known_count')}"
            )
            print_status(str(t.get("task_id")), line, int(t.get("verified") or 0) > 0 or t.get("status") == "open")
            if t.get("actions_log"):
                print(f"      log: {t['actions_log']}")
            if t.get("report_md"):
                print(f"      report: {t['report_md']}")
            if t.get("handoff"):
                print(f"      handoff: {t['handoff']}")

    # 7. Summary
    print_section("7. Summary")
    # 开发机（非 Kali）不因 is_kali 判失败；以配置与文件为主
    base_ok = config["file_exists"] and config["mode"] == "local"
    if base_ok:
        print(f"{Colors.GREEN}{Colors.BOLD}")
        print("+---------------------------------------------------------------+")
        print("|  [OK] Core config looks usable (local executor)               |")
        print("|  Check section 6 for task graph / verified / log paths        |")
        print("+---------------------------------------------------------------+")
        print(Colors.END)
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}")
        print("+---------------------------------------------------------------+")
        print("|  [!] Config needs attention                                   |")
        print("+---------------------------------------------------------------+")
        print(Colors.END)

    if not processes.get("mcp_server"):
        print(f"{Colors.YELLOW}{_INFO} MCP not running: python mcp_server.py --tool-profile harness{Colors.END}")
    if not os_info["is_kali"] and available_count < total_count * 0.5:
        print(f"{Colors.YELLOW}{_INFO} Dev host: many Kali tools missing (expected on Windows){Colors.END}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
