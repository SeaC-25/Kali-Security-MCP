#!/usr/bin/env python3
"""Insight branch: produce Hypothesis candidates only (never drive executor).

v2: cross-domain hypotheses fed by autonomous_engine knowledge graph.
drive_executor is ALWAYS False — candidates must go through verify_finding.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from kali_mcp.core.action_log import log_action, read_actions
from kali_mcp.core.findings_store import list_findings, upsert_finding
from kali_mcp.core.target_graph import get_graph
from kali_mcp.core.task_workspace import get_workspace, utc_now_iso

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _normalize_engine_cross_domain_map(raw: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
    """Normalize autonomous_engine keys (to_command_injection → command_injection)."""
    out: Dict[str, Dict[str, List[str]]] = {}
    if not isinstance(raw, dict):
        return out
    for src, targets in raw.items():
        if not isinstance(targets, dict):
            continue
        src_key = str(src).strip()
        bucket: Dict[str, List[str]] = {}
        for dst, techniques in targets.items():
            dst_key = str(dst).strip()
            if dst_key.startswith("to_"):
                dst_key = dst_key[3:]
            if not dst_key:
                continue
            if isinstance(techniques, list):
                lines = [str(t) for t in techniques if str(t).strip()]
            elif techniques:
                lines = [str(techniques)]
            else:
                lines = []
            if lines:
                bucket[dst_key] = lines
        if bucket:
            out[src_key] = bucket
    return out


def get_cross_domain_map() -> Dict[str, Dict[str, List[str]]]:
    """Prefer autonomous_engine.cross_domain_mappings; fall back to inline map.

    Read-only. Never constructs an executor or runs tools.
    """
    try:
        from kali_mcp.reasoning.autonomous_engine import AutonomousReasoningEngine

        engine = AutonomousReasoningEngine()
        normalized = _normalize_engine_cross_domain_map(
            getattr(engine, "cross_domain_mappings", None) or {}
        )
        if normalized:
            return normalized
    except Exception:
        pass
    return {k: dict(v) for k, v in _CROSS_DOMAIN_MAP.items()}


def engine_cross_domain_map_available() -> bool:
    try:
        from kali_mcp.reasoning.autonomous_engine import AutonomousReasoningEngine

        engine = AutonomousReasoningEngine()
        normalized = _normalize_engine_cross_domain_map(
            getattr(engine, "cross_domain_mappings", None) or {}
        )
        return bool(normalized)
    except Exception:
        return False


def insight_config() -> Dict[str, Any]:
    return {
        "enabled": _env_bool("KALI_MCP_INSIGHT_ENABLED", True),
        # hard rule: never true in this bridge
        "drive_executor": False,
        "max_per_phase": _env_int("KALI_MCP_INSIGHT_MAX_PER_PHASE", 5),
        "only_when_stuck": _env_bool("KALI_MCP_INSIGHT_ONLY_WHEN_STUCK", True),
        "cross_domain_enabled": _env_bool("KALI_MCP_INSIGHT_CROSS_DOMAIN", True),
        "engine_map_loaded": engine_cross_domain_map_available(),
    }


# ---------------------------------------------------------------------------
# Stuck / dead helpers
# ---------------------------------------------------------------------------

def _is_stuck(task_id: str, graph) -> bool:
    actions = graph.next_actions(limit=20, include_insights=False)
    if not actions:
        return True
    recent = read_actions(task_id, limit=30)
    fails = 0
    for a in recent:
        if a.get("tool") in ("verify_finding", "observer_analyze"):
            continue
        if a.get("exit") not in (0, "0", None, ""):
            fails += 1
    return fails >= 5


def _dead_values(graph) -> Set[str]:
    out: Set[str] = set()
    for n in graph.nodes.values():
        if n.dead_reason:
            out.add((n.value or "").strip().lower())
    return out


def _existing_hypothesis_keys(task_id: str) -> Set[str]:
    keys: Set[str] = set()
    for f in list_findings(task_id):
        if f.get("source") != "insight":
            continue
        keys.add(f"{f.get('title')}|{f.get('target')}")
    return keys


# ---------------------------------------------------------------------------
# Cross-domain knowledge from autonomous_engine (read-only, no executor)
# ---------------------------------------------------------------------------

# Inline the cross_domain_mappings so insight_bridge has no hard dep on
# autonomous_engine at import time (avoids random import, keeps deterministic).
_CROSS_DOMAIN_MAP: Dict[str, Dict[str, List[str]]] = {
    "sql_injection": {
        "command_injection": [
            "xp_cmdshell / sys_exec RCE via SQL injection",
            "写入 WebShell 路径后执行命令 (INTO DUMPFILE)",
            "UDF 自定义函数执行系统命令",
        ],
        "file_inclusion": [
            "LOAD_FILE() 读取服务器本地文件",
            "INTO DUMPFILE 写入文件触发 LFI",
            "Oracle UTL_FILE 读写文件路径",
        ],
        "ssrf": [
            "MySQL LOAD_FILE 触发内网 SSRF 探测",
            "PostgreSQL COPY TO/FROM 外带内网数据",
        ],
    },
    "command_injection": {
        "file_inclusion": [
            "cat/tail 读取配置文件或敏感路径",
            "find 搜索 .env / config 目录",
            "grep 提取配置文件中的数据库凭据",
        ],
        "privilege_escalation": [
            "SUID 二进制提权路径",
            "Cron job 写权限导致提权",
            "PATH 变量劫持提权",
        ],
        "sql_injection": [
            "CLI 连接本地数据库获取数据",
            "mysqldump / pg_dump 直接导出",
        ],
    },
    "file_inclusion": {
        "command_injection": [
            "LFI 读取 SSH 私钥后横向",
            "LFI 包含带 PHP 代码的日志文件",
            "LFI 包含 uploads/ 下图片马",
            "PHP filter/expect 伪协议执行命令",
        ],
        "file_upload": [
            "LFI 定位已上传 WebShell 路径",
            "LFI 包含已上传图片马触发解析",
        ],
        "sql_injection": [
            "LFI 读取数据库连接配置",
            "LFI 读取 WordPress wp-config.php 获取凭据",
        ],
    },
    "xss": {
        "command_injection": [
            "XSS 窃取 admin Cookie 后台上传 WebShell",
            "CSRF+XSS 自动上传脚本",
        ],
        "ssrf": [
            "XSS JavaScript 发起绕过 SSRF 防护请求",
        ],
    },
    "ssrf": {
        "file_inclusion": [
            "file:// 协议读取本地文件",
            "SSRF 扫描内网 169.254.x / 10.x 服务",
        ],
        "command_injection": [
            "SSRF → Redis SLAVEOF 写 crontab",
            "SSRF → FastCGI 9000 执行任意 PHP",
            "SSRF → 内网未鉴权 RCE 端点",
        ],
    },
}

# Map finding title keywords / tech stack to a vuln type key
_VULN_KEYWORD_MAP: Dict[str, str] = {
    "sql": "sql_injection",
    "sqli": "sql_injection",
    "injection": "sql_injection",
    "sqlmap": "sql_injection",
    "union": "sql_injection",
    "cmd": "command_injection",
    "rce": "command_injection",
    "command": "command_injection",
    "exec": "command_injection",
    "lfi": "file_inclusion",
    "rfi": "file_inclusion",
    "include": "file_inclusion",
    "traverse": "file_inclusion",
    "path": "file_inclusion",
    "xss": "xss",
    "cross-site": "xss",
    "script": "xss",
    "ssrf": "ssrf",
    "redirect": "ssrf",
    "open redirect": "ssrf",
    "request forgery": "ssrf",
    "upload": "file_upload",
    "webshell": "file_upload",
    "shell": "command_injection",
}

# Target-type patterns for cross-domain probes (reproduce_cmd templates)
_CROSS_DOMAIN_PROBE_CMD: Dict[str, str] = {
    "command_injection": 'curl -sk "{base}/cmd?cmd=id&exec=id&command=id"',
    "file_inclusion": 'curl -sk "{base}/?page=/etc/passwd&file=/etc/passwd&include=/etc/passwd"',
    "sql_injection": 'curl -sk "{base}/?id=1%27--+&id=1+AND+1=1--+"',
    "ssrf": 'curl -sk "{base}/?url=http://127.0.0.1/&target=http://127.0.0.1/&path=http://127.0.0.1/"',
    "xss": 'curl -sk "{base}/?q=%3Cscript%3Ealert(1)%3C/script%3E&search=<script>alert(1)</script>"',
    "file_upload": 'curl -sk -o /dev/null -w "%{{http_code}}" "{base}/upload"',
    "privilege_escalation": 'curl -sk "{base}/api/admin&role=admin&privilege=1"',
}

_CROSS_DOMAIN_SIGNAL: Dict[str, str] = {
    "command_injection": "re:(?i)(uid=|root:|www-data|apache)",
    "file_inclusion": "re:(?i)(root:x:|/bin/bash|passwd)",
    "sql_injection": "re:(?i)(mysql|syntax|error|ORA-)",
    "ssrf": "re:(?i)(127\\.0\\.0\\.1|localhost|internal|connection refused)",
    "xss": "re:(?i)(alert|<script|XSS)",
    "file_upload": "200",
    "privilege_escalation": "re:(?i)(admin|root|privilege)",
}

_CROSS_DOMAIN_TECHNIQUE: Dict[str, str] = {
    "command_injection": "T1059",
    "file_inclusion": "T1083",
    "sql_injection": "T1190",
    "ssrf": "T1090",
    "xss": "T1059",
    "file_upload": "T1190",
    "privilege_escalation": "T1068",
}


def _infer_vuln_type(node) -> Optional[str]:
    """Guess vuln category from a finding/tech/path graph node's metadata."""
    title = str(
        (node.meta or {}).get("title") or
        node.value or ""
    ).lower()
    status = str((node.meta or {}).get("status") or "").lower()
    service = str((node.meta or {}).get("service") or "").lower()
    combined = f"{title} {service}"
    for keyword, vuln_type in _VULN_KEYWORD_MAP.items():
        if keyword in combined:
            return vuln_type
    return None


def _base_url_from_graph(graph) -> Optional[str]:
    """Pick the most-confident URL/host for anchoring cross-domain probes."""
    best = None
    best_conf = 0.0
    for n in graph.nodes.values():
        if n.dead_reason:
            continue
        if n.type in ("url",) and float(n.confidence or 0) > best_conf:
            best = n.value
            best_conf = float(n.confidence or 0)
    if not best:
        for n in graph.nodes.values():
            if n.dead_reason:
                continue
            if n.type == "host" and float(n.confidence or 0) > best_conf:
                best = f"http://{n.value}/"
                best_conf = float(n.confidence or 0)
    return best


def _cross_domain_hypotheses(task_id: str, graph) -> List[Dict[str, Any]]:
    """Generate cross-domain hypotheses from verified/candidate findings.

    Prefers autonomous_engine mapping via get_cross_domain_map(); inline map is fallback.
    Only produces hypotheses when a concrete base URL exists and the
    source vuln type is known. Never binds executor.
    """
    cmap = get_cross_domain_map()
    if not cmap:
        return []
    map_source = "autonomous_engine" if engine_cross_domain_map_available() else "fallback_inline"
    base_url = _base_url_from_graph(graph)
    if not base_url:
        return []
    base = base_url.rstrip("/")
    hyps: List[Dict[str, Any]] = []
    seen_target_types: Set[str] = set()

    findings = list_findings(task_id)
    for f in findings:
        if f.get("status") not in ("verified", "candidate"):
            continue
        if f.get("source") == "insight":
            continue
        title = str(f.get("title") or "").lower()
        src_vuln: Optional[str] = None
        for kw, vt in _VULN_KEYWORD_MAP.items():
            if kw in title:
                src_vuln = vt
                break
        if not src_vuln:
            continue
        targets = cmap.get(src_vuln) or {}
        for dst_vuln, reasoning_list in targets.items():
            if dst_vuln in seen_target_types:
                continue
            reasoning = reasoning_list[0] if reasoning_list else dst_vuln
            probe_cmd_tpl = _CROSS_DOMAIN_PROBE_CMD.get(dst_vuln, "")
            if not probe_cmd_tpl:
                continue
            cmd = probe_cmd_tpl.format(base=base)
            signal = _CROSS_DOMAIN_SIGNAL.get(dst_vuln, "re:(?i)(200)")
            technique = _CROSS_DOMAIN_TECHNIQUE.get(dst_vuln, "T1190")
            hyps.append(
                {
                    "title": f"insight_xdomain_{src_vuln}_to_{dst_vuln}:{base}",
                    "target": base + "/",
                    "severity": "medium",
                    "reproduce_cmd": cmd,
                    "expected_signal": signal,
                    "technique_ids": [technique],
                    "reasoning": f"cross-domain: {src_vuln} finding suggests {dst_vuln} probe — {reasoning}",
                    "_source_finding_id": str(f.get("finding_id") or ""),
                    "_src_vuln": src_vuln,
                    "_dst_vuln": dst_vuln,
                    "_mapping_source": map_source,
                }
            )
            seen_target_types.add(dst_vuln)
    return hyps


# ---------------------------------------------------------------------------
# Core hypothesis builder
# ---------------------------------------------------------------------------

def _build_hypotheses_for_node(node) -> List[Dict[str, Any]]:
    """Rule + cross-domain hypotheses bound to a concrete graph node."""
    hyps: List[Dict[str, Any]] = []
    ntype = (node.type or "").lower()
    value = (node.value or "").strip()
    if not value:
        return hyps
    if node.dead_reason:
        return hyps

    if ntype == "url":
        base = value.rstrip("/")
        # base paths
        hyps.append(
            {
                "title": f"insight_auth_surface:{base}/login",
                "target": f"{base}/login",
                "severity": "info",
                "reproduce_cmd": f'curl -sk -o /dev/null -w "%{{http_code}}" "{base}/login"',
                "expected_signal": "200",
                "technique_ids": ["T1078"],
                "reasoning": "URL node present; check login entry as candidate auth surface",
            }
        )
        hyps.append(
            {
                "title": f"insight_api_health:{base}/api/health",
                "target": f"{base}/api/health",
                "severity": "info",
                "reproduce_cmd": f'curl -sk "{base}/api/health"',
                "expected_signal": "ok",
                "technique_ids": ["T1595"],
                "reasoning": "URL node present; probe common health API path",
            }
        )
        hyps.append(
            {
                "title": f"insight_admin_path:{base}/admin",
                "target": f"{base}/admin",
                "severity": "low",
                "reproduce_cmd": f'curl -sk -o /dev/null -w "%{{http_code}}" "{base}/admin"',
                "expected_signal": "200",
                "technique_ids": ["T1190"],
                "reasoning": "URL node present; probe admin path exposure",
            }
        )
        # robots.txt hint
        hyps.append(
            {
                "title": f"insight_robots:{base}/robots.txt",
                "target": f"{base}/robots.txt",
                "severity": "info",
                "reproduce_cmd": f'curl -sk "{base}/robots.txt"',
                "expected_signal": "re:(?i)(disallow|allow|user-agent)",
                "technique_ids": ["T1595"],
                "reasoning": "robots.txt may reveal hidden paths",
            }
        )
        # .git leakage
        hyps.append(
            {
                "title": f"insight_git_leak:{base}/.git/HEAD",
                "target": f"{base}/.git/HEAD",
                "severity": "high",
                "reproduce_cmd": f'curl -sk "{base}/.git/HEAD"',
                "expected_signal": "re:(?i)(ref:|repository)",
                "technique_ids": ["T1083"],
                "reasoning": "Exposed .git directory leaks source code",
            }
        )
        # env file
        hyps.append(
            {
                "title": f"insight_env_file:{base}/.env",
                "target": f"{base}/.env",
                "severity": "high",
                "reproduce_cmd": f'curl -sk "{base}/.env"',
                "expected_signal": "re:(?i)(APP_KEY|DB_PASSWORD|SECRET|TOKEN)",
                "technique_ids": ["T1552"],
                "reasoning": ".env file exposure often leaks credentials",
            }
        )
    elif ntype == "host":
        hyps.append(
            {
                "title": f"insight_http_probe:http://{value}/",
                "target": f"http://{value}/",
                "severity": "info",
                "reproduce_cmd": f'curl -sk -o /dev/null -w "%{{http_code}}" "http://{value}/"',
                "expected_signal": "200",
                "technique_ids": ["T1595"],
                "reasoning": "Host node without URL checks; seed HTTP probe hypothesis",
            }
        )
        hyps.append(
            {
                "title": f"insight_https_probe:https://{value}/",
                "target": f"https://{value}/",
                "severity": "info",
                "reproduce_cmd": f'curl -sk -o /dev/null -w "%{{http_code}}" "https://{value}/"',
                "expected_signal": "200",
                "technique_ids": ["T1595"],
                "reasoning": "Host node; also probe HTTPS port",
            }
        )
    elif ntype == "port":
        port = value.split(":")[-1] if ":" in value else value
        host = value.split(":")[0] if ":" in value else value
        hyps.append(
            {
                "title": f"insight_service_banner:{value}",
                "target": value,
                "severity": "info",
                "reproduce_cmd": f"nmap -sV -Pn -p {port} {host}",
                "expected_signal": "open",
                "technique_ids": ["T1046"],
                "reasoning": "Port node present; service fingerprint candidate",
            }
        )
    elif ntype == "tech":
        # tech-specific probes: e.g. nginx, apache, php
        vl = value.lower()
        if "php" in vl:
            hyps.append(
                {
                    "title": f"insight_phpinfo_exposure:phpinfo:{value}",
                    "target": "__tech_bound__",
                    "severity": "medium",
                    "reproduce_cmd": 'curl -sk "{base}/phpinfo.php"',
                    "expected_signal": "re:(?i)(phpinfo|PHP Version)",
                    "technique_ids": ["T1082"],
                    "reasoning": "PHP tech stack detected; phpinfo.php exposure check",
                    "_needs_base": True,
                }
            )
        if any(k in vl for k in ("wordpress", "wp-")):
            hyps.append(
                {
                    "title": f"insight_wp_login:wp-login:{value}",
                    "target": "__tech_bound__",
                    "severity": "medium",
                    "reproduce_cmd": 'curl -sk -o /dev/null -w "%{{http_code}}" "{base}/wp-login.php"',
                    "expected_signal": "200",
                    "technique_ids": ["T1078"],
                    "reasoning": "WordPress detected; wp-login.php brute-force surface",
                    "_needs_base": True,
                }
            )
    return hyps


def propose_insights(
    task_id: str,
    *,
    phase: Optional[str] = None,
    force: bool = False,
    max_per_phase: Optional[int] = None,
    enqueue_verify: bool = False,
) -> Dict[str, Any]:
    """Generate structured hypotheses → candidate findings (source=insight).

    Never calls LocalCommandExecutor. Candidates must go through verify_finding.
    enqueue_verify: if True, also sticky insight_verify labels onto bound nodes
    (default False so chain_done / terminal tasks stay clean; explicit MCP can opt in).
    """
    import time

    t0 = time.perf_counter()
    cfg = insight_config()
    if not cfg["enabled"] and not force:
        return {"ok": True, "skipped": True, "reason": "insight.disabled", "hypotheses": []}
    if cfg.get("drive_executor"):
        # belt-and-suspenders: this bridge never executes
        cfg["drive_executor"] = False

    ws = get_workspace(task_id, create=True)
    graph = get_graph(ws.task_id, reload=True)
    meta = ws.read_meta()
    phase = phase or meta.get("phase") or "RECON"

    if cfg["only_when_stuck"] and not force and not _is_stuck(ws.task_id, graph):
        return {
            "ok": True,
            "skipped": True,
            "reason": "not_stuck",
            "phase": phase,
            "hypotheses": [],
            "config": cfg,
        }

    budget = int(max_per_phase if max_per_phase is not None else cfg["max_per_phase"])
    # Reserve at least 1/3 of budget for cross-domain hypotheses so they are never crowded out.
    # node_budget = at most 2/3; min 1 so trivially small budgets still work.
    node_budget = max(1, budget * 2 // 3) if budget >= 3 else budget
    xd_budget = budget - node_budget  # remainder reserved for cross-domain
    dead = _dead_values(graph)
    existing = _existing_hypothesis_keys(ws.task_id)
    created: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []

    # Prefer higher-confidence alive nodes with concrete values
    nodes = sorted(
        [n for n in graph.nodes.values() if not n.dead_reason],
        key=lambda n: float(n.confidence or 0),
        reverse=True,
    )

    for node in nodes:
        if len(created) >= node_budget:
            break
        for hyp in _build_hypotheses_for_node(node):
            if len(created) >= node_budget:
                break
            # Resolve _needs_base tech hypotheses
            if hyp.get("_needs_base"):
                base_url = _base_url_from_graph(graph)
                if not base_url:
                    rejected.append({"reason": "no_base_for_tech_hyp", "title": hyp.get("title")})
                    continue
                base_url = base_url.rstrip("/")
                hyp = dict(hyp)
                hyp["target"] = hyp["target"].replace("__tech_bound__", base_url + "/")
                hyp["reproduce_cmd"] = hyp.get("reproduce_cmd", "").replace("{base}", base_url)
                del hyp["_needs_base"]
            target = (hyp.get("target") or "").strip()
            title = (hyp.get("title") or "").strip()
            if not target or not title:
                rejected.append({"reason": "missing_bind", "hyp": hyp})
                continue
            if target.lower() in dead:
                rejected.append({"reason": "dead_node", "target": target})
                continue
            if not hyp.get("reproduce_cmd") or not hyp.get("expected_signal"):
                rejected.append({"reason": "missing_reproduce", "title": title})
                continue
            key = f"{title}|{target}"
            if key in existing:
                rejected.append({"reason": "duplicate_hypothesis", "title": title})
                continue

            finding = upsert_finding(
                ws.task_id,
                {
                    "title": title,
                    "target": target,
                    "severity": hyp.get("severity") or "info",
                    "status": "candidate",
                    "reproduce_cmd": hyp.get("reproduce_cmd"),
                    "expected_signal": hyp.get("expected_signal"),
                    "source": "insight",
                    "technique_ids": list(hyp.get("technique_ids") or []),
                    "meta": {
                        "bound_node_id": node.id,
                        "bound_node_type": node.type,
                        "bound_node_value": node.value,
                        "reasoning": hyp.get("reasoning"),
                        "phase": phase,
                        "drive_executor": False,
                        "created_via": "propose_insights",
                    },
                },
            )
            # optional sticky queue — off by default (chain finalization must not re-dirty)
            if enqueue_verify:
                try:
                    checks = list(node.next_checks or [])
                    label = f"insight_verify:{finding.get('finding_id')}"
                    if label not in checks:
                        checks.append(label)
                        node.next_checks = checks
                        node.source = node.source or "scan"
                        node.meta = dict(node.meta or {})
                        node.meta.setdefault("insight_checks", []).append(label)
                except Exception:
                    pass

            existing.add(key)
            created.append(finding)

    # Phase2: cross-domain hypotheses from existing findings
    # Use xd_budget reserved above; if cross_domain disabled fall through silently.
    if cfg.get("cross_domain_enabled", True) and xd_budget > 0:
        remaining_budget = budget - len(created)
        try:
            xd_hyps = _cross_domain_hypotheses(ws.task_id, graph)
        except Exception:
            xd_hyps = []
        for hyp in xd_hyps:
            if len(created) >= budget:  # never exceed total
                break
            target = (hyp.get("target") or "").strip()
            title = (hyp.get("title") or "").strip()
            if not target or not title:
                continue
            if target.lower() in dead:
                rejected.append({"reason": "dead_node_xdomain", "target": target})
                continue
            if not hyp.get("reproduce_cmd") or not hyp.get("expected_signal"):
                rejected.append({"reason": "missing_reproduce_xdomain", "title": title})
                continue
            key = f"{title}|{target}"
            if key in existing:
                rejected.append({"reason": "duplicate_xdomain", "title": title})
                continue
            finding = upsert_finding(
                ws.task_id,
                {
                    "title": title,
                    "target": target,
                    "severity": hyp.get("severity") or "medium",
                    "status": "candidate",
                    "reproduce_cmd": hyp.get("reproduce_cmd"),
                    "expected_signal": hyp.get("expected_signal"),
                    "source": "insight",
                    "technique_ids": list(hyp.get("technique_ids") or []),
                    "meta": {
                        "reasoning": hyp.get("reasoning"),
                        "phase": phase,
                        "drive_executor": False,
                        "created_via": "propose_insights_cross_domain",
                        "src_vuln": hyp.get("_src_vuln"),
                        "dst_vuln": hyp.get("_dst_vuln"),
                        "source_finding_id": hyp.get("_source_finding_id"),
                        "mapping_source": hyp.get("_mapping_source") or "fallback_inline",
                    },
                },
            )
            existing.add(key)
            created.append(finding)

    graph.save()
    insight_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    log_action(
        ws.task_id,
        phase=str(phase or "RECON"),
        target="",
        tool="propose_insights",
        args={"budget": budget, "created": len(created), "rejected": len(rejected)},
        exit_code=0,
        duration_ms=insight_ms,
        source="insight",
        finding_ids=[str(f.get("finding_id")) for f in created if f.get("finding_id")],
        extra={
            "rejected_sample": rejected[:10],
            "event": "propose_insights",
            "created_count": len(created),
            "engine_map_loaded": bool(cfg.get("engine_map_loaded")),
        },
    )

    return {
        "ok": True,
        "task_id": ws.task_id,
        "phase": phase,
        "config": cfg,
        "created_count": len(created),
        "rejected_count": len(rejected),
        "hypotheses": created,
        "rejected_sample": rejected[:20],
        "drive_executor": False,
        "enqueue_verify": bool(enqueue_verify),
        "note": "candidates only; call verify_finding before report main table",
        "generated_at": utc_now_iso(),
    }
