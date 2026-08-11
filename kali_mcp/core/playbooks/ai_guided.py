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
        target: target URL (e.g. http://host/api/orders)
        depth: quick | standard | thorough
        kwargs:
            params: override param candidate list
            headers: auth headers (k:v;k:v)
            seq_file: optional login sequence YAML
    """
    params = kwargs.get("params") or DEFAULT_PARAMS
    headers = kwargs.get("headers", "")
    seq_file = kwargs.get("seq_file", "")
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
            return _summary(stages, findings, tmpdir)

        # Stage 2: priority inside diff_data; surface top-N for AI decision
        prio = diff_data.get("priority", [])
        top_params = [p.get("param") for p in prio[:3]]  # AI 决策点：取 top3
        _stage("prioritize", True, f"Top 参数: {top_params}")

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
                paths = "\n".join(
                    f'      - "{{{{BaseURL}}}}{base_path}?{pname}={v}"'
                    for v in ("2", "0", "-1", "999999")
                )
                tpl = (
                    f"id: diff-{pname}\n\n"
                    f"info:\n  name: Behavioral diff probe for {pname}\n"
                    f"  author: fastsec-ai\n  severity: {sev}\n\n"
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

        # Stage 5: stateful sequence validation (if provided)
        if seq_file and os.path.exists(seq_file):
            seq_json = tmpdir / "seq.json"
            s = subprocess.run(
                [FASTSEC_BIN, "-u", str(target), "-seq", seq_file,
                 "-delay-min", "100", "-delay-max", "300", "-json", str(seq_json)],
                capture_output=True, text=True, timeout=300,
            )
            seq_data = []
            if seq_json.exists():
                try:
                    seq_data = json.loads(seq_json.read_text())
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
            _stage("seq_validate", True, f"状态化序列执行 {len(seq_data)} 步")

    except Exception as e:
        _stage("error", False, str(e))

    return _summary(stages, findings, tmpdir)


def _summary(stages: List[Dict[str, Any]], findings: List[Dict[str, Any]], tmpdir: Path) -> Dict[str, Any]:
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
    return summary
