#!/usr/bin/env python3
"""gen_templates.py — 把 fastsec -diff 的 JSON 结果转成针对性 nuclei 模板。

AI 决策层（MCP）读取 diff JSON → 选出 top 参数 → 本脚本生成 YAML 模板
→ fastsec 模板模式深挖。闭环的一环：把"发现"固化成"可复用检测"。

用法:
    py gen_templates.py --diff diff.json --out /tmp/gen-templates/
    # 或直接传参数
    py gen_templates.py --url http://target/user --params id,userId --out ./gen/
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


def load_diff(json_path: str) -> dict:
    with open(json_path, encoding="utf-8") as f:
        return json.load(f)


def _safe_id(s: str) -> str:
    """sanitize a param name into a template id fragment."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", s)[:40]


def build_template(url: str, param: str, severity: str, reason: str, out_dir: Path) -> Path:
    """Generate a single YAML template that probes the param with multiple values."""
    # normalize url to base (strip existing query + scheme+host, keep path)
    base = url.split("?")[0]
    from urllib.parse import urlparse
    parsed = urlparse(base)
    base_path = parsed.path or "/"
    tid = f"diff-{_safe_id(param)}"
    # mutations: 2 (existence of second object), 0, -1, 999999
    paths = "\n".join(
        f'      - "{{{{BaseURL}}}}{base_path}?{param}={v}"'
        for v in ("2", "0", "-1", "999999")
    )
    tpl = f"""id: {tid}

info:
  name: Behavioral diff probe for {param} ({reason})
  author: fastsec-ai
  severity: {severity}

http:
  - method: GET
    path:
{paths}
    matchers:
      - type: status
        status:
          - 200
          - 403
"""
    # NOTE: 该模板只做"参数存在响应"探测；真正的差异判断由 fastsec -diff 完成。
    # 生成后建议人工/AI 审阅并补充 word matcher。
    out = out_dir / f"{tid}.yaml"
    out.write_text(tpl, encoding="utf-8")
    return out


def _path_with_query(base: str, param: str, value: str) -> str:
    sep = "?" if "?" not in base else "&"
    return f"{base}{sep}{param}={value}"


def main():
    ap = argparse.ArgumentParser(description="diff JSON → targeted templates")
    ap.add_argument("--diff", help="fastsec -diff -json output file")
    ap.add_argument("--url", help="target URL (when not using --diff file)")
    ap.add_argument("--params", help="comma list of params (when not using --diff file)")
    ap.add_argument("--out", default="./gen/", help="output dir")
    ap.add_argument("--top", type=int, default=3, help="generate templates for top N params")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # source: diff JSON or direct params
    findings = []
    if args.diff:
        d = load_diff(args.diff)
        # priority list has scores; findings has urls
        prio = d.get("priority", [])
        for p in prio[: args.top]:
            # find matching finding url
            url = next(
                (f["url"] for f in d.get("findings", []) if f.get("param") == p.get("param")),
                args.url or "http://target/",
            )
            findings.append({
                "param": p.get("param", "p"),
                "severity": p.get("severity", "medium"),
                "reason": "; ".join(p.get("reasons", [])) or "behavioral diff",
                "url": url,
            })
    elif args.url and args.params:
        for p in args.params.split(","):
            findings.append({
                "param": p.strip(),
                "severity": "medium",
                "reason": "manual param probe",
                "url": args.url,
            })

    if not findings:
        print("no findings to convert (need --diff file or --url + --params)")
        sys.exit(1)

    generated = []
    for f in findings:
        p = build_template(f["url"], f["param"], f["severity"], f["reason"], out_dir)
        generated.append(p)
        print(f"  generated {p}  ({f['param']}, {f['severity']})")

    print(f"\n{len(generated)} templates written to {out_dir}")
    print("next: fastsec -u <target> -d <out_dir> -c 30")


if __name__ == "__main__":
    main()
