"""MCP SSE client probe v3 — trust_env=False (no proxy), urljoin for relative endpoint."""
import json
import re
import sys
import time
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("NO_REQUESTS")
    sys.exit(2)

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.157.8"
PORT = sys.argv[2] if len(sys.argv) > 2 else "8765"
BASE = f"http://{HOST}:{PORT}"
SESSION = requests.Session()
# 跳过环境代理（本机有死代理历史），SSE 直连
SESSION.trust_env = False


def get_endpoint(timeout=15):
    with SESSION.get(BASE + "/sse", headers={"Accept": "text/event-stream"},
                     stream=True, timeout=timeout) as r:
        print("SSE_STATUS:", r.status_code)
        deadline = time.time() + timeout
        buf = ""
        for line in r.iter_lines(decode_unicode=True):
            buf += (line or "") + "\n"
            m = re.search(r"event:\s*endpoint\s*\ndata:\s*(\S+)", buf)
            if m:
                return urljoin(BASE + "/sse", m.group(1).strip())
            if time.time() > deadline:
                break
    return ""


def rpc(endpoint, msg):
    resp = SESSION.post(endpoint, json=msg, timeout=15)
    return resp.status_code, resp.text


def main():
    ep = get_endpoint()
    if not ep:
        print("NO_ENDPOINT")
        return 1
    print("ENDPOINT:", ep)

    code, init = rpc(ep, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "crow5-probe", "version": "0.2"}},
    })
    print("INIT_CODE:", code)
    print("INIT_HEAD:", re.sub(r"[^\x20-\x7e\n\r]", "", init)[:200])

    code2, tools_raw = rpc(ep, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    print("TOOLS_CODE:", code2)
    try:
        data = json.loads(tools_raw)
        tlist = data.get("result", {}).get("tools", [])
        print("TOOLS_COUNT:", len(tlist))
        for t in tlist[:20]:
            print("  -", t.get("name"))
    except Exception as e:
        print("PARSE_FAIL:", str(e)[:150])
        print("RAW:", re.sub(r"[^\x20-\x7e\n\r]", "", tools_raw)[:600])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
