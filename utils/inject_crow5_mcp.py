"""Inject kali remote MCP server into Crow5 runtime config (JSONC)."""
import json
import re
import shutil
import time
from pathlib import Path

CONF = Path(r"C:/Users/Administrator/AppData/Local/com.crow5.desktop/crow5/crow5.jsonc")


def strip_jsonc_comments(raw: str) -> str:
    lines = []
    for ln in raw.split("\n"):
        out = []
        i = 0
        in_str = False
        while i < len(ln):
            ch = ln[i]
            if ch == '"' and (i == 0 or ln[i - 1] != "\\"):
                in_str = not in_str
            if ch == "/" and i + 1 < len(ln) and ln[i + 1] == "/" and not in_str:
                break
            out.append(ch)
            i += 1
        lines.append("".join(out))
    return "\n".join(lines)


def main():
    raw = CONF.read_text(encoding="utf-8")
    stripped = strip_jsonc_comments(raw)
    data = json.loads(stripped)

    # backup
    bak = CONF.with_name(f"crow5.jsonc.bak_{time.strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(CONF, bak)
    print("BACKUP:", bak.name)

    if "mcp" in data:
        print("mcp already present:", list(data["mcp"].keys()))
    data["mcp"] = {
        "kali": {
            "type": "remote",
            "url": "http://192.168.157.8:8765/sse",
            "enabled": True,
        }
    }

    # re-serialize preserving structure as compact JSON (safe for JSONC readers)
    out = json.dumps(data, ensure_ascii=False, indent=2)
    CONF.write_text(out, encoding="utf-8")
    print("WROTE mcp.kali =", data["mcp"]["kali"])
    # verify readable
    re_read = json.loads(strip_jsonc_comments(CONF.read_text(encoding="utf-8")))
    print("VERIFY mcp:", re_read.get("mcp"))


if __name__ == "__main__":
    main()
