"""Generic MCP tool caller over SSE to Kali. Usage: py mcp_call_tool.py <tool> <json-args>"""
import asyncio
import json
import sys

from mcp import ClientSession
from mcp.client.sse import sse_client

URL = "http://192.168.157.8:8765/sse"


async def main(tool: str, args: dict):
    try:
        async with sse_client(URL) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, args)
                print(json.dumps({
                    "tool": tool,
                    "result": result.content[0].text if result.content else None,
                    "is_error": getattr(result, "isError", False),
                }, ensure_ascii=False, indent=2)[:6000])
    except BaseException as e:
        print(json.dumps({"tool": tool, "error": f"{type(e).__name__}: {str(e)[:300]}"}, ensure_ascii=False))


if __name__ == "__main__":
    tool = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    asyncio.run(main(tool, args))
