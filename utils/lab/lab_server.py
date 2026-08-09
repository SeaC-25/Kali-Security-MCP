#!/usr/bin/env python3
"""Kali local research lab (stdlib only). Default http://127.0.0.1:18081/"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("LAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("LAB_PORT", "18081"))

PAGES = {
    "/": (
        "text/html; charset=utf-8",
        """<!doctype html><html><head><title>Crow5 Lab</title></head>
<body>
<h1>Crow5 Research Lab</h1>
<ul>
<li><a href="/login">/login</a></li>
<li><a href="/admin/">/admin/</a></li>
<li><a href="/api/">/api/</a></li>
<li><a href="/api/health">/api/health</a></li>
<li><a href="/api/v1/users">/api/v1/users</a></li>
<li><a href="/console">/console</a></li>
<li><a href="/search?q=test">/search?q=test</a></li>
<li><a href="/robots.txt">/robots.txt</a></li>
</ul>
</body></html>""",
    ),
    "/login": (
        "text/html; charset=utf-8",
        """<!doctype html><html><head><title>Login</title></head>
<body>
<h1>Login</h1>
<form method="POST" action="/login">
<label>username <input name="username"></label>
<label>password <input type="password" name="password"></label>
<button type="submit">login</button>
</form>
<p>demo: admin / admin123</p>
</body></html>""",
    ),
    "/admin": (
        "text/html; charset=utf-8",
        """<!doctype html><html><head><title>Admin</title></head>
<body><h1>Admin Panel</h1><p>secret-admin-panel FLAG_LAB_OK</p>
<p>Need login cookie for /admin/secret</p></body></html>""",
    ),
    "/admin/": (
        "text/html; charset=utf-8",
        """<!doctype html><html><head><title>Admin</title></head>
<body><h1>Admin Panel</h1><p>secret-admin-panel FLAG_LAB_OK</p></body></html>""",
    ),
    "/admin/secret": (
        "text/html; charset=utf-8",
        """<!doctype html><html><head><title>Secret</title></head>
<body><h1>Admin Secret</h1><p>FLAG{lab_auth_ok}</p></body></html>""",
    ),
    "/api": (
        "application/json; charset=utf-8",
        json.dumps(
            {"service": "crow5-lab-api", "status": "ok", "version": "1.0"},
            ensure_ascii=False,
        ),
    ),
    "/api/": (
        "application/json; charset=utf-8",
        json.dumps(
            {
                "service": "crow5-lab-api",
                "status": "ok",
                "endpoints": ["/api/health", "/api/v1/users"],
            },
            ensure_ascii=False,
        ),
    ),
    "/api/health": (
        "application/json; charset=utf-8",
        json.dumps({"status": "ok", "health": "up"}, ensure_ascii=False),
    ),
    "/api/v1/users": (
        "application/json; charset=utf-8",
        json.dumps(
            {"users": [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]},
            ensure_ascii=False,
        ),
    ),
    "/robots.txt": (
        "text/plain; charset=utf-8",
        "User-agent: *\nDisallow: /admin/\nDisallow: /api/v1/\n",
    ),
    "/console": (
        "text/html; charset=utf-8",
        """<!doctype html><html><head><title>Console</title></head>
<body><h1>Console Login</h1>
<form><input name="username"><input type="password" name="password"><button>login</button></form>
</body></html>""",
    ),
}


class LabHandler(BaseHTTPRequestHandler):
    server_version = "Crow5Lab/1.0"

    def _send(self, code: int, content_type: str, body: str, extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Lab", "crow5-research")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _cookies(self):
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        candidates = [parsed.path, path, path + "/"]
        for key in candidates:
            if key in PAGES:
                ctype, body = PAGES[key]
                if key == "/admin/secret" and self._cookies().get("lab_session") != "admin":
                    self._send(401, "text/plain; charset=utf-8", "unauthorized")
                    return
                self._send(200, ctype, body)
                return
        if path == "/search":
            q = parse_qs(parsed.query).get("q", [""])[0]
            body = f"<!doctype html><html><body><h1>Search</h1><p>q={q}</p></body></html>"
            self._send(200, "text/html; charset=utf-8", body)
            return
        self._send(404, "text/plain; charset=utf-8", f"not found: {parsed.path}")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = parse_qs(raw)
        if parsed.path.rstrip("/") == "/login":
            user = (form.get("username") or [""])[0]
            pw = (form.get("password") or [""])[0]
            if user == "admin" and pw == "admin123":
                self._send(
                    200,
                    "text/html; charset=utf-8",
                    "<html><body>login ok <a href='/admin/secret'>secret</a></body></html>",
                    extra_headers={"Set-Cookie": "lab_session=admin; Path=/"},
                )
                return
            self._send(401, "text/html; charset=utf-8", "<html><body>login failed</body></html>")
            return
        self._send(404, "text/plain; charset=utf-8", "not found")

    def log_message(self, format, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), LabHandler)
    print(f"Crow5 lab listening on http://{HOST}:{PORT}/", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
