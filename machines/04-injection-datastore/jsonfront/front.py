"""WSTG-INJT-26 JSON Parser Differentials - front validator/proxy.

INTENTIONALLY VULNERABLE training target. This front layer parses JSON with a
FIRST-wins duplicate-key policy and authorises on that view, then forwards the
RAW bytes to the backend (app /json/backend), which parses with Python's
standard LAST-wins json.loads. A duplicated `role` key therefore passes the
front check as "user" while the backend acts as "admin".

stdlib only; loopback-published via compose. See README.md.
"""
import json
import os
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BACKEND = os.environ.get("BACKEND_URL", "http://app:5000/json/backend")


def first_wins(pairs):
    d = {}
    for k, v in pairs:
        if k not in d:
            d[k] = v
    return d


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._send(200, {"service": "jsonfront", "policy": "duplicate keys: FIRST wins",
                             "backend": BACKEND, "status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/json/transfer":
            self._send(404, {"error": "not found"})
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            doc = json.loads(raw, object_pairs_hook=first_wins)
        except Exception as e:
            self._send(400, {"stage": "front", "error": str(e)})
            return
        # Front authorisation decision on the FIRST-wins view: external
        # callers may not claim the admin role. Anything else is forwarded.
        if doc.get("role") == "admin":
            self._send(403, {"stage": "front", "seen_role": doc.get("role"),
                             "granted": False,
                             "reason": "front rejects admin claims from external callers"})
            return
        # Forward the ORIGINAL bytes untouched - the backend re-parses them.
        req = urllib.request.Request(BACKEND, data=raw, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "X-From-Front": "jsonfront"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                backend = json.loads(r.read())
                self._send(r.status, {"stage": "front+backend",
                                      "front_seen_role": doc.get("role"),
                                      "backend": backend})
        except urllib.error.HTTPError as e:
            backend = json.loads(e.read())
            self._send(e.code, {"stage": "front+backend",
                                "front_seen_role": doc.get("role"),
                                "backend": backend})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 5000), Handler).serve_forever()