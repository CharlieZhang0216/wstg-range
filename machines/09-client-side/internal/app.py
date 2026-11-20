"""Internal-only admin service (WSTG-CLNT-21 rebinding target).

Published on loopback only. Accepts ANY Host header and has no authentication -
exactly the kind of internal service DNS rebinding reaches through the browser.
Stdlib only.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = "WSTG-M09{dns_rebinding_sop_bypass}"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, "ok", "text/plain")
        elif self.path.startswith("/internal/secret"):
            # no auth, no Host validation: reachable via a rebound origin
            self._send(200, json.dumps({
                "flag": FLAG,
                "internal_only": True,
                "received_host": self.headers.get("Host", ""),
                "admin_users": ["alice", "bob"],
            }))
        elif self.path == "/":
            self._send(200, "<h1>Internal admin console</h1><p>Not for public use.</p>",
                       "text/html")
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8902), Handler).serve_forever()