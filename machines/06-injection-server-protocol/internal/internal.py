"""Internal-only service (backend network, NOT published to the host).

Reachable only via SSRF from the portal/renderer. Holds a secret that proves
the SSRF reached an internal-only target.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("SECRET", "WSTG-M06{internal_only_service_not_published}")


class H(BaseHTTPRequestHandler):
    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send({"ok": True})
        elif self.path.startswith("/secret"):
            self._send({"secret": SECRET, "service": "internal-admin",
                        "note": "not published to host; reachable only in-range"})
        else:
            self._send({"service": "internal-admin", "paths": ["/secret", "/health"]})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()