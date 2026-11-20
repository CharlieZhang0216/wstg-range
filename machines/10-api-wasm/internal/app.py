"""Internal metadata service - backend network only, never published.

Stands in for a cloud metadata / internal config service. It is unreachable
from the host; only a server-side request (SSRF) from the API can read it.
Stdlib only.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET_DOC = {
    "service": "acme-internal-metadata",
    "internal_token": "itok_6f2b9c44d1ae47e0b83c5f9a2d7e1043",
    "db_password": "InternalDB-Pw-9f3e2a",
    "note": "backend network only - if you can read this from outside, SSRF worked",
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = {"ok": True}
        elif self.path.startswith("/latest/secret"):
            body = SECRET_DOC
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()