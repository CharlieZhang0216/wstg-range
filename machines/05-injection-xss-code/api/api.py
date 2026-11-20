"""M05 internal backend - the LAST-occurrence side of the HPP differential.

The gateway (app) validates the first occurrence of each duplicated parameter
and then forwards the raw body here. This service parses with last-wins
semantics, so `action=view&action=transfer` executes a transfer.
"""
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG_HPP", "WSTG-M05{hpp_body}")
BALANCE = {"alice": 1000, "mallory": 0}


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
        if self.path.startswith("/health"):
            self._send(200, {"status": "ok", "service": "m05-api"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/transfer"):
            self._send(404, {"error": "not found"})
            return
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode()
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        last = {k: v[-1] for k, v in parsed.items()}      # LAST wins here
        action = last.get("action", "view")
        try:
            amount = int(last.get("amount", "0"))
        except ValueError:
            amount = 0
        src, dst = last.get("from", "alice"), last.get("to", "mallory")
        result = {
            "backend_saw": last,
            "all_occurrences": parsed,
            "executed": action,
        }
        if action == "transfer":
            BALANCE[src] = BALANCE.get(src, 0) - amount
            BALANCE[dst] = BALANCE.get(dst, 0) + amount
            result.update(balances=dict(BALANCE), flag=FLAG,
                          impact=f"{amount} moved from {src} to {dst}")
        else:
            result.update(balances=dict(BALANCE), read_only=True)
        self._send(200, result)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 5000), Handler).serve_forever()