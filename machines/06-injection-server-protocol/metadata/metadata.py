"""Cloud-metadata-style service bound to 169.254.169.254 (in-range alias).

Mimics the EC2 IMDSv1 credential endpoint so SSRF can steal fake instance
credentials. All data is synthetic; nothing leaves the compose network.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = "acme-portal-role"
CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-01-01T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAFAKEKEYID000000",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY",
    "Token": "FAKESESSIONTOKEN==",
    "Expiration": "2026-01-01T06:00:00Z",
}


class H(BaseHTTPRequestHandler):
    def _send(self, body, ctype="text/plain", code=200):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path
        if p == "/health":
            self._send({"ok": True}, "application/json")
        elif p in ("/latest/meta-data/", "/latest/meta-data"):
            self._send("ami-id\ninstance-id\niam/\n")
        elif p.rstrip("/") == "/latest/meta-data/iam/security-credentials":
            self._send(ROLE + "\n")
        elif p.startswith("/latest/meta-data/iam/security-credentials/"):
            self._send(CREDS, "application/json")
        elif p == "/latest/dynamic/instance-identity/document":
            self._send({"region": "us-east-1", "instanceId": "i-fake000000",
                        "accountId": "000000000000"}, "application/json")
        else:
            self._send("metadata\n", code=200)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()