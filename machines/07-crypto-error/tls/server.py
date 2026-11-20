"""Weak-TLS endpoint for WSTG-CRYP-01 / WSTG-CRYP-03. Training only.

Accepts TLSv1.0+ with ALL:@SECLEVEL=0 (legacy provider activated; RC4/3DES
are compiled out of this OpenSSL build, so the weakest real suites are
CBC-SHA1 / static-RSA), serves an expired self-signed hostname-mismatched
RSA-1024/SHA1 certificate, sends no HSTS, and hosts a login form that submits
to plain HTTP (mixed content) plus a session cookie without the Secure flag.
"""
import socketserver
import ssl

CERT = "/app/cert.pem"
KEY = "/app/key.pem"

PAGE = b"""<!doctype html><html><head><title>Acme Legacy Portal (TLS)</title></head><body>
<h1>Acme Legacy Portal</h1>
<p>This page is served over TLS, but the login form submits over plain HTTP.</p>
<form action="http://127.0.0.1:8700/login" method="post">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Sign in</button>
</form>
</body></html>"""


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = self.rfile.read(1)
                if not chunk:
                    return
                head += chunk
            line = head.split(b"\r\n", 1)[0].decode("latin1")
            parts = line.split()
            path = parts[1] if len(parts) > 1 else "/"
            # drain any body so the client sees a clean close
            length = 0
            for h in head.split(b"\r\n")[1:]:
                if h.lower().startswith(b"content-length:"):
                    length = int(h.split(b":", 1)[1].strip())
            if length:
                self.rfile.read(length)
            if path == "/health":
                body, ctype = b'{"status":"ok"}', "application/json"
            else:
                body, ctype = PAGE, "text/html"
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: AcmeLegacyTLS/1.0\r\n"
                b"Content-Type: " + ctype.encode() + b"\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                # No Strict-Transport-Security. Cookie lacks Secure/HttpOnly.
                b"Set-Cookie: legacy_sid=cleartext-session-8817; Path=/\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            self.wfile.write(resp)
        except (ssl.SSLError, ConnectionError, OSError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(CERT, KEY)
    with Server(("0.0.0.0", 8443), Handler) as srv:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        print("weak TLS listening on :8443 (TLSv1+, SECLEVEL=0, legacy provider)")
        srv.serve_forever()