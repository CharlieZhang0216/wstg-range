"""CL-framing reverse proxy front-end (INJT-16).

A real reverse proxy that forwards requests to the backend over a persistent
connection. VULNERABLE: it frames request bodies by Content-Length and ignores
Transfer-Encoding, while the backend honours (obfuscated) Transfer-Encoding as
chunked. The CL.TE disagreement lets a smuggled prefix poison the next request
on the same connection.
"""
import socket
import socketserver

BACKEND = ("smuggle-back", 8080)


def _read_headers(f):
    line = f.readline(65537)
    if not line:
        return None, None
    headers = []
    while True:
        h = f.readline(65537)
        if h in (b"\r\n", b"\n", b""):
            break
        headers.append(h)
    return line, headers


def _content_length(headers):
    for h in headers:
        if h.lower().startswith(b"content-length:"):
            try:
                return int(h.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def _read_response(f):
    line = f.readline(65537)
    if not line:
        return None
    parts = [line]
    cl = 0
    while True:
        h = f.readline(65537)
        parts.append(h)
        if h in (b"\r\n", b"\n", b""):
            break
        if h.lower().startswith(b"content-length:"):
            try:
                cl = int(h.split(b":", 1)[1].strip())
            except ValueError:
                cl = 0
    body = f.read(cl) if cl else b""
    return b"".join(parts) + body


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        cf = client.makefile("rb")
        try:
            back = socket.create_connection(BACKEND, timeout=15)
        except Exception:
            client.close()
            return
        bf = back.makefile("rb")
        try:
            while True:
                req, headers = _read_headers(cf)
                if req is None:
                    break
                # FRONT frames by Content-Length only (ignores Transfer-Encoding).
                cl = _content_length(headers)
                body = cf.read(cl) if cl else b""
                back.sendall(req + b"".join(headers) + b"\r\n" + body)
                resp = _read_response(bf)
                if resp is None:
                    break
                client.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                back.close()
            except Exception:
                pass
            client.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", 8080), Handler).serve_forever()