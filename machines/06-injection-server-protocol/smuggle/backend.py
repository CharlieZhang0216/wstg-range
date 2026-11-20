"""Smuggling backend (INJT-16). Deliberately disagrees with the HAProxy front.

The front-end frames requests by Content-Length when it does not recognise the
Transfer-Encoding token; this backend treats ANY TE value containing "chunked"
(including obfuscated forms like "xchunked") as chunked framing. The resulting
CL.TE / TE.TE desync lets a smuggled prefix poison the next request on the same
connection.
"""
import socketserver

MARKER = "SMUGGLED-RESPONSE"


class Handler(socketserver.StreamRequestHandler):
    def _respond(self, body, code="200 OK"):
        data = body.encode()
        self.wfile.write(
            f"HTTP/1.1 {code}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(data)}\r\nConnection: keep-alive\r\n\r\n".encode()
            + data)

    def handle(self):
        rfile = self.rfile
        while True:
            line = rfile.readline(65537)
            if not line:
                return
            request_line = line.decode(errors="replace").strip()
            if not request_line:
                continue
            headers = []
            while True:
                h = rfile.readline(65537)
                if h in (b"\r\n", b"\n", b""):
                    break
                headers.append(h.decode(errors="replace").rstrip("\r\n"))
            te = [v.split(":", 1)[1].strip() for v in headers
                  if v.lower().startswith("transfer-encoding:")]
            cl = [v.split(":", 1)[1].strip() for v in headers
                  if v.lower().startswith("content-length:")]
            # VULNERABLE: obfuscated TE tokens are honoured as chunked.
            chunked = any("chunked" in v.lower() for v in te)
            try:
                if chunked:
                    while True:
                        size_line = rfile.readline(65537).strip()
                        if not size_line:
                            break
                        size = int(size_line.split(b";")[0], 16)
                        if size == 0:
                            while True:
                                t = rfile.readline(65537)
                                if t in (b"\r\n", b"\n", b""):
                                    break
                            break
                        rfile.read(size)
                        rfile.read(2)
                elif cl:
                    n = int(cl[0])
                    if n > 0:
                        rfile.read(n)
            except Exception:
                return

            parts = request_line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            method = parts[0] if parts else "GET"
            if path.startswith("/health"):
                self._respond("ok")
            elif path.startswith("/smuggled"):
                self._respond(f"{MARKER} method={method} path={path}")
            elif path == "/":
                self._respond(f"NORMAL-RESPONSE method={method} path={path}")
            else:
                self._respond(f"NOTFOUND method={method} path={path}", "404 Not Found")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", 8080), Handler).serve_forever()