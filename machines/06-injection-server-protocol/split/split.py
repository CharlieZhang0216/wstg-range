"""Legacy raw-socket HTTP service - HTTP Response Splitting (INJT-15).

User input is placed into a response header (Set-Cookie) WITHOUT stripping
CR/LF, so %0d%0a injects an extra header or a whole second response. Written
with raw sockets because modern frameworks (Werkzeug/nginx) normalise CRLF in
headers and would hide the flaw. Exposed directly on its own port.
"""
import socketserver
import urllib.parse

BODY = b"<html><body>legacy portal</body></html>"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            line = self.rfile.readline(65537).decode(errors="replace").strip()
            if not line:
                return
            # drain headers
            while True:
                h = self.rfile.readline(65537)
                if h in (b"\r\n", b"\n", b""):
                    break
            parts = line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            if path.startswith("/health"):
                resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        b"Content-Length: 2\r\nConnection: close\r\n\r\nok")
            elif path.startswith("/legacy"):
                qs = urllib.parse.urlsplit(path).query
                params = urllib.parse.parse_qs(qs, keep_blank_values=True)
                lang = params.get("lang", ["en"])[0]
                # VULNERABLE: lang decoded then written verbatim into a header.
                resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                        b"Set-Cookie: lang=" + lang.encode(errors="replace") + b"\r\n"
                        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
                        b"Connection: close\r\n\r\n" + BODY)
            else:
                resp = (b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n"
                        b"Connection: close\r\n\r\nnot found")
            self.wfile.write(resp)
        except Exception:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", 8080), Handler).serve_forever()