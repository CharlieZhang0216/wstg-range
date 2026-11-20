"""Legacy maintenance console - cleartext credential channel (WSTG-CRYP-03).

A telnet-style TCP service: username, password and a live API token all cross
the wire unencrypted. Training only; synthetic credentials.
"""
import socketserver

USERS = {"alice": "Password123!", "bob": "Summer2024!"}
TOKEN = "tok_live_9f8e7d6c5b4a3210"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.wfile.write(b"Acme Legacy Maintenance Console v2.1\r\nlogin: ")
            user = self.rfile.readline(256).strip().decode("latin1")
            self.wfile.write(b"Password: ")
            pw = self.rfile.readline(256).strip().decode("latin1")
            if USERS.get(user) == pw and user:
                self.wfile.write(
                    b"Welcome, " + user.encode() + b".\r\n"
                    b"SECRET_TOKEN=" + TOKEN.encode() + b"\r\n"
                    b"Last backup: 2026-11-01 03:00 UTC\r\n"
                )
            else:
                self.wfile.write(b"Access denied.\r\n")
        except (ConnectionError, OSError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", 8723), Handler) as srv:
        print("cleartext maintenance console on :8723")
        srv.serve_forever()