"""DNS rebinding infrastructure for WSTG-CLNT-21. Stdlib only.

Three pieces in one container:
  * Authoritative DNS server (UDP+TCP :53, published as 127.0.0.1:8953) for
    rebind.lab.test with TTL 0. The A answer flips between the attacker
    container's edge-network IP (phase "attacker") and the internal victim
    container's edge-network IP (phase "victim").
  * HTTP forward proxy (:8908, published as 127.0.0.1:8908). Chromium is pointed
    at it, so name resolution happens here - every request triggers a fresh
    TTL-0 DNS lookup, exactly like a stub resolver with no cache. This is the
    standard way to demonstrate rebinding when the browser's own resolver
    cannot be aimed at the lab DNS.
  * Control endpoints on the proxy port (origin-form requests):
    GET /state  -> phase + DNS/proxy logs
    GET /flip   -> switch answers to the internal victim IP
    GET /reset  -> back to the attacker IP, clear logs

The lab never resolves or contacts anything outside its own network.
"""
import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

STATE = {"phase": "attacker", "dns_log": [], "proxy_log": []}
LOCK = threading.Lock()
ZONE = "rebind.lab.test"
HOSTS = {"attacker": "wstg-m09-attacker", "victim": "wstg-m09-internal"}


def resolve_phase_ip(phase):
    infos = socket.getaddrinfo(HOSTS[phase], None, socket.AF_INET)
    return infos[0][4][0]


def dns_answer(name, phase):
    ip = resolve_phase_ip(phase)
    with LOCK:
        STATE["dns_log"].append({"name": name, "phase": phase, "answer": ip,
                                 "ttl": 0, "ts": time.time()})
    return ip


def build_response(query, answer_ip):
    tid = query[:2]
    # parse question
    idx = 12
    while query[idx] != 0:
        idx += query[idx] + 1
    qend = idx + 5  # null label + QTYPE + QCLASS
    question = query[12:qend]
    qtype = struct.unpack("!H", query[qend - 4:qend - 2])[0]
    if answer_ip is None or qtype != 1:
        flags = 0x8403  # AA + NXDOMAIN
        return tid + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question
    flags = 0x8400  # QR + AA
    answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4)
              + socket.inet_aton(answer_ip))
    return tid + struct.pack("!HHHHH", flags, 1, 1, 0, 0) + question + answer


def handle_dns_query(query):
    try:
        idx = 12
        labels = []
        while query[idx] != 0:
            labels.append(query[idx + 1:idx + 1 + query[idx]].decode())
            idx += query[idx] + 1
        name = ".".join(labels).lower()
    except Exception:
        return None
    if name != ZONE:
        return build_response(query, None)
    with LOCK:
        phase = STATE["phase"]
    return build_response(query, dns_answer(name, phase))


def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 53))
    while True:
        data, addr = s.recvfrom(4096)
        resp = handle_dns_query(data)
        if resp:
            s.sendto(resp, addr)


def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 53))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        try:
            hdr = conn.recv(2)
            if len(hdr) == 2:
                ln = struct.unpack("!H", hdr)[0]
                data = conn.recv(ln)
                resp = handle_dns_query(data)
                if resp:
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            conn.close()


def dns_lookup_via_server(name):
    """Real DNS query to our own authoritative server - no caching."""
    q = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(q, ("127.0.0.1", 53))
        resp, _ = s.recvfrom(4096)
    finally:
        s.close()
    ancount = struct.unpack("!H", resp[6:8])[0]
    if ancount == 0:
        raise OSError(f"NXDOMAIN for {name}")
    # skip question
    idx = 12
    while resp[idx] != 0:
        idx += resp[idx] + 1
    idx += 5
    # answer: pointer(2) type(2) class(2) ttl(4) rdlength(2) rdata
    rdlength = struct.unpack("!H", resp[idx + 10:idx + 12])[0]
    rdata = resp[idx + 12:idx + 12 + rdlength]
    return socket.inet_ntoa(rdata)


HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection"}


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _control(self, path):
        if path == "/state":
            with LOCK:
                body = json.dumps(STATE)
            code = 200
        elif path == "/flip":
            with LOCK:
                STATE["phase"] = "victim"
            body, code = json.dumps({"phase": "victim"}), 200
        elif path == "/reset":
            with LOCK:
                STATE["phase"] = "attacker"
                STATE["dns_log"].clear()
                STATE["proxy_log"].clear()
            body, code = json.dumps({"phase": "attacker"}), 200
        elif path == "/health":
            body, code = "ok", 200
        else:
            body, code = json.dumps({"error": "unknown control path"}), 404
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _forward(self):
        parts = urlsplit(self.path)
        host = parts.hostname
        port = parts.port or 80
        if host == ZONE:
            try:
                ip = dns_lookup_via_server(host)  # fresh TTL-0 lookup per request
            except OSError as e:
                self.send_error(502, str(e))
                return
        elif host in ("127.0.0.1", "localhost"):
            ip = "127.0.0.1"
        else:
            self.send_error(403, "lab proxy refuses out-of-range hosts")
            return
        with LOCK:
            STATE["proxy_log"].append({"host": host, "ip": ip, "path": parts.path,
                                       "phase": STATE["phase"], "ts": time.time()})
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        import http.client
        conn = http.client.HTTPConnection(ip, port, timeout=15)
        try:
            path = parts.path + (("?" + parts.query) if parts.query else "")
            conn.request(self.command, path or "/", body=body, headers=headers)
            r = conn.getresponse()
            data = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in HOP | {"content-length"}:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except OSError as e:
            self.send_error(502, str(e))
        finally:
            conn.close()

    def _handle(self):
        if self.path.startswith("http://"):
            self._forward()
        else:
            self._control(self.path.split("?")[0])

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle

    def do_CONNECT(self):
        self.send_error(405, "HTTPS not used in this lab")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    threading.Thread(target=udp_server, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8908), Proxy).serve_forever()