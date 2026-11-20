"""Stdlib-only HTTP helpers for WSTG lab probes.

http.client is used rather than urllib so that duplicate headers, malformed
status lines and unusual methods survive intact - several WSTG tests depend on
exactly those artefacts.
"""
import http.client
import json
import re
import socket
import ssl
import time
import urllib.parse

DEFAULT_TIMEOUT = 15


class Response:
    def __init__(self, status, reason, headers, body):
        self.status = status
        self.reason = reason
        self.headers = headers  # list of (name, value), duplicates preserved
        self.body = body

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text)

    def header(self, name, default=None):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def header_all(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def __repr__(self):
        return f"<Response {self.status} {len(self.body)}b>"


def split_url(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {url}")
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return p.scheme, host, port, path


def request(method, url, headers=None, data=None, timeout=DEFAULT_TIMEOUT, insecure=True):
    """Single request, no redirect following, no automatic header rewriting."""
    scheme, host, port, path = split_url(url)
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if insecure:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    body = data
    if isinstance(body, str):
        body = body.encode()
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        headers = dict(headers or {})
        headers.setdefault("Content-Type", "application/json")
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        raw = r.read()
        return Response(r.status, r.reason, r.getheaders(), raw)
    finally:
        conn.close()


def get(url, **kw):
    return request("GET", url, **kw)


def post(url, data=None, **kw):
    return request("POST", url, data=data, **kw)


def raw(host, port, payload, timeout=DEFAULT_TIMEOUT, tls=False, read_all=True):
    """Send bytes verbatim and return the peer's bytes. For smuggling/splitting."""
    if isinstance(payload, str):
        payload = payload.encode()
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        s = ctx.wrap_socket(s, server_hostname=host)
    try:
        s.sendall(payload)
        chunks = []
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
            if not read_all:
                break
        return b"".join(chunks)
    finally:
        s.close()


class Session:
    """Cookie-jar session; enough for login -> authenticated probe flows."""

    def __init__(self, base=None):
        self.base = base.rstrip("/") if base else None
        self.cookies = {}
        self.headers = {}

    def url(self, path):
        if path.startswith("http"):
            return path
        if not self.base:
            raise ValueError("no base url")
        return self.base + (path if path.startswith("/") else "/" + path)

    def request(self, method, path, **kw):
        headers = dict(self.headers)
        headers.update(kw.pop("headers", None) or {})
        if self.cookies:
            existing = headers.get("Cookie", "")
            jar = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = (existing + "; " + jar).strip("; ") if existing else jar
        r = request(method, self.url(path), headers=headers, **kw)
        for v in r.header_all("set-cookie"):
            parts = v.split(";")
            if "=" in parts[0]:
                k, val = parts[0].split("=", 1)
                self.cookies[k.strip()] = val.strip()
        return r

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, data=None, **kw):
        return self.request("POST", path, data=data, **kw)

    def form(self, path, fields, **kw):
        headers = dict(kw.pop("headers", None) or {})
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self.post(path, data=urllib.parse.urlencode(fields), headers=headers, **kw)


def wait_for(url, timeout=180, interval=2, expect=None):
    """Block until the lab answers. expect: callable(Response)->bool."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = get(url, timeout=5)
            if expect is None or expect(r):
                return r
            last = f"status {r.status}"
        except Exception as e:
            last = str(e)
        time.sleep(interval)
    raise TimeoutError(f"{url} not ready after {timeout}s (last: {last})")


def contains(response, *needles):
    body = response.text if isinstance(response, Response) else str(response)
    return all(n.lower() in body.lower() for n in needles)


def evidence(response, limit=240):
    """Short, human-readable proof string for the report."""
    if isinstance(response, Response):
        snippet = re.sub(r"\s+", " ", response.text)[:limit]
        return f"HTTP {response.status} | {snippet}"
    return re.sub(r"\s+", " ", str(response))[:limit]