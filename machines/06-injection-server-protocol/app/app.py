"""WSTG machine 06 - main portal. Intentionally vulnerable.

Hosts: IMAP/SMTP injection client (INJT-10), Host header injection (INJT-17),
SSRF (INJT-19), mass assignment (INJT-20), CSV export (INJT-21), pickle
deserialization (INJT-23), server-side URL redirect (INJT-24), ReDoS (INJT-28),
and the benign store stage of the incubated vulnerability (INJT-14).
"""
import base64
import html
import os
import pickle
import re
import socket
import time
import urllib.parse
import urllib.request
import uuid

from flask import Flask, request, jsonify, Response, redirect

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "WSTG-M06{pickle_rce_server_side_injection}")
SMTP_HOST = os.environ.get("SMTP_HOST", "mail")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "1025"))
IMAP_HOST = os.environ.get("IMAP_HOST", "imap")
IMAP_PORT = int(os.environ.get("IMAP_PORT", "143"))
WORKER_URL = os.environ.get("WORKER_URL", "http://worker:8080")
LISTENER_URL = os.environ.get("LISTENER_URL", "http://listener:8080")

# --- in-memory state ---------------------------------------------------------
USERS = {}
FEEDBACK = []
INCUBATED = {}
HOST_CACHE = {}


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/")
def home():
    return Response(
        "<html><body><h1>Acme Portal (M06)</h1>"
        "<ul>"
        "<li><a href='/contact'>Contact us</a> (SMTP injection)</li>"
        "<li><a href='/webmail?folder=INBOX'>Webmail</a> (IMAP injection)</li>"
        "<li><a href='/password-reset?email=alice@lab.test'>Password reset</a> (Host header)</li>"
        "<li><a href='/fetch?url=http://internal:8080/secret'>URL fetcher</a> (SSRF)</li>"
        "<li><a href='/redirect?url=https://portal.trusted.lab/'>Link redirector</a></li>"
        "<li><a href='/validate?username=alice'>Username validator</a> (ReDoS)</li>"
        "<li><a href='/export.csv'>Feedback export</a> (CSV injection)</li>"
        "</ul>"
        "<form method='post' action='/api/users'><input name='name'><input name='email'>"
        "<button>Register</button></form>"
        "<form method='post' action='/feedback'><input name='name'><input name='comment'>"
        "<button>Leave feedback</button></form>"
        "</body></html>", mimetype="text/html")


# --- INJT-10: IMAP / SMTP injection ------------------------------------------

def _smtp_session(lines):
    """Raw SMTP conversation. Commands are concatenated from user input."""
    s = socket.create_connection((SMTP_HOST, SMTP_PORT), timeout=10)
    f = s.makefile("rwb")
    transcript = [f.readline().decode(errors="replace").strip()]
    for cmd in lines:
        f.write((cmd + "\r\n").encode())
        f.flush()
        # read single or multi-line reply
        while True:
            line = f.readline().decode(errors="replace").strip()
            transcript.append(line)
            if len(line) < 4 or line[3] != "-":
                break
    s.close()
    return transcript


@app.post("/contact")
def contact():
    email = request.form.get("email", "alice@lab.test")
    rcpt = request.form.get("rcpt", "support@lab.test")
    message = request.form.get("message", "hello")
    # VULNERABLE: user input concatenated straight into SMTP commands.
    lines = [
        "EHLO portal.lab.test",
        "MAIL FROM:<" + email + ">",
        "RCPT TO:<" + rcpt + ">",
        "DATA",
        "Subject: contact\r\n\r\n" + message + "\r\n.",
        "QUIT",
    ]
    try:
        transcript = _smtp_session(lines)
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(transcript=transcript)


def _imap_session(commands):
    s = socket.create_connection((IMAP_HOST, IMAP_PORT), timeout=10)
    f = s.makefile("rwb")
    transcript = [f.readline().decode(errors="replace").strip()]
    for cmd in commands:
        f.write((cmd + "\r\n").encode())
        f.flush()
        tag = cmd.split(" ", 1)[0]
        while True:
            line = f.readline().decode(errors="replace").strip()
            transcript.append(line)
            if line.startswith(tag + " "):
                break
    s.close()
    return transcript


@app.get("/webmail")
def webmail():
    folder = request.args.get("folder", "INBOX")
    user = request.args.get("user", "alice")
    pw = request.args.get("pass", "Password123!")
    # VULNERABLE: folder name concatenated into the IMAP SELECT command.
    commands = [
        "a001 LOGIN " + user + " " + pw,
        'a002 SELECT "' + folder + '"',
        "a003 FETCH 1 (BODY[HEADER])",
        "a004 LOGOUT",
    ]
    try:
        transcript = _imap_session(commands)
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(transcript=transcript)


# --- INJT-17: Host header injection ------------------------------------------

def _host():
    # X-Forwarded-Host takes precedence, then Host. Both attacker-controlled.
    return request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "localhost")


@app.get("/password-reset")
def password_reset():
    email = request.args.get("email", "alice@lab.test")
    token = uuid.uuid4().hex
    host = _host()
    link = f"http://{host}/reset?token={token}&email={urllib.parse.quote(email)}"
    return jsonify(reset_link=link, host_used=host,
                   host_headers=request.headers.getlist("Host"),
                   x_forwarded_host=request.headers.get("X-Forwarded-Host"))


@app.get("/host-echo")
def host_echo():
    return jsonify(host=_host(), host_headers=request.headers.getlist("Host"))


@app.get("/host-cache/page")
def host_cache_page():
    key = request.full_path
    host = _host()
    if key in HOST_CACHE:
        body = HOST_CACHE[key]
        return Response(body, mimetype="text/html", headers={"X-Cache": "HIT"})
    body = f"<html><body><h1>Welcome to {html.escape(host)}</h1><a href='http://{html.escape(host)}/login'>Login</a></body></html>"
    HOST_CACHE[key] = body
    return Response(body, mimetype="text/html", headers={"X-Cache": "MISS"})


@app.post("/host-cache/reset")
def host_cache_reset():
    HOST_CACHE.clear()
    return jsonify(ok=True)


# --- INJT-19: SSRF -----------------------------------------------------------

@app.get("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="url required"), 400
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    try:
        if scheme in ("http", "https"):
            # No allowlist: any in-range (or arbitrary) host is fetched.
            req = urllib.request.Request(url, headers={"User-Agent": "AcmeFetcher/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read(200000).decode(errors="replace")
                return jsonify(scheme=scheme, status=r.status, body=body)
        if scheme == "file":
            path = urllib.parse.unquote(parsed.path)
            with open(path, "r", errors="replace") as fh:
                return jsonify(scheme=scheme, body=fh.read(200000))
        if scheme == "gopher":
            host = parsed.hostname
            port = parsed.port or 70
            # gopher://host:port/_<urlencoded raw payload>
            payload = urllib.parse.unquote(parsed.path.lstrip("/"))
            if payload.startswith("_"):
                payload = payload[1:]
            s = socket.create_connection((host, port), timeout=8)
            s.sendall(payload.encode())
            chunks = []
            s.settimeout(5)
            try:
                while True:
                    b = s.recv(65536)
                    if not b:
                        break
                    chunks.append(b)
            except socket.timeout:
                pass
            s.close()
            return jsonify(scheme=scheme, body=b"".join(chunks).decode(errors="replace"))
        return jsonify(error=f"unsupported scheme {scheme}"), 400
    except Exception as e:
        return jsonify(scheme=scheme, error=str(e)), 502


# --- INJT-20: Mass assignment ------------------------------------------------

@app.post("/api/users")
def create_user():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    uid = str(data.get("id") or uuid.uuid4().hex[:8])
    user = {"id": uid, "name": data.get("name", ""), "email": data.get("email", ""),
            "is_admin": False, "role": "user", "balance": 0}
    # VULNERABLE: every supplied field is bound, including privileged ones.
    user.update(data)
    USERS[uid] = user
    return jsonify(user), 201


@app.get("/api/users/<uid>")
def get_user(uid):
    if uid not in USERS:
        return jsonify(error="not found"), 404
    return jsonify(USERS[uid])


@app.get("/api/admin/flag")
def admin_flag():
    uid = request.args.get("user_id", "")
    user = USERS.get(uid)
    if not user or not user.get("is_admin"):
        return jsonify(error="admin only"), 403
    return jsonify(flag=FLAG, user=user)


@app.post("/api/users/reset")
def users_reset():
    USERS.clear()
    return jsonify(ok=True)


# --- INJT-21: CSV injection --------------------------------------------------

@app.post("/feedback")
def feedback():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    FEEDBACK.append({"name": data.get("name", ""), "comment": data.get("comment", "")})
    return jsonify(ok=True, count=len(FEEDBACK))


@app.post("/feedback/reset")
def feedback_reset():
    FEEDBACK.clear()
    return jsonify(ok=True)


@app.get("/export.csv")
def export_csv():
    # VULNERABLE: user-controlled cells written verbatim, no formula neutralisation.
    out = "name,comment\r\n"
    for row in FEEDBACK:
        out += f"{row['name']},{row['comment']}\r\n"
    return Response(out, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=feedback.csv"})


# --- INJT-23: Insecure deserialization (Python pickle) -----------------------

@app.get("/pickle")
def pickle_loads():
    data = request.args.get("data", "")
    try:
        obj = pickle.loads(base64.b64decode(data))
        return jsonify(result=str(obj), type=type(obj).__name__)
    except Exception as e:
        return jsonify(error=f"{type(e).__name__}: {e}"), 500


# --- INJT-24: Server-side URL redirect ---------------------------------------

def _redirect_allowed(url):
    u = urllib.parse.unquote(url)
    # naive "relative path" check: browsers normalise \ to /, so \/\/ and //
    # and %2f%2f all slip through as "relative".
    if u.startswith("/") or u.replace("\\", "/").startswith("/"):
        return True
    netloc = urllib.parse.urlsplit(u).netloc
    return "trusted.lab" in netloc  # substring check: userinfo bypass


def _resolve_for_fetch(url):
    u = urllib.parse.unquote(url).replace("\\", "/")
    if u.startswith("//"):
        u = "http:" + u
    p = urllib.parse.urlsplit(u)
    host = p.hostname or "portal.trusted.lab"
    port = p.port or 80
    path = p.path or "/"
    return f"http://{host}:{port}{path}"


@app.get("/redirect")
def server_redirect():
    url = request.args.get("url", "")
    if not _redirect_allowed(url):
        return jsonify(error="target not allowed"), 400
    # The SERVER validates the target by fetching it (server-side, not client-side).
    target = _resolve_for_fetch(url)
    fetched = None
    try:
        with urllib.request.urlopen(target, timeout=6) as r:
            fetched = r.status
    except Exception as e:
        fetched = str(e)
    location = urllib.parse.unquote(url)
    resp = redirect(location, code=302)
    resp.headers["X-Server-Validated"] = str(fetched)
    return resp


# --- INJT-28: ReDoS ----------------------------------------------------------

@app.get("/validate")
def validate():
    username = request.args.get("username", "")
    pattern = request.args.get("pattern", r"^(a+)+$")
    start = time.time()
    try:
        matched = re.fullmatch(pattern, username) is not None
        err = None
    except re.error as e:
        matched, err = False, str(e)
    elapsed = time.time() - start
    return jsonify(matched=matched, elapsed=elapsed, pattern=pattern, error=err)


# --- INJT-14: Incubated vulnerability (benign store stage) -------------------

@app.post("/incubate/store")
def incubate_store():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    iid = uuid.uuid4().hex[:8]
    filename = data.get("filename", "report.txt")
    content = data.get("content", "")
    INCUBATED[iid] = {"id": iid, "filename": filename, "content": content}
    # Stage 1: the value is stored and displayed HTML-escaped - it looks harmless.
    return jsonify(id=iid, stored=True,
                   display=html.escape(filename),
                   note="filename stored; no command executed at store time")


@app.get("/incubate/list")
def incubate_list():
    return jsonify(items=[{"id": v["id"], "display": html.escape(v["filename"])}
                          for v in INCUBATED.values()])


@app.post("/incubate/recall")
def incubate_recall():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    iid = data.get("id", "")
    item = INCUBATED.get(iid)
    if not item:
        return jsonify(error="not found"), 404
    # Stage 2: a DIFFERENT component (the export worker) later uses the stored
    # filename inside a shell command - the incubated payload detonates here.
    try:
        req = urllib.request.Request(
            WORKER_URL + "/export",
            data=urllib.parse.urlencode({"filename": item["filename"], "content": item["content"]}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return jsonify(worker=r.read().decode(errors="replace"))
    except Exception as e:
        return jsonify(error=str(e)), 502


@app.post("/incubate/reset")
def incubate_reset():
    INCUBATED.clear()
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)