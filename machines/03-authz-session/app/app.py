"""M03 portal - INTENTIONALLY VULNERABLE training target.

Covers WSTG-ATHZ-01..04, WSTG-ATHZ-05 (client side, 05.2) and
WSTG-SESS-01..11. Every weakness below is deliberate. Do not deploy.
"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
import uuid

from flask import Flask, g, jsonify, request

app = Flask(__name__)

AS_INTERNAL = os.environ.get("AS_INTERNAL", "http://as:5000")
AS_PUBLIC = os.environ.get("AS_PUBLIC", "http://127.0.0.1:8310")
EVIL_PUBLIC = os.environ.get("EVIL_PUBLIC", "http://127.0.0.1:8320")
CLIENT_ID = "portal"
CLIENT_SECRET = "portal-secret"
SELF_REDIRECT = "http://127.0.0.1:8300/oauth/callback"
FILES_ROOT = "/srv/files"

# SESS-10: weak HMAC secret, brute-forceable from any small wordlist.
JWT_SECRET = "secret"

USERS = {
    "alice": {"password": "Password123!", "role": "user",
              "email": "alice@corp.lab", "balance": 1000,
              "display_name": "Alice Anderson"},
    "bob": {"password": "Password123!", "role": "user",
            "email": "bob@corp.lab", "balance": 1000,
            "display_name": "Bob Brown"},
    "admin": {"password": "AdminPass123!", "role": "admin",
              "email": "admin@corp.lab", "balance": 9999,
              "display_name": "Site Administrator"},
}

DOCS = {
    1: {"owner": "alice", "title": "Alice private notes",
        "body": "ALICE-SECRET: payroll draft, do not share. token=alice-doc-7f3c"},
    2: {"owner": "bob", "title": "Bob todo",
        "body": "BOB-SECRET: renew gym membership. token=bob-doc-9a1e"},
    3: {"owner": "admin", "title": "Ops runbook",
        "body": "ADMIN-SECRET: root rotation schedule. token=admin-doc-55b2"},
}
ORDERS = {
    1001: {"owner": "alice", "item": "Laptop", "total": "1200.00",
           "address": "1 Alice Way, Labville"},
    1002: {"owner": "bob", "item": "Keyboard", "total": "80.00",
            "address": "2 Bob Street, Labville"},
}
MESSAGES = {
    str(uuid.UUID(int=0xA11CE)): {"owner": "alice", "subject": "Re: bonus",
                                  "body": "ALICE-MSG-SECRET: your bonus is 15%"},
    str(uuid.UUID(int=0xB0B)): {"owner": "bob", "subject": "Re: leave",
                                "body": "BOB-MSG-SECRET: leave approved"},
}

# SESS-01/03/06/07/09/11: server-side session store with sequential ids,
# no rotation, no timeout, no logout invalidation, no client binding.
SESSIONS = {}
SID_SEQ = 1000
RESET_TOKENS = {}
ANNOUNCEMENTS = []
SETTINGS = {"maintenance": False}


def _new_sid():
    global SID_SEQ
    SID_SEQ += 1
    return str(SID_SEQ)


def _record():
    return {"user": None, "created": time.time(), "last_seen": time.time()}


@app.before_request
def _resolve_session():
    # SESS-04: session id accepted from URL query or form field as well as cookie.
    sid = (request.cookies.get("SID")
           or request.args.get("sid")
           or request.form.get("sid"))
    g.sid = sid
    g.sess = None
    g.issue_sid = None
    if sid:
        if sid not in SESSIONS:
            # SESS-03: adopt any client-supplied id (session fixation).
            SESSIONS[sid] = _record()
        SESSIONS[sid]["last_seen"] = time.time()
        g.sess = SESSIONS[sid]


@app.after_request
def _issue_cookie(resp):
    if g.get("issue_sid"):
        # SESS-02: no HttpOnly, no Secure, no SameSite.
        resp.headers.add("Set-Cookie", f"SID={g.issue_sid}; Path=/")
    return resp


def _ensure_session():
    if g.sess is None:
        g.sid = _new_sid()
        SESSIONS[g.sid] = _record()
        g.sess = SESSIONS[g.sid]
        g.issue_sid = g.sid
    return g.sess


def _user():
    if g.sess and g.sess.get("user"):
        return g.sess["user"]
    return None


def _need_login():
    u = _user()
    if not u:
        return None, (jsonify({"error": "login required"}), 401)
    return u, None


# --- basics ------------------------------------------------------------------

@app.get("/health")
def health():
    return "ok"


@app.get("/")
def home():
    s = _ensure_session()
    u = _user()
    return f"""<html><body><h1>CorpPortal (M03 lab)</h1>
<p>user: {u or 'anonymous'}</p>
<form method="post" action="/profile/update">
  <input type="hidden" name="sid" value="{g.sid}">
  <input name="display_name"><button>Save profile</button>
</form>
<a href="/dashboard?sid={g.sid}">Dashboard (URL rewriting)</a>
<a href="/oauth/login">Sign in with CorpSSO</a>
</body></html>"""


@app.get("/dashboard")
def dashboard():
    s = _ensure_session()
    u = _user()
    # SESS-04: sid in URL + hidden field + third-party image => Referer leak.
    return f"""<html><body><h1>Dashboard</h1><p>user: {u or 'anonymous'}</p>
<input type="hidden" name="sid" value="{g.sid}">
<img src="{EVIL_PUBLIC}/pixel" width="1" height="1">
<a href="{EVIL_PUBLIC}/offers">Partner offers</a>
</body></html>"""


@app.post("/login")
def login():
    s = _ensure_session()
    u, p = request.form.get("username", ""), request.form.get("password", "")
    if u in USERS and USERS[u]["password"] == p:
        # SESS-03: session id is NOT rotated on login.
        s["user"] = u
        return jsonify({"ok": True, "user": u, "role": USERS[u]["role"], "sid": g.sid})
    return jsonify({"ok": False, "error": "bad credentials"}), 401


@app.post("/logout")
def logout():
    # SESS-06: only the client cookie is cleared; server record stays valid.
    resp = jsonify({"ok": True, "logged_out": True})
    resp.headers.add("Set-Cookie", "SID=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
    return resp


@app.get("/api/me")
def me():
    u, err = _need_login()
    if err:
        return err
    return jsonify({"user": u, "role": USERS[u]["role"], "email": USERS[u]["email"],
                    "balance": USERS[u]["balance"], "sid": g.sid,
                    "session_created": g.sess["created"],
                    "session_last_seen": g.sess["last_seen"]})


@app.get("/api/session-policy")
def session_policy():
    # SESS-07: no idle or absolute timeout is configured or enforced anywhere.
    return jsonify({"idle_timeout_seconds": None, "absolute_timeout_seconds": None,
                    "rotate_on_login": False, "invalidate_on_logout": False,
                    "invalidate_on_password_change": False, "max_concurrent": None})


@app.post("/debug/age-session")
def age_session():
    """Lab knob: backdate a session so elapsed time can be simulated without waiting."""
    sid = request.form.get("sid") or request.args.get("sid")
    seconds = float(request.form.get("seconds") or request.args.get("seconds") or 0)
    if sid not in SESSIONS:
        return jsonify({"error": "unknown sid"}), 404
    SESSIONS[sid]["created"] -= seconds
    SESSIONS[sid]["last_seen"] -= seconds
    return jsonify({"ok": True, "sid": sid, "aged_seconds": seconds})


# --- ATHZ-03: privilege escalation via mass assignment ------------------------

@app.post("/profile/update")
def profile_update():
    u, err = _need_login()
    if err:
        return err
    for field in ("display_name", "email", "role"):  # 'role' must never be here
        if field in request.form:
            USERS[u][field] = request.form[field]
    return jsonify({"ok": True, "user": u, "role": USERS[u]["role"]})


# --- ATHZ-02: bypassing authorization schema ----------------------------------

@app.get("/admin")
def admin_home():
    u = _user()
    if not u or USERS[u]["role"] != "admin":
        return jsonify({"error": "admin only"}), 403
    return jsonify({"ok": True, "panel": "admin home", "users": len(USERS)})


@app.get("/admin/users")
def admin_users():
    # Forced browsing: no server-side check at all.
    return jsonify([{"username": k, "email": v["email"], "role": v["role"]}
                    for k, v in USERS.items()])


@app.post("/admin/announce")
def admin_announce():
    # State-changing admin POST with no authorization check.
    msg = request.form.get("message", "")
    ANNOUNCEMENTS.append(msg)
    return jsonify({"ok": True, "announcements": ANNOUNCEMENTS}), 201


@app.route("/admin/export", methods=["GET", "POST"])
def admin_export():
    if request.method == "GET":
        u = _user()
        if not u or USERS[u]["role"] != "admin":
            return jsonify({"error": "admin only"}), 403
    # POST path forgot the check: HTTP method switching bypass.
    return "username,email,role\n" + "\n".join(
        f"{k},{v['email']},{v['role']}" for k, v in USERS.items()), 200, {
        "Content-Type": "text/csv"}


@app.get("/admin/panel")
def admin_panel():
    u = _user()
    role = USERS[u]["role"] if u else "anonymous"
    # Client-side-only role check: page + controls shipped to everyone.
    return f"""<html><body><h1>Admin panel</h1>
<div id="adminControls" style="display:none">
  <form method="post" action="/admin/settings">
    <input type="hidden" name="role" value="{role}">
    <input name="maintenance" value="true"><button>Apply</button>
  </form>
</div>
<script>
var role = "{role}";
if (role === "admin") {{ document.getElementById('adminControls').style.display = 'block'; }}
</script></body></html>"""


@app.post("/admin/settings")
def admin_settings():
    # Server trusts the client-supplied 'role' field instead of the session.
    if request.form.get("role") != "admin":
        return jsonify({"error": "admin only"}), 403
    SETTINGS["maintenance"] = request.form.get("maintenance") == "true"
    return jsonify({"ok": True, "settings": SETTINGS})


# --- ATHZ-01: directory traversal / file include ------------------------------

@app.get("/files/download")
def files_download():
    name = request.args.get("name", "")
    path = os.path.join(FILES_ROOT, name)  # no containment check at all
    try:
        with open(path, "r") as fh:
            return fh.read(), 200, {"Content-Type": "text/plain"}
    except OSError:
        return jsonify({"error": "not found"}), 404


@app.get("/files/fetch")
def files_fetch():
    path = request.args.get("path", "")
    path = path.replace("../", "")          # naive single-pass blacklist
    path = urllib.parse.unquote(path)       # decode AFTER filtering
    full = os.path.join(FILES_ROOT, path)
    try:
        with open(full, "r") as fh:
            return fh.read(), 200, {"Content-Type": "text/plain"}
    except OSError:
        return jsonify({"error": "not found"}), 404


# --- ATHZ-04: IDOR -------------------------------------------------------------

@app.get("/documents/<int:doc_id>")
def get_doc(doc_id):
    u, err = _need_login()
    if err:
        return err
    doc = DOCS.get(doc_id)
    if not doc:
        return jsonify({"error": "no such document"}), 404
    return jsonify({"id": doc_id, **doc})  # no ownership check


@app.post("/documents/<int:doc_id>/edit")
def edit_doc(doc_id):
    u, err = _need_login()
    if err:
        return err
    doc = DOCS.get(doc_id)
    if not doc:
        return jsonify({"error": "no such document"}), 404
    if "body" in request.form:
        doc["body"] = request.form["body"]  # cross-user write
    if "title" in request.form:
        doc["title"] = request.form["title"]
    return jsonify({"ok": True, "id": doc_id, **doc})


@app.get("/orders/<int:order_id>")
def get_order(order_id):
    u, err = _need_login()
    if err:
        return err
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "no such order"}), 404
    return jsonify({"id": order_id, **order})


@app.get("/api/users")
def api_users():
    # Leaks the UUID object references of every user's private inbox.
    out = []
    for name, v in USERS.items():
        mid = next((m for m, mv in MESSAGES.items() if mv["owner"] == name), None)
        out.append({"username": name, "role": v["role"], "message_uuid": mid})
    return jsonify(out)


@app.route("/messages/<msg_id>", methods=["GET", "POST"])
def messages(msg_id):
    u, err = _need_login()
    if err:
        return err
    msg = MESSAGES.get(msg_id)
    if not msg:
        return jsonify({"error": "no such message"}), 404
    if request.method == "POST" and "body" in request.form:
        msg["body"] = request.form["body"]
    return jsonify({"id": msg_id, **msg})


# --- SESS-05: CSRF --------------------------------------------------------------

@app.post("/transfer")
def transfer():
    u, err = _need_login()
    if err:
        return err
    to = request.form.get("to", "")
    amount = float(request.form.get("amount", "0"))
    if to not in USERS:
        return jsonify({"error": "unknown recipient"}), 400
    # No CSRF token, no Origin/Referer check, cookie has no SameSite.
    USERS[u]["balance"] -= amount
    USERS[to]["balance"] += amount
    return jsonify({"ok": True, "from": u, "to": to, "amount": amount,
                    "balance": USERS[u]["balance"]})


@app.post("/account/email")
def change_email():
    u, err = _need_login()
    if err:
        return err
    USERS[u]["email"] = request.form.get("email", USERS[u]["email"])
    return jsonify({"ok": True, "email": USERS[u]["email"]})


# --- SESS-11: concurrent sessions ------------------------------------------------

@app.post("/account/password")
def change_password():
    u, err = _need_login()
    if err:
        return err
    USERS[u]["password"] = request.form.get("new_password", USERS[u]["password"])
    # No session invalidation: every existing session stays live.
    return jsonify({"ok": True, "user": u, "sessions_invalidated": 0})


# --- SESS-08: session puzzling -----------------------------------------------------

@app.post("/reset/request")
def reset_request():
    username = request.form.get("username", "")
    if username not in USERS:
        return jsonify({"error": "unknown user"}), 404
    token = uuid.uuid4().hex
    RESET_TOKENS[token] = username
    # Lab stands in for the emailed link; token returned in the response.
    return jsonify({"ok": True, "emailed_to": USERS[username]["email"], "token": token})


@app.post("/reset/confirm")
def reset_confirm():
    s = _ensure_session()
    token = request.form.get("token", "")
    username = RESET_TOKENS.get(token)
    if not username:
        return jsonify({"error": "bad token"}), 400
    # Session puzzling: the reset flow writes the SAME session variable the
    # authenticated area trusts, entering a privileged context with no password.
    s["user"] = username
    return jsonify({"ok": True, "message": "you may now set a new password",
                    "reset_user": username})


# --- ATHZ-05 (05.2): OAuth client weaknesses ---------------------------------------

@app.get("/oauth/login")
def oauth_login():
    # No 'state' parameter generated or stored.
    q = urllib.parse.urlencode({
        "response_type": "code", "client_id": CLIENT_ID,
        "redirect_uri": SELF_REDIRECT, "scope": "read"})
    return "", 302, {"Location": f"{AS_PUBLIC}/oauth/authorize?{q}"}


@app.get("/oauth/callback")
def oauth_callback():
    s = _ensure_session()
    code = request.args.get("code", "")
    # No state validation -> login CSRF. Any code is accepted and bound to
    # whoever's browser hits this URL.
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "redirect_uri": SELF_REDIRECT}).encode()
    try:
        with urllib.request.urlopen(
                urllib.request.Request(AS_INTERNAL + "/oauth/token", data=data),
                timeout=10) as r:
            tok = json.load(r)
        with urllib.request.urlopen(
                AS_INTERNAL + "/oauth/userinfo?access_token=" + tok["access_token"],
                timeout=10) as r:
            info = json.load(r)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    s["user"] = info["sub"]
    return jsonify({"ok": True, "logged_in_as": info["sub"],
                    "access_token": tok["access_token"]})


@app.get("/redirect")
def open_redirect():
    return "", 302, {"Location": request.args.get("to", "/")}


@app.get("/oauth/connected")
def oauth_connected():
    # Access token carried in the URL; third-party image leaks it via Referer.
    token = request.args.get("access_token", "")
    return f"""<html><body><h1>SSO connected</h1>
<p>access_token: {token}</p>
<img src="{EVIL_PUBLIC}/pixel" width="1" height="1">
</body></html>"""


# --- SESS-10: JWT ------------------------------------------------------------------

def _b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_sign(payload):
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"


@app.post("/api/token")
def api_token():
    body = request.get_json(silent=True) or request.form
    u, p = body.get("username", ""), body.get("password", "")
    if u not in USERS or USERS[u]["password"] != p:
        return jsonify({"error": "bad credentials"}), 401
    now = int(time.time())
    return jsonify({"token": _jwt_sign({"sub": u, "role": USERS[u]["role"],
                                        "iat": now, "exp": now + 3600,
                                        "iss": "corp-portal", "aud": "portal-api"})})


def _jwt_verify(token):
    try:
        h, p, s = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(h + "=="))
        payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    except Exception:
        return None
    if header.get("alg") == "none":
        return payload  # accepts unsigned tokens
    if header.get("alg") == "HS256":
        want = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        if _b64u(want) == s:
            return payload  # no exp / aud / iss validation
    return None


def _bearer_payload():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return _jwt_verify(auth[7:])


@app.get("/api/v2/me")
def v2_me():
    p = _bearer_payload()
    if not p:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"sub": p.get("sub"), "role": p.get("role"), "claims": p})


@app.get("/api/v2/admin")
def v2_admin():
    p = _bearer_payload()
    if not p:
        return jsonify({"error": "invalid token"}), 401
    if p.get("role") != "admin":
        return jsonify({"error": "admin only"}), 403
    return jsonify({"ok": True, "admin_data": "ADMIN-JWT-SECRET: backup keys",
                    "sub": p.get("sub")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)