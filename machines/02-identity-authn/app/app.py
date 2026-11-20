"""WSTG M02 - Identity & Authentication portal. INTENTIONALLY VULNERABLE.

Covers WSTG-IDNT-01..05 and WSTG-ATHN-01..14. Every weakness is deliberate,
for authorised security training only. See README.md.
"""
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import struct
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zlib

from flask import Flask, request, session, jsonify, make_response, redirect
from lxml import etree

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

APP = Flask(__name__)
APP.secret_key = "wstg-m02-static-secret"

KC_INTERNAL = os.environ.get("KC_INTERNAL", "http://keycloak:8080")
KC_EXTERNAL = os.environ.get("KC_EXTERNAL", "http://127.0.0.1:8210")
PORTAL_ORIGIN = os.environ.get("PORTAL_ORIGIN", "http://127.0.0.1:8200")
RP_ID = "127.0.0.1"

# ATHN-13: one global static challenge, never bound to a session.
STATIC_CHALLENGE = b"wstg-m02-static-challenge-32bytes!"

DB_PATH = "/data/portal.db"
DB_LOCK = threading.Lock()
DB = sqlite3.connect(DB_PATH, check_same_thread=False)
DB.row_factory = sqlite3.Row

FAILS = {}          # ATHN-03: lockout keyed on (username, client-controlled IP)
RESET_TOKENS = {}   # ATHN-09: token -> username, no expiry
RESET_COUNTER = [1000]
BACKUP_CODES = [f"{i:06d}" for i in range(1, 11)]  # ATHN-11: enumerable


def db_exec(sql, args=()):
    with DB_LOCK:
        cur = DB.execute(sql, args)
        DB.commit()
        return cur


def db_all(sql, args=()):
    with DB_LOCK:
        return [dict(r) for r in DB.execute(sql, args).fetchall()]


def db_one(sql, args=()):
    rows = db_all(sql, args)
    return rows[0] if rows else None


def init_db():
    db_exec("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, password TEXT, email TEXT, role TEXT,
        mfa_enabled INTEGER DEFAULT 0, security_a TEXT DEFAULT 'smith',
        created_at REAL)""")  # NOTE: no UNIQUE constraint on username (IDNT-02)
    db_exec("""CREATE TABLE IF NOT EXISTS webauthn_creds(
        cred_id TEXT PRIMARY KEY, username TEXT, public_key BLOB,
        sign_count INTEGER DEFAULT 0)""")
    if db_one("SELECT id FROM users LIMIT 1"):
        return
    seeds = [
        ("admin", "admin", "admin@corp.lab", "admin", 0),
        ("admin", "password", "admin@corp.lab", "admin", 0),   # duplicate default
        ("operator", "operator", "operator@corp.lab", "editor", 0),
        ("administrator", "administrator", "administrator@corp.lab", "admin", 0),
        ("test", "test", "test@corp.lab", "viewer", 0),
        ("alice", "Password123!", "alice@corp.lab", "viewer", 0),
        ("lockme", "Correct123!", "lockme@corp.lab", "viewer", 0),
        ("mobileuser", "Mobile123!", "mobileuser@corp.lab", "viewer", 1),
        ("mfauser", "Mfa123!", "mfauser@corp.lab", "viewer", 1),
    ]
    for u, p, e, r, m in seeds:
        db_exec("INSERT INTO users(username,password,email,role,mfa_enabled,created_at) "
                "VALUES(?,?,?,?,?,?)", (u, p, e, r, m, time.time()))


def find_user(username):
    return db_one("SELECT * FROM users WHERE username=? ORDER BY id LIMIT 1", (username,))


def check_creds(username, password):
    return db_one("SELECT * FROM users WHERE username=? AND password=? ORDER BY id LIMIT 1",
                  (username, password))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def totp(seed_b32, t=None):
    key = base64.b32decode(seed_b32 + "=" * (-len(seed_b32) % 8))
    counter = int((t or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def mfa_seed(username):
    # ATHN-11: predictable seed derived only from the username.
    return base64.b32encode(username.encode()).decode().rstrip("=")


def current_user():
    """Session, then remember-me cookie (ATHN-05), then client flag (ATHN-04/11)."""
    if session.get("user"):
        return find_user(session["user"])
    rem = request.cookies.get("remember_me")
    if rem:
        try:
            u, p = base64.b64decode(rem).decode().split(":", 1)
            row = check_creds(u, p)
            if row:
                return row
        except Exception:
            pass
    return None


def client_ip():
    # ATHN-03: lockout bucket keyed on a client-controlled header.
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?")


def fields():
    base = request.args.to_dict()
    if request.is_json:
        base.update(request.get_json(silent=True) or {})
    else:
        base.update(request.form.to_dict())
    return base


def do_login(username, password, remember=False):
    f = fields()
    if f.get("reset_counter") == "1":
        FAILS.pop((username, client_ip()), None)
    key = (username, client_ip())
    if FAILS.get(key, 0) >= 5:
        return jsonify({"error": "locked", "message": "Account locked (5 failures)"}), 423
    if not find_user(username):
        return jsonify({"error": "no_such_user",
                        "message": f"No such user: {username}"}), 401
    row = check_creds(username, password)
    if not row:
        FAILS[key] = FAILS.get(key, 0) + 1
        return jsonify({"error": "invalid_password",
                        "message": f"Invalid password for existing user {username}",
                        "failures": FAILS[key]}), 401
    FAILS.pop(key, None)
    session["user"] = username
    session["mfa_passed"] = not row["mfa_enabled"]
    resp = make_response(jsonify({
        "status": "ok", "user": username, "role": row["role"],
        "mfa_required": bool(row["mfa_enabled"]),
        "next": "/mfa/verify" if row["mfa_enabled"] else "/account",
    }))
    if remember:
        # ATHN-05: credentials stored base64 in a cookie.
        resp.set_cookie("remember_me", base64.b64encode(f"{username}:{password}".encode()).decode(),
                        httponly=False)
    return resp


# ---------------------------------------------------------------- basic pages

@APP.get("/health")
def health():
    return jsonify({"status": "ok"})


@APP.get("/")
def index():
    return ("<html><body><h1>Corp Portal (M02)</h1><ul>"
            "<li><a href='/login'>Login</a></li><li><a href='/register'>Register</a></li>"
            "<li><a href='/account'>Account</a></li><li><a href='/api/roles'>Roles</a></li>"
            "<li><a href='/saml/login'>SAML login</a></li><li><a href='/oidc/login'>OIDC login</a></li>"
            "</ul></body></html>")


@APP.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and request.args.get("username"):
        # ATHN-07: GET-based login, credentials in the URL query string.
        return do_login(request.args.get("username", ""), request.args.get("password", ""),
                        request.args.get("remember") == "1")
    if request.method == "POST":
        f = fields()
        return do_login(f.get("username", ""), f.get("password", ""),
                        str(f.get("remember", "")) in ("1", "true", "on"))
    # ATHN-01: form posts credentials over plain HTTP, absolute http:// action.
    return make_response(
        "<html><body><h1>Login</h1>"
        f"<form method='POST' action='{PORTAL_ORIGIN}/login'>"
        "<input name='username'><input type='password' name='password'>"
        "<label><input type='checkbox' name='remember' value='1'>Remember me</label>"
        "<button>Sign in</button></form></body></html>")


@APP.get("/logout")
def logout():
    session.clear()
    resp = make_response(redirect("/"))
    resp.delete_cookie("remember_me")
    return resp


@APP.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return ("<html><body><form method='POST' action='/register'>"
                "<input name='username'><input name='password'><input name='email'>"
                "<button>Register</button></form></body></html>")
    f = fields()
    username = f.get("username", "")
    # IDNT-05: no username policy at all (empty / 1-char / unicode / spaces accepted).
    # IDNT-02: no email verification, disposable domains accepted, duplicates allowed.
    # IDNT-01: role is client-supplied and honoured.
    exists = find_user(username) is not None
    cur = db_exec(
        "INSERT INTO users(username,password,email,role,mfa_enabled,security_a,created_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (username, f.get("password", ""), f.get("email", ""),
         f.get("role", "viewer"), 1 if str(f.get("mfa", "")) in ("1", "true") else 0,
         f.get("maiden", "smith"), time.time()))
    return jsonify({
        "status": "created", "id": cur.lastrowid, "username": username,
        "role": f.get("role", "viewer"), "email_verified": False, "active": True,
        "username_exists": exists,
        "message": "username already exists (duplicate account created)" if exists else "welcome",
    }), 201


@APP.get("/whoami")
def whoami():
    row = current_user()
    if not row:
        return jsonify({"user": None}), 401
    return jsonify({"user": row["username"], "role": row["role"],
                    "mfa_passed": bool(session.get("mfa_passed")),
                    "mfa_pending": bool(row["mfa_enabled"] and not session.get("mfa_passed"))})


# ------------------------------------------------------- IDNT-01 role matrix

@APP.get("/api/roles")
def roles():
    return jsonify({
        "documented": ["viewer", "editor", "admin"],
        "roles": {
            "viewer": ["read:own"],
            "editor": ["read:own", "write:own"],
            "admin": ["read:*", "write:*", "manage:users"],
            "superadmin": ["*"],          # undocumented, wildcard
            "root": ["*"],                # undocumented, wildcard
        },
        "self_assignable_at_registration": True,
    })


@APP.get("/admin/panel")
def admin_panel():
    row = current_user()
    if not row or row["role"] not in ("admin", "superadmin", "root"):
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"panel": "user management", "as": row["username"], "role": row["role"],
                    "permissions": ["*"] if row["role"] in ("superadmin", "root") else ["manage:users"]})


# ------------------------------------------- IDNT-03 provisioning / IDNT-02

@APP.post("/api/provision/bulk")
def bulk_provision():
    # No authentication or authorization at all.
    f = fields()
    count = min(int(f.get("count", 1)), 50)
    prefix = f.get("prefix", "svc")
    created = []
    for i in range(count):
        name = f"{prefix}{int(time.time()) % 100000:05d}{i:02d}"
        cur = db_exec("INSERT INTO users(username,password,email,role,created_at) "
                      "VALUES(?,?,?,?,?)",
                      (name, "Welcome123!", f"{name}@corp.lab", f.get("role", "service"), time.time()))
        created.append({"id": cur.lastrowid, "username": name, "password": "Welcome123!"})
    return jsonify({"created": created, "authorized": False}), 201


@APP.get("/api/users")
def list_users():
    name = request.args.get("username")
    if name is not None:
        rows = db_all("SELECT id,username,email,role FROM users WHERE username=? ORDER BY id", (name,))
    else:
        rows = db_all("SELECT id,username,email,role FROM users ORDER BY id LIMIT 100")
    return jsonify({"users": rows, "count": len(rows)})


@APP.get("/api/users/<int:uid>")
def get_user(uid):
    row = db_one("SELECT id,username,email,role FROM users WHERE id=?", (uid,))
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(row)


# ------------------------------------------------- ATHN-04/06 account page

@APP.get("/account")
def account():
    row = current_user()
    # ATHN-04: parameter/cookie tampering bypasses authentication entirely.
    if not row and (request.args.get("authenticated") == "true"
                    or request.cookies.get("authenticated") == "true"):
        row = find_user("admin")
    if not row:
        return jsonify({"error": "authentication required"}), 401
    if row["mfa_enabled"] and not session.get("mfa_passed") \
            and request.cookies.get("mfa_passed") != "1":
        return jsonify({"error": "mfa_required", "next": "/mfa/verify"}), 403
    resp = make_response(jsonify({
        "username": row["username"], "email": row["email"], "role": row["role"],
        "api_key": "ak-live-m02-9f3c9d21e8b44a0f", "account_id": row["id"],
    }))
    # ATHN-06: authenticated, sensitive page cached by browsers and proxies.
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


# ------------------------------------------------------- ATHN-07 basic auth

@APP.get("/basic/profile")
def basic_profile():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        resp = make_response(jsonify({"error": "basic auth required"}), 401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="corp-portal"'
        return resp
    try:
        u, p = base64.b64decode(auth[6:]).decode().split(":", 1)
    except Exception:
        return jsonify({"error": "bad header"}), 400
    row = check_creds(u, p)
    if not row:
        resp = make_response(jsonify({"error": "invalid credentials"}), 401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="corp-portal"'
        return resp
    return jsonify({"username": row["username"], "email": row["email"], "channel": "basic-over-http"})


# --------------------------------------------------- ATHN-08 security questions

@APP.get("/recover/questions")
def recover_questions():
    name = request.args.get("username", "")
    if not find_user(name):
        return jsonify({"error": "no such user"}), 404
    return jsonify({"username": name, "questions": [
        {"id": "maiden", "text": "What is your mother's maiden name?"},
        {"id": "pet", "text": "What was your first pet's name?"},
    ]})


@APP.post("/recover/answer")
def recover_answer():
    f = fields()
    name = f.get("username", "")
    row = find_user(name)
    if not row:
        return jsonify({"error": "no such user"}), 404
    # No rate limiting, tiny answer space (default answer is 'smith').
    if f.get("answer", "").lower() in (row["security_a"].lower(), "fluffy"):
        token = str(RESET_COUNTER[0]); RESET_COUNTER[0] += 1
        RESET_TOKENS[token] = name
        return jsonify({"status": "verified", "reset_token": token})
    return jsonify({"error": "wrong answer"}), 401


# ------------------------------------------------------ ATHN-09 password reset

@APP.post("/reset/request")
def reset_request():
    f = fields()
    name = f.get("username", "")
    if not find_user(name):
        return jsonify({"error": "no such user"}), 404
    token = str(RESET_COUNTER[0]); RESET_COUNTER[0] += 1   # predictable, 4 digits
    RESET_TOKENS[token] = name                              # no expiry
    # Host-header poisoning: link built from the request Host header.
    link = f"http://{request.host}/reset/confirm?token={token}"
    return jsonify({"status": "sent", "token": token, "reset_link": link, "expires": None})


@APP.route("/reset/confirm", methods=["GET", "POST"])
def reset_confirm():
    f = fields()
    token = f.get("token", "")
    if token not in RESET_TOKENS:
        return jsonify({"error": "invalid token"}), 400
    if request.method == "GET":
        return ("<html><body><form method='POST' action='/reset/confirm'>"
                f"<input type='hidden' name='token' value='{token}'>"
                "<input type='password' name='new_password'><button>Reset</button></form></body></html>")
    name = RESET_TOKENS[token]
    # No old-password check, token stays valid (no expiry / single-use).
    db_exec("UPDATE users SET password=? WHERE username=?", (f.get("new_password", ""), name))
    return jsonify({"status": "password_reset", "username": name, "old_password_required": False})


# ------------------------------------------------------------- ATHN-11 MFA

@APP.post("/mfa/enable")
def mfa_enable():
    row = current_user()
    if not row:
        return jsonify({"error": "auth required"}), 401
    db_exec("UPDATE users SET mfa_enabled=1 WHERE username=?", (row["username"],))
    return jsonify({"seed": mfa_seed(row["username"]), "backup_codes": BACKUP_CODES})


@APP.post("/mfa/verify")
def mfa_verify():
    name = session.get("user")
    if not name:
        return jsonify({"error": "login first"}), 401
    f = fields()
    code = f.get("code", "")
    seed = mfa_seed(name)
    if code in BACKUP_CODES or code == totp(seed) or code == totp(seed, time.time() - 30):
        session["mfa_passed"] = True
        return jsonify({"status": "mfa_passed"})
    return jsonify({"error": "bad code"}), 401


@APP.get("/mfa/dashboard")
def mfa_dashboard():
    # ATHN-11: post-MFA page only checks login, never mfa_passed.
    row = current_user()
    if not row:
        return jsonify({"error": "auth required"}), 401
    resp = make_response(jsonify({"dashboard": "sensitive post-MFA data", "user": row["username"],
                                  "mfa_passed": bool(session.get("mfa_passed"))}))
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


# --------------------------------------------------- ATHN-10 mobile channel

@APP.route("/mobile/login", methods=["GET", "POST"])
def mobile_login():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            u, p = base64.b64decode(auth[6:]).decode().split(":", 1)
        except Exception:
            return jsonify({"error": "bad header"}), 400
    else:
        f = fields()
        u, p = f.get("username", ""), f.get("password", "")
    # No lockout, no MFA, no rate limit on the mobile channel.
    row = check_creds(u, p)
    if not row:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": base64.b64encode(f"{u}:{p}".encode()).decode(),
                    "mfa_skipped": bool(row["mfa_enabled"]), "lockout": "none"})


@APP.get("/mobile/profile")
def mobile_profile():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "bearer token required"}), 401
    try:
        u, p = base64.b64decode(auth[7:]).decode().split(":", 1)
    except Exception:
        return jsonify({"error": "bad token"}), 401
    row = check_creds(u, p)
    if not row:
        return jsonify({"error": "invalid token"}), 401
    return jsonify({"username": row["username"], "email": row["email"], "channel": "mobile"})


# ------------------------------------------------------------- ATHN-12 SAML

SP_ENTITY = "portal-sp"


@APP.get("/saml/metadata")
def saml_metadata():
    xml = (f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY}">'
           f'<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
           f'<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
           f'Location="{PORTAL_ORIGIN}/saml/acs" index="0"/>'
           f'</SPSSODescriptor></EntityDescriptor>')
    return make_response(xml, 200, {"Content-Type": "application/samlmetadata+xml"})


@APP.get("/saml/login")
def saml_login():
    req = (f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
           f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{uuid.uuid4()}" '
           f'Version="2.0" IssueInstant="{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}" '
           f'AssertionConsumerServiceURL="{PORTAL_ORIGIN}/saml/acs">'
           f'<saml:Issuer>{SP_ENTITY}</saml:Issuer></samlp:AuthnRequest>')
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = co.compress(req.encode()) + co.flush()
    qs = urllib.parse.urlencode({"SAMLRequest": base64.b64encode(deflated).decode(),
                                 "RelayState": PORTAL_ORIGIN + "/account"})
    return redirect(f"{KC_EXTERNAL}/realms/lab/protocol/saml?{qs}")


@APP.post("/saml/acs")
def saml_acs():
    raw = request.form.get("SAMLResponse", "")
    try:
        xml = base64.b64decode(raw)
        root = etree.fromstring(xml)
    except Exception as e:
        return jsonify({"error": f"bad SAMLResponse: {e}"}), 400
    # WEAK: no signature validation, no Audience/Recipient/NotOnOrAfter checks.
    nids = root.xpath("//*[local-name()='NameID']")
    if not nids:
        return jsonify({"error": "no NameID"}), 400
    # WEAK: naive .text read - XML comment injection truncates the NameID.
    name = (nids[0].text or "").split("@")[0]
    if not name:
        return jsonify({"error": "empty NameID"}), 400
    if not find_user(name):
        db_exec("INSERT INTO users(username,password,email,role,created_at) VALUES(?,?,?,?,?)",
                (name, uuid.uuid4().hex, f"{name}@corp.lab", "viewer", time.time()))
    session["user"] = name
    session["mfa_passed"] = True
    return jsonify({"status": "saml_login_ok", "user": name,
                    "signature_checked": False, "conditions_checked": False})


# --------------------------------------------------------- ATHN-13 WebAuthn

@APP.post("/webauthn/register/options")
def wa_reg_options():
    f = fields()
    name = f.get("username", "")
    opts = generate_registration_options(
        rp_id=RP_ID, rp_name="Corp Portal",
        user_id=name.encode() or b"anon", user_name=name or "anon", user_display_name=name or "anon",
        challenge=STATIC_CHALLENGE,                       # WEAK: static, not per-session
        attestation=AttestationConveyancePreference.NONE,  # WEAK: no attestation
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.DISCOURAGED),  # WEAK: UV not required
    )
    return make_response(options_to_json(opts), 200, {"Content-Type": "application/json"})


@APP.post("/webauthn/register/complete")
def wa_reg_complete():
    f = fields()
    name = f.get("username", "")
    cred = f.get("credential", f)
    if isinstance(cred, dict):
        cred = json.dumps(cred)
    try:
        ver = verify_registration_response(
            credential=cred, expected_challenge=STATIC_CHALLENGE,
            expected_rp_id=RP_ID, expected_origin=PORTAL_ORIGIN,
            require_user_verification=False)  # WEAK: UV not enforced
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    db_exec("INSERT OR REPLACE INTO webauthn_creds(cred_id,username,public_key,sign_count) "
            "VALUES(?,?,?,?)",
            (bytes_to_base64url(ver.credential_id), name, ver.credential_public_key, ver.sign_count))
    session["user"] = name
    return jsonify({"status": "registered", "credential_id": bytes_to_base64url(ver.credential_id),
                    "attestation_verified": False})


@APP.get("/webauthn/credentials")
def wa_creds():
    # WEAK: credential-id enumeration for any username, unauthenticated.
    name = request.args.get("username", "")
    rows = db_all("SELECT cred_id,username,sign_count FROM webauthn_creds WHERE username=?", (name,))
    return jsonify({"credentials": rows})


@APP.post("/webauthn/login/options")
def wa_login_options():
    f = fields()
    name = f.get("username", "")
    rows = db_all("SELECT cred_id FROM webauthn_creds WHERE username=?", (name,))
    opts = generate_authentication_options(
        rp_id=RP_ID, challenge=STATIC_CHALLENGE,          # WEAK: static challenge
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["cred_id"]))
                           for r in rows],
        user_verification=UserVerificationRequirement.DISCOURAGED)
    return make_response(options_to_json(opts), 200, {"Content-Type": "application/json"})


@APP.post("/webauthn/login/complete")
def wa_login_complete():
    f = fields()
    cred = f.get("credential", f)
    cid = cred.get("id") or cred.get("rawId") or ""
    row = db_one("SELECT * FROM webauthn_creds WHERE cred_id=?", (cid,))
    if not row:
        return jsonify({"error": "unknown credential"}), 400
    if isinstance(cred, dict):
        cred = json.dumps(cred)
    try:
        ver = verify_authentication_response(
            credential=cred, expected_challenge=STATIC_CHALLENGE,
            expected_rp_id=RP_ID, expected_origin=PORTAL_ORIGIN,
            credential_public_key=row["public_key"],
            credential_current_sign_count=row["sign_count"],
            require_user_verification=False)  # WEAK: UV not enforced
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    db_exec("UPDATE webauthn_creds SET sign_count=? WHERE cred_id=?", (ver.new_sign_count, cid))
    session["user"] = row["username"]
    session["mfa_passed"] = True
    return jsonify({"status": "authenticated", "user": row["username"],
                    "challenge_session_bound": False})


# ------------------------------------------------------------- ATHN-14 OIDC

def decode_id_token_unverified(token):
    # WEAK: no signature verification (alg=none accepted), no nonce/aud/iss checks.
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("malformed token")
    return json.loads(b64u_dec(parts[1]))


@APP.get("/oidc/login")
def oidc_login():
    post = request.args.get("redirect_uri", "")
    if post:
        # WEAK: substring match instead of exact allow-list.
        if "127.0.0.1:8200" not in post:
            return jsonify({"error": "redirect_uri not allowed"}), 400
        session["post_login_redirect"] = post
    state, nonce = uuid.uuid4().hex, uuid.uuid4().hex
    session["oidc_state"], session["oidc_nonce"] = state, nonce
    qs = urllib.parse.urlencode({
        "client_id": "portal-rp", "response_type": "code", "scope": "openid",
        "redirect_uri": PORTAL_ORIGIN + "/oidc/callback", "state": state, "nonce": nonce,
    })
    return redirect(f"{KC_EXTERNAL}/realms/lab/protocol/openid-connect/auth?{qs}")


@APP.route("/oidc/callback")
def oidc_callback():
    token = request.args.get("id_token", "")
    if not token and request.args.get("code"):
        # Real code exchange against Keycloak (backchannel).
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code", "client_id": "portal-rp",
            "code": request.args["code"], "redirect_uri": PORTAL_ORIGIN + "/oidc/callback",
        }).encode()
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(KC_INTERNAL + "/realms/lab/protocol/openid-connect/token",
                                           data=data), timeout=10) as r:
                token = json.loads(r.read()).get("id_token", "")
        except Exception as e:
            return jsonify({"error": f"token exchange failed: {e}"}), 400
    if not token:
        return jsonify({"error": "missing code/id_token"}), 400
    # WEAK: state and nonce are never compared to the session values.
    try:
        claims = decode_id_token_unverified(token)
    except Exception as e:
        return jsonify({"error": f"bad id_token: {e}"}), 400
    name = claims.get("preferred_username") or claims.get("sub") or "unknown"
    if not find_user(name):
        db_exec("INSERT INTO users(username,password,email,role,created_at) VALUES(?,?,?,?,?)",
                (name, uuid.uuid4().hex, claims.get("email", f"{name}@corp.lab"),
                 claims.get("role", "viewer"), time.time()))
    session["user"] = name
    session["mfa_passed"] = True
    post = session.pop("post_login_redirect", "")
    if post:
        # WEAK: tokens leaked in the URL fragment to the (open) redirect target.
        sep = "&" if "#" in post else "#"
        return redirect(f"{post}{sep}id_token={token}&access_token={token}&token_type=Bearer")
    return redirect("/account")


init_db()

if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=5000, threaded=True)