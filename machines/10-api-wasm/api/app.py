"""Acme API platform - intentionally vulnerable training target (machine 10).

REST v1/v2 + GraphQL + inbound webhooks. Every weakness here is deliberate:
  APIT-01  discoverable surface: openapi.json, /debug/routes, .well-known,
           undocumented /v2, hidden legacy endpoint
  APIT-02  BOLA on orders (path id + body id) and documents (UUID)
  APIT-03  full model objects returned; the UI filters client-side
  APIT-04  admin functions guarded by method/path pattern, not by role
  APIT-09  webhook receiver: no HMAC check, no idempotency, trusts claimed
           identity/amount, fetches attacker-supplied callback_url (SSRF)
"""
import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.request
import uuid

from flask import Flask, g, jsonify, request

import graphql_schema

app = Flask(__name__)
DB = "/tmp/acme.db"
PROVIDER_SECRET = os.environ.get("WEBHOOK_PROVIDER_SECRET", "whsec_lab_dev")

# ---------------------------------------------------------------------------
# storage


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def hash_pw(pw):
    return "pbkdf2$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), b"acme-static-salt", 1000).hex()


def init_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, username TEXT UNIQUE, email TEXT, password_hash TEXT,
            api_token TEXT, is_admin INTEGER DEFAULT 0, balance INTEGER DEFAULT 0,
            ssn TEXT, internal_notes TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, owner_id INTEGER, item TEXT, amount INTEGER, status TEXT
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, owner_id INTEGER, title TEXT, content TEXT
        );
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT, type TEXT, account_id INTEGER, amount INTEGER,
            signature_ok INTEGER, callback_url TEXT, callback_response TEXT,
            received_at REAL
        );
        """
    )
    if con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        seed = [
            ("alice", "alice@acme.test", "Password123!", 0, 100, "111-22-3333", "loyal customer"),
            ("bob", "bob@acme.test", "Password123!", 0, 250, "444-55-6666", "churn risk - do not tell him"),
            ("admin", "admin@acme.test", "Adm1nPassword!", 1, 0, "000-00-0000", "platform owner"),
        ]
        for u, e, p, adm, bal, ssn, note in seed:
            con.execute(
                "INSERT INTO users (uuid,username,email,password_hash,api_token,is_admin,balance,ssn,internal_notes)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), u, e, hash_pw(p), f"ak_{u}_{uuid.uuid4().hex}", adm, bal, ssn, note),
            )
        for owner, item, amount, status in [
            (1, "widget", 25, "shipped"), (2, "gadget", 90, "pending"),
            (1, "gizmo", 40, "pending"), (2, "doohickey", 15, "paid"),
        ]:
            con.execute(
                "INSERT INTO orders (uuid,owner_id,item,amount,status) VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), owner, item, amount, status),
            )
        for owner, title, content in [
            (1, "alice-tax-2025.pdf", "Alice tax return: income 82000, account 99112233"),
            (2, "bob-medical-notes.txt", "Bob medical record: condition REDACTED-FOR-LAB, insurer Bupa-Test"),
            (2, "bob-contract-draft.txt", "Bob contract: negotiated rate 450/day, clause 7 pending"),
        ]:
            con.execute(
                "INSERT INTO documents (uuid,owner_id,title,content) VALUES (?,?,?,?)",
                (str(uuid.uuid4()), owner, title, content),
            )
        con.commit()
    con.close()


def user_row(r):
    return dict(r) if r is not None else None


def find_user(uid):
    return user_row(db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())


TOKENS = {}          # token -> user id
LOGIN_FAILURES = {}  # username -> consecutive failure count (REST only)


def current_user():
    tok = (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    uid = TOKENS.get(tok)
    return find_user(uid) if uid else None


def require_user():
    u = current_user()
    if u is None:
        return None, (jsonify({"error": "authentication required"}), 401)
    return u, None


# BFLA by design: the "admin guard" matches a path prefix AND a method pattern
# instead of checking the caller's role. GET /api/admin/* slips through, and
# admin-equivalent routes outside /api/admin/ are never matched at all.
@app.before_request
def admin_pattern_guard():
    if request.path.startswith("/api/admin/") and request.method in ("POST", "PUT", "DELETE"):
        u = current_user()
        if u is None or not u["is_admin"]:
            return jsonify({"error": "admin only"}), 403


# ---------------------------------------------------------------------------
# auth


@app.post("/api/auth/register")
def register():
    d = request.get_json(force=True)
    uname = d.get("username", "")
    if not uname or not d.get("password"):
        return jsonify({"error": "username and password required"}), 400
    if db().execute("SELECT 1 FROM users WHERE username=?", (uname,)).fetchone():
        return jsonify({"error": "username taken"}), 409
    cur = db().execute(
        "INSERT INTO users (uuid,username,email,password_hash,api_token,balance,ssn,internal_notes)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), uname, d.get("email", f"{uname}@acme.test"),
         hash_pw(d["password"]), f"ak_{uname}_{uuid.uuid4().hex}", 0, "999-00-0000", "self-registered"),
    )
    db().commit()
    return jsonify(user_row(find_user(cur.lastrowid))), 201  # full model object, of course


@app.post("/api/auth/login")
def login():
    d = request.get_json(force=True)
    uname = d.get("username", "")
    if LOGIN_FAILURES.get(uname, 0) >= 5:
        return jsonify({"error": "too many failed attempts, locked for this window"}), 429
    r = db().execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
    if r is None or r["password_hash"] != hash_pw(d.get("password", "")):
        LOGIN_FAILURES[uname] = LOGIN_FAILURES.get(uname, 0) + 1
        return jsonify({"error": "bad credentials"}), 401
    LOGIN_FAILURES[uname] = 0
    tok = uuid.uuid4().hex
    TOKENS[tok] = r["id"]
    return jsonify({"token": tok, "user_id": r["id"], "username": uname})


def issue_token(uid):
    tok = uuid.uuid4().hex
    TOKENS[tok] = uid
    return tok


graphql_schema.HOOKS["issue_token"] = issue_token


# ---------------------------------------------------------------------------
# users / documents  (APIT-02 UUID BOLA, APIT-03 excessive data exposure)


@app.get("/api/me")
def me():
    u, err = require_user()
    return err or jsonify(user_row(u))


@app.get("/api/users")
def users():
    u, err = require_user()
    if err:
        return err
    # Excessive data exposure: every column of every user goes over the wire.
    # app.js "protects" the secrets by only rendering username + email.
    rows = db().execute("SELECT * FROM users").fetchall()
    return jsonify([user_row(r) for r in rows])


@app.get("/api/users/<int:uid>")
def get_user(uid):
    u, err = require_user()
    if err:
        return err
    target = find_user(uid)
    if not target:
        return jsonify({"error": "no such user"}), 404
    return jsonify(user_row(target))


@app.get("/api/users/<int:uid>/documents")
def user_documents(uid):
    u, err = require_user()
    if err:
        return err
    # BOLA: no ownership check - any authenticated user lists anyone's documents.
    rows = db().execute("SELECT uuid,title,owner_id FROM documents WHERE owner_id=?", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/documents")
def create_document():
    u, err = require_user()
    if err:
        return err
    d = request.get_json(force=True)
    doc_uuid = str(uuid.uuid4())
    db().execute(
        "INSERT INTO documents (uuid,owner_id,title,content) VALUES (?,?,?,?)",
        (doc_uuid, u["id"], d.get("title", "untitled"), d.get("content", "")),
    )
    db().commit()
    return jsonify({"uuid": doc_uuid, "owner_id": u["id"]}), 201


@app.get("/api/documents/<doc_uuid>")
def get_document(doc_uuid):
    u, err = require_user()
    if err:
        return err
    # BOLA (UUID variant): the UUID is the only "authorization".
    r = db().execute("SELECT * FROM documents WHERE uuid=?", (doc_uuid,)).fetchone()
    if not r:
        return jsonify({"error": "no such document"}), 404
    return jsonify(dict(r))


@app.put("/api/documents/<doc_uuid>")
def put_document(doc_uuid):
    u, err = require_user()
    if err:
        return err
    r = db().execute("SELECT * FROM documents WHERE uuid=?", (doc_uuid,)).fetchone()
    if not r:
        return jsonify({"error": "no such document"}), 404
    d = request.get_json(force=True)
    db().execute("UPDATE documents SET content=? WHERE uuid=?", (d.get("content", r["content"]), doc_uuid))
    db().commit()
    return jsonify(dict(db().execute("SELECT * FROM documents WHERE uuid=?", (doc_uuid,)).fetchone()))


# ---------------------------------------------------------------------------
# orders  (APIT-02 path/body BOLA, APIT-04 BFLA delete)


def order_dict(r):
    return dict(r) if r is not None else None


@app.post("/v1/orders")
def create_order():
    u, err = require_user()
    if err:
        return err
    d = request.get_json(force=True)
    cur = db().execute(
        "INSERT INTO orders (uuid,owner_id,item,amount,status) VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), u["id"], d.get("item", "widget"), int(d.get("amount", 1)), "pending"),
    )
    db().commit()
    return jsonify(order_dict(db().execute("SELECT * FROM orders WHERE id=?", (cur.lastrowid,)).fetchone())), 201


@app.get("/v1/orders")
def list_orders():
    u, err = require_user()
    if err:
        return err
    rows = db().execute("SELECT * FROM orders WHERE owner_id=?", (u["id"],)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/v1/orders/<int:oid>")
def get_order(oid):
    u, err = require_user()
    if err:
        return err
    r = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()  # BOLA: no owner check
    if not r:
        return jsonify({"error": "no such order"}), 404
    return jsonify(order_dict(r))


@app.put("/v1/orders/<int:oid>")
def put_order(oid):
    u, err = require_user()
    if err:
        return err
    r = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()  # BOLA: no owner check
    if not r:
        return jsonify({"error": "no such order"}), 404
    d = request.get_json(force=True)
    db().execute(
        "UPDATE orders SET status=?, item=?, amount=? WHERE id=?",
        (d.get("status", r["status"]), d.get("item", r["item"]), int(d.get("amount", r["amount"])), oid),
    )
    db().commit()
    return jsonify(order_dict(db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()))


@app.post("/v1/orders/update")
def update_order_body():
    u, err = require_user()
    if err:
        return err
    d = request.get_json(force=True)
    oid = int(d.get("order_id", 0))  # BOLA: object id in the body, still no owner check
    r = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not r:
        return jsonify({"error": "no such order"}), 404
    db().execute("UPDATE orders SET status=? WHERE id=?", (d.get("status", r["status"]), oid))
    db().commit()
    return jsonify(order_dict(db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()))


@app.delete("/v1/orders/<int:oid>")
def delete_order(oid):
    u, err = require_user()
    if err:
        return err
    # BFLA: deleting orders is an admin/support function, but only login is checked.
    r = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not r:
        return jsonify({"error": "no such order"}), 404
    db().execute("DELETE FROM orders WHERE id=?", (oid,))
    db().commit()
    return jsonify({"deleted": oid}), 200


# undocumented v2 - richer serializer, absent from openapi.json
@app.get("/v2/orders/<int:oid>")
def get_order_v2(oid):
    u, err = require_user()
    if err:
        return err
    r = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not r:
        return jsonify({"error": "no such order"}), 404
    out = order_dict(r)
    out["owner"] = find_user(r["owner_id"])  # embeds the FULL owner model, secrets included
    return jsonify(out)


# ---------------------------------------------------------------------------
# admin functions (APIT-04)


@app.get("/api/admin/users")
def admin_users():
    u, err = require_user()
    if err:
        return err
    # BFLA: the pattern guard only matches write methods, so GET sails through.
    rows = db().execute("SELECT * FROM users").fetchall()
    return jsonify({"admin_panel": True, "users": [user_row(r) for r in rows]})


@app.post("/api/admin/announce")
def admin_announce():
    return jsonify({"announced": request.get_json(force=True).get("message", "")})


@app.post("/api/users/<int:uid>/role")
def set_role(uid):
    u, err = require_user()
    if err:
        return err
    # BFLA: role management lives outside /api/admin/, so the guard never fires.
    target = find_user(uid)
    if not target:
        return jsonify({"error": "no such user"}), 404
    role = request.get_json(force=True).get("role", "user")
    db().execute("UPDATE users SET is_admin=? WHERE id=?", (1 if role == "admin" else 0, uid))
    db().commit()
    return jsonify(user_row(find_user(uid)))


# ---------------------------------------------------------------------------
# recon surface (APIT-01)


@app.get("/api/legacy/orders")
def legacy_orders():
    # Deprecated 2019 endpoint. Never removed, never authenticated, not in the docs.
    oid = int(request.args.get("order_id", 1))
    r = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not r:
        return jsonify({"error": "no such order"}), 404
    out = order_dict(r)
    owner = find_user(r["owner_id"])
    out["owner_email"] = owner["email"]
    out["owner_token"] = owner["api_token"]
    return jsonify(out)


@app.get("/debug/routes")
def debug_routes():
    # Leftover Flask debug helper - enumerates the entire URL map, no auth.
    rules = sorted(
        [{"path": str(r), "methods": sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS"))}
         for r in app.url_map.iter_rules()],
        key=lambda x: x["path"],
    )
    return jsonify({"werkzeug_debug": True, "count": len(rules), "routes": rules})


OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Acme Public API", "version": "1.0.0",
             "description": "Public v1 surface. Internal/legacy routes are not listed."},
    "paths": {
        "/api/auth/login": {"post": {"summary": "Login"}},
        "/api/auth/register": {"post": {"summary": "Register"}},
        "/api/me": {"get": {"summary": "Current user"}},
        "/v1/orders": {"get": {"summary": "List my orders"}, "post": {"summary": "Create order"}},
        "/v1/orders/{order_id}": {"get": {"summary": "Get order"}, "put": {"summary": "Update order"}},
        "/api/documents/{document_uuid}": {"get": {"summary": "Get document"}},
    },
}


@app.get("/openapi.json")
def openapi():
    return jsonify(OPENAPI)


@app.get("/swagger/")
def swagger():
    items = "".join(f"<li><code>{p}</code> - {', '.join(m.upper() for m in ops)}</li>"
                    for p, ops in OPENAPI["paths"].items())
    return f"""<!doctype html><html><head><title>Acme API docs</title></head><body>
<h1>Acme Public API (v1)</h1><p>Machine-readable spec: <a href="/openapi.json">/openapi.json</a></p>
<ul>{items}</ul></body></html>"""


@app.get("/.well-known/api-catalog")
def api_catalog():
    return jsonify({
        "api_version": "1.0.0",
        "specs": [{"type": "openapi", "url": "/openapi.json"}],
        "graphql": "/graphql",
        "legacy_collection": "/api/legacy/orders",
        "webhook_receiver": "/webhooks/provider",
    })


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "api"})


# ---------------------------------------------------------------------------
# inbound webhooks (APIT-09)


@app.post("/webhooks/provider")
def webhook_provider():
    raw = request.get_data()
    try:
        event = json.loads(raw)
    except Exception:
        return jsonify({"error": "invalid json"}), 400
    sig = request.headers.get("X-Provider-Signature", "")
    expected = hmac.new(PROVIDER_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    signature_ok = hmac.compare_digest(sig, expected)
    # VULN: signature is computed... and then ignored. Forged events accepted.
    account_id = int(event.get("account_id", 0))   # VULN: trusts claimed identity
    amount = int(event.get("amount", 0))           # VULN: trusts claimed amount
    target = find_user(account_id)
    callback_body = None
    callback_url = event.get("callback_url")
    if callback_url:
        # VULN: server-side fetch of an attacker-supplied URL (SSRF), response kept.
        try:
            with urllib.request.urlopen(callback_url, timeout=4) as resp:
                callback_body = resp.read(4096).decode("utf-8", "replace")
        except Exception as e:
            callback_body = f"callback error: {e}"
    if event.get("type") == "payment.succeeded" and target:
        # VULN: no event_id dedup / timestamp window - replays credit again.
        db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, account_id))
    cur = db().execute(
        "INSERT INTO webhook_events (event_id,type,account_id,amount,signature_ok,callback_url,callback_response,received_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (event.get("event_id"), event.get("type"), account_id, amount,
         1 if signature_ok else 0, callback_url, callback_body, time.time()),
    )
    db().commit()
    return jsonify({"accepted": True, "event_record": cur.lastrowid,
                    "credited": amount if target else 0}), 200


@app.get("/api/webhooks/events")
def webhook_events():
    u, err = require_user()
    if err:
        return err
    rows = db().execute("SELECT * FROM webhook_events ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# GraphQL (APIT-99) - mounted with introspection on, no depth/complexity limits


@app.route("/graphql", methods=["GET", "POST"])
def graphql_endpoint():
    if request.method == "GET" and not request.args.get("query"):
        return """<!doctype html><html><body><h1>Acme GraphQL</h1>
<p>POST your queries here. Introspection is enabled.</p></body></html>"""
    if request.method == "POST":
        payload = request.get_json(force=True)
    else:
        payload = {"query": request.args.get("query"),
                   "variables": json.loads(request.args.get("variables") or "null")}
    result = graphql_schema.execute(payload, context={"user": current_user()})
    return jsonify(result)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)