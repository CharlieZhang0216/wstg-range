"""AcmePortal crypto/error lab - intentionally vulnerable. Authorised training only.

Covers: WSTG-CRYP-02 (padding oracle), WSTG-CRYP-03 (cleartext channels),
WSTG-CRYP-04 (weak primitives), WSTG-ERRH-01 (improper error handling),
WSTG-ERRH-02 (stack traces via Werkzeug debugger).
"""
import base64
import hashlib
import random
import re
import sqlite3
import threading
import traceback
import uuid

from flask import Flask, Response, jsonify, request
from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

DB_PATH = "/app/lab.db"

# --- WSTG-CRYP-04: hardcoded/static keys, documented for "legacy partners" ----
ECB_KEY = b"ACME-ECB-KEY-000"          # static AES-128 key, ECB mode
DES_KEY = b"Acme1234"                 # 56-bit DES, static key
RC4_KEY = b"AcmeRC4Key"               # RC4, static key
ECB_SECRET = b"FLAG{ecb_mode}"
DES_SECRET = b"FLAG{des_legacy}"
RC4_SECRET = b"FLAG{rc4_legacy}"

# --- WSTG-CRYP-02: AES-CBC with fixed key AND fixed IV, padding oracle --------
ORACLE_KEY = b"0123456789abcdef"
ORACLE_IV = b"ACME-STATIC-IV00"
ORACLE_SECRET = b"FLAG{cbc_oracle}"   # one block incl. PKCS#7 padding

# --- WSTG-CRYP-04: predictable PRNG (fixed-seed MT19937) for reset tokens -----
_rng = random.Random(0xC0FFEE)
_rng_lock = threading.Lock()

USERS = {"alice": "Password123!", "bob": "Summer2024!"}


def _db():
    return sqlite3.connect(DB_PATH)


def _init_db():
    db = _db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, name TEXT, email TEXT, pw_md5 TEXT);
        CREATE TABLE IF NOT EXISTS accounts (
            name TEXT PRIMARY KEY, balance REAL);
        """
    )
    db.execute("DELETE FROM users")
    db.execute("DELETE FROM accounts")
    for i, (name, pw) in enumerate(USERS.items(), start=1):
        db.execute(
            "INSERT INTO users VALUES (?,?,?,?)",
            (i, name, f"{name}@acme.test", hashlib.md5(pw.encode()).hexdigest()),
        )
    db.execute("INSERT INTO accounts VALUES ('alice', 500.0)")
    db.execute("INSERT INTO accounts VALUES ('bob', 120.0)")
    db.commit()
    db.close()


def _md5(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def _api_token(user):
    return "tok_live_" + hashlib.md5((user + ":acme").encode()).hexdigest()


def _pkcs7_ok(pt):
    if not pt:
        return False
    n = pt[-1]
    return 1 <= n <= 16 and pt[-n:] == bytes([n]) * n


# --- pages -------------------------------------------------------------------

@app.get("/")
def home():
    # WSTG-CRYP-03: credentials submitted over plain HTTP, no TLS anywhere here.
    html = """<!doctype html><html><head><title>AcmePortal</title></head><body>
<h1>AcmePortal</h1>
<form action="http://127.0.0.1:8700/login" method="post">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Sign in</button>
</form>
<ul>
  <li><a href="/users">user directory</a></li>
  <li><a href="/legacy/docs">legacy integration docs</a></li>
  <li><a href="/oracle/secret">encrypted vault token</a></li>
  <li><a href="/token">password reset token</a></li>
  <li><a href="/user?id=1">user lookup</a></li>
</ul>
</body></html>"""
    return Response(html, mimetype="text/html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# --- WSTG-CRYP-03: cleartext credentials / tokens over HTTP -------------------

@app.post("/login")
def login():
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    if user in USERS and _md5(pw) == _md5(USERS[user]):
        resp = jsonify({"status": "ok", "api_token": _api_token(user)})
        # Cookie deliberately lacks Secure and HttpOnly.
        resp.headers.add("Set-Cookie", f"session={_md5(user)}; Path=/")
        return resp
    return jsonify({"error": "invalid credentials"}), 401


@app.get("/api/account")
def account():
    # Basic auth over plain HTTP: the Authorization header crosses the wire
    # in base64 (cleartext-equivalent) and the response carries secrets.
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return jsonify({"error": "basic auth required"}), 401
    try:
        user, pw = base64.b64decode(auth[6:]).decode().split(":", 1)
    except Exception:
        return jsonify({"error": "bad authorization header"}), 401
    if user not in USERS or pw != USERS[user]:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({
        "user": user,
        "account_number": "ACME-0042-8817-1234",
        "api_token": _api_token(user),
        "balance": _db().execute(
            "SELECT balance FROM accounts WHERE name=?", (user,)).fetchone()[0],
    })


# --- WSTG-CRYP-04: weak primitives --------------------------------------------

@app.get("/users")
def users():
    # Unsalted MD5 password hashes, publicly listed.
    rows = _db().execute("SELECT id, name, email, pw_md5 FROM users").fetchall()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2], "pw_md5": r[3]}
                    for r in rows])


@app.get("/legacy/docs")
def legacy_docs():
    # "Integration documentation" that ships the static keys.
    return jsonify({
        "note": "legacy partner integration - do not distribute",
        "aes_ecb_key": ECB_KEY.decode(),
        "des_key": DES_KEY.decode(),
        "rc4_key": RC4_KEY.decode(),
    })


@app.get("/ecb/encrypt")
def ecb_encrypt():
    data = request.args.get("data", "").encode()
    ct = AES.new(ECB_KEY, AES.MODE_ECB).encrypt(pad(data, 16))
    return jsonify({"mode": "AES-128-ECB", "ciphertext": ct.hex()})


@app.get("/ecb/secret")
def ecb_secret():
    ct = AES.new(ECB_KEY, AES.MODE_ECB).encrypt(pad(ECB_SECRET, 16))
    return jsonify({"ciphertext": ct.hex()})


@app.get("/des/secret")
def des_secret():
    ct = DES.new(DES_KEY, DES.MODE_ECB).encrypt(pad(DES_SECRET, 8))
    return jsonify({"cipher": "DES-ECB", "ciphertext": ct.hex()})


@app.get("/rc4/secret")
def rc4_secret():
    ct = ARC4.new(RC4_KEY).encrypt(RC4_SECRET)
    return jsonify({"cipher": "RC4", "ciphertext": ct.hex()})


@app.get("/token")
def token():
    # Reset tokens from a fixed-seed Mersenne Twister: fully predictable.
    with _rng_lock:
        t = "%08x%08x" % (_rng.getrandbits(32), _rng.getrandbits(32))
    return jsonify({"reset_token": t})


# --- WSTG-CRYP-02: padding oracle ----------------------------------------------

@app.get("/oracle/secret")
def oracle_secret():
    ct = AES.new(ORACLE_KEY, AES.MODE_CBC, ORACLE_IV).encrypt(pad(ORACLE_SECRET, 16))
    return jsonify({"ciphertext": (ORACLE_IV + ct).hex(),
                    "note": "IV || AES-128-CBC, PKCS#7"})


@app.post("/oracle/decrypt")
def oracle_decrypt():
    data = request.get_json(force=True, silent=True) or {}
    try:
        blob = bytes.fromhex(data.get("ct", ""))
    except ValueError:
        return jsonify({"error": "Invalid data"}), 400
    if len(blob) < 32 or len(blob) % 16:
        return jsonify({"error": "Invalid data"}), 400
    iv, ct = blob[:16], blob[16:]
    pt = AES.new(ORACLE_KEY, AES.MODE_CBC, iv).decrypt(ct)
    # Distinguishable failures: padding error vs content error.
    if not _pkcs7_ok(pt):
        return jsonify({"error": "Padding error"}), 500
    pt = unpad(pt, 16)
    if not re.fullmatch(rb"FLAG\{[a-z_]+\}", pt):
        return jsonify({"error": "Invalid data"}), 400
    return jsonify({"status": "valid"})


# --- WSTG-ERRH-01: improper error handling ------------------------------------

@app.get("/user")
def user_lookup():
    q = request.args.get("id", "")
    sql = f"SELECT id, name, email FROM users WHERE id = {q}"
    try:
        row = _db().execute(sql).fetchone()
    except Exception as e:
        # Debug mode left on: SQL, schema, filesystem path and traceback leak.
        return jsonify({
            "error": str(e),
            "query": sql,
            "db_path": DB_PATH,
            "traceback": traceback.format_exc(),
        }), 500
    if row is None:
        # Distinct response enables user-id enumeration.
        return jsonify({"error": f"user {q} not found"}), 404
    return jsonify({"id": row[0], "name": row[1], "email": row[2]})


@app.get("/api/balance")
def balance():
    name = request.args.get("user", "")
    row = _db().execute("SELECT balance FROM accounts WHERE name=?",
                        (name,)).fetchone()
    if row is None:
        return jsonify({"error": f"account {name} not found"}), 404
    return jsonify({"user": name, "balance": row[0]})


@app.post("/api/transfer")
def transfer():
    data = request.get_json(force=True, silent=True) or {}
    src, dst = data.get("from", ""), data.get("to", "")
    tid = "tx-" + uuid.uuid4().hex[:8]
    try:
        amount = float(data.get("amount", 0))
        db = _db()
        b = db.execute("SELECT balance FROM accounts WHERE name=?",
                       (src,)).fetchone()
        d = db.execute("SELECT balance FROM accounts WHERE name=?",
                       (dst,)).fetchone()
        if b is None or d is None:
            raise ValueError(f"unknown account in transfer {src}->{dst}")
        if amount <= 0 or b[0] < amount:
            raise ValueError("insufficient funds")
        db.execute("UPDATE accounts SET balance=balance-? WHERE name=?",
                   (amount, src))
        db.execute("UPDATE accounts SET balance=balance+? WHERE name=?",
                   (amount, dst))
        db.commit()
    except Exception as e:
        # Swallowed: the caller is told "success" no matter what happened.
        app.logger.error("transfer %s failed: %s", tid, e)
    return jsonify({"status": "success", "transfer_id": tid})


# --- WSTG-ERRH-02: unhandled exception -> Werkzeug interactive debugger --------

@app.get("/boom")
def boom():
    internal_signing_key = "sk_live_51HARDCODEDsigningKEY"
    report_rows = 4213
    raise RuntimeError("report generator failed: quarterly rollup division by zero")


if __name__ == "__main__":
    _init_db()
    # debug=True: full tracebacks + interactive (PIN-protected) console.
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False, threaded=True)