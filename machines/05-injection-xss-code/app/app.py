"""M05 main application - intentionally vulnerable.

Owns: WSTG-INJT-01 (reflected XSS), 02 (stored XSS), 03 (verb tampering),
04 (HPP gateway side), 12 (command injection), 18 (SSTI), 25 (Unicode).
Every weakness below is deliberate training material.
"""
import json
import os
import sqlite3
import subprocess
import unicodedata
import urllib.parse
import urllib.request

from flask import Flask, Response, jsonify, render_template_string, request
from mako.template import Template as MakoTemplate

app = Flask(__name__)

DB = "/data/lab.db"
PAGES = "/srv/data/pages"
API_URL = os.environ.get("API_URL", "http://api:5000")
ADMIN_TOKEN = "s3cr3t-admin-token"          # synthetic, not a real credential
FLAG_SSTI = os.environ.get("FLAG_SSTI", "WSTG-M05{ssti}")
FLAG_ADMIN = os.environ.get("FLAG_ADMIN", "WSTG-M05{verb}")
FLAG_HPP = os.environ.get("FLAG_HPP", "WSTG-M05{hpp}")
FLAG_UNICODE = os.environ.get("FLAG_UNICODE", "WSTG-M05{unicode}")

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "FOO", "BAR"]


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs("/data", exist_ok=True)
    os.makedirs(PAGES, exist_ok=True)
    # Flag reachable only through code/template injection, never served by a route.
    with open("/flag.txt", "w") as fh:
        fh.write(FLAG_SSTI + "\n")
    with open(os.path.join(PAGES, "welcome.txt"), "w") as fh:
        fh.write("Welcome to the M05 document store.\n")
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT, body TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS profiles (user TEXT PRIMARY KEY, bio TEXT);
        CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, role TEXT);
        CREATE TABLE IF NOT EXISTS products (name TEXT, price TEXT);
        CREATE TABLE IF NOT EXISTS vault (name TEXT, secret TEXT);
        """
    )
    conn.execute("DELETE FROM products")
    conn.executemany("INSERT INTO products VALUES (?,?)",
                     [("widget", "9.99"), ("gadget", "19.99"), ("sprocket", "4.50")])
    conn.execute("DELETE FROM vault")
    conn.executemany("INSERT INTO vault VALUES (?,?)",
                     [("api_key", "vault-secret-7f3c9d21e8b4"),
                      ("db_password", "Sup3rS3cretLabPW")])
    conn.execute("INSERT OR IGNORE INTO users VALUES ('alice','user')")
    conn.execute("INSERT OR IGNORE INTO users VALUES ('bob','user')")
    conn.commit()
    conn.close()


PORTAL = """<html><head><title>M05 Injection / XSS / Code</title></head><body>
<h1>M05 - Injection, XSS and Code Execution range</h1>
<p>Intentionally vulnerable training target. Authorised testing only.</p>
<ul>
  <li><a href="/search?q=hello">/search?q=</a> - reflected XSS (HTML body, attribute, JS string)</li>
  <li><a href="/guestbook">/guestbook</a> - stored XSS (POST comment=, author=)</li>
  <li><a href="/profile">/profile</a> - stored XSS in a JS context (POST bio=)</li>
  <li><a href="/admin/panel">/admin/panel</a> - auth enforced on GET/POST only</li>
  <li><a href="/admin/users/delete?user=bob">/admin/users/delete?user=</a> - same verb gap</li>
  <li><a href="/hpp/admin?role=user">/hpp/admin?role=</a> - front layer reads first, app reads last</li>
  <li>/hpp/transfer (POST action=&amp;amount=) - gateway validates first, backend takes last</li>
  <li><a href="/net/ping?host=127.0.0.1">/net/ping?host=</a> - command injection</li>
  <li><a href="/net/lookup?host=localhost">/net/lookup?host=</a> - blind command injection</li>
  <li><a href="/tpl/jinja?name=world">/tpl/jinja?name=</a> - Jinja2 SSTI</li>
  <li><a href="/tpl/mako?name=world">/tpl/mako?name=</a> - Mako SSTI</li>
  <li><a href="/unicode/download?file=welcome.txt">/unicode/download?file=</a> - blacklist before NFKC</li>
  <li><a href="/unicode/whoami?user=guest">/unicode/whoami?user=</a> - equality check before NFKC</li>
  <li><a href="/unicode/search?q=widget">/unicode/search?q=</a> - blacklist before casefold</li>
  <li><a href="/unicode/reflect?text=hi">/unicode/reflect?text=</a> - XSS filter before NFKC</li>
  <li><a href="/ssi/">/ssi/</a> - Apache mod_include (SSI injection)</li>
  <li><a href="/php/">/php/</a> - PHP eval() + LFI/RFI</li>
  <li><a href="/proto/">/proto/</a> - Node prototype pollution</li>
</ul>
</body></html>"""


@app.route("/health")
def health():
    return jsonify(status="ok", service="m05-app")


@app.route("/")
def index():
    return Response(PORTAL, mimetype="text/html")


# --- WSTG-INJT-01: reflected XSS in three distinct contexts -------------------

@app.route("/search", methods=["GET", "POST"])
def search():
    q = request.values.get("q", "")
    # No output encoding anywhere: HTML body, HTML attribute and JS string.
    html = (
        "<html><head><title>Search</title></head><body>\n"
        f"<h1>Results for {q}</h1>\n"
        f'<form action="/search" method="get"><input type="text" name="q" value="{q}">'
        "<button>Search</button></form>\n"
        f'<div id="results">0 results for {q}</div>\n'
        f'<script>var q = "{q}"; document.getElementById("results").innerHTML = "query: " + q;</script>\n'
        "</body></html>"
    )
    return Response(html, mimetype="text/html")


# --- WSTG-INJT-02: stored XSS -------------------------------------------------

@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    conn = db()
    if request.method == "POST":
        author = request.form.get("author") or request.cookies.get("user") or "anon"
        body = request.form.get("comment", "")
        cur = conn.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, body))
        conn.commit()
        cid = cur.lastrowid
        conn.close()
        return jsonify(id=cid, author=author, stored=body)
    rows = conn.execute("SELECT id, author, body FROM comments ORDER BY id").fetchall()
    conn.close()
    items = "\n".join(
        f'<div class="comment" id="c{r["id"]}" data-author="{r["author"]}">'
        f'<span class="author">{r["author"]}</span> wrote: {r["body"]}</div>'
        for r in rows
    )
    html = (
        "<html><body><h1>Guestbook</h1>\n"
        '<form method="post" action="/guestbook">'
        '<input name="author" placeholder="name"><textarea name="comment"></textarea>'
        "<button>Sign</button></form>\n"
        f'<div id="comments">{items}</div>\n'
        "</body></html>"
    )
    return Response(html, mimetype="text/html")


@app.route("/guestbook/delete", methods=["POST"])
def guestbook_delete():
    cid = request.form.get("id", "")
    conn = db()
    conn.execute("DELETE FROM comments WHERE id = ?", (cid,))
    conn.commit()
    conn.close()
    return jsonify(deleted=cid)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = request.cookies.get("user", "guest")
    conn = db()
    if request.method == "POST":
        bio = request.form.get("bio", "")
        conn.execute("INSERT OR REPLACE INTO profiles (user, bio) VALUES (?,?)", (user, bio))
        conn.commit()
    row = conn.execute("SELECT bio FROM profiles WHERE user = ?", (user,)).fetchone()
    conn.close()
    bio = row["bio"] if row else ""
    # Stored value lands unescaped in a JS string literal and in an attribute.
    html = (
        f"<html><body><h1>Profile of {user}</h1>\n"
        f'<div class="bio" title="{bio}">{bio}</div>\n'
        f'<script>var bio = "{bio}";</script>\n'
        '<form method="post"><textarea name="bio"></textarea><button>Save</button></form>'
        "</body></html>"
    )
    return Response(html, mimetype="text/html")


# --- WSTG-INJT-03: HTTP verb tampering ----------------------------------------

def _verb_guard():
    """Access control applied to GET/POST only. Any other verb walks straight in."""
    if request.method in ("GET", "POST"):
        return request.headers.get("X-Admin-Token") == ADMIN_TOKEN
    return True


@app.route("/admin/panel", methods=ALL_METHODS)
def admin_panel():
    if not _verb_guard():
        return Response("forbidden: admin token required\n", status=403)
    resp = Response(f"<h1>Admin panel</h1><p>{FLAG_ADMIN}</p>\n", mimetype="text/html")
    resp.headers["X-Admin-Flag"] = FLAG_ADMIN
    resp.headers["X-Auth-Bypassed-With"] = request.method
    return resp


@app.route("/admin/users/delete", methods=ALL_METHODS)
def admin_users_delete():
    if not _verb_guard():
        return Response("forbidden: admin token required\n", status=403)
    name = request.values.get("user", "bob")
    conn = db()
    conn.execute("INSERT OR IGNORE INTO users (name, role) VALUES (?, 'user')", (name,))
    conn.execute("DELETE FROM users WHERE name = ?", (name,))
    conn.commit()
    left = [r["name"] for r in conn.execute("SELECT name FROM users").fetchall()]
    conn.close()
    resp = jsonify(deleted=name, method=request.method, remaining=left, flag=FLAG_ADMIN)
    resp.headers["X-Deleted-User"] = name
    return resp


# --- WSTG-INJT-04: HTTP parameter pollution (gateway side) --------------------

@app.route("/hpp/admin")
def hpp_admin():
    roles = request.args.getlist("role")
    role = roles[-1] if roles else "user"      # backend convention: LAST wins
    if role != "admin":
        return jsonify(role=role, occurrences=roles, denied=True), 403
    return jsonify(role=role, occurrences=roles, flag=FLAG_HPP)


@app.route("/hpp/echo")
def hpp_echo():
    vals = request.args.getlist("role")
    return jsonify(all=vals, first=vals[0] if vals else None,
                   last=vals[-1] if vals else None, joined=",".join(vals))


@app.route("/hpp/transfer", methods=["POST"])
def hpp_transfer():
    raw = request.get_data(as_text=True)
    parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
    first = {k: v[0] for k, v in parsed.items()}
    # Gateway validation looks at the FIRST occurrence only ...
    if first.get("action") not in ("view", "summary"):
        return jsonify(error="gateway rejected action", gateway_saw=first), 403
    # ... then forwards the untouched body to the backend, which takes the LAST.
    req = urllib.request.Request(
        API_URL + "/transfer", data=raw.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read()
    return jsonify(gateway_saw=first, backend=json.loads(body))


# --- WSTG-INJT-12: command injection ------------------------------------------

@app.route("/net/ping", methods=["GET", "POST"])
def net_ping():
    host = request.values.get("host", "127.0.0.1")
    out = subprocess.getoutput("ping -c 1 -W 1 " + host)   # shell=True, unfiltered
    return Response(f"<html><body><pre>{out}</pre></body></html>", mimetype="text/html")


@app.route("/net/lookup", methods=["GET", "POST"])
def net_lookup():
    host = request.values.get("host", "localhost")
    # Blind variant: output is discarded, only timing leaks the injection.
    subprocess.run("getent hosts " + host, shell=True, capture_output=True, timeout=60)
    return jsonify(status="done", host=host)


# --- WSTG-INJT-18: server-side template injection ------------------------------

@app.route("/tpl/jinja", methods=["GET", "POST"])
def tpl_jinja():
    name = request.values.get("name", "world")
    return Response(render_template_string("<h1>Hello " + name + "</h1>"), mimetype="text/html")


@app.route("/tpl/mako", methods=["GET", "POST"])
def tpl_mako():
    name = request.values.get("name", "world")
    return Response(MakoTemplate("<h1>Hello " + name + "</h1>").render(), mimetype="text/html")


# --- WSTG-INJT-25: Unicode normalization / case mapping ------------------------

@app.route("/unicode/download")
def unicode_download():
    raw = request.args.get("file", "welcome.txt")
    # Blacklist runs on the RAW input, before NFKC normalization.
    if ".." in raw or "passwd" in raw.lower() or raw.startswith("/"):
        return Response("blocked by path filter\n", status=403)
    norm = unicodedata.normalize("NFKC", raw)
    path = os.path.join(PAGES, norm)
    try:
        with open(path, "r", errors="replace") as fh:
            data = fh.read()
    except OSError as e:
        return Response(f"not found: {e}\n", status=404)
    return Response(f"<html><body><pre>{data}</pre></body></html>", mimetype="text/html")


@app.route("/unicode/whoami")
def unicode_whoami():
    raw = request.args.get("user", "guest")
    # Authorization equality check happens BEFORE normalization.
    if raw.lower() in ("admin", "root"):
        return jsonify(user=raw, denied=True), 403
    norm = unicodedata.normalize("NFKC", raw).lower()
    if norm == "admin":
        return jsonify(user=raw, normalized=norm, role="admin", flag=FLAG_UNICODE)
    return jsonify(user=raw, normalized=norm, role="guest")


@app.route("/unicode/search")
def unicode_search():
    raw = request.args.get("q", "")
    low = raw.lower()
    if any(w in low for w in ("select", "union", "drop", "insert", "delete")):
        return Response("blocked by SQL keyword filter\n", status=403)
    # NFKC + casefold AFTER the filter: fullwidth letters and U+017F long-s fold
    # back into ASCII keywords, which then reach the SQL sink.
    norm = unicodedata.normalize("NFKC", raw).casefold()
    sql = f"SELECT name, price FROM products WHERE name LIKE '%{norm}%'"
    conn = db()
    try:
        rows = [list(r) for r in conn.execute(sql).fetchall()]
        err = None
    except sqlite3.Error as e:
        rows, err = [], str(e)
    conn.close()
    return jsonify(raw=raw, normalized=norm, sql=sql, rows=rows, error=err)


@app.route("/unicode/reflect")
def unicode_reflect():
    raw = request.args.get("text", "")
    if "<script" in raw.lower():
        return Response("blocked by XSS filter\n", status=403)
    norm = unicodedata.normalize("NFKC", raw)
    return Response(f"<html><body><div id='out'>{norm}</div></body></html>", mimetype="text/html")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)