"""AcmePortal 3.2.1 - intentionally misconfigured legacy portal (WSTG M01)."""
import os
import stat
import traceback

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

DB_PASSWORD = os.environ.get("DB_PASSWORD", "Sup3rS3cretPortalPW")
DB_HOST = os.environ.get("DB_HOST", "db")
FLAG = os.environ.get("FLAG", "WSTG-M01{path_confusion_and_alias_traversal}")

DATA = "/srv/data"
WEAK_CSP = "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *; object-src *; style-src 'unsafe-inline' *"

PAGES = {
    "/products": ("Products", '<a href="/about">About</a> <a href="/reports">Reports</a>'),
    "/about": ("About", '<a href="/contact">Contact</a> <a href="/login">Login</a>'),
    "/reports": ("Reports", '<a href="/reports/quarterly">Quarterly reports</a>'),
    "/reports/quarterly": ("Quarterly", '<a href="/reports/quarterly/export">Export CSV</a>'),
    "/reports/quarterly/export": ("Export", "id,revenue\n1,1000\n2,2000\n"),
    "/old/": ("Legacy portal", "This is the decommissioned 2019 portal. <a href='/debug/config'>config</a>"),
}


def _html(title, body, csp=None, extra=None):
    headers = {"X-Powered-By": "AcmePortal/3.2.1", "X-Backend": "portal-app-01"}
    # WSTG-CONF-12: a CSP is sent, but it is trivially bypassable.
    if csp:
        headers["Content-Security-Policy"] = csp
    # WSTG-CONF-14: X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
    # Permissions-Policy and the Cross-Origin-* policies are all absent.
    if extra:
        headers.update(extra)
    return Response(
        f"<!DOCTYPE html><html><head><title>{title}</title>"
        f'<meta name="generator" content="AcmePortal 3.2.1 (build 412)"></head>'
        f"<body><h1>{title}</h1>{body}</body></html>",
        headers=headers,
        mimetype="text/html",
    )


@app.after_request
def _tier_headers(resp):
    # WSTG-INFO-10: the backend tier identifies itself, letting a tester map
    # proxy -> cache -> application -> database from the outside.
    resp.headers.setdefault("X-Backend", "portal-app-01")
    resp.headers.setdefault("X-App-Version", "3.2.1")
    return resp


@app.route("/health")
def health():
    return "ok"


@app.route("/")
def index():
    return _html("AcmePortal", '<a href="/products">Products</a>')


@app.route("/search")
def search():
    q = request.args.get("q", "")
    tenant = request.args.get("tenant", "")
    # WSTG-INFO-06: GET entry point, parameters echoed into the response.
    return _html(
        "Search",
        f"<p>Results for <b>{q}</b> in tenant {tenant}</p>",
        csp=WEAK_CSP,
    )


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        return _html("Contact", f"<p>Thanks {request.form.get('name','')}</p>")
    return _html("Contact", '<form method="post"><input name="name"><input name="email"></form>')


@app.route("/login", methods=["GET"])
def login_form():
    return _html("Login", '<form method="post" action="/login"><input name="username"><input name="password" type="password"></form>')


@app.route("/login", methods=["POST"])
def login_post():
    # WSTG-CONF-05: default credentials accepted by the application admin login.
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    if (u, p) in (("admin", "admin"), ("admin", "password")):
        return _html("Admin", '<a href="/admin/users">User list</a>')
    return _html("Login", "<p>Invalid credentials</p>"), 401


@app.route("/admin/users")
def admin_users():
    """Denied at the proxy, reachable via /apiadmin/users (WSTG-CONF-13)."""
    return jsonify(
        {
            "users": [
                {"id": 1, "email": "admin@acme.internal", "role": "admin", "password_md5": "5f4dcc3b5aa765d61d8327deb882cf99"},
                {"id": 2, "email": "alice@acme.internal", "role": "user"},
            ],
            "flag": FLAG,
        }
    )


@app.route("/internal/users")
def internal_users():
    import psycopg2
    conn = psycopg2.connect(host=DB_HOST, user="portal", password=DB_PASSWORD, dbname="portal", connect_timeout=5)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM users")
            count = cur.fetchone()[0]
    finally:
        conn.close()
    return jsonify({"internal": True, "count": count, "db_host": DB_HOST, "db_engine": "postgresql"})


@app.route("/flags.json")
def flags():
    # WSTG-CONF-15: the full feature-flag inventory is publicly readable.
    return jsonify(
        {
            "ff_new_admin": {"enabled": False, "rollout": "internal"},
            "ff_beta_billing": {"enabled": False},
            "ff_debug_console": {"enabled": True},
            "admin_preview_cookie": "ff_new_admin=1",
        }
    )


@app.route("/feature-preview")
def feature_preview():
    # WSTG-CONF-15: a server-side authorisation decision is made from a
    # client-controlled cookie / header instead of the user's role.
    enabled = request.cookies.get("ff_new_admin") == "1" or request.headers.get("X-Feature-Flag") == "ff_new_admin"
    if not enabled:
        return _html("Forbidden", "<p>feature not enabled</p>"), 403
    return _html("New admin preview", f"<p>privileged console</p><pre>{FLAG}</pre>")


@app.route("/cached/page")
def cached_page():
    """WSTG-CONF-16: reflects X-Forwarded-Host into a cacheable response."""
    host = request.headers.get("X-Forwarded-Host") or request.host
    body = f"<html><body><script src='https://{host}/static/app.js'></script><p>portal</p></body></html>"
    return Response(
        body,
        mimetype="text/html",
        headers={"Cache-Control": "public, max-age=120", "X-Backend": "portal-app-01"},
    )


@app.route("/debug/files")
def debug_files():
    """WSTG-CONF-09: leftover diagnostic exposes the filesystem permission model."""
    os.makedirs(f"{DATA}/uploads", exist_ok=True)
    cfg = f"{DATA}/config.ini"
    if not os.path.exists(cfg):
        with open(cfg, "w") as fh:
            fh.write(f"[database]\nhost={DB_HOST}\npassword={DB_PASSWORD}\n")
    os.chmod(f"{DATA}/uploads", 0o777)
    os.chmod(cfg, 0o644)
    out = []
    for p in (DATA, f"{DATA}/uploads", cfg):
        st = os.stat(p)
        out.append({"path": p, "mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid, "world_writable": bool(st.st_mode & stat.S_IWOTH)})
    return jsonify({"files": out, "note": "uploads is world-writable; config.ini is world-readable"})


@app.route("/debug/config")
def debug_config():
    return jsonify(
        {
            "db_host": DB_HOST,
            "db_user": "portal",
            "db_password": DB_PASSWORD,
            "tiers": ["nginx-front", "varnish-cache", "flask-app", "postgres-db"],
            "internal_subnet": "10.20.30.0/24",
        }
    )


@app.route("/CHANGELOG.txt")
def changelog():
    # WSTG-INFO-09: application-level fingerprint and version history.
    return Response(
        "AcmePortal changelog\n3.2.1 (build 412) - 2019-04-11\n3.2.0 - 2019-02-02\n3.1.0 - 2018-11-20\n",
        mimetype="text/plain",
    )


@app.route("/tier")
def tier():
    return jsonify({"app": "portal-app-01", "version": "3.2.1", "db": DB_HOST, "proxy": "nginx", "cache": "varnish"})


@app.route("/boom")
def boom():
    # WSTG-INFO-08: framework fingerprint via the Werkzeug error page.
    raise RuntimeError("deliberate failure for framework fingerprinting")


@app.errorhandler(404)
def not_found(e):
    return _html("404 Not Found", "<p>AcmePortal could not find that page.</p>"), 404


@app.errorhandler(500)
def server_error(e):
    # WSTG-INFO-08: the framework and its exact version are disclosed on failure.
    try:
        from importlib.metadata import version
        wz = version("werkzeug")
    except Exception:
        wz = "unknown"
    tb = "".join(traceback.format_exception(type(e), e, getattr(e, "__traceback__", None)))
    return Response(
        "<html><body><h1>Internal Server Error</h1><pre>"
        + tb
        + f"</pre><p>AcmePortal 3.2.1 / Werkzeug {wz} / Flask</p></body></html>",
        status=500,
        mimetype="text/html",
    )


for _path, (_title, _body) in PAGES.items():
    def _make(t=_title, b=_body):
        return _html(t, b)
    app.add_url_rule(_path, _path.replace("/", "_").strip("_") or "root_old", _make)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)