"""AcmeClient 2.4 - intentionally vulnerable client-side training app (WSTG M09).

Every weakness here is deliberate. See README.md and ../../CONVENTIONS.md.
aiohttp serves HTTP + WebSockets from one process.
"""
import json
import re
import uuid

from aiohttp import web

ATTACKER = "http://127.0.0.1:8901"

USERS = {
    "alice": {
        "password": "Password123!",
        "ssn": "123-45-6789",
        "email": "alice@lab.test",
        "balance": 1000,
        "salary": 95000,
        "secret_note": "launch code 7391",
        "card": "4111-1111-1111-1111",
    },
    "bob": {
        "password": "Password123!",
        "ssn": "987-65-4321",
        "email": "bob@lab.test",
        "balance": 250,
        "salary": 72000,
        "secret_note": "vault pin 4410",
        "card": "5500-0000-0000-0004",
    },
}
SESSIONS = {}  # token -> username
STATE = {"transfers": [], "emails": {}, "custom_scripts": {}, "themes": {}}
DOCS = {
    "report.txt": {"file": "report.txt", "content": "Q3 public report - nothing sensitive"},
    "readme.txt": {"file": "readme.txt", "content": "Public document viewer. Pick a doc."},
}


def _user(request):
    return SESSIONS.get(request.cookies.get("session", ""))


def _html(body, title="AcmeClient", headers=None, status=200):
    return web.Response(
        text=f"<!DOCTYPE html><html><head><title>{title}</title></head>"
             f"<body><h1>{title}</h1>{body}</body></html>",
        content_type="text/html", status=status, headers=headers or {},
    )


def _json(data, headers=None, status=200):
    return web.Response(text=json.dumps(data), content_type="application/json",
                        status=status, headers=headers or {})


def _js(text, headers=None):
    return web.Response(text=text, content_type="application/javascript",
                        headers=headers or {})


def _need_login(request):
    u = _user(request)
    if not u:
        raise web.HTTPFound("/login")
    return u


async def index(request):
    links = [
        "/dom-xss", "/self-xss", "/js-exec", "/html-inject", "/redirect?next=/",
        "/profile", "/widget", "/account/settings", "/messages", "/storage",
        "/links", "/template", "/clobber", "/dashboard", "/files", "/sw-page",
        "/login",
    ]
    return _html("<ul>" + "".join(f'<li><a href="{l}">{l}</a></li>' for l in links) + "</ul>",
                 "AcmeClient 2.4 - client-side lab")


async def health(request):
    return web.Response(text="ok")


async def login_get(request):
    return _html(
        '<form method="POST" action="/login">'
        '<input name="username" id="username" placeholder="username">'
        '<input name="password" id="password" type="password" placeholder="password">'
        '<button id="login-btn">Sign in</button></form>'
        "<p>Hint: alice / Password123!</p>", "Login")


async def login_post(request):
    data = await request.post()
    u, p = data.get("username", ""), data.get("password", "")
    if u in USERS and USERS[u]["password"] == p:
        token = uuid.uuid4().hex
        SESSIONS[token] = u
        resp = web.HTTPFound("/")
        # WSTG-CLNT-07/10/12: cookie is readable by JS (no HttpOnly) and sent on
        # every cross-origin request (SameSite=None). 127.0.0.1 is a secure
        # context for Chromium, so Secure works over plain HTTP here.
        resp.set_cookie("session", token, path="/", samesite="None", secure=True,
                        httponly=False)
        raise resp
    return _html("<p>Bad credentials.</p>", "Login", status=401)


async def logout(request):
    SESSIONS.pop(request.cookies.get("session", ""), None)
    resp = web.HTTPFound("/")
    resp.del_cookie("session")
    raise resp


async def reset(request):
    STATE["transfers"].clear()
    STATE["emails"].clear()
    STATE["custom_scripts"].clear()
    STATE["themes"].clear()
    return _json({"reset": True})


# --- WSTG-CLNT-01: DOM-based XSS ---------------------------------------------

async def dom_xss(request):
    return _html("""
<div id="hash-out"></div>
<script>
  var p = new URLSearchParams(location.search);
  // sink 1: location.search -> document.write
  if (p.get('name')) { document.write('<div id="dw">' + p.get('name') + '</div>'); }
  // sink 2: location.hash -> innerHTML
  document.getElementById('hash-out').innerHTML = decodeURIComponent(location.hash.slice(1));
</script>""", "DOM XSS lab")


async def self_xss(request):
    # WSTG-CLNT-01 sub-doc 01.1: payload is typed by the victim and only ever
    # executes in their own browser. ?csp=1 shows a nonce-based CSP blocking it.
    csp = request.query.get("csp") == "1"
    headers = {}
    if csp:
        headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'nonce-labselfnonce'; "
            "style-src 'unsafe-inline'; img-src 'self' " + ATTACKER)
    return _html("""
<p>Paste a snippet to preview your signature (rendered locally, never sent to the server):</p>
<input id="payload" size="60"><button id="render">Preview</button>
<div id="preview"></div>
<script nonce="labselfnonce">
  document.getElementById('render').onclick = function () {
    document.getElementById('preview').innerHTML = document.getElementById('payload').value;
  };
</script>""", "Self DOM XSS lab", headers=headers)


# --- WSTG-CLNT-02: JavaScript execution ---------------------------------------

async def js_exec(request):
    return _html("""
<div id="out"></div>
<input id="fn-in" placeholder="new Function body"><button id="fn-btn">Run Function</button>
<input id="st-in" placeholder="setTimeout string"><button id="st-btn">Run Timer</button>
<script>
  var p = new URLSearchParams(location.search);
  // sink 1: eval of URL parameter
  if (p.get('expr')) { try { eval(p.get('expr')); } catch (e) {} }
  // sink 2: new Function from user input
  document.getElementById('fn-btn').onclick = function () {
    new Function(document.getElementById('fn-in').value)();
  };
  // sink 3: setTimeout(string) from user input
  document.getElementById('st-btn').onclick = function () {
    setTimeout(document.getElementById('st-in').value, 5);
  };
  // sink 4: JSONP callback name taken from the URL, no sanitisation
  if (p.get('cb')) {
    var s = document.createElement('script');
    s.src = '/api/jsonp?callback=' + encodeURIComponent(p.get('cb'));
    document.body.appendChild(s);
  }
</script>""", "JavaScript execution lab")


async def api_jsonp(request):
    cb = request.query.get("callback", "callback")  # WSTG-CLNT-02/13: unsanitised
    u = _user(request)
    data = {"user": u or "anonymous", "ssn": USERS[u]["ssn"] if u else None}
    return _js(f"{cb}({json.dumps(data)});")


# --- WSTG-CLNT-03: HTML injection (scripts blocked by CSP) --------------------

async def html_inject(request):
    markup = request.query.get("markup", "")
    csp = ("default-src 'self' " + ATTACKER + "; script-src 'none'; "
           "form-action 'self' " + ATTACKER)
    return _html(f'<div id="content">{markup}</div>', "HTML injection lab",
                 headers={"Content-Security-Policy": csp})


# --- WSTG-CLNT-04: client-side URL redirect -----------------------------------

async def redirect_lab(request):
    return _html("""
<p>Redirecting...</p>
<script>
  var next = new URLSearchParams(location.search).get('next');
  // no allowlist, no scheme validation
  if (next) { location.href = next; }
</script>""", "Redirect lab")


# --- WSTG-CLNT-05: CSS injection ----------------------------------------------

async def profile(request):
    u = _user(request)
    css = request.query.get("css", STATE["themes"].get(u or "anon", ""))
    return _html(f"""
<style>{css}</style>
<p>Your profile token (treat as secret):</p>
<input id="token" value="tok_9f2e77" readonly>
<form method="POST" action="/profile/theme">
  <input name="css" size="60" placeholder="custom theme CSS"><button>Save theme</button>
</form>""", "Profile / theme lab")


async def profile_theme(request):
    u = _need_login(request)
    data = await request.post()
    STATE["themes"][u] = data.get("css", "")
    raise web.HTTPFound("/profile")


# --- WSTG-CLNT-06: client-side resource manipulation --------------------------

async def widget(request):
    return _html("""
<div id="widget-box"></div>
<script>
  var p = new URLSearchParams(location.search);
  // attacker controls which script resource the page loads
  var s = document.createElement('script');
  s.src = p.get('src') || '/static/safe.js';
  document.body.appendChild(s);
  // ... and which iframe
  if (p.get('frame')) {
    var f = document.createElement('iframe');
    f.src = p.get('frame');
    document.getElementById('widget-box').appendChild(f);
  }
</script>""", "Widget loader lab")


# --- WSTG-CLNT-07: CORS misconfigurations -------------------------------------

def _cors_headers(origin, cred=True):
    h = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    if cred:
        h["Access-Control-Allow-Credentials"] = "true"
    return h


async def cors_reflect(request):
    u = _need_login(request)
    origin = request.headers.get("Origin", "")
    # reflects ANY origin with credentials
    return _json({"user": u, "ssn": USERS[u]["ssn"], "balance": USERS[u]["balance"]},
                 headers=_cors_headers(origin))


async def cors_regex(request):
    u = _need_login(request)
    origin = request.headers.get("Origin", "")
    # prefix match without port/$ anchor: http://127.0.0.1:8901 slips through
    if re.match(r"^http://127\.0\.0\.1", origin):
        return _json({"user": u, "ssn": USERS[u]["ssn"]}, headers=_cors_headers(origin))
    return _json({"user": u, "ssn": USERS[u]["ssn"]})


async def cors_regex2(request):
    u = _need_login(request)
    origin = request.headers.get("Origin", "")
    # subdomain regex without trailing anchor: trusted.lab.test.evil.com passes
    if re.match(r"^https?://([a-z0-9-]+\.)*trusted\.lab\.test", origin):
        return _json({"user": u, "ssn": USERS[u]["ssn"]}, headers=_cors_headers(origin))
    return _json({"user": u, "ssn": USERS[u]["ssn"]})


async def cors_null(request):
    u = _need_login(request)
    origin = request.headers.get("Origin", "")
    if origin == "null":  # sandboxed iframes / data: documents send Origin: null
        return _json({"user": u, "ssn": USERS[u]["ssn"]}, headers=_cors_headers("null"))
    return _json({"user": u, "ssn": USERS[u]["ssn"]})


async def cors_wildcard(request):
    # "public profile" API: no auth + ACAO:* -> any origin can read the PII
    return _json({"user": "alice", "email": USERS["alice"]["email"]},
                 headers=_cors_headers("*", cred=False))


# --- WSTG-CLNT-09/10/11: state-changing actions -------------------------------

async def account_settings(request):
    u = _need_login(request)
    # WSTG-CLNT-09: no X-Frame-Options, no frame-ancestors -> framable
    return _html(f"""
<p>Signed in as {u}. Email: {STATE['emails'].get(u, USERS[u]['email'])}</p>
<form method="POST" action="/account/transfer">
  <input name="to" value="mallory"><input name="amount" value="100">
  <button id="confirm">Confirm transfer</button>
</form>""", "Account settings")


async def account_transfer(request):
    u = _need_login(request)
    data = await request.post()
    STATE["transfers"].append({"user": u, "to": data.get("to"),
                               "amount": data.get("amount"), "via": "form"})
    raise web.HTTPFound("/account/settings")


async def account_email(request):
    u = _need_login(request)
    if request.content_type == "application/json":
        data = await request.json()
    else:
        data = await request.post()
    STATE["emails"][u] = data.get("email", "")
    return _json({"ok": True, "email": STATE["emails"][u]})


async def account_state(request):
    u = _need_login(request)
    return _json({"user": u, "email": STATE["emails"].get(u, USERS[u]["email"]),
                  "transfers": STATE["transfers"]})


async def ws_handler(request):
    # WSTG-CLNT-10: no Origin check on the handshake, cookie-only auth,
    # message content is acted on directly (CSWSH).
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    u = _user(request)
    origin = request.headers.get("Origin", "")
    async for msg in ws:
        if msg.type != web.WSMsgType.TEXT:
            continue
        try:
            data = json.loads(msg.data)
        except ValueError:
            await ws.send_str(json.dumps({"error": "bad json"}))
            continue
        action = data.get("action")
        if action == "transfer" and u:
            STATE["transfers"].append({"user": u, "to": data.get("to"),
                                       "amount": data.get("amount"), "via": "ws",
                                       "origin": origin})
            await ws.send_str(json.dumps({"ok": True, "user": u,
                                          "balance": USERS[u]["balance"],
                                          "origin": origin}))
        elif action == "echo":
            # unsanitised echo of attacker-controlled content
            await ws.send_str(json.dumps({"echo": data.get("msg", "")}))
        else:
            await ws.send_str(json.dumps({"error": "unknown action", "authed": bool(u)}))
    return ws


# --- WSTG-CLNT-11: web messaging ----------------------------------------------

async def messages(request):
    u = _need_login(request)
    return _html(f"""
<p>Messaging bridge for {u}.</p>
<script>
  var PROFILE = {{user: '{u}', ssn: '{USERS[u]['ssn']}', csrf: 'csrf-alice-static'}};
  // no event.origin validation, wildcard targetOrigin
  window.addEventListener('message', function (e) {{
    if (e.data && e.data.action === 'get-profile') {{
      e.source.postMessage(PROFILE, '*');
    }}
    if (e.data && e.data.action === 'set-email') {{
      fetch('/account/email', {{method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{email: e.data.email}})}})
        .then(function () {{ e.source.postMessage({{done: true}}, '*'); }});
    }}
  }});
  if (window.parent !== window) {{ window.parent.postMessage({{ready: true, user: '{u}'}}, '*'); }}
</script>""", "Web messaging lab")


# --- WSTG-CLNT-12: browser storage --------------------------------------------

async def storage(request):
    u = _need_login(request)
    token = request.cookies.get("session", "")
    return _html(f"""
<div id="note-out"></div>
<div id="sync"></div>
<script>
  // sensitive data parked in every browser storage mechanism
  localStorage.setItem('auth_token', '{token}');
  localStorage.setItem('pii', JSON.stringify({{ssn: '{USERS[u]['ssn']}', email: '{USERS[u]['email']}'}}));
  sessionStorage.setItem('session_pii', '{USERS[u]['ssn']}');
  var open = indexedDB.open('wallet', 1);
  open.onupgradeneeded = function () {{ open.result.createObjectStore('cards', {{keyPath: 'id'}}); }};
  open.onsuccess = function () {{
    var tx = open.result.transaction('cards', 'readwrite');
    tx.objectStore('cards').put({{id: 'visa', number: '{USERS[u]['card']}'}});
  }};
  // DOM-XSS sink on the same page -> any script can read all of the above
  var p = new URLSearchParams(location.search);
  if (p.get('note')) {{ document.getElementById('note-out').innerHTML = p.get('note'); }}
  // cross-tab sync renders storage events as HTML (leak + sink)
  window.addEventListener('storage', function (e) {{
    document.getElementById('sync').innerHTML = e.key + ':' + e.newValue;
  }});
</script>""", "Browser storage lab")


# --- WSTG-CLNT-13: cross-site script inclusion --------------------------------

async def api_private_js(request):
    u = _need_login(request)
    return _js(f"var PRIVATE_DATA = {json.dumps({'ssn': USERS[u]['ssn'], 'salary': USERS[u]['salary'], 'email': USERS[u]['email']})};")


async def api_orders(request):
    u = _need_login(request)
    # top-level JSON array served as JavaScript (classic JSON-hijacking shape)
    return _js(json.dumps([{"order": 1, "total": 120, "card": USERS[u]["card"]},
                           {"order": 2, "total": 80, "card": USERS[u]["card"]}]))


# --- WSTG-CLNT-14: reverse tabnabbing -----------------------------------------

async def links(request):
    # rel="opener" explicitly defeats the browser's implicit noopener;
    # window.open() without noopener keeps window.opener too. No COOP header.
    return _html(f"""
<a id="ext" href="{ATTACKER}/tabnab" target="_blank" rel="opener">Partner portal (new tab)</a>
<button id="wopen">Open partner via window.open</button>
<script>
  document.getElementById('wopen').onclick = function () {{
    window.open('{ATTACKER}/tabnab');
  }};
</script>""", "Links lab")


# --- WSTG-CLNT-15: client-side template injection -----------------------------

async def template(request):
    expr = request.query.get("expr", "world")
    # raw reflection into an AngularJS 1.8.2 template (sandbox removed in 1.8)
    return _html(f"""
<div ng-app><p id="greet">Hello {expr}</p></div>
<script src="/static/angular.min.js"></script>""", "Template lab")


# --- WSTG-CLNT-16: DOM clobbering ----------------------------------------------

def _sanitize(html):
    # naive "sanitiser": strips script tags and event handlers, keeps id/name/href
    html = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "", html, flags=re.S | re.I)
    html = re.sub(r"\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", html, flags=re.I)
    return html


async def clobber(request):
    bio = _sanitize(request.query.get("bio", ""))
    return _html(f"""
<div id="bio">{bio}</div>
<script>
  // reads a global that may be undefined -> clobberable via named DOM access
  var cfg = window.config || {{href: '/static/safe.js'}};
  var s = document.createElement('script');
  s.src = cfg.href;
  document.body.appendChild(s);
</script>""", "DOM clobbering lab")


# --- WSTG-CLNT-18: cross-site leaks --------------------------------------------

async def dashboard(request):
    u = _user(request)
    if not u:
        return _html("<p>Please log in.</p>", "Dashboard")
    # frame count differs with authentication state (window.length oracle)
    return _html("".join(f'<iframe src="/widgets/{w}" width="200" height="80"></iframe>'
                         for w in ("a", "b", "c")), "Dashboard")


async def widgets(request):
    return _html(f"<p>widget {request.match_info['name']}</p>", "Widget")


async def api_search(request):
    u = _need_login(request)
    q = request.query.get("q", "")
    # 200 vs 404 leaks whether the private note contains q (error-event oracle).
    # Served as JavaScript so classic cross-origin <script> inclusion is not
    # blocked by the browser's Opaque Response Blocking.
    if q and q in USERS[u]["secret_note"]:
        return _js("var hits=1;")
    return web.Response(text="var hits=0;", content_type="application/javascript",
                        status=404)


# --- WSTG-CLNT-19: client-side path traversal ----------------------------------

async def files_viewer(request):
    return _html("""
<pre id="doc"></pre>
<script>
  var doc = new URLSearchParams(location.search).get('doc') || 'report.txt';
  // user input concatenated into the fetch path, no normalisation/allowlist
  fetch('/api/files/' + doc)
    .then(function (r) { return r.json(); })
    .then(function (d) { document.getElementById('doc').textContent = JSON.stringify(d); });
</script>""", "Document viewer")


async def api_files(request):
    name = request.match_info["name"]
    if name in DOCS:
        return _json(DOCS[name])
    return _json({"error": "no such document"}, status=404)


async def api_admin_users(request):
    _need_login(request)
    # unintended endpoint reached via client-side traversal: every user's PII
    return _json({"users": [{"name": n, "ssn": d["ssn"], "email": d["email"],
                             "salary": d["salary"]} for n, d in USERS.items()]})


# --- WSTG-CLNT-20: service workers ----------------------------------------------

async def custom_script_post(request):
    name = request.match_info["name"]
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.js", name):
        return _json({"error": "bad name"}, status=400)
    # "custom theme script" feature: no auth, no CSRF token, arbitrary JS stored
    STATE["custom_scripts"][name] = await request.text()
    return _json({"stored": name}, status=201)


async def custom_script_get(request):
    name = request.match_info["name"]
    body = STATE["custom_scripts"].get(name)
    if body is None:
        return _json({"error": "not found"}, status=404)
    # Service-Worker-Allowed lets a script at /custom/ claim the whole origin
    return _js(body, headers={"Service-Worker-Allowed": "/"})


async def custom_script_delete(request):
    STATE["custom_scripts"].pop(request.match_info["name"], None)
    return _json({"deleted": True})


async def sw_page(request):
    return _html("""
<div id="sw-status">registering...</div>
<script>
  var sw = new URLSearchParams(location.search).get('sw') || '/static/app-sw.js';
  // script path is attacker-controllable; scope widened to '/'
  navigator.serviceWorker.register(sw, {scope: '/'})
    .then(function (r) { document.getElementById('sw-status').textContent = 'registered ' + r.scope; })
    .catch(function (e) { document.getElementById('sw-status').textContent = 'error ' + e; });
</script>""", "Service worker lab")


async def api_data(request):
    u = _user(request)
    return _json({"balance": USERS[u]["balance"] if u else 0, "owner": u or "anonymous"})


def make_app():
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/health", health)
    app.router.add_get("/login", login_get)
    app.router.add_post("/login", login_post)
    app.router.add_get("/logout", logout)
    app.router.add_get("/reset", reset)
    app.router.add_get("/dom-xss", dom_xss)
    app.router.add_get("/self-xss", self_xss)
    app.router.add_get("/js-exec", js_exec)
    app.router.add_get("/api/jsonp", api_jsonp)
    app.router.add_get("/html-inject", html_inject)
    app.router.add_get("/redirect", redirect_lab)
    app.router.add_get("/profile", profile)
    app.router.add_post("/profile/theme", profile_theme)
    app.router.add_get("/widget", widget)
    app.router.add_get("/api/cors/reflect", cors_reflect)
    app.router.add_get("/api/cors/regex", cors_regex)
    app.router.add_get("/api/cors/regex2", cors_regex2)
    app.router.add_get("/api/cors/null", cors_null)
    app.router.add_get("/api/cors/wildcard", cors_wildcard)
    app.router.add_get("/account/settings", account_settings)
    app.router.add_post("/account/transfer", account_transfer)
    app.router.add_post("/account/email", account_email)
    app.router.add_get("/account/state", account_state)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/messages", messages)
    app.router.add_get("/storage", storage)
    app.router.add_get("/api/private.js", api_private_js)
    app.router.add_get("/api/orders", api_orders)
    app.router.add_get("/links", links)
    app.router.add_get("/template", template)
    app.router.add_get("/clobber", clobber)
    app.router.add_get("/dashboard", dashboard)
    app.router.add_get("/widgets/{name}", widgets)
    app.router.add_get("/api/search", api_search)
    app.router.add_get("/files", files_viewer)
    app.router.add_get("/api/files/{name}", api_files)
    app.router.add_get("/api/admin/users", api_admin_users)
    app.router.add_post("/custom/{name}", custom_script_post)
    app.router.add_get("/custom/{name}", custom_script_get)
    app.router.add_delete("/custom/{name}", custom_script_delete)
    app.router.add_get("/sw-page", sw_page)
    app.router.add_get("/api/data", api_data)
    app.router.add_static("/static", "static")
    return app


if __name__ == "__main__":
    web.run_app(make_app(), host="0.0.0.0", port=5000, print=None)