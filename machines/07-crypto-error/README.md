# Machine 07 — Cryptography & Error Handling

> **WARNING — intentionally vulnerable training target.**
> This machine is deliberately broken for authorised security testing / training
> (OWASP WSTG coverage lab) only. All credentials and data are synthetic.
> Ports are published on loopback only. Do not expose it to any network, do not
> reuse any code, key or credential from it in real systems, and do not attack
> anything outside this compose project.

## WSTG tests covered

| ID | Name | Severity | Probe |
|---|---|---|---|
| WSTG-CRYP-01 | Weak Transport Layer Security | high | `cryp_01` |
| WSTG-CRYP-02 | Padding Oracle | critical | `cryp_02` |
| WSTG-CRYP-03 | Sensitive Information Sent via Unencrypted Channels | high | `cryp_03` |
| WSTG-CRYP-04 | Weak Cryptographic Primitives | critical | `cryp_04` |
| WSTG-ERRH-01 | Improper Error Handling | high | `errh_01` |
| WSTG-ERRH-02 | Stack Traces | medium | `errh_02` |

## Topology & ports (block 8700–8799)

| Service | Container | Host port | Purpose |
|---|---|---|---|
| app (Flask, debug=True) | `wstg-m07-app` | `127.0.0.1:8700` | primary HTTP portal: padding oracle, weak crypto, cleartext logins, error handling |
| node (Express, dev mode) | `wstg-m07-node` | `127.0.0.1:8705` | second stack for full stack traces + `/debug/vars` |
| telnet (Python TCP) | `wstg-m07-telnet` | `127.0.0.1:8723` | cleartext maintenance console (creds + token on the wire) |
| tls (Python ssl server) | `wstg-m07-tls` | `127.0.0.1:8743` | weak TLS: TLSv1.0+, SECLEVEL=0, expired bad cert, no HSTS |

All services sit on one compose bridge network (`edge`). The app uses an
embedded SQLite database (`/app/lab.db`), so no separate datastore is published.

## Run

```bash
cd machines/07-crypto-error
docker compose up --build -d     # wait until all four containers are healthy
```

## Verify (isolated venv)

```bash
python3 -m venv verify/.venv
verify/.venv/bin/pip install -r verify/requirements.txt   # pycryptodome, cryptography
# from the repo root:
verify/.venv/bin/python ../../tools/runner.py .
# or: machines/07-crypto-error/verify/.venv/bin/python tools/runner.py machines/07-crypto-error
```

All 6 probes must PASS, and PASS again on re-run (they are idempotent).

## How to attack this

Synthetic accounts: `alice / Password123!`, `bob / Summer2024!`.

### WSTG-CRYP-01 — Weak TLS (:8743)

Enumerate what the server actually accepts:

```bash
openssl s_client -connect 127.0.0.1:8743 -tls1        # TLSv1.0 negotiates
openssl s_client -connect 127.0.0.1:8743 -tls1_1      # TLSv1.1 negotiates
openssl s_client -connect 127.0.0.1:8743 -cipher 'AES128-SHA:@SECLEVEL=0' -tls1_2
```

Real results: TLSv1.0/TLSv1.1 negotiate (`ECDHE-RSA-AES256-SHA`, CBC+SHA1);
`AES128-SHA`/`AES256-SHA` (static RSA key exchange, no PFS, CBC+SHA1) negotiate
at TLSv1.2. The certificate is self-signed, **expired**, RSA-**1024**, signed
with **SHA1**, and issued to `legacy.acme.test` (hostname mismatch for
`127.0.0.1`). No `Strict-Transport-Security` header is ever sent.

Note: RC4/3DES/NULL/export suites are attempted by the probe but are compiled
out of modern OpenSSL builds (client *and* server), so they cannot negotiate;
the deprecated protocols and CBC-SHA1/static-RSA suites above are the weakest
things that are real. The server config still activates the legacy provider
and `MinProtocol=TLSv1`, `CipherString=ALL:@SECLEVEL=0`.

### WSTG-CRYP-02 — Padding oracle (`POST /oracle/decrypt`)

`GET /oracle/secret` returns `IV || AES-128-CBC(PKCS#7(FLAG{cbc_oracle}))`
under a fixed key and fixed IV. The decrypt endpoint leaks padding validity:

```bash
curl -s -X POST http://127.0.0.1:8700/oracle/decrypt \
  -H 'Content-Type: application/json' -d '{"ct":"<hex>"}'
# bad padding  -> 500 {"error":"Padding error"}
# good padding, bad content -> 400 {"error":"Invalid data"}
# valid token  -> 200 {"status":"valid"}
```

Classic attack on the single ciphertext block `C1` with preceding block `IV`:
for byte `k` from 15 down to 0, set padding target `p = 16-k`, forge
`IV'[j] = I[j] ^ p` for already-recovered bytes `j>k`, and try all 256 values
of `IV'[k]`. Any response other than 500 means the decrypted byte equals `p`,
so `I[k] = guess ^ p` and `P[k] = I[k] ^ IV[k]`. The probe runs this for real
(~700–2100 requests) and recovers `FLAG{cbc_oracle}` byte by byte.

### WSTG-CRYP-03 — Cleartext channels

* The homepage form posts to `http://127.0.0.1:8700/login` — credentials and
  the returned `tok_live_…` API token cross plain HTTP. Capture them:
  `tcpdump -i lo0 port 8700` (or just use the raw-socket probe).
* `GET /api/account` with `Authorization: Basic YWxpY2U6UGFzc3dvcmQxMjMh`
  (alice:Password123!) over HTTP returns account number + API token.
* The TLS page `https://127.0.0.1:8743/` submits its login form to the
  **HTTP** endpoint (mixed content) and sets `legacy_sid` **without Secure**.
  The app's `session` cookie also lacks `Secure`/`HttpOnly` and is used over HTTP.
* Telnet-style console: `nc 127.0.0.1 8723`, send `alice` / `Password123!` in
  cleartext, receive `SECRET_TOKEN=tok_live_9f8e7d6c5b4a3210` in cleartext.

### WSTG-CRYP-04 — Weak primitives

1. **Unsalted MD5**: `GET /users` lists `pw_md5`. Reverse with a precomputed
   table (`md5("Password123!")` matches alice) and log in with the recovered
   password to prove the reversal.
2. **AES-ECB**: `GET /ecb/encrypt?data=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB`
   returns ciphertext whose first two 16-byte blocks are identical — plaintext
   structure leaks. `GET /legacy/docs` ships the static key; decrypt
   `/ecb/secret` with it to recover `FLAG{ecb_mode}`.
3. **DES / RC4 with static keys**: decrypt `/des/secret` (DES-ECB, key
   `Acme1234`) and `/rc4/secret` (RC4, key `AcmeRC4Key`) — both keys are in
   `/legacy/docs` — recovering `FLAG{des_legacy}` and `FLAG{rc4_legacy}`.
4. **Predictable PRNG**: `/token` issues reset tokens from a fixed-seed
   MT19937 (`random.Random(0xC0FFEE)`, two 32-bit draws per token). Collect
   312 tokens (624 outputs), untemper each, `random.setstate((3, tuple+ (624,), None))`,
   and predict the next token exactly. The probe does this live.

### WSTG-ERRH-01 — Improper error handling

* Enumeration: `GET /user?id=1` → 200 (alice), `id=99999` → 404 "not found",
  `id=abc` → 500 "no such column".
* Leak: `GET /user?id=1'` → 500 JSON containing the raw SQL query, the
  `users` schema, `/app/lab.db` and a full Python traceback (debug left on).
* **Fail-open**: `POST /api/transfer {"from":"alice","to":"ghost","amount":1000000}`
  → `200 {"status":"success","transfer_id":…}` although the destination does
  not exist and no money moved (`GET /api/balance?user=alice` unchanged,
  `ghost` still 404). Same for an insufficient-funds transfer to `bob`.

### WSTG-ERRH-02 — Stack traces (two stacks)

* Flask: `GET http://127.0.0.1:8700/boom` → Werkzeug interactive debugger
  page: full traceback, `/app/app.py` source with line numbers, framework
  version in `Server: Werkzeug/3.0.3 Python/3.12.x`. Frame local variables
  (including `internal_signing_key`) are readable via the debugger's inspector
  (`?__debugger__=yes&cmd=inspect&frm=<id>&s=<secret>` — the secret is embedded
  in the page). The embedded console is PIN-protected; the PIN is derivable
  from leaked `/proc` values — that exposure is itself a finding. This lab
  demonstrates trace/local-variable disclosure only, not RCE.
* Express: `GET http://127.0.0.1:8705/crash` → 500 HTML with the full
  `TypeError` stack (`/app/server.js:<line>`, `node_modules/express/lib/router/layer.js`,
  `node:internal/…` frames). `GET /parse?data={broken` → `SyntaxError` stack.
  `GET /debug/vars` discloses exact Node/Express versions and environment.

## Teardown

```bash
docker compose down -v
```