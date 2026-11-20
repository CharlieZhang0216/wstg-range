# Lab build conventions (contract for all 10 machines)

Every machine MUST follow this exactly. `coverage/check_coverage.py` enforces the
machine-checkable parts; the rest is reviewed by hand.

## 0. Safety posture

These are **intentionally vulnerable** training targets.

- Publish ports on loopback only: `"127.0.0.1:8100:80"`. Never `0.0.0.0`, never bare `8100:80`.
- Each machine gets its own compose network. Backend datastores go on a second
  network with `internal: true` so they are not reachable from the host.
- No real credentials, no real PII, no outbound calls to third-party services.
  Seed data is synthetic (`alice`, `bob`, `Password123!`, ...).
- No machine may attack anything outside its own compose network. SSRF/XSS probes
  target only in-range hosts.
- Every README starts with a warning banner and the intended use (authorised
  security testing / training only).

## 1. Port blocks

| Machine | Block | Primary HTTP |
|---|---|---|
| 01-recon-config | 8100-8199 | 8100 |
| 02-identity-authn | 8200-8299 | 8200 |
| 03-authz-session | 8300-8399 | 8300 |
| 04-injection-datastore | 8400-8499 | 8400 |
| 05-injection-xss-code | 8500-8599 | 8500 |
| 06-injection-server-protocol | 8600-8699 | 8600 |
| 07-crypto-error | 8700-8799 | 8700 |
| 08-business-logic | 8800-8899 | 8800 |
| 09-client-side | 8900-8999 | 8900 |
| 10-api-wasm | 9000-9099 | 9000 |

Auxiliary services take `block_start + N`. Declare every published port in
`manifest.endpoints` and in the README table. Blocks must not overlap.

## 2. Directory layout

```
machines/NN-slug/
  docker-compose.yml
  manifest.json
  README.md
  verify/
    probes.py
    requirements.txt      # optional, only if stdlib is insufficient
  <service>/              # one dir per built image: app/, nginx/, db/, ...
    Dockerfile
    ...source...
```

Use `docker compose up --build -d` from the machine directory. Do not depend on
files outside the machine directory (no shared build contexts) — each machine
must be independently runnable.

## 3. manifest.json schema

```json
{
  "machine": "01-recon-config",
  "title": "Reconnaissance & Configuration",
  "port_block": "8100-8199",
  "primary_url": "http://127.0.0.1:8100",
  "health_path": "/",
  "startup_timeout": 180,
  "endpoints": {
    "admin": "http://127.0.0.1:8105",
    "minio": "http://127.0.0.1:8190"
  },
  "tests": [
    {
      "id": "WSTG-CONF-06",
      "surface": "PUT /files/report.txt",
      "weakness": "nginx dav_methods allows PUT/DELETE; TRACE enabled in vhost",
      "severity": "medium",
      "probe": "conf_06",
      "degraded": null
    }
  ]
}
```

Rules:

- `machine` == directory name.
- One entry per WSTG ID. **Exactly one machine owns each ID** — no double claiming.
- `docs` may be omitted; it then defaults to the catalog's full doc list. If you
  set it, it must equal the catalog list exactly (sub-documents included).
- `probe` is a function name in `verify/probes.py`.
- `severity` ∈ `info|low|medium|high|critical`.
- `degraded` is `null` for a faithful implementation. If a test can only be
  partially realised (e.g. a protocol is simulated rather than a real server),
  put a one-line reason here. **Never silently downgrade** — it shows up in the
  matrix and the final report.

## 4. Probe contract

`verify/probes.py` defines one function per test:

```python
def conf_06(ctx):
    r = ctx.session().request("PUT", "/files/probe.txt", data="owned")
    ok = r.status in (201, 204)
    return ok, f"PUT -> {r.status}"
```

- Signature: `fn(ctx) -> (bool, str)`. The bool asserts **the weakness is present**
  (the lab is correctly broken), the string is short evidence for the report.
- `ctx.base` — primary URL. `ctx.url("/path")` — absolute URL on the primary.
  `ctx.url("admin")` — looks up `manifest.endpoints`. `ctx.session()` — cookie-jar
  `labhttp.Session`.
- Import helpers from `labhttp` (already on `sys.path`): `request, get, post, raw,
  Session, wait_for, contains, evidence`.
- **stdlib only** unless unavoidable. If you need a third-party lib, add it to
  `verify/requirements.txt` and import it lazily inside the probe so the rest of
  the machine still runs without it.
- Probes must be self-contained and idempotent: create their own state, clean up
  where practical, never assume another probe ran first.
- Prefix helpers with `_` so the coverage checker does not flag them as orphans.
- A probe must genuinely demonstrate the vulnerability, not just assert that an
  endpoint returns 200. `200 OK` alone is not evidence.

## 5. Compose conventions

- Pin image tags. No `:latest`.
- Every long-running service gets a `healthcheck`; app services depend on
  datastores with `condition: service_healthy`.
- `restart: "no"` — a crashed lab should stay crashed and visible.
- Set `container_name: wstg-mNN-<service>` so 10 machines can run side by side.
- Keep total image size reasonable; prefer `-slim` / `-alpine` bases.
- Do not use `network_mode: host`, `privileged`, or docker socket mounts.
  (M06's native overflow target may use `cap_add: [SYS_PTRACE]` only if a debugger
  is genuinely needed; prefer not to.)

## 6. README.md per machine

Must contain: warning banner, WSTG IDs covered (table), service topology + port
table, `docker compose up --build -d`, how to run probes, and a short "how to
attack this" walkthrough per test with the exact request/payload. Keep it usable
as a training handout.

## 7. Definition of done for a machine

1. `docker compose config -q` passes.
2. `docker compose up --build -d` reaches healthy.
3. `python3 tools/runner.py machines/NN-slug` → **all probes PASS**.
4. `python3 coverage/check_coverage.py` reports no new errors.

Report honestly. If a probe cannot be made to pass, say so and mark `degraded`
with the reason — do not weaken the probe until it passes, and do not delete the
test from the manifest.