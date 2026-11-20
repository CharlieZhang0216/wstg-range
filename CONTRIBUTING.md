# Contributing to wstg-range

Thanks for helping make this lab better. The most valuable contributions are:

1. **Stronger probes** for tests that already exist — real impact beats a status code.
2. **Fixes for the four `degraded` items** (see the README's *Known limitations*).
3. **Bug fixes** where a target does not actually behave as its manifest claims.
4. **Documentation** — clearer attack walkthroughs in a machine's README.

Please read [`CONVENTIONS.md`](CONVENTIONS.md) before writing code. It is the
binding contract, and CI enforces the machine-checkable parts of it.

## Ground rules

### 1. Every WSTG ID belongs to exactly one machine

`coverage/catalog.json` is the authority. Never hand-edit it — regenerate it:

```bash
git clone --depth 1 https://github.com/OWASP/wstg /tmp/wstg
python3 coverage/build_catalog.py /tmp/wstg
```

If you believe an ID is assigned to the wrong machine, open an issue first.
Moving an ID between machines changes both manifests and both probe files.

### 2. A probe must demonstrate real impact

```python
def injt_09(ctx):
    r = ctx.post("/xpath/login", data={"user": "' or '1'='1", "pass": "x"})
    ok = r.status == 200 and "admin-secret" in r.text
    return ok, f"xpath bypass -> {r.status}, secret extracted={'admin-secret' in r.text}"
```

`fn(ctx) -> (bool, evidence)`. **True means the intentional weakness is present.**

Not acceptable as sole evidence:

- `status == 200`
- "the payload appears somewhere in the response"
- "an error message was returned"
- a static grep of served JavaScript for an execution-dependent client-side test

Acceptable: another user's object read or written, a forged token accepted,
plaintext recovered, command output returned, a measured timing delta, a value
received by an in-range listener, a real browser navigation or DOM change.

### 3. Probes are idempotent and self-contained

Create your own state. Reset what you depend on. Never assume another probe ran
first. The full suite must pass on a second and third consecutive run.

Business-logic and state-mutating tests should expose a reset endpoint (see
M08's `/lab/reset`) or create uniquely-named entities per run.

### 4. stdlib only, unless genuinely unavoidable

[`tools/labhttp.py`](tools/labhttp.py) already gives you `request`, `get`,
`post`, `raw` (byte-exact sockets), `Session` (cookie jar), `wait_for`,
`contains`, `evidence`. It preserves duplicate headers and unusual HTTP methods,
which is what makes smuggling and splitting probeable.

If you truly need a third-party library, add it to that machine's
`verify/requirements.txt` and **import it lazily inside the probe** so the rest
of the machine still runs without it.

Prefix helper functions with `_` so the coverage checker does not flag them as
orphans.

### 5. Never weaken a probe to make it pass

> If a probe cannot be made to pass, say so and mark `degraded` with the reason —
> do not weaken the probe until it passes, and do not delete the test from the
> manifest.

Set `"degraded": "one-line reason"` in the manifest entry. It surfaces as a CI
warning and appears in the README's limitations table. An honest degradation is
a good contribution; a silently weakened assertion is not.

### 6. Safety is non-negotiable

- Publish ports on loopback only: `"127.0.0.1:8500:80"`.
- Backend datastores go on an `internal: true` network, unpublished.
- Synthetic data only. No real credentials, no real PII.
- No outbound attacks. Every SSRF/XSS/RFI/exfil target must be inside the same
  Compose network.
- No `privileged`, no `network_mode: host`, no Docker socket mounts.
- Pin image tags. No `:latest`.
- `restart: "no"`, a healthcheck on every long-running service,
  `container_name: wstg-mNN-<service>`.
- Copy the `x-proxy-args` / `x-proxy-env` anchors from M01 into any new Compose
  file, or container build-time downloads will break for users with a Docker
  proxy configured.

## Development setup

Each machine is independently runnable. Use a **per-machine venv** so parallel
work does not collide on a shared one:

```bash
M=machines/01-recon-config

python3 -m venv "$M/verify/.venv"
"$M/verify/.venv/bin/pip" install -r "$M/verify/requirements.txt"   # if present

(cd "$M" && docker compose up --build -d)
"$M/verify/.venv/bin/python" tools/runner.py "$M"
```

M09 additionally needs `playwright install chromium` in its venv.

If your host Python is very new and a dependency has no wheel yet, build the
venv with an older interpreter (the reference host used `python3.12` for M02 and
M09 because 3.14 lacked `cryptography` / `greenlet` wheels).

## Definition of done

Before opening a pull request, all four must hold:

```bash
# 1. Compose is valid and the safety contract holds
python3 tools/audit_safety.py

# 2. Coverage is complete and consistent
python3 coverage/check_coverage.py          # must exit 0, 132/132

# 3. Your machine's probes pass — twice
"$M/verify/.venv/bin/python" tools/runner.py "$M"
"$M/verify/.venv/bin/python" tools/runner.py "$M"

# 4. No real secrets
python3 tools/scan_secrets.py
```

Also update the machine's `README.md` so the per-ID walkthrough matches what you
changed, and keep `README.md` / `README.zh-CN.md` in sync if you touch the
top-level docs.

## Commit and PR style

- One logical change per commit. Mention the WSTG ID(s) affected, e.g.
  `M06: make INJT-16 prove a real CL.TE desync`.
- In the PR description, state **what the probe now proves** and paste the
  evidence line from the runner output.
- If you changed a `degraded` status in either direction, call it out explicitly.

## Reporting problems

- **Intentional vulnerabilities are not bugs.** Do not open issues for them.
- Lab escapes, real secrets, non-loopback exposure, unsafe container settings,
  or a probe that passes without the weakness being present → report privately
  per [`SECURITY.md`](SECURITY.md).
- Everything else → a normal issue, using the templates.

## License

By contributing, you agree that your code contributions are licensed under the
[MIT License](LICENSE). Note that `coverage/catalog.json` is derived from the
OWASP WSTG and remains under [CC BY-SA 4.0](NOTICE) — changes to that file carry
ShareAlike obligations.