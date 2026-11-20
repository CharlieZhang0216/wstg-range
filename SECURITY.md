# Security Policy

## This software is intentionally vulnerable

`wstg-range` is a **deliberately insecure** training lab. Every one of the 132
WSTG tests it covers is implemented as a *real, exploitable* weakness. SQL
injection, remote code execution, authentication bypass, SSRF, weak cryptography
and insecure deserialization are **features, not bugs**.

**Please do not open security advisories or issues for the intentional
vulnerabilities.** They are the product. Each one is documented in the relevant
machine's `README.md` with its exact payload, and asserted by an executable
probe in `verify/probes.py`.

## What IS in scope for a security report

Report privately if you find any of the following:

| In scope | Why it matters |
|---|---|
| **A real secret** — an actual credential, API key, token, private key or real PII committed anywhere in the repo | Everything in this lab must be synthetic. A real secret is a genuine incident. |
| **Lab escape** — a way for a target to reach the host, the Docker daemon, the local network, or the internet | The lab must stay inside its own Compose network. |
| **Non-loopback exposure** — any published port not bound to `127.0.0.1`, or a service reachable from outside the machine | Would expose deliberately vulnerable code to others. |
| **Unsafe defaults** — `privileged`, `network_mode: host`, a Docker socket mount, or a container that can attack a sibling machine | Violates the isolation contract in `CONVENTIONS.md`. |
| **A probe that passes without the weakness being present** | Undermines the coverage claim; the lab would be teaching something false. |
| **Supply-chain risk** — a pinned image tag or dependency that is malicious or hijacked | Affects everyone who builds the lab. |

## How to report

Use **GitHub private vulnerability reporting**:
<https://github.com/CharlieZhang0216/wstg-range/security/advisories/new>

Please include: the machine directory, the file and line, a reproduction, and
the impact. Do not open a public issue for anything in the table above.

We aim to acknowledge within 7 days.

## Safety contract (enforced by convention and CI)

Every machine in this repository must satisfy all of the following:

- **Loopback only.** Every published port is `"127.0.0.1:NNNN:NN"`. Never
  `0.0.0.0`, never a bare `NNNN:NN`.
- **Isolated networks.** Each machine has its own Compose network. Backend
  datastores sit on a second network with `internal: true` and are not
  published to the host at all.
- **No outbound attacks.** SSRF, XSS, RFI, CSV/DDE exfiltration, webhook and
  DNS-rebinding probes target only hosts inside the same Compose network.
  Nothing in this lab contacts a third-party service.
- **Synthetic data only.** `alice`, `bob`, `Password123!`, `FLAG{...}`,
  `4111-1111-1111-1111`. No real credentials, no real PII.
- **No dangerous container settings.** No `privileged`, no
  `network_mode: host`, no Docker socket mounts, no `:latest` tags.
- **`restart: "no"`.** A crashed lab stays crashed and visible.
- **Warning banner.** Every machine README opens with an authorised-use warning.

`CONVENTIONS.md` is the full contract. `.github/workflows/ci.yml` checks the
machine-verifiable parts on every push and pull request.

## If you are deploying this lab

- Run it on an isolated workstation or VM, not on a shared or internet-facing
  host.
- Do **not** change the port bindings to `0.0.0.0`. If you need remote access,
  put it behind an authenticated VPN or an SSH tunnel to loopback.
- Do not connect the lab networks to production networks.
- Tear it down when you are finished: `docker compose down -v` in each machine
  directory.
- The lab contains working RCE, deserialization and SSRF chains. Treat every
  container as hostile.

## Supported versions

Only the `main` branch is maintained. There are no released versions yet.