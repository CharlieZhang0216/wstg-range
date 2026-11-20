---
name: Lab bug
about: A target does not behave as its manifest claims, a probe fails, or a build breaks
title: "[Mxx] "
labels: bug
---

<!--
STOP — is this actually a bug?

The vulnerabilities in this lab are INTENTIONAL. SQL injection, RCE, auth bypass,
weak crypto and XSS are the product, not defects. Please do not report them here.

Report privately instead if you found: a real (non-synthetic) secret, a way for a
target to escape to the host/network/internet, a non-loopback exposure, an unsafe
container setting, or a probe that passes WITHOUT the weakness being present.
See SECURITY.md.
-->

## Machine

<!-- e.g. machines/06-injection-server-protocol -->

## WSTG ID(s) affected

<!-- e.g. WSTG-INJT-16 -->

## What is wrong

<!--
Pick one:
  - build failure (docker compose up --build fails)
  - container never becomes healthy
  - probe FAILs or ERRORs
  - probe passes but the target does not actually exhibit the claimed weakness
  - manifest / README does not match the implementation
  - suite is not idempotent (passes once, fails on re-run)
-->

## Reproduction

```bash
# exact commands, from the repo root
```

## Output

```
# paste the runner output or the build error
```

## Environment

- OS / arch: <!-- e.g. macOS 15 arm64, Ubuntu 24.04 x86_64 -->
- Docker / Compose version: <!-- docker version; docker compose version -->
- Host Python version: <!-- python3 -V -->
- Registry mirror or proxy in use: <!-- yes/no, which -->

## Additional context

<!-- Anything else: did you change LAB_HTTP_PROXY, pin a subnet, use a mirror? -->