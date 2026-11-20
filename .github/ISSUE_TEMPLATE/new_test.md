---
name: Strengthen or add a test
about: Propose a stronger probe, a new vulnerable surface, or a fix for a degraded item
title: "[Mxx] WSTG-XXXX-NN: "
labels: enhancement
---

## WSTG ID

<!-- Must be an existing ID in coverage/catalog.json. New IDs are not accepted
     unless upstream WSTG adds them — regenerate the catalogue instead. -->

## Which machine owns it

<!-- Every ID belongs to exactly one machine. Check coverage/matrix.md. -->

## Current state

<!-- What does the probe assert today? Paste its evidence line.
     If the item is marked `degraded`, quote the reason from the manifest. -->

## What is weak about it

<!-- e.g. "asserts only HTTP 200", "does not cover sub-doc 05.3",
     "the weakness is simulated rather than real", "not idempotent" -->

## Proposed improvement

<!-- What should the probe prove instead? Be concrete about the observable
     impact: extracted secret, forged token, cross-user write, timing delta,
     browser effect, listener callback. -->

## Real service or substitute?

<!-- This lab prefers real services. If you must substitute, say what and why,
     and propose the `degraded` wording. -->

## Safety check

- [ ] All new targets stay inside this machine's Compose network
- [ ] Any new published port binds to `127.0.0.1` and falls in the machine's port block
- [ ] Synthetic data only
- [ ] No `privileged` / host networking / Docker socket
- [ ] Probe is idempotent and stdlib-only (or lazily imports a declared dependency)

## Willing to implement?

<!-- yes / no / needs guidance -->