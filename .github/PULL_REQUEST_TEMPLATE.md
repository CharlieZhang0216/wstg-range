## What this changes

<!-- One logical change. Mention the WSTG ID(s) affected. -->

## Machine(s)

<!-- e.g. machines/06-injection-server-protocol -->

## What the probe now proves

<!-- Be concrete about observable impact, not status codes.
     Paste the evidence line from tools/runner.py output. -->

```
[+] WSTG-XXXX-NN     PASS    <evidence>
```

## Definition of done

- [ ] `python3 tools/audit_safety.py` passes
- [ ] `python3 coverage/check_coverage.py` exits 0 (132/132)
- [ ] Affected machine's probes pass **twice in a row** (idempotent)
- [ ] `python3 tools/scan_secrets.py` clean
- [ ] Machine `README.md` walkthrough updated to match
- [ ] Top-level `README.md` / `README.zh-CN.md` updated if applicable

## Degraded status

- [ ] No change to any `degraded` field
- [ ] Changed — explained below

<!-- If you added, removed or reworded a `degraded` reason, quote the before and
     after. Remember: never weaken a probe to make it pass, and never delete a
     test from a manifest. -->

## Safety

- [ ] All published ports bind to `127.0.0.1` and stay inside the machine's port block
- [ ] New targets are in-range only; no outbound calls
- [ ] Synthetic data only
- [ ] No `privileged`, host networking, Docker socket, or `:latest` tags
- [ ] `x-proxy-args` / `x-proxy-env` anchors present in any new/changed Compose file

## Notes for reviewers

<!-- Anything tricky: emulation, pinned subnets, mirror workarounds, upstream quirks. -->