#!/usr/bin/env python3
"""Audit every machine against the safety contract in CONVENTIONS.md.

Uses `docker compose config --format json` so the checks run against Compose's
own normalized view (resolved anchors, defaults and port syntax) rather than
against fragile text patterns.

Usage:  python3 tools/audit_safety.py [machine-dir ...]
Exit 0 only if every machine passes every check.
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MACHINES = ROOT / "machines"

LATEST = re.compile(r":latest$|^[^:]+$")
BANNER = re.compile(r"WARNING|警告|intentionally vulnerable|故意", re.I)


def compose_json(path):
    out = subprocess.run(
        ["docker", "compose", "-f", str(path), "config", "--format", "json"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else "config failed")
    return json.loads(out.stdout)


def audit(d):
    problems = []
    manifest = json.loads((d / "manifest.json").read_text())
    prefix = "wstg-m" + d.name.split("-")[0]
    block = manifest.get("port_block", "")
    lo, hi = (int(x) for x in block.split("-")) if "-" in block else (0, 0)

    try:
        cfg = compose_json(d / "docker-compose.yml")
    except RuntimeError as exc:
        return [f"compose config failed: {exc}"]

    for name, svc in sorted(cfg.get("services", {}).items()):
        for p in svc.get("ports", []):
            ip = p.get("host_ip")
            if ip not in ("127.0.0.1", "::1"):
                problems.append(f"{name}: port {p.get('published')} bound to {ip!r}, must be loopback")
            pub = p.get("published")
            if pub and str(pub).isdigit() and lo and not (lo <= int(pub) <= hi):
                problems.append(f"{name}: published port {pub} outside manifest block {block}")

        if svc.get("privileged"):
            problems.append(f"{name}: privileged is forbidden")
        if svc.get("network_mode") == "host":
            problems.append(f"{name}: network_mode host is forbidden")
        for v in svc.get("volumes", []):
            src = v.get("source", "") if isinstance(v, dict) else str(v)
            if "docker.sock" in src:
                problems.append(f"{name}: docker socket mount is forbidden")

        image = svc.get("image", "")
        if image and LATEST.search(image.split("@")[0]):
            problems.append(f"{name}: image {image!r} is not pinned to an explicit tag")

        cname = svc.get("container_name", "")
        if cname and not cname.startswith(prefix + "-"):
            problems.append(f"{name}: container_name {cname!r} must start with {prefix}-")

        if svc.get("restart") in ("always", "unless-stopped", "on-failure"):
            problems.append(f"{name}: restart={svc['restart']!r}; a crashed lab must stay visible")

    raw = (d / "docker-compose.yml").read_text()
    for anchor in ("x-proxy-args", "x-proxy-env"):
        if anchor not in raw:
            problems.append(f"missing {anchor} anchor (container build egress will break)")

    readme = d / "README.md"
    if not readme.is_file():
        problems.append("missing README.md")
    elif not BANNER.search("\n".join(readme.read_text().splitlines()[:12])):
        problems.append("README.md has no warning banner in its first 12 lines")

    return problems


def main():
    args = [pathlib.Path(a) for a in sys.argv[1:]]
    dirs = args or sorted(p for p in MACHINES.iterdir() if p.is_dir())
    failed = 0
    for d in dirs:
        problems = audit(d)
        if problems:
            failed += 1
            print(f"[FAIL] {d.name}")
            for p in problems:
                print(f"         - {p}")
        else:
            print(f"[ OK ] {d.name}")
    print(f"\n{len(dirs) - failed}/{len(dirs)} machines pass the safety contract")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())