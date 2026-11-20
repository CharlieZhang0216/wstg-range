#!/usr/bin/env python3
"""Run a machine's WSTG probes and report per-test PASS/FAIL.

    python3 tools/runner.py machines/01-recon-config
    python3 tools/runner.py machines/01-recon-config --only WSTG-CONF-06
    python3 tools/runner.py --all

A probe is a function `def name(ctx) -> (bool, evidence_str)` in the machine's
verify/probes.py. PASS means the intentional weakness is demonstrably present,
i.e. the lab is correctly broken and the WSTG test can be exercised against it.
"""
import argparse
import importlib.util
import json
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from labhttp import Session, wait_for  # noqa: E402


class Ctx:
    def __init__(self, manifest):
        self.manifest = manifest
        self.base = manifest["primary_url"].rstrip("/")
        self.endpoints = manifest.get("endpoints", {})
        self.machine = manifest["machine"]

    def url(self, key="/"):
        if key in self.endpoints:
            return self.endpoints[key].rstrip("/")
        if key.startswith("http"):
            return key
        return self.base + (key if key.startswith("/") else "/" + key)

    def session(self, base=None):
        return Session(base or self.base)


def load_probes(machine_dir):
    path = machine_dir / "verify" / "probes.py"
    spec = importlib.util.spec_from_file_location(f"probes_{machine_dir.name}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    table = getattr(mod, "PROBES", None)
    if table is None:
        table = {
            t["probe"]: getattr(mod, t["probe"])
            for t in json.loads((machine_dir / "manifest.json").read_text())["tests"]
            if hasattr(mod, t.get("probe", ""))
        }
    return table


def run_machine(machine_dir, only=None, wait=True, verbose=False):
    manifest = json.loads((machine_dir / "manifest.json").read_text())
    ctx = Ctx(manifest)
    try:
        probes = load_probes(machine_dir)
    except Exception as e:
        print(f"[{machine_dir.name}] cannot load probes: {e}")
        if verbose:
            traceback.print_exc()
        return {"machine": machine_dir.name, "error": str(e), "results": []}

    if wait:
        try:
            wait_for(ctx.base + manifest.get("health_path", "/"), timeout=manifest.get("startup_timeout", 180))
        except Exception as e:
            print(f"[{machine_dir.name}] not reachable: {e}")

    results = []
    print(f"\n=== {machine_dir.name} - {manifest.get('title','')} ===")
    for t in manifest["tests"]:
        tid = t["id"]
        if only and tid not in only and t.get("probe") not in only:
            continue
        fn = probes.get(t["probe"])
        if fn is None:
            status, ev = "MISSING", f"probe {t['probe']!r} not found"
        else:
            start = time.time()
            try:
                out = fn(ctx)
                if isinstance(out, tuple):
                    ok, ev = out
                else:
                    ok, ev = bool(out), ""
                status = "PASS" if ok else "FAIL"
                ev = str(ev)[:400]
            except Exception as e:
                status, ev = "ERROR", f"{type(e).__name__}: {e}"
                if verbose:
                    traceback.print_exc()
            elapsed = time.time() - start
            if verbose:
                print(f"    ({elapsed:.2f}s)")
        results.append({"id": tid, "probe": t["probe"], "status": status, "evidence": ev})
        mark = {"PASS": "+", "FAIL": "-", "ERROR": "!", "MISSING": "?"}[status]
        print(f"  [{mark}] {tid:16} {status:7} {ev[:150]}")

    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("PASS", "FAIL", "ERROR", "MISSING")}
    print(f"  -> {counts['PASS']}/{len(results)} passed" + (f"  {counts}" if counts["FAIL"] or counts["ERROR"] or counts["MISSING"] else ""))
    return {"machine": machine_dir.name, "counts": counts, "results": results}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("machine", nargs="?", help="machine directory")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--no-wait", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--report", default=None, help="write JSON report to this path")
    a = ap.parse_args()

    if a.all:
        dirs = sorted(p for p in (ROOT / "machines").iterdir() if p.is_dir() and (p / "manifest.json").is_file())
    elif a.machine:
        d = Path(a.machine)
        if not d.is_absolute():
            d = ROOT / d
        dirs = [d]
    else:
        ap.error("give a machine directory or --all")

    reports = [run_machine(d, a.only, not a.no_wait, a.verbose) for d in dirs]

    if a.report:
        Path(a.report).parent.mkdir(parents=True, exist_ok=True)
        Path(a.report).write_text(json.dumps(reports, indent=2, ensure_ascii=False) + "\n")

    total = sum(len(r["results"]) for r in reports)
    passed = sum(r.get("counts", {}).get("PASS", 0) for r in reports)
    print(f"\n=== TOTAL: {passed}/{total} probes passed across {len(reports)} machine(s) ===")
    bad = [r for r in reports if r.get("error") or any(x["status"] != "PASS" for x in r["results"])]
    return 1 if bad or passed != total else 0


if __name__ == "__main__":
    sys.exit(main())