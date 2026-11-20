#!/usr/bin/env python3
"""Assert that the 10 machines cover every active WSTG test, and emit the matrix.

Three-way consistency is enforced:
    coverage/catalog.json  (upstream truth)
      <-> machines/*/manifest.json  (declared coverage)
      <-> machines/*/verify/probes.py  (executable proof)

Exit code 0 only when coverage is complete and every declared test has a probe.
"""
import ast
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MACHINES = ROOT / "machines"
COVERAGE = ROOT / "coverage"

REQUIRED_FILES = ["docker-compose.yml", "manifest.json", "README.md", "verify/probes.py"]
PORT_BLOCK = re.compile(r"^(\d+)-(\d+)$")


def load_catalog():
    return json.loads((COVERAGE / "catalog.json").read_text())


def probe_names(path):
    """Top-level function names, read statically so no runtime deps are needed."""
    tree = ast.parse(path.read_text(), filename=str(path))
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "PROBES" and isinstance(node.value, ast.Dict):
                    for k in node.value.keys:
                        if isinstance(k, ast.Constant):
                            names.add(str(k.value))
    return names


def main():
    catalog = load_catalog()
    by_id = {t["id"]: t for t in catalog["tests"]}
    deprecated = {d["id"] for d in catalog["deprecated"]}
    errors, warnings = [], []

    dirs = sorted(p for p in MACHINES.iterdir() if p.is_dir()) if MACHINES.is_dir() else []
    if not dirs:
        sys.exit("no machines found")

    claimed = defaultdict(list)
    rows = []
    blocks = {}

    for d in dirs:
        for f in REQUIRED_FILES:
            if not (d / f).is_file():
                errors.append(f"{d.name}: missing {f}")
        mf = d / "manifest.json"
        if not mf.is_file():
            continue
        try:
            m = json.loads(mf.read_text())
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append(f"{d.name}: manifest.json is not valid JSON ({exc})")
            continue

        if m.get("machine") != d.name:
            errors.append(f"{d.name}: manifest.machine={m.get('machine')!r} != directory name")

        block = m.get("port_block")
        if not block or not PORT_BLOCK.match(str(block)):
            errors.append(f"{d.name}: missing/invalid port_block (expected 'NNNN-NNNN')")
        else:
            lo, hi = map(int, PORT_BLOCK.match(block).groups())
            if hi - lo < 10:
                errors.append(f"{d.name}: port_block too small")
            for other, (olo, ohi) in blocks.items():
                if not (hi < olo or ohi < lo):
                    errors.append(f"{d.name}: port_block {block} overlaps {other} ({olo}-{ohi})")
            blocks[d.name] = (lo, hi)

        probes_py = d / "verify" / "probes.py"
        available = set()
        if probes_py.is_file():
            try:
                available = probe_names(probes_py)
            except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
                errors.append(f"{d.name}: verify/probes.py cannot be parsed ({exc})")
                available = None
        seen_here = set()

        for t in m.get("tests", []):
            tid = t.get("id")
            if tid not in by_id:
                kind = "deprecated" if tid in deprecated else "unknown"
                errors.append(f"{d.name}: {kind} id {tid}")
                continue
            if tid in seen_here:
                errors.append(f"{d.name}: duplicate entry {tid}")
            seen_here.add(tid)
            claimed[tid].append(d.name)

            want_docs = set(by_id[tid]["docs"])
            got_docs = set(t.get("docs") or want_docs)
            if got_docs != want_docs:
                errors.append(
                    f"{d.name}: {tid} docs mismatch\n"
                    f"    missing: {sorted(want_docs - got_docs)}\n"
                    f"    extra:   {sorted(got_docs - want_docs)}"
                )
            probe = t.get("probe")
            if not probe:
                errors.append(f"{d.name}: {tid} has no probe")
            elif available is not None and probe not in available:
                errors.append(f"{d.name}: {tid} probe {probe!r} not defined in verify/probes.py")
            for field in ("surface", "weakness", "severity"):
                if not t.get(field):
                    errors.append(f"{d.name}: {tid} missing {field}")
            if t.get("degraded"):
                warnings.append(f"{d.name}: {tid} DEGRADED - {t['degraded']}")

            rows.append(
                {
                    "machine": d.name,
                    "id": tid,
                    "category": by_id[tid]["category"],
                    "name": by_id[tid]["name"],
                    "docs": len(want_docs),
                    "surface": t.get("surface", ""),
                    "weakness": t.get("weakness", ""),
                    "severity": t.get("severity", ""),
                    "probe": probe or "",
                    "degraded": t.get("degraded") or "",
                }
            )

        orphan = (available or set()) - {t.get("probe") for t in m.get("tests", [])}
        orphan = {o for o in orphan if not o.startswith("_") and o not in {"main", "run"}}
        if orphan:
            warnings.append(f"{d.name}: probes not referenced by manifest: {sorted(orphan)}")

    for tid in by_id:
        owners = claimed.get(tid, [])
        if not owners:
            errors.append(f"UNCOVERED: {tid} ({by_id[tid]['name']})")
        elif len(owners) > 1:
            errors.append(f"MULTI-CLAIMED: {tid} by {owners} (must be exactly one machine)")

    covered = len([t for t in by_id if claimed.get(t)])
    docs_covered = sum(len(by_id[t]["docs"]) for t in by_id if claimed.get(t))
    total_docs = catalog["stats"]["active_docs"]

    COVERAGE.mkdir(exist_ok=True)
    with (COVERAGE / "matrix.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["machine", "id"])
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["machine"], r["id"])))

    lines = [
        "# WSTG coverage matrix",
        "",
        f"Upstream: `{catalog['source']['repo']}` @ `{catalog['source']['commit'][:12]}`",
        "",
        f"**{covered}/{len(by_id)} test IDs** - **{docs_covered}/{total_docs} test documents** - "
        f"{len(blocks)} machines",
        "",
        "Excluded as removed upstream: " + ", ".join(sorted(deprecated)),
        "",
        "| Machine | ID | Name | Docs | Surface | Severity | Probe |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in sorted(rows, key=lambda r: (r["machine"], r["id"])):
        flag = " (degraded)" if r["degraded"] else ""
        lines.append(
            f"| {r['machine']} | `{r['id']}` | {r['name']}{flag} | {r['docs']} | "
            f"`{r['surface']}` | {r['severity']} | `{r['probe']}` |"
        )
    (COVERAGE / "matrix.md").write_text("\n".join(lines) + "\n")

    per_machine = defaultdict(int)
    for r in rows:
        per_machine[r["machine"]] += 1
    print("=== coverage ===")
    for name in sorted(per_machine):
        print(f"  {name:24} {per_machine[name]:3} ids")
    print(f"  {'TOTAL':24} {covered:3}/{len(by_id)} ids, {docs_covered}/{total_docs} docs")
    if warnings:
        print("\n=== warnings ===")
        for w in warnings:
            print("  " + w)
    if errors:
        print("\n=== ERRORS ===")
        for e in errors:
            print("  " + e)
        print(f"\nFAIL: {len(errors)} error(s)")
        return 1
    print("\nPASS: 100% coverage, every declared test has an executable probe")
    return 0


if __name__ == "__main__":
    sys.exit(main())