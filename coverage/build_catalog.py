#!/usr/bin/env python3
"""Build coverage/catalog.json from an OWASP/wstg checkout.

Usage: python3 coverage/build_catalog.py /path/to/wstg [output.json]

The upstream markdown ID tables are the source of truth. checklists/checklist.json
is used only to enrich entries with objectives, because it silently drops the two
removed chapters and de-duplicates the WSTG-INJT-13 collision.
"""
import json
import re
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path

DOC_REL = "document/4-Web_Application_Security_Testing"
ID_RE = re.compile(r"\|\s*(WSTG-[A-Z]+-[0-9]+(?:\.[0-9]+)?)\s*\|")
REMOVED_MARKER = "This content has been removed."

# Sub-chapters carry no ID table of their own; they belong to a parent test.
SUBDOC_PARENT = {
    "05-Authorization/05.1-OAuth_Authorization_Server_Weaknesses.md": "WSTG-ATHZ-05",
    "05-Authorization/05.2-OAuth_Client_Weaknesses.md": "WSTG-ATHZ-05",
    "07-Injection/05.1-Oracle.md": "WSTG-INJT-05",
    "07-Injection/05.2-MySQL.md": "WSTG-INJT-05",
    "07-Injection/05.3-SQL_Server.md": "WSTG-INJT-05",
    "07-Injection/05.4-PostgreSQL.md": "WSTG-INJT-05",
    "07-Injection/05.5-MS_Access.md": "WSTG-INJT-05",
    "07-Injection/05.6-NoSQL_Injection.md": "WSTG-INJT-05",
    "07-Injection/05.7-ORM_Injection.md": "WSTG-INJT-05",
    "07-Injection/05.8-Client-side.md": "WSTG-INJT-05",
    "07-Injection/11.1-File_Inclusion.md": "WSTG-INJT-11",
    "11-Client-side/01.1-Self_DOM_Based_Cross_Site_Scripting.md": "WSTG-CLNT-01",
}

CATEGORY_NAMES = {
    "WSTG-INFO": "Information Gathering",
    "WSTG-CONF": "Configuration and Deployment Management",
    "WSTG-IDNT": "Identity Management",
    "WSTG-ATHN": "Authentication",
    "WSTG-ATHZ": "Authorization",
    "WSTG-SESS": "Session Management",
    "WSTG-INJT": "Injection",
    "WSTG-ERRH": "Error Handling",
    "WSTG-CRYP": "Weak Cryptography",
    "WSTG-BUSL": "Business Logic",
    "WSTG-CLNT": "Client-side",
    "WSTG-APIT": "API Testing",
    "WSTG-WASM": "WebAssembly Testing",
}


def title_of(text, path):
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    repo = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).with_name("catalog.json")
    base = repo / DOC_REL
    if not base.is_dir():
        sys.exit(f"not a wstg checkout: {base}")

    objectives = {}
    ck_path = repo / "checklists" / "checklist.json"
    if ck_path.is_file():
        ck = json.loads(ck_path.read_text())
        for cat in ck["categories"].values():
            for t in cat["tests"]:
                objectives[t["id"]] = t.get("objectives", [])

    entries = OrderedDict()
    deprecated = []
    orphans = []

    for path in sorted(base.rglob("*.md")):
        rel = str(path.relative_to(base))
        if path.name == "README.md" or path.name.startswith("00-"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        found = ID_RE.findall(text)
        if not found:
            parent = SUBDOC_PARENT.get(rel)
            if parent is None:
                orphans.append(rel)
                continue
            entries.setdefault(parent, {"docs": [], "titles": []})
            entries[parent]["docs"].append(rel)
            entries[parent]["titles"].append(title_of(text, path))
            continue
        for tid in dict.fromkeys(found):
            if REMOVED_MARKER in text:
                deprecated.append({"id": tid, "doc": rel})
                continue
            e = entries.setdefault(tid, {"docs": [], "titles": []})
            e["docs"].append(rel)
            e["titles"].append(title_of(text, path))

    if orphans:
        sys.exit(f"unmapped sub-documents (update SUBDOC_PARENT): {orphans}")

    tests = []
    for tid in sorted(entries, key=lambda x: (list(CATEGORY_NAMES).index(x.rsplit("-", 1)[0]), x)):
        e = entries[tid]
        prefix = tid.rsplit("-", 1)[0]
        name = " / ".join(dict.fromkeys(e["titles"]))
        tests.append(
            {
                "id": tid,
                "category": prefix,
                "category_name": CATEGORY_NAMES[prefix],
                "name": name,
                "docs": sorted(e["docs"]),
                "objectives": objectives.get(tid, []),
                "id_collision": len([d for d in e["docs"] if d not in SUBDOC_PARENT]) > 1,
            }
        )

    try:
        commit = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        commit = "unknown"

    catalog = {
        "source": {
            "repo": "https://github.com/OWASP/wstg",
            "branch": "master",
            "commit": commit,
            "doc_base": DOC_REL,
            "license": "CC-BY-SA-4.0",
            "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "attribution": "OWASP Web Security Testing Guide (https://owasp.org/www-project-web-security-testing-guide/)",
            "note": "Derived work of the OWASP WSTG. This file is CC BY-SA 4.0, not MIT; ShareAlike applies to derivatives. See NOTICE.",
        },
        "deprecated": deprecated,
        "tests": tests,
        "stats": {
            "active_ids": len(tests),
            "active_docs": sum(len(t["docs"]) for t in tests),
            "categories": len({t["category"] for t in tests}),
        },
    }
    out.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}")
    print(json.dumps(catalog["stats"], indent=2))
    print("deprecated:", [d["id"] for d in deprecated])
    print("collisions:", [t["id"] for t in tests if t["id_collision"]])


if __name__ == "__main__":
    main()