#!/usr/bin/env python3
"""Fail if a real-looking credential was committed anywhere in the repo.

Every secret in this lab must be synthetic. Patterns are assembled from
fragments so this file does not match its own scan.

Usage:  python3 tools/scan_secrets.py
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

PATTERNS = [
    ("GitHub PAT", "gh" + "p_" + r"[A-Za-z0-9]{20,}"),
    ("GitHub OAuth token", "gh" + "o_" + r"[A-Za-z0-9]{20,}"),
    ("GitHub fine-grained PAT", "github" + "_pat_" + r"[A-Za-z0-9_]{20,}"),
    ("AWS access key id", "AKIA" + r"[0-9A-Z]{16}"),
    ("private key block", r"-----BEGIN [A-Z ]*PRIVATE" + r" KEY-----"),
    ("Slack token", "xox" + r"[baprs]-[A-Za-z0-9-]{10,}"),
]

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".browsers", "reports", ".mypy_cache", ".pytest_cache"}
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2", ".ttf", ".wasm", ".so", ".o", ".pyc"}


def main():
    hits = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIX:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for label, pattern in PATTERNS:
            for m in re.finditer(pattern, text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(f"{path.relative_to(ROOT)}:{line}: {label}")

    if hits:
        print("Possible real credentials committed (all lab secrets must be synthetic):")
        for h in hits:
            print(f"  {h}")
        return 1
    print("secret scan clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())