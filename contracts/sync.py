#!/usr/bin/env python3
"""Copy the contracts into each repo that implements them.

    python3 sync.py                       # every repo checked out beside this one
    python3 sync.py --check               # list what is stale, write nothing
    python3 sync.py --root collarID_thread=/path/to/a/worktree

Each repo gets the spec, the vectors and the generated constants for its
language, at the paths in TARGETS; its own contract test reads them there,
checks its code against them, and (when this repo is beside it) checks that
its copies are still these. Standard library only.
"""

import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC = os.path.join(HERE, "collarid_contracts.json")
VECTORS = os.path.join(ROOT, "test_vectors", "contracts_v1.json")
GEN = os.path.join(HERE, "generated")

# repo -> {path in the repo: source}
TARGETS = {
    "collarID_thread": {
        "Core/Inc/collarid_contracts.h": os.path.join(GEN, "collarid_contracts.h"),
        "test/host/contracts/collarid_contracts.json": SPEC,
        "test/host/contracts/contracts_v1.json": VECTORS,
        "scripts/fleet_flash/collarid_contracts.py": os.path.join(GEN, "collarid_contracts.py"),
    },
    "CollarID_BLE": {
        "common/collarid_contracts.h": os.path.join(GEN, "collarid_contracts.h"),
        "tools/contracts/collarid_contracts.json": SPEC,
        "tools/contracts/contracts_v1.json": VECTORS,
    },
    "collarid-prod": {
        "api/collarid_contracts.py": os.path.join(GEN, "collarid_contracts.py"),
        "tests/contracts/collarid_contracts.json": SPEC,
        "tests/contracts/contracts_v1.json": VECTORS,
    },
    "collaridwebsite": {
        "js/collarid-contracts.js": os.path.join(GEN, "collarid-contracts.js"),
        "test/contracts/collarid_contracts.json": SPEC,
        "test/contracts/contracts_v1.json": VECTORS,
    },
    "CollarIDApp": {
        "src/contracts/collaridContracts.ts": os.path.join(GEN, "collaridContracts.ts"),
        "test-utils/contracts/collarid_contracts.json": SPEC,
        "test-utils/contracts/contracts_v1.json": VECTORS,
    },
}


def default_root(repo):
    return os.path.join(os.path.dirname(ROOT), repo)


def plan(roots):
    """[(repo, destination, source, state)] where state is current / stale / new / no repo."""
    out = []
    for repo, files in TARGETS.items():
        root = roots.get(repo) or default_root(repo)
        for rel, src in files.items():
            dest = os.path.join(root, rel)
            if not os.path.isdir(root):
                out.append((repo, dest, src, "no repo"))
                continue
            if not os.path.exists(dest):
                out.append((repo, dest, src, "new"))
            else:
                same = open(dest, "rb").read() == open(src, "rb").read()
                out.append((repo, dest, src, "current" if same else "stale"))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--root", action="append", default=[], metavar="REPO=PATH")
    ap.add_argument("--only", action="append", default=[], metavar="REPO")
    a = ap.parse_args(argv)
    roots = dict(r.split("=", 1) for r in a.root)
    rows = [r for r in plan(roots) if not a.only or r[0] in a.only]
    bad = 0
    for repo, dest, src, state in rows:
        if state in ("stale", "new"):
            bad += 1
            if not a.check:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copyfile(src, dest)
                state = "written"
        print(f"{state:<8} {repo:<18} {dest}")
    if a.check and bad:
        print(f"\n{bad} stale or missing: run contracts/sync.py")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
