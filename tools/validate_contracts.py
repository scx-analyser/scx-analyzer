#!/usr/bin/env python3
"""Validate fixtures and epic outputs against the shared contracts.

Run locally: python3 tools/validate_contracts.py
"""
import json
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {k: json.loads((ROOT / f"contracts/{k}.schema.json").read_text()) for k in ("catalog", "callgraph", "findings")}

# schema -> glob patterns of files that must conform
TARGETS = {
    "catalog": ["contracts/fixtures/catalog*.yaml", "catalog/invariants/*.yaml"],
    "callgraph": ["contracts/fixtures/callgraph*.json", "extractor/out/*.callgraph.json"],
    "findings": ["contracts/fixtures/findings*.json", "validation/results/*.findings.json"],
}


def load(p: Path):
    return yaml.safe_load(p.read_text()) if p.suffix in (".yaml", ".yml") else json.loads(p.read_text())


def main() -> int:
    failed = checked = 0
    for kind, globs in TARGETS.items():
        v = jsonschema.Draft202012Validator(SCHEMAS[kind])
        for g in globs:
            for p in sorted(ROOT.glob(g)):
                checked += 1
                errs = list(v.iter_errors(load(p)))
                for e in errs:
                    print(f"FAIL {p.relative_to(ROOT)}: {'/'.join(map(str, e.path))}: {e.message}")
                failed += bool(errs)
                if not errs:
                    print(f"ok   {p.relative_to(ROOT)} ({kind})")
    print(f"{checked} file(s) checked, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
