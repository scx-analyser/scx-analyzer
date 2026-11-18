#!/usr/bin/env python3
"""Validate fixtures and epic outputs against the shared contracts.

Run locally: python3 tools/validate_contracts.py

Besides JSON-Schema validation, catalog files get checks a schema cannot express:
id prefix == family, end_line >= line, ids unique across catalog/invariants/*.yaml,
and the catalog's enforcement-mechanism enum must equal the findings schema's.
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
# Real catalog files share one id namespace; fixtures are self-contained.
CATALOG_NAMESPACE = "catalog/invariants/"


def load(p: Path):
    return yaml.safe_load(p.read_text()) if p.suffix in (".yaml", ".yml") else json.loads(p.read_text())


def iter_refs(inv: dict):
    yield from inv.get("references", [])
    yield from inv.get("enforcement", {}).get("sites", [])


def catalog_semantic_errors(doc: dict) -> list[str]:
    errs, seen = [], set()
    for i, inv in enumerate(doc.get("invariants", [])):
        iid = inv.get("id", "")
        if iid in seen:
            errs.append(f"invariants/{i}/id: duplicate id {iid!r}")
        seen.add(iid)
        if iid.split(".", 1)[0] != inv.get("family"):
            errs.append(f"invariants/{i}/id: {iid!r} does not start with family {inv.get('family')!r}")
        for ref in iter_refs(inv):
            if "end_line" in ref and ref["end_line"] < ref.get("line", 0):
                errs.append(f"invariants/{i}: reference {ref.get('file')}:{ref.get('line')} has end_line < line")
            if "end_line" in ref and "line" not in ref:
                errs.append(f"invariants/{i}: reference {ref.get('file')} has end_line without line")
    return errs


def cross_contract_errors() -> list[str]:
    cat = set(SCHEMAS["catalog"]["$defs"]["mechanism"]["enum"])
    fnd = set(SCHEMAS["findings"]["properties"]["findings"]["items"]["properties"]["enforcement"]["items"]["enum"])
    if cat != fnd:
        return [f"catalog mechanism enum != findings enforcement enum: {sorted(cat ^ fnd)}"]
    return []


def main() -> int:
    failed = checked = 0
    for msg in cross_contract_errors():
        print(f"FAIL contracts: {msg}")
        failed += 1
    namespace: dict[str, Path] = {}
    for kind, globs in TARGETS.items():
        v = jsonschema.Draft202012Validator(SCHEMAS[kind])
        for g in globs:
            for p in sorted(ROOT.glob(g)):
                checked += 1
                rel = p.relative_to(ROOT).as_posix()
                doc = load(p)
                errs = [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(doc)]
                if kind == "catalog" and not errs:
                    errs += catalog_semantic_errors(doc)
                    if rel.startswith(CATALOG_NAMESPACE):
                        for inv in doc["invariants"]:
                            iid = inv["id"]
                            if iid in namespace and namespace[iid] != p:
                                other = namespace[iid].relative_to(ROOT).as_posix()
                                errs.append(f"id {iid!r} also defined in {other}")
                            namespace.setdefault(iid, p)
                for e in errs:
                    print(f"FAIL {rel}: {e}")
                failed += bool(errs)
                if not errs:
                    print(f"ok   {rel} ({kind})")
    print(f"{checked} file(s) checked, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
