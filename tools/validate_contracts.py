#!/usr/bin/env python3
"""Validate fixtures and epic outputs against the shared contracts.

Run locally: python3 tools/validate_contracts.py
Negative tests: python3 -m unittest discover -s tools/tests

Besides JSON-Schema validation, catalog files get checks a schema cannot express:
- family ids and rule ids unique (within a file and across catalog/invariants/*.yaml),
  rule id prefix == enclosing family id, rule category == family category;
- end_line >= line everywhere; applies_to ["*"] not mixed with names;
- enforcement.expected consistent with enforcement.mechanisms (lockdep never counts
  as runtime; expected none needs mechanism none and excludes unknown);
- kernel_version: real catalogs == KERNEL_VERSION (once pinned), catalog fixtures ==
  the call-graph fixture's; kernel_commit == the known commit of kernel_version;
- rule roles: protection rules have obligations, entry_state rules have
  objects [] / access none / no obligations;
- obligations: unique ids per rule, access names a struct/fields listed in the rule's
  objects, ordering only on atomic accesses, requires present unless an ordered
  atomic, basis backed by matching evidence, no hypothesis in a source_verified rule,
  each path's root among the rule's applies_to and its last step a site function.
The catalog's enforcement-mechanism enum must equal the findings schema's.
"""
import json
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {k: json.loads((ROOT / f"contracts/{k}.schema.json").read_text(encoding="utf-8"))
           for k in ("catalog", "callgraph", "findings")}

# schema -> glob patterns of files that must conform
TARGETS = {
    "catalog": ["contracts/fixtures/catalog*.yaml", "catalog/invariants/*.yaml"],
    "callgraph": ["contracts/fixtures/callgraph*.json", "extractor/out/*.callgraph.json"],
    "findings": ["contracts/fixtures/findings*.json", "validation/results/*.findings.json"],
}
# Real catalog files share one id namespace; fixtures are self-contained.
CATALOG_NAMESPACE = "catalog/invariants/"
CALLGRAPH_FIXTURE = ROOT / "contracts/fixtures/callgraph.example.json"

# Full commits of the kernel tags catalogs are verified against. A catalog whose
# kernel_version is listed here must carry exactly this kernel_commit.
KNOWN_KERNEL_COMMITS = {
    "v7.1": "8cd9520d35a6c38db6567e97dd93b1f11f185dc6",
}

# enforcement.expected is about checks active on production kernels; lockdep
# (CONFIG_LOCKDEP only) is allowed in any rule but never counts.
STATIC_MECHS = {"kfunc_set", "verifier"}
RUNTIME_MECHS = {"lock", "scx_error", "warn", "guard", "atomic", "kf_mask"}

# obligation basis -> evidence kinds that can support it
BASIS_EVIDENCE = {
    "checked": {"lockdep_assert", "runtime_check"},
    "documented": {"kernel_comment"},
    "observed": {"acquired_on_path", "lockdep_assert"},
}


def load(p: Path):
    text = p.read_text(encoding="utf-8")
    return yaml.safe_load(text) if p.suffix in (".yaml", ".yml") else json.loads(text)


def pinned_kernel_version():
    """KERNEL_VERSION's tag, or None while it is still TBD."""
    try:
        text = (ROOT / "KERNEL_VERSION").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return None if line.upper().startswith("TBD") else line
    return None


def enforcement_errors(enf: dict) -> list[str]:
    exp, mechs = enf["expected"], set(enf["mechanisms"])
    has_s, has_r = bool(mechs & STATIC_MECHS), bool(mechs & RUNTIME_MECHS)
    want = {"static": (True, False), "runtime": (False, True),
            "static+runtime": (True, True), "none": (False, False)}.get(exp)
    errs = []
    if want and (has_s, has_r) != want:
        errs.append(f"expected {exp!r} does not match mechanisms {sorted(mechs)} "
                    f"(static: {sorted(STATIC_MECHS)}; runtime: {sorted(RUNTIME_MECHS)}; lockdep counts as neither)")
    if "none" in mechs and exp != "none":
        errs.append(f"mechanism 'none' used with expected {exp!r}")
    if exp == "none":
        if "unknown" in mechs:
            errs.append("expected 'none' (not enforced) contradicts mechanism 'unknown' (not determined)")
        if "none" not in mechs:
            errs.append("expected 'none' needs mechanism 'none'")
    return errs


def iter_lines(rule: dict):
    """(where, obj) for every object carrying line / end_line in a rule."""
    for ref in rule.get("references", []):
        yield "references", ref
    for ref in rule.get("enforcement", {}).get("sites", []):
        yield "enforcement.sites", ref
    for k, ob in enumerate(rule.get("obligations", [])):
        base = f"obligations[{k}]"
        for s in ob.get("sites", []):
            yield f"{base}.sites", s
        for ev in ob.get("evidence", []):
            yield f"{base}.evidence", ev
        for path in ob.get("paths", []):
            for s in path.get("entry", []):
                yield f"{base}.paths.entry", s
        for pred in ob.get("requires", {}).get("predicates", []):
            if "evaluated_at" in pred:
                yield f"{base}.requires.predicates.evaluated_at", pred["evaluated_at"]


def obligation_errors(rule: dict, loc: str) -> list[str]:
    errs, seen = [], set()
    objects = {}
    for obj in rule.get("objects", []):
        objects.setdefault(obj["struct"], set()).update(obj["fields"])
    for k, ob in enumerate(rule.get("obligations", [])):
        oloc = f"{loc}.obligations[{k}]"
        if ob["id"] in seen:
            errs.append(f"{oloc}.id: duplicate obligation id {ob['id']!r}")
        seen.add(ob["id"])
        acc = ob["access"]
        missing = set(acc["fields"]) - objects.get(acc["struct"], set())
        if acc["struct"] not in objects:
            errs.append(f"{oloc}.access: struct {acc['struct']!r} is not listed in the rule's objects")
        elif missing:
            errs.append(f"{oloc}.access: fields {sorted(missing)} of {acc['struct']!r} are not listed in the rule's objects")
        if "ordering" in acc and acc["op"] != "atomic":
            errs.append(f"{oloc}.access.ordering: only allowed with op 'atomic'")
        if "requires" not in ob and not (acc["op"] == "atomic" and "ordering" in acc):
            errs.append(f"{oloc}: requires is mandatory unless the access is an atomic with 'ordering'")
        basis = ob["basis"]
        if basis == "hypothesis" and rule.get("status") == "source_verified":
            errs.append(f"{oloc}.basis: a hypothesis cannot be part of a source_verified rule (use a draft rule)")
        kinds = {ev["kind"] for ev in ob["evidence"]}
        if basis in BASIS_EVIDENCE and not kinds & BASIS_EVIDENCE[basis]:
            errs.append(f"{oloc}.basis: {basis!r} needs evidence of kind {sorted(BASIS_EVIDENCE[basis])}, got {sorted(kinds)}")
        applies = set(rule.get("applies_to", []))
        for p, path in enumerate(ob.get("paths", [])):
            if "*" not in applies and path["root"] not in applies:
                errs.append(f"{oloc}.paths[{p}].root: {path['root']!r} is not in the rule's applies_to")
            if path["steps"][-1]["function"] not in {s["function"] for s in ob["sites"]}:
                errs.append(f"{oloc}.paths[{p}]: last step {path['steps'][-1]['function']!r} is not a site function")
    return errs


def role_errors(rule: dict, loc: str) -> list[str]:
    role, errs = rule.get("role"), []
    if role == "protection" and not rule.get("obligations"):
        errs.append(f"{loc}: role 'protection' needs at least one obligation")
    if role == "entry_state":
        if rule.get("obligations"):
            errs.append(f"{loc}: role 'entry_state' must not have obligations")
        if rule.get("objects"):
            errs.append(f"{loc}.objects: role 'entry_state' must have objects []")
        if rule.get("access") != "none":
            errs.append(f"{loc}.access: role 'entry_state' must have access 'none'")
    return errs


def catalog_ids(doc: dict) -> list[str]:
    """Family ids and rule ids of a schema-valid catalog (one shared namespace)."""
    ids = []
    for fam in doc["invariants"]:
        ids.append(fam["id"])
        ids.extend(rule["id"] for rule in fam["rules"])
    return ids


def catalog_semantic_errors(doc: dict) -> list[str]:
    errs, seen = [], set()
    for i, fam in enumerate(doc.get("invariants", [])):
        fid = fam.get("id", "")
        if fid in seen:
            errs.append(f"$.invariants[{i}].id: duplicate family id {fid!r}")
        seen.add(fid)
        for j, rule in enumerate(fam.get("rules", [])):
            loc = f"$.invariants[{i}].rules[{j}]"
            rid = rule.get("id", "")
            if rid in seen:
                errs.append(f"{loc}.id: duplicate rule id {rid!r}")
            seen.add(rid)
            if rid.split(".", 1)[0] != fid:
                errs.append(f"{loc}.id: {rid!r} does not start with family {fid!r}")
            if rule.get("category") != fam.get("category"):
                errs.append(f"{loc}.category: {rule.get('category')!r} != family category {fam.get('category')!r}")
            for where, ref in iter_lines(rule):
                if "end_line" in ref and ref["end_line"] < ref.get("line", 0):
                    errs.append(f"{loc}.{where}: {ref.get('file')}:{ref.get('line')} has end_line < line")
            if "*" in rule.get("applies_to", []) and len(rule["applies_to"]) > 1:
                errs.append(f"{loc}.applies_to: '*' must be the only entry")
            errs += [f"{loc}.enforcement: {e}" for e in enforcement_errors(rule["enforcement"])]
            errs += role_errors(rule, loc)
            errs += obligation_errors(rule, loc)
    return errs


def kernel_version_errors(doc: dict, rel: str) -> list[str]:
    kv, errs = doc["kernel_version"], []
    if rel.startswith(CATALOG_NAMESPACE):
        pinned = pinned_kernel_version()
        if pinned and kv != pinned:
            errs.append(f"$.kernel_version: {kv!r} != KERNEL_VERSION {pinned!r}")
    elif CALLGRAPH_FIXTURE.exists():
        cg = load(CALLGRAPH_FIXTURE).get("kernel_version")
        if kv != cg:
            errs.append(f"$.kernel_version: {kv!r} != {CALLGRAPH_FIXTURE.name} kernel_version {cg!r} "
                        "(the checker pairs the fixtures; change them together)")
    known = KNOWN_KERNEL_COMMITS.get(kv)
    if known and "kernel_commit" in doc and doc["kernel_commit"] != known:
        errs.append(f"$.kernel_commit: {doc['kernel_commit']!r} is not the commit of {kv} ({known})")
    if rel.startswith(CATALOG_NAMESPACE) and "kernel_commit" in doc and kv not in KNOWN_KERNEL_COMMITS:
        errs.append(f"$.kernel_version: {kv!r} has no known commit; add it to KNOWN_KERNEL_COMMITS")
    return errs


def cross_contract_errors() -> list[str]:
    try:
        cat = set(SCHEMAS["catalog"]["$defs"]["mechanism"]["enum"])
    except (KeyError, TypeError):
        return ["catalog schema has no $defs.mechanism.enum; update cross_contract_errors()"]
    try:
        fnd = set(SCHEMAS["findings"]["properties"]["findings"]["items"]["properties"]["enforcement"]["items"]["enum"])
    except (KeyError, TypeError):
        return ["findings schema has no findings[].enforcement enum; update cross_contract_errors()"]
    if cat != fnd:
        return [f"catalog mechanism enum != findings enforcement enum: {sorted(cat ^ fnd)}"]
    return []


def catalog_errors(doc, rel: str) -> list[str]:
    """All errors of one catalog document (schema first, then semantic checks)."""
    v = jsonschema.Draft202012Validator(SCHEMAS["catalog"])
    errs = [f"{e.json_path}: {e.message}" for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.path)))]
    if not errs:
        errs += catalog_semantic_errors(doc)
        errs += kernel_version_errors(doc, rel)
    return errs


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
                try:
                    doc = load(p)
                except (OSError, ValueError, yaml.YAMLError) as e:
                    print(f"FAIL {rel}: cannot parse: {e}")
                    failed += 1
                    continue
                if kind == "catalog":
                    errs = catalog_errors(doc, rel)
                    if not errs and rel.startswith(CATALOG_NAMESPACE):
                        for iid in catalog_ids(doc):
                            if iid in namespace and namespace[iid] != p:
                                other = namespace[iid].relative_to(ROOT).as_posix()
                                errs.append(f"id {iid!r} also defined in {other}")
                            namespace.setdefault(iid, p)
                else:
                    errs = [f"{e.json_path}: {e.message}"
                            for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.path)))]
                for e in errs:
                    print(f"FAIL {rel}: {e}")
                failed += bool(errs)
                if not errs:
                    print(f"ok   {rel} ({kind})")
    print(f"{checked} file(s) checked, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
