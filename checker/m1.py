"""M1 handoff preflight: no extraction, semantic dispatch or safety verdicts.

This fallback prepares an input contract while Epic B output is unpublished.
Site annotations are separate from the graph and never become proof by loading.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath

import jsonschema
import yaml

from .runner import load_data, require_compatible_dependencies, validate


SOURCE_VERSION = "v7.1"
SOURCE_COMMIT = "8cd9520d35a6c38db6567e97dd93b1f11f185dc6"
TARGET_ROOTS = ("scx_bpf_kick_cpu", "scx_bpf_cpuperf_set", "scx_bpf_test_and_clear_cpu_idle")


def graph_fingerprint(graph: dict) -> str:
    """Same canonical JSON fingerprint as C4; a digest is not source verification."""
    data = json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _relative_source(path: str) -> bool:
    return not (PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                or "\\" in path or ":" in path)


def _check_sidecar(graph: dict, sidecar: dict, digest: str) -> None:
    schema = json.loads(Path(__file__).with_name("m1-sidecar.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(sidecar)
    if sidecar["graph_sha256"] != digest:
        raise ValueError("sidecar graph fingerprint mismatch; annotations need review against this graph")
    if sidecar["extraction_claim"]["generator"] != graph["generator"]:
        raise ValueError("sidecar extraction generator does not match graph")
    seen = set()
    for site in sidecar["sites"]:
        key = (site["root"], site["rule_id"], site["obligation_id"], site["function"],
               site["event_index"], site["object"])
        if key in seen:
            raise ValueError("duplicate hand-reviewed site binding")
        seen.add(key)
        if site["root"] not in graph["roots"]:
            raise ValueError("sidecar site root is not a graph root")
        node = graph["nodes"].get(site["function"])
        if node is None or node["kind"] not in ("kfunc", "internal"):
            raise ValueError("sidecar site function is missing or opaque")
        events = node.get("events", [])
        # JSON Schema integer includes integral floats such as 0.0. The schema
        # has already rejected fractional values/bools; index without mutating
        # the supplied annotation or rounding an unvalidated number.
        index = int(site["event_index"])
        if index >= len(events):
            raise ValueError("sidecar site event is missing; unordered writes are insufficient")
        event = events[index]
        if (node.get("file") != site["file"] or event.get("line") != site["line"]
                or event["kind"] != site["access_kind"] or event.get("field") != site["field"]):
            raise ValueError("sidecar site does not match exact function/file/line/field/access kind")
        ref = site["reference"]
        if (not _relative_source(site["file"]) or ref["file"] != site["file"]
                or ref["symbol"] != site["function"] or not ref["line"] <= site["line"] <= ref["end_line"]):
            raise ValueError("sidecar source reference does not cover its exact site")


def preflight(callgraph: dict | None = None, sidecar: dict | None = None) -> dict:
    """Validate handoff consistency and emit UNKNOWN readiness coverage.

    Never calls an analyzer, authenticates publication or compiles a catalog
    obligation. Even a matching site/URL/hash is insufficient to establish any
    predicate, lock, reachability or completeness fact. Inputs are not modified.
    """
    require_compatible_dependencies()
    blockers = {"catalog_policy_adapter_pending", "analyzer_dispatch_pending"}
    digest = None
    if callgraph is None:
        if sidecar is not None:
            raise ValueError("a sidecar requires its exact callgraph")
        blockers.add("published_extraction_missing")
    else:
        validate("callgraph", callgraph)
        if callgraph["kernel_version"] != SOURCE_VERSION:
            raise ValueError("kernel version mismatch: this proposed M1 slice requires v7.1")
        if set(callgraph["roots"]) - callgraph["nodes"].keys():
            raise ValueError("graph roots missing from nodes")
        digest = graph_fingerprint(callgraph)
        blockers.add("extraction_publication_and_source_not_verified")
        if callgraph.get("illustrative", False):
            blockers.add("illustrative_input")
    if sidecar is None:
        blockers.add("hand_reviewed_sidecar_missing")
    else:
        _check_sidecar(callgraph, sidecar, digest)
        blockers.add("annotation_semantics_and_object_bindings_not_verified")
        if not sidecar["extraction_claim"].get("config_sha256"):
            blockers.add("configuration_provenance_missing")

    findings = []
    coverage = []
    for root in TARGET_ROOTS:
        present = callgraph is not None and root in callgraph["roots"]
        reasons = set(blockers)
        if not present:
            reasons.add("requested_root_not_extracted")
        elif callgraph["nodes"][root]["kind"] != "kfunc":
            reasons.add("requested_root_not_expanded_as_kfunc")
        coverage.append({"root": root, "present_in_graph_roots": present, "blockers": sorted(reasons)})
        for family in ("I1", "I3"):
            sites = [] if sidecar is None else [s for s in sidecar["sites"]
                if s["root"] == root and s["rule_id"].startswith(family + ".")]
            findings.append({
                "kfunc": root, "invariant": family, "verdict": "unknown",
                "enforcement": ["unknown"], "static_or_runtime": "unknown",
                "explanation": "Requested M1 coverage only; applicability is unknown. "
                               "No semantic analyzer or kernel access assessed.",
                "evidence": [{"function": root, "detail": "Missing or unverified integration inputs; "
                             "site bindings are untrusted claims, not semantic evidence.",
                    "record_kind": "requested_coverage", "applicability": "unknown",
                    "analysis_performed": False, "expected_kernel_commit": SOURCE_COMMIT,
                    "source_verified": False, "publication_verified": False,
                    "site_bindings_trusted": False,
                    "annotation_origin": sidecar["origin"] if sidecar is not None else None,
                    "runtime_results_included": False,
                    "graph_sha256": digest, "blockers": sorted(reasons), "site_bindings": sites}],
            })
    envelope = {"kernel_version": callgraph["kernel_version"] if callgraph is not None else "unknown",
                "findings": findings}
    if digest is not None:
        envelope["callgraph"] = "sha256:" + digest
    validate("findings", envelope)
    # Snapshot annotation dictionaries so callers cannot change evidence later.
    return json.loads(json.dumps({
        "format": "scxa.m1.preflight.v1", "status": "blocked", "analysis_performed": False,
        "expected_source": {"version": SOURCE_VERSION, "commit": SOURCE_COMMIT},
        "extraction": {"claim": sidecar["extraction_claim"] if sidecar is not None else None,
                       "publication_verified": False, "source_verified": False},
        "analyzers_called": [], "coverage": coverage,
        "annotations": {"provided": sidecar is not None,
                        "origin": "hand_reviewed_source_annotations", "semantics_evaluated": False,
                        "site_bindings_checked": len(sidecar["sites"]) if sidecar is not None else 0},
        "runtime_results": {"included": False, "correlation_performed": False},
        "static_findings": envelope,
    }, allow_nan=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--callgraph", type=Path, help="actual published Epic B graph; no fixture default")
    parser.add_argument("--sidecar", type=Path, help="separate proposed hand-reviewed site-binding sidecar")
    args = parser.parse_args(argv)
    try:
        graph = load_data(args.callgraph) if args.callgraph is not None else None
        sidecar = load_data(args.sidecar) if args.sidecar is not None else None
        print(json.dumps(preflight(graph, sidecar), indent=2, sort_keys=True, allow_nan=False))
        return 3  # Explicitly blocked; zero is reserved for future completed integration.
    except (jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        print(f"scxa m1: {exc.json_path}: {exc.message}", file=sys.stderr)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print(f"scxa m1: {exc}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
