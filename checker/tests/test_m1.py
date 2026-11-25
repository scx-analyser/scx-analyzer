"""Synthetic handoff-contract tests; no extracted Linux data or kernel proofs."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import jsonschema

from checker.checkers import registered
from checker.m1 import SOURCE_COMMIT, SOURCE_VERSION, TARGET_ROOTS, graph_fingerprint, main, preflight
from checker.runner import ROOT, validate


def inputs():
    # Deliberately illustrative. The public root names exercise handoff routing;
    # synthetic.c and its invented event are NOT Linux source annotations.
    graph = {"kernel_version": SOURCE_VERSION, "generator": "synthetic contract test, not extraction",
             "illustrative": True, "roots": list(TARGET_ROOTS),
             "nodes": {r: {"kind": "kfunc", "file": "synthetic.c", "events": [], "callees": []}
                       for r in TARGET_ROOTS}}
    graph["nodes"][TARGET_ROOTS[0]]["events"] = [
        {"kind": "atomic", "field": "rq.synthetic_state", "op": "set_bit", "line": 7}]
    sidecar = {"format": "scxa.m1.sidecar.v1", "origin": "hand_reviewed_source_annotations",
               "source": {"version": SOURCE_VERSION, "commit": SOURCE_COMMIT},
               "graph_sha256": graph_fingerprint(graph),
               "extraction_claim": {"kind": "epic_b_extraction", "repository": "scx-analyser/scx-analyzer",
                   "revision": "0" * 40, "url": "https://example.invalid/not-a-published-artifact",
                   "generator": graph["generator"], "config_sha256": None},
               "sites": [{"root": TARGET_ROOTS[0], "rule_id": "I3.synthetic", "obligation_id": "synthetic",
                   "function": TARGET_ROOTS[0], "file": "synthetic.c", "line": 7, "event_index": 0,
                   "field": "rq.synthetic_state", "access_kind": "atomic", "object": "synthetic:rq0",
                   "reference": {"file": "synthetic.c", "symbol": TARGET_ROOTS[0], "line": 7, "end_line": 7}}]}
    return graph, sidecar


class HandoffTests(unittest.TestCase):
    def test_missing_extraction_has_unknown_coverage_for_every_requested_root_and_family(self):
        report = preflight()
        self.assertEqual("blocked", report["status"])
        self.assertFalse(report["analysis_performed"])
        self.assertEqual([], report["analyzers_called"])
        self.assertFalse(report["annotations"]["provided"])
        self.assertEqual("unknown", report["static_findings"]["kernel_version"])
        rows = report["static_findings"]["findings"]
        self.assertEqual({(r, i) for r in TARGET_ROOTS for i in ("I1", "I3")},
                         {(f["kfunc"], f["invariant"]) for f in rows})
        self.assertTrue(all(f["verdict"] == "unknown" and "path" not in f for f in rows))
        self.assertTrue(all("published_extraction_missing" in c["blockers"] for c in report["coverage"]))
        validate("findings", report["static_findings"])

    def test_matching_sidecar_is_consistency_only_not_source_or_safety_verification(self):
        graph, sidecar = inputs()
        report = preflight(graph, sidecar)
        self.assertEqual(1, report["annotations"]["site_bindings_checked"])
        self.assertFalse(report["annotations"]["semantics_evaluated"])
        self.assertFalse(report["extraction"]["publication_verified"])
        self.assertFalse(report["extraction"]["source_verified"])
        self.assertTrue(all(f["verdict"] == "unknown" for f in report["static_findings"]["findings"]))
        self.assertFalse(report["runtime_results"]["included"])
        self.assertTrue(all("illustrative_input" in c["blockers"] for c in report["coverage"]))
        evidence = report["static_findings"]["findings"][1]["evidence"][0]
        self.assertEqual(SOURCE_COMMIT, evidence["expected_kernel_commit"])
        self.assertEqual(graph_fingerprint(graph), evidence["graph_sha256"])
        self.assertEqual(sidecar["sites"], evidence["site_bindings"])

    def test_exported_envelope_preserves_exact_identities_unknown_applicability_and_trust(self):
        expected = {("scx_bpf_kick_cpu", "I1"), ("scx_bpf_kick_cpu", "I3"),
                    ("scx_bpf_cpuperf_set", "I1"), ("scx_bpf_cpuperf_set", "I3"),
                    ("scx_bpf_test_and_clear_cpu_idle", "I1"),
                    ("scx_bpf_test_and_clear_cpu_idle", "I3")}
        for args in ((), inputs()):
            envelope = json.loads(json.dumps(preflight(*args)["static_findings"]))
            rows = envelope["findings"]
            self.assertEqual(6, len(rows))
            self.assertEqual(expected, {(f["kfunc"], f["invariant"]) for f in rows})
            for finding in rows:
                self.assertEqual("unknown", finding["verdict"])
                self.assertEqual(["unknown"], finding["enforcement"])
                self.assertEqual("unknown", finding["static_or_runtime"])
                self.assertNotIn("path", finding)
                evidence = finding["evidence"][0]
                self.assertEqual(finding["kfunc"], evidence["function"])
                self.assertEqual("requested_coverage", evidence["record_kind"])
                self.assertEqual("unknown", evidence["applicability"])
                for key in ("analysis_performed", "source_verified", "publication_verified",
                            "site_bindings_trusted", "runtime_results_included"):
                    self.assertIs(evidence[key], False)
                self.assertEqual("hand_reviewed_source_annotations" if args else None,
                                 evidence["annotation_origin"])
            validate("findings", envelope)

    def test_schema_valid_integral_json_index_does_not_crash_or_mutate_the_annotation(self):
        graph, sidecar = inputs()
        sidecar["sites"][0]["event_index"] = 0.0
        report = preflight(graph, sidecar)
        self.assertEqual(1, report["annotations"]["site_bindings_checked"])
        self.assertIsInstance(sidecar["sites"][0]["event_index"], float)
        self.assertFalse(report["analysis_performed"])
        for index in (0.25, True):
            sidecar["sites"][0]["event_index"] = index
            with self.subTest(index=index), self.assertRaises(jsonschema.ValidationError):
                preflight(graph, sidecar)

    def test_nested_trust_claims_are_rejected_at_every_sidecar_level(self):
        for location in ("top", "source", "extraction_claim", "site", "reference"):
            graph, sidecar = inputs()
            target = {"top": sidecar, "source": sidecar["source"],
                      "extraction_claim": sidecar["extraction_claim"], "site": sidecar["sites"][0],
                      "reference": sidecar["sites"][0]["reference"]}[location]
            target["source_verified"] = True
            with self.subTest(location=location), self.assertRaises(jsonschema.ValidationError):
                preflight(graph, sidecar)

    def test_nonillustrative_label_and_config_hash_do_not_authenticate_publication(self):
        graph, sidecar = inputs()
        graph["illustrative"] = False  # Adversarial assertion, not real extraction.
        sidecar["graph_sha256"] = graph_fingerprint(graph)
        sidecar["extraction_claim"]["config_sha256"] = "1" * 64
        report = preflight(graph, sidecar)
        self.assertEqual("blocked", report["status"])
        self.assertTrue(all("extraction_publication_and_source_not_verified" in c["blockers"]
                            for c in report["coverage"]))

    def test_graph_without_sidecar_stays_unknown(self):
        graph, _ = inputs()
        report = preflight(graph)
        self.assertTrue(all("hand_reviewed_sidecar_missing" in c["blockers"] for c in report["coverage"]))

    def test_sidecar_without_graph_is_rejected(self):
        _, sidecar = inputs()
        with self.assertRaisesRegex(ValueError, "exact callgraph"):
            preflight(sidecar=sidecar)

    def test_partial_roots_do_not_disappear(self):
        graph, _ = inputs()
        graph["roots"] = [TARGET_ROOTS[0]]
        report = preflight(graph)
        self.assertEqual(6, len(report["static_findings"]["findings"]))
        self.assertEqual([True, False, False], [c["present_in_graph_roots"] for c in report["coverage"]])
        self.assertTrue(all("requested_root_not_extracted" in c["blockers"] for c in report["coverage"][1:]))

    def test_declared_missing_node_and_opaque_root_are_conservative(self):
        graph, _ = inputs()
        del graph["nodes"][TARGET_ROOTS[0]]
        with self.assertRaisesRegex(ValueError, "roots missing"):
            preflight(graph)
        graph, _ = inputs()
        graph["nodes"][TARGET_ROOTS[0]]["kind"] = "boundary"
        self.assertIn("requested_root_not_expanded_as_kfunc", preflight(graph)["coverage"][0]["blockers"])

    def test_stale_graph_fingerprint_and_generator_mismatch_are_rejected(self):
        graph, sidecar = inputs()
        graph["nodes"][TARGET_ROOTS[0]]["events"][0]["line"] = 8
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            preflight(graph, sidecar)
        graph, sidecar = inputs()
        sidecar["extraction_claim"]["generator"] = "different tool"
        with self.assertRaisesRegex(ValueError, "generator"):
            preflight(graph, sidecar)

    def test_source_version_and_full_commit_must_match_the_reference(self):
        graph, sidecar = inputs()
        graph["kernel_version"] = "TBD"
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            preflight(graph, sidecar)
        for change in ({"version": "v7.2"}, {"commit": "1" * 40}, {"commit": SOURCE_COMMIT[:7]}):
            graph, sidecar = inputs()
            sidecar["source"].update(change)
            with self.subTest(change=change), self.assertRaises(jsonschema.ValidationError):
                preflight(graph, sidecar)

    def test_exact_event_site_and_source_reference_binding(self):
        for change in ({"function": "absent"}, {"file": "wrong.c"}, {"line": 8},
                       {"field": "rq.other"}, {"access_kind": "write"}, {"event_index": 9}):
            graph, sidecar = inputs()
            sidecar["sites"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                preflight(graph, sidecar)
        for change in ({"symbol": "other"}, {"end_line": 6}, {"file": "wrong.c"}):
            graph, sidecar = inputs()
            sidecar["sites"][0]["reference"].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "reference"):
                preflight(graph, sidecar)

    def test_unordered_writes_cannot_supply_an_ordered_site(self):
        graph, sidecar = inputs()
        graph["nodes"][TARGET_ROOTS[0]]["events"] = []
        graph["nodes"][TARGET_ROOTS[0]]["writes"] = ["rq.synthetic_state"]
        sidecar["graph_sha256"] = graph_fingerprint(graph)
        with self.assertRaisesRegex(ValueError, "unordered writes"):
            preflight(graph, sidecar)

    def test_site_existence_does_not_invent_reachability_or_aliases(self):
        graph, sidecar = inputs()
        graph["nodes"]["unreachable_helper"] = graph["nodes"][TARGET_ROOTS[0]]
        graph["nodes"][TARGET_ROOTS[0]] = {"kind": "kfunc", "events": [], "callees": []}
        sidecar["sites"][0]["function"] = "unreachable_helper"
        sidecar["sites"][0]["reference"]["symbol"] = "unreachable_helper"
        sidecar["graph_sha256"] = graph_fingerprint(graph)
        report = preflight(graph, sidecar)
        self.assertFalse(report["analysis_performed"])
        self.assertTrue(all("path" not in f for f in report["static_findings"]["findings"]))
        self.assertTrue(all("annotation_semantics_and_object_bindings_not_verified" in c["blockers"]
                            for c in report["coverage"]))

    def test_empty_object_duplicate_sites_and_unbound_root_are_rejected(self):
        graph, sidecar = inputs()
        sidecar["sites"][0]["object"] = " "
        with self.assertRaises(jsonschema.ValidationError):
            preflight(graph, sidecar)
        graph, sidecar = inputs()
        sidecar["sites"].append(copy.deepcopy(sidecar["sites"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            preflight(graph, sidecar)
        graph, sidecar = inputs()
        graph["roots"] = [TARGET_ROOTS[1]]
        sidecar["graph_sha256"] = graph_fingerprint(graph)
        with self.assertRaisesRegex(ValueError, "not a graph root"):
            preflight(graph, sidecar)

    def test_distinct_objects_and_conjunctive_obligations_are_not_merged(self):
        graph, sidecar = inputs()
        other = copy.deepcopy(sidecar["sites"][0])
        other["object"] = "synthetic:rq1"
        third = copy.deepcopy(sidecar["sites"][0])
        third["obligation_id"] = "other_requirement"
        sidecar["sites"].extend([other, third])
        report = preflight(graph, sidecar)
        self.assertEqual(3, report["annotations"]["site_bindings_checked"])
        self.assertTrue(all(f["verdict"] == "unknown" for f in report["static_findings"]["findings"]))

    def test_runtime_data_proofs_and_completeness_flags_are_not_accepted_as_site_bindings(self):
        for key,value in (("runtime_results", [{"outcome": "runtime_error"}]),
                          ("bindings_verified", True), ("complete_events", True), ("cfg", [])):
            graph, sidecar = inputs()
            sidecar[key] = value
            with self.subTest(key=key), self.assertRaises(jsonschema.ValidationError):
                preflight(graph, sidecar)
        with self.assertRaises(jsonschema.ValidationError):
            preflight({"test": "D4", "outcome": "runtime_error", "pass": True})

    def test_source_paths_must_be_repository_relative(self):
        for file in ("/kernel/sched/ext.c", "../ext.c", "kernel/../ext.c", "C:/ext.c", "kernel\\ext.c"):
            graph, sidecar = inputs()
            graph["nodes"][TARGET_ROOTS[0]]["file"] = file
            sidecar["sites"][0]["file"] = sidecar["sites"][0]["reference"]["file"] = file
            sidecar["graph_sha256"] = graph_fingerprint(graph)
            with self.subTest(file=file), self.assertRaisesRegex(ValueError, "reference"):
                preflight(graph, sidecar)

    def test_fingerprint_is_canonical_and_inputs_and_output_are_independent(self):
        graph, sidecar = inputs()
        original = copy.deepcopy((graph, sidecar))
        report = preflight(graph, sidecar)
        encoded = json.dumps(graph, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), graph_fingerprint(graph))
        reordered = dict(reversed(list(graph.items())))
        self.assertEqual(report, preflight(reordered, sidecar))
        self.assertEqual(original, (graph, sidecar))
        sidecar["sites"][0]["object"] = "different"
        self.assertNotEqual(sidecar["sites"], report["static_findings"]["findings"][1]["evidence"][0]["site_bindings"])
        validate("findings", report["static_findings"])

    def test_import_and_preflight_do_not_register_semantic_checkers(self):
        before = registered()
        preflight(*inputs())
        self.assertEqual(before, registered())


class CliTests(unittest.TestCase):
    def test_no_input_returns_blocked_json_without_using_illustrative_fixture(self):
        result = subprocess.run([sys.executable, "-m", "checker.m1"], cwd=ROOT,
                                capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(3, result.returncode)
        data = json.loads(result.stdout)
        self.assertIsNone(data["extraction"]["claim"])
        self.assertNotIn("callgraph", data["static_findings"])
        self.assertEqual("", result.stderr)

    def test_bad_json_missing_file_and_wrong_schema_have_concise_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "graph.json"
            for content in (None, "{", '{"kernel_version": "v7.1"}'):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                with self.subTest(content=content), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(2, main(["--callgraph", str(path)]))
                self.assertEqual("", out.getvalue())
                self.assertIn("scxa m1:", err.getvalue())
                self.assertNotIn('"$schema"', err.getvalue())

    def test_serialization_from_matching_files_remains_blocked(self):
        graph, sidecar = inputs()
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("graph.json", "sidecar.json")]
            for path, data in zip(paths, (graph, sidecar)):
                path.write_text(json.dumps(data), encoding="utf-8")
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(3, main(["--callgraph", str(paths[0]), "--sidecar", str(paths[1])]))
        data = json.loads(out.getvalue())
        self.assertFalse(data["analysis_performed"])
        self.assertEqual(6, len(data["static_findings"]["findings"]))
        validate("findings", data["static_findings"])

    def test_wrong_version_and_contradictory_files_are_errors_not_successful_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            graph_path, sidecar_path = (Path(directory) / name for name in ("graph.json", "sidecar.json"))
            for case in ("version", "commit", "digest", "site"):
                graph, sidecar = inputs()
                if case == "version":
                    graph["kernel_version"] = "TBD"
                elif case == "commit":
                    sidecar["source"]["commit"] = "1" * 40
                elif case == "digest":
                    sidecar["graph_sha256"] = "1" * 64
                else:
                    sidecar["sites"][0]["field"] = "rq.wrong_field"
                graph_path.write_text(json.dumps(graph), encoding="utf-8")
                sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
                with self.subTest(case=case), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                    code = main(["--callgraph", str(graph_path), "--sidecar", str(sidecar_path)])
                self.assertEqual(2, code)
                self.assertEqual("", out.getvalue())
                self.assertIn("scxa m1:", err.getvalue())
                self.assertNotIn('"$schema"', err.getvalue())


if __name__ == "__main__":
    unittest.main()
