"""Negative and positive tests for tools/validate_contracts.py (catalog checks).

Run: python -m unittest discover -s tools/tests
"""
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("validate_contracts", ROOT / "tools/validate_contracts.py")
vc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vc)

FIXTURE = ROOT / "contracts/fixtures/catalog.example.yaml"
FIXTURE_REL = "contracts/fixtures/catalog.example.yaml"
REAL_REL = "catalog/invariants/I9.yaml"
V71 = "8cd9520d35a6c38db6567e97dd93b1f11f185dc6"


def obligation(**over):
    ob = {
        "id": "dst_nr",
        "access": {"struct": "scx_dispatch_q", "fields": ["nr"], "op": "write", "instance": "dst_dsq"},
        "sites": [{"function": "move_local_task_to_local_dsq", "file": "kernel/sched/ext.c", "line": 2266}],
        "requires": {"locks": [{"lock": "rq", "instance": "dst_rq", "state": "held"}]},
        "basis": "checked",
        "evidence": [{"kind": "lockdep_assert", "file": "kernel/sched/ext.c", "line": 2257}],
    }
    ob.update(over)
    return ob


def catalog(rules=None, **top):
    """A minimal real-style catalog (one I9 family) that passes all checks."""
    rule = {
        "id": "I9.example.rule",
        "title": "t",
        "description": "d",
        "category": "context_locking",
        "status": "source_verified",
        "role": "protection",
        "objects": [{"struct": "scx_dispatch_q", "fields": ["list", "nr"]}],
        "access": "write",
        "requires": {"locks": [{"lock": "bpf_spin_lock", "state": "not_held", "where": "access_site"}]},
        "obligations": [obligation()],
        "applies_to": ["scx_bpf_dsq_move_to_local"],
        "enforcement": {"expected": "runtime", "mechanisms": ["lock", "lockdep"]},
        "references": [{"file": "kernel/sched/ext.c", "line": 2248, "end_line": 2270}],
    }
    doc = {"kernel_version": "v7.1", "kernel_commit": V71,
           "invariants": [{"id": "I9", "title": "t", "description": "d", "category": "context_locking",
                           "rules": rules if rules is not None else [rule]}]}
    doc.update(top)
    return doc


def rule0(doc):
    return doc["invariants"][0]["rules"][0]


class CatalogValidatorTests(unittest.TestCase):
    def assert_ok(self, doc, rel=REAL_REL):
        self.assertEqual([], vc.catalog_errors(doc, rel))

    def assert_fails(self, doc, needle, rel=REAL_REL):
        errs = vc.catalog_errors(doc, rel)
        self.assertTrue(errs, "expected a validation error")
        self.assertTrue(any(needle in e for e in errs), f"{needle!r} not in {errs}")

    # positive baselines

    def test_fixture_is_valid(self):
        self.assert_ok(vc.load(FIXTURE), FIXTURE_REL)

    def test_minimal_catalog_is_valid(self):
        self.assert_ok(catalog())

    # enforcement

    def test_expected_none_with_unknown_mechanism_rejected(self):
        for mechs in (["unknown"], ["none", "unknown"]):
            doc = catalog()
            rule0(doc)["enforcement"] = {"expected": "none", "mechanisms": mechs}
            self.assert_fails(doc, "contradicts mechanism 'unknown'")

    def test_expected_none_without_none_mechanism_rejected(self):
        doc = catalog()
        rule0(doc)["enforcement"] = {"expected": "none", "mechanisms": ["lockdep"]}
        self.assert_fails(doc, "needs mechanism 'none'")

    def test_expected_none_with_none_and_lockdep_accepted(self):
        doc = catalog()
        rule0(doc)["enforcement"] = {"expected": "none", "mechanisms": ["none", "lockdep"]}
        self.assert_ok(doc)

    def test_lockdep_alone_is_not_runtime(self):
        doc = catalog()
        rule0(doc)["enforcement"] = {"expected": "runtime", "mechanisms": ["lockdep"]}
        self.assert_fails(doc, "does not match mechanisms")

    def test_none_mechanism_with_other_expected_rejected(self):
        doc = catalog()
        rule0(doc)["enforcement"] = {"expected": "unknown", "mechanisms": ["none"]}
        self.assert_fails(doc, "mechanism 'none' used with expected 'unknown'")

    # provenance

    def test_source_verified_requires_kernel_commit(self):
        doc = catalog()
        del doc["kernel_commit"]
        self.assert_fails(doc, "'kernel_commit' is a required property")

    def test_draft_only_catalog_may_omit_kernel_commit(self):
        doc = catalog()
        del doc["kernel_commit"]
        rule0(doc)["status"] = "draft"
        self.assert_ok(doc)

    def test_abbreviated_kernel_commit_rejected(self):
        self.assert_fails(catalog(kernel_commit=V71[:12]), "does not match")

    def test_kernel_commit_must_match_known_tag(self):
        self.assert_fails(catalog(kernel_commit="0" * 40), "is not the commit of v7.1")

    def test_real_catalog_with_unknown_tag_rejected(self):
        self.assert_fails(catalog(kernel_version="v9.9"), "has no known commit")

    # contexts

    def test_one_context_with_two_sets_rejected(self):
        doc = catalog()
        rule0(doc)["requires"]["contexts"] = {"kfunc_sets": ["scx_kfunc_ids_dispatch", "scx_kfunc_ids_unlocked"]}
        self.assert_fails(doc, "is too long")

    def test_context_alternatives_accepted(self):
        doc = catalog()
        rule0(doc)["requires"]["contexts_any_of"] = [
            {"kfunc_sets": ["scx_kfunc_ids_dispatch"], "callbacks": ["ops.dispatch"]},
            {"kfunc_sets": ["scx_kfunc_ids_unlocked"], "program_types": ["BPF_PROG_TYPE_SYSCALL"]},
        ]
        self.assert_ok(doc)

    def test_contexts_and_alternatives_together_rejected(self):
        doc = catalog()
        req = rule0(doc)["requires"]
        req["contexts"] = {"kfunc_sets": ["scx_kfunc_ids_dispatch"]}
        req["contexts_any_of"] = [{"kfunc_sets": ["scx_kfunc_ids_dispatch"]}, {"kfunc_sets": ["scx_kfunc_ids_unlocked"]}]
        self.assert_fails(doc, "should not be valid")

    def test_single_alternative_rejected(self):
        doc = catalog()
        rule0(doc)["requires"]["contexts_any_of"] = [{"kfunc_sets": ["scx_kfunc_ids_dispatch"]}]
        self.assert_fails(doc, "is too short")

    # obligations

    def test_hypothesis_in_source_verified_rule_rejected(self):
        doc = catalog()
        rule0(doc)["obligations"] = [obligation(basis="hypothesis")]
        self.assert_fails(doc, "hypothesis cannot be part of a source_verified rule")

    def test_hypothesis_in_draft_rule_accepted(self):
        doc = catalog()
        rule0(doc)["status"] = "draft"
        rule0(doc)["obligations"] = [obligation(basis="hypothesis")]
        self.assert_ok(doc)

    def test_basis_without_matching_evidence_rejected(self):
        for basis, kind in (("checked", "kernel_comment"), ("documented", "acquired_on_path"),
                            ("observed", "kernel_comment")):
            doc = catalog()
            rule0(doc)["obligations"] = [obligation(
                basis=basis, evidence=[{"kind": kind, "file": "kernel/sched/ext.c", "line": 1}])]
            self.assert_fails(doc, f"{basis!r} needs evidence")

    def test_obligation_field_must_be_in_objects(self):
        doc = catalog()
        ob = obligation()
        ob["access"]["fields"] = ["seq"]
        rule0(doc)["obligations"] = [ob]
        self.assert_fails(doc, "are not listed in the rule's objects")

    def test_obligation_struct_must_be_in_objects(self):
        doc = catalog()
        ob = obligation()
        ob["access"]["struct"] = "rq"
        rule0(doc)["obligations"] = [ob]
        self.assert_fails(doc, "struct 'rq' is not listed")

    def test_duplicate_obligation_id_rejected(self):
        doc = catalog()
        rule0(doc)["obligations"] = [obligation(), obligation()]
        self.assert_fails(doc, "duplicate obligation id")

    def test_ordering_only_on_atomic(self):
        doc = catalog()
        ob = obligation()
        ob["access"]["ordering"] = "release"
        rule0(doc)["obligations"] = [ob]
        self.assert_fails(doc, "only allowed with op 'atomic'")

    def test_requires_mandatory_unless_ordered_atomic(self):
        doc = catalog()
        ob = obligation()
        del ob["requires"]
        rule0(doc)["obligations"] = [ob]
        self.assert_fails(doc, "requires is mandatory")
        ob["access"].update(op="atomic", ordering="release")
        self.assert_ok(doc)

    def test_obligation_lock_needs_instance(self):
        doc = catalog()
        ob = obligation(requires={"locks": [{"lock": "rq", "state": "held"}]})
        rule0(doc)["obligations"] = [ob]
        self.assert_fails(doc, "'instance' is a required property")

    def test_obligation_needs_evidence(self):
        doc = catalog()
        rule0(doc)["obligations"] = [obligation(evidence=[])]
        self.assert_fails(doc, "should be non-empty")

    def test_path_must_end_in_a_site_function(self):
        doc = catalog()
        rule0(doc)["obligations"] = [obligation(paths=[{"root": "scx_bpf_dsq_move_to_local", "steps": [
            {"function": "consume_dispatch_q", "file": "kernel/sched/ext.c", "line": 2543, "held": []}]}])]
        self.assert_fails(doc, "is not a site function")

    def test_site_end_line_before_line_rejected(self):
        doc = catalog()
        rule0(doc)["obligations"] = [obligation(sites=[
            {"function": "f", "file": "kernel/sched/ext.c", "line": 10, "end_line": 9}])]
        self.assert_fails(doc, "has end_line < line")

    # roles

    def test_protection_rule_needs_obligations(self):
        doc = catalog()
        del rule0(doc)["obligations"]
        self.assert_fails(doc, "role 'protection' needs at least one obligation")

    def test_entry_state_rule_must_not_carry_objects_or_obligations(self):
        doc = catalog()
        rule0(doc)["role"] = "entry_state"
        errs = vc.catalog_errors(doc, REAL_REL)
        for needle in ("must not have obligations", "must have objects []", "must have access 'none'"):
            self.assertTrue(any(needle in e for e in errs), f"{needle!r} not in {errs}")

    # pre-existing checks

    def test_rule_prefix_and_duplicates(self):
        doc = catalog()
        r = rule0(doc)
        r2 = copy.deepcopy(r)
        r2["id"] = "I8.other"
        doc["invariants"][0]["rules"] = [r, copy.deepcopy(r), r2]
        errs = vc.catalog_errors(doc, REAL_REL)
        self.assertTrue(any("duplicate rule id" in e for e in errs))
        self.assertTrue(any("does not start with family" in e for e in errs))

    def test_star_mixed_with_names_rejected(self):
        doc = catalog()
        rule0(doc)["applies_to"] = ["*", "scx_bpf_kick_cpu"]
        self.assert_fails(doc, "'*' must be the only entry")

    def test_rule_category_must_match_family(self):
        doc = catalog()
        rule0(doc)["category"] = "ownership_state"
        self.assert_fails(doc, "!= family category")


if __name__ == "__main__":
    unittest.main()
