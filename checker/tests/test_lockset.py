"""Synthetic lockset proofs and conservative failures, not kernel execution tests."""
import copy
import json
import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from itertools import product
from pathlib import Path
from unittest.mock import patch

import jsonschema

from checker import runner
from checker.checkers import _REGISTRY, registered
from checker.context import (SOURCE_COMMIT, SOURCE_VERSION, LockIdentity as ContextLockIdentity,
                             LockState, SourceReference, SourceVersionMismatch)
from checker.lock_policy import AccessKind, LockIdentity, ProtectionPolicy, ProtectionRule
from checker.lockset import (
    Assessment, ControlEffect, ControlSemantics, GuardBranch, LockOwnership, Lockset,
    PreconditionStatus, Provenance, analyze, to_findings,
)

ROOT = Path(__file__).resolve().parents[2]
RQ = LockIdentity("cpu0.rq.lock")
OTHER_RQ = LockIdentity("cpu1.rq.lock")
DSQ = LockIdentity("dsq0.lock")
FIELD = "rq.nr_running"
TRUSTED = Provenance(complete_events=True, linear_events=True, synthetic=True)


def lock(token="rq.lock", **kwargs):
    return {"kind": "lock", "lock": token, **kwargs}


def unlock(token="rq.lock"):
    return {"kind": "unlock", "lock": token}


def write(field=FIELD, **kwargs):
    return {"kind": "write", "field": field, **kwargs}


def call(target, **kwargs):
    return {"kind": "call", "target": target, **kwargs}


def node(events=None, *, callees=None, writes=None, kind="internal"):
    value = {"kind": kind, "file": "synthetic.c", "callees": []}
    if events is not None:
        value["events"] = events
        value["callees"] = [{"target": event["target"], "kind": "direct",
                              **({"line": event["line"]} if "line" in event else {})}
                             for event in events if event["kind"] == "call" and "target" in event]
    if callees is not None:
        value["callees"] = callees
    if writes is not None:
        value["writes"] = writes
    return value


def graph(nodes, *, roots=("root",), illustrative=False, version="synthetic-c3-v1"):
    return {"kernel_version": version, "generator": "synthetic-lockset-tests", "illustrative": illustrative,
            "roots": list(roots), "nodes": nodes}


def policy(*functions, required=RQ, field=FIELD, access=AccessKind.WRITE):
    return ProtectionPolicy(tuple(ProtectionRule(function, field, required, access) for function in functions))


class LocksetTests(unittest.TestCase):
    def run_nodes(self, nodes, *, rules=None, bindings=None, provenance=TRUSTED, **kwargs):
        return analyze(graph(nodes), rules if rules is not None else policy(*nodes),
                       bindings=bindings if bindings is not None else {name: {"rq.lock": RQ} for name in nodes},
                       provenance=provenance, **kwargs)

    def assert_assessments(self, result, *expected):
        self.assertEqual(list(expected), [access.assessment for access in result.accesses])

    def codes(self, result):
        return {condition.code for condition in result.conditions}

    def test_lock_write_unlock(self):
        result = self.run_nodes({"root": node([lock(), write(line=17), unlock()])})
        self.assert_assessments(result, Assessment.PROTECTED)
        access = result.accesses[0]
        self.assertEqual(LockState.KNOWN_HELD, access.observed)
        self.assertEqual(("root",), access.site.path)
        self.assertEqual(("synthetic.c", 17, 1), (access.site.file, access.site.line, access.site.event_index))
        self.assertEqual(LockState.KNOWN_NOT_HELD, result.exits[0].locks.state(RQ))

    def test_write_after_unlock_is_unprotected_in_the_model(self):
        result = self.run_nodes({"root": node([lock(), unlock(), write()])})
        self.assert_assessments(result, Assessment.UNPROTECTED)
        self.assertEqual(LockState.KNOWN_NOT_HELD, result.accesses[0].observed)

    def test_missing_held_fact_is_unknown_not_absent(self):
        result = self.run_nodes({"root": node([write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertEqual(LockState.UNKNOWN, result.accesses[0].observed)

    def test_caller_acquires_callee_writes(self):
        result = self.run_nodes({"root": node([lock(), call("leaf")]), "leaf": node([write()])})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertEqual(("root", "leaf"), result.accesses[0].site.path)

    def test_callee_releases_before_caller_write(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]), "leaf": node([unlock()])})
        self.assert_assessments(result, Assessment.UNPROTECTED)

    def test_callee_acquisition_without_release_cannot_protect_caller(self):
        result = self.run_nodes({"root": node([call("leaf"), write()]), "leaf": node([lock()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("unverified_lock_escape", self.codes(result))

    def test_four_function_call_chain(self):
        result = self.run_nodes({"root": node([lock(), call("a")]), "a": node([call("b")]),
                                 "b": node([call("c")]), "c": node([write()])})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertEqual(("root", "a", "b", "c"), result.accesses[0].site.path)

    def test_same_callee_has_different_states_at_different_calls(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), unlock(), call("leaf")]),
                                 "leaf": node([write()])})
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.UNPROTECTED)

    def test_assert_held_is_not_an_acquisition(self):
        result = self.run_nodes({"root": node([{"kind": "assert_held", "lock": "rq.lock"}, write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertEqual(PreconditionStatus.UNPROVEN, result.preconditions[0].status)
        self.assertEqual(LockState.UNKNOWN, result.exits[0].locks.state(RQ))

    def test_assert_held_with_proven_lock(self):
        result = self.run_nodes({"root": node([lock(), {"kind": "assert_held", "lock": "rq.lock"}, write()])})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertEqual(PreconditionStatus.MET, result.preconditions[0].status)

    def test_assert_not_held_does_not_acquire(self):
        result = self.run_nodes({"root": node([lock(), unlock(),
                                               {"kind": "assert_not_held", "lock": "rq.lock"}, write()])})
        self.assert_assessments(result, Assessment.UNPROTECTED)
        self.assertEqual(PreconditionStatus.MET, result.preconditions[0].status)

    def test_unknown_assert_not_held_is_unproven(self):
        result = self.run_nodes({"root": node([{"kind": "assert_not_held", "lock": "rq.lock"}, write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertEqual(PreconditionStatus.UNPROVEN, result.preconditions[0].status)

    def test_failed_assertion_does_not_prove_a_reachable_violation(self):
        result = self.run_nodes({"root": node([lock(), unlock(),
                                               {"kind": "assert_held", "lock": "rq.lock"}, write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertEqual(PreconditionStatus.UNMET, result.preconditions[0].status)

    def test_self_recursion_invalidates_exit_effects(self):
        result = self.run_nodes({"root": node([lock(), call("root"), write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("recursion", self.codes(result))

    def test_mutual_cycle_is_bounded(self):
        result = self.run_nodes({"root": node([lock(), call("b"), write()]), "b": node([call("root")])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        cycle = next(condition for condition in result.conditions if condition.code == "recursion")
        self.assertEqual(("root", "b", "root"), cycle.site.path)

    def test_missing_direct_callee_may_release_any_lock(self):
        result = self.run_nodes({"root": node([lock(), call("missing"), write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("missing_callee", self.codes(result))

    def test_opaque_call_also_invalidates_known_absence(self):
        result = self.run_nodes({"root": node([lock(), unlock(), call("missing"), write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertEqual(LockState.UNKNOWN, result.accesses[0].observed)

    def test_indirect_call_does_not_trust_a_named_target_body(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()],
                                               callees=[{"target": "leaf", "kind": "indirect"}]),
                                 "leaf": node([unlock()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("unresolved_call", self.codes(result))

    def test_external_and_boundary_bodies_are_opaque(self):
        for kind in ("external", "boundary"):
            with self.subTest(kind=kind):
                result = self.run_nodes({"root": node([lock(), call("leaf"), write()]),
                                         "leaf": node([], kind=kind)})
                self.assert_assessments(result, Assessment.UNKNOWN)
                self.assertIn("opaque_callee", self.codes(result))

    def test_empty_complete_internal_body_can_preserve_state(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]), "leaf": node([])})
        self.assert_assessments(result, Assessment.PROTECTED)

    def test_missing_call_target_is_unknown(self):
        result = self.run_nodes({"root": node([lock(), {"kind": "call"}, write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_call_kind_cannot_be_inferred_from_node_existence(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()], callees=[]), "leaf": node([])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_ambiguous_direct_and_indirect_metadata_is_unknown(self):
        edges = [{"target": "leaf", "kind": kind} for kind in ("direct", "indirect")]
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()], callees=edges), "leaf": node([])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_call_source_lines_must_not_silently_disagree(self):
        result = self.run_nodes({"root": node([lock(), call("leaf", line=7), write()],
                                               callees=[{"target": "leaf", "kind": "direct", "line": 8}]),
                                 "leaf": node([])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_one_unlocated_call_cannot_cover_two_distinct_call_sites(self):
        edges = [{"target": "leaf", "kind": "direct", "line": line} for line in (10, 20)]
        result = self.run_nodes({"root": node([lock(), call("leaf"), lock(), write()], callees=edges),
                                 "leaf": node([unlock()])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_two_unlocated_calls_can_cover_two_direct_call_sites(self):
        edges = [{"target": "leaf", "kind": "direct", "line": line} for line in (10, 20)]
        for first_call in (call("leaf"), call("leaf", line=10)):
            with self.subTest(first_call=first_call):
                result = self.run_nodes({"root": node([lock(), first_call, lock(), call("leaf"), lock(), write()],
                                                       callees=edges), "leaf": node([unlock()])})
                self.assert_assessments(result, Assessment.PROTECTED)

    def test_duplicate_metadata_for_one_call_site_does_not_invent_another_call(self):
        edge = {"target": "leaf", "kind": "direct", "line": 10}
        result = self.run_nodes({"root": node([lock(), call("leaf"), lock(), write()], callees=[edge, dict(edge)]),
                                 "leaf": node([unlock()])})
        self.assert_assessments(result, Assessment.PROTECTED)

    def test_missing_events_are_not_an_empty_effect_summary(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]), "leaf": node()})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("missing_events", self.codes(result))

    def test_unordered_callee_can_precede_any_ordered_event(self):
        result = self.run_nodes({"root": node([lock(), write()],
                                               callees=[{"target": "leaf", "kind": "direct"}]),
                                 "leaf": node([unlock()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("unsequenced_callee", self.codes(result))

    def test_unordered_writes_are_unknown_candidates_without_a_position(self):
        for events in (None, []):
            with self.subTest(events=events):
                result = self.run_nodes({"root": node(events, writes=[FIELD])})
                self.assert_assessments(result, Assessment.UNKNOWN)
                self.assertIsNone(result.accesses[0].site.event_index)
                self.assertIsNone(result.accesses[0].access)

    def test_missing_write_event_taints_the_entire_function(self):
        result = self.run_nodes({"root": node([lock(), write()], writes=[FIELD, "rq.other"])},
                                rules=ProtectionPolicy((ProtectionRule("root", FIELD, RQ),
                                                        ProtectionRule("root", "rq.other", RQ))))
        self.assert_assessments(result, Assessment.UNKNOWN, Assessment.UNKNOWN)

    def test_two_runqueue_objects_do_not_alias(self):
        result = self.run_nodes({"root": node([lock(), write()])}, rules=policy("root", required=OTHER_RQ))
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_caller_holds_a_but_callee_field_requires_b(self):
        nodes = {"root": node([lock(), call("leaf")]), "leaf": node([write()])}
        for state, expected in ((LockState.UNKNOWN, Assessment.UNKNOWN),
                                (LockState.KNOWN_NOT_HELD, Assessment.UNPROTECTED)):
            with self.subTest(state=state):
                result = self.run_nodes(nodes, rules=policy("leaf", required=OTHER_RQ),
                                        entry_states={"root": Lockset.from_mapping({OTHER_RQ: state})})
                self.assert_assessments(result, expected)

    def test_all_required_locks_must_be_held_before_claiming_protection(self):
        rules = ProtectionPolicy((ProtectionRule("root", FIELD, RQ), ProtectionRule("root", FIELD, OTHER_RQ)))
        for state in (LockState.UNKNOWN, LockState.KNOWN_NOT_HELD):
            with self.subTest(other_lock_state=state):
                result = self.run_nodes({"root": node([lock(), write()])}, rules=rules,
                                        entry_states={"root": Lockset.from_mapping({OTHER_RQ: state})})
                self.assertNotIn(Assessment.PROTECTED, [item.assessment for item in result.accesses])
                witness = next(item for item in result.accesses if item.required_lock == OTHER_RQ)
                self.assertEqual(state, witness.observed)
                if state == LockState.KNOWN_NOT_HELD:
                    self.assertEqual(Assessment.UNPROTECTED, witness.assessment)

    def test_all_required_locks_can_establish_model_protection(self):
        rules = ProtectionPolicy((ProtectionRule("root", FIELD, RQ), ProtectionRule("root", FIELD, OTHER_RQ)))
        result = self.run_nodes({"root": node([lock(), write()])}, rules=rules,
                                entry_states={"root": Lockset.from_mapping({OTHER_RQ: LockState.KNOWN_HELD})})
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.PROTECTED)

    def test_acquiring_other_rq_does_not_erase_known_absence(self):
        result = self.run_nodes({"root": node([lock(), write()])}, rules=policy("root", required=OTHER_RQ),
                                entry_states={"root": Lockset.from_mapping({OTHER_RQ: LockState.KNOWN_NOT_HELD})})
        self.assert_assessments(result, Assessment.UNPROTECTED)

    def test_dsq_lock_is_not_a_runqueue_lock(self):
        result = self.run_nodes({"root": node([lock("dsq"), write()])}, bindings={"root": {"dsq": DSQ}})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_unresolved_lock_binding_invalidates_existing_facts(self):
        result = self.run_nodes({"root": node([lock("unbound"), write()])},
                                entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("unresolved_lock", self.codes(result))

    def test_identical_local_tokens_in_different_functions_need_not_alias(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]), "leaf": node([unlock()])},
                                bindings={"root": {"rq.lock": RQ}, "leaf": {"rq.lock": OTHER_RQ}})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertEqual(LockState.KNOWN_NOT_HELD, result.exits[0].locks.state(OTHER_RQ))

    def test_guard_before_write_is_unknown(self):
        result = self.run_nodes({"root": node([lock(), {"kind": "guard", "cond": "flag"}, write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertIn("unknown_control_flow", self.codes(result))

    def test_a_later_lock_does_not_recover_control_flow_certainty(self):
        result = self.run_nodes({"root": node([{"kind": "guard", "cond": "flag"}, lock(), write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_callee_control_uncertainty_propagates_to_the_caller(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]),
                                 "leaf": node([{"kind": "guard", "cond": "flag", "action": "return"}])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_error_and_warn_are_not_assumed_to_be_harmless(self):
        for kind in ("error", "warn"):
            with self.subTest(kind=kind):
                result = self.run_nodes({"root": node([lock(), {"kind": kind}, write()])})
                self.assert_assessments(result, Assessment.UNKNOWN)

    def test_conditional_and_qualified_acquisitions_are_not_definite(self):
        for event in (lock(cond="try_succeeded"), lock(op="spin_trylock")):
            with self.subTest(event=event):
                result = self.run_nodes({"root": node([event, write()])})
                self.assert_assessments(result, Assessment.UNKNOWN)

    def test_invalid_repeated_operations_do_not_prove_reachable_accesses(self):
        for events in ([lock(), lock(), write()], [lock(), unlock(), unlock(), write()]):
            with self.subTest(events=events):
                result = self.run_nodes({"root": node(events)})
                self.assert_assessments(result, Assessment.UNKNOWN)
                self.assertIn("invalid_lock_transition", self.codes(result))

    def test_depth_limit_and_root_depth_zero(self):
        nodes = {"root": node([lock(), call("a"), write()]), "a": node([call("b")]), "b": node([])}
        shallow = self.run_nodes(nodes, max_depth=0)
        self.assert_assessments(shallow, Assessment.UNKNOWN)
        self.assertIn("depth_limit", self.codes(shallow))
        self.assert_assessments(self.run_nodes(nodes, max_depth=2), Assessment.PROTECTED)

    def test_atomic_access_never_borrows_a_write_policy(self):
        result = self.run_nodes({"root": node([{"kind": "atomic", "field": FIELD, "op": "cmpxchg"}])})
        self.assertEqual((), result.accesses)
        self.assertIn("no_atomic_policy", self.codes(result))

    def test_atomic_access_can_have_an_explicit_different_lock_policy(self):
        result = self.run_nodes({"root": node([lock("dsq"), {"kind": "atomic", "field": FIELD}])},
                                rules=policy("root", required=DSQ, access=AccessKind.ATOMIC),
                                bindings={"root": {"dsq": DSQ}})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertEqual(AccessKind.ATOMIC, result.accesses[0].access)

    def test_write_and_atomic_rules_are_not_combined_into_one_requirement(self):
        rules = ProtectionPolicy((ProtectionRule("root", FIELD, RQ, AccessKind.WRITE),
                                  ProtectionRule("root", FIELD, OTHER_RQ, AccessKind.ATOMIC)))
        result = self.run_nodes({"root": node([lock(), write(), {"kind": "atomic", "field": FIELD}])}, rules=rules)
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.UNKNOWN)

    def test_atomic_event_does_not_acquire_a_lock(self):
        result = self.run_nodes({"root": node([{"kind": "atomic", "field": FIELD}, write()])})
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_policy_is_function_scoped_not_a_blanket_catalog_requirement(self):
        result = self.run_nodes({"root": node([call("leaf")]), "leaf": node([write()])}, rules=policy("root"))
        self.assertEqual((), result.accesses)

    def test_untrusted_or_illustrative_input_cannot_prove_protection(self):
        nodes = {"root": node([lock(), write()])}
        for provenance in (Provenance(), Provenance(complete_events=True), Provenance(linear_events=True)):
            with self.subTest(provenance=provenance):
                self.assert_assessments(self.run_nodes(nodes, provenance=provenance), Assessment.UNKNOWN)
        result = analyze(graph(nodes, illustrative=True), policy("root"), bindings={"root": {"rq.lock": RQ}},
                         provenance=TRUSTED)
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_missing_access_field_and_lock_token_are_explicitly_unknown(self):
        for event in ({"kind": "lock"}, {"kind": "write"}):
            with self.subTest(event=event):
                result = self.run_nodes({"root": node([event, write()])})
                self.assert_assessments(result, Assessment.UNKNOWN)
                self.assertTrue(result.conditions)

    def test_existing_tbd_fixture_is_an_illustration_only(self):
        fixture = runner.load_data(ROOT / "contracts/fixtures/callgraph.example.json")
        rules = ProtectionPolicy((ProtectionRule("mark_direct_dispatch", "task_struct.scx.ddsp_dsq_id", RQ),))
        result = analyze(fixture, rules)
        self.assertTrue(result.accesses)
        self.assertTrue(all(item.assessment == Assessment.UNKNOWN for item in result.accesses))
        self.assertTrue(all(finding["verdict"] == "unknown" for finding in to_findings(result, invariant="I1")))

    def test_definite_results_agree_with_all_short_concrete_entry_states(self):
        # Independent set-of-possible-owners oracle: UNKNOWN initially means
        # either concrete ownership, and an opaque call may produce either.
        for length in range(4):
            for operations in product(("lock", "unlock", "opaque"), repeat=length):
                possible = {LockState.KNOWN_HELD, LockState.KNOWN_NOT_HELD}
                events = []
                for operation in operations:
                    if operation == "lock":
                        possible = {LockState.KNOWN_HELD} if LockState.KNOWN_NOT_HELD in possible else set()
                        events.append(lock())
                    elif operation == "unlock":
                        possible = {LockState.KNOWN_NOT_HELD} if LockState.KNOWN_HELD in possible else set()
                        events.append(unlock())
                    else:
                        if possible:
                            possible = {LockState.KNOWN_HELD, LockState.KNOWN_NOT_HELD}
                        events.append(call("opaque"))
                    if not possible:
                        break  # No successful primitive execution reaches the write.
                if not possible:
                    continue
                result = self.run_nodes({"root": node([*events, write()]), "opaque": node([], kind="external")})
                observed = result.accesses[0].observed
                with self.subTest(operations=operations):
                    if observed != LockState.UNKNOWN:
                        self.assertEqual({observed}, possible)


class ReviewBlockerTests(unittest.TestCase):
    run_nodes = LocksetTests.run_nodes
    assert_assessments = LocksetTests.assert_assessments
    codes = LocksetTests.codes

    def test_unbalanced_callee_protects_own_prefix_but_not_caller(self):
        result = self.run_nodes({"root": node([call("leaf"), write()]), "leaf": node([lock(), write()])})
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.UNKNOWN)
        self.assertEqual(("root", "leaf"), result.accesses[0].site.path)
        self.assertEqual(("root",), result.accesses[1].site.path)
        leaf = next(s for s in result.summaries if s.site.function == "leaf")
        self.assertEqual((RQ,), leaf.acquired)
        self.assertEqual(LockState.UNKNOWN, leaf.exit.state(RQ))

    def test_release_then_reacquire_entry_held_lock_is_not_a_verified_handoff(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]),
                                 "leaf": node([unlock(), lock()])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        leaf = next(s for s in result.summaries if s.site.function == "leaf")
        self.assertEqual(LockState.KNOWN_HELD, leaf.entry.state(RQ))
        self.assertEqual(LockState.UNKNOWN, leaf.exit.state(RQ))
        self.assertEqual((RQ,), leaf.acquired)
        self.assertEqual((RQ,), leaf.released)

    def test_balanced_callee_release_propagates_definite_absence(self):
        result = self.run_nodes({"root": node([call("leaf"), write()]),
                                 "leaf": node([lock(), write(), unlock()])})
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.UNPROTECTED)
        self.assertNotIn("unverified_lock_escape", self.codes(result))

    def test_nested_callee_acquisition_cannot_escape_multiple_returns(self):
        result = self.run_nodes({"root": node([call("a"), write()]), "a": node([call("b")]),
                                 "b": node([lock(), write()])})
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.UNKNOWN)
        self.assertEqual(("root", "a", "b"), result.accesses[0].site.path)
        self.assertEqual(LockState.UNKNOWN, result.exits[0].locks.state(RQ))

    def test_scope_uncertainty_cannot_suppress_an_unrelated_explicit_unlock(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), unlock(), write()]),
                                 "leaf": node([lock()])},
                                bindings={"root": {"rq.lock": RQ}, "leaf": {"rq.lock": OTHER_RQ}})
        self.assert_assessments(result, Assessment.UNPROTECTED)
        self.assertEqual(LockState.KNOWN_NOT_HELD, result.exits[0].locks.state(RQ))
        self.assertEqual(LockState.UNKNOWN, result.exits[0].locks.state(OTHER_RQ))

    def test_scope_uncertainty_does_not_erase_an_unrelated_entry_lock(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]), "leaf": node([lock()])},
                                bindings={"root": {"rq.lock": RQ}, "leaf": {"rq.lock": OTHER_RQ}})
        self.assert_assessments(result, Assessment.PROTECTED)

    def test_assertion_is_not_an_exit_lifetime_annotation(self):
        result = self.run_nodes({"root": node([call("leaf"), write()]),
                                 "leaf": node([lock(), {"kind": "assert_held", "lock": "rq.lock"}])})
        self.assert_assessments(result, Assessment.UNKNOWN)
        leaf = next(s for s in result.summaries if s.site.function == "leaf")
        self.assertEqual(PreconditionStatus.MET, leaf.required_held[0].status)
        self.assertEqual(1, leaf.required_held[0].site.event_index)
        self.assertEqual(LockState.UNKNOWN, leaf.exit.state(RQ))

    def test_tagged_guard_acquisitions_do_not_imply_linear_lifetime(self):
        for op in ("guard(raw_spinlock_irqsave)", "scoped_guard(raw_spinlock)"):
            result = self.run_nodes({"root": node([call("leaf"), write()]),
                                     "leaf": node([lock(op=op), write()])})
            self.assert_assessments(result, Assessment.UNKNOWN, Assessment.UNKNOWN)
            self.assertIn("unsupported_lock_operation", self.codes(result))

    def test_root_held_prefix_is_not_a_guarantee_of_held_exit(self):
        result = self.run_nodes({"root": node([lock(), write()])})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertEqual(LockState.UNKNOWN, result.exits[0].locks.state(RQ))

    def test_function_summaries_keep_distinct_entry_contexts(self):
        result = self.run_nodes({"root": node([lock(), call("leaf"), unlock(), call("leaf")]),
                                 "leaf": node([write()])})
        summaries = [s for s in result.summaries if s.site.function == "leaf"]
        self.assertEqual([LockState.KNOWN_HELD, LockState.KNOWN_NOT_HELD], [s.entry.state(RQ) for s in summaries])
        self.assertEqual([LockState.KNOWN_HELD, LockState.KNOWN_NOT_HELD], [s.exit.state(RQ) for s in summaries])
        with self.assertRaises(FrozenInstanceError):
            summaries[0].entry = Lockset()

    def test_unknown_policy_write_is_explicit_and_adapts_to_unknown(self):
        result = self.run_nodes({"root": node([lock(), write(line=9)])}, rules=ProtectionPolicy(()))
        self.assertEqual((), result.accesses)
        self.assertIn("no_write_policy", self.codes(result))
        findings = to_findings(result, invariant="I1")
        self.assertTrue(findings)
        self.assertTrue(all(f["verdict"] == "unknown" for f in findings))
        missing = next(f for f in findings if "no_write_policy" in f["evidence"][0]["detail"])
        self.assertEqual(9, missing["evidence"][0]["line"])
        self.assertIn(FIELD, missing["evidence"][0]["detail"])

    def test_unknown_atomic_policy_is_reported_without_borrowing_write_rules(self):
        result = self.run_nodes({"root": node([{"kind": "atomic", "field": FIELD}])})
        self.assertEqual((), result.accesses)
        self.assertEqual(["unknown"], [f["verdict"] for f in to_findings(result, invariant="I1")])

    def test_doubling_chain_is_bounded_by_default_global_budget(self):
        nodes = {f"f{i}": node([call(f"f{i+1}"), call(f"f{i+1}")]) for i in range(40)}
        nodes.update({"root": node([call("f0"), write()]), "f40": node([write()])})
        result = self.run_nodes(nodes, rules=policy("root", "f40"), max_depth=64,
                                entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assertTrue(result.work.exhausted)
        self.assertEqual(10000, result.work.consumed)
        self.assertLess(result.work.function_visits, 10000)
        self.assertEqual(Assessment.UNKNOWN, result.accesses[-1].assessment)
        self.assertEqual(("root",), result.accesses[-1].site.path)
        self.assertIn("work_budget", self.codes(result))

    def test_diamond_graph_keeps_real_paths_and_bounds_repeated_visits(self):
        nodes = {"root": node([call("s0"), write()])}
        for i in range(18):
            nodes[f"s{i}"] = node([call(f"l{i}"), call(f"r{i}")])
            nodes[f"l{i}"] = node([call(f"s{i+1}")])
            nodes[f"r{i}"] = node([call(f"s{i+1}")])
        nodes["s18"] = node([write()])
        result = self.run_nodes(nodes, rules=policy("root", "s18"), max_depth=64, max_work=1500,
                                entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assertTrue(result.work.exhausted)
        self.assertEqual(1500, result.work.consumed)
        self.assertEqual(Assessment.UNKNOWN, result.accesses[-1].assessment)
        for item in (*result.accesses, *result.conditions):
            for caller, callee in zip(item.site.path, item.site.path[1:]):
                self.assertIn(callee, [event.get("target") for event in nodes[caller]["events"]])

    def test_deep_linear_path_can_complete_without_a_false_budget_cut(self):
        nodes = {"root": node([call("f0"), write()])}
        nodes.update({f"f{i}": node([call(f"f{i+1}")]) for i in range(90)})
        nodes["f90"] = node([write()])
        result = self.run_nodes(nodes, rules=policy("root", "f90"), max_depth=100,
                                entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.PROTECTED)
        self.assertFalse(result.work.exhausted)
        self.assertEqual(92, result.work.function_visits)

    def test_budget_cut_invalidates_held_and_absent_entry_states(self):
        for state in (LockState.KNOWN_HELD, LockState.KNOWN_NOT_HELD):
            result = self.run_nodes({"root": node([write(line=7)])}, max_work=1,
                                    entry_states={"root": Lockset.from_mapping({RQ: state})})
            self.assert_assessments(result, Assessment.UNKNOWN)
            self.assertEqual(7, result.accesses[0].site.line)
            self.assertEqual(LockState.UNKNOWN, result.exits[0].locks.state(RQ))

    def test_budget_is_shared_across_sorted_roots(self):
        fixture = graph({"a": node([]), "b": node([write()])}, roots=("b", "a"))
        result = analyze(fixture, policy("b"), max_work=1, provenance=TRUSTED,
                         entry_states={"b": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assertEqual(1, result.work.function_visits)
        self.assertEqual(["a", "b"], [s.root for s in result.exits])
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertEqual(("b",), result.accesses[0].site.path)

    def test_exact_budget_boundary_is_not_itself_exhaustion(self):
        result = self.run_nodes({"root": node([])}, max_work=1)
        self.assertEqual(1, result.work.consumed)
        self.assertFalse(result.work.exhausted)

    def test_metadata_work_is_charged_and_cannot_escape_the_budget(self):
        nodes = {"root": node([*[call("leaf", line=i) for i in range(100)], write()]), "leaf": node([])}
        result = self.run_nodes(nodes, rules=policy("root"), max_work=25)
        self.assertTrue(result.work.exhausted)
        self.assertGreater(result.work.metadata, 0)
        self.assertEqual(25, result.work.consumed)
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_budget_gap_with_no_observed_access_is_still_an_unknown_finding(self):
        result = self.run_nodes({"root": node([call("leaf")]), "leaf": node([])}, max_work=1)
        self.assertEqual((), result.accesses)
        findings = to_findings(result, invariant="I1")
        self.assertTrue(findings)
        self.assertTrue(all(f["verdict"] == "unknown" for f in findings))
        self.assertIn("work_budget", findings[0]["evidence"][0]["detail"])

    def test_opaque_or_missing_callee_without_an_observed_access_stays_explicit(self):
        for nodes in ({"root": node([call("missing")])},
                      {"root": node([call("opaque")]), "opaque": node([], kind="external")}):
            result = self.run_nodes(nodes)
            self.assertEqual((), result.accesses)
            findings = to_findings(result, invariant="I1")
            self.assertTrue(findings)
            self.assertTrue(all(f["verdict"] == "unknown" for f in findings))

    def test_budget_results_do_not_depend_on_unordered_adjacency(self):
        fixture = graph({"root": node([call("a"), call("b"), write()]), "a": node([]), "b": node([])})
        before = analyze(fixture, policy("root"), provenance=TRUSTED, max_work=8).to_json()
        fixture["nodes"]["root"]["callees"].reverse()
        after = analyze(fixture, policy("root"), provenance=TRUSTED, max_work=8).to_json()
        self.assertEqual(before, after)

    def test_work_statistics_account_for_all_charged_units(self):
        result = self.run_nodes({"root": node([lock(), write(), unlock()])})
        self.assertEqual(result.work.consumed,
                         result.work.function_visits + result.work.events + result.work.metadata)
        self.assertLessEqual(result.work.consumed, result.work.limit)

    def test_invalid_work_limits_are_explicit(self):
        for limit in (0, -1, True, None, 1.5, "100", 1000001):
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, "max_work"):
                self.run_nodes({"root": node([])}, max_work=limit)


class ControlFlowReviewTests(unittest.TestCase):
    assert_assessments = LocksetTests.assert_assessments
    codes = LocksetTests.codes
    provenance = Provenance("synthetic-control", True, True, True)

    def run_nodes(self, nodes, **kwargs):
        kwargs.setdefault("provenance", self.provenance)
        return LocksetTests.run_nodes(self, nodes, **kwargs)

    def annotation(self, event, effect=ControlEffect.FALLTHROUGH, *, function="root", index=0,
                   branch_when=None):
        ref = SourceReference("synthetic.c", function, event["line"], event["line"],
                              "synthetic-c3-v1", "synthetic-control")
        return ControlSemantics.for_event(function, index, event, effect, ref, branch_when=branch_when)

    def return_guard(self, *, function="root", index=0, branch_when=GuardBranch.CONDITION_TRUE):
        event = {"kind": "guard", "cond": "invalid_argument", "action": "return", "line": 10}
        return event, self.annotation(event, ControlEffect.EARLY_RETURN, function=function,
                                      index=index, branch_when=branch_when)

    def test_nonterminating_warn_before_lock_allows_protected_write(self):
        event = {"kind": "warn", "msg": "diagnostic", "line": 1}
        result = self.run_nodes({"root": node([event, lock(), write(), unlock()])},
                                control_semantics=(self.annotation(event),))
        self.assert_assessments(result, Assessment.PROTECTED)

    def test_warn_preserves_both_held_and_absent_lock_knowledge(self):
        event = {"kind": "warn", "line": 1}
        for state, expected in ((LockState.KNOWN_HELD, Assessment.PROTECTED),
                                (LockState.KNOWN_NOT_HELD, Assessment.UNPROTECTED)):
            with self.subTest(state=state):
                result = self.run_nodes({"root": node([event, write()])},
                                        control_semantics=(self.annotation(event),),
                                        entry_states={"root": Lockset.from_mapping({RQ: state})})
                self.assert_assessments(result, expected)

    def test_proven_return_guard_preserves_only_the_continuation(self):
        event, semantics = self.return_guard()
        result = self.run_nodes({"root": node([event, lock(), write(), unlock()])},
                                control_semantics=(semantics,))
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertEqual(LockState.UNKNOWN, result.exits[0].locks.state(RQ))
        self.assertIn("early_return_join", self.codes(result))

    def test_return_guard_preserves_known_absence_at_a_continuing_access(self):
        event, semantics = self.return_guard(branch_when=GuardBranch.CONDITION_FALSE)
        result = self.run_nodes({"root": node([event, write()])}, control_semantics=(semantics,),
                                entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_NOT_HELD})})
        self.assert_assessments(result, Assessment.UNPROTECTED)
        self.assertEqual(GuardBranch.CONDITION_FALSE, result.control_semantics[0].branch_when)

    def test_return_guard_does_not_acquire_a_lock(self):
        event, semantics = self.return_guard()
        self.assert_assessments(self.run_nodes({"root": node([event, write()])},
                                              control_semantics=(semantics,)), Assessment.UNKNOWN)

    def test_guard_action_return_without_reviewed_semantics_stays_unknown(self):
        event, _ = self.return_guard()
        self.assert_assessments(self.run_nodes({"root": node([event, lock(), write()])}), Assessment.UNKNOWN)

    def test_fallback_and_continue_guards_stay_unknown(self):
        for action in ("fallback", "continue", "error"):
            with self.subTest(action=action):
                event = {"kind": "guard", "cond": "flag", "action": action, "line": 1}
                self.assert_assessments(self.run_nodes({"root": node([event, lock(), write()])}),
                                        Assessment.UNKNOWN)
                with self.assertRaises(ValueError):
                    self.annotation(event, ControlEffect.EARLY_RETURN, branch_when=GuardBranch.CONDITION_TRUE)

    def test_reviewed_early_exit_in_callee_is_joined_before_caller_write(self):
        event, semantics = self.return_guard(function="leaf")
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]),
                                 "leaf": node([event, unlock()])}, control_semantics=(semantics,))
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertEqual(LockState.UNKNOWN, next(s for s in result.summaries
                                                 if s.site.function == "leaf").exit.state(RQ))

    def test_callee_access_on_verified_continuation_can_be_protected(self):
        event, semantics = self.return_guard(function="leaf")
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]),
                                 "leaf": node([event, write()])}, control_semantics=(semantics,))
        self.assert_assessments(result, Assessment.PROTECTED, Assessment.UNKNOWN)
        self.assertEqual(("root", "leaf"), result.accesses[0].site.path)

    def test_errors_require_explicit_fallthrough_or_exit_semantics(self):
        event = {"kind": "error", "msg": "error helper", "line": 1}
        for effect in (None, ControlEffect.FALLTHROUGH, ControlEffect.EXIT):
            with self.subTest(effect=effect):
                semantics = () if effect is None else (self.annotation(event, effect),)
                result = self.run_nodes({"root": node([event, write()])}, control_semantics=semantics,
                                        entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
                if effect == ControlEffect.EXIT:
                    self.assertEqual((), result.accesses)
                    self.assertIn("control_exit", self.codes(result))
                    self.assertTrue(to_findings(result, invariant="I1"))
                else:
                    self.assert_assessments(result, Assessment.PROTECTED if effect is not None else Assessment.UNKNOWN)

    def test_error_exit_does_not_prove_caller_locks_or_reachability(self):
        event = {"kind": "error", "action": "return", "line": 1}
        result = self.run_nodes({"root": node([lock(), call("leaf"), write()]),
                                 "leaf": node([event, write()])},
                                control_semantics=(self.annotation(event, ControlEffect.EXIT, function="leaf"),))
        self.assert_assessments(result, Assessment.UNKNOWN)
        self.assertEqual(("root",), result.accesses[0].site.path)

    def test_fallthrough_cannot_certify_a_return_or_conditional_termination(self):
        with self.assertRaises(ValueError):
            self.annotation({"kind": "error", "action": "return", "line": 1})
        with self.assertRaises(ValueError):
            self.annotation({"kind": "error", "cond": "flag", "line": 1}, ControlEffect.EXIT)

    def test_reviewed_diagnostic_does_not_repair_unknown_call_effects(self):
        event = {"kind": "warn", "line": 1}
        result = self.run_nodes({"root": node([call("missing"), event, lock(), write()])},
                                control_semantics=(self.annotation(event, index=1),))
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_reviewed_controls_do_not_repair_incomplete_or_illustrative_models(self):
        event, semantics = self.return_guard()
        nodes = {"root": node([event, lock(), write()])}
        for attr in ("complete_events", "linear_events"):
            self.assert_assessments(self.run_nodes(nodes, control_semantics=(semantics,),
                                                  provenance=replace(self.provenance, **{attr: False})),
                                    Assessment.UNKNOWN)
        result = analyze(graph(nodes, illustrative=True), policy("root"), bindings={"root": {"rq.lock": RQ}},
                         provenance=self.provenance, control_semantics=(semantics,))
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_return_guard_and_wrong_object_lock_do_not_imply_protection(self):
        event, semantics = self.return_guard()
        result = self.run_nodes({"root": node([event, lock(), write()])},
                                rules=policy("root", required=OTHER_RQ), control_semantics=(semantics,),
                                entry_states={"root": Lockset.from_mapping({OTHER_RQ: LockState.KNOWN_NOT_HELD})})
        self.assert_assessments(result, Assessment.UNPROTECTED)

    def test_reviewed_control_cannot_turn_an_assertion_into_ownership(self):
        event = {"kind": "warn", "line": 1}
        result = self.run_nodes({"root": node([event, {"kind": "assert_held", "lock": "rq.lock"}, write()])},
                                control_semantics=(self.annotation(event),))
        self.assert_assessments(result, Assessment.UNKNOWN)

    def test_annotation_matches_the_entire_event_not_just_kind_or_index(self):
        event = {"kind": "warn", "msg": "diagnostic", "line": 1}
        semantics = self.annotation(event)
        for changed in ({**event, "msg": "different operation"}, {**event, "op": "panic"},
                        {**event, "cond": "flag"}, {**event, "action": "return"}):
            with self.subTest(event=changed), self.assertRaisesRegex(ValueError, "exact recorded event"):
                self.run_nodes({"root": node([changed, write()])}, control_semantics=(semantics,))

    def test_annotation_rejects_source_version_and_commit_mismatches(self):
        event = {"kind": "warn", "line": 1}
        semantics = self.annotation(event)
        for ref in (replace(semantics.reference, source_version=SOURCE_VERSION),
                    replace(semantics.reference, source_commit=SOURCE_COMMIT)):
            with self.subTest(ref=ref), self.assertRaises(SourceVersionMismatch):
                self.run_nodes({"root": node([event, write()])},
                               control_semantics=(replace(semantics, reference=ref),))

    def test_annotation_rejects_missing_provenance_and_stale_source_location(self):
        event = {"kind": "warn", "line": 1}
        semantics = self.annotation(event)
        with self.assertRaises(SourceVersionMismatch):
            self.run_nodes({"root": node([event])}, provenance=TRUSTED, control_semantics=(semantics,))
        for ref in (replace(semantics.reference, file="other.c"),
                    replace(semantics.reference, line=2, end_line=3)):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "source location"):
                self.run_nodes({"root": node([event])}, control_semantics=(replace(semantics, reference=ref),))

    def test_duplicate_and_out_of_range_annotations_are_rejected(self):
        event = {"kind": "warn", "line": 1}
        semantics = self.annotation(event)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_nodes({"root": node([event])}, control_semantics=(semantics, semantics))
        with self.assertRaisesRegex(ValueError, "exact recorded event"):
            self.run_nodes({"root": node([event])}, control_semantics=(replace(semantics, event_index=3),))
        with self.assertRaises(TypeError):
            self.run_nodes({"root": node([event])}, control_semantics=({},))

    def test_control_semantics_are_typed_immutable_and_deterministic(self):
        warn = {"kind": "warn", "line": 1}
        guard, early = self.return_guard(index=1)
        first = self.annotation(warn)
        before = self.run_nodes({"root": node([warn, guard, lock(), write()])},
                                control_semantics=(first, early)).to_json()
        after = self.run_nodes({"root": node([warn, guard, lock(), write()])},
                               control_semantics=(early, first)).to_json()
        self.assertEqual(before, after)
        warn["msg"] = "changed after binding"
        self.assertNotIn("msg", dict(first.event))
        with self.assertRaises(FrozenInstanceError):
            first.effect = ControlEffect.EXIT
        for index in (-1, True):
            with self.assertRaises(ValueError):
                replace(first, event_index=index)
        with self.assertRaises(TypeError):
            replace(first, effect="fallthrough")

    def test_controls_cannot_annotate_locking_operations_or_assertions(self):
        for kind in ("lock", "unlock", "assert_held", "assert_not_held", "call"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.annotation({"kind": kind, "line": 1})

    def test_reference_symbol_range_and_file_are_required(self):
        semantics = self.annotation({"kind": "warn", "line": 1})
        for ref in (replace(semantics.reference, symbol="other"),
                    replace(semantics.reference, line=0), replace(semantics.reference, line=True),
                    replace(semantics.reference, end_line=0), replace(semantics.reference, file="")):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                replace(semantics, reference=ref)

    def test_nonsynthetic_controls_require_a_full_commit(self):
        event = {"kind": "warn", "line": 1}
        with self.assertRaisesRegex(SourceVersionMismatch, "full commit"):
            self.run_nodes({"root": node([event])}, control_semantics=(self.annotation(event),),
                           provenance=replace(self.provenance, synthetic=False))

    def test_control_domain_values_reject_boolean_conversion(self):
        for value in (*ControlEffect, *GuardBranch):
            with self.subTest(value=value), self.assertRaises(TypeError):
                bool(value)


class MetadataIndexTests(unittest.TestCase):
    run_nodes = LocksetTests.run_nodes
    assert_assessments = LocksetTests.assert_assessments

    def fanout(self, targets, calls=None):
        calls = targets if calls is None else calls
        nodes = {"root": node([*[call(f"f{i % targets}", line=i + 1) for i in range(calls)], write()])}
        nodes.update({f"f{i}": node([]) for i in range(targets)})
        return nodes

    def test_twenty_targets_thirty_calls_fit_a_small_work_budget(self):
        result = self.run_nodes(self.fanout(20, 30), rules=policy("root"), max_work=350,
                                entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertFalse(result.work.exhausted)
        self.assertEqual(31, result.work.function_visits)

    def test_metadata_work_scales_linearly_across_distinct_targets(self):
        previous = None
        for size in (8, 80, 800):
            result = self.run_nodes(self.fanout(size), rules=policy("root"),
                                    entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
            self.assert_assessments(result, Assessment.PROTECTED)
            self.assertFalse(result.work.exhausted)
            self.assertLess(result.work.metadata, 7 * size + 10)
            if previous is not None:
                self.assertLess(result.work.metadata, 11 * previous)
            previous = result.work.metadata

    def test_repeated_target_with_many_distinct_sites_also_scales_linearly(self):
        result = self.run_nodes(self.fanout(1, 800), rules=policy("root"),
                                entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assert_assessments(result, Assessment.PROTECTED)
        self.assertFalse(result.work.exhausted)
        self.assertLess(result.work.metadata, 7 * 800 + 10)
        self.assertEqual(801, result.work.function_visits)

    def test_tight_budget_boundary_and_every_earlier_cut_are_conservative(self):
        nodes = self.fanout(4)
        full = self.run_nodes(nodes, rules=policy("root"))
        for state in (LockState.KNOWN_HELD, LockState.KNOWN_NOT_HELD):
            for budget in range(1, full.work.consumed):
                result = self.run_nodes(nodes, rules=policy("root"), max_work=budget,
                                        entry_states={"root": Lockset.from_mapping({RQ: state})})
                self.assertTrue(result.work.exhausted)
                self.assertEqual(budget, result.work.consumed)
                self.assert_assessments(result, Assessment.UNKNOWN)
        boundary = self.run_nodes(nodes, rules=policy("root"), max_work=full.work.consumed,
                                  entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assertFalse(boundary.work.exhausted)
        self.assert_assessments(boundary, Assessment.PROTECTED)

    def test_indexing_is_deterministic_under_adjacency_reordering(self):
        fixture = graph(self.fanout(8, 20))
        for budget in (5, 35, 10000):
            before = analyze(fixture, policy("root"), provenance=TRUSTED, max_work=budget).to_json()
            fixture["nodes"]["root"]["callees"].reverse()
            after = analyze(fixture, policy("root"), provenance=TRUSTED, max_work=budget).to_json()
            self.assertEqual(before, after)


class SourceHelperExampleTests(unittest.TestCase):
    def test_complete_helper_continuations_use_the_specific_local_rq_entry_lock(self):
        from checker.lockset_demo import source_example

        result = source_example()
        self.assertEqual([("dsq_dec_nr", "scx_dispatch_q.nr", 1408), ("dsq_dec_nr", "rq.scx.nr_immed", 1417)],
                         [(a.site.function, a.field, a.site.line) for a in result.accesses])
        self.assertEqual([Assessment.PROTECTED, Assessment.PROTECTED], [a.assessment for a in result.accesses])
        self.assertEqual(LockState.UNKNOWN, result.exits[0].locks.state(result.accesses[0].required_lock))
        self.assertEqual(SOURCE_COMMIT, result.provenance.source_commit)
        self.assertTrue(result.provenance.synthetic)  # hand model, not an extracted kernel trace
        self.assertEqual([GuardBranch.CONDITION_FALSE, GuardBranch.CONDITION_TRUE],
                         [s.branch_when for s in result.control_semantics])
        self.assertTrue(all(f["verdict"] == "unknown" for f in to_findings(result, invariant="I1")))

    def test_helper_does_not_infer_entry_ownership_or_completeness(self):
        from checker.lockset_demo import source_example

        for state, expected in ((LockState.KNOWN_NOT_HELD, Assessment.UNPROTECTED),
                                (LockState.UNKNOWN, Assessment.UNKNOWN)):
            result = source_example(entry_state=state)
            self.assertEqual([expected, expected], [a.assessment for a in result.accesses])
        result = source_example(complete_events=False)
        self.assertEqual([Assessment.UNKNOWN, Assessment.UNKNOWN], [a.assessment for a in result.accesses])

    def test_source_helper_cli_is_deterministic(self):
        outputs = []
        for seed in ("1", "42"):
            completed = subprocess.run([sys.executable, "-m", "checker.lockset_demo", "--source-example", "--json"],
                                       cwd=ROOT, capture_output=True, text=True,
                                       env=dict(os.environ, PYTHONHASHSEED=seed))
            self.assertEqual(0, completed.returncode, completed.stderr)
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])


class InputAndContextTests(unittest.TestCase):
    def test_same_callee_reached_with_held_and_unknown_states(self):
        fixture = graph({"a": node([lock(), call("leaf")]), "b": node([call("leaf")]), "leaf": node([write()])},
                        roots=("a", "b"))
        result = analyze(fixture, policy("leaf"), bindings={"a": {"rq.lock": RQ}}, provenance=TRUSTED)
        self.assertEqual([Assessment.PROTECTED, Assessment.UNKNOWN], [item.assessment for item in result.accesses])
        self.assertEqual(["a", "b"], [item.site.root for item in result.accesses])

    def test_lockset_updates_copy_and_do_not_mutate_input(self):
        values = {RQ: LockState.KNOWN_NOT_HELD}
        before = Lockset.from_mapping(values)
        values[RQ] = LockState.KNOWN_HELD
        after = before.with_state(RQ, LockState.KNOWN_HELD)
        self.assertEqual(LockState.KNOWN_NOT_HELD, before.state(RQ))
        self.assertEqual(LockState.KNOWN_HELD, after.state(RQ))
        with self.assertRaises(FrozenInstanceError):
            before.entries = ()

    def test_root_states_are_independent(self):
        result = analyze(graph({"a": node([lock(), write()]), "b": node([write()])}, roots=("b", "a")),
                         policy("a", "b"), bindings={"a": {"rq.lock": RQ}, "b": {"rq.lock": RQ}}, provenance=TRUSTED)
        self.assertEqual([Assessment.PROTECTED, Assessment.UNKNOWN], [item.assessment for item in result.accesses])

    def test_malformed_lock_identity_and_policy_are_rejected(self):
        for value in (None, True, 0, "", " rq.lock", "rq lock", "*", "dsq?", "unknown"):
            with self.subTest(identity=value), self.assertRaises(ValueError):
                LockIdentity(value)
        for args in (("root", "not_a_field", RQ), ("*", FIELD, RQ)):
            with self.subTest(rule=args), self.assertRaises(ValueError):
                ProtectionRule(*args)
        with self.assertRaises(TypeError):
            ProtectionRule("root", FIELD, "rq.lock")
        with self.assertRaises(TypeError):
            ProtectionRule("root", FIELD, RQ, "write")
        with self.assertRaises(TypeError):
            ProtectionPolicy(({},))
        rule = ProtectionRule("root", FIELD, RQ)
        with self.assertRaises(ValueError):
            ProtectionPolicy((rule, rule))

    def test_lockset_states_are_not_booleans_or_untyped_strings(self):
        for value in (True, False, "known_held"):
            with self.subTest(value=value), self.assertRaises(TypeError):
                Lockset.from_mapping({RQ: value})
        with self.assertRaises(TypeError):
            Lockset((LockOwnership("rq", LockState.KNOWN_HELD),))

    def test_invalid_analysis_options_are_explicit(self):
        fixture = graph({"root": node([])})
        for depth in (-1, True, 129):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                analyze(fixture, policy("root"), max_depth=depth)
        with self.assertRaises(TypeError):
            Provenance(complete_events="yes")
        with self.assertRaises(TypeError):
            analyze(fixture, policy("root"), bindings={"root": {"rq": "rq.lock"}})
        with self.assertRaises(ValueError):
            analyze(fixture, policy("root"), callbacks={"not_root": "dispatch"})

    def test_real_schema_rejects_malformed_graph(self):
        fixture = graph({"root": node([])})
        fixture["nodes"]["root"]["events"] = "not events"
        with self.assertRaises(jsonschema.ValidationError):
            analyze(fixture, policy("root"))

    def c2_analysis(self, *, version=SOURCE_VERSION, commit=SOURCE_COMMIT, entry_states=None, bindings=None,
                    callback="dispatch", context_bindings=None):
        return analyze(graph({"root": node([write()])}, version=version), policy("root"),
                       callbacks={"root": callback}, bindings={"root": {"rq": RQ}} if bindings is None else bindings,
                       context_bindings=({"root": {ContextLockIdentity("rq", "dispatch.cpu:cpu"): RQ}}
                                         if context_bindings is None and bindings is None else context_bindings),
                       entry_states=entry_states,
                       provenance=Provenance(commit, complete_events=True, linear_events=True, synthetic=True))

    def test_c2_source_version_mismatch_is_rejected(self):
        for version in ("TBD", "TBD (see KERNEL_VERSION)", "v7.0", "v7.1-custom"):
            with self.subTest(version=version), self.assertRaises(SourceVersionMismatch):
                self.c2_analysis(version=version)

    def test_c2_source_provenance_must_match_exactly(self):
        for commit in (None, "other-source-commit"):
            with self.subTest(commit=commit), self.assertRaisesRegex(SourceVersionMismatch, "provenance"):
                self.c2_analysis(commit=commit)

    def test_c2_asserted_entry_fact_is_not_an_observed_acquisition(self):
        result = self.c2_analysis()
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertEqual(PreconditionStatus.UNPROVEN, result.preconditions[0].status)
        self.assertTrue(result.preconditions[0].evidence)

    def test_c2_entry_requirement_can_be_met_by_explicit_model_entry_state(self):
        result = self.c2_analysis(entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})})
        self.assertEqual(Assessment.PROTECTED, result.accesses[0].assessment)
        self.assertEqual(PreconditionStatus.MET, result.preconditions[0].status)

    def test_c2_local_name_binding_alone_cannot_identify_the_callback_rq(self):
        result = self.c2_analysis(entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})},
                                  context_bindings={})
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertIsNone(result.preconditions[0].lock)

    def test_c2_wrong_cpu_identity_cannot_satisfy_callback_rq_requirement(self):
        result = self.c2_analysis(entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD})},
                                  context_bindings={"root": {ContextLockIdentity("rq", "dispatch.cpu:other"): RQ}})
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertEqual(PreconditionStatus.UNPROVEN, result.preconditions[0].status)

    def test_c2_conditional_callback_requires_explicit_matching_config_and_identities(self):
        pi = LockIdentity("p0.pi_lock")
        fixture = graph({"root": node([write()])}, version=SOURCE_VERSION)
        identities = {"root": {ContextLockIdentity("rq", "cgroup_move.task:p"): RQ,
                               ContextLockIdentity("pi_lock", "cgroup_move.task:p"): pi}}
        states = {"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD, pi: LockState.KNOWN_HELD})}
        for configs, expected in ((None, Assessment.UNKNOWN), (("CONFIG_EXT_GROUP_SCHED",), Assessment.PROTECTED)):
            with self.subTest(configs=configs):
                result = analyze(fixture, policy("root"), callbacks={"root": "cgroup_move"},
                                 context_bindings=identities, entry_states=states,
                                 provenance=Provenance(SOURCE_COMMIT, True, True, True, configs))
                self.assertEqual(expected, result.accesses[0].assessment)
                if configs is None:
                    self.assertIn("unknown_callback_configuration", {c.code for c in result.conditions})

    def test_c2_read_side_ownership_cannot_be_promoted_to_exclusive_protection(self):
        sem = LockIdentity("scx_cgroup_ops_rwsem")
        result = analyze(graph({"root": node([write()])}, version=SOURCE_VERSION), policy("root"),
                         callbacks={"root": "cgroup_set_weight"},
                         context_bindings={"root": {ContextLockIdentity("scx_cgroup_ops_rwsem", "global:scx_cgroup_ops_rwsem"): sem}},
                         entry_states={"root": Lockset.from_mapping({RQ: LockState.KNOWN_HELD, sem: LockState.KNOWN_HELD})},
                         provenance=Provenance(SOURCE_COMMIT, True, True, True, ("CONFIG_EXT_GROUP_SCHED",)))
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertIn("unsupported_entry_lock_mode", {c.code for c in result.conditions})

    def test_c2_init_task_unknown_rq_is_not_injected_as_definitely_absent(self):
        pi = LockIdentity("p0.pi_lock")
        result = analyze(graph({"root": node([write()])}, version=SOURCE_VERSION), policy("root"),
                         callbacks={"root": "init_task"},
                         context_bindings={"root": {ContextLockIdentity("pi_lock", "init_task.task:p"): pi}},
                         entry_states={"root": Lockset.from_mapping({pi: LockState.KNOWN_NOT_HELD})},
                         provenance=Provenance(SOURCE_COMMIT, True, True, True))
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertEqual(LockState.UNKNOWN, result.accesses[0].observed)

    def test_c2_context_bindings_require_typed_object_identities(self):
        with self.assertRaises(TypeError):
            self.c2_analysis(context_bindings={"root": {"rq": RQ}})
        with self.assertRaises(TypeError):
            self.c2_analysis(context_bindings={"root": {ContextLockIdentity("rq", "dispatch.cpu:cpu"): "rq"}})

    def test_config_provenance_is_immutable_and_rejects_ambiguous_mappings(self):
        configs = ["CONFIG_EXT_GROUP_SCHED", "CONFIG_EXT_GROUP_SCHED"]
        provenance = Provenance(enabled_configs=configs)
        configs.clear()
        self.assertEqual(("CONFIG_EXT_GROUP_SCHED",), provenance.enabled_configs)
        for invalid in ("CONFIG_EXT_GROUP_SCHED", {"CONFIG_EXT_GROUP_SCHED": False}, [True], ["bad"]):
            with self.subTest(configs=invalid), self.assertRaises((TypeError, ValueError)):
                Provenance(enabled_configs=invalid)

    def test_c2_unresolved_lock_alias_is_not_guessed(self):
        result = self.c2_analysis(bindings={})
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertIsNone(result.preconditions[0].lock)

    def test_c2_unknown_callback_is_conservative(self):
        result = self.c2_analysis(callback="future_callback")
        self.assertEqual(Assessment.UNKNOWN, result.accesses[0].assessment)
        self.assertIn("unknown_callback", {condition.code for condition in result.conditions})

    def test_result_states_cannot_silently_be_booleans(self):
        result = analyze(graph({"root": node([{"kind": "assert_held", "lock": "rq.lock"}, write()])}),
                         policy("root"), bindings={"root": {"rq.lock": RQ}}, provenance=TRUSTED)
        for value in (*Assessment, *PreconditionStatus, *result.accesses, *result.preconditions,
                      LockOwnership(RQ, LockState.UNKNOWN)):
            with self.subTest(value=value), self.assertRaises(TypeError):
                bool(value)


class OutputTests(unittest.TestCase):
    def result(self):
        return analyze(graph({"root": node([lock(), write(line=2), unlock(), write(line=4),
                                            {"kind": "guard", "cond": "flag"}, write(line=6)])}),
                       policy("root"), bindings={"root": {"rq.lock": RQ}}, provenance=TRUSTED)

    def test_deterministic_json_and_no_input_mutation(self):
        fixture = graph({"root": node([lock(), call("a"), call("b"), write()]), "a": node([]), "b": node([])})
        original = copy.deepcopy(fixture)
        before = analyze(fixture, policy("root"), bindings={"root": {"rq.lock": RQ}}, provenance=TRUSTED).to_json()
        fixture["nodes"]["root"]["callees"].reverse()
        after = analyze(fixture, policy("root"), bindings={"root": {"rq.lock": RQ}}, provenance=TRUSTED).to_json()
        self.assertEqual(before, after)
        fixture["nodes"]["root"]["callees"].reverse()
        self.assertEqual(original, fixture)
        self.assertEqual(before, analyze(fixture, policy("root"), bindings={"root": {"rq.lock": RQ}},
                                         provenance=TRUSTED).to_json())

    def test_adapter_is_schema_valid_and_never_emits_holds_or_violated(self):
        result = self.result()
        self.assertEqual([Assessment.PROTECTED, Assessment.UNPROTECTED, Assessment.UNKNOWN],
                         [item.assessment for item in result.accesses])
        findings = to_findings(result, invariant="I1")
        runner.validate("findings", {"kernel_version": result.source_version, "findings": findings})
        self.assertEqual(["unknown"] * 3, [finding["verdict"] for finding in findings])
        self.assertTrue(all(finding["enforcement"] == ["unknown"] for finding in findings))
        self.assertEqual(2, findings[0]["evidence"][0]["line"])
        self.assertIn("unknown_control_flow", findings[2]["evidence"][0]["detail"])

    def test_adapter_requires_explicit_invariant_id(self):
        for value in (None, "", "all-fields"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                to_findings(self.result(), invariant=value)

    def test_adapter_can_be_used_explicitly_under_the_c1_plugin_contract(self):
        fixture = graph({"root": node([lock(), write()])})
        catalog = runner.load_data(ROOT / "contracts/fixtures/catalog.example.yaml")
        catalog["kernel_version"] = fixture["kernel_version"]

        def check(callgraph, _catalog):
            return to_findings(analyze(callgraph, policy("root"), bindings={"root": {"rq.lock": RQ}},
                                       provenance=TRUSTED), invariant="I1")

        with patch.dict(_REGISTRY, {"I1": check}, clear=True):
            self.assertEqual("unknown", runner.check(fixture, catalog)[0]["verdict"])
        self.assertEqual({}, registered())

    def test_demo_and_hash_seed_independence(self):
        outputs = []
        for seed in ("1", "42"):
            completed = subprocess.run([sys.executable, "-m", "checker.lockset_demo", "--json"], cwd=ROOT,
                                       capture_output=True, text=True, env=dict(os.environ, PYTHONHASHSEED=seed))
            self.assertEqual(0, completed.returncode, completed.stderr)
            value = json.loads(completed.stdout)
            self.assertTrue(value["provenance"]["synthetic"])
            self.assertEqual(["protected", "unprotected", "unknown"],
                             [item["assessment"] for item in value["accesses"]])
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
