"""Synthetic lockset proofs and conservative failures, not kernel execution tests."""
import copy
import json
import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from itertools import product
from pathlib import Path
from unittest.mock import patch

import jsonschema

from checker import runner
from checker.checkers import _REGISTRY, registered
from checker.context import SOURCE_COMMIT, SOURCE_VERSION, LockState, SourceVersionMismatch
from checker.lock_policy import AccessKind, LockIdentity, ProtectionPolicy, ProtectionRule
from checker.lockset import (
    Assessment, LockOwnership, Lockset, PreconditionStatus, Provenance, analyze, to_findings,
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

    def test_callee_acquires_before_caller_write(self):
        result = self.run_nodes({"root": node([call("leaf"), write()]), "leaf": node([lock()])})
        self.assert_assessments(result, Assessment.PROTECTED)

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
                    callback="dispatch"):
        return analyze(graph({"root": node([write()])}, version=version), policy("root"),
                       callbacks={"root": callback}, bindings={"root": {"rq": RQ}} if bindings is None else bindings,
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
