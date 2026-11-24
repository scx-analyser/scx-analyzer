"""Synthetic abstract-model tests, not tests of Linux safety or enforcement."""
from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace

import jsonschema

from checker import runner
from checker.checkers import registered
from checker.guards import (
    Assessment, BranchWhen, ControlEdge, DominanceEvidence, EntryFact, FunctionModel, GuardPolicy, GuardSemantics,
    Model, Predicate, PredicatePreservation, Source, SourceReference, Truth, analyze, graph_digest,
)


SOURCE = Source("synthetic-c4-v1", "0" * 40)
CPU = Predicate("ops_cpu_valid(cpu)", ("cpu:argument-0",))
OTHER_CPU = Predicate("ops_cpu_valid(cpu)", ("cpu:argument-1",))
AFFINITY = Predicate("cpumask_test_cpu(cpu, p->cpus_ptr)", ("task:argument-0", "cpu:argument-0"))
DSQ = Predicate("dsq_exists(id)", ("dsq:argument-0",))
FIELD = "rq.synthetic_state"
REF = SourceReference("synthetic.c", "root", 1, 10000)


def guard_event(condition="!ops_cpu_valid(cpu)", action="return", **kwargs):
    return {"kind": "guard", "cond": condition, "action": action, **kwargs}


def write(field=FIELD, **kwargs):
    return {"kind": "write", "field": field, **kwargs}


def call(target="helper", **kwargs):
    return {"kind": "call", "target": target, **kwargs}


def node(events=(), callees=(), kind="internal", **kwargs):
    return {"kind": kind, "file": "synthetic.c", "events": list(events),
            "callees": [dict(e) if isinstance(e, dict) else {"target": e, "kind": "direct"}
                        for e in callees], **kwargs}


def graph(events=(), nodes=None, callees=(), **kwargs):
    return {"kernel_version": SOURCE.version, "generator": "C4 synthetic tests", "illustrative": True,
            "roots": ["root"], "nodes": {"root": node(events, callees, kind="kfunc"), **(nodes or {})}, **kwargs}


def policy(function="root", predicate=CPU, root="root", **kwargs):
    return GuardPolicy("I3.synthetic", root, function, FIELD, predicate, SOURCE,
                       replace(REF, symbol=function), **kwargs)


def semantics(function="root", index=0, predicate=CPU, **kwargs):
    values = dict(condition="!ops_cpu_valid(cpu)", action="return", condition_true_means=Truth.FALSE,
                  branch_when=BranchWhen.CONDITION_TRUE, exits_function=True,
                  reference=replace(REF, symbol=function))
    values.update(kwargs)
    return GuardSemantics(function, index, predicate, **values)


def model_for(g, guards=(), **kwargs):
    values = dict(source=SOURCE, graph_digest=graph_digest(g),
                  functions=tuple(FunctionModel(f, replace(REF, symbol=f), True, True)
                                  for f in sorted(g["nodes"])),
                  guards=tuple(guards), bindings_verified=True, synthetic=True)
    values.update(kwargs)
    return Model(**values)


def run(g, policies=None, guards=(), **kwargs):
    model = kwargs.pop("model", model_for(g, guards))
    return analyze(g, tuple(policies if policies is not None else [policy()]), model=model, **kwargs)


class GuardTransferTests(unittest.TestCase):
    def test_polarity_against_independent_concrete_boolean_paths(self):
        def return_if_invalid(value):
            if not value:
                return None
            return value

        def return_if_valid(value):
            if value:
                return None
            return value

        # The oracle executes ordinary Python branches. It does not call any
        # abstract transfer/join helper, nor infer expectations from our enums.
        cases = [
            ("!ops_cpu_valid(cpu)", Truth.FALSE, BranchWhen.CONDITION_TRUE, return_if_invalid),
            ("ops_cpu_valid(cpu)", Truth.TRUE, BranchWhen.CONDITION_TRUE, return_if_valid),
            ("ops_cpu_valid(cpu)", Truth.TRUE, BranchWhen.CONDITION_FALSE, return_if_invalid),
            ("!ops_cpu_valid(cpu)", Truth.FALSE, BranchWhen.CONDITION_FALSE, return_if_valid),
        ]
        for condition, meaning, sense, concrete in cases:
            for entry in (None, False, True):
                with self.subTest(condition=condition, sense=sense, entry=entry):
                    inputs = (False, True) if entry is None else (entry,)
                    reached = {concrete(v) for v in inputs} - {None}
                    facts = [] if entry is None else [EntryFact(
                        CPU, Truth.TRUE if entry else Truth.FALSE, REF, "root")]
                    g = graph([guard_event(condition), write()])
                    result = run(g, guards=[semantics(condition=condition,
                        condition_true_means=meaning, branch_when=sense)], entry_facts=facts)
                    observed = [a for a in result.accesses if a.event_index is not None]
                    self.assertEqual(1 if reached else 0, len(observed))
                    if reached:
                        access = observed[0]
                        self.assertEqual("true" if reached == {True} else "false", access.observed.value)
                        self.assertEqual("established" if reached == {True} else "false", access.assessment.value)

    def test_verified_negative_branch_return_establishes_predicate(self):
        result = run(graph([guard_event(), write()]), guards=[semantics()])
        access = result.accesses[0]
        self.assertIs(access.observed, Truth.TRUE)
        self.assertIs(access.assessment, Assessment.ESTABLISHED)
        self.assertIn("!ops_cpu_valid", access.evidence[0].detail)

    def test_missing_guard_is_missing_check_not_false_argument(self):
        access = run(graph([write()])).accesses[0]
        self.assertIs(access.assessment, Assessment.MISSING)
        self.assertIs(access.observed, Truth.UNKNOWN)
        self.assertIn("actual predicate value unknown", access.explanation)

    def test_known_false_argument_is_distinct_from_missing_check(self):
        fact = EntryFact(CPU, Truth.FALSE, REF, "root")
        access = run(graph([write()]), entry_facts=[fact]).accesses[0]
        self.assertIs(access.assessment, Assessment.FALSE)
        self.assertIs(access.observed, Truth.FALSE)

    def test_explicit_entry_precondition_is_labeled_as_such(self):
        fact = EntryFact(CPU, Truth.TRUE, REF, "root")
        access = run(graph([write()]), entry_facts=[fact]).accesses[0]
        self.assertIs(access.assessment, Assessment.ESTABLISHED)
        self.assertIn("not a runtime observation", access.evidence[0].detail)

    def test_wrong_polarity_proves_false_on_continuing_path(self):
        condition = "ops_cpu_valid(cpu)"
        access = run(graph([guard_event(condition), write()]),
                     guards=[semantics(condition=condition, condition_true_means=Truth.TRUE)]).accesses[0]
        self.assertIs(access.assessment, Assessment.FALSE)

    def test_failure_action_when_condition_false_has_explicit_semantics(self):
        condition = "ops_cpu_valid(cpu)"
        access = run(graph([guard_event(condition), write()]), guards=[semantics(
            condition=condition, condition_true_means=Truth.TRUE,
            branch_when=BranchWhen.CONDITION_FALSE)]).accesses[0]
        self.assertIs(access.assessment, Assessment.ESTABLISHED)

    def test_guard_after_write_cannot_protect_earlier_write(self):
        result = run(graph([write(), guard_event()]), guards=[semantics(index=1)])
        self.assertIs(result.accesses[0].assessment, Assessment.MISSING)

    def test_symbolic_guard_without_annotation_is_unknown(self):
        access = run(graph([guard_event(), write()])).accesses[0]
        self.assertIs(access.assessment, Assessment.UNKNOWN)

    def test_compound_condition_is_not_automatically_parsed_or_matched(self):
        g = graph([guard_event("!ops_cpu_valid(cpu) && dsq_exists(id)"), write()])
        self.assertIs(run(g).accesses[0].assessment, Assessment.UNKNOWN)

    def test_error_warn_fallback_and_continue_do_not_imply_termination(self):
        for action in ("error", "fallback", "continue", "return"):
            with self.subTest(action=action):
                g = graph([guard_event(action=action), write()])
                s = semantics(action=action, exits_function=False)
                self.assertIs(run(g, guards=[s]).accesses[0].assessment, Assessment.UNKNOWN)

    def test_error_with_separately_verified_return_can_filter_path(self):
        g = graph([guard_event(action="error"), write()])
        self.assertIs(run(g, guards=[semantics(action="error")]).accesses[0].assessment,
                      Assessment.ESTABLISHED)

    def test_bare_error_and_warn_do_not_skip_later_write_or_preserve_facts(self):
        for kind in ("error", "warn"):
            with self.subTest(kind=kind):
                g = graph([guard_event(), {"kind": kind}, write()])
                self.assertIs(run(g, guards=[semantics()]).accesses[0].assessment, Assessment.UNKNOWN)

    def test_assertions_and_locks_are_not_predicate_checks(self):
        for kind in ("lock", "unlock", "assert_held", "assert_not_held"):
            with self.subTest(kind=kind):
                access = run(graph([{"kind": kind, "lock": "rq"}, write()])).accesses[0]
                self.assertIs(access.assessment, Assessment.MISSING)

    def test_atomic_needs_its_own_explicit_policy(self):
        g = graph([guard_event(), {"kind": "atomic", "field": FIELD, "op": "cmpxchg"}])
        missing = run(g, guards=[semantics()]).accesses[0]
        self.assertIsNone(missing.event_index)
        self.assertIs(missing.assessment, Assessment.UNKNOWN)
        self.assertEqual("write", missing.access_kind)
        access = run(g, [policy(access_kind="atomic")], [semantics()]).accesses[0]
        self.assertIs(access.assessment, Assessment.ESTABLISHED)

    def test_memory_mutation_invalidates_dependent_predicates(self):
        g = graph([guard_event(), write(), write()])
        result = run(g, guards=[semantics()])
        self.assertIs(result.accesses[0].assessment, Assessment.ESTABLISHED)
        self.assertIs(result.accesses[1].assessment, Assessment.UNKNOWN)

    def test_verified_new_guard_can_reestablish_after_memory_mutation(self):
        g = graph([guard_event(), write(), guard_event(), write()])
        result = run(g, guards=[semantics(), semantics(index=2)])
        self.assertEqual([Assessment.ESTABLISHED] * 2, [a.assessment for a in result.accesses])

    def test_conditional_write_or_call_does_not_look_unconditional(self):
        for event in (write(cond="maybe"), call(cond="maybe")):
            with self.subTest(event=event):
                callees = ["helper"] if event["kind"] == "call" else []
                g = graph([guard_event(), event, write()], nodes={"helper": node()}, callees=callees)
                result = run(g, guards=[semantics()])
                self.assertEqual(1 if callees else 2, len(result.accesses))
                for access in result.accesses:
                    self.assertIs(access.assessment, Assessment.UNKNOWN)
                    self.assertIn("conditional event lacks branch structure", access.unresolved)

    def test_conflicting_terminating_guards_make_later_write_unreachable(self):
        positive = "ops_cpu_valid(cpu)"
        g = graph([guard_event(), guard_event(positive), write()])
        result = run(g, guards=[semantics(), semantics(index=1, condition=positive,
                                                     condition_true_means=Truth.TRUE)])
        self.assertTrue(all(a.event_index is None and a.assessment is Assessment.UNKNOWN for a in result.accesses))

    def test_unproven_context_cannot_prune_writes_using_inferred_facts(self):
        positive = "ops_cpu_valid(cpu)"
        g = graph([guard_event(), guard_event(positive), write()])
        guards = [semantics(), semantics(index=1, condition=positive, condition_true_means=Truth.TRUE)]
        result = run(g, guards=guards, model=model_for(g, guards, bindings_verified=False))
        self.assertEqual(1, len(result.accesses))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)

    def test_two_cpu_identities_do_not_alias(self):
        g = graph([guard_event(), write()])
        access = run(g, [policy(predicate=OTHER_CPU)], [semantics()]).accesses[0]
        self.assertIs(access.assessment, Assessment.MISSING)

    def test_affinity_and_dsq_require_distinct_explicit_predicates(self):
        for pred in (AFFINITY, DSQ):
            with self.subTest(pred=pred):
                condition = "!(" + pred.expression + ")"
                g = graph([guard_event(condition), write()])
                result = run(g, [policy(predicate=pred)], [semantics(predicate=pred, condition=condition)])
                self.assertIs(result.accesses[0].assessment, Assessment.ESTABLISHED)

    def test_multiple_policy_obligations_are_not_combined_into_false_success(self):
        result = run(graph([guard_event(), write()]), [policy(), policy(predicate=AFFINITY)], [semantics()])
        statuses = {a.predicate: a.assessment for a in result.accesses}
        self.assertIs(statuses[CPU], Assessment.ESTABLISHED)
        self.assertIs(statuses[AFFINITY], Assessment.MISSING)
        self.assertTrue(all(f["verdict"] == "unknown" for f in result.to_findings()))


class InterproceduralGuardTests(unittest.TestCase):
    def test_return_join_against_independent_concrete_invocations(self):
        observed = {"helper": set(), "root": set()}

        def helper(value):
            if not value:
                return
            observed["helper"].add(value)

        for value in (False, True):
            helper(value)
            observed["root"].add(value)  # Caller resumes after BOTH callee exits.
        self.assertEqual({"helper": {True}, "root": {False, True}}, observed)
        g = graph([call(), write()], {"helper": node([guard_event(), write()])}, ["helper"])
        result = run(g, [policy(), policy(function="helper")], [semantics(function="helper")])
        self.assertEqual(2, len(result.accesses))
        statuses = {a.function: a.assessment.value for a in result.accesses}
        self.assertEqual({"helper": "established", "root": "unknown"}, statuses)

    def test_caller_guard_propagates_into_callee(self):
        g = graph([guard_event(), call()], {"helper": node([write()])}, ["helper"])
        result = run(g, [policy(function="helper")], [semantics()])
        self.assertIs(result.accesses[0].assessment, Assessment.ESTABLISHED)
        self.assertEqual(("root", "helper"), result.accesses[0].path)

    def test_three_functions_preserve_call_path_evidence(self):
        g = graph([guard_event(), call("a")], {
            "a": node([call("b")], ["b"]), "b": node([call("c")], ["c"]),
            "c": node([write()])}, ["a"])
        access = run(g, [policy(function="c")], [semantics()]).accesses[0]
        self.assertIs(access.assessment, Assessment.ESTABLISHED)
        self.assertEqual(("root", "a", "b", "c"), access.path)
        self.assertEqual(("root",), access.evidence[0].path)

    def test_callee_early_return_does_not_establish_caller_predicate(self):
        g = graph([call(), write()], {"helper": node([guard_event()])}, ["helper"])
        access = run(g, guards=[semantics(function="helper")]).accesses[0]
        self.assertIs(access.assessment, Assessment.UNKNOWN)
        self.assertIs(access.observed, Truth.UNKNOWN)

    def test_callee_writes_are_protected_only_on_its_continuing_path(self):
        g = graph([call(), write()], {"helper": node([guard_event(), write()])}, ["helper"])
        result = run(g, [policy(), policy(function="helper")], [semantics(function="helper")])
        self.assertEqual([Assessment.ESTABLISHED, Assessment.UNKNOWN], [a.assessment for a in result.accesses])

    def test_callee_mutation_invalidates_caller_fact(self):
        g = graph([guard_event(), call(), write()], {"helper": node([write("task_struct.cpus_ptr")])}, ["helper"])
        access = run(g, guards=[semantics()]).accesses[0]
        self.assertIs(access.assessment, Assessment.UNKNOWN)

    def test_same_callee_from_different_states_has_separate_results(self):
        g = graph([guard_event(), call(), call()], {"helper": node([write()])}, ["helper"])
        result = run(g, [policy(function="helper")], [semantics()])
        self.assertEqual([Assessment.ESTABLISHED, Assessment.UNKNOWN], [a.assessment for a in result.accesses])

    def test_root_entry_precondition_cannot_leak_into_another_root(self):
        g = graph([write()], {"other": node([write()], kind="kfunc")}, roots=["root", "other"])
        result = run(g, [policy(), policy(function="other", root="other")],
                     entry_facts=[EntryFact(CPU, Truth.TRUE, REF, "root")])
        statuses = {a.root: a.assessment for a in result.accesses}
        self.assertIs(statuses["root"], Assessment.ESTABLISHED)
        self.assertIs(statuses["other"], Assessment.MISSING)

    def test_distinct_roots_can_have_conflicting_entry_preconditions(self):
        g = graph([write()], {"other": node([write()], kind="kfunc")}, roots=["root", "other"])
        result = run(g, [policy(), policy(function="other", root="other")], entry_facts=[
            EntryFact(CPU, Truth.TRUE, REF, "root"), EntryFact(CPU, Truth.FALSE, REF, "other")])
        self.assertEqual([Assessment.FALSE, Assessment.ESTABLISHED], [a.assessment for a in result.accesses])

    def test_distinct_caller_object_cannot_protect_callee_object(self):
        g = graph([guard_event(), call()], {"helper": node([write()])}, ["helper"])
        access = run(g, [policy(function="helper", predicate=OTHER_CPU)], [semantics()]).accesses[0]
        self.assertIs(access.assessment, Assessment.MISSING)

    def test_calls_execute_in_event_order(self):
        g = graph([call(), guard_event()], {"helper": node([write()])}, ["helper"])
        result = run(g, [policy(function="helper")], [semantics(index=1)])
        self.assertIs(result.accesses[0].assessment, Assessment.MISSING)

    def test_missing_callee_invalidates_predicates(self):
        g = graph([guard_event(), call("missing"), write()], callees=["missing"])
        result = run(g, guards=[semantics()])
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIn("opaque", result.gaps[0].reason)

    def test_guard_after_unknown_call_cannot_repair_unknown_bindings(self):
        g = graph([call("missing"), guard_event(), write()], callees=["missing"])
        result = run(g, guards=[semantics(index=1)])
        self.assertEqual(1, len(result.accesses))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIs(result.accesses[0].observed, Truth.UNKNOWN)

    def test_indirect_call_is_not_followed_as_a_direct_call(self):
        g = graph([guard_event(), call(), write()], {"helper": node([write()])},
                  [{"target": "helper", "kind": "indirect"}])
        result = run(g, [policy(), policy(function="helper")], [semantics()])
        self.assertEqual(["root"], [a.function for a in result.accesses if a.event_index is not None])
        missing = next(a for a in result.accesses if a.function == "helper")
        self.assertIsNone(missing.event_index)
        self.assertIs(missing.assessment, Assessment.UNKNOWN)
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertTrue(result.gaps)

    def test_call_event_without_direct_edge_confirmation_is_unknown(self):
        g = graph([guard_event(), call(), write()], {"helper": node()})
        self.assertIs(run(g, guards=[semantics()]).accesses[0].assessment, Assessment.UNKNOWN)

    def test_opaque_function_with_events_stays_opaque(self):
        for kind in ("external", "boundary"):
            with self.subTest(kind=kind):
                g = graph([guard_event(), call(), write()], {"helper": node([], kind=kind)}, ["helper"])
                self.assertIs(run(g, guards=[semantics()]).accesses[0].assessment, Assessment.UNKNOWN)

    def test_recursion_terminates_conservatively(self):
        g = graph([guard_event(), call(), write()], {"helper": node([call("root")], ["root"])}, ["helper"])
        result = run(g, guards=[semantics()])
        self.assertTrue(any("cycle" in gap.reason for gap in result.gaps))
        self.assertEqual(2, len(result.accesses))
        self.assertTrue(all(a.assessment is Assessment.UNKNOWN for a in result.accesses))

    def test_depth_limit_cannot_create_established_result(self):
        g = graph([guard_event(), call(), write()], {"helper": node()}, ["helper"])
        result = run(g, guards=[semantics()], max_depth=0)
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertTrue(any("depth" in gap.reason for gap in result.gaps))

    def test_work_budget_creates_explicit_unknown_obligations(self):
        g = graph([guard_event(), write()])
        result = run(g, guards=[semantics()], max_work=1)
        self.assertEqual(1, result.work_used)
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIsNone(result.accesses[0].event_index)
        self.assertTrue(any("budget" in gap.reason for gap in result.gaps))

    def test_budget_cut_retains_guard_evidence_already_observed(self):
        # Entry + two metadata event scans + the guard consume four units.
        # The pending write is not reached; the guard's trace must survive.
        g = graph([guard_event(line=2), write(line=4)])
        result = run(g, guards=[semantics()], max_work=4)
        self.assertEqual(4, result.work_used)
        self.assertEqual(1, len(result.accesses))
        access = result.accesses[0]
        self.assertIs(access.assessment, Assessment.UNKNOWN)
        self.assertIsNone(access.event_index)
        self.assertEqual([2], [e.line for e in access.evidence])
        self.assertEqual(("root",), access.evidence[0].path)

    def test_join_work_is_included_in_the_global_budget(self):
        g = graph([guard_event(), call(), write()], {"helper": node()}, ["helper"])
        facts = [EntryFact(Predicate(f"other_{i}()", (f"obj:{i}",)), Truth.UNKNOWN, REF, "root")
                 for i in range(100)]
        result = run(g, guards=[semantics()], entry_facts=facts, max_work=10)
        self.assertLessEqual(result.work_used, 10)
        self.assertTrue(any("budget" in gap.reason for gap in result.gaps))
        self.assertTrue(result.accesses)
        self.assertTrue(all(a.assessment is Assessment.UNKNOWN for a in result.accesses))

    def test_diamond_graph_is_bounded_and_deterministic(self):
        nodes = {"leaf": node([write()])}
        for n in reversed(range(12)):
            target = "leaf" if n == 11 else f"level{n + 1}"
            nodes[f"level{n}"] = node([call(target), call(target)], [target])
        g = graph([call("level0")], nodes, ["level0"])
        result = run(g, [policy(function="leaf")], max_work=150)
        self.assertEqual(150, result.work_used)
        self.assertTrue(any("budget" in gap.reason for gap in result.gaps))
        self.assertEqual(result.to_dict(), run(g, [policy(function="leaf")], max_work=150).to_dict())

    def test_deep_graph_stops_before_python_recursion_limit(self):
        nodes = {f"n{i}": node([call(f"n{i+1}")], [f"n{i+1}"]) for i in range(140)}
        nodes["n140"] = node([write()])
        g = graph([call("n0")], nodes, ["n0"])
        result = run(g, [policy(function="n140")], max_depth=12)
        self.assertTrue(any("depth" in gap.reason for gap in result.gaps))


class GuardInputTests(unittest.TestCase):
    def test_no_provenance_means_unknown_even_with_apparent_guard(self):
        result = run(graph([guard_event(), write()]), model=None)
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)

    def test_incomplete_input_cannot_justify_establishment(self):
        g = graph([guard_event(), write()])
        for key in ("complete_events", "linear_except_guards"):
            with self.subTest(key=key):
                fm = replace(FunctionModel("root", REF, True, True), **{key: False})
                m = model_for(g, [semantics()], functions=[fm])
                self.assertIs(run(g, model=m).accesses[0].assessment, Assessment.UNKNOWN)

    def test_unverified_aliases_cannot_establish_predicate(self):
        g = graph([guard_event(), write()])
        m = model_for(g, [semantics()], bindings_verified=False)
        self.assertIs(run(g, model=m).accesses[0].assessment, Assessment.UNKNOWN)

    def test_missing_events_create_unknown_obligation(self):
        g = graph()
        del g["nodes"]["root"]["events"]
        result = run(g)
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIn("missing ordered events", result.gaps[0].reason)

    def test_unordered_callee_metadata_is_not_executed_or_assumed_harmless(self):
        g = graph([guard_event(), write()], {"helper": node()}, ["helper"])
        result = run(g, guards=[semantics()])
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIn("unsequenced", result.gaps[0].reason)

    def test_unordered_call_site_on_different_line_is_detected(self):
        g = graph([guard_event(), call(line=20), write()], {"helper": node()},
                  [{"target": "helper", "kind": "direct", "line": 20},
                   {"target": "helper", "kind": "direct", "line": 30}])
        result = run(g, guards=[semantics()])
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)

    def test_unsequenced_write_is_unknown_not_ordered_from_metadata(self):
        g = graph([guard_event()])
        g["nodes"]["root"]["writes"] = [FIELD]
        result = run(g, guards=[semantics()])
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIsNone(result.accesses[0].event_index)

    def test_memory_event_without_identity_invalidates_certainty(self):
        g = graph([guard_event(), {"kind": "write"}, write()])
        self.assertIs(run(g, guards=[semantics()]).accesses[0].assessment, Assessment.UNKNOWN)

    def test_unidentified_write_alone_reports_unknown_coverage(self):
        g = graph([guard_event(), {"kind": "write", "line": 5}])
        result = run(g, guards=[semantics()])
        self.assertTrue(any("field identity" in gap.reason for gap in result.gaps))
        self.assertEqual(1, len(result.accesses))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIsNone(result.accesses[0].event_index)
        self.assertEqual(5, result.accesses[0].line)

    def test_unidentified_atomic_does_not_apply_an_ordinary_write_policy(self):
        g = graph([{"kind": "atomic"}])
        result = run(g)
        self.assertEqual(1, len(result.accesses))
        self.assertIsNone(result.accesses[0].event_index)
        self.assertEqual("write", result.accesses[0].access_kind)
        self.assertTrue(result.gaps)
        atomic = run(g, [policy(access_kind="atomic")])
        self.assertEqual(1, len(atomic.accesses))
        self.assertIs(atomic.accesses[0].assessment, Assessment.UNKNOWN)

    def test_unidentified_write_at_exact_policy_site_reports_one_unknown(self):
        result = run(graph([{"kind": "write", "line": 5}]), [policy(access_line=5)])
        self.assertEqual(1, len(result.accesses))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)

    def test_incomplete_empty_stream_has_an_explicit_unknown_gap(self):
        g = graph()
        result = run(g, model=model_for(g, functions=[FunctionModel("root", REF)]))
        self.assertEqual(1, len(result.accesses))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIsNone(result.accesses[0].event_index)
        self.assertTrue(any("completeness" in gap.reason for gap in result.gaps))
        self.assertTrue(all(f["verdict"] == "unknown" for f in result.to_findings()))

    def test_illustrative_input_cannot_be_promoted_to_real_source(self):
        g = graph([guard_event(), write(line=4)])
        m = model_for(g, [semantics()], synthetic=False, config_digest="a" * 64)
        result = run(g, [policy(access_line=4)], model=m)
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIn("illustrative graph is not a verified kernel trace", result.accesses[0].unresolved)

    def test_policy_applies_only_to_explicit_field_function_and_root(self):
        g = graph([write("rq.other_state"), call()], {"helper": node([write()])}, ["helper"])
        coverage = run(g).accesses
        self.assertEqual(1, len(coverage))
        self.assertIsNone(coverage[0].event_index)
        self.assertIs(coverage[0].assessment, Assessment.UNKNOWN)
        self.assertEqual("root", coverage[0].function)

    def test_source_version_mismatch_fails_explicitly(self):
        g = graph([write()])
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            run(g, [replace(policy(), source=Source("v7.1", SOURCE.commit))])

    def test_source_commit_mismatch_fails_explicitly(self):
        g = graph([write()])
        with self.assertRaisesRegex(ValueError, "commit mismatch"):
            run(g, model=model_for(g, source=Source(SOURCE.version, "1" * 40)))

    def test_source_model_version_mismatch_without_policies(self):
        g = graph()
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            run(g, [], model=model_for(g, source=Source("v7.1", SOURCE.commit)))

    def test_snapshot_mismatch_rejects_stale_annotations(self):
        g = graph([guard_event(), write()])
        m = model_for(g, [semantics()])
        g["nodes"]["root"]["events"].reverse()
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            run(g, model=m)

    def test_annotation_must_match_exact_condition_action_event_and_source(self):
        g = graph([guard_event(), write()])
        for change in ({"condition": "other"}, {"action": "fallback"}, {"event_index": 1},
                       {"event_index": 10}, {"reference": replace(REF, file="other.c")}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "guard annotation"):
                run(g, guards=[replace(semantics(), **change)])

    def test_function_reference_and_event_ranges_must_match(self):
        g = graph([write(line=30)])
        for reference in (replace(REF, file="other.c"), replace(REF, end_line=10)):
            with self.subTest(reference=reference), self.assertRaisesRegex(ValueError, "source"):
                run(g, model=model_for(g, functions=[FunctionModel("root", reference, True, True)]))

    def test_non_synthetic_policy_needs_exact_access_site(self):
        g = graph([write()])
        with self.assertRaisesRegex(ValueError, "exact access line"):
            run(g, model=model_for(g, synthetic=False))

    def test_missing_access_source_line_cannot_match_real_policy_optimistically(self):
        g = graph([guard_event(), write()], illustrative=False)
        result = run(g, [policy(access_line=8)], model=model_for(
            g, [semantics()], synthetic=False, config_digest="a" * 64))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIn("access source location unresolved", result.accesses[0].unresolved)

    def test_missing_exact_policy_site_is_explicit_unknown_obligation(self):
        result = run(graph(), [policy(access_line=8)])
        self.assertEqual(1, len(result.accesses))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIsNone(result.accesses[0].event_index)
        self.assertIn("policy access site absent", result.gaps[0].reason)

    def test_missing_kernel_configuration_provenance_is_unknown(self):
        g = graph([guard_event(), write(line=8)], illustrative=False)
        result = run(g, [policy(access_line=8)], model=model_for(g, [semantics()], synthetic=False))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIn("kernel configuration provenance missing", result.accesses[0].unresolved)

    def test_annotated_source_model_still_cannot_make_kernel_safety_verdict(self):
        g = graph([guard_event(), write(line=8)], illustrative=False)
        m = model_for(g, [semantics()], synthetic=False, config_digest="a" * 64)
        result = run(g, [policy(access_line=8)], model=m)
        self.assertIs(result.accesses[0].assessment, Assessment.ESTABLISHED)
        self.assertEqual("a" * 64, result.config_digest)
        self.assertEqual("unknown", result.to_findings()[0]["verdict"])

    def test_invalid_configuration_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "configuration digest"):
            model_for(graph(), config_digest="short")

    def test_schema_malformed_graph_is_rejected(self):
        for g in ({}, graph([{"kind": "unsupported"}]), graph([write("bad_field")])):
            with self.subTest(g=g), self.assertRaises(jsonschema.ValidationError):
                analyze(g, [policy()])

    def test_missing_root_is_rejected(self):
        g = graph()
        g["roots"] = ["absent"]
        with self.assertRaisesRegex(ValueError, "roots missing"):
            analyze(g, [])

    def test_entry_fact_for_absent_root_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "entry fact root"):
            run(graph(), entry_facts=[EntryFact(CPU, Truth.TRUE, REF, "absent")])

    def test_malformed_policy_identity_and_parameters_are_rejected(self):
        for change in ({"field": "invalid"}, {"root": "*"}, {"function": "*"},
                       {"access_kind": "read"}, {"predicate": True}, {"access_line": False},
                       {"rule_id": "I1.context"}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                replace(policy(), **change)
        for objects in ((), ("",), "cpu", (None,)):
            with self.subTest(objects=objects), self.assertRaises((ValueError, TypeError)):
                Predicate("valid(cpu)", objects)
        for param in ({"max_depth": -1}, {"max_depth": 129}, {"max_work": 0}, {"max_work": True}):
            with self.subTest(param=param), self.assertRaises(ValueError):
                run(graph(), **param)

    def test_duplicate_policies_and_conflicting_entry_facts_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            run(graph(), [policy(), policy()])
        with self.assertRaisesRegex(ValueError, "entry facts"):
            run(graph(), entry_facts=[EntryFact(CPU, Truth.TRUE, REF, "root"),
                                     EntryFact(CPU, Truth.FALSE, REF, "root")])

    def test_duplicate_models_or_guard_annotations_are_rejected(self):
        g = graph([guard_event()])
        for change in ({"functions": [FunctionModel("root", REF)] * 2},
                       {"guards": [semantics()] * 2}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "duplicate"):
                model_for(g, **change)

    def test_invalid_source_and_guard_polarity_are_rejected(self):
        with self.assertRaises(ValueError):
            Source("v7.1", "short")
        with self.assertRaises(ValueError):
            semantics(condition_true_means=Truth.UNKNOWN)
        with self.assertRaises(TypeError):
            semantics(branch_when=True)
        with self.assertRaises(ValueError):
            SourceReference("a.c", "fn", 10, 2)

    def test_public_domains_reject_truthiness(self):
        for value in (*Truth, *Assessment, *BranchWhen):
            with self.subTest(value=value), self.assertRaises(TypeError):
                bool(value)

    def test_inputs_and_states_are_not_mutated(self):
        g = graph([guard_event(), write()])
        original = copy.deepcopy(g)
        p = policy()
        run(g, [p], [semantics()])
        self.assertEqual(original, g)
        with self.assertRaises(FrozenInstanceError):
            p.field = "rq.other"

    def test_output_is_deterministic_under_node_and_policy_order_changes(self):
        g = graph([guard_event(), call()], {"helper": node([write()])}, ["helper"])
        policies = [policy(function="helper"), policy(function="helper", predicate=AFFINITY)]
        first = run(g, policies, [semantics()])
        g["nodes"] = dict(reversed(list(g["nodes"].items())))
        second = run(g, list(reversed(policies)), [semantics()])
        self.assertEqual(json.dumps(first.to_dict(), sort_keys=True), json.dumps(second.to_dict(), sort_keys=True))

    def test_unordered_metadata_permutation_preserves_output(self):
        g = graph([write()], {"a": node(), "b": node()}, ["a", "b"])
        first = run(g).to_dict()
        g["nodes"]["root"]["callees"].reverse()
        second = run(g).to_dict()
        # The input fingerprint intentionally records even unordered metadata.
        first.pop("graph_digest")
        second.pop("graph_digest")
        self.assertEqual(first, second)

    def test_findings_adapter_is_schema_valid_and_cannot_claim_holds_or_violation(self):
        for g, guards, entries in (
            (graph([guard_event(), write()]), [semantics()], []),
            (graph([write()]), [], [EntryFact(CPU, Truth.FALSE, REF, "root")]),
            (graph([write()]), [], []),
            (graph([guard_event(), write()]), [], []),
        ):
            with self.subTest(g=g):
                result = run(g, guards=guards, entry_facts=entries)
                findings = result.to_findings()
                runner.validate("findings", {"kernel_version": SOURCE.version, "findings": findings})
                self.assertTrue(findings)
                self.assertTrue(all(f["verdict"] == "unknown" for f in findings))
                json.dumps(result.to_dict(), allow_nan=False)

    def test_gap_adapter_validates_against_real_shared_schema(self):
        g = graph([call("missing")], callees=["missing"])
        result = run(g, [])
        runner.validate("findings", {"kernel_version": SOURCE.version, "findings": result.to_findings()})
        self.assertTrue(result.gaps)
        self.assertEqual(result.graph_digest, result.to_findings()[0]["evidence"][0]["graph_digest"])

    def test_import_and_analysis_do_not_register_a_production_checker(self):
        before = registered()
        run(graph([write()]))
        self.assertEqual(before, registered())

    def test_synthetic_demo_covers_all_four_outcomes_deterministically(self):
        from checker.guards_demo import demo

        value = demo()
        self.assertEqual({
            "demo_established": ("true", "established"),
            "demo_false": ("false", "false"),
            "demo_missing": ("unknown", "missing_check"),
            "demo_unknown": ("unknown", "unknown"),
        }, {a["root"]: (a["observed"], a["assessment"]) for a in value["assessments"]})
        self.assertIs(value["synthetic"], True)
        self.assertIs(value["kernel_safety_claim"], False)
        self.assertEqual(value, demo())

    def test_real_fixture_stays_unknown_and_c1_still_has_no_semantic_plugins(self):
        g = runner.load_data(runner.ROOT / "contracts/fixtures/callgraph.example.json")
        catalog = runner.load_data(runner.ROOT / "contracts/fixtures/catalog.example.yaml")
        self.assertEqual([], runner.check(g, catalog))
        p = GuardPolicy("I3.illustrative", "scx_bpf_kick_cpu", "scx_bpf_kick_cpu", "rq.scx.flags",
                        CPU, Source(g["kernel_version"], "0" * 40), REF)
        result = analyze(g, [p])
        self.assertTrue(result.accesses)
        self.assertTrue(all(a.assessment is Assessment.UNKNOWN for a in result.accesses))


class MissingObligationTests(unittest.TestCase):
    def test_policy_function_typo_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "policy function"):
            run(graph(), [policy(function="roott")])

    def test_unreachable_existing_function_gets_one_explicit_unknown(self):
        g = graph(nodes={"helper": node([write(line=9)])})
        p = policy(function="helper", access_line=9, access_object="rq:helper")
        result = run(g, [p])
        self.assertEqual(1, len(result.accesses))
        row = result.accesses[0]
        self.assertEqual(("helper", FIELD, 9, "rq:helper"), (row.function, row.field, row.line, row.access_object))
        self.assertEqual(("root",), row.path)  # No invented root -> helper call.
        self.assertIsNone(row.event_index)
        self.assertIs(row.assessment, Assessment.UNKNOWN)
        self.assertEqual("unassessed_obligation", row.proof_basis)
        self.assertTrue(result.to_findings())

    def test_indirect_helper_policy_cannot_disappear(self):
        g = graph([call()], {"helper": node([write()])}, [{"target": "helper", "kind": "indirect"}])
        result = run(g, [policy(function="helper")])
        self.assertEqual(1, len(result.accesses))
        self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
        self.assertIsNone(result.accesses[0].event_index)
        self.assertTrue(any("not reached or assessed" in gap.reason for gap in result.gaps))

    def test_descendant_policy_survives_a_depth_or_work_cut_in_ancestor(self):
        g = graph([call("a")], {"a": node([call("helper")], ["helper"]), "helper": node([write()])}, ["a"])
        for limits in ({"max_work": 1}, {"max_depth": 0}):
            with self.subTest(limits=limits):
                result = run(g, [policy(function="helper")], **limits)
                self.assertEqual(1, len(result.accesses))
                self.assertIs(result.accesses[0].assessment, Assessment.UNKNOWN)
                self.assertEqual(("root",), result.accesses[0].path)

    def test_unassessed_rows_are_per_predicate_root_site_and_object(self):
        g = graph(nodes={"helper": node()})
        policies = [policy(function="helper", predicate=CPU, access_line=5, access_object="rq:a"),
                    policy(function="helper", predicate=OTHER_CPU, access_line=6, access_object="rq:b"),
                    policy(function="helper", predicate=AFFINITY, access_kind="atomic", access_line=7,
                           access_object="rq:a")]
        result = run(g, policies)
        self.assertEqual(3, len(result.accesses))
        self.assertEqual({(p.predicate, p.access_line, p.access_object, p.access_kind) for p in policies},
                         {(a.predicate, a.line, a.access_object, a.access_kind) for a in result.accesses})
        self.assertTrue(all(a.assessment is Assessment.UNKNOWN and a.event_index is None for a in result.accesses))
        runner.validate("findings", {"kernel_version": SOURCE.version, "findings": result.to_findings()})

    def test_covered_policy_does_not_gain_a_duplicate_unassessed_row(self):
        result = run(graph([guard_event(), write()]), guards=[semantics()])
        self.assertEqual(1, len(result.accesses))
        self.assertEqual(1, result.accesses[0].event_index)

    def test_budget_cut_retains_intended_site_and_object_in_findings(self):
        p = policy(access_line=9, access_object="rq:argument-1", access_kind="atomic")
        result = run(graph([{"kind": "atomic", "field": FIELD, "line": 9}]), [p], max_work=1)
        row = result.accesses[0]
        self.assertIs(row.assessment, Assessment.UNKNOWN)
        self.assertIsNone(row.event_index)
        self.assertEqual((9, "rq:argument-1", "atomic"), (row.line, row.access_object, row.access_kind))
        evidence = result.to_findings()[0]["evidence"][-1]
        self.assertEqual(("synthetic.c", 9, None), (evidence["file"], evidence["line"], evidence["event_index"]))


class DominanceTests(unittest.TestCase):
    def case(self, middle=None):
        middle = {"kind": "error", "line": 3} if middle is None else middle
        events = [guard_event(line=1), guard_event("choose_side", "continue", line=2),
                  middle, write("rq.other_state", line=4), write(line=5)]
        others, callees = {}, []
        if middle["kind"] == "call":
            others["opaque"] = node(kind="boundary")
            callees = [{"target": "opaque", "kind": "direct", "line": 3}]
        g = graph(events, others, callees)
        p = policy(access_line=5, access_object="rq:argument-0")
        edges = (ControlEdge(0, None, Truth.TRUE), ControlEdge(0, 1, Truth.FALSE),
                 ControlEdge(1, 2, Truth.TRUE), ControlEdge(1, 4, Truth.FALSE),
                 ControlEdge(2, 3), ControlEdge(3, 4), ControlEdge(4, None))
        preserves = tuple(PredicatePreservation(i, REF, "synthetic operation preserves CPU and fixed rq identity")
                          for i in (1, 2, 3))
        proof = DominanceEvidence(p, graph_digest(g), 0, 4, edges, preserves,
                                  ((CPU.objects[0], "cpu"), (p.access_object, "rq")), REF, (REF,),
                                  "explicit synthetic CFG; returning invalid guard, two source branches, stable value")
        functions = tuple(FunctionModel(f, replace(REF, symbol=f), True, f != "root") for f in sorted(g["nodes"]))
        m = model_for(g, [semantics()], functions=functions, dominance=(proof,))
        return g, p, m

    def assessment(self, g, p, m, **kwargs):
        return analyze(g, (p,), model=m, **kwargs).accesses[0]

    def test_branched_cfg_positive_against_independent_concrete_paths(self):
        seen = []
        for valid in (False, True):
            for choose_side in (False, True):
                if not valid:
                    continue  # Real early-return semantics of the synthetic reference program.
                if choose_side:
                    other_state = 1  # Diagnostic and unrelated write do not change the tested CPU value.
                    self.assertEqual(1, other_state)
                seen.append(valid)
        self.assertEqual([True, True], seen)
        g, p, m = self.case()
        self.assertFalse(next(f for f in m.functions if f.function == "root").linear_except_guards)
        row = self.assessment(g, p, m)
        self.assertIs(row.assessment, Assessment.ESTABLISHED)
        self.assertEqual("reviewed_source_cfg", row.proof_basis)

    def test_source_order_without_cfg_does_not_establish_dominance(self):
        g, p, m = self.case()
        self.assertIs(self.assessment(g, p, replace(m, dominance=())).assessment, Assessment.UNKNOWN)

    def test_guard_failure_reaching_access_prevents_a_positive(self):
        g, p, m = self.case()
        d = m.dominance[0]
        edges = tuple(replace(e, target=4) if e.origin == 0 and e.outcome is Truth.TRUE else e for e in d.edges)
        row = self.assessment(g, p, replace(m, dominance=(replace(d, edges=edges),)))
        self.assertIs(row.assessment, Assessment.UNKNOWN)

    def test_a_path_bypassing_the_guard_prevents_a_positive(self):
        g, p, m = self.case()
        d = m.dominance[0]
        g["nodes"]["root"]["events"].insert(0, guard_event("bypass", "continue", line=1))
        edges = tuple(ControlEdge(e.origin + 1, None if e.target is None else e.target + 1, e.outcome)
                      for e in d.edges) + (ControlEdge(0, 5, Truth.TRUE), ControlEdge(0, 1, Truth.FALSE))
        proof = replace(d, graph_digest=graph_digest(g), guard_index=1, access_index=5, edges=edges,
                        preserves=tuple(replace(v, event_index=v.event_index + 1) for v in d.preserves))
        m = replace(m, graph_digest=graph_digest(g), guards=(semantics(index=1),), dominance=(proof,))
        self.assertIs(self.assessment(g, p, m).assessment, Assessment.UNKNOWN)

    def test_wrong_polarity_does_not_become_a_dominance_proof(self):
        g, p, m = self.case()
        self.assertIs(self.assessment(g, p, replace(m, guards=(semantics(condition_true_means=Truth.TRUE),))).assessment,
                      Assessment.UNKNOWN)

    def test_guard_then_branch_without_function_exit_is_supported_locally(self):
        g, p, m = self.case()
        # if (valid) { ... write(); } after(); -- neither guard edge returns.
        events = g["nodes"]["root"]["events"]
        events[0] = guard_event(CPU.expression, "continue", line=1)
        events.append({"kind": "warn", "line": 6})
        d = m.dominance[0]
        edges = tuple(e for e in d.edges if e.origin not in (0, 4)) + (
            ControlEdge(0, 1, Truth.TRUE), ControlEdge(0, 5, Truth.FALSE),
            ControlEdge(4, 5), ControlEdge(5, None))
        proof = replace(d, graph_digest=graph_digest(g), edges=edges)
        annotation = semantics(condition=CPU.expression, action="continue",
                               condition_true_means=Truth.TRUE, exits_function=False)
        m = replace(m, graph_digest=graph_digest(g), guards=(annotation,), dominance=(proof,))
        self.assertIs(self.assessment(g, p, m).assessment, Assessment.ESTABLISHED)

    def test_unknown_effect_on_one_reaching_branch_invalidates_the_proof(self):
        g, p, m = self.case()
        d = m.dominance[0]
        for missing in (1, 2, 3):
            with self.subTest(event=missing):
                proof = replace(d, preserves=tuple(v for v in d.preserves if v.event_index != missing))
                self.assertIs(self.assessment(g, p, replace(m, dominance=(proof,))).assessment, Assessment.UNKNOWN)

    def test_opaque_call_needs_specific_preservation_evidence(self):
        g, p, m = self.case(call("opaque", line=3))
        self.assertIs(self.assessment(g, p, m).assessment, Assessment.ESTABLISHED)
        d = m.dominance[0]
        proof = replace(d, preserves=tuple(v for v in d.preserves if v.event_index != 2))
        self.assertIs(self.assessment(g, p, replace(m, dominance=(proof,))).assessment, Assessment.UNKNOWN)

    def test_indirect_or_missing_call_cannot_be_certified_by_a_preservation_label(self):
        for missing in (False, True):
            g, p, m = self.case(call("opaque", line=3))
            if missing:
                del g["nodes"]["opaque"]
            else:
                g["nodes"]["root"]["callees"][0]["kind"] = "indirect"
            proof = replace(m.dominance[0], graph_digest=graph_digest(g))
            m = replace(m, graph_digest=graph_digest(g), dominance=(proof,),
                        functions=tuple(f for f in m.functions if f.function in g["nodes"]))
            self.assertIs(self.assessment(g, p, m).assessment, Assessment.UNKNOWN)

    def test_cycle_in_the_reviewed_cfg_is_unknown(self):
        g, p, m = self.case()
        d = m.dominance[0]
        edges = tuple(replace(e, target=1) if e.origin == 3 else e for e in d.edges)
        self.assertIs(self.assessment(g, p, replace(m, dominance=(replace(d, edges=edges),))).assessment,
                      Assessment.UNKNOWN)

    def test_missing_branch_or_continuation_is_unknown(self):
        g, p, m = self.case()
        d = m.dominance[0]
        for origin in (0, 1, 2):
            with self.subTest(origin=origin):
                proof = replace(d, edges=tuple(e for e in d.edges if e.origin != origin))
                self.assertIs(self.assessment(g, p, replace(m, dominance=(proof,))).assessment, Assessment.UNKNOWN)

    def test_known_source_lines_do_not_override_unsequenced_metadata(self):
        g, p, m = self.case()
        g["nodes"]["root"]["writes"] = ["rq.unsequenced"]
        proof = replace(m.dominance[0], graph_digest=graph_digest(g))
        m = replace(m, graph_digest=graph_digest(g), dominance=(proof,))
        self.assertIs(self.assessment(g, p, m).assessment, Assessment.UNKNOWN)

    def test_missing_bindings_or_completeness_remains_unknown(self):
        g, p, m = self.case()
        for changed in (replace(m, bindings_verified=False),
                        replace(m, functions=(FunctionModel("root", REF, False, False),))):
            self.assertIs(self.assessment(g, p, changed).assessment, Assessment.UNKNOWN)

    def test_no_fake_config_digest_is_needed_for_a_reviewed_source_relation(self):
        g, p, m = self.case()
        g["illustrative"] = False
        d = replace(m.dominance[0], graph_digest=graph_digest(g))
        m = replace(m, graph_digest=graph_digest(g), synthetic=False, dominance=(d,))
        self.assertIs(self.assessment(g, p, m).assessment, Assessment.UNKNOWN)
        m = replace(m, dominance=(replace(d, configuration_independent=True),))
        self.assertIsNone(m.config_digest)
        self.assertIs(self.assessment(g, p, m).assessment, Assessment.ESTABLISHED)

    def test_illustrative_graph_cannot_be_promoted_by_a_real_source_proof(self):
        g, p, m = self.case()
        m = replace(m, synthetic=False, dominance=(replace(m.dominance[0], configuration_independent=True),))
        self.assertIs(self.assessment(g, p, m).assessment, Assessment.UNKNOWN)

    def test_graph_digest_cannot_be_refreshed_without_rebinding_the_proof(self):
        g, p, m = self.case()
        g["nodes"]["root"]["events"][2]["msg"] = "different operation"
        with self.assertRaisesRegex(ValueError, "dominance graph fingerprint"):
            self.assessment(g, p, replace(m, graph_digest=graph_digest(g)))

    def test_wrong_policy_object_and_guard_predicate_are_rejected(self):
        g, p, m = self.case()
        with self.assertRaisesRegex(ValueError, "configured policy"):
            self.assessment(g, replace(p, access_object="rq:other"), m)
        with self.assertRaisesRegex(ValueError, "predicate/objects"):
            self.assessment(g, p, replace(m, guards=(semantics(predicate=OTHER_CPU),)))
        with self.assertRaisesRegex(ValueError, "every exact"):
            replace(m.dominance[0], object_bindings=((CPU.objects[0], "cpu"),))

    def test_exact_access_kind_site_and_source_are_required(self):
        g, p, m = self.case()
        d = m.dominance[0]
        for change in ({"access_index": 3}, {"access_index": 100},
                       {"reference": replace(REF, file="wrong.c")}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.assessment(g, p, replace(m, dominance=(replace(d, **change),)))
        with self.assertRaises(ValueError):
            replace(d, policy=replace(p, access_line=None))

    def test_proof_source_version_and_commit_mismatch_fail_loudly(self):
        g, p, m = self.case()
        for source in (Source("different", SOURCE.commit), Source(SOURCE.version, "1" * 40)):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "mismatch"):
                self.assessment(g, p, replace(m, source=source))

    def test_early_budget_cuts_cannot_complete_a_partial_dominance_proof(self):
        g, p, m = self.case()
        for budget in range(1, 16):
            with self.subTest(budget=budget):
                result = analyze(g, (p,), model=m, max_work=budget)
                self.assertLessEqual(result.work_used, budget)
                self.assertTrue(result.accesses)
                self.assertTrue(all(a.assessment is Assessment.UNKNOWN for a in result.accesses))

    def test_dominance_does_not_discharge_a_different_required_predicate(self):
        g, p, m = self.case()
        other = replace(p, predicate=AFFINITY)
        result = analyze(g, (p, other), model=m)
        self.assertEqual({CPU: Assessment.ESTABLISHED, AFFINITY: Assessment.UNKNOWN},
                         {a.predicate: a.assessment for a in result.accesses})

    def test_local_dominance_does_not_export_predicate_to_caller(self):
        g, p, m = self.case()
        g["roots"] = ["outer"]
        g["nodes"]["outer"] = node([call("root"), write(line=8)], ["root"], kind="kfunc")
        p = replace(p, root="outer")
        caller = policy(root="outer", function="outer", access_line=8, access_object="rq:caller")
        proof = replace(m.dominance[0], policy=p, graph_digest=graph_digest(g))
        m = replace(m, graph_digest=graph_digest(g), dominance=(proof,),
                    functions=(*m.functions, FunctionModel("outer", replace(REF, symbol="outer"), True, True)))
        result = analyze(g, (p, caller), model=m)
        self.assertEqual({"root": Assessment.ESTABLISHED, "outer": Assessment.UNKNOWN},
                         {a.function: a.assessment for a in result.accesses})

    def test_proof_data_is_immutable_typed_and_serialized_deterministically(self):
        g, p, m = self.case()
        d = m.dominance[0]
        first = analyze(g, (p,), model=m)
        changed = replace(d, edges=tuple(reversed(d.edges)), preserves=tuple(reversed(d.preserves)))
        second = analyze(g, (p,), model=replace(m, dominance=(changed,)))
        self.assertEqual(first.to_dict(), second.to_dict())
        with self.assertRaises(FrozenInstanceError):
            d.access_index = 1
        with self.assertRaises(TypeError):
            ControlEdge(0, 1, True)
        with self.assertRaises(ValueError):
            replace(d, edges=(*d.edges, d.edges[0]))
        with self.assertRaises(ValueError):
            replace(m, dominance=(d, d))
        findings = first.to_findings()
        self.assertTrue(all(f["verdict"] == "unknown" for f in findings))
        self.assertTrue(any("dominance_evidence" in e for f in findings for e in f["evidence"]))


class SourceDominanceTests(unittest.TestCase):
    def test_real_kick_write_is_established_without_false_linearity_attestations(self):
        from checker.guards_demo import kick_cpu_inputs

        g, policies, m = kick_cpu_inputs()
        result = analyze(g, policies, model=m)
        self.assertTrue(all(not f.linear_except_guards for f in m.functions))
        self.assertIsNone(m.config_digest)
        self.assertFalse(m.synthetic)
        self.assertEqual("8cd9520d35a6c38db6567e97dd93b1f11f185dc6", m.source.commit)
        row = result.accesses[0]
        self.assertEqual(("scx_kick_cpu", 8921, "rq.scx.cpus_to_kick", "atomic", "rq:calling_cpu"),
                         (row.function, row.line, row.field, row.access_kind, row.access_object))
        self.assertEqual(("scx_bpf_kick_cpu", "scx_kick_cpu"), row.path)
        self.assertIs(row.assessment, Assessment.ESTABLISHED)
        self.assertTrue(result.gaps)  # The local theorem is not complete root/callee coverage.
        self.assertTrue(all(f["verdict"] == "unknown" for f in result.to_findings()))

    def test_pinned_source_guard_relationship_against_concrete_flag_cases(self):
        # Independent reference program for the relevant C control, rather
        # than traversing the supplied proof edges to generate expectations.
        writes = []
        for valid in (False, True):
            for bypass in (False, True):
                for idle in (False, True):
                    for trylock in (False, True):
                        for skip in (False, True):
                            if not valid or bypass:
                                continue
                            if idle:
                                if trylock and skip:
                                    continue
                                writes.append((8919, valid))
                            else:
                                writes.append((8921, valid))
        self.assertEqual({8919, 8921}, {line for line, _ in writes})
        self.assertEqual({True}, {valid for _, valid in writes})
        from checker.guards_demo import kick_cpu_inputs

        _, _, m = kick_cpu_inputs()
        edges = {(e.origin, e.target, e.outcome) for e in m.dominance[0].edges}
        self.assertIn((1, None, Truth.TRUE), edges)  # Actual invalid-CPU return.
        self.assertIn((9, 10, Truth.UNKNOWN), edges)  # scx_error does NOT terminate.
        self.assertIn((5, 23, Truth.TRUE), edges)  # Bypass goes through IRQ restore.
        self.assertIn((14, 23, Truth.UNKNOWN), edges)  # Idle-skip releases rq before restore.

    def test_real_example_without_dominance_or_stability_remains_unknown(self):
        from checker.guards_demo import kick_cpu_inputs

        g, policies, m = kick_cpu_inputs()
        for model in (replace(m, dominance=()), replace(m, bindings_verified=False),
                      replace(m, dominance=(replace(m.dominance[0], preserves=()),))):
            with self.subTest(model=model):
                result = analyze(g, policies, model=model)
                self.assertTrue(all(a.assessment is Assessment.UNKNOWN for a in result.accesses))

    def test_real_example_cutoffs_report_the_configured_obligation(self):
        from checker.guards_demo import kick_cpu_inputs

        g, policies, m = kick_cpu_inputs()
        for limits in ({"max_work": 1}, {"max_work": 100}, {"max_depth": 0}, {"max_depth": 1}):
            result = analyze(g, policies, model=m, **limits)
            self.assertTrue(result.accesses)
            self.assertTrue(all(a.assessment is Assessment.UNKNOWN for a in result.accesses))
            self.assertTrue(all(a.rule_id == "I3.cpu_arg.kick_cpu" for a in result.accesses))

    def test_source_demo_is_deterministic_and_retains_unknown_coverage(self):
        from checker.guards_demo import source_demo

        first = source_demo()
        self.assertEqual(first, source_demo())
        self.assertTrue(first["hand_provided_evidence"])
        self.assertFalse(first["kernel_safety_claim"])
        self.assertEqual("established", first["assessments"][0]["assessment"])
        self.assertTrue(first["gaps"])


if __name__ == "__main__":
    unittest.main()
