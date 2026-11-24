"""Standalone lockset models; no kernel execution trace or safety verdict."""
import argparse

from .context import SOURCE_COMMIT, SOURCE_VERSION, LockState, SourceReference
from .lock_policy import LockIdentity, ProtectionPolicy, ProtectionRule
from .lockset import ControlEffect, ControlSemantics, GuardBranch, Lockset, Provenance, analyze


def demo():
    # This explicit synthetic policy is deliberately separate from the analyzer
    # and from Epic A's catalog. No Linux invariant is asserted here.
    rq = LockIdentity("synthetic.rq0.lock")
    policy = ProtectionPolicy((ProtectionRule("demo", "rq.nr_running", rq),))
    graph = {
        "kernel_version": "synthetic-c3-v1", "generator": "synthetic-linear-demo",
        "roots": ["demo"], "nodes": {"demo": {
            "kind": "kfunc", "file": "synthetic_demo.c", "callees": [], "events": [
                {"kind": "lock", "lock": "rq.lock", "line": 1},
                {"kind": "write", "field": "rq.nr_running", "line": 2},
                {"kind": "unlock", "lock": "rq.lock", "line": 3},
                {"kind": "write", "field": "rq.nr_running", "line": 4},
                {"kind": "guard", "cond": "synthetic_branch", "line": 5},
                {"kind": "write", "field": "rq.nr_running", "line": 6},
            ],
        }},
    }
    return analyze(graph, policy, bindings={"demo": {"rq.lock": rq}},
                   provenance=Provenance(complete_events=True, linear_events=True, synthetic=True))


def source_example(*, entry_state=LockState.KNOWN_HELD, complete_events=True):
    """Full lock/write/control model of ext.c:1405-1419 for ONE local DSQ.

    The fixed local-DSQ object and its owning rq entry state are explicit model
    inputs. Completeness covers this helper, not a kfunc/caller graph. It has
    no acquisitions, hidden cleanup or lock-changing calls on its continuation.
    Source evidence: v7.1 1408/1410/1413-1417; local protection 2574-2576.
    """
    function = "dsq_dec_nr"
    rq = LockIdentity("local_dsq.cpu0.owning_rq.lock")
    events = [
        {"kind": "write", "field": "scx_dispatch_q.nr", "line": 1408},
        {"kind": "guard", "cond": "p->scx.flags & SCX_TASK_IMMED", "action": "return", "line": 1410},
        {"kind": "guard", "cond": "WARN_ON_ONCE(dsq->id != SCX_DSQ_LOCAL) || WARN_ON_ONCE(rq->scx.nr_immed <= 0)",
         "action": "return", "line": 1413},
        {"kind": "write", "field": "rq.scx.nr_immed", "line": 1417},
    ]
    graph = {
        "kernel_version": SOURCE_VERSION, "generator": "hand-annotated-local-dsq-helper-model",
        "roots": [function], "nodes": {function: {
            "kind": "internal", "file": "kernel/sched/ext.c", "callees": [], "events": events,
        }},
    }
    controls = (
        ControlSemantics.for_event(
            function, 1, events[1], ControlEffect.EARLY_RETURN,
            SourceReference("kernel/sched/ext.c", function, 1410, 1419),
            branch_when=GuardBranch.CONDITION_FALSE,
        ),
        ControlSemantics.for_event(
            function, 2, events[2], ControlEffect.EARLY_RETURN,
            SourceReference("kernel/sched/ext.c", function, 1413, 1415),
            branch_when=GuardBranch.CONDITION_TRUE,
        ),
    )
    policy = ProtectionPolicy(tuple(ProtectionRule(function, field, rq)
                                    for field in ("scx_dispatch_q.nr", "rq.scx.nr_immed")))
    return analyze(
        graph, policy, entry_states={function: Lockset.from_mapping({rq: entry_state})},
        control_semantics=controls,
        provenance=Provenance(SOURCE_COMMIT, complete_events=complete_events, linear_events=True, synthetic=True),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--source-example", action="store_true",
                        help="hand-annotated v7.1 dsq_dec_nr model, assuming a fixed local DSQ and its rq entry lock")
    args = parser.parse_args(argv)
    result = source_example() if args.source_example else demo()
    if args.json:
        print(result.to_json(), end="")
    else:
        print("HAND-ANNOTATED v7.1 HELPER MODEL: assumes a local DSQ and owning rq held; no kernel safety verdicts"
              if args.source_example else "SYNTHETIC MODEL ONLY: no kernel safety verdicts")
        for access in result.accesses:
            print(f"line {access.site.line}: {access.field}, {access.required_lock.name}: "
                  f"{access.observed.value} -> {access.assessment.value}")
        if args.source_example:
            print("function exit: unknown (early-return paths/cleanup joined)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
