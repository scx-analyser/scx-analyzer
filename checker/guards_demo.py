"""Synthetic and hand-reviewed source guard models; no production plugin."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .guards import (
    BranchWhen, ControlEdge, DominanceEvidence, FunctionModel, GuardPolicy, GuardSemantics,
    Model, Predicate, PredicatePreservation, Source, SourceReference, Truth, analyze, graph_digest,
)


def demo() -> dict:
    source = Source("synthetic-c4-demo", "0" * 40)
    predicate = Predicate("ops_cpu_valid(cpu)", ("synthetic:cpu-argument",))
    nodes = {}
    functions = []
    policies = []
    guards = []
    for name in ("established", "false", "missing", "unknown"):
        function = "demo_" + name
        reference = SourceReference("synthetic.c", function, 1, 10)
        events = []
        if name != "missing":
            condition = "ops_cpu_valid(cpu)" if name == "false" else "!ops_cpu_valid(cpu)"
            events.append({"kind": "guard", "cond": condition, "action": "return", "line": 2})
            if name != "unknown":
                guards.append(GuardSemantics(function, 0, predicate, condition, "return",
                    Truth.TRUE if name == "false" else Truth.FALSE,
                    BranchWhen.CONDITION_TRUE, True, reference))
        events.append({"kind": "write", "field": "rq.synthetic_state", "line": 4})
        nodes[function] = {"kind": "kfunc", "file": "synthetic.c", "events": events, "callees": []}
        functions.append(FunctionModel(function, reference, True, True))
        policies.append(GuardPolicy("I3.synthetic", function, function, "rq.synthetic_state",
                                    predicate, source, reference))
    graph = {"kernel_version": source.version, "generator": "C4 synthetic demo", "illustrative": True,
             "roots": sorted(nodes), "nodes": nodes}
    model = Model(source, graph_digest(graph), tuple(functions), tuple(guards),
                  bindings_verified=True, synthetic=True)
    result = analyze(graph, tuple(policies), model=model)
    return {"synthetic": True, "kernel_safety_claim": False,
            "assessments": [{"root": a.root, "observed": a.observed.value,
                             "assessment": a.assessment.value} for a in result.accesses]}


def kick_cpu_inputs() -> tuple[dict, tuple[GuardPolicy, ...], Model]:
    """Reviewed predicate-relevant source projection, with opaque callees explicit.

    Every source branch in scx_kick_cpu is represented. The wrapper and helper
    remain NONLINEAR; this is not an extracted/complete Linux callgraph or build.
    CPU bounds stability and parameter/current-rq bindings are hand-reviewed
    normal-runtime model inputs, never inferred from an arg-name prefix.
    """
    source = Source("v7.1", "8cd9520d35a6c38db6567e97dd93b1f11f185dc6")
    root, function = "scx_bpf_kick_cpu", "scx_kick_cpu"
    file = "kernel/sched/ext.c"
    reference = SourceReference(file, function, 8881, 8932)
    wrapper = SourceReference(file, root, 8945, 8953)
    predicate = Predicate("ops_cpu_valid(sch, cpu, NULL)",
                          ("arg:scx_bpf_kick_cpu.cpu", "kernel:nr_cpu_ids", "kernel:cpu_possible_mask"))

    def call(target, line, **kwargs):
        return {"kind": "call", "target": target, "line": line, **kwargs}

    def branch(condition, action, line):
        return {"kind": "guard", "cond": condition, "action": action, "line": line}

    def mask(field, line):
        return {"kind": "atomic", "field": "rq.scx." + field, "op": "set_bit", "line": line}

    events = [
        call("ops_cpu_valid", 8886),                                                   # 0
        branch("!ops_cpu_valid(sch, cpu, NULL)", "return", 8886),                      # 1
        call("local_irq_save", 8889), call("this_rq", 8891),                           # 2, 3
        call("scx_bypassing", 8898), branch("scx_bypassing(sch, cpu_of(this_rq))", "fallback", 8898),  # 4, 5
        branch("flags & SCX_KICK_IDLE", "continue", 8906),                             # 6
        call("cpu_rq", 8907),                                                         # 7
        branch("flags & (SCX_KICK_PREEMPT | SCX_KICK_WAIT)", "error", 8909),             # 8
        {"kind": "error", "msg": "PREEMPT/WAIT cannot be used with SCX_KICK_IDLE", "line": 8910},  # 9
        call("raw_spin_rq_trylock", 8912), branch("raw_spin_rq_trylock(target_rq)", "continue", 8912),  # 10, 11
        call("can_skip_idle_kick", 8913), branch("can_skip_idle_kick(target_rq)", "fallback", 8913),  # 12, 13
        call("raw_spin_rq_unlock", 8914), call("raw_spin_rq_unlock", 8917),              # 14, 15
        mask("cpus_to_kick_if_idle", 8919), mask("cpus_to_kick", 8921),                 # 16, 17
        branch("flags & SCX_KICK_PREEMPT", "continue", 8923), mask("cpus_to_preempt", 8924),  # 18, 19
        branch("flags & SCX_KICK_WAIT", "continue", 8925), mask("cpus_to_wait", 8926),   # 20, 21
        call("irq_work_queue", 8929), call("local_irq_restore", 8931),                  # 22, 23
    ]
    wrapper_events = [
        {"kind": "lock", "lock": "rcu_read", "line": 8949}, call("scx_prog_sched", 8950),
        branch("sch", "continue", 8951), call(function, 8952, cond="sch"),
        {"kind": "unlock", "lock": "rcu_read", "line": 8953},
    ]

    def body(items, kind):
        return {"kind": kind, "file": file, "events": items,
                "callees": [{"target": e["target"], "kind": "direct", "line": e["line"]}
                            for e in items if e["kind"] == "call"]}

    nodes = {root: body(wrapper_events, "kfunc"), function: body(events, "internal")}
    for node in tuple(nodes.values()):
        for edge in node["callees"]:
            if edge["target"] not in nodes:
                nodes[edge["target"]] = {"kind": "boundary", "callees": []}
    nodes["ops_cpu_valid"]["file"] = file  # Definition known; return/effect analysis remains a boundary.
    graph = {"kernel_version": source.version, "generator": "hand-reviewed-v7.1-kick-source-projection",
             "roots": [root], "nodes": nodes}
    policy = GuardPolicy("I3.cpu_arg.kick_cpu", root, function, "rq.scx.cpus_to_kick", predicate, source,
                         SourceReference(file, function, 8886, 8921), access_kind="atomic", access_line=8921,
                         access_object="rq:calling_cpu")
    guard = GuardSemantics(function, 1, predicate, events[1]["cond"], "return", Truth.FALSE,
                           BranchWhen.CONDITION_TRUE, True, SourceReference(file, function, 8886, 8887))
    edges = [ControlEdge(0, 1), ControlEdge(1, None, Truth.TRUE), ControlEdge(1, 2, Truth.FALSE),
             ControlEdge(2, 3), ControlEdge(3, 4), ControlEdge(4, 5),
             ControlEdge(5, 23, Truth.TRUE), ControlEdge(5, 6, Truth.FALSE),
             ControlEdge(6, 7, Truth.TRUE), ControlEdge(6, 17, Truth.FALSE),
             ControlEdge(7, 8), ControlEdge(8, 9, Truth.TRUE), ControlEdge(8, 10, Truth.FALSE),
             ControlEdge(9, 10), ControlEdge(10, 11),
             ControlEdge(11, 12, Truth.TRUE), ControlEdge(11, 16, Truth.FALSE),
             ControlEdge(12, 13), ControlEdge(13, 14, Truth.TRUE), ControlEdge(13, 15, Truth.FALSE),
             ControlEdge(14, 23), ControlEdge(15, 16), ControlEdge(16, 22),
             ControlEdge(17, 18), ControlEdge(18, 19, Truth.TRUE), ControlEdge(18, 20, Truth.FALSE),
             ControlEdge(19, 20), ControlEdge(20, 21, Truth.TRUE), ControlEdge(20, 22, Truth.FALSE),
             ControlEdge(21, 22), ControlEdge(22, 23), ControlEdge(23, None)]
    stability = (
        wrapper, reference, SourceReference(file, "__cpu_valid", 1083, 1086),
        SourceReference(file, "ops_cpu_valid", 1098, 1105),
        SourceReference("include/linux/cpumask.h", "cpu_possible_mask", 92, 97),
        SourceReference("kernel/smp.c", "setup_nr_cpu_ids", 992, 1002),
        SourceReference("include/linux/cpumask.h", "cpumask_set_cpu", 595, 603),
    )
    preserves = tuple(PredicatePreservation(i, SourceReference(file, function, events[i]["line"], events[i]["line"]),
        "Target cpu is passed by value and not reassigned/exposed by address; normal-runtime CPU bounds are stable. "
        "The calling-rq binding is fixed between IRQ save/restore. This is a reviewed model assumption.")
        for i in (2, 3, 4, 5, 6))
    bindings = (("arg:scx_bpf_kick_cpu.cpu", "cpu"), ("kernel:nr_cpu_ids", "nr_cpu_ids"),
                ("kernel:cpu_possible_mask", "cpu_possible_mask"), ("rq:calling_cpu", "this_rq"))
    proof = DominanceEvidence(policy, graph_digest(graph), 1, 17, tuple(edges), preserves, bindings, reference, stability,
        "A failed CPU-validity check at 8886 returns at 8887 before every mask write; bypass/idle-skip go to IRQ restore. "
        "The non-idle 8921 write is reached only by the validated branch. Both flag branches are explicit, "
        "and no access from the idle branch is mistaken for the normal mask. Source relation is independent "
        "of a selected build; boot-bound stability and exact argument/current-rq identities remain reviewed inputs.",
        configuration_independent=True)
    model = Model(source, graph_digest(graph),
                  (FunctionModel(root, wrapper, True, False), FunctionModel(function, reference, True, False)),
                  (guard,), bindings_verified=True, synthetic=False, dominance=(proof,))
    return graph, (policy,), model


def source_demo() -> dict:
    graph, policies, model = kick_cpu_inputs()
    result = analyze(graph, policies, model=model)
    return {"source_version": model.source.version, "source_commit": model.source.commit,
            "hand_provided_evidence": True, "kernel_safety_claim": False, "config_digest": model.config_digest,
            "scope": "one reviewed source guard/access relationship; opaque callees and full-root coverage remain unknown",
            "object_bindings": dict(model.dominance[0].object_bindings),
            "assessments": [{"path": a.path, "function": a.function, "line": a.line, "field": a.field,
                             "access_kind": a.access_kind, "access_object": a.access_object,
                             "observed": a.observed.value, "assessment": a.assessment.value,
                             "proof_basis": a.proof_basis} for a in result.accesses],
            "work_used": result.work_used, "gaps": [asdict(gap) for gap in result.gaps]}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-example", action="store_true", help="reviewed v7.1 kick-CPU source-CFG example")
    args = parser.parse_args(argv)
    print(json.dumps(source_demo() if args.source_example else demo(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
