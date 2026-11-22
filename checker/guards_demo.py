"""Standalone synthetic C4 demonstration. No Linux policy or plugin is installed."""
from __future__ import annotations

import json

from .guards import (
    BranchWhen, FunctionModel, GuardPolicy, GuardSemantics, Model, Predicate,
    Source, SourceReference, Truth, analyze, graph_digest,
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


def main() -> None:
    print(json.dumps(demo(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
