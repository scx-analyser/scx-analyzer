"""Standalone synthetic demonstration; no Linux policy or execution trace."""
import argparse

from .lock_policy import LockIdentity, ProtectionPolicy, ProtectionRule
from .lockset import Provenance, analyze


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = demo()
    if args.json:
        print(result.to_json(), end="")
    else:
        print("SYNTHETIC MODEL ONLY: no kernel safety verdicts")
        for access in result.accesses:
            print(f"line {access.site.line}: {access.field}, {access.required_lock.name}: "
                  f"{access.observed.value} -> {access.assessment.value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
