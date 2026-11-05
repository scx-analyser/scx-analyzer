# Epic C - invariant checkers

Owner: Person C · Contract: `contracts/findings.schema.json`

Input: `callgraph.json` (Epic B) + `catalog/invariants/*.yaml` (Epic A).
Output: `findings.json` - per kfunc x invariant: `holds | violated | unknown`, enforcement mechanisms, static vs runtime, evidence.

Planned layout:

```
checker/
  context.py          C2  ops callback -> entry locks + SCX_KF_* mask
  lockset.py          C3  interprocedural lockset over B's ordered events
  checkers/
    i1_context.py     C3  I1
    i2_state.py       C5  I2 (ops_state transitions, DSQ membership, deferred dispatch)
    i3_guards.py      C4  I3 (guard/predicate dominance before state writes)
  classify.py         C6  static / runtime / none
  cli.py              C1  scxa check --callgraph X --catalog catalog/ -o findings.json
```

Develop against `contracts/fixtures/callgraph.example.json` from day 1; switch to B's real output when B3 lands.
