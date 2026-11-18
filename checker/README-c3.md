# C3: conservative interprocedural locksets

`checker.lockset` tracks ownership of specific lock objects through Epic B's ordered events and assesses explicitly protected accesses. It is a static model, not a kernel execution, verifier result, or completed I1 checker. No semantic plugin is registered. C1's API/CLI, C2, the shared contracts/fixtures, and `KERNEL_VERSION` are unchanged.

## Domain, policies, and identities

`LockState` is reused from C2: `KNOWN_HELD`, `KNOWN_NOT_HELD`, `UNKNOWN`. No fact means unknown, not absent. `Lockset` is immutable, copies caller mappings, and returns new states on updates. Compare states and assessments explicitly; their boolean conversion raises `TypeError`.

`checker.lock_policy` defines `LockIdentity`, `ProtectionRule`, and `ProtectionPolicy`. Each rule names an exact function, contract field reference, access kind (`WRITE` or `ATOMIC`), and required lock object. Rules for the same function/field/access kind are conjunctive: every required lock must be held before any record for that access is labeled protected. Records retain individual lock observations; a known-absent required lock is an unprotected witness, while a held lock with another unsatisfied requirement cannot certify protection. Atomic rules do not constrain normal writes, or vice versa. These are caller-supplied internal policies; C3 does not translate the illustrative catalog's `requires.locks` into blanket field requirements.

`LockIdentity("cpu0.rq.lock")`, `LockIdentity("cpu1.rq.lock")`, `LockIdentity("p0.pi_lock")`, and `LockIdentity("dsq0.lock")` are distinct. Every event lock token needs an explicit per-function binding to an identity. Identical token spellings in different functions do not imply the same object; different tokens alias only if the caller explicitly binds them to the same object. Field rules also apply only to the specified function: a structural field name does not identify one runtime object across all functions.

Bindings attest to stable objects for the entire analysis invocation. There are no call arguments or points-to facts in the current schema, so C3 cannot resolve a generic callee's parameter to different objects at different call sites. Use separate invocations/bindings for such contexts, or leave bindings unresolved. Missing bindings invalidate ownership facts because an unidentified lock operation could affect any tracked object. No real Linux protection policy is installed; the demo's `rq.nr_running` policy is synthetic.

## Input assumptions and transfer functions

`Provenance(complete_events=True, linear_events=True)` is an explicit caller attestation that event bodies are exhaustive and primitive operations are successful and unconditional, with stable bindings and no omitted branches. It is not inferred from schema validity or the generator name, and is not a certificate of source correctness. Defaults are conservative: missing attestations or `illustrative: true` make assessments unknown. Synthetic examples use their own source-version string and set `synthetic=True`.

For an attested linear model with no unresolved conditions:

| Event | Transfer |
|---|---|
| `lock` | Bound lock becomes held after a successful unconditional acquisition. |
| `unlock` | Bound lock becomes not held after a successful unconditional release. |
| `assert_held`, `assert_not_held` | Check a precondition; never acquire/release a lock. Record met, unmet, or unproven. |
| `write` | Assess matching explicit write-policy rules against the current ownership state. |
| `atomic` | Assess only explicit atomic-policy rules; never borrow a normal-write requirement or acquire a lock. Missing atomic policies are reported as coverage diagnostics. |
| `call` | Visit a confirmed direct callee with the current state, then use its exit state in the caller. |
| `guard`, `error`, `warn` | Invalidate definite ownership/reachability; no CFG proves a harmless continuation. |

Conditional `cond`/`action` qualifiers, lock-operation `op` qualifiers (including trylocks), malformed semantic events, and repeated acquisition/release of an already held/absent simple lock are unsupported and cause uncertainty. An unknown entry state is not an assertion that the lock is absent: a successful release can establish absence even when initial ownership was unspecified. No recursive-lock counting, lock modes, IRQ state, RCU analysis, or atomic memory-order reasoning is implemented.

An unmet or unproven assertion records its precondition status and makes the continuation unknown. This prevents a failed assertion from being mistaken for acquisition or for a proven reachable counterexample. Unknown control flow/effects are deliberately sticky for the rest of that root's continuation, including its callers; a later apparent acquisition does not restore certainty. Earlier accesses retain their point-in-time model assessments, which never establish whole-function safety.

## Calls, coverage, and bounds

Only `events` supplies execution order. The unordered `callees` list supplies call-kind classification and coverage checks. A call event needs compatible, unambiguously direct metadata; missing/indirect/ambiguous metadata cannot be resolved merely because a target node exists. Source lines must agree when present on both records. Distinct line-specific call sites must have enough compatible ordered call events: one event without a line cannot cover two different source lines. Duplicate metadata for the same target/line does not invent an additional call. Calls on the same source line cannot be distinguished reliably without call-site IDs; completeness remains a caller assumption.

Missing definitions, `external`/`boundary` nodes, missing event bodies, recursion/cycles, and depth exhaustion invalidate all lock facts, including known-absent facts: an opaque function may acquire or release locks. An explicitly empty internal event body is pure only under the completeness attestation. Calls are analyzed afresh with each entry state; there is no universal function-state cache. Roots are independent. Default maximum call depth is 32 (root depth 0), configurable from 0 to 128 to keep Python traversal bounded. There is no fixed-point recursion analysis or bound on total acyclic call visits.

A callee in adjacency without an ordered call could occur anywhere in the function, so it makes the entire function uncertain from entry. The same applies to fields in `node.writes` without matching ordered access events. Such metadata produces explicitly unordered/unknown access candidates (`event_index=None`, `access=None`) where a policy matches; C3 never invents their position or follows adjacency as an execution sequence. Missing protected writes in both events and metadata cannot be detected: completeness remains an external assumption. There is no CFG, path-sensitive branch merge, alias analysis, or reachability proof.

## C2 integration and provenance

`analyze(..., callbacks={root: "dispatch"}, provenance=Provenance(source_commit=...))` requests an explicit C2 context. The callgraph version must exactly match C2's provisional `v7.1`, and the supplied commit must match C2's exact source commit. Mismatches or missing commit provenance raise `SourceVersionMismatch`. The existing TBD fixture therefore cannot receive v7.1 entry facts. An unsupported callback remains unknown.

C2's source-backed lock facts are treated as **entry requirements**, not observations that an execution acquired a lock. They never populate the held set from `lockdep_assert_*` evidence. A requirement is met only by an explicitly supplied `entry_states[root]` for the same bound object; otherwise it is unproven/unmet. C2 evidence is retained in the precondition record. Unresolved C2 lock symbols are not aliased to a policy lock by spelling. Callback identity, object bindings, and any intervening path from callback entry to a kfunc root remain the caller's responsibility; C2 callback facts alone do not prove kfunc-entry ownership.

## Results and findings

`AnalysisResult` contains ordered access assessments, precondition assessments, explicit conditions/coverage diagnostics, and per-root exit states. Each access has an `AnalysisSite` (root, call path, function, available file/event line, event index), field/access kind, required identity, observed state, assessment, explanation, and unresolved conditions affecting that point. A missing event line stays absent rather than using a function declaration line as a write location. Serialization is deterministic, including across hash seeds and adjacency-list order.

For a complete trusted synthetic path, a single-lock policy maps held to `protected`, absent to `unprotected`, and unknown to `unknown`. Multiple-lock policies additionally require every applicable lock for a protected assessment. These terms describe only that specific model access:

- `protected`: the policy's lock requirements hold under the specified abstract model and its input assumptions.
- Potentially unprotected: missing ownership may merit investigation, but is reported as `unknown`, not as proven absence or a violation.
- `unprotected`: a specific required lock is definitely absent under the model assumptions. This is not automatically a concrete reachable kernel counterexample.
- `unknown`: ownership, ordering, coverage, or another required lock cannot be established; explanations and conditions identify the cause. Potential risk is descriptive, not a fourth categorical verdict.

`to_findings(result, invariant="I1")` provides an explicit schema-validated adapter for access records. It preserves model assessments in evidence but always emits `verdict: unknown`, `enforcement: [unknown]`, and `static_or_runtime: unknown`. It cannot certify kernel safety, source completeness, policy validity, or enforcement from this model. Preconditions and coverage diagnostics remain in the richer `AnalysisResult`; an empty findings list does not establish analysis coverage. The adapter is not registered automatically and does not infer invariant applicability from the illustrative catalog.

## Example and validation

```python
from checker.lock_policy import LockIdentity, ProtectionPolicy, ProtectionRule
from checker.lockset import Provenance, analyze

rq0 = LockIdentity("synthetic.rq0.lock")
policy = ProtectionPolicy((ProtectionRule("root", "rq.nr_running", rq0),))
# graph is a schema-valid synthetic graph with a complete ordered event body.
result = analyze(graph, policy, bindings={"root": {"rq.lock": rq0}},
                 provenance=Provenance(complete_events=True, linear_events=True, synthetic=True))
```

```text
python -m checker.lockset_demo
python -m checker.lockset_demo --json
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
python -m checker check
python -m checker.context --source-version v7.1
```

Observed demo output:

```text
SYNTHETIC MODEL ONLY: no kernel safety verdicts
line 2: rq.nr_running, synthetic.rq0.lock: known_held -> protected
line 4: rq.nr_running, synthetic.rq0.lock: known_not_held -> unprotected
line 6: rq.nr_running, synthetic.rq0.lock: unknown -> unknown
```

The demo graph validates against the real callgraph schema. It is not the shared illustrative graph or a Linux trace. Unit tests exercise the synthetic abstract semantics, uncertainty, calls, identity separation, provenance, and adapter compatibility; they do not run a kernel or prove actual scheduler safety.

## Coordination before semantic I1 activation

Epic A must verify function/field-to-specific-lock requirements, atomic-access distinctions, invariant applicability, and source evidence against the team's agreed kernel. Epic B must establish event completeness, unconditional/success semantics, object and argument bindings, direct/indirect call-site correspondence, CFG/return information, and source-commit provenance. The present schema cannot carry all those facts, so any future contract changes require cross-epic review. Once that evidence exists, integrate a reviewed policy and richer entry/path facts before deciding which aggregated I1 findings can justify semantic verdicts. C4 guard analysis, I2 state transitions, verifier changes, VM execution, and runtime BPF validation remain outside this change.
