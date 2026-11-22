# C3 catalog integration: source obligations to policies

This is the proposed Epic C consumption design for Issue #34, based on
[A2 PR #52](https://github.com/scx-analyser/scx-analyzer/pull/52)
(`847a014d9d253d5bb7e0a4c5fd6b1b7a8abf1af7`) and
[A3 PR #53](https://github.com/scx-analyser/scx-analyzer/pull/53)
(`698b3eb51c42fcde3ba7762df8c99563ee51c9a7`), inspected 2026-11-22.
No Epic A document, shared schema, fixture or version pin is modified here.

## What can be translated

A source-verified **field-specific access-site obligation** can become:

```python
ProtectionRule(
    function=verified_access_function,
    field=verified_struct_field,
    lock=verified_specific_lock_identity,
    access=verified_access_kind,
)
```

That translation is valid only when all of these are established:

1. The actual course-source version, full commit and build configuration agree
   across catalog, graph, C2 and evidence. The v7.1 reference is provisional.
   A tag alone or the existing TBD illustrative graph is insufficient.
2. The rule establishes a required locking discipline for that exact modification,
   not just a permission, observed access, possible improvement or hypothesis.
   `status: source_verified` alone cannot establish this relationship.
3. The writer/helper function, field, source site and affected object are bound.
   `applies_to` identifies root applicability, not every transitive write site.
4. A specific required lock object and mode protect that specific field/object.
   A list of fields and a list of locks do not authorize a Cartesian product.
   Callback rq, subject-task rq, foreign rq and DSQ locks cannot be interchanged.
5. A write/rw obligation is refined to an explicit WRITE or ATOMIC policy.
   Read-only objects are excluded. Atomic updates do not inherit plain-write rules.
6. All applicability predicates and call-site/object substitutions are resolved
   on the analyzed path. Disjunctions, conditional requirements, unresolved
   aliases, different callee arguments or unsupported modes remain UNKNOWN.
7. Events establish complete ordering, successful primitive lock semantics and
   cleanup/exit effects. Scope acquisition alone does not certify an exit lock.
   C3's current per-function binding map requires stable objects for **all**
   relevant visits/sites; otherwise specialize with verified identities or defer.

Multiple verified obligations for an access are conjunctive. C3 may report
PROTECTED or UNPROTECTED **under that abstract model** only after all applicability
and event assumptions are established. A kernel-level HOLDS/VIOLATED finding
also needs verified input/policy provenance and complete applicable-path coverage;
current `to_findings` deliberately reports UNKNOWN.

## Entry facts are not access-site requirements

A2's `requires.locks[].where=callback_entry` is routed to C2/context-precondition
checking, with explicit object bindings. It does not produce ProtectionRule.
It neither proves current ownership nor establishes that every named field needs
that lock at every access. C3 never seeds actual ownership from an assertion.

Likewise, `requires.contexts` describes kfunc sets, callback membership and
program-type restrictions. It is supporting context, not a shared-state write
invariant. `KF_RCU`, sleepability, interrupt state and a prohibition on holding
BPF spin locks require their own domains/checkers. They must not be disguised
as exclusive protecting-lock identities.

## Audit of current A3 candidates

The following is an eligibility audit, not a claim that A3's recorded kernel
behavior is wrong. All 14 rule IDs were inspected.

| A3 rule(s) | Why no current exclusive field-lock policy can be compiled automatically |
|---|---|
| I1.dsq_insert.context | rq/pi_lock are callback-entry facts. The access-site requirement names interrupt-disabled state and BPF-lock exclusion, not a verified field-to-specific-exclusive-lock relation. |
| I1.dispatch_only.context; I1.cpu_release.context | Held rq requirements are callback-entry context; no field/site/object locking relation is established merely by sharing this rule. |
| I1.dsq_move.context | Callback-dependent entry locks/absence and runtime-state predicates do not bind the moved task's actual field object/lock on every path. |
| I1.create_dsq.sleepable; I1.select_cpu.context | Sleepability/context or read conditions; no eligible shared-write locking obligation. |
| I1.idle.context; I1.any.context | Permission groups and broad affected objects do not define a protecting-lock policy. |
| I1.locked_rq.runtime | Runtime rq predicates/ownership checks require resolved arguments and path conditions; there is no unconditional field-specific lock obligation to copy. |
| I1.dump.context | Source-backed dump entry guards support C2; an explicit access-site field/object obligation is still required for C3 policy compilation. |
| I1.task_cgroup.subject_task | Read/subject-task and callback-entry facts, not the required shared modification invariant. |
| I1.task_set.unlocked_write | The task_rq access-site entry explicitly describes a **hypothesis** for stable writes, NOT a requirement stated or checked by the kernel. Source_verified describes the observed behavior; it cannot certify the hypothesized obligation. |
| I1.bpf_spin_lock.no_calls; I1.prog_type.gate | Program/verifier exclusions and type gates; no exclusive protecting-lock relation for shared state. |

The most tempting candidate is
[`I1.task_set.unlocked_write`](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.yaml#L483-L512):
`scx_bpf_task_set_slice` / `scx_bpf_task_set_dsq_vtime` modify
`task_struct.scx.slice` / `scx.dsq_vtime`, but the description explicitly says
the task_rq lock requirement is a hypothesis and kernel-doc states no such rule.
C3 must not turn that into either a proven violation or a safety proof.

Thus **zero production policies are installed from the inspected A3 catalog**.
Unsupported writes produce explicit `no_write_policy`/`no_atomic_policy`
conditions when analyzed; missing paths, events or budgets produce their own
conditions. The UNKNOWN-only findings adapter preserves gaps even when there
are no observed accesses. The normal C1 CLI still reports an empty registry
explicitly as "no semantic checkers installed (no safety claim)".

## Proposed integration sequence

1. **A:** agree the course kernel, identify a real shared-field modification
   invariant, and distinguish observed source behavior from the normative
   obligation. Review one exact field/site/object-to-lock/mode relation, including
   all predicates and whether a hypothesized requirement is actually justified.
2. **A/C:** provide an explicit reviewed binding manifest or a coordinated
   contract extension connecting a rule ID to writer sites and field/lock object
   expressions. Keep rule-family identity for C1 findings. The current nested
   objects/locks lists alone do not specify that relation safely.
3. **B:** provide actual call paths, ordered events with cleanup/return semantics,
   call-site IDs, argument/field-object identities, completeness evidence,
   full commit and configuration. Current callgraph JSON has no commit, scope or
   argument/object binding fields. Caller attestations are model assumptions,
   not automatically verified source evidence.
4. **C:** compile only the reviewed relation into existing ProtectionRule objects.
   Require explicit matching source provenance and stable object bindings.
   Record rejected candidates with rule/root/source and a precise UNKNOWN reason;
   never manufacture locks, field sites, call paths or enforcement.
5. **C:** add a source-backed positive/negative/unknown end-to-end fixture,
   with cross-epic review before changing shared fixtures. Only then register an
   opt-in/approved semantic checker and define source/coverage aggregation for
   HOLDS versus a definite counterexample. Until then use the UNKNOWN adapter.
6. **D:** validate real kernel/verifier/runtime cases under the agreed source,
   independently of host unit tests. C4 handles applicable guard/predicate
   reasoning; C3 does not silently discharge those conditions.

## Current contract and acceptance blockers

The actual branch still contains the existing C1 catalog schema, not the
unmerged A2 family/rules schema. C1 correctly rejects the new A3 document against
that old contract. Bypassing validation or modifying the shared schema in this
C3 patch would not be a sound integration.

Consequently the requested production catalog-derived policy through
`python -m checker check` is **not implemented** in this revision. There is no
sufficiently justified field-lock relation plus real graph/source/binding/scope
evidence to enable it. This remains an explicit #34 acceptance dependency,
rather than an optimistic demonstration claiming to satisfy it.

The scope-return and complexity fixes, invocation summaries and regressions are
ready for review independently. Closing #34/merging a production checker still
requires the A/B decisions and evidence above. Verifier calling-context permissions
alone do not satisfy the TA's three graded shared scheduler-state modification
invariants.
