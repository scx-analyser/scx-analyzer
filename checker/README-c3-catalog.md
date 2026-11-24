# C3 catalog integration: source obligations to policies

This is the proposed Epic C consumption design for Issue #34, based on
[A2 PR #52](https://github.com/scx-analyser/scx-analyzer/pull/52)
(`fa34ff0a6866205bc93169909c2b25c3d1b61911`) and
[A3 PR #53](https://github.com/scx-analyser/scx-analyzer/pull/53)
(`b4a71e6d2d89f831b3c20b768eb3c55344ae7dbd`), inspected 2026-11-24.
These immutable references identify this audit, not a claim that moving PR
branches will remain unchanged. Revalidate their current heads before integration.
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

The revised A3 has seven protection rules and thirteen supporting entry-state
rules. A2 now provides explicit `obligations` with field/access/object/site
bindings, lock instances/modes, predicate captures, applicability and basis.
This resolves the old independent field/lock-list binding gap. Schema validity
does not verify alias relationships, source claims or event completeness.

| A3 protection rule | C3 consumption boundary |
|---|---|
| I1.nonlocal_dsq.dsq_lock | Observed acquisitions are not automatically normative policies. The documented dsq_flags obligation still needs the exact nonlocal DSQ/field identity. |
| I1.local_dsq.rq_lock | Checked/documented local-DSQ obligations are candidates after binding the destination rq, source DSQ, concrete writer sites and applicability. |
| I1.rq_scx.rq_lock | Target rq and captured locked_rq must be resolved; balance entry-prefix writes are not descendants of every root. |
| I1.ops_state.atomic | Atomic ordering/state requirements are not ordinary write-lock policies. The inspected claim_cmpxchg still shares a dispatch-only snapshot predicate with ops_dequeue; that scope correction is tracked in the A3 review. |
| I1.dsq_insert.commit_guards | Direct/buffered snapshot and capacity requirements need guard analysis, not a guessed lock. Earlier slice/vtime writes are outside those guarantees. |
| I1.dsq_move.slice_vtime | Source task rq plus source DSQ are explicit candidates, subject to verified caller/object bindings, scope, provenance and complete events. |
| I1.task_slice_vtime.unlocked_writers | Draft, basis=hypothesis. Never compile the proposed task_rq requirement into a mandatory policy. |

All thirteen `role: entry_state` rules remain context/precondition information;
they produce no field-protection policies. The old `I1.task_set.unlocked_write`
and `I1.locked_rq.runtime` ids were replaced. The revised catalog now supplies
genuine shared-state obligations; permission groups alone remain insufficient.

For the precise remaining A3 predicate-scope issue, see the
[source-backed re-review](https://github.com/scx-analyser/scx-analyzer/pull/53#pullrequestreview-6047938021).
That catalog issue is not repaired by silently dropping a conjunct in C3.

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
2. **A/C:** consume the revised A2 obligation bindings after review: exact writer
   function, field, access kind, sites, object, required lock mode, applicability
   and basis. Keep rule-family identity for C1 findings. Current ProtectionRule
   matches function/field/access, not individual source lines: an adapter must
   prove uniform applicability at every matching site or retain UNKNOWN rather
   than widen a site-specific or conditional obligation to the whole function.
3. **B:** provide actual call paths, ordered events with cleanup/return semantics,
   reviewed per-event diagnostic/guard semantics, branch polarity, call-site IDs,
   argument/field-object identities, completeness evidence,
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

The source-backed dsq_dec_nr helper demo supplies a fixed local-DSQ object and
explicit assumed rq entry ownership. Its complete helper-level model illustrates
reviewed returning guards; it does not supply a real extracted kfunc graph or
replace production catalog translation. The findings adapter remains UNKNOWN.

The scope-return, control-event and metadata-indexing fixes, invocation summaries
and regressions are ready for review independently. Closing #34/merging a production checker still
requires the A/B decisions and evidence above. Verifier calling-context permissions
alone do not satisfy the TA's three graded shared scheduler-state modification
invariants.
