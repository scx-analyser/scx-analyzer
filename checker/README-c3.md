# C3: conservative interprocedural locksets

`checker.lockset` propagates specific lock-object ownership through ordered
events and evaluates explicit field policies. Results describe an abstract
model, not a kernel execution or an implemented graded invariant. No semantic
checker is automatically registered. C1, C2, shared contracts/fixtures and
`KERNEL_VERSION` are unchanged.

## Domain and policy

C3 reuses C2's KNOWN_HELD / KNOWN_NOT_HELD / UNKNOWN domain. Missing facts mean
UNKNOWN. Locksets are immutable; states and assessments reject boolean conversion.

A `ProtectionRule(function, field, lock, access)` is an explicit obligation for
one function/field/access kind and one object identity. Rules applying to the
same access are conjunctive: every required lock must be held before any record
for that access is PROTECTED. A definitely absent required lock is an
UNPROTECTED witness **in the model**, not a demonstrated kernel violation.
WRITE and ATOMIC policies are separate. With no matching policy, C3 emits
`no_write_policy` / `no_atomic_policy`; it infers no protecting lock.

`LockIdentity("cpu0.rq.lock")`, `LockIdentity("cpu1.rq.lock")`, task pi locks and
DSQ locks remain distinct. Every event token needs an explicit per-function
binding; spelling alone never aliases objects. Bindings and field obligations
attest to stable objects throughout the analysis invocation. The current schema
has no call arguments, field-object IDs or points-to facts: a generic helper
used with different objects must be specialized with verified bindings, analyzed
separately, or left UNKNOWN. One structural field name does not identify one
runtime object across all sites.

No Linux field-protection policy is installed. The demo's
`rq.nr_running -> synthetic.rq0.lock` obligation is synthetic.
[Catalog integration design](README-c3-catalog.md) explains why callback entry
locks and the current A3 hypotheses cannot simply become access-site policies.

## Transfer functions and control flow

| Event | Effect |
|---|---|
| Unqualified, unconditional `lock` | The explicitly bound lock becomes KNOWN_HELD after a successful primitive acquisition in the trusted model. |
| Unqualified, unconditional `unlock` | That lock becomes KNOWN_NOT_HELD after release. |
| `assert_held` / `assert_not_held` | Record MET, UNMET or UNPROVEN; never acquire/release a lock. An unmet/unproven precondition invalidates certainty. |
| `write` / `atomic` | Evaluate only explicit policies for that access kind. |
| Confirmed direct `call` | Analyze with the caller's current state; propagate the conservative callee exit. |
| Guard/error/warn, conditional or unsupported lock operation | Control/effect uncertainty is sticky; later acquisitions do not recover proof of reachability. |
| Missing/indirect/opaque call, recursion, depth or work limit | UNKNOWN effects with an explicit condition and the actual cut path. |

Only ordered `events` determines sequence. Adjacency supplies coverage checks
and direct/indirect classification, never execution order. Distinct source
call sites need enough compatible ordered calls; one unlocated call cannot cover
two different lines. Same-line sites remain ambiguous without IDs/completeness.

Unsequenced callees may precede any event and invalidate certainty from function
entry. Writes in metadata without ordered accesses produce unordered UNKNOWN
candidates (`event_index=None`, `access=None`). Missing accesses from both places
cannot be detected. There is no CFG, path-sensitive join or reachability proof.

## Scoped locks and function exits

The provisional source reference is upstream v7.1 commit
`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`; this does **not** choose the course kernel.

Linux cleanup objects have destructors at lexical scope exit.
[`CLASS`, cleanup.h:301-306](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/include/linux/cleanup.h#L301-L306)
uses a cleanup attribute;
[`guard` and `scoped_guard`, 399-450](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/include/linux/cleanup.h#L399-L450)
create those objects, with scoped_guard's lifetime confined to its compound
statement. Raw spin guards pair acquisition/release:
[spinlock.h:535-537 and 571-574](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/include/linux/spinlock.h#L535-L574).
See actual sched_ext uses at
[ext.c:1243-1269](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1243-L1269),
[4111](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4111),
[4237](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4237), and
[4621](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4621).

A callee's apparent acquisition without a release is therefore **not** a held
exit guarantee. C3 tracks acquisitions during each invocation. If an acquired
lock is still apparently held on return, its exit state becomes UNKNOWN and
`unverified_lock_escape` records the reason. This also catches a lock held on
entry, released and then reacquired: comparing only entry/exit states would miss
that case. Assertions do not certify lifetime or handoff.

An explicit release still propagates KNOWN_NOT_HELD. A caller-held lock untouched
by the callee remains held. Scope uncertainty affects only the acquired identities;
it does not suppress a later explicit unlock of another lock. Root exit ownership
is treated the same way. Earlier protected accesses inside a trusted linear
primitive sequence remain model assessments; they do not certify a held exit.

No lock-handoff annotation is accepted in this revision. Such an annotation
would need reviewed object, source, acquisition and all-exit evidence. Tagged
guard/scoped_guard operations remain unsupported/UNKNOWN. Untagged inner-scope
cleanup omitted by extraction is still a limitation: complete_events must not
be asserted for a body with hidden releases or branches. C3 cannot reconstruct
inner lexical scope from this schema.

## Invocation summaries and global work budget

`AnalysisResult.summaries` records each analyzed invocation's path, entry/exit
locksets, successful acquisition/release events, encountered held/not-held
assertions (with sites/status), and uncertainty. Acquired does **not** mean held
on exit. Assertions are body-site requirements, not inferred universal entry
requirements. The same function reached with different states has separate
summaries. These are not memoized universal effects.

`analyze(..., max_work=10000)` sets one deterministic budget shared by **all**
roots and callees. A unit charges function entry, ordered-event processing or
metadata inspection/comparison. Metadata scans are charged too; the budget
cannot be bypassed by repeated call-site coverage checks. Static policy lookups
are indexed once. max_work accepts integers 1 through 1,000,000; max_depth remains
0 through 128, with root depth zero.

When the budget is exceeded, expansion stops and exit ownership becomes UNKNOWN.
The `work_budget` condition retains the real cut path. Known remaining local
access candidates are reported UNKNOWN without traversing skipped callees.
Skipped deeper accesses are not assigned invented paths; the unresolved gap is
reported explicitly by the output adapter even when no access was observed.
Evidence already produced for visited prefixes is retained.

`AnalysisResult.work` reports limit, consumed units, visits, events, metadata
and exhaustion. This bounds recursive expansion, including doubling/diamond
graphs; it is not a wall-clock or total-memory quota. Input/schema validation,
policy indexing and local candidate reporting after a cut still cost input work.
Very large inputs, large locksets, policy conjunctions and output volume retain
their own costs. No exponential complete-path enumeration is promised after
exhaustion.

## C2 integration

Pass an explicit callback, exact source version/commit, configuration and object
bindings. C2 facts are source-backed **entry requirements**; they never seed
observed ownership. Explicit model entry states must satisfy them.

```python
from checker.context import LockIdentity as C2Identity, SOURCE_COMMIT
from checker.lock_policy import LockIdentity
from checker.lockset import Lockset, LockState, Provenance, analyze

rq0 = LockIdentity("cpu0.rq.lock")
result = analyze(
    graph, policy,
    callbacks={"root": "dispatch"},
    context_bindings={"root": {C2Identity("rq", "dispatch.cpu:cpu"): rq0}},
    entry_states={"root": Lockset.from_mapping({rq0: LockState.KNOWN_HELD})},
    provenance=Provenance(
        source_commit=SOURCE_COMMIT, complete_events=True, linear_events=True,
        enabled_configs=("CONFIG_EXT_GROUP_SCHED",),
    ),
)
```

The example assumes externally supplied graph/policy and independently justified
entry-state/binding attestations. It does not establish them from source facts.

Existing `bindings` remains the per-function **event-token** map. A bare `rq`
token cannot identify which callback task/CPU owns that lock. `context_bindings`
maps C2's complete typed identities to C3's explicitly identified objects. Old
name-only context mappings now remain UNKNOWN; this intentional tightening
prevents a wrong-rq precondition from passing.

Version/commit mismatches and missing commit provenance raise SourceVersionMismatch.
Cgroup callbacks need `Provenance.enabled_configs`; unresolved configuration
produces `unknown_callback_configuration`. C2's 37 callbacks are available,
but source-backed requirements with READ ownership remain
`unsupported_entry_lock_mode`: C3 currently models exclusive ownership and must
not silently turn shared ownership into exclusive field protection. init_task's
rq remains UNKNOWN; no generic alias/absence is injected. The normal TBD fixture
cannot receive v7.1 facts.

## Output and commands

`AccessAssessment` records root/path, function, file/line/index, field, access kind,
required identity, observed state, explanation and conditions.
`to_findings(..., invariant="I1")` is an explicit UNKNOWN-only adapter. It reports
unsupported/incomplete gaps not already covered by access evidence, including
missing callees and missing policies, so a cut does not become a checked-empty
result. It invents neither enforcement nor kernel counterexamples and installs
no plugin.

```text
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
python -m checker check
python -m checker.context --source-version v7.1
python -m checker.lockset_demo
python -m checker.lockset_demo --json
git diff --check
```

The synthetic demo produces protected, unprotected and unknown accesses.
Unit tests exercise scoped-return regressions, explicit release propagation,
deep and diamond graphs, global budgets, path evidence, contextual summaries,
C2 identity/mode/configuration boundaries and unknown output. Host unit tests
prove no actual kernel safety.

## Remaining integration boundary

A must verify the field-specific obligation, mode and object relationship.
B must supply ordered complete events, scope cleanup/return information,
call/argument/field-object bindings and source/config provenance. The current
catalog/callgraph contracts do not carry all of that evidence. Cross-epic review
is required before changing them. Callback permissions alone do not satisfy
the TA's three shared scheduler-state modification invariants.

Read [the catalog design](README-c3-catalog.md) for the current A2/A3 rule audit,
a fail-closed translation proposal and the remaining #34 acceptance blockers.
C4, verifier changes, LLVM extraction, VM execution and runtime tests are outside
this revision.
