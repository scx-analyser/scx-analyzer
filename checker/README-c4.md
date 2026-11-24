# C4: guard coverage over ordered kfunc call paths

Issue [#35](https://github.com/scx-analyser/scx-analyzer/issues/35). This is a
conservative, interprocedural **model analysis**, built on the C1 interfaces on
main. It checks explicit predicate obligations at specific state modifications.
It installs no semantic plugin and leaves `python -m checker check` unchanged.
Callback permissions are supporting facts, not any of the three graded shared
scheduler-state invariants. This implementation does not establish those three
invariants or measure enforcement on a running kernel.

## Meaning of a result

`checker.guards.analyze(graph, policies, *, model=None, entry_facts=(),
max_depth=32, max_work=10000)` validates the **real** callgraph schema first.
It returns immutable access assessments, analysis gaps and a work counter.

| Assessment | Predicate value | Meaning under the supplied model |
|---|---|---|
| `established` | `true` | A reviewed guard or explicit entry precondition establishes the predicate before this access. |
| `false` | `false` | The predicate is false on the modeled path, e.g. a guard with the wrong polarity. This is not a verified kernel counterexample. |
| `missing_check` | `unknown` | A complete modeled path contains no established check/precondition. This establishes missing coverage, not that the argument actually has an invalid value. |
| `unknown` | normally `unknown` | Completeness, CFG, bindings, predicate stability or other required evidence is missing. |

Missing facts are never interpreted as false. Truth, assessment and branch
enums reject boolean conversion. Multiple predicates at one access have separate
assessments: one successful predicate does not discharge the others. Results
are per access and invocation; they are not a whole-root or family verdict.
An empty result is not a safety claim; inspect `gaps` as well as `accesses`.
Every configured policy receives at least one assessment. A nonexistent policy
function raises `ValueError`. An existing but unvisited function, an unmatched
site, indirect call, unsupported branch or budget/depth cut cannot silently
remove its obligation: a final coverage pass emits an explicit UNKNOWN row.
This is coverage per configured policy, not a claim that every invocation was
reached; omitted invocations still appear in the analysis gaps.

`AnalysisResult.to_dict()` is deterministically JSON-serializable. Assessments
carry the root, complete call path, function, event index, file/line if known,
field, access kind/object, exact predicate/object identities, policy rule/reference/source,
observed value, explanation, establishing evidence and unresolved conditions.
An event index of `None` identifies an **unobserved obligation at a coverage
cut**, not a fabricated observed write. A never-visited policy uses only
`(root,)` as its path, retaining the intended function/site separately; no
root-to-helper call path is invented. Gaps explicitly describe omitted paths.
Missing field identities produce a gap and UNKNOWN candidate obligations only
for potentially relevant policies of the same access kind. Unverified
completeness/control flow also produces a gap when no access was observed;
an empty event stream is not evidence of complete coverage.

`to_findings()` uses the unchanged shared findings contract, family `I3`, and
**only `verdict: unknown` and unknown enforcement**. Model assessments remain
in the evidence. Neither successful synthetic coverage nor a missing check is
promoted to `holds`/`violated`. The adapter validates its result against the
real findings schema, including gap-only output. Source-level guards may be observed without being
shown to enforce a complete invariant on all real paths. No production checker
is registered automatically.

## Required inputs and trust boundary

No field-predicate relationship is inferred from names or catalog lists.
`GuardPolicy` names exactly one root, function, field, predicate and access
kind (`write` or `atomic`), with a rule id, version, full commit and source
reference for the obligation. Real-source policies also require an exact
access line. `access_object` optionally binds the modified object and is
mandatory for reviewed dominance evidence. Different roots/functions/fields,
access kinds, sites and explicit object identities are separate obligations.

`Predicate(expression, objects)` is opaque: both the expression and the ordered
tuple of object identities must match. `cpu:argument-0` and `cpu:argument-1`
are distinct. Identical parameter spellings in different functions are not
evidence of aliasing. Caller-to-callee parameter/object correspondence must be
reviewed explicitly; no substitution, pointer/DSQ alias analysis, C expression
parser, theorem prover or LLVM analysis is implemented.

The graph schema has no source commit, complete CFG, branch sense, return
values, phi nodes, argument bindings or extraction-completeness marker.
Accordingly, `Model` supplies separate **caller attestations**:

- `source`: exact version and 40-character commit, equal to every policy's
  source. A missing model gives UNKNOWN. Any supplied version/commit mismatch
  raises `ValueError`; no version fallback is used.
- `graph_digest`: `graph_digest(graph)`, a SHA-256 fingerprint binding all
  annotations to the exact JSON graph. It detects stale annotations, not an
  incorrect extraction. Changing a graph requires reviewing its attestations.
- `config_digest`: SHA-256 of the reviewed kernel configuration. Missing
  configuration provenance taints normal non-synthetic traversal UNKNOWN; a
  synthetic model has no kernel configuration to assert. A separately reviewed
  configuration-independent **local source relation** may be assessed as
  described below, without inventing a configuration hash. This does not
  certify a build or remove the overall configuration/coverage gap.
- `functions`: `FunctionModel` references with exact function file/range,
  `complete_events=True` and `linear_except_guards=True` only after confirming
  exhaustive events, unconditional sequencing except annotated guard branches,
  and all relevant side effects. Missing assertions of these properties taint
  that invocation and its caller UNKNOWN. A branched function must remain
  `linear_except_guards=False`; a local CFG proof never changes this flag.
- `bindings_verified=True`: canonical object/argument identities remain valid
  across every analyzed call and there are no unmodeled concurrent predicate
  changes. In particular, affinity, CPU online state and DSQ lifetime need
  appropriate synchronization/lifetime evidence. This flag is not a substitute
  for that review. Defaults are conservative.
- `guards`: `GuardSemantics` for exact function/event/condition/action and
  source range. Each asserts the relation between condition truth and the
  required predicate, the branch sense, and whether that branch actually exits
  the current function. Compound expressions require an independently reviewed
  equivalence, not token/name matching.
- `dominance`: optional `DominanceEvidence` for one exact policy/access,
  with the reviewed source CFG and predicate-preservation evidence below.

`synthetic=True` labels a test model; it does not certify source facts.
Illustrative input without that label cannot produce established/false/missing
source-model results. Synthetic source files, commits and policies in the tests
and demo are invented test data, clearly separate from the source audit below.
Supplying unjustified attestations can make any model inaccurate; the analyzer
does not independently verify them from C. Even a fully annotated real-source
model gets UNKNOWN from the findings adapter until whole-invariant integration
and evidence requirements are agreed.

Optional `EntryFact` values require a root and references. They apply only to
that root, even if other roots use identical predicate spellings. They are explicit preconditions
of the model, described as such in evidence, not observations that real callers
satisfy them. C2 supplies no argument-predicate facts automatically; callback
entry-lock facts are not access-site predicate obligations.

## Transfer and interprocedural semantics

Only ordered events sequence execution. Confirmed direct calls need matching
direct adjacency metadata and, when available, call-site lines. Calls execute
in event order, receive copied immutable states and propagate exit effects.
Repeated callees are analyzed for each incoming state and call path; no shared
context-insensitive summary is reused.

For `if (!P) return;`, annotate `condition_true_means=Truth.FALSE`,
`branch_when=BranchWhen.CONDITION_TRUE`, `exits_function=True`. The continuing
path has P true. For `if (P) return;`, use `Truth.TRUE`: continuation has P
false. The contract's `action` says what happens when a guard fails, while
`cond` is only described as a source condition. Its spelling alone does not
settle which sense the extractor used. Both senses must be specified, even
when `action` is `return`.

An established fact excludes an inconsistent branch only in a trusted model.
Conflicting guards can make a later access unreachable. Unverified contexts
cannot prune accesses this way. Every feasible early-return branch is retained
and **joined at function exit**: a guard in a callee does not establish P in the
caller, since the caller also resumes after the callee's failed-check return.
Exit-branch side effects are conservatively unknown. Joining keeps only
unanimous facts; disagreements remain UNKNOWN.

Writes are assessed **before** their effects. Every write/atomic event then
invalidates predicate values, because the representation cannot establish which
arguments, affinity masks, DSQ lifetime or dependent memory they affect. A later
reviewed guard may establish a fresh fact. Atomic accesses need an explicit
atomic policy; a write policy is not automatically applied to them.

Bare `error`/`warn`, unannotated guards, nonterminating guard branches/fallbacks,
conditional events without CFG, opaque/missing/indirect calls, recursive cycles
and depth/work cuts taint subsequent analysis UNKNOWN. Error helper names and
`action: error` do not prove termination. `lock`, `unlock` and lockdep assertion
events do not establish argument predicates or prove lock ownership here.
`guard(rcu)()` in C is resource scope syntax, not a CPU/DSQ predicate check.
Reviewed dominance evidence may prove a local guard/access relationship despite
these general traversal gaps. It does not repair or export traversal facts.

Unordered `callees`/`writes` metadata is checked for omissions but never executed
as an event sequence. Missing ordered accesses and omitted calls produce explicit
coverage gaps. A `boundary`/`external` node remains opaque even if it has events.

Recursion terminates conservatively; there is no recursive fixed point. The
global deterministic work budget charges function entries, event scans,
metadata scans, matching call-edge checks and predicate comparisons at return
joins across all roots. Joins align the immutable predicate vectors directly,
avoiding repeated searches through each state. This caps repeated
diamond traversal. The depth limit is at most 128 to avoid Python stack overflow.
Cuts emit UNKNOWN obligations/gaps and retain evidence collected before the cut,
never successful summaries. Parsing, schema
validation, indexing and output construction are outside the traversal budget;
it is not a wall-clock or input-size quota. Call paths are preserved.

## Reviewed local dominance evidence

`DominanceEvidence` is a narrow, hand-reviewable mechanism, independent of C3.
It binds one `GuardPolicy` to its exact guard/access event IDs, source function
range, full version/commit, accessed object, predicate objects and graph digest.
Each object identity is explicitly bound to a C expression **in the access
function**. Changing the graph requires rebinding the proof's own digest,
in addition to the model's digest. Neither hash proves source fidelity.

The supplied `ControlEdge` DAG starts at event zero, includes every modeled
event, labels both outcomes of every source condition, and gives every ordinary
event an explicit continuation or exit (`target=None`). C4 checks all
entry-to-access paths. A successful-check token is generated only on the guard
outcome where `GuardSemantics` says the required predicate is true. Joins keep
it only when **all reaching paths** carry it. Source line order establishes
neither dominance nor a branch edge. A bypass, wrong polarity, missing edge,
unsequenced metadata, cycle, incomplete function or budget cut cannot prove
the access protected. Unreachable accesses remain UNKNOWN.

The token survives an intervening event only with a `PredicatePreservation`
reference and reason for this proof's predicate **and object binding**. There
is no automatic exemption for by-value names, WARN, error helpers, writes or
opaque calls. An indirect/unresolved call cannot be certified by a preservation
label. A known direct boundary may have reviewed predicate-specific preservation
while its other effects and whole-root analysis remain UNKNOWN. Guards after
the chosen access have no bearing on its assessment.

Successful assessment is `established` with `proof_basis=reviewed_source_cfg`:
**if this exact access is reached, the predicate is established under the
reviewed local model**. It is not a reachability claim, a proof that the wrapper
always invokes the helper, a summary returned to callers, or an invariant-level
HOLDS verdict. Global gaps and UNKNOWN findings remain. Proofs are only applied
when traversal reaches the candidate event; they cannot turn a skipped function
or unobserved coverage row into a positive result. DAG checks also consume the
deterministic global work budget.

This mechanism verifies the logical consequences of the supplied CFG, not that
the annotation matches C. CFG completeness, predicate equivalence, preservation,
object/argument bindings, concurrent stability and any configuration-independent
scope remain explicit reviewed inputs. The source demo below supplies these
by hand. It does not claim automatic extraction or kernel-wide safety.

## Source audit: provisional Linux v7.1

Inspected upstream commit **`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`**.
This is a provisional reference, not the agreed course kernel. No built-in
Linux policy is installed and `KERNEL_VERSION` is unchanged. The links below
are source observations for A5 review, not declarations that any inferred
predicate is a universal kernel invariant.

| Candidate / observation | Exact source evidence | Consequence for C4 integration |
|---|---|---|
| CPU range/possible check | [`__cpu_valid`, `ops_cpu_valid`, ext.c:1083-1105](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1083-L1105) | CPU validity means nonnegative, below `nr_cpu_ids`, and `cpu_possible`; it does not mean online or task-affine. |
| Explicit CPU early return before kick-mask updates | [`scx_kick_cpu`, ext.c:8881-8929](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L8881-L8929) | Lines 8886-8887 filter invalid CPUs. Lines 8919-8926 modify different kick masks on conditional paths. Need root/helper binding and these branches, not the illustrative `rq.scx.flags` association. |
| Range and CPU-specific performance write | [`scx_bpf_cpuperf_set`, ext.c:9431-9459](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9431-L9459) | Range error explicitly returns; CPU-valid branch encloses `rq->scx.cpuperf_target` at 9458. CPU/rq identity, nested branches and calls require separate evidence. |
| Invalid/nonexistent destination falls back | [`find_dsq_for_dispatch`, ext.c:1735-1764](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1735-L1764) | Invalid local CPU/nonexistent user DSQ returns a **global DSQ**, not a guarantee that the requested DSQ was valid. Need return-value/object bindings. |
| Affinity, migration-disabled and online checks | [`task_can_run_on_remote_rq`, ext.c:2328-2374](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2328-L2374), [`task_allowed_on_cpu`, sched.h:2820-2826](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/sched.h#L2820-L2826) | The affinity helper tests `p->cpus_ptr`. Migration-disabled is separately checked first. Do not replace all three predicates with CPU validity or infer a stable affinity mask without synchronization. |
| Failure can still perform a different state modification | [ext.c:2469-2475](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2469-L2475), [ext.c:2601-2605](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2601-L2605) | Remote-task checks can select/enqueue on the global DSQ. Restrict obligations to the relevant local-target writes. |
| Dispatch/task and argument checks | [`mark_direct_dispatch`, ext.c:1776-1794](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1776-L1794), [`scx_vet_enq_flags` / `scx_dsq_insert_preamble`, ext.c:8082-8123](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L8082-L8123) | Task identity errors explicitly return before `p->scx.ddsp_*` writes, but the per-CPU `direct_dispatch_task` update at 1776 precedes that check. Preamble checks return **bool**; caller return-value branches matter. |
| Slice update precedes destination commit | [`scx_bpf_dsq_insert___v2`, ext.c:8204-8212](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L8204-L8212) | The slice write follows the preamble, before DSQ insertion/commit. Do not assign the later destination's CPU/affinity obligations to every slice write based on the illustrative catalog. |
| Errors do not necessarily stop writes | [`dispatch_enqueue`, ext.c:1532-1595](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1532-L1595), [ext.c:8909-8919](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L8909-L8919) | Destroyed-DSQ fallback, clearing a vtime flag, FIFO/PRIQ errors and a kick flag error continue execution. Error detection, recovery and termination are different facts. |

### One source-backed positive: kicking a CPU

`python -m checker.guards_demo --source-example` constructs a schema-valid,
hand-written source projection of `scx_bpf_kick_cpu -> scx_kick_cpu`. Both
functions remain marked **nonlinear**. Internal callees are explicit opaque
boundaries; their complete callgraphs are unavailable. The projection includes
all source branches of `scx_kick_cpu`, including bypass and idle-skip cleanup,
the nonterminating flag error and both flag-controlled mask updates.

To inspect that annotation from Python:

```python
from checker.guards import analyze
from checker.guards_demo import kick_cpu_inputs

graph, policies, model = kick_cpu_inputs()  # Explicit source CFG/bindings, not extraction.
result = analyze(graph, policies, model=model)
print(result.accesses[0].assessment.value)  # established, for the one local source relation
print(model.functions[1].linear_except_guards)  # False
assert all(f["verdict"] == "unknown" for f in result.to_findings())
```

The one configured policy is A5's `I3.cpu_arg.kick_cpu`, narrowed to the
**atomic** `rq.scx.cpus_to_kick` update at `ext.c:8921`. Its object is
`rq:calling_cpu` (`this_rq`), distinct from the target CPU argument. The reviewed
evidence is:

- [`scx_bpf_kick_cpu`, ext.c:8945-8953](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L8945-L8953)
  passes `cpu` by value when `sch` exists. Root invocation remains conditional.
- [`scx_kick_cpu`, ext.c:8881-8932](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L8881-L8932)
  returns at 8887 when `ops_cpu_valid(sch, cpu, NULL)` is false. The bypass at
  8899 and idle skip at 8915 go to IRQ restore at 8931. The non-idle branch
  reaches 8921; the idle branch reaches a **different mask** at 8919.
  `scx_error` at 8910 continues to the trylock and idle-mask code.
- [`__cpu_valid` / `ops_cpu_valid`, ext.c:1083-1105](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1083-L1105)
  establish the range/possible-CPU predicate, not affinity or online status.
- [`cpumask_set_cpu`, cpumask.h:595-603](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/include/linux/cpumask.h#L595-L603)
  uses `set_bit`; the access therefore has an atomic policy.
- [`cpu_possible_mask`, cpumask.h:92-97](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/include/linux/cpumask.h#L92-L97)
  is documented as fixed at boot. [`nr_cpu_ids`, smp.c:992-1002](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/smp.c#L992-L1002)
  is initialized during boot and declared `__read_mostly`, **not**
  `__ro_after_init`. Bounds stability during normal operation remains an
  explicit model assumption, not proof of immutability. No CPU-online or
  affinity predicate receives this assumption automatically.

The proof binds the target `cpu`, `nr_cpu_ids`, `cpu_possible_mask` and calling
`this_rq` separately. The five intervening events on paths to 8921 have explicit
preservation references: IRQ save, current-rq lookup, bypass call/branch and
the idle flag branch. Target CPU is not reassigned or passed by address;
the calling-rq binding is held fixed by IRQ save/restore. These bindings and
normal-runtime stability are hand-reviewed model inputs. There is no invented
build configuration: `config_digest` remains `null`. A reviewed
`configuration_independent=True` asserts only this source control relation,
while the missing-build and opaque-call gaps stay visible.

Observed output contains one `true / established` assessment at 8921 with
`proof_basis: reviewed_source_cfg`, `hand_provided_evidence: true` and
`kernel_safety_claim: false`. Removing the CFG, a required preservation reference
or verified bindings produces UNKNOWN. The other three mask writes and the
remaining I3 rules are not claimed covered. No Linux runtime test was performed.

## Catalog and extractor integration requirements

Reviewed [C1 #48](https://github.com/scx-analyser/scx-analyzer/pull/48),
[C2 #49](https://github.com/scx-analyser/scx-analyzer/pull/49),
[C3 #51](https://github.com/scx-analyser/scx-analyzer/pull/51) at `0cc197d`,
[A2 #52](https://github.com/scx-analyser/scx-analyzer/pull/52) at
`fa34ff0a6866205bc93169909c2b25c3d1b61911`, and
[A5 #56](https://github.com/scx-analyser/scx-analyzer/pull/56) at
`80c465f42d6cfece521e9aaee1b618fd5cecc25b`.
Main currently has C1 and the original catalog contract. C4 imports no unmerged
C2/C3 files. The revised A2 `obligations` interface binds fields, access kinds,
sites and object instances to required predicates/locks, with basis and full
source provenance. A5 provides the explicit kick-mask obligation used in the
source example. These are policy inputs, not automatically verified CFGs or
alias/stability facts. In particular `checked_by` is not proof that an ordered
call returned success, and `on_failure` is not proof of function termination.

The eventual adapter should validate the merged catalog contract, require
matching full source provenance, reject draft/unverified obligations, filter
`applies_to` roots, and accept a separately reviewed mapping of **each** rule's
predicate to its actual access sites and object identities. It must distinguish
policy requirements from descriptive observations or hypotheses even where
`status: source_verified` describes the source. Only then construct policies
and guard annotations. Do not take a Cartesian product of objects/predicates,
assign callback-entry locks to every access, or infer I3 from I1 permissions.
Reporting stays at family `I3`, with the rule id retained in evidence.

At inspection time A5 is a separate PR and `catalog/invariants/I3.yaml` is
absent from main. A3 is I1, not a substitute I3 policy. Automatic ingestion
still needs merged/reviewed obligations and explicit acceptance of each rule's
normative basis; draft hypotheses must never become mandatory policies.
Needed from Epic A: approved field/site obligations,
intended local-vs-global targets, failure/fallback meaning, exact root names,
commit/config/lifetime assumptions, and normative requirements separated from
observed checks. No Epic A catalog or shared schema is edited here.

Needed from [Epic B #28](https://github.com/scx-analyser/scx-analyzer/issues/28):
complete ordered side effects; function entry and exhaustive CFG edges/exits
with source-condition polarity; return values and early exits; direct/indirect
call-site identity; parameter/return/alias bindings; predicate-specific call
effects and stability evidence; source version/full commit/config (or an
explicitly reviewed configuration-independent scope); and explicit boundary/
completeness information. Until agreed, local model annotations express these requirements
without adding unapproved fields to the shared JSON contracts. Branch merges
without reviewed CFG/preservation, fallback target rewriting, indirect targets, loop fixed points,
concurrent mutation and source parsing remain unsupported/UNKNOWN. The exact
course kernel must be confirmed before turning the provisional audit into
production facts. Epic D runtime/enforcement validation is separate work.

## Run and observed synthetic output

Use C1's dependencies (`python -m pip install -r checker/requirements.txt`) and
Python 3.12+. Paths and subprocess tests use portable stdlib facilities.

```text
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
python -m checker check
python -m checker.guards_demo
python -m checker.guards_demo --source-example
git diff --check
```

The schema-valid standalone demo supplies explicit synthetic policies/models.
Its observed assessment rows are:

```text
demo_established  true     established
demo_false        false    false
demo_missing      unknown  missing_check
demo_unknown      unknown  unknown
```

Actual demo output is JSON with `synthetic: true` and
`kernel_safety_claim: false`. The tests cover polarity in both branch senses,
guards after accesses, false/missing/unknown distinctions, early returns and
joins, interprocedural state and evidence, call side effects, aliases, opaque
calls, recursion, deep/diamond graphs and work cuts, incomplete/malformed input,
provenance mismatches, serialization and the unchanged C1 runner/fixtures.
These tests validate the abstract implementation, not real kernel safety.
Polarity is additionally checked against ordinary concrete Boolean branches
for both entry values and both branch senses. A separate concrete invocation
test checks both callee return paths before comparing the caller result.
These oracles do not use the analyzer's transfer/join helpers. Tests isolate
conditional-event, source-location and illustrative-input failures so an
unrelated UNKNOWN cause cannot mask a regression; demo expectations use a
literal root-to-outcome table rather than the implementation's enum inventory.

Issue #35's modeled traversal/guard assessment is implemented. Full catalog
predicate mapping, every-real-path coverage and enforcement validation remain
blocked on A5, Epic B evidence and the agreed course source. This is reviewable
as a C4 foundation; it does not close the production acceptance criteria.
