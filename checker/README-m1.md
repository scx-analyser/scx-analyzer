# M1 integration slice: proposed handoff contract and blocked-input preflight

As inspected on 2026-11-25, the repository has no published Epic B branch, PR
or extraction artifact. Main's `extractor/` contains only its README. Published
`harness-results` artifacts belong to Epic D. There is no extracted graph to
connect to the semantic analyzers yet.

This fallback is based on reviewed main `e3693c818c3c2115c288ec83e25f68f6fc6fe704`
(merged C1). `checker.m1` validates proposed handoff inputs and emits explicit
UNKNOWN readiness coverage. It does not extract events, call C2/C3/C4, compile
catalog policies, verify source/publication, or register a semantic plugin.
The C2/C3/C4 PR branches and shared contracts remain unchanged.

## Scope and source boundary

The requested real roots are:

| Root | Candidate shared-state target, requiring reviewed access bindings |
|---|---|
| `scx_bpf_kick_cpu` | Calling rq's kick masks; existing C4 source example targets the atomic normal-mask update at ext.c:8921. |
| `scx_bpf_cpuperf_set` | Target rq's `scx.cpuperf_target`. |
| `scx_bpf_test_and_clear_cpu_idle` | Idle-mask updates through the idle helper. |

These are discovery targets, not installed policies. No site annotations or
graphs for them are shipped as extracted data. Tests use invented `synthetic.c`
events with `illustrative: true`; an invalid example URL explicitly identifies
the test publication claim as fictitious.

The proposed slice accepts only reference version `v7.1`, full commit
`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`. A mismatch is an explicit input error.
This pins the proposed analysis scope, not a change to `KERNEL_VERSION` or a
claim about another kernel. Main still has the TBD pin; A1 PR #50 records the
course-kernel confirmation. Central pin/configuration reconciliation remains
necessary before real integration. Supplying the expected SHA is not evidence
that a graph was actually extracted from that source.

## Implemented input contract

`preflight(callgraph=None, sidecar=None) -> dict` accepts two separate objects:

1. **Callgraph:** unchanged `contracts/callgraph.schema.json`. No default graph
   is loaded. Only real published B output should be used as extraction in a
   demonstration. Partial/illustrative data can be inspected, but stays UNKNOWN.
   Declared roots must exist as nodes. Missing requested roots receive coverage
   records instead of silently disappearing.
2. **Sidecar:** proposed, checker-owned `m1-sidecar.schema.json`. This is a
   site-binding preflight profile, not a shared contract change or a complete
   executable proof format. A sidecar without its graph is rejected.

Sidecar fields:

| Field | Meaning |
|---|---|
| `format` | Exactly `scxa.m1.sidecar.v1`. |
| `origin` | Exactly `hand_reviewed_source_annotations`; annotations stay separate from extracted facts. |
| `source.version`, `source.commit` | Exact reference version/full kernel commit for every annotation/reference in this sidecar. |
| `graph_sha256` | SHA-256 of UTF-8 canonical JSON: `json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False)`. Matches C4's fingerprint definition. Array order is retained. |
| `extraction_claim` | Claimed repository, full **producer** revision, HTTPS publication URL and generator; optional `.config` SHA-256. The producer revision and kernel commit have different meanings. Claims are never authenticated by this preflight. |
| `sites` | Hand-reviewed site inventory, each bound to root, A2 rule/obligation IDs, function/file/line/event index, field, write/atomic kind, accessed-object identity and source reference. Empty means no supplied site bindings. |

Each site must match an existing defined graph function, exact event kind,
field and location. Its source reference must cover that line in the same
function/file, with repository-relative POSIX paths. Duplicate bindings are
rejected; different objects and different conjunctive obligations remain
separate. Object strings are **claims**, not alias proofs. Event existence does
not establish a root-to-helper path. Unordered `writes` cannot supply an event.
JSON Schema's integral numeric indices (including `0.0`) are accepted for
lookup; fractional/boolean indices are rejected and input annotations stay unchanged.

A matching hash detects stale annotation binding, not incorrect extraction.
A matching URL/generator/config hash proves no publication, source fidelity,
CFG completeness, predicate, lock ownership or object relationship. The profile
therefore rejects injected CFG/proof/completeness flags rather than treating
them as analysis evidence. Those inputs require a separately agreed executable
model/translation once B output and the reviewed analyzer stack are available.

## Output contract

The returned `scxa.m1.preflight.v1` object contains:

- `status: blocked`, `analysis_performed: false`, `analyzers_called: []`.
- `expected_source`: the intended reference, explicitly distinct from verified
  graph provenance.
- `extraction`: the supplied publication claim, or null, with both
  `publication_verified` and `source_verified` false.
- `coverage`: exactly one record per requested root, whether it is present in
  graph roots, and explicit blockers. Root presence is not path coverage.
- `annotations`: whether provided, how many site bindings were structurally
  checked, and `semantics_evaluated: false`.
- `static_findings`: an envelope validated against the **real unchanged**
  findings schema. It contains six UNKNOWN readiness records: I1 and I3 for each
  requested root. They describe requested coverage, including unavailable roots,
  and contain no fabricated access/call path. Matching site claims retain their
  rule/obligation, field, object, source reference, expected commit and graph
  fingerprint in evidence. With no graph, `kernel_version` is `unknown` and
  `callgraph` is omitted. These records are not production-plugin results.
  Each record explicitly states `record_kind: requested_coverage` and
  `applicability: unknown`; it does not assert that the family applies to the
  root. Publication/source verification, site-binding trust and runtime
  inclusion are false **inside the envelope**, with annotation origin retained,
  so exporting it independently cannot lose these qualifications.
- `runtime_results`: excluded, with no correlation performed.

There is no I2/C5 analysis in this slice. Neither permissions nor callback entry
locks constitute a field-protection policy. The no-input report has no source
access facts, locks, CFG edges or asserted completeness to bind or evaluate.

## Exact missing handoff inputs and API translation

Inspected API revisions: C2 `dc7e147` (#49), C3 `0cc197d` (#51), C4 `fe11573`
(#54), revised A2 `fa34ff0` (#52), and A5 `80c465f` (#56). No unmerged analyzer
code is copied into this branch. The current base has the original C1 catalog
schema, so a real A2 catalog adapter is pending.

| Consumer | Required input / future mapping |
|---|---|
| C1 `runner.check(callgraph, catalog)` | Actual graph plus a catalog valid against the agreed merged A2 schema, matching full provenance. Load only explicitly enabled reviewed family plugins. An empty registry is not a safety claim. |
| C2 `context.get_context(...)` | Explicit BPF callback, program type, attachment, full source version/commit and enabled CONFIGs. Map subject-task/cpu/object identities explicitly. Kernel kfunc roots alone do not identify their BPF caller context. These scenario facts may come from D, rather than B's kernel graph. |
| C3 `lockset.analyze(...)` | Reviewed `ProtectionPolicy`; precise symbolic-to-object lock bindings and modes; justified entry state; `Provenance`; per-event `ControlSemantics`; complete ordered calls, writes/atomics, successful acquisitions and all releases/cleanup paths. Never turn lockdep assertions into ownership. |
| C4 `guards.analyze(...)` | Exact root/site/object `GuardPolicy`s; `Model` bound to graph/config/source; complete per-function evidence; guard polarity and exits; argument/object bindings, stability/preservation and, for branched sites, reviewed `DominanceEvidence`. Mark branched functions nonlinear. |

Epic B's minimum deliverable is schema-valid extraction for the three roots,
including recursive located direct calls, ordered side effects and explicit
opaque/indirect boundaries. The supplemental evidence must identify function
entry, both branch outcomes, joins/exits, scoped releases, conditional effects,
parameter/return/object relationships, build/configuration, extraction limits
and completeness. CFG order cannot be reconstructed from source line order or
LLVM basic-block print order. Missing scope releases or uncertain aliases stay
UNKNOWN. Unsupported returns/fallback target rewriting require explicit gaps.

A/C must supply a reviewed catalog-to-policy translation, not ask B to invent
obligations. Validate actual A2 `obligations`, resolve root applicability and
every `when`, predicate, capture, access kind, site, object and lock mode. Keep
`entry_state`, draft/hypothesis and merely observed facts out of mandatory
protection policies. `source_verified` alone does not establish an obligation.
WARN/reporting-only checks do not imply prevention. C3 policies currently match
function/field/access, so a site-specific rule cannot be widened unless it is
proved uniform at every matching site. All applicable conjuncts remain required.

Construct module-qualified C2/C3/C4 types explicitly; similarly named source
and lock identity classes are not interchangeable. Retain all UNKNOWN coverage
and budgets. Only then dispatch the analyzers and use their schema-compatible
UNKNOWN adapters. Defining reviewed kernel-level HOLDS/VIOLATED aggregation is
separate work; it is not needed to show honest model diagnostics in M1.

## D4 remains separate

PR #60's [published run](https://github.com/scx-analyser/scx-analyzer/actions/runs/45254243117)
has D4 pass/fail observations for these three roots. Those observations are
runtime harness results, not extracted events or static protection evidence.
This preflight neither downloads nor imports them. A future report may join on
root/family/rule plus exact kernel/configuration/scenario identity, preserving
the independent static and runtime columns. A runtime error does not prove
that every relevant write was prevented; an `ok` result does not prove safety.

## Commands and observed results

Python 3.12+ and C1's `checker/requirements.txt` dependencies suffice.

```text
python -m checker.m1
python -m unittest discover -s checker/tests -p test_m1.py -v
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
python -m checker check
git diff --check
```

The first command emits JSON: `blocked`, no analyzers called, six UNKNOWN
readiness records and missing-extraction/sidecar/policy-adapter/dispatch blockers.
Its exit code is **3 (blocked)**, not success. Malformed/mismatched inputs use
**2** with a concise error/path. No command substitutes the illustrative fixture
for missing extraction. A future actual handoff can be structurally inspected
with `python -m checker.m1 --callgraph <published.json> --sidecar <reviewed.json>`;
this still returns blocked because structural consistency is not semantic
integration. Extract `static_findings` when a consumer needs only the shared
findings envelope; the whole preflight report has its own wrapper contract.

Current tests exercise consistency, source/hash mismatches, exact sites,
missing roots/events, separate identities/obligations, non-inference of paths,
publication claims and runtime separation. They establish host contract
behavior, not real Linux analysis. Until B publishes extraction and the A/C
model/adapter inputs are reviewed, the 3-root end-to-end goal remains blocked.
