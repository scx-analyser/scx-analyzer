# Epic A - kfunc inventory & invariant catalog

Owner: Person A · Contract: `contracts/catalog.schema.json`

| File | Task | Content |
|---|---|---|
| `kfuncs.csv` | A1 | every sched_ext kfunc: name, kfunc set, BTF flags, file:line |
| `scripts/inventory.*` | A1 | regenerates `kfuncs.csv` from the pinned kernel |
| `invariants/I1.yaml` | A3 | locking requirements for protected scheduler-state writes (+ supporting entry state) |
| `invariants/I2.yaml` | A4 | task / DSQ ownership and valid state transitions |
| `invariants/I3.yaml` | A5 | CPU / affinity checks before scheduling-state modifications |
| `invariants/I4.yaml` | A6 (stretch) | value ranges & flag combinations |
| `ground_truth.csv` | A7 | manual oracle: kfunc x invariant -> holds? enforced how/where? |

## Catalog contract

A catalog file has `kernel_version` (must equal the call graph's), `kernel_commit` (full
40-hex commit the references were checked against; **required as soon as one rule is
`source_verified`**, and it must equal the known commit of `kernel_version`, e.g. v7.1 =
`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`) and `invariants`: one entry per invariant
**family**, each holding its concrete **rules**. This is the shape the checker runner
(`checker/runner.py`) expects: plug-ins register under the family id (`register("I1", fn)`)
and findings carry it in `invariant`.

Family entry (`invariants[]`):

| Field | Req. | Meaning |
|---|---|---|
| `id` | yes | `I1` locking of protected writes, `I2` ownership / state transitions, `I3` CPU / affinity checks, `I4` value ranges. Unique across `invariants/*.yaml`. Registered checker name and findings `invariant`. |
| `title`, `description` | yes | One-line statement of the family; scope and conventions shared by its rules. |
| `category` | yes | `context_locking`, `ownership_state`, `argument_validity`, `value_range`. |
| `rules` | yes | Non-empty list of rules (below). |

Rule (`invariants[].rules[]`):

| Field | Req. | Meaning |
|---|---|---|
| `id` | yes | `<family>.<slug>[.<slug>]`, lower_snake slugs, e.g. `I1.local_dsq.rq_lock`; must start with the enclosing family id; unique across `invariants/*.yaml`. Finer key for `ground_truth.csv` and finding evidence. |
| `title`, `description` | yes | One-line statement; precise prose incl. exceptions. |
| `category` | yes | Same as the family's. |
| `status` | yes | `draft` or `source_verified`: every cited source observation was checked at `kernel_commit`. It does **not** by itself make a proposed requirement established; that is each obligation's `basis`. A `source_verified` rule cannot contain a `hypothesis` obligation. |
| `role` | no | `protection`: the rule's content is its `obligations` (at least one). `entry_state`: supporting calling-context / callback-entry facts only (`objects: []`, `access: none`, no obligations); never compiled into a field-protection policy. Omitted: generic rule (I2 transitions, I3 predicates). |
| `objects` | yes | `[{struct, fields, access?}]`; `struct.field` equals a call-graph fieldref. Summary of the state the rule is about; every obligation's access must be listed here. |
| `access` | yes | `read`, `write`, `rw`, `none`. |
| `requires` | yes | Rule-level context: `contexts` (one BTF set: {`kfunc_sets` (exactly one), `callbacks`, `program_types`}, conjunctive) **or** `contexts_any_of` (two or more alternative contexts, one per set: the call is allowed if any one alternative allows it; alternatives are never combined); `locks` [{`lock`, `instance`?, `state`, `where`: callback_entry / access_site, `callbacks`?}] = entry facts and kfunc-wide conditions, never field protection; `predicates` [{`expr`, `captures`?, `evaluated_at`?, `checked_by`, `on_failure`}]; `transitions` [{`from`, `to`, `op`, `lock`?, `sites`?}]. |
| `obligations` | no | Field-to-requirement bindings, see below. |
| `applies_to` | yes | Root kfunc names, or `["*"]`. Root applicability only; the transitive write sites are in the obligations. |
| `enforcement` | yes | `expected`, `mechanisms`, `sites`; see "Enforcement semantics". |
| `references` | yes | `[{file, line?, end_line?, symbol?, note?}]`, paths relative to the kernel tree. |
| `notes` | no | Caveats, open questions. |

### Obligations

An obligation binds **one access** to **what protects it**, at named source sites:

```yaml
obligations:
  - id: dst_local_dsq                       # unique in the rule; key "<rule id>/<id>"
    access: {struct: scx_dispatch_q, fields: [list, nr], op: write, instance: dst_dsq}
    sites: [{function: move_local_task_to_local_dsq, file: kernel/sched/ext.c, line: 2261, end_line: 2266}]
    when: "..."                             # optional applicability condition
    requires:
      locks: [{lock: rq, instance: dst_rq, state: held, mode: exclusive}]
      predicates: [{expr: ..., captures: [...], on_failure: return}]
    basis: checked                          # checked | documented | observed | hypothesis
    evidence: [{kind: lockdep_assert, file: kernel/sched/ext.c, line: 2257}]
    paths:                                  # optional concrete call paths from a root kfunc
      - root: scx_bpf_dsq_move_to_local___v2
        entry: [{function: balance_one, file: kernel/sched/ext.c, line: 2890}]
        steps:
          - {function: consume_dispatch_q, file: kernel/sched/ext.c, line: 2543,
             call: "move_local_task_to_local_dsq(sch, p, enq_flags, dsq, rq)",
             held: [{lock: rq, instance: rq}, {lock: dsq, instance: dsq}]}
```

* `access.instance` and every lock `instance` are C expressions in the scope of **each**
  site function, so a lock is bound to the same object the access names (callback rq,
  `task_rq(p)`, a foreign rq and a DSQ lock are never interchangeable). Different variable
  names at different sites mean separate obligations.
* `op`: `write` (store, RMW, list / rbtree update), `atomic` (atomic_* / cmpxchg; does not
  inherit plain-write rules, may carry `ordering`: relaxed / acquire / release / full), `read`.
  `requires` may be omitted only for an atomic with `ordering`.
* All locks and predicates in one obligation, and all obligations on the same access, are
  conjunctive. A consumer that cannot resolve `when` reports UNKNOWN.
* `basis` says why it is a requirement and must be backed by `evidence` of a matching kind:
  `checked` (lockdep_assert / runtime_check on every path), `documented` (kernel_comment),
  `observed` (acquired_on_path / lockdep_assert, but the kernel states no rule),
  `hypothesis` (draft rules only). Epic C should compile only `checked` / `documented`.
* `paths[].steps[].held` lists the tracked locks held at that line (instances in that
  function's scope); the last step is in a site function.

Vocabulary is shared with `checker/context.py` (C2): `kfunc_sets` are the BTF set names its
`KfuncGroup`s map to (`scx_kfunc_ids_enqueue_dispatch` = `ENQUEUE`, ...), `callbacks` are
`ops.<name>` (accepted by `get_context()`), and lock kinds follow the call-graph / C2
vocabulary: `rq`, `task_rq`, `dsq`, `pi_lock`, `scx_dump_lock` and pseudo-locks
`irqs_disabled`, `preempt_disabled`, `rcu_read`. In rule-level `requires.locks`, `rq` without
`instance` is the rq the callback was invoked with (C2's "callback's rq"). `not_held` at
`callback_entry` states the documented precondition of the cited call sites, not an
object-specific absence fact for every ambient lock.
`kernel_version`: a real catalog file (`invariants/*.yaml`) carries the tag it was derived
from (`v7.1`, the course kernel), which must equal `/KERNEL_VERSION` once that file is set.
`contracts/fixtures/catalog.example.yaml` is illustrative and is paired with the call-graph
fixture by the checker tests, so it carries the call-graph fixture's value
(`"TBD (see KERNEL_VERSION)"`) and must change in the same PR as that fixture.

### Enforcement semantics

`enforcement.expected` describes checks that are active on a **production** kernel:

| Mechanism | Kind | Counts toward `expected` |
|---|---|---|
| `kfunc_set`, `verifier` | load / verify time | `static` |
| `lock`, `scx_error`, `warn`, `guard`, `atomic`, `kf_mask` (absent in v7.1) | every kernel at run time | `runtime` |
| `lockdep` | `lockdep_assert_*()`, only with `CONFIG_LOCKDEP` (debug kernels) | nothing: it is listed for completeness but never makes a rule `runtime` |
| `none` | not enforced | only with, and required by, `expected: none` |
| `unknown` | not determined | anything except `expected: none` |

So `static` needs a static mechanism and no production run-time one, `runtime` the reverse,
`static+runtime` both, and `none` neither (`[none]`, optionally plus `lockdep`; never with
`unknown`, since "not enforced" and "not determined" are different conclusions). A rule whose
only run-time check is a lockdep assertion is therefore `static`, or `none` if nothing else
checks it.

`tools/validate_contracts.py` additionally checks: rule id starts with the family id; rule
category = family category; `end_line >= line` everywhere; family and rule ids unique within
and across `invariants/*.yaml`; `applies_to: ["*"]` is not mixed with names; `expected` agrees
with `mechanisms` as in the table above; `kernel_commit` equals the known commit of
`kernel_version`; real catalogs match `KERNEL_VERSION` and catalog fixtures match the
call-graph fixture's `kernel_version`; role constraints; obligation ids unique per rule,
accesses listed in `objects`, `ordering` only on atomics, `basis` backed by evidence, no
`hypothesis` in a `source_verified` rule; and the mechanism enum equals the findings schema's.
Errors are reported as `FAIL <file>: $.json.path: message`. Negative tests:
`python -m unittest discover -s tools/tests` (run in CI).

All `invariants/*.yaml` files must validate against the catalog schema (CI checks this).
Starting point: `contracts/fixtures/catalog.example.yaml`.
