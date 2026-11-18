# Epic A - kfunc inventory & invariant catalog

Owner: Person A · Contract: `contracts/catalog.schema.json`

| File | Task | Content |
|---|---|---|
| `kfuncs.csv` | A1 | every sched_ext kfunc: name, kfunc set, BTF flags, file:line |
| `scripts/inventory.*` | A1 | regenerates `kfuncs.csv` from the pinned kernel |
| `invariants/I1.yaml` | A3 | calling context & locking |
| `invariants/I2.yaml` | A4 | task ownership, DSQ membership, ops_state transitions |
| `invariants/I3.yaml` | A5 | CPU / affinity / argument validity |
| `invariants/I4.yaml` | A6 (stretch) | value ranges & flag combinations |
| `ground_truth.csv` | A7 | manual oracle: kfunc x invariant -> holds? enforced how/where? |

All `invariants/*.yaml` files must validate against the catalog schema (CI checks this).
Starting point: `contracts/fixtures/catalog.example.yaml`.

## Catalog contract

A catalog file has `kernel_version` (must equal the call graph's), optional `kernel_commit`
(40-hex, the commit references were checked against) and `invariants`: one entry per
invariant **family**, each holding its concrete **rules**. This is the shape the checker
runner (`checker/runner.py`) expects: plug-ins register under the family id
(`register("I1", fn)`) and findings carry it in `invariant`.

Family entry (`invariants[]`):

| Field | Req. | Meaning |
|---|---|---|
| `id` | yes | `I1` context & locking, `I2` ownership / DSQ / ops_state, `I3` CPU / affinity / arguments, `I4` value ranges. Unique across `invariants/*.yaml`. Registered checker name and findings `invariant`. |
| `title`, `description` | yes | One-line statement of the family; scope and conventions shared by its rules. |
| `category` | yes | `context_locking`, `ownership_state`, `argument_validity`, `value_range`. |
| `rules` | yes | Non-empty list of rules (below). |
| `notes` | no | Remarks on the family as a whole. |

Rule (`invariants[].rules[]`):

| Field | Req. | Meaning |
|---|---|---|
| `id` | yes | `<family>.<slug>[.<slug>]`, lower_snake slugs, e.g. `I1.dsq_insert.context`; must start with the enclosing family id; unique across `invariants/*.yaml`. Finer key for `ground_truth.csv` and finding evidence. |
| `title`, `description` | yes | One-line statement; precise prose incl. exceptions. |
| `category` | yes | Same as the family's. |
| `status` | yes | `draft` or `source_verified` (all references checked against `kernel_commit`). |
| `objects` | yes | `[{struct, fields, access?}]`; `struct.field` equals a call-graph fieldref (`task_struct` + `scx.ops_state`). May be `[]` for pure context rules. |
| `access` | yes | `read`, `write`, `rw`, `none`. |
| `requires` | yes | At least one of: `contexts` {`kfunc_sets`, `callbacks` (`ops.<name>`), `program_types`}; `locks` [{`lock`, `state`: held/not_held, `where`: callback_entry/access_site, `callbacks`?}]; `predicates` [{`expr`, `checked_by`, `on_failure`: return/error/fallback/continue}]; `transitions` [{`from`, `to`, `op`: set/set_release/cmpxchg, `lock`?, `sites`?}]. |
| `applies_to` | yes | kfunc names, or `["*"]`. |
| `enforcement` | yes | `expected`: `static` / `runtime` / `static+runtime` / `none` / `unknown`; `mechanisms`: `kfunc_set`, `verifier`, `kf_mask`, `lock`, `lockdep`, `scx_error`, `warn`, `guard`, `atomic`, `none`, `unknown` (same enums as `findings.schema.json`); `sites`: file:line refs. |
| `references` | yes | `[{file, line?, end_line?, symbol?, note?}]`, paths relative to the kernel tree. |
| `notes` | no | Caveats, open questions. |

Vocabulary is shared with `checker/context.py` (C2): `kfunc_sets` are the BTF set names its
`KfuncGroup`s map to (`scx_kfunc_ids_enqueue_dispatch` = `ENQUEUE`, ...), `callbacks` are
`ops.<name>` (accepted by `get_context()`), and lock names follow the call-graph / C2
vocabulary: `rq` is the rq the callback was invoked with (C2's "callback's rq"; for task ops
that is `task_rq(p)`), `task_rq` a task argument's rq where it differs, plus `dsq`,
`pi_lock`, `scx_dump_lock` and pseudo-locks `irqs_disabled`, `preempt_disabled`, `rcu_read`.
`kernel_version` of a real catalog is the source it was derived from (`v7.1`, which C2
requires); the fixture keeps the call-graph fixture's TBD value.

`tools/validate_contracts.py` additionally checks the rule-id/family prefix, rule category =
family category, `end_line >= line`, uniqueness of family and rule ids within and across files,
and that the mechanism enum matches the findings schema.
