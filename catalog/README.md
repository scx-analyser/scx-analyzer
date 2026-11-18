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
(40-hex, the commit references were checked against) and `invariants`. Each entry has:

| Field | Req. | Meaning |
|---|---|---|
| `id` | yes | `<family>.<slug>[.<slug>]`, lower_snake slugs, e.g. `I1.dsq_insert.context`; unique across `invariants/*.yaml`. Findings and `ground_truth.csv` use it. |
| `family` | yes | `I1` context & locking, `I2` ownership / DSQ / ops_state, `I3` CPU / affinity / arguments, `I4` value ranges; must prefix `id`. Checker plug-ins register per family. |
| `title`, `description` | yes | One-line statement; precise prose incl. exceptions. |
| `category` | yes | `context_locking`, `ownership_state`, `argument_validity`, `value_range`. |
| `status` | yes | `draft` or `source_verified` (all references checked against `kernel_commit`). |
| `objects` | yes | `[{struct, fields, access?}]`; `struct.field` equals a call-graph fieldref (`task_struct` + `scx.ops_state`). May be `[]` for pure context rules. |
| `access` | yes | `read`, `write`, `rw`, `none`. |
| `requires` | yes | At least one of: `contexts` {`kfunc_sets`, `callbacks` (`ops.<name>`), `program_types`}; `locks` [{`lock`, `state`: held/not_held, `where`: callback_entry/access_site, `callbacks`?}]; `predicates` [{`expr`, `checked_by`, `on_failure`: return/error/fallback/continue}]; `transitions` [{`from`, `to`, `op`: set/set_release/cmpxchg, `lock`?, `sites`?}]. |
| `applies_to` | yes | kfunc names, or `["*"]`. |
| `enforcement` | yes | `expected`: `static` / `runtime` / `static+runtime` / `none` / `unknown`; `mechanisms`: `kfunc_set`, `verifier`, `kf_mask`, `lock`, `lockdep`, `scx_error`, `warn`, `guard`, `atomic`, `none`, `unknown` (same enums as `findings.schema.json`); `sites`: file:line refs. |
| `references` | yes | `[{file, line?, end_line?, symbol?, note?}]`, paths relative to the kernel tree. |
| `notes` | no | Caveats, open questions. |

Lock names follow the call-graph vocabulary (`rq`, `task_rq`, `dsq`, `pi_lock`, `scx_dump_lock`) plus pseudo-locks
`irqs_disabled`, `preempt_disabled`, `rcu_read`. `tools/validate_contracts.py` additionally checks the id/family prefix,
`end_line >= line`, id uniqueness across files and that the mechanism enum matches the findings schema.
