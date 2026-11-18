# Epic A - kfunc inventory & invariant catalog

Owner: Person A · Contract: `contracts/catalog.schema.json`

| File | Task | Content |
|---|---|---|
| `kfuncs.csv` | A1 | every sched_ext kfunc: name, kfunc set, BTF flags, file:line |
| `scripts/inventory.py` | A1 | regenerates `kfuncs.csv` from the pinned kernel |
| `invariants/I1.yaml` | A3 | calling context & locking |
| `invariants/I2.yaml` | A4 | task ownership, DSQ membership, ops_state transitions |
| `invariants/I3.yaml` | A5 | CPU / affinity / argument validity |
| `invariants/I4.yaml` | A6 (stretch) | value ranges & flag combinations |
| `ground_truth.csv` | A7 | manual oracle: kfunc x invariant -> holds? enforced how/where? |

All `invariants/*.yaml` files must validate against the catalog schema (CI checks this).
Starting point: `contracts/fixtures/catalog.example.yaml`.

## kfunc inventory (`kfuncs.csv`)

Pinned kernel: see `/KERNEL_VERSION` (currently **v7.1**). Every line number in
`kfuncs.csv` refers to that tag.

### Regenerating

```sh
cd ~/linux && git checkout v7.1          # must match KERNEL_VERSION
cd <scx-analyzer>
python3 catalog/scripts/inventory.py     # kernel tree: $KERNEL_SRC, else ~/linux
# or: python3 catalog/scripts/inventory.py --kernel-src /path/to/linux [--output -]
```

Python 3 stdlib only. The script scans every `*.c`/`*.h` under `kernel/sched/`
for `BTF_KFUNCS_START(set) ... BTF_ID_FLAGS(func, name, flags) ... BTF_KFUNCS_END(set)`
blocks and for `__bpf_kfunc` definitions, prints per-set counts to stderr, and
warns if the kernel tree is not at the `KERNEL_VERSION` tag or a set entry has
no `__bpf_kfunc` definition. Output is sorted by `(name, kfunc_set)`, so reruns
are byte-identical.

Sanity check: `grep -c '^BTF_ID_FLAGS(func' kernel/sched/ext.c kernel/sched/ext_idle.c`
gives 52 + 14 = 66, equal to the number of CSV rows.

### Columns

| Column | Meaning |
|---|---|
| `name` | kfunc symbol as registered in BTF |
| `kfunc_set` | BTF id set (`scx_kfunc_ids_*`); a kfunc in several sets has one row per set |
| `flags` | `KF_*` flags from `BTF_ID_FLAGS`, `\|`-separated, empty if none |
| `config` | enclosing `#ifdef` condition of the set entry, empty if unconditional |
| `def_location` | `file:line` of the `__bpf_kfunc` definition (line of `__bpf_kfunc`) |
| `set_entry_location` | `file:line` of the `BTF_ID_FLAGS` entry |

### v7.1 summary

66 rows, 59 unique kfuncs, 7 sets. Only `kernel/sched/ext.c` and
`kernel/sched/ext_idle.c` contain kfunc sets in v7.1.

| Set (file) | Rows | Registered for prog types | Callable from (SCX struct_ops callbacks) |
|---|---|---|---|
| `scx_kfunc_ids_enqueue_dispatch` (ext.c) | 4 | STRUCT_OPS | `select_cpu`, `enqueue`, `dispatch` |
| `scx_kfunc_ids_dispatch` (ext.c) | 9 | STRUCT_OPS | `dispatch` |
| `scx_kfunc_ids_cpu_release` (ext.c) | 1 | STRUCT_OPS | `cpu_release` |
| `scx_kfunc_ids_unlocked` (ext.c) | 8 | STRUCT_OPS, SYSCALL | `init_task`, `dump`, `cgroup_{init,exit,prep_move,cancel_move,set_weight,set_bandwidth,set_idle}` (with `CONFIG_EXT_GROUP_SCHED`), `sub_attach`, `sub_detach`, `cpu_online`, `cpu_offline`, `init`, `exit` |
| `scx_kfunc_ids_select_cpu` (ext_idle.c) | 3 | STRUCT_OPS, SYSCALL | `select_cpu`, `enqueue` |
| `scx_kfunc_ids_idle` (ext_idle.c) | 11 | STRUCT_OPS, TRACING, SYSCALL | any SCX callback |
| `scx_kfunc_ids_any` (ext.c) | 30 | STRUCT_OPS, TRACING, SYSCALL | any SCX callback |

How this is enforced (v7.1): sets are registered with `register_btf_kfunc_id_set()`
in `scx_init()` (ext.c) and `scx_idle_init()` (ext_idle.c). Every set carries
`.filter = scx_kfunc_context_filter` (ext.c), which decides at verify time:

- kfunc not in any SCX set: allowed (the filter does not govern it);
- `BPF_PROG_TYPE_SYSCALL`: `unlocked`, `select_cpu`, `idle`, `any` allowed;
- other non-STRUCT_OPS types (TRACING): only `any` and `idle`;
- STRUCT_OPS for a struct other than `sched_ext_ops`: all SCX kfuncs rejected;
- `sched_ext_ops` callbacks: `any`/`idle` always allowed; context-sensitive sets
  are allowed per callback through the `scx_kf_allow_flags[]` table
  (`SCX_KF_ALLOW_{UNLOCKED,CPU_RELEASE,DISPATCH,ENQUEUE,SELECT_CPU}`), which is
  what the last column above is derived from. Callbacks not in the table
  (e.g. `running`, `stopping`, `tick`, `enable`) only get `any`/`idle`.

Kfuncs in several sets: `scx_bpf_dsq_move{,_vtime,_set_slice,_set_vtime}`
(dispatch + unlocked) and `__scx_bpf_select_cpu_and`, `scx_bpf_select_cpu_and`,
`scx_bpf_select_cpu_dfl` (select_cpu + unlocked; the unlocked entries live in
ext.c while the definitions and the select_cpu set are in ext_idle.c).

Config-dependent entries: `scx_bpf_sub_dispatch` (`CONFIG_EXT_SUB_SCHED`),
`scx_bpf_task_cgroup` (`CONFIG_CGROUP_SCHED`).

`KF_IMPLICIT_ARGS` marks kfuncs whose trailing `const struct bpf_prog_aux *aux`
parameter is supplied by the verifier and hidden from the BPF-side prototype.

### Naming drift (read before comparing with older docs/papers/schedulers)

From `tools/sched_ext/include/scx/compat.bpf.h` and the `COMPAT:` comments in
the kernel at v7.1:

- **v6.13**: `scx_bpf_dispatch[_vtime]()` -> `scx_bpf_dsq_insert[_vtime]()`;
  `scx_bpf_consume()` -> `scx_bpf_dsq_move_to_local()`;
  `scx_bpf_dispatch[_vtime]_from_dsq[_set_slice|_set_vtime]()` ->
  `scx_bpf_dsq_move[_vtime|_set_slice|_set_vtime]()`. None of the old
  `scx_bpf_dispatch*`/`scx_bpf_consume` names exist in v7.1
  (`scx_bpf_dispatch_nr_slots` and `scx_bpf_dispatch_cancel` were never renamed).
- **v6.19**: `scx_bpf_dsq_insert()` returns `bool`; the kernel symbol is
  `scx_bpf_dsq_insert___v2`, the old void `scx_bpf_dsq_insert` is kept as COMPAT
  ("removed in v6.23").
- **v6.19**: argument-packing variants `__scx_bpf_dsq_insert_vtime` and
  `__scx_bpf_select_cpu_and` (args struct, BPF parameter limit); the unpacked
  `scx_bpf_dsq_insert_vtime` / `scx_bpf_select_cpu_and` are COMPAT
  ("removed in v6.23" / "v6.22").
- **v6.19**: `scx_bpf_reenqueue_local___v2` (void, callable anywhere, in `any`);
  the original `scx_bpf_reenqueue_local` (u32, `cpu_release` only) is kept.
  **v6.20**: `scx_bpf_dsq_reenq()` generalises both.
- **v6.18/v6.19**: `scx_bpf_cpu_rq()` is deprecated (runtime warning); use
  `scx_bpf_locked_rq()` or `scx_bpf_cpu_curr()`. `scx_bpf_dsq_peek()` added;
  `scx_bpf_task_set_slice()` / `scx_bpf_task_set_dsq_vtime()` replace direct
  writes to `p->scx.slice` / `p->scx.dsq_vtime` (now deprecated).
- **v7.1**: `scx_bpf_dsq_move_to_local___v2(dsq_id, enq_flags)`; the
  one-argument `scx_bpf_dsq_move_to_local` stays as COMPAT. New
  `scx_bpf_sub_dispatch()` (sub-schedulers).
- Mainline went v6.19 -> v7.0, so the COMPAT symbols marked "removed in
  v6.22/v6.23" are all still present in v7.1. `___v2`/`__`-prefixed names and
  their COMPAT twins are distinct BTF kfuncs (distinct rows).
- Calling-context restrictions are enforced at verify time by
  `scx_kfunc_context_filter()` + `scx_kf_allow_flags[]`; the runtime
  `scx_kf_allowed()` / `current->scx.kf_mask` checks of older kernels no longer
  exist in v7.1. Keep this in mind for invariant I1.
