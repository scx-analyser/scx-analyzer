# C2: provisional execution contexts

`checker.context` supplies typed, immutable entry facts for later C3 analysis. It records callback name, program type, per-group permission (`ALLOWED`, `DENIED`, `UNKNOWN`), lock facts, source references, and verification status. It emits no findings and registers no I1 checker. C1's `check(callgraph, catalog)` API and normal CLI are unchanged.

## Source and version boundary

The only inspected reference is upstream **Linux v7.1**, commit `8cd9520d35a6c38db6567e97dd93b1f11f185dc6`. It is **provisional**: the team's `KERNEL_VERSION` remains TBD. Every query requires `source_version`; a different version, a custom-version suffix, or the existing fixture's TBD marker raises `SourceVersionMismatch`. Supplying `v7.1` selects this reference explicitly; it does not verify a caller's source tree or select the team's kernel.

`SOURCE_VERIFIED` means inspected source supports the permission rule. It does not mean runtime validation, a successful verifier run, or proof of kernel safety. Lock claims have their own evidence; unknown locks remain unknown even in a source-verified permission context.

## Permissions

The model follows `scx_kf_allow_flags[]` and the final `scx_kfunc_context_filter()` in v7.1, rather than the older `scx_kf_allowed()` illustration. These are the context-sensitive groups; `ANY` and `IDLE` are handled separately.

| Callback | Context-sensitive groups | Exact source row in `scx_kf_allow_flags[]` |
|---|---|---|
| `select_cpu` | `SELECT_CPU`, `ENQUEUE` | [ext.c:9829](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9829) |
| `enqueue` | `SELECT_CPU`, `ENQUEUE` | [ext.c:9830](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9830) |
| `dispatch` | `ENQUEUE`, `DISPATCH` | [ext.c:9831](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9831) |
| `cpu_release` | `CPU_RELEASE` | [ext.c:9832](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9832) |
| `init_task` | `UNLOCKED` | [ext.c:9833](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9833) |
| `dump` | `UNLOCKED` | [ext.c:9834](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9834) |

`ENQUEUE` names the `scx_kfunc_ids_enqueue_dispatch` BTF set; it is not a separate enqueue-only set. Each `GroupPermission` exposes its actual registration-set name and source locations.

Permissions include the program-type registrations in [`scx_init()`](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9936-L9956) and [`scx_idle_init()`](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext_idle.c#L1468-L1520), together with the [final filter](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9860-L9917):

- Identified SCX `STRUCT_OPS`: the row above plus `ANY` and `IDLE`.
- `SYSCALL`: `UNLOCKED`, `SELECT_CPU`, `ANY`, `IDLE`; query with callback `None`.
- `TRACING`: `ANY`, `IDLE`; `SELECT_CPU` is deliberately not registered for tracing.
- Non-SCX struct_ops (`scx_attachment=False`): all modeled SCX groups denied, including `ANY`/`IDLE`.
- Unresolved attachment (`scx_attachment=None`), unmodeled callback, or unmodeled program type: unknown. The filter's early pass before attachment resolution is not treated as a final grant. Only the six named callbacks are modeled; even other existing callbacks return unknown.

A kfunc may belong to multiple sets. For example, select-CPU helpers also appear in the [unlocked set](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L8814-L8825). `permission_for_groups()` uses OR semantics: one confirmed allowed membership suffices. A denial requires `complete=True` and every membership to be denied; an empty/incomplete inventory or unknown membership otherwise remains unknown. Membership inventories are a caller/catalog responsibility. Group permission alone does not establish full verifier acceptance: argument, RCU, sleepability, lifetime, and other conditions are outside C2.

BTF attributes are separate from group membership, registration hooks, and callback entry locks. For example, the unlocked set contains `scx_bpf_create_dsq` with `KF_SLEEPABLE` and other functions with `KF_RCU`; the [select-CPU set](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext_idle.c#L1499-L1503) also carries per-function flags. C2 does not evaluate those attributes. An `ALLOWED` group result proves neither a sleepable calling context nor an RCU critical section or lock ownership.

## Entry locks are separate facts

`LockState` represents known-held, known-not-held, and unknown. Known states require source evidence. No known-not-held fact is asserted in this initial model; absence of a fact returns unknown, rather than an empty lockset or a claim that no locks are held.

| Callback | Recorded known-held lock | Evidence |
|---|---|---|
| `enqueue` | callback's `rq` | `do_enqueue_task()` [ext.c:1944-1948](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1944-L1948), through `SCX_CALL_OP_TASK` and `SCX_CALL_OP` |
| `dispatch` | callback's `rq` | `scx_dispatch_sched()` [ext.c:2839-2844](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2839-L2844), through `SCX_CALL_OP` |
| `cpu_release` | callback's `rq` | `switch_class()` [ext.c:3047-3054](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3047-L3054), through `SCX_CALL_OP` |
| `dump` | `scx_dump_lock` | `scx_dump_state()` acquires the function-scoped guard at [ext.c:6337](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6321-L6337) before calling `ops.dump()` at [ext.c:6365](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6363-L6367) |

The rq evidence chain is [`SCX_CALL_OP_TASK` (518-524)](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L518-L524), [`SCX_CALL_OP` (474-485)](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L474-L485), and [`update_locked_rq()` (458-468)](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L458-L468), which calls `lockdep_assert_rq_held()` before callback entry. These are source-declared entry preconditions, not observations that lockdep was enabled or that an execution satisfied them. `rq` denotes that specific callback argument; it does not grant ownership of every runqueue or automatically alias `task_rq`.

`select_cpu`/`init_task` rq state, `pi_lock`, `dsq`, and other unrecorded locks are unknown. Neither an `UNLOCKED` permission nor passing `NULL` as `locked_rq` proves any lock is absent. In particular, the `dump` facts show why `UNLOCKED` must not be interpreted as lock-free execution.

## Querying and inspection

```python
from checker.context import KfuncGroup, LockState, Permission, get_context

entry = get_context("dispatch", source_version="v7.1")
assert entry.permission(KfuncGroup.DISPATCH) is Permission.ALLOWED
assert entry.lock("rq").state is LockState.KNOWN_HELD
assert entry.lock("dsq").state is LockState.UNKNOWN
```

The assertions above exercise the model, not a kernel. Compare enum values explicitly; decisions are not boolean safety results. Boolean checks on `Permission`, `GroupPermission`, `LockState`, or `LockFact` raise `TypeError`, so `if entry.permission(...)` and `if entry.lock(...)` cannot silently promote an unknown result into permission or lock ownership. Compare `.decision` or `.state` explicitly when using the fact objects. JSON exports use strings, which consumers must also compare explicitly. `ops.dispatch` is accepted as an alias for `dispatch`.

```text
python -m checker.context --source-version v7.1
```

Observed output:

```text
PROVISIONAL Linux v7.1 reference (8cd9520d35a6c38db6567e97dd93b1f11f185dc6)
CALLBACK       CONTEXT GROUPS           ENTRY LOCK FACTS
cpu_release    CPU_RELEASE              rq=known_held
dispatch       DISPATCH,ENQUEUE         rq=known_held
dump           UNLOCKED                 scx_dump_lock=known_held
enqueue        ENQUEUE,SELECT_CPU       rq=known_held
init_task      UNLOCKED                 unknown
select_cpu     ENQUEUE,SELECT_CPU       unknown
ANY and IDLE also permitted for these SCX callbacks; other lock states remain unknown.
Source-inspected entry facts only; KERNEL_VERSION remains TBD; no invariant verdicts.
```

Use `python -m checker.context --source-version v7.1 --json` for deterministic JSON with evidence. This inspection format is internal to Epic C, not a change to the shared findings schema. `--source-version TBD` exits 2 without a table. Validation commands remain:

```text
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
python -m checker check
```

## C3 integration boundary

C3 should pass the actual callgraph/catalog version to this API and stop or propagate unknown on a version mismatch; the current TBD fixture cannot establish v7.1 facts. After cross-epic agreement on a kernel and A3's catalog facts, confirm kfunc memberships and callback identities, bind symbolic locks to the correct objects, and use supported entry facts to initialize lockset analysis while preserving unknown states. Entry facts do not assert that a lock remains held after calls which can drop or transfer it. Interprocedural propagation, path-sensitive checks, I1 verdicts, and guard analysis remain later work. No LLVM, verifier, VM, or runtime BPF analysis is included here.
