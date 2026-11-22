# C2: provisional execution-context facts

`checker.context` supplies immutable, typed entry facts for later shared-state
analysis. It emits no findings and registers no I1 checker. C1's
`check(callgraph, catalog) -> list[Finding]`, CLI, and shared contracts are unchanged.
**Callback permissions alone do not meet the TA's shared scheduler-state
modification requirement and are not a kernel-safety verdict.**

## Source and trust boundary

The sole inspected reference is **upstream Linux v7.1**, commit
`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`. This remains **provisional**.
The course kernel has not been established; the repository's `KERNEL_VERSION`
remains TBD. PR #50's proposed pin does not establish team/course agreement.

Every query requires `source_version`. `source_commit` defaults to the pinned
reference above for backwards-compatible reference inspection. Any supplied
version **or commit** mismatch raises `SourceVersionMismatch`, including TBD,
custom suffixes, abbreviated hashes, and another commit labeled v7.1. Selecting
the reference does not authenticate a caller's tree. A downstream analyzer must
supply its actual version **and full commit**, verify provenance/configuration,
and stop or propagate UNKNOWN if those cannot be established. Do not substitute
the reference defaults for missing input provenance.

Each `SourceReference`, including those on lock facts, carries file, symbol,
inclusive line range, version, commit, and a commit-pinned URL property.
`SOURCE_VERIFIED` means source inspection supports the modeled rule.
Entry preconditions assume normal kernel control flow and kernel locking
contracts; they are neither observed executions nor production enforcement.

## Complete callback inventory and permissions

The inventory was discovered from **all 37 function-pointer declarations** in
[`struct sched_ext_ops`, ext_internal.h:292-797](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext_internal.h#L292-L797),
rather than by assuming a callback count. Previously only `select_cpu`, `enqueue`,
`dispatch`, `cpu_release`, `init_task`, and `dump` were recognized.
There are 29 unconditional declarations and eight conditional declarations.

The table below shows all source-declared callbacks. Context groups exclude
`ANY`/`IDLE`, which the final filter also permits for every **verified SCX**
callback. “Absent” means a recognized callback with **zero context flags** in
[`scx_kf_allow_flags[]`, ext.c:9823-9850](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9823-L9850);
it does not mean an unrecognized callback. Such callbacks deny the five
context-sensitive groups while allowing `ANY`/`IDLE`.

An asterisk marks `CONFIG_EXT_GROUP_SCHED`. These eight callbacks stay UNKNOWN
by default, including entry locks, until the query explicitly supplies
`enabled_configs=("CONFIG_EXT_GROUP_SCHED",)`. This is the caller's attestation
about its build, not configuration discovery. `cgroup_move` is conditional but
has **no** UNLOCKED row. `sub_attach`/`sub_detach` are unconditional declarations;
their invocation paths are under `CONFIG_EXT_SUB_SCHED`. `core_sched_before`
invocation is under `CONFIG_SCHED_CORE`. Entry facts apply when the kernel actually
invokes a callback, not merely because a callback/program was attached.

| Callback | Context groups | Allow row (ext.c) | Known entry facts; other locks UNKNOWN | All invocation sites (ext.c unless idle:) |
|---|---|---|---|---|
| `cgroup_cancel_move` * | `UNLOCKED` | [9839](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9839) | UNKNOWN | [4389-4390](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4389-L4390), [4430-4431](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4430-L4431) |
| `cgroup_exit` * | `UNLOCKED` | [9837](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9837) | UNKNOWN | [4345](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4345-L4345), [4708](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4708-L4708) |
| `cgroup_init` * | `UNLOCKED` | [9836](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9836) | UNKNOWN | [4323-4324](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4323-L4324), [4739-4740](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4739-L4740) |
| `cgroup_move` * | none | absent | `rq` held (task:p); `pi_lock` held (task:p) | [4412-4414](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4412-L4414) |
| `cgroup_prep_move` * | `UNLOCKED` | [9838](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9838) | UNKNOWN | [4374-4375](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4374-L4375) |
| `cgroup_set_bandwidth` * | `UNLOCKED` | [9841](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9841) | `scx_cgroup_ops_rwsem` held (global:scx_cgroup_ops_rwsem; read mode) | [4480-4481](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4480-L4481) |
| `cgroup_set_idle` * | `UNLOCKED` | [9842](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9842) | `scx_cgroup_ops_rwsem` held (global:scx_cgroup_ops_rwsem; read mode) | [4460](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4460-L4460) |
| `cgroup_set_weight` * | `UNLOCKED` | [9840](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9840) | `scx_cgroup_ops_rwsem` held (global:scx_cgroup_ops_rwsem; read mode) | [4445](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4445-L4445) |
| `core_sched_before` | none | absent | `rq` held (task:a) | [3302-3305](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3302-L3305) |
| `cpu_acquire` | none | absent | `rq` held (cpu:cpu) | [2903](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2903-L2903) |
| `cpu_offline` | `UNLOCKED` | [9847](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9847) | UNKNOWN | [3413](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3413-L3413) |
| `cpu_online` | `UNLOCKED` | [9846](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9846) | UNKNOWN | [3411](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3411-L3411) |
| `cpu_release` | `CPU_RELEASE` | [9832](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9832) | `rq` held (cpu:cpu) | [3054](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3054-L3054) |
| `dequeue` | none | absent | `rq` held (task:p) | [1453](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1453-L1453) |
| `disable` | none | absent | `rq` held (task:p) | [3659](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3659-L3659) |
| `dispatch` | `DISPATCH`, `ENQUEUE` | [9831](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9831) | `rq` held (cpu:cpu) | [2840](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2840-L2840), [2844](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2844-L2844) |
| `dump` | `UNLOCKED` | [9834](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9834) | `scx_dump_lock` held (global:scx_dump_lock) | [6365](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6365-L6365) |
| `dump_cpu` | none | absent | `rq` held (cpu:cpu); `scx_dump_lock` held (global:scx_dump_lock) | [6425](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6425-L6425) |
| `dump_task` | none | absent | `rq` held (cpu:dumped); `scx_dump_lock` held (global:scx_dump_lock) | [6301](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6301-L6301) |
| `enable` | none | absent | `rq` held (task:p) | [3637](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3637-L3637) |
| `enqueue` | `ENQUEUE`, `SELECT_CPU` | [9830](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9830) | `rq` held (task:p) | [1948](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L1948-L1948) |
| `exit` | `UNLOCKED` | [9849](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9849) | UNKNOWN | [5899](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L5899-L5899), [6016](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6016-L6016) |
| `exit_task` | none | absent | `rq` held (task:p); `pi_lock` held (task:p) | [3697](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3697-L3697), [3713](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3713-L3713) |
| `init` | `UNLOCKED` | [9848](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9848) | `scx_enable_mutex` held (global:scx_enable_mutex) | [6903](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6903-L6903), [7211](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L7211-L7211) |
| `init_task` | `UNLOCKED` | [9833](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9833) | `pi_lock` not held (task:p); rq UNKNOWN | [3572](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3572-L3572) |
| `quiescent` | none | absent | `rq` held (task:p) | [2186](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2186-L2186) |
| `runnable` | none | absent | `rq` held (task:p) | [2052](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2052-L2052) |
| `running` | none | absent | `rq` held (task:p) | [2982](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2982-L2982) |
| `select_cpu` | `ENQUEUE`, `SELECT_CPU` | [9829](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9829) | `pi_lock` held (task:p) | [3339](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3339-L3339) |
| `set_cpumask` | none | absent | `rq` held (task:p) | [3389](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3389-L3389), [3930](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3930-L3930) |
| `set_weight` | none | absent | `rq` held (task:p) | [3640](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3640-L3640), [3909](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3909-L3909) |
| `stopping` | none | absent | `rq` held (task:p) | [2182](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2182-L2182), [3072](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3072-L3072) |
| `sub_attach` | `UNLOCKED` | [9844](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9844) | `scx_enable_mutex` held (global:scx_enable_mutex) | [7228-7229](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L7228-L7229) |
| `sub_detach` | `UNLOCKED` | [9845](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9845) | `scx_enable_mutex` not held (global:scx_enable_mutex) | [5894-5895](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L5894-L5895) |
| `tick` | none | absent | `rq` held (task:p) | [3531](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3531-L3531) |
| `update_idle` | none | absent | `rq` held (cpu:cpu) | [idle:792](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext_idle.c#L792-L792) |
| `yield` | none | absent | `rq` held (task:from) | [2208](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2208-L2208), [2219](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L2219-L2219) |

Every `CallbackSpec` exposes the exact declaration, required configuration, and
all invocation-site references. The inventory includes 48 invocation sites across
the 37 callbacks, including multiple `exit_task`, `set_weight`, `set_cpumask`,
`yield`, `stopping`, `dispatch`, `init`, and `exit` paths.

Permissions use the **final**
[`scx_kfunc_context_filter()`, ext.c:9860-9917](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9860-L9917)
intersected with
[`scx_init()` registrations, ext.c:9936-9956](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L9936-L9956)
and
[`scx_idle_init()`, ext_idle.c:1511-1520](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext_idle.c#L1511-L1520):

| Program/attachment | Available groups |
|---|---|
| Identified SCX STRUCT_OPS callback | Its verified row plus ANY/IDLE |
| SYSCALL (callback `None`) | UNLOCKED, SELECT_CPU, ANY, IDLE |
| TRACING (callback `None`) | ANY, IDLE |
| Non-SCX STRUCT_OPS | All modeled SCX groups DENIED, including ANY/IDLE |
| Unknown callback, program type, attachment, or required configuration | UNKNOWN; no entry locks inferred |

`scx_attachment=None` represents unresolved attachment identity. The temporary
early filter bypass before `st_ops` resolution is not a final permission grant.
Unrecognized names receive no default ANY/IDLE rights.
`ops.dispatch` is an accepted spelling for `dispatch`.

`ENQUEUE` maps to `scx_kfunc_ids_enqueue_dispatch`; the other enum values
map to their correspondingly named BTF sets. Each `GroupPermission` exposes
the actual set name. A kfunc can have multiple memberships: four `scx_bpf_dsq_move*`
helpers are DISPATCH + UNLOCKED, and three select-CPU helpers are SELECT_CPU +
UNLOCKED. `permission_for_groups()` uses OR semantics: one verified allowed
membership suffices. DENIED requires `complete=True` and all memberships denied;
empty, incomplete, or unresolved memberships otherwise remain UNKNOWN.
The caller/catalog must establish the membership inventory's provenance.

**Group filtering, BPF program-type registration, per-function BTF attributes,
and actual entry lock ownership are separate facts.** `KF_RCU`, `KF_SLEEPABLE`,
reference lifetime, argument checks, and other verifier/runtime rules are not
evaluated by C2. For example, UNLOCKED group permission for `ops.dump` does not
make a `KF_SLEEPABLE` call acceptable, and says nothing about RCU.
See [ext_idle.c:1488-1503](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext_idle.c#L1488-L1503)
for why select-CPU helpers are excluded from TRACING.

## Lock identity, preconditions, and unknown states

`LockState` has KNOWN_HELD, KNOWN_NOT_HELD, and UNKNOWN. Known states require
source evidence. Missing facts return UNKNOWN, never absence.
`Permission`, `GroupPermission`, `LockState`, `LockMode`, and `LockFact` reject boolean
conversion. Compare decisions/states explicitly; JSON consumers must likewise
compare serialized strings rather than their truthiness.

Every emitted known lock fact has a `LockIdentity(name, object)`.
For example, `rq/enqueue.task:p` binds to the subject task of **one invocation**;
`rq/dispatch.cpu:cpu` binds to the callback's CPU. The identity must still be
bound to actual objects and an invocation by the consuming analysis.
It is not a globally unique task address. A string lookup such as `lock("rq")`
is retained for C2 API compatibility and means only the callback-local fact
described by its identity. It must not be copied to every rq.

An explicit identity query must match exactly. There is no implicit alias between
`rq`, `task_rq`, `rq.lock`, a DSQ lock, another task's `pi_lock`, or another CPU's
rq. For `yield` the known rq belongs to `from`, not arbitrary `to`; for
`core_sched_before` it belongs to `a`, not arbitrary `b`. `dump_task` records the
dumped CPU's rq; it does not bind a generic `task_rq(p)`. Known global symbols
have shared `global:...` identities across callbacks.

`LockFact.mode` distinguishes EXCLUSIVE, READ, and UNKNOWN. The cgroup setters
hold `scx_cgroup_ops_rwsem` in **read** mode; this is not proof of exclusive
ownership or permission to write data requiring its write side.

Evidence for the lock families in the table:

- The 21 rq preconditions follow the listed invocation sites, the
  [SCX_CALL_OP/RET wrappers, ext.c:474-499](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L474-L499),
  [TASK/2TASKS wrapper contracts, ext.c:502-545](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L502-L545),
  and [update_locked_rq, ext.c:458-468](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L458-L468).
  `lockdep_assert_rq_held()` states a required precondition; it **does not acquire**
  the lock or guarantee that production executions satisfy it.
- `select_cpu`'s subject `pi_lock` follows the wrapper contract and the actual
  [try_to_wake_up guard/call, core.c:4190-4290](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/core.c#L4190-L4290)
  and [wake_up_new_task, core.c:4831-4843](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/core.c#L4831-L4843).
  No generic rq absence is inferred from its NULL wrapper argument.
- Both `exit_task` paths explicitly require `p->pi_lock`
  ([ext.c:3670-3697](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3670-L3697),
  [3705-3713](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L3705-L3713)).
  `cgroup_move` follows [sched_move_task, core.c:9444-9457](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/core.c#L9444-L9457),
  the [task_rq_lock guard, sched.h:1939-1943](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/sched.h#L1939-L1943),
  and its [actual acquisition, core.c:737-747](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/core.c#L737-L747).
- `init_task`'s **subject-specific pi_lock** absence is established by inspecting
  all four `__scx_init_task()` callers: fork is after
  [sched_cgroup_fork drops pi_lock, core.c:4758-4785](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/core.c#L4758-L4785);
  [root enable:6995-7000](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6995-L7000),
  [sub enable:7291-7301](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L7291-L7301), and
  [sub disable:5807-5827](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L5807-L5827)
  drop the task iterator's locks before init and reacquire afterwards.
  See [scx_task_iter_unlock, ext.c:825-850](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L825-L850)
  and [task_rq_unlock, sched.h:1923-1937](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/sched.h#L1923-L1937).
  This describes ownership by the invoking execution, not another CPU.
  The common rq state remains UNKNOWN: the three iterator paths explicitly
  release rq, but the cited fork path only explicitly releases pi_lock. The
  child not yet being runnable, or no rq acquisition in this local snippet,
  does not prove absence of an rq lock already held by its caller. No generic
  rq-not-held fact is inferred for all four paths.
- All three dump callbacks are enclosed by
  [scx_dump_state's function-scoped guard at 6337](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6321-L6337).
  The dumped rq acquisition is at [6381](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6381-L6384),
  before `dump_cpu`/`dump_task`, not before `dump`.
- The cgroup setter read guards enclose their respective calls at
  [4436-4449](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4436-L4449),
  [4452-4465](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4452-L4465),
  and [4468-4487](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L4468-L4487).
- Root/sub enable workers acquire `scx_enable_mutex` at
  [6833](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L6833) / [7163](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L7163)
  before `init`/`sub_attach`. `sub_detach` follows the
  [explicit release at 5880](https://github.com/torvalds/linux/blob/8cd9520d35a6c38db6567e97dd93b1f11f185dc6/kernel/sched/ext.c#L5880-L5895).
  `exit` joins a root path with that mutex held and a sub path after release,
  so its common mutex state is UNKNOWN.

UNKNOWN remains intentional for unproven rq absence in all UNLOCKED callbacks,
`select_cpu`'s rq, `set_cpumask`'s pi_lock across all paths, unmodeled cgroup/hotplug
outer-lock ownership, DSQ locks, and unresolved aliases. Knowing that a hotplug
operation excludes other activity is not proof that the callback's execution owns
the coordinating lock. These callbacks have all been inventoried and inspected;
UNKNOWN records a gap in common entry facts, not an unknown callback name.

## Source coverage audit and tests

`checker/tests/data/context-v7.1.json` contains callback declarations, their config
guard, the allow table, and BTF membership blocks copied from the pinned source.
It is an internal C2 source extract; shared contracts/fixtures are unchanged.
Tests cover every callback and group denial, real overlapping memberships,
all recorded held/not-held entry states, identity separation, configuration,
program types, version/commit mismatches, truthiness safeguards, and serialization.

`audit_callback_coverage(header, ext_source, source_version=..., source_commit=...)`
compares a supplied source header and allow table against the model. It rejects
added, removed, renamed, duplicate, or differently configured callbacks and
changed allow rows, including changed CONFIG guards on otherwise identical masks.
Tests inject such changes to require source review instead
of silently extending permissions. The audit was also run against the **complete
downloaded pinned source files**. The checked-in extract enables offline tests;
it does not monitor upstream automatically, authenticate files, or replace a new
audit when changing kernels.

## Querying and observed inspection output

```python
from checker.context import (
    SOURCE_COMMIT, KfuncGroup, LockIdentity, LockState, Permission, get_context,
)

entry = get_context("dispatch", source_version="v7.1", source_commit=SOURCE_COMMIT)
assert entry.permission(KfuncGroup.DISPATCH) is Permission.ALLOWED
assert entry.lock(LockIdentity("rq", "dispatch.cpu:cpu")).state is LockState.KNOWN_HELD
assert entry.lock(LockIdentity("rq", "dispatch.cpu:other")).state is LockState.UNKNOWN
```

```text
python -m checker.context --source-version v7.1
python -m checker.context --source-version v7.1 --enabled-config CONFIG_EXT_GROUP_SCHED
python -m checker.context --source-version v7.1 --enabled-config CONFIG_EXT_GROUP_SCHED --json
```

Observed excerpts from the default table (the command prints all 37 callbacks):

```text
cgroup_move            UNKNOWN (config)         unknown
dispatch               DISPATCH,ENQUEUE         rq=known_held[dispatch.cpu:cpu]
init_task              UNLOCKED                 pi_lock=known_not_held[init_task.task:p]
select_cpu             ENQUEUE,SELECT_CPU       pi_lock=known_held[select_cpu.task:p]
```

JSON is deterministic, includes every modeled permission and its evidence, and is
an internal Epic C format, not a findings-schema change. `--source-version TBD`
or `--source-commit wrong` exits 2 without a table or traceback.

```text
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
python -m checker check
python -m checker.context --source-version v7.1
git diff --check
```

## A3 coordination and later shared-state analysis

The [A3 comparison report](README-c2-a3-review.md) records the inspected PR heads,
aligned mappings, conservative differences, and data required from A/B.
PR #52/#53 are proposed interfaces; this branch's real shared schemas remain
unchanged. Normal C1 input with TBD never receives v7.1 entry facts.

C3 should identify an actual kernel callback invocation and its source provenance,
bind callback arguments and lock identities to concrete/symbolic objects, honor
lock mode, and propagate entry facts through ordered kernel events. Attaching a
BPF program to a member does not establish that asynchronous subprograms run with
the member's kernel-entry locks. Calls can drop/transfer locks; entry assertions
are preconditions, not acquisitions. C2 does not propagate locks, resolve aliases,
prove CFG coverage, check shared field writes, implement old runtime masks, or
run LLVM, verifier, VM, or runtime BPF tests. Verified state-modification policies
from Epic A and ordered, complete paths/object identities from Epic B are still
needed before any meaningful I1 safety verdict.
