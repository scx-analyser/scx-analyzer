# 2. Call-graph extraction

Epic B turns the pinned kernel (Linux v7.1, `8cd9520d35a6`) into the annotated call graph that the checkers
(Epic C) analyse: one node per kernel function reachable from a sched_ext kfunc, with the scheduler-state fields
it reads and writes and an ordered list of locking, assertion, error and guard events. The contract is
`contracts/callgraph.schema.json`; the reference output is `extractor/out/v7.1.callgraph.json`.

## 2.1 Pipeline

```
kernel tree ──build_kernel_ir.sh──► build_policy.ll, core.ll ──scxa extract──► callgraph.json ──scxa dot──► DOT/SVG
 (pinned)     clang -O2 + DWARF       (ext.c, ext_idle.c, core.c)    (Python, no LLVM bindings)
```

**IR build (B2).** `extractor/build_kernel_ir.sh` checks that the tree is the pinned commit, configures it with
`defconfig`, the upstream sched_ext selftest fragment and the options of Epic D's test VM (sched_ext, BTF,
lockdep, plus `SCHED_CORE`), runs `make prepare` and only the two Kbuild `.ll` targets. Building the IR takes about
30 s on 4 cores instead of a full kernel build. We keep the kernel's normal `-O2`: lowering the optimisation level
breaks the kernel's compile-time assertions, and the optimised IR is what actually runs. DWARF debug info is the
key input. It gives source lines, struct member names and, through `inlinedAt`, the functions that were inlined.

**Extraction (B3–B7).** A small Python reader parses the textual IR (functions, metadata, struct types, module
asm). We chose this over an LLVM pass because the team's tooling is Python, the IR text is stable enough for the
few constructs we need, and it keeps the extractor runnable without an LLVM development install.

## 2.2 Design choices

**Roots.** The extractor reads the kfunc list from `catalog/kfuncs.csv` (A1) or, without it, from the
`__BTF_ID__` entries that `BTF_KFUNCS_START/BTF_ID_FLAGS` leave in the IR. Both give the same 59 kfuncs in 7 sets.

**Inlining.** At `-O2` most static helpers have no body of their own (for example `mark_direct_dispatch`).
Every instruction's `DILocation` chain says which function the code belongs to and where that function was
inlined, so each inline expansion becomes a call edge at the call-site line. The inlined instructions are
attributed to the helper, so the graph follows the source structure, not the optimiser's. Copies of a helper
(several inline expansions, out-of-line bodies in both modules) are merged into one node, and optimizer
suffixes such as `.constprop.0` are mapped back to the source name.

**Library code and macros.** Inlined code from generic headers (`include/`, `arch/`: `list_add`, `atomic_*`,
`cpumask_set_cpu`, ...) and the lock/assert wrappers of `kernel/sched/sched.h` (`rq_lock*`,
`lockdep_assert_rq_held`, `class_*lock*` guards) are folded into their caller at the call-site line. Their
memory accesses and lock operations become events of the scheduler function that used them, which is the level
at which the invariants are stated. Macros such as `scx_error()`, `WARN_ON_ONCE()`, `lockdep_assert_held()` and
`guard(...)` have no frame of their own and are recognised by what they expand to: a call to `scx_exit()` with an
`SCX_EXIT_ERROR` kind, a `ud2` + `__bug_table` asm, `lock_is_held_type()` followed by a comparison with 0
(held) or 1 (not held), and the out-of-line `_raw_spin_*` / `raw_spin_rq_*` / `_task_rq_lock` calls.

**Fields (B5).** A pointer is resolved to a root struct and byte offset (struct GEPs with offsets from the IR
type layout, byte GEPs, typed debug values, loads of pointer fields, and `container_of` both as a negative
offset and in clang's folded form). The member name then comes from DWARF. The computed IR layout equals the
DWARF offsets for every tracked struct. Fields are named by the outermost tracked struct (`task_struct.scx.slice`,
`rq.scx.nr_immed`) and stop at generic containers (`list_head`, `rb_node`, atomics, locks, `cpumask`).

**Events (B6).** Events are ordered by source line and column (then IR position). This is program order for
straight-line code but is not a control-flow graph; that limit is stated in the contract so that consumers
treat ordering across branches as unknown. Lock events carry a class token (`rq`, `dsq`, `pi_lock`, or a global
name) and `expr`, the argument as written in the source (`&dsq->lock`, `dst_rq`), so that C can bind a token to
a specific instance. Guards combine the IR and the source. A conditional branch on a line `if (cond)` is a guard
when its branch ends in `return` (`error` if it also calls `scx_error`/WARN), `goto`/`break`/`continue`, or a
single assignment without `else` (`fallback`). Because a branch often sits in inlined callee code
(`if (!ops_cpu_valid(...)) return;`), the enclosing call-site lines are checked too. Stores the optimizer merged
into a line-0 location are placed on the source lines that assign the field.

**Indirect calls (B7).** Calls through function pointers are never dropped. They are named by the slot they
load from: `ops.<op>` for `SCX_CALL_OP*` into the BPF scheduler (`ops.enqueue` at ext.c:1948, `ops.dispatch` at
2840/2844), `sched_class.<method>` for scheduling-class methods, `<struct>.<member>` otherwise. They are not
resolved to implementations: BPF ops are not in the kernel image, and a `sched_class` method may belong to any
class.

**Depth and boundaries (B4).** Only functions defined in the sched_ext files, `sched.h` and
`include/linux/sched/ext.h` are expanded by default. Anything else (for example `raw_spin_rq_lock_nested` in
`core.c`) is a `boundary` node with its file and line but no body, and functions only declared in the IR are
`external`. `--expand GLOB` widens the scope (`--expand kernel/sched/core.c`) and `--depth N` caps the call
depth (default 12, never reached with the default scope). Calls to code that cannot touch scheduler state
(lockdep bookkeeping, RCU read-side bookkeeping, tracepoints, printk, sanitizers) are left out entirely, so the
graph is not dominated by debugging infrastructure. Lockdep *assertions* are kept.

## 2.3 Results and scalability

All runs read the same IR (157k + 88k lines of `.ll`) and use about 160 MB of memory.

| Scope | Time | Nodes (kfunc / internal / boundary / external) | Edges | Events | Max depth |
|---|---|---|---|---|---|
| default | 6.4 s | 208 (59 / 106 / 11 / 32) | 376 | 829 | 5 |
| `--expand kernel/sched/core.c` | 6.6 s | 227 (59 / 128 / 7 / 33) | 415 | 913 | 7 |
| everything in the IR | 6.2 s | 241 (59 / 147 / 0 / 35) | 443 | 971 | 10 |

Most of the time is parsing; graph construction is linear in the IR size, so analysing more of the kernel
mainly costs building more `.ll` files. With the default scope the graph contains 188 guards, 25 lock and
33 unlock events, 29 lockdep assertions, 44 `scx_error` and 35 WARN sites, 84 writes and 15 atomic operations
on 40 distinct scheduler-state fields, and 5 indirect calls (all `SCX_CALL_OP` into BPF or `cpufreq` hooks).

**Validation.** The hand-written fixture (`contracts/fixtures/callgraph.example.json`) was written from the v7.1
source independently of the extractor. Of its 98 call edges, written fields and non-call events, the extractor
reproduces 92 with the same line. All six misses are writes to a DSQ's list head or rbtree root: they happen
through neighbour pointers loaded from the task's list node, or inside the out-of-line `rb_erase()`, so the
extractor cannot tell which struct they hit. In addition the tests check, on the real IR, that every callee has a
`call` event and every written field a `write`/`atomic` event, as the contract requires. They also check that
known facts are present: the dsq lock in `consume_dispatch_q`, the `dsq`/`rq` assertions in
`move_local_task_to_local_dsq`, the `ops_cpu_valid` guard in `scx_kick_cpu`, and `rq.scx.nr_immed` through
`container_of`.

## 2.4 Limitations

- **No control flow.** Events are ordered but carry no branch structure (`cond` is not filled on non-guard
  events), and loops are not represented. Consumers must not assume an event happens on every path.
- **Aliasing.** Accesses through pointers whose type is lost (list neighbours, `phi`/`select` of pointers,
  pointers returned by out-of-line calls) are not attributed to a field. Bitfield storage is not attributed.
- **Guards from source text.** The guard `action` is read from the source of the `if`. A `goto` is reported as
  `continue` even when the label leads to a return, and conditions computed by `switch` are not guards.
- **Merged copies.** All inline expansions of a helper share one node, so a helper specialised differently in two
  callers shows the union of its events.
- **Scope.** Only `build_policy.c` (sched_ext, idle) and `core.c` are compiled to IR. Calls into the rest of the
  kernel are `external` leaves, and indirect calls are named but not resolved.
- **x86-64 only.** Atomic and WARN detection rely on x86 inline asm, and the layout code assumes the x86-64 data
  layout.
