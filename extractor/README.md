# Epic B - call-graph extraction

Owner: Person B · Contract: `contracts/callgraph.schema.json`

Input: pinned kernel source (`KERNEL_VERSION`) + kfunc roots (`catalog/kfuncs.csv`).
Output: `callgraph.json` validating against the schema - nodes with field `reads`/`writes`, ordered `events`, `callees`.

Planned components:

| Path | Task | |
|---|---|---|
| `build_kernel_ir.sh` | B2 | clang (`LLVM=1`) build emitting IR for `kernel/sched/build_policy.o` (includes `ext.c`, `ext_idle.c`) and `core.o`, with debug info |
| `pass/` or `src/` | B3-B7 | IR analysis (LLVM pass in C++ or IR parser) |
| CLI | B8 | `scxa extract --kernel <dir> --roots catalog/kfuncs.csv --depth N -o callgraph.json`, `scxa dot <kfunc>` |

## Building the analysis IR (B2)

```sh
extractor/build_kernel_ir.sh                       # kernel tree: $KERNEL_SRC, else ~/linux (fetched if missing)
extractor/build_kernel_ir.sh --kernel-src /path/to/linux --build-dir /tmp/kir -j 8
```

Requirements: `clang`, `ld.lld`, `llvm-ar` (LLVM 18 tested), `make`, `flex`, `bison`, `bc`, `libelf-dev`,
`libssl-dev` (Ubuntu: `apt-get install clang lld llvm flex bison bc libelf-dev libssl-dev`).

The script checks that the kernel tree is the pinned commit (`KERNEL_COMMIT`, else v7.1 =
`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`) with no local changes under `kernel/sched` or `include`,
then runs `defconfig` + `tools/testing/selftests/sched_ext/config` + `extractor/kernel.config`,
`make prepare` and the two Kbuild `.ll` targets. It does not build a full kernel (about 30 s on 4 cores).

Output in `extractor/build/` (git-ignored):

| File | Content |
|---|---|
| `kernel/sched/build_policy.ll` | `ext.c` and `ext_idle.c` (both `#include`d by `build_policy.c`), with DWARF debug info |
| `kernel/sched/core.ll` | `core.c` |
| `.config` | the exact configuration |
| `ir-manifest.txt` | kernel commit, clang version, config SHA-256, IR SHA-256s |

The IR is built at the kernel's normal `-O2`, so small static helpers (for example `mark_direct_dispatch`) are
inlined. Their call sites survive as `inlinedAt` debug locations, which the extractor uses to rebuild the calls.
`extractor/kernel.config` mirrors Epic D's `validation/vm/config` (sched_ext, BTF, lockdep) plus
`CONFIG_SCHED_CORE`, so the call graph and the test VM describe the same options.

## Command line (B8)

```sh
./scxa extract --kernel ~/linux --roots catalog/kfuncs.csv --depth 12 -o extractor/out/v7.1.callgraph.json
./scxa extract --roots scx_bpf_kick_cpu,scx_bpf_dsq_insert            # some roots, to stdout
./scxa dot scx_bpf_dsq_move_to_local --depth 4 -o g.dot && dot -Tsvg g.dot -o g.svg
./scxa dot scx_bpf_kick_cpu --callgraph extractor/out/v7.1.callgraph.json --no-details
```

`scxa extract` reads the IR in `--build-dir` (default `extractor/build/`) and, if it is missing and `--kernel` is
given, builds it first with `build_kernel_ir.sh` (`--no-build` to refuse). `python3 -m extractor` is the same
command. `scxa dot [kfunc]` renders the nodes reachable from `kfunc` (whole graph without it) within `--depth`
calls: kfuncs bold, boundary nodes dashed yellow, external nodes grey, indirect edges dashed to their ops/method
slot, call-site lines on the edges, and per node a summary of its events, lock tokens and written fields.
`scxa check` (Epic C) is unchanged.

`extractor/out/v7.1.callgraph.json` is the reference extraction for the pinned kernel (all 59 kfuncs, default
limits), checked by the contracts CI. Regenerate it with the first command above after extractor changes.

## Extraction (B3)

`extractor/scxa_extract/` reads the textual IR directly (Python, no LLVM bindings):

- **Roots.** `catalog/kfuncs.csv` if present, else every kfunc registered in an `scx_kfunc_ids_*` BTF set, read
  from the `__BTF_ID__` entries the IR carries (59 for v7.1, the same as the A1 inventory). Every kfunc found in
  the BTF sets gets `kind: kfunc`, root or not.
- **Nodes** are kernel functions named by their DWARF name (optimizer suffixes such as `.constprop.0` are mapped
  back). `file`/`line` come from the `DISubprogram`, `end_line` from the closing brace in the source tree
  (omitted for macro-generated functions such as tracepoints).
- **Inlining.** At `-O2` most static helpers have no body of their own. Every instruction's `DILocation`
  `inlinedAt` chain says which function's code it is and where that function was inlined, so each inline
  expansion becomes a `direct` edge at the call-site line, and the inlined code is attributed to the helper.
  All copies of a function (several inline expansions, out-of-line bodies in both modules) merge into one node.
- **Kinds.** `kfunc`; `internal` (has code in the IR, out of line or inlined); `external` (only declared, e.g.
  `_raw_spin_lock`, `irq_work_queue`). Calls through function pointers are kept as `indirect` edges.
- **Depth** is the shortest call distance from any root.

### Depth limit, stop-list and boundary (B4)

| Option | Default | Effect |
|---|---|---|
| `--depth N` | 12 | nodes at depth N are recorded as `boundary` and not expanded |
| `--expand GLOB` | `kernel/sched/ext*.c`, `kernel/sched/ext*.h`, `kernel/sched/sched.h`, `include/linux/sched/ext.h` | functions defined elsewhere (e.g. `kernel/sched/core.c`, generic headers) are `boundary` nodes: file and line recorded, callees not followed. Repeat to add files, e.g. `--expand kernel/sched/core.c` |
| `--stop REGEX` | lockdep bookkeeping (`lock_acquire`, `lockdep_*` except asserts), RCU read-side bookkeeping, tracepoints (`__SCT__*`, `trace_*`), printk, sanitizers, `__might_sleep` | calls to these are left out entirely (no node, no edge): they do not touch the tracked scheduler state. `--no-default-stop` keeps them |

Roots are always expanded. With the defaults, v7.1 gives 267 nodes (59 kfuncs, 96 internal, 83 boundary,
29 external, maximum depth 5); `--expand kernel/sched/core.c` gives 291.

The kernel tree is inferred from the IR's debug info (pass `--kernel` if it moved); it is needed for `end_line`.

### Field reads and writes (B5)

`reads`/`writes` list the fields of the tracked structs (`task_struct`, `sched_ext_entity` as `task_struct.scx`,
`rq`, `scx_rq` as `rq.scx`, `scx_dispatch_q`) that a function loads or stores:

- A pointer is resolved to *(root struct, byte offset)* from struct GEPs (offsets from the IR type layout), byte
  GEPs on a known base, pointer-typed debug values (arguments, locals) and loads of pointer fields
  (`p->scx.dsq`). `container_of()` is followed both as a negative byte offset and as clang's folded form (a GEP of
  `struct scx_rq` on a DSQ pointer).
- The field is read from DWARF: the members that contain the accessed bytes, down to generic containers
  (`list_head`, `rb_node`, `atomic*_t`, `raw_spinlock_t`, `cpumask`, ...). Bitfield storage is not attributed.
- Loads are reads, stores (incl. `WRITE_ONCE`) are writes, and x86 memory-operand inline asm (`set_bit`,
  lock-prefixed RMW) is both.
- Inlined generic library code (`include/`, `arch/`: `list_add`, `atomic_long_set`, `cpumask_set_cpu`, ...) is
  attributed to the calling function at the call-site line, so its stores are the caller's writes. This also
  removes those helpers as separate nodes (228 nodes on v7.1, 40 distinct written fields).

Limits: accesses through pointers whose type cannot be recovered (e.g. a list neighbour loaded from `node.next`,
or a pointer chosen by a `phi`) are not attributed, and functions that are only `external` have no sets.

### Ordered events (B6)

Each expanded node gets `events` in source order (line, column, IR position); this is the order of straight-line
code, not a control-flow graph. Encoding (see the descriptions in `contracts/callgraph.schema.json`):

| Event | Produced from | Fields |
|---|---|---|
| `lock` / `unlock` | calls to `_raw_spin_{lock,unlock}*`, `raw_spin_rq_{lock_nested,trylock,unlock}`, `_task_rq_lock` (pi_lock + rq), `task_rq_unlock`, `double_rq_{lock,unlock}`, `mutex_*`, `percpu_{down,up}_*` | `lock` token (`rq`, `dsq`, `pi_lock`, global name), `expr` = the argument in the source (`&dsq->lock`, `target_rq`), `op: trylock` |
| `assert_held` / `assert_not_held` | `lock_is_held_type()` (polarity from the compared constant), `lockdep_assert_irqs_{disabled,enabled}()` | `lock`, `expr`; the WARN on the same line is folded into the assertion |
| `error` | `scx_exit()`/`scx_vexit()` with an `SCX_EXIT_ERROR*` kind, i.e. `scx_error()` | `msg` = the format string |
| `warn` | x86 `ud2` + `__bug_table` asm (`WARN_ON*`, `BUG*`) | `msg` = the WARN condition |
| `guard` | a conditional branch on a source line `if (cond)` whose branch ends in `return` (`action: return`, or `error` if it also calls `scx_error`/WARN), `goto`/`break`/`continue` (`continue`), or a single assignment without `else` (`fallback`) | `cond` = source condition; also found on the caller line when the branch is in inlined callee code (`if (!ops_cpu_valid(...)) return;`) |
| `write` | stores to tracked fields | `field`, `op` (`set`, `write_once`, `list_add`, `list_del`, `rb_*`, `set_bit` for non-atomic bit ops) |
| `atomic` | accesses inside inlined `atomic*_*`, `*_bit`, `cpumask_*_cpu`, `*cmpxchg*`, `*xchg*`, lock-prefixed asm | `field`, `op` (`read`, `read_acquire`, `set`, `set_release`, `cmpxchg`, `set_bit`, ...) |
| `call` | one per callee (direct, inline expansion, indirect) | `target` |

Lock, lockdep-assertion and `scx_exit` calls are events, not callees; the inline wrappers around them in
`kernel/sched/sched.h` (`rq_lock*`, `lockdep_assert_rq_held`, `class_*lock*` guards, ...) are folded into their
caller like library code. Copies of an event from several inline expansions are merged. Stores the optimizer
merged into a line-0 location are placed on the source lines that assign the field.

Not modelled: `cond` on non-guard events (which branch an event is in), loops, and conditions computed by
`switch` statements. Every `writes` entry has a `write`/`atomic` event and every callee a `call` event.
On v7.1: 188 guards, 25 locks, 33 unlocks, 29 assertions, 44 errors, 35 warns, 84 writes, 15 atomics.

### Indirect calls (B7)

Calls through a function pointer are always kept as `kind: indirect` edges (and `call` events). The target is the
slot the pointer is loaded from, read from DWARF: `ops.<op>` for `struct sched_ext_ops` (the `SCX_CALL_OP*`
calls into the BPF scheduler, e.g. `ops.enqueue` at ext.c:1948, `ops.dispatch` at 2840/2844),
`sched_class.<method>` for scheduling-class methods (visible with `--expand kernel/sched/core.c`), otherwise
`<struct>.<member>`. A pointer whose origin cannot be traced is `<indirect>`. Targets are not resolved to
implementations: the BPF ops are not in the kernel image, and a `sched_class` method can belong to any class.

Notes:
- Inlined helpers: use debug-info `inlinedAt` or build analysis IR with `-fno-inline`.
- Indirect calls (`SCX_CALL_OP*`, `sched_class` methods) must appear as `kind: indirect`, never dropped.
- Until real output exists, consumers use `contracts/fixtures/callgraph.example.json` - keep it representative.
