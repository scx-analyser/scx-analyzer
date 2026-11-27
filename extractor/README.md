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

## Extracting the call graph (B3)

```sh
python3 -m extractor -o extractor/out/v7.1.callgraph.json          # reads extractor/build/kernel/sched/*.ll
python3 -m extractor --roots scx_bpf_kick_cpu,scx_bpf_dsq_insert     # only some roots
python3 -m extractor --roots catalog/kfuncs.csv --kernel ~/linux
```

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

The kernel tree is inferred from the IR's debug info (pass `--kernel` if it moved); it is needed for `end_line`.

Notes:
- Inlined helpers: use debug-info `inlinedAt` or build analysis IR with `-fno-inline`.
- Indirect calls (`SCX_CALL_OP*`, `sched_class` methods) must appear as `kind: indirect`, never dropped.
- Until real output exists, consumers use `contracts/fixtures/callgraph.example.json` - keep it representative.
