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

Notes:
- Inlined helpers: use debug-info `inlinedAt` or build analysis IR with `-fno-inline`.
- Indirect calls (`SCX_CALL_OP*`, `sched_class` methods) must appear as `kind: indirect`, never dropped.
- Until real output exists, consumers use `contracts/fixtures/callgraph.example.json` - keep it representative.
