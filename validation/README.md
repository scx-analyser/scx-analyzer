# Epic D - validation

Owner: Person D · Contract: test VM + harness outcome format

```
validation/
  vm/                 D1  virtme-ng / QEMU setup for the pinned kernel (sched_ext, BTF, lockdep)
  harness/            D2  build + load a scheduler, classify the outcome
  tests/
    pass/             one program per invariant that respects it
    fail/             one program per invariant that violates it
  results/            D6  findings + test outcomes + comparison
```

**Outcome classes** (each test declares the expected one and the invariant id it targets):
`verifier_reject` · `runtime_error` (scx_error / scheduler ejected - record the exit reason) · `lockdep` · `warn` · `ok`.

## Test VM (D1)

One command builds the pinned kernel (`KERNEL_COMMIT`) with sched_ext, BTF and lockdep, boots it in
[virtme-ng](https://github.com/arighi/virtme-ng) and runs the upstream sched_ext selftests:

```sh
validation/vm/run-selftests.sh            # all selftests
validation/vm/run-selftests.sh -t minimal # runner args pass through
```

It uses the kernel tree in `$KERNEL_SRC` (default `~/linux`, the same tree as `catalog/scripts/inventory.py`),
shallow-fetching the pinned commit if the directory does not exist, and refuses to run if the tree is at another
commit. Upstream tests listed as `known_flaky` in the script still run but do not fail it. The guest shares the host root filesystem read-only, so binaries built on the host run inside it.
Config: virtme-ng's minimal config + `tools/testing/selftests/sched_ext/config` + [`vm/config`](vm/config).

**Host:** Linux (x86_64 or arm64), ideally with `/dev/kvm`. Ubuntu 24.04 packages:

```sh
sudo apt install build-essential flex bison bc cpio libelf-dev libssl-dev zlib1g-dev libzstd-dev \
  clang llvm lld qemu-system-x86 busybox-static   # qemu-system-arm on arm64
pip install virtme-ng
```

Plus **pahole >= 1.27** (Ubuntu 24.04 ships 1.25): without its `bpf_kfunc` decl tags, kfuncs with implicit
arguments get the wrong BTF prototype and most selftests fail with `func_proto ... incompatible with vmlinux`.
Build it from source as the CI workflow does (tag v1.30). The script refuses to run with an older pahole.

**macOS:** run the script inside a Linux VM (UTM, Lima, OrbStack). Apple M1/M2 have no nested virtualization,
so the inner VM falls back to TCG emulation: slow but works. Allow ~15 GB of disk for the kernel build.

CI ([`validation-vm.yml`](../.github/workflows/validation-vm.yml)) runs the same script, then the harness, on every
change under `validation/`.

## Harness (D2)

A test is a single `.bpf.c` file; no user-space code. It declares what it targets and what the kernel should do:

```c
/* scxa: invariant=I1 expect=runtime_error kfunc=scx_bpf_cpuperf_set rule=I1.rq_scx.rq_lock reason="Invalid target CPU" */
```

`invariant` and `expect` are required. `kfunc` is the kfunc under test and `rule` the catalog rule id, so results
join with findings on `(kfunc, invariant)`. `reason` must be a substring of the classified reason, so a rejection or
error for an unrelated cause does not count as a match.

Run after `run-selftests.sh` has built the kernel and selftests:

```sh
python3 validation/harness/harness.py                          # every tests/{pass,fail}/*.bpf.c
python3 validation/harness/harness.py validation/tests/fail/I3_insert_bogus_dsq.bpf.c
```

For each test it compiles with the selftests' own `BPF_CFLAGS`, boots a **fresh VM** (lockdep and `WARN_ON_ONCE`
report only once per boot) and runs [`harness/loader.c`](harness/loader.c) inside it. The loader fills in the
`__SCX_*` enum constants, loads the object and attaches every struct_ops map; the harness then runs a fork-heavy load
for `$SECS` seconds (default 5) and reads dmesg. Each VM run is killed after `$TIMEOUT` seconds (default
120 + `$SECS`). Classification, first match wins:

| Outcome | Evidence |
|---|---|
| `verifier_reject` | object failed to load with a verifier log; reason = the verifier's error line |
| `lockdep` | lockdep / RCU / might_sleep splat (`WARNING: possible ...`, `BUG: sleeping function ...`) |
| `runtime_error` | `sched_ext: BPF scheduler "x" disabled (runtime error / scx_bpf_error / runnable task stall)`, reason = the scx_error message; attach failed; or the scheduler was no longer enabled at the end of the load (e.g. `scx_bpf_exit()`) |
| `warn` | any other `WARNING:` / `BUG:` (includes failed `lockdep_assert_held()`, which is a plain WARN) |
| `ok` | `/sys/kernel/sched_ext/state` still `enabled` after the load, clean dmesg |

These map onto the `enforcement` values of `contracts/findings.schema.json`: `verifier_reject` -> `verifier`,
`runtime_error` -> `scx_error`, `lockdep` -> `lockdep`, `warn` -> `warn`. When a test cannot be judged, the outcome is
`build_error` (clang failed), `timeout` (no result in time: hang or deadlock) or `harness_error` (load failed without
a verifier log, e.g. a BTF mismatch; lockdep already off from a boot-time splat; VM failure). A test never expects these.

Output: one `PASS/FAIL` line per test, exit 1 on any mismatch, `results/outcomes.jsonl` (one record per test,
written as each finishes, always the same keys: `test, invariant, kfunc, rule, expect, outcome, reason, loader_rc,
scx_state, pass`) and the full guest log in `results/logs/`.
Unit tests for the classifier: `python3 -m unittest discover -s validation/harness`.

Test naming: `tests/{pass,fail}/<invariant>_<short_name>.bpf.c`, e.g. `fail/I3_local_on_invalid_cpu.bpf.c`.
Tests in `pass/` expect `ok`. The upstream `tools/testing/selftests/sched_ext` suite is a good template.
