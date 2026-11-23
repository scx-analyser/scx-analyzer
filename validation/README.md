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
/* scxa: invariant=I3 expect=runtime_error */
```

Run after `run-selftests.sh` has built the kernel and selftests:

```sh
python3 validation/harness/harness.py                          # every tests/{pass,fail}/*.bpf.c
python3 validation/harness/harness.py validation/tests/fail/I3_insert_bogus_dsq.bpf.c
```

For each test it compiles with the selftests' own `BPF_CFLAGS`, boots a **fresh VM** (lockdep and `WARN_ON_ONCE`
report only once per boot) and runs [`harness/loader.c`](harness/loader.c) inside it. The loader fills in the
`__SCX_*` enum constants, loads the object and attaches every struct_ops map; the harness then runs a fork-heavy load
for `$SECS` seconds (default 5) and reads dmesg. Classification, first match wins:

| Outcome | Evidence |
|---|---|
| `verifier_reject` | object failed to load; reason = the verifier's error line |
| `lockdep` | lockdep / RCU / might_sleep splat (`WARNING: possible ...`, `BUG: sleeping function ...`) |
| `runtime_error` | `sched_ext: BPF scheduler "x" disabled (runtime error / scx_bpf_error / runnable task stall)`, reason = the scx_error message; or attach failed |
| `warn` | any other `WARNING:` / `BUG:` (includes failed `lockdep_assert_held()`, which is a plain WARN) |
| `ok` | stayed attached, clean dmesg |

Output: one `PASS/FAIL` line per test, exit 1 on any mismatch, `results/outcomes.jsonl` (one record per test:
`test, invariant, expect, outcome, reason, loader_rc, scx_state, pass`) and the full guest log in `results/logs/`.
Unit tests for the classifier: `python3 -m unittest discover -s validation/harness`.

Test naming: `tests/{pass,fail}/<invariant>_<short_name>.bpf.c`, e.g. `fail/I3_local_on_invalid_cpu.bpf.c`.
Tests in `pass/` expect `ok`. The upstream `tools/testing/selftests/sched_ext` suite is a good template.
