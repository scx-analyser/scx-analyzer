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
commit. The guest shares the host root filesystem read-only, so binaries built on the host run inside it.
Config: virtme-ng's minimal config + `tools/testing/selftests/sched_ext/config` + [`vm/config`](vm/config).

**Host:** Linux (x86_64 or arm64), ideally with `/dev/kvm`. Ubuntu 24.04 packages:

```sh
sudo apt install build-essential flex bison bc cpio libelf-dev libssl-dev zlib1g-dev \
  dwarves clang llvm lld qemu-system-x86 busybox-static   # qemu-system-arm on arm64
pip install virtme-ng
```

**macOS:** run the script inside a Linux VM (UTM, Lima, OrbStack). Apple M1/M2 have no nested virtualization,
so the inner VM falls back to TCG emulation: slow but works. Allow ~15 GB of disk for the kernel build.

CI ([`validation-vm.yml`](../.github/workflows/validation-vm.yml)) runs the same script on every change to `validation/vm/`.

Test naming: `tests/{pass,fail}/<invariant>_<short_name>.bpf.c`, e.g. `fail/I3_local_on_invalid_cpu.bpf.c`.
The upstream `tools/testing/selftests/sched_ext` suite is the baseline and a good template.
