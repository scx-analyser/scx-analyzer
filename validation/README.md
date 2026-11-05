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

Test naming: `tests/{pass,fail}/<invariant>_<short_name>.bpf.c`, e.g. `fail/I3_local_on_invalid_cpu.bpf.c`.
The upstream `tools/testing/selftests/sched_ext` suite is the baseline and a good template.
