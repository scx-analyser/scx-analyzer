# scx-analyzer

Extracting kernel scheduling constraints from **sched_ext kfuncs**: start at the BPF-facing kfuncs,
recursively follow the kernel call graph, and catalog the invariants the kernel imposes on shared
scheduler state (`task_struct`, `struct rq`, DSQs): locks, execution contexts, valid values/flags,
CPU/affinity restrictions and task-state transitions. Then validate them with sched_ext programs that
satisfy or deliberately violate each constraint.

## Pipeline & ownership

```
            Epic A                     Epic B                    Epic C                   Epic D
   kfunc inventory + catalog ──► call-graph extractor ──► invariant checkers ──► validation + report
   catalog/   (contract:          extractor/ (contract:    checker/ (contract:      validation/ (contract:
   catalog.schema.json)           callgraph.schema.json)   findings.schema.json)    VM + harness)
```

| Epic | Owner | Folder | Grading part | Contract (due M0) |
|---|---|---|---|---|
| A - Inventory & invariant catalog | Person A | `catalog/` | 50% | `contracts/catalog.schema.json` |
| B - Call-graph extraction | Person B | `extractor/` | 30% | `contracts/callgraph.schema.json` + fixture |
| C - Invariant checkers | Person C | `checker/` | 30% | `contracts/findings.schema.json` |
| D - Validation & report | Person D | `validation/`, `docs/report/` | 20% | test VM + harness |

## How we stay parallel

1. **Contracts first (M0, due Tue Nov 10).** Each epic publishes one schema/fixture/environment in `contracts/`.
   Changing a contract needs approval from every consumer (see `.github/CODEOWNERS`).
2. **Code against fixtures, not against each other.** C develops on
   `contracts/fixtures/callgraph.example.json` while B builds the real extractor; D builds the VM and tests
   from day 1 because they need only the pinned kernel.
3. **One folder per epic.** No shared files except `contracts/` and `docs/report/` (one chapter per epic).
4. **CI validates every fixture/output against the schemas**, so integration breaks show up on the PR, not at the end.

Full plan with dependency graph: [`docs/plan.md`](docs/plan.md). The backlog lives in GitHub issues
generated from [`planning/issues.yaml`](planning/issues.yaml).

## Layout

```
contracts/      JSON schemas + fixtures shared between epics
catalog/        Epic A - kfuncs.csv, invariants/I*.yaml, ground_truth.csv
extractor/      Epic B - kernel IR build + call-graph extractor
checker/        Epic C - checkers per invariant + classifier
validation/     Epic D - VM, harness, tests/{pass,fail}/
docs/           plan + report chapters
planning/       issues.yaml + create_issues.py (backlog generator)
tools/          repo tooling (contract validation)
```

## Pinned kernel

See [`KERNEL_VERSION`](KERNEL_VERSION) (set in task A1). Everyone analyses and tests the same tag.
