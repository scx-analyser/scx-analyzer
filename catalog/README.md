# Epic A - kfunc inventory & invariant catalog

Owner: Person A · Contract: `contracts/catalog.schema.json`

| File | Task | Content |
|---|---|---|
| `kfuncs.csv` | A1 | every sched_ext kfunc: name, kfunc set, BTF flags, file:line |
| `scripts/inventory.*` | A1 | regenerates `kfuncs.csv` from the pinned kernel |
| `invariants/I1.yaml` | A3 | calling context & locking |
| `invariants/I2.yaml` | A4 | task ownership, DSQ membership, ops_state transitions |
| `invariants/I3.yaml` | A5 | CPU / affinity / argument validity |
| `invariants/I4.yaml` | A6 (stretch) | value ranges & flag combinations |
| `ground_truth.csv` | A7 | manual oracle: kfunc x invariant -> holds? enforced how/where? |

All `invariants/*.yaml` files must validate against the catalog schema (CI checks this).
Starting point: `contracts/fixtures/catalog.example.yaml`.
