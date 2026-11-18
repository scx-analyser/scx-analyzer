# C1 implementation — checkers and findings interface

**Scope:** the `scxa check` CLI validates the existing schemas, loads a hand-written call-graph fixture and catalog, calls registered invariant plug-ins, validates all returned findings, and writes JSON suitable for Epic D. It does **not** make safety judgments without implemented checkers. The current fixture is illustrative, not a verified kernel trace.

Requirements: Python 3.12+, `jsonschema`, `PyYAML`. CI runs the same checks on Windows and Linux with Python 3.12, 3.13, and 3.14.

```bash
python -m pip install jsonschema pyyaml
python -m checker check --callgraph contracts/fixtures/callgraph.example.json --catalog contracts/fixtures/catalog.example.yaml
python -m checker check -o .dist/scxa-findings.json
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
```

On Linux, `./scxa check` is also available; on Windows, use `python scxa check` or the module form above. Defaults resolve relative to the repository, including when the script is run from another directory. JSON goes to stdout (or `-o`); diagnostics go to stderr. Exit 0 means the runner completed and its output conforms to the contract. Exit 2 reports invalid input, a contract/version mismatch, invalid plugin output, or an I/O error; it is not an invariant verdict.

## Plug-in contract

The public API is `checker.check(callgraph: dict, catalog: dict) -> list[Finding]`. `Finding`, exported from `checker`, is a dictionary conforming to the item definition in `contracts/findings.schema.json`; the CLI wraps this list with `kernel_version` and the input callgraph path. The runner reads the actual shared schemas without modifying them and rejects mismatched input versions, missing root nodes, duplicate catalog IDs, and findings that cannot be serialized as JSON.

Register a function using `checker.checkers.register("I1", fn)`. It has the same signature as `check`, must return a list, and must report its registered invariant ID and a kfunc among the callgraph roots. Registrations must be unique and present in the catalog. The runner calls plugins in sorted invariant-ID order. To activate a future module, import and register it at the end of `checker/checkers/__init__.py`; plugin modules can import `Finding` and `register` from that package.

**C1 installs no semantic plugins.** Its empty findings list means no semantic analysis ran, and stderr states this explicitly. An installed plugin can also return no findings; this is reported separately and makes no safety claim. No I1/I2/I3 validation, lockset analysis, guard dominance analysis, context model, or enforcement classification is implemented here. Never emit `holds` from an unverified illustration: use evidence-backed analysis or `unknown` with an explanation.

`KERNEL_VERSION` remains TBD. The existing fixture and catalog contain draft, potentially version-specific assumptions. Their schema validity does not establish kernel behavior or verifier outcomes. C1 treats version strings as opaque identifiers and makes no assumptions about kernel helper names; verify source against the agreed kernel before adding semantics.

**Next:** C2 define callback contexts/lock-state facts and C3/C4 implement evidence-backed analyses. Before changing a contract or fixture, request review from CODEOWNERS.
