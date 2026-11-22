# Epic C - invariant checkers

Owner: Person C. Contract: [`findings.schema.json`](../contracts/findings.schema.json), consumed by Epic D.

C1 provides the checker API, plugin registry, schema validation, and `scxa check` CLI. It loads a callgraph and one catalog file, runs explicitly registered plugins, validates their findings, and emits JSON. **This branch installs no semantic plugins:** an empty findings list makes no safety claim. The shared fixture is illustrative, not a verified kernel trace.

## Install and run

Use Python 3.12+ with `jsonschema>=4.18,<5` and `PyYAML>=6.0.3,<7`:

```text
python -m pip install -r checker/requirements.txt
python -m checker check
python -m checker check --callgraph contracts/fixtures/callgraph.example.json --catalog contracts/fixtures/catalog.example.yaml
python -m checker check -o .dist/scxa-findings.json
python -m unittest discover -s checker/tests -v
python tools/validate_contracts.py
```

The runner checks installed dependency versions before schema resolution. Older jsonschema releases, including Ubuntu's reported 4.10.3 package, can fail resolving the contracts' relative `$id` values. Unsupported versions produce an installation hint instead of reaching that resolution failure. Checker CI uses this requirements file on Windows/Linux with Python 3.12-3.14, and also runs tests with the minimum dependency versions. The separate `contracts.yml` workflow owns repository-wide fixture/output validation.

On Linux, `./scxa check` is available; on Windows use `python scxa check` or the module form above. Fixture defaults resolve relative to the repository even when the script is invoked from another directory.

`--catalog` currently accepts **one JSON or YAML file**, containing the complete catalog envelope (`kernel_version` and `invariants`) defined by the existing catalog schema. It does not read a directory or merge per-invariant files. Directory input is rejected explicitly.

JSON goes to stdout or the `-o` file; diagnostics go to stderr. Exit 0 means the runner completed and its output conforms to the contract. Exit 2 reports invalid input, version/contract mismatch, invalid plugin output, unsupported dependencies, or an I/O error. Neither exit code is an invariant verdict.

Schema errors show a JSON path and the validation message, for example:

```text
scxa check: $: 'kernel_version' is a required property
```

Nested errors identify the failing value, such as `$.roots[0]` or `$.findings[0].verdict`, without dumping the schema. Paths for missing properties point to the containing object.

The findings envelope's `callgraph` string uses a repository-relative path with forward slashes whenever the resolved input is inside this checkout, including for default arguments and absolute input paths. For example, the fixture is recorded as `contracts/fixtures/callgraph.example.json`. Inputs outside the checkout retain a resolved absolute path, normalized to forward slashes; those external paths remain machine-specific. This uses the existing schema field without changing its type or meaning.

## Current C1 layout

```text
checker/
  __init__.py          public Finding/check exports
  __main__.py          python -m checker check
  runner.py            loading, dependency/contract checks, plugin execution
  requirements.txt    compatible dependency ranges
  checkers/__init__.py explicit plugin registry (empty in C1)
  tests/test_runner.py
scxa                  repository-root script entry point
```

## Plugin contract and output

The API remains `checker.check(callgraph: dict, catalog: dict) -> list[Finding]`. `Finding` is a dictionary matching an item in the shared findings schema. The CLI adds `kernel_version` and the callgraph path around that list. The schema supports `holds`, `violated`, `unknown`, and `not_applicable` verdicts; C1 supplies no semantic verdicts itself.

Register a function with `checker.checkers.register("I1", fn)`. It has the same signature as `check`, must return a list, and may report only its registered invariant ID and kfuncs among the graph roots. Registration IDs must be unique and present in the catalog. Plugins run in sorted invariant-ID order. A future plugin module can import `Finding` and `register` from `checker.checkers` and be explicitly imported/registered at the end of that package's `__init__.py`.

The runner validates the real input schemas and findings envelope, rejects mismatched source versions, duplicate catalog IDs, missing root nodes, incorrect invariant/root references, and values that cannot be serialized as JSON. An empty registry and an installed plugin returning no findings receive distinct diagnostics; neither is proof that invariants hold. No I1/I2/I3 analysis, lockset/context model, guard analysis, or enforcement classifier is implemented by C1.

`KERNEL_VERSION` remains TBD. Version strings are opaque identifiers compared for equality. Existing fixture/catalog assumptions and example verdicts require source verification against the team's agreed kernel before semantic analysis can rely on them.

## Shared contract review and follow-up work

The existing findings schema remains the working integration contract, unchanged by these C1 improvements. This change does not declare downstream sign-off or alter the schema under the label of finalization. Finalization should be reviewed with the Epic D consumer (`@othmanehousni`, alongside `@housss77` in CODEOWNERS); any agreed changes belong in a coordinated follow-up PR with matching consumer updates and fixtures.

Directory-based catalog loading is deferred for coordination with Epic A. The current schema describes a complete catalog envelope, while the proposed `catalog/invariants/I1.yaml`, `I2.yaml`, etc. may be fragments. Directory support needs an agreed file/envelope format, kernel-version handling, deterministic merge order, and duplicate-ID policy. C1 will not invent those shared semantics or change the schema to accommodate them.

Related work covers execution-context facts (#33), interprocedural lockset analysis (#34), and guard analysis (#35). Those implementations remain in their respective changes; this PR is limited to C1. Shared contract or fixture changes need consumer review under CODEOWNERS.
