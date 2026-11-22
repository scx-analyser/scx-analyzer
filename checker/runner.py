"""Contract-checked runner for pluggable kernel invariant analyses.

C1 only builds the trustworthy boundary. It does not infer semantic safety.
"""
from __future__ import annotations

import json
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .checkers import Finding, registered

ROOT = Path(__file__).resolve().parents[1]


def require_compatible_dependencies() -> None:
    """Fail before schema resolution when an unsupported system package is used."""
    for package, lower, upper, requirement in (
        ("jsonschema", (4, 18, 0), (5, 0, 0), "jsonschema>=4.18,<5"),
        ("PyYAML", (6, 0, 3), (7, 0, 0), "PyYAML>=6.0.3,<7"),
    ):
        try:
            installed = version(package)
        except PackageNotFoundError as exc:
            raise ValueError(f"missing {package} metadata; install -r checker/requirements.txt") from exc
        release = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.post\d+)?(?:\+[A-Za-z0-9.]+)?", installed)
        parsed = tuple(int(part or 0) for part in release.groups()) if release else None
        if parsed is None or not lower <= parsed < upper:
            raise ValueError(f"requires {requirement}; found {installed}. "
                             "Run python -m pip install -r checker/requirements.txt")


def load_data(path: Path) -> dict[str, Any]:
    """Load JSON or YAML, rejecting arrays and scalars at the document root."""
    if path.is_dir():
        raise ValueError(f"expected one JSON or YAML file, got a directory: {path}")
    if not path.is_file():
        raise ValueError(f"file not found: {path}")
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) if path.suffix.lower() in (".yaml", ".yml") else json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"expected an object at document root: {path}")
    return data


def validate(kind: str, data: dict[str, Any]) -> None:
    """Validate data against the repository's JSON Schema contract."""
    if kind not in {"callgraph", "catalog", "findings"}:
        raise ValueError(f"unknown contract: {kind}")
    require_compatible_dependencies()
    schema = json.loads((ROOT / "contracts" / f"{kind}.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(data)
    # JSON Schema permits arbitrary metadata in some nested objects. Reject
    # Python-only values there before they can break output serialization.
    try:
        json.dumps(data, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{kind} must be JSON-serializable: {exc}") from exc


def check(callgraph: dict[str, Any], catalog: dict[str, Any]) -> list[Finding]:
    """Run registered semantic checkers and return validated Finding objects.

    The bundled registry is empty, so no semantic checks run in C1. An empty
    list is not evidence that any invariant holds, even with plugins installed.
    All roots and evidence must be resolved by the checker implementation;
    the runner never guesses a verdict.
    """
    validate("callgraph", callgraph)
    validate("catalog", catalog)
    if callgraph["kernel_version"] != catalog["kernel_version"]:
        raise ValueError("kernel version mismatch between callgraph and catalog")

    result: list[Finding] = []
    valid_invariants = {item["id"] for item in catalog["invariants"]}
    if len(valid_invariants) != len(catalog["invariants"]):
        raise ValueError("duplicate invariant id in catalog")
    roots = set(callgraph["roots"])
    missing_roots = roots - callgraph["nodes"].keys()
    if missing_roots:
        raise ValueError(f"callgraph roots missing from nodes: {', '.join(sorted(missing_roots))}")
    for inv_id, fn in sorted(registered().items()):
        if inv_id not in valid_invariants:
            raise ValueError(f"checker {inv_id} is not present in the invariant catalog")
        values = fn(callgraph, catalog)
        if not isinstance(values, list):
            raise TypeError(f"checker {inv_id} must return a list")
        for finding in values:
            if not isinstance(finding, dict):
                raise TypeError(f"checker {inv_id} returned a non-object finding")
            if finding.get("invariant") != inv_id:
                raise ValueError(f"checker {inv_id} reported a mismatched invariant id")
            kfunc = finding.get("kfunc")
            if not isinstance(kfunc, str) or kfunc not in roots:
                raise ValueError(f"checker {inv_id} reported a non-root kfunc")
            result.append(finding)
    # Validate the actual envelope too, so malformed plugin outputs fail early.
    validate("findings", {"kernel_version": callgraph["kernel_version"], "findings": result})
    return result
