"""CLI: python3 -m checker check --callgraph path [--catalog path]."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jsonschema
import yaml

from .checkers import registered
from .runner import ROOT, check, load_data, validate


def portable_callgraph_path(path: Path) -> str:
    """Use repository-relative POSIX paths, with an absolute fallback outside it."""
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scxa", description="sched_ext constraint analyzer")
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("check", help="validate inputs and run semantic checker plugins")
    cmd.add_argument("--callgraph", type=Path, default=ROOT / "contracts/fixtures/callgraph.example.json")
    cmd.add_argument("--catalog", type=Path, default=ROOT / "contracts/fixtures/catalog.example.yaml",
                     help="one JSON or YAML catalog file (directory input is not supported)")
    cmd.add_argument("-o", "--output", type=Path, help="write findings JSON (otherwise stdout)")
    args = parser.parse_args(argv)

    try:
        graph = load_data(args.callgraph)
        catalog = load_data(args.catalog)
        has_checkers = bool(registered())
        findings = check(graph, catalog)
        output = {"kernel_version": graph["kernel_version"],
                  "callgraph": portable_callgraph_path(args.callgraph), "findings": findings}
        validate("findings", output)
        serialized = json.dumps(output, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized, encoding="utf-8")
            print(f"wrote {len(findings)} finding(s) to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(serialized)
        if not has_checkers:
            print("note: 0 findings; no semantic checkers installed (no safety claim)", file=sys.stderr)
        elif not findings:
            print("note: installed checkers returned 0 findings (no safety claim)", file=sys.stderr)
        return 0
    except (jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        print(f"scxa check: {exc.json_path}: {exc.message}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print(f"scxa check: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
