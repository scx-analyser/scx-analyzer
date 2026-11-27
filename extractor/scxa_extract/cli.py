"""`scxa extract` and `scxa dot` (the root `scxa` launcher routes these here)."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import extract
from .dot import to_dot

REPO = extract.REPO


def ensure_ir(args: argparse.Namespace) -> None:
    """Build the IR with build_kernel_ir.sh when it is missing and --kernel is given."""
    missing = [p for p in (args.ir or [args.build_dir / rel for rel in extract.DEFAULT_IR]) if not p.exists()]
    if not missing or args.ir:
        return
    if args.kernel is None or args.no_build:
        raise FileNotFoundError(f"{missing[0]} not found; run extractor/build_kernel_ir.sh "
                                "or pass --kernel DIR to build it")
    print(f"scxa extract: building IR from {args.kernel} into {args.build_dir}", file=sys.stderr)
    subprocess.run([str(REPO / "extractor/build_kernel_ir.sh"), "--kernel-src", str(args.kernel),
                    "--build-dir", str(args.build_dir)], check=True)


def cmd_extract(argv: list[str]) -> int:
    parser = extract.build_parser()
    parser.add_argument("--no-build", action="store_true", help="never run build_kernel_ir.sh")
    args = parser.parse_args(argv)
    try:
        ensure_ir(args)
        graph = extract.run(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"scxa extract: {exc}", file=sys.stderr)
        return 2
    extract.write(graph, args.output)
    return 0


def cmd_dot(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="scxa dot", description="Render the call graph (from one kfunc) as Graphviz DOT")
    parser.add_argument("kfunc", nargs="?", help="start node (default: the whole graph)")
    parser.add_argument("--callgraph", type=Path,
                        help="callgraph JSON (default: extract from extractor/build/ on the fly)")
    parser.add_argument("--depth", type=int, help="only nodes within N calls of the start node")
    parser.add_argument("--no-details", action="store_true", help="names and files only, no event/field summary")
    parser.add_argument("-o", "--output", type=Path, help="write DOT here (default stdout); render with dot -Tsvg")
    args = parser.parse_args(argv)
    try:
        if args.callgraph:
            graph = json.loads(args.callgraph.read_text(encoding="utf-8"))
        else:
            graph = extract.run(extract.build_parser().parse_args([]))
        text = to_dot(graph, args.kfunc, args.depth, not args.no_details)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"scxa dot: {exc}", file=sys.stderr)
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


COMMANDS = {"extract": cmd_extract, "dot": cmd_dot}


def main(argv: list[str]) -> int:
    return COMMANDS[argv[0]](argv[1:])
