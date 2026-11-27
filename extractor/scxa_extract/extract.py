"""Command line: build callgraph.json from the IR produced by build_kernel_ir.sh."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .graph import DEFAULT_EXPAND, DEFAULT_MAX_DEPTH, Limits, Program, read_kfuncs
from .ir import btf_kfunc_sets, parse_module

REPO = Path(__file__).resolve().parents[2]
DEFAULT_IR = ("kernel/sched/build_policy.ll", "kernel/sched/core.ll")


def infer_kernel_root(module_text_paths: list[Path], modules) -> Path | None:
    """The kernel root is the directory the compile unit's kernel/sched/*.c lives in."""
    for module in modules:
        for text in module.metadata.values():
            m = re.search(r'!DIFile\(filename: "([^"]*/)kernel/sched/(?:build_policy|core)\.c", directory: "([^"]*)"', text)
            if m:
                root = Path(m.group(2)) / m.group(1)
                if (root / "kernel/sched/ext.c").exists():
                    return root.resolve()
    return None


def read_manifest(build_dir: Path) -> dict[str, str]:
    values = {}
    try:
        for line in (build_dir / "ir-manifest.txt").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition(": ")
            values.setdefault(key, value)
    except OSError:
        pass
    return values


def pinned_version() -> str:
    try:
        for line in (REPO / "KERNEL_VERSION").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return "TBD (see KERNEL_VERSION)" if line.upper().startswith("TBD") else line
    except OSError:
        pass
    return "TBD (see KERNEL_VERSION)"


def ir_kfuncs(modules) -> list[str]:
    """Every kfunc registered in an scx_kfunc_ids_* BTF set, in set order."""
    names: list[str] = []
    for module in modules:
        for members in btf_kfunc_sets(module).values():
            names.extend(n for n in members if n not in names)
    return names


def parse_roots(value: str | None, modules) -> tuple[list[str], set[str]]:
    """--roots: a kfuncs.csv path or comma-separated names. Returns (roots, kfunc names).

    Default: catalog/kfuncs.csv if present, else every kfunc found in the IR's
    BTF kfunc sets. Kfuncs in the IR are always marked kind=kfunc."""
    known = set(ir_kfuncs(modules))
    if value is None:
        csv_path = REPO / "catalog/kfuncs.csv"
        names = read_kfuncs(csv_path) if csv_path.exists() else ir_kfuncs(modules)
    elif value.endswith(".csv") or Path(value).is_file():
        names = read_kfuncs(Path(value))
    else:
        names = [n.strip() for n in value.split(",") if n.strip()]
    return names, known | set(names)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="scxa extract", description="Extract the annotated sched_ext call graph from kernel IR")
    p.add_argument("--build-dir", type=Path, default=REPO / "extractor/build",
                   help="output directory of build_kernel_ir.sh (default extractor/build)")
    p.add_argument("--ir", type=Path, action="append",
                   help="IR file to read (repeatable; default: build_policy.ll and core.ll in --build-dir)")
    p.add_argument("--kernel", type=Path, help="kernel source tree (default: inferred from the IR debug info); "
                                              "with `scxa extract`, the IR is built from it if missing")
    p.add_argument("--roots", help="kfuncs.csv path or comma-separated kfunc names "
                                   "(default catalog/kfuncs.csv, else every kfunc in the IR's BTF sets)")
    p.add_argument("--depth", type=int, default=DEFAULT_MAX_DEPTH,
                   help=f"maximum call depth; nodes at this depth are boundary nodes (default {DEFAULT_MAX_DEPTH})")
    p.add_argument("--expand", action="append", metavar="GLOB",
                   help="also expand functions defined in files matching GLOB, e.g. kernel/sched/core.c "
                        f"(always expanded: {', '.join(DEFAULT_EXPAND)}); others are boundary nodes")
    p.add_argument("--stop", action="append", metavar="REGEX",
                   help="leave out calls to functions whose name fully matches REGEX (adds to the built-in stop-list)")
    p.add_argument("--no-default-stop", action="store_true", help="do not apply the built-in stop-list")
    p.add_argument("-o", "--output", type=Path, help="write JSON here (default stdout)")
    return p


def run(args: argparse.Namespace) -> dict:
    ir_files = args.ir or [args.build_dir / rel for rel in DEFAULT_IR]
    for path in ir_files:
        if not path.exists():
            raise FileNotFoundError(f"{path} not found; run extractor/build_kernel_ir.sh first")
    modules = [parse_module(path) for path in ir_files]
    kernel = args.kernel.resolve() if args.kernel else infer_kernel_root(ir_files, modules)
    roots, kfuncs = parse_roots(args.roots, modules)
    program = Program(modules, kernel)
    program.collect()
    manifest = read_manifest(args.build_dir)
    limits = Limits(args.depth,
                    (() if args.no_default_stop else Limits().stop) + tuple(args.stop or ()),
                    DEFAULT_EXPAND + tuple(args.expand or ()))
    return program.to_json(roots, kfuncs, pinned_version(), manifest.get("kernel_commit"), limits)


def write(graph: dict, output: Path | None) -> None:
    text = json.dumps(graph, indent=1) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"wrote {len(graph['nodes'])} nodes for {len(graph['roots'])} roots to {output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    from .cli import cmd_extract
    return cmd_extract(sys.argv[1:] if argv is None else argv)
