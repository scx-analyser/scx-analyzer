"""Build the annotated call graph from one or more parsed IR modules.

Every kernel function is a node, whether the IR keeps it out of line or only as
inlined copies: inlined code is attributed to its source function through the
DILocation inlinedAt chain, and each inline expansion becomes a call edge at the
line of the call site. Copies of the same function (several inline expansions,
or an out-of-line body in more than one module) are merged into one node.
"""
from __future__ import annotations

import csv
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .debuginfo import DebugInfo, Frame, Source, Subprogram
from .ir import Function, Instruction, Module, call_target

GENERATOR = "scxa-extract 0.1"

def is_intrinsic(name: str) -> bool:
    return name.startswith("llvm.")


@dataclass
class Site:
    """One call site inside a node."""
    target: str
    kind: str            # direct | indirect
    line: int


@dataclass
class NodeFacts:
    name: str
    sub: Subprogram | None = None
    defined: bool = False          # an out-of-line body exists in some module
    inlined: bool = False          # code of it appears inlined somewhere
    declared: bool = False         # only known from a declaration / call
    sites: dict[tuple[str, str, int], Site] = field(default_factory=dict)

    def add_site(self, target: str, kind: str, line: int) -> None:
        self.sites.setdefault((target, kind, line), Site(target, kind, line))


@dataclass
class Context:
    """What an instruction belongs to after resolving its inline chain."""
    owner: str              # node key the instruction is attributed to
    line: int               # source line in the owner's body
    column: int
    frames: tuple[Frame, ...]


class Program:
    def __init__(self, modules: list[Module], kernel_root: Path | None):
        self.modules = modules
        self.debug = {id(m): DebugInfo(m, kernel_root) for m in modules}
        self.source = Source(kernel_root)
        self.nodes: dict[str, NodeFacts] = {}
        self._key_of_sub: dict[tuple[str, str, int], str] = {}
        # per module: IR function name (may carry .constprop/.llvm suffixes) -> node key
        self.alias: dict[int, dict[str, str]] = {}

    # -- node identity ---------------------------------------------------------
    def key_for(self, sub: Subprogram) -> str:
        """Node key for a subprogram: its name, disambiguated if two different
        definitions share a name (e.g. two static functions in different files)."""
        ident = (sub.name, sub.file, sub.line)
        if ident in self._key_of_sub:
            return self._key_of_sub[ident]
        key = sub.name
        existing = self.nodes.get(key)
        if existing is not None and existing.sub is not None and \
                (existing.sub.file, existing.sub.line) != (sub.file, sub.line):
            key = f"{sub.name}@{Path(sub.file).name}:{sub.line}"
        self._key_of_sub[ident] = key
        facts = self.nodes.setdefault(key, NodeFacts(key))
        if facts.sub is None:
            facts.sub = sub
        return key

    def facts(self, name: str) -> NodeFacts:
        return self.nodes.setdefault(name, NodeFacts(name))

    # -- per-instruction attribution ---------------------------------------------
    def owner_index(self, frames: tuple[Frame, ...]) -> int:
        """Index of the frame an instruction is attributed to. Later stages
        collapse library helpers into their callers; here it is the innermost."""
        return 0

    def context(self, di: DebugInfo, inst: Instruction, fn_key: str) -> Context:
        frames = di.frames(inst.dbg)
        if not frames:
            return Context(fn_key, 0, 0, ())
        k = self.owner_index(frames)
        owner = self.key_for(frames[k].sub)
        return Context(owner, frames[k].line, frames[k].column, frames)

    # -- collection --------------------------------------------------------------
    def resolve(self, module: Module, ir_name: str) -> str:
        return self.alias.get(id(module), {}).get(ir_name, ir_name)

    def collect(self) -> None:
        for module in self.modules:
            di = self.debug[id(module)]
            names = self.alias.setdefault(id(module), {})
            for fn in module.functions.values():
                sub = di.subprogram(fn.dbg)
                if sub is not None:
                    names[fn.name] = self.key_for(sub)
        for module in self.modules:
            di = self.debug[id(module)]
            for fn in module.functions.values():
                self.collect_function(module, di, fn)
            for name in module.declarations:
                if not is_intrinsic(name):
                    self.facts(self.resolve(module, name)).declared = True

    def collect_function(self, module: Module, di: DebugInfo, fn: Function) -> None:
        sub = di.subprogram(fn.dbg)
        fn_key = self.key_for(sub) if sub else fn.name
        self.facts(fn_key).defined = True
        for inst in fn.instructions:
            ctx = self.context(di, inst, fn_key)
            self.add_inline_edges(ctx)
            self.visit_instruction(module, di, fn, inst, ctx)

    def add_inline_edges(self, ctx: Context) -> None:
        """frames[i] (caller) inlined frames[i-1] (callee) at frames[i].line."""
        frames, k = ctx.frames, self.owner_index(ctx.frames)
        for i in range(len(frames) - 1, k, -1):
            caller = self.key_for(frames[i].sub)
            callee = self.key_for(frames[i - 1].sub)
            self.facts(callee).inlined = True
            self.nodes[caller].add_site(callee, "direct", frames[i].line)

    def visit_instruction(self, module: Module, di: DebugInfo, fn: Function,
                          inst: Instruction, ctx: Context) -> None:
        target = call_target(inst)
        if target is None:
            return
        kind, value = target
        if kind == "direct" and not is_intrinsic(value):
            callee = self.resolve(module, value)
            self.facts(callee)
            self.facts(ctx.owner).add_site(callee, "direct", ctx.line)
        elif kind == "indirect":
            self.facts(ctx.owner).add_site("<indirect>", "indirect", ctx.line)

    # -- graph ----------------------------------------------------------------
    def node_kind(self, facts: NodeFacts, kfuncs: set[str]) -> str:
        if facts.name in kfuncs:
            return "kfunc"
        if facts.defined or facts.inlined:
            return "internal"
        return "external"

    def callees(self, facts: NodeFacts) -> list[Site]:
        return sorted(facts.sites.values(), key=lambda s: (s.line, s.target, s.kind))

    def reachable(self, roots: list[str]) -> dict[str, int]:
        """Shortest call depth of every node reachable from the roots."""
        depth: dict[str, int] = {}
        queue = deque()
        for root in roots:
            if root in self.nodes and root not in depth:
                depth[root] = 0
                queue.append(root)
        while queue:
            name = queue.popleft()
            for site in self.callees(self.nodes[name]):
                if site.kind != "direct" or site.target in depth or site.target not in self.nodes:
                    continue
                depth[site.target] = depth[name] + 1
                queue.append(site.target)
        return depth

    def node_json(self, facts: NodeFacts, kind: str, depth: int) -> dict:
        out: dict = {"kind": kind}
        sub = facts.sub
        if sub is not None and sub.file != "?":
            out["file"] = sub.file
            if sub.line > 0:
                out["line"] = sub.line
                end = self.source.end_line(sub.file, sub.line)
                if end:
                    out["end_line"] = end
        out["depth"] = depth
        out["callees"] = [{"target": s.target, "kind": s.kind, "line": s.line} for s in self.callees(facts)
                          if s.line > 0] + [{"target": s.target, "kind": s.kind}
                                            for s in self.callees(facts) if s.line <= 0]
        return out

    def to_json(self, roots: list[str], kfuncs: set[str], kernel_version: str,
                kernel_commit: str | None) -> dict:
        missing = [r for r in roots if r not in self.nodes]
        if missing:
            raise ValueError("roots not found in the IR: " + ", ".join(missing))
        depth = self.reachable(roots)
        nodes = {}
        for name in sorted(depth):
            facts = self.nodes[name]
            nodes[name] = self.node_json(facts, self.node_kind(facts, kfuncs), depth[name])
        graph = {"kernel_version": kernel_version}
        if kernel_commit:
            graph["kernel_commit"] = kernel_commit
        graph.update({"generator": GENERATOR, "roots": list(roots), "nodes": nodes})
        return graph


def read_kfuncs(path: Path) -> list[str]:
    """kfunc names from catalog/kfuncs.csv (column 'name'), in first-seen order."""
    with open(path, newline="", encoding="utf-8") as fh:
        names = [row["name"] for row in csv.DictReader(fh)]
    return list(dict.fromkeys(names))
