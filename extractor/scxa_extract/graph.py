"""Build the annotated call graph from one or more parsed IR modules.

Every kernel function is a node, whether the IR keeps it out of line or only as
inlined copies: inlined code is attributed to its source function through the
DILocation inlinedAt chain, and each inline expansion becomes a call edge at the
line of the call site. Copies of the same function (several inline expansions,
or an out-of-line body in more than one module) are merged into one node.
"""
from __future__ import annotations

import csv
import re
from collections import deque
from fnmatch import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from .debuginfo import DebugInfo, Frame, Source, Subprogram
from .fields import FieldResolver
from .ir import Function, Instruction, Module, call_target

GENERATOR = "scxa-extract 0.1"

def is_intrinsic(name: str) -> bool:
    return name.startswith("llvm.")


# Functions that never touch the tracked scheduler state: their calls are left out
# of the graph entirely (no node, no edge). Patterns are full-match regexes.
DEFAULT_STOP = (
    r"lock_acquire|lock_release|lock_pin_lock|lock_unpin_lock|lock_repin_lock|lockdep_(?!assert)\w+|"
    r"debug_lockdep_rcu_enabled|rcu_is_watching|rcu_read_lock_held\w*|__rcu_read_(?:un)?lock|"
    r"rcu_read_(?:un)?lock(?:_sched)?(?:_notrace)?|class_rcu_\w+|rcu_lock_(?:acquire|release)|__rcu_\w+",
    r"__SCT__\w+|__SCK__\w+|__traceiter_\w+|__do_trace_\w+|trace_\w+|perf_\w+|__perf_\w+",
    r"_?printk\w*|vprintk\w*|__warn_printk|__WARN_printf|dump_stack\w*",
    r"__asan_\w+|__kasan_\w+|kasan_\w+|__kcsan_\w+|kcsan_\w+|__ubsan_\w+|__sanitizer_\w+|__kmsan_\w+",
    r"__might_sleep|__might_resched|__cant_sleep|__cant_migrate|might_fault",
)

# Generic library code (include/, arch/): when inlined, its instructions are
# attributed to the calling function at the call-site line, so e.g. the stores of an
# inlined list_add() are writes of the caller.
LIBRARY_PREFIXES = ("include/", "arch/")


def is_library(sub: Subprogram) -> bool:
    return sub.file.startswith(LIBRARY_PREFIXES) and not sub.file.startswith("include/linux/sched/ext.h")


# Files whose functions are expanded; anything else is recorded as a boundary node.
DEFAULT_EXPAND = ("kernel/sched/ext*.c", "kernel/sched/ext*.h", "kernel/sched/sched.h", "include/linux/sched/ext.h")
DEFAULT_MAX_DEPTH = 12


@dataclass
class Limits:
    """B4: how far to follow the graph."""
    max_depth: int = DEFAULT_MAX_DEPTH
    stop: tuple[str, ...] = DEFAULT_STOP
    expand: tuple[str, ...] = DEFAULT_EXPAND

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError("max depth must be >= 0")
        self._stop = re.compile("|".join(f"(?:{p})" for p in self.stop)) if self.stop else None

    def stopped(self, name: str) -> bool:
        return bool(self._stop and self._stop.fullmatch(name))

    def expandable(self, file: str | None) -> bool:
        return file is not None and any(fnmatch(file, pattern) for pattern in self.expand)


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
    reads: set[str] = field(default_factory=set)
    writes: set[str] = field(default_factory=set)

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
    def __init__(self, modules: list[Module], kernel_root: Path | None, collapse_library: bool = True):
        self.modules = modules
        self.collapse_library = collapse_library
        self.debug = {id(m): DebugInfo(m, kernel_root) for m in modules}
        self.fields = {id(m): FieldResolver(m) for m in modules}
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
        """Index of the frame an instruction is attributed to: the innermost frame
        that is not inlined generic library code (the physical function at worst)."""
        if not self.collapse_library:
            return 0
        for i, frame in enumerate(frames[:-1]):
            if not is_library(frame.sub):
                return i
        return len(frames) - 1

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
        self.fields[id(module)].start_function(fn)
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
        access = self.fields[id(module)].access(inst)
        if access is not None:
            kind, ref, _ = access
            facts = self.facts(ctx.owner)
            if kind in ("read", "rmw"):
                facts.reads.add(ref)
            if kind in ("write", "rmw"):
                facts.writes.add(ref)
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
    def node_kind(self, facts: NodeFacts, kfuncs: set[str], expanded: bool) -> str:
        if facts.name in kfuncs and expanded:
            return "kfunc"
        if not (facts.defined or facts.inlined):
            return "external"
        return "internal" if expanded else "boundary"

    def callees(self, facts: NodeFacts) -> list[Site]:
        return sorted(facts.sites.values(), key=lambda s: (s.line, s.target, s.kind))

    def expanded(self, name: str, depth: int, roots: set[str], limits: Limits) -> bool:
        """Whether a reachable node's own callees are followed."""
        facts = self.nodes[name]
        if not (facts.defined or facts.inlined):
            return False                      # external: nothing to expand
        if name in roots:
            return True
        if depth >= limits.max_depth:
            return False
        return limits.expandable(facts.sub.file if facts.sub else None)

    def reachable(self, roots: list[str], limits: Limits) -> tuple[dict[str, int], set[str]]:
        """Shortest depth of every recorded node, and the set of expanded nodes."""
        depth: dict[str, int] = {}
        expanded: set[str] = set()
        queue = deque()
        for root in roots:
            if root in self.nodes and root not in depth:
                depth[root] = 0
                queue.append(root)
        while queue:
            name = queue.popleft()
            if not self.expanded(name, depth[name], set(roots), limits):
                continue
            expanded.add(name)
            for site in self.callees(self.nodes[name]):
                if site.kind != "direct" or site.target in depth or site.target not in self.nodes:
                    continue
                if limits.stopped(site.target):
                    continue
                depth[site.target] = depth[name] + 1
                queue.append(site.target)
        return depth, expanded

    def node_json(self, facts: NodeFacts, kind: str, depth: int, limits: Limits) -> dict:
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
        if kind not in ("boundary", "external"):
            if facts.reads:
                out["reads"] = sorted(facts.reads)
            if facts.writes:
                out["writes"] = sorted(facts.writes)
        sites = [] if kind in ("boundary", "external") else \
            [s for s in self.callees(facts) if not (s.kind == "direct" and limits.stopped(s.target))]
        out["callees"] = [{"target": s.target, "kind": s.kind, "line": s.line} if s.line > 0
                          else {"target": s.target, "kind": s.kind} for s in sites]
        return out

    def to_json(self, roots: list[str], kfuncs: set[str], kernel_version: str,
                kernel_commit: str | None, limits: Limits | None = None) -> dict:
        limits = limits or Limits()
        missing = [r for r in roots if r not in self.nodes]
        if missing:
            raise ValueError("roots not found in the IR: " + ", ".join(missing))
        depth, expanded = self.reachable(roots, limits)
        nodes = {}
        for name in sorted(depth):
            facts = self.nodes[name]
            kind = self.node_kind(facts, kfuncs, name in expanded)
            nodes[name] = self.node_json(facts, kind, depth[name], limits)
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
