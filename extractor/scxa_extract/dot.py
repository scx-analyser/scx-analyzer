"""B8: render (part of) a call graph as Graphviz DOT."""
from __future__ import annotations

from collections import deque

KIND_STYLE = {
    "kfunc": 'shape=box, style="filled,bold", fillcolor="#dbe8fb"',
    "internal": 'shape=box, style=filled, fillcolor="#f4f4f4"',
    "boundary": 'shape=box, style="filled,dashed", fillcolor="#fff5d6"',
    "external": 'shape=box, style=dashed, color="#888888", fontcolor="#555555"',
}
EVENT_LABELS = (("lock", "lock"), ("unlock", "unlock"), ("assert_held", "assert"), ("assert_not_held", "assert!"),
                ("atomic", "atomic"), ("write", "write"), ("guard", "guard"), ("error", "error"), ("warn", "warn"))


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def subgraph(graph: dict, root: str | None, depth: int | None) -> dict[str, int]:
    """Nodes reachable from `root` (all nodes if None) within `depth` calls."""
    nodes = graph["nodes"]
    if root is None:
        return {name: node.get("depth", 0) for name, node in nodes.items()}
    if root not in nodes:
        raise ValueError(f"{root} is not a node of the call graph")
    seen = {root: 0}
    queue = deque([root])
    while queue:
        name = queue.popleft()
        if depth is not None and seen[name] >= depth:
            continue
        for callee in nodes[name].get("callees", []):
            target = callee["target"]
            if target in nodes and target not in seen:
                seen[target] = seen[name] + 1
                queue.append(target)
    return seen


def label(name: str, node: dict, details: bool) -> str:
    lines = [name]
    if node.get("file"):
        lines.append(f'{node["file"]}:{node.get("line", "?")}')
    if details:
        counts = {}
        for event in node.get("events", []):
            counts[event["kind"]] = counts.get(event["kind"], 0) + 1
        summary = ", ".join(f"{counts[k]} {text}" for k, text in EVENT_LABELS if counts.get(k))
        if summary:
            lines.append(summary)
        locks = sorted({e["lock"] for e in node.get("events", []) if e["kind"] in ("lock", "assert_held")})
        if locks:
            lines.append("locks: " + ", ".join(locks))
        writes = node.get("writes", [])
        if writes:
            shown = ", ".join(w.split(".", 1)[1] if "." in w else w for w in writes[:4])
            lines.append("writes: " + shown + (f" (+{len(writes) - 4})" if len(writes) > 4 else ""))
    return "\\n".join(line.replace('"', '\\"') for line in lines)


def to_dot(graph: dict, root: str | None = None, depth: int | None = None, details: bool = True) -> str:
    nodes = graph["nodes"]
    keep = subgraph(graph, root, depth)
    title = f"{root} (depth {depth})" if root and depth is not None else (root or "call graph")
    out = ["digraph scxa {",
           f"  label={_quote(title + ' - ' + graph.get('kernel_version', '?'))}; labelloc=t; rankdir=LR;",
           '  node [fontname="Helvetica", fontsize=10]; edge [fontname="Helvetica", fontsize=8];']
    for name in sorted(keep, key=lambda n: (keep[n], n)):
        node = nodes[name]
        out.append(f'  {_quote(name)} [label="{label(name, node, details)}", {KIND_STYLE.get(node["kind"], "")}];')
    indirect_targets = set()
    for name in sorted(keep):
        for callee in nodes[name].get("callees", []):
            target, line = callee["target"], callee.get("line")
            attrs = [f'label="{line}"'] if line else []
            if callee["kind"] == "indirect":
                attrs.append("style=dashed")
                if target not in nodes:
                    indirect_targets.add(target)
            if target in keep or target in indirect_targets:
                out.append(f"  {_quote(name)} -> {_quote(target)}" + (f" [{', '.join(attrs)}]" if attrs else "") + ";")
    for target in sorted(indirect_targets):
        out.append(f'  {_quote(target)} [shape=ellipse, style=dashed, color="#aa5500", fontcolor="#aa5500"];')
    out.append("}")
    return "\n".join(out) + "\n"
