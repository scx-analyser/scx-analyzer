"""Minimal reader for textual LLVM IR (.ll) as emitted by clang 18 for the kernel.

It keeps only what the extractor needs: function bodies (instructions with their
!dbg attachment), declarations, named struct types and the metadata table, with a
small parser for the specialized DI* metadata nodes. It is not a general IR parser.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_DEFINE = re.compile(r'^define\b.*?@("(?:[^"\\]|\\.)*"|[\w.$]+)\(')
_DECLARE = re.compile(r'^declare\b.*?@("(?:[^"\\]|\\.)*"|[\w.$]+)\(')
_FUNC_DBG = re.compile(r'!dbg !(\d+)\s*\{\s*$')
_TYPE = re.compile(r'^(%[\w.$"]+) = type (.*)$')
_META = re.compile(r'^!(\d+) = (?:distinct )?(.*)$')
_INST_DBG = re.compile(r', !dbg !(\d+)')
_RESULT = re.compile(r'^\s*(%[\w.$]+|%"[^"]*") = ')
_LABEL = re.compile(r'^([\w.$-]+):')


def _unquote(name: str) -> str:
    return name[1:-1] if name.startswith('"') else name


@dataclass
class Instruction:
    text: str                 # the instruction without leading whitespace
    result: str | None        # SSA result name (with %), if any
    dbg: int | None           # !dbg metadata id
    block: str                # enclosing basic block label

    @property
    def opcode(self) -> str:
        body = self.text.split(" = ", 1)[1] if self.result else self.text
        for prefix in ("tail ", "musttail ", "notail "):
            if body.startswith(prefix):
                body = body[len(prefix):]
        return body.split(" ", 1)[0]


@dataclass
class Function:
    name: str
    dbg: int | None
    linkage_internal: bool
    instructions: list[Instruction] = field(default_factory=list)
    defs: dict[str, Instruction] = field(default_factory=dict)   # SSA name -> defining instruction
    args: list[str] = field(default_factory=list)                 # argument SSA names


@dataclass
class Module:
    path: Path
    functions: dict[str, Function]
    declarations: set[str]
    types: dict[str, str]          # '%struct.task_struct' -> body text
    metadata: dict[int, str]       # id -> raw text after '='
    module_asm: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._parsed: dict[int, tuple[str, dict[str, str]] | list[str]] = {}

    def node(self, ref: int | None) -> tuple[str, dict[str, str]] | None:
        """Parse a specialized metadata node: ('DILocation', {'line': '12', ...})."""
        if ref is None or ref not in self.metadata:
            return None
        cached = self._parsed.get(ref)
        if cached is None:
            cached = parse_di(self.metadata[ref])
            self._parsed[ref] = cached
        return cached if isinstance(cached, tuple) else None

    def tuple_items(self, ref: int | None) -> list[str]:
        """Items of a generic metadata tuple !{!1, !2, ...}."""
        if ref is None or ref not in self.metadata:
            return []
        text = self.metadata[ref].strip()
        if not text.startswith("!{"):
            return []
        return [item.strip() for item in _split_top(text[2:-1])]


def ref_id(value: str | None) -> int | None:
    if value and value.startswith("!") and value[1:].isdigit():
        return int(value[1:])
    return None


def _split_top(text: str) -> list[str]:
    """Split on commas outside quotes and brackets."""
    parts, depth, quote, start, i = [], 0, False, 0, 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == '"':
                quote = False
        elif ch == '"':
            quote = True
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    if text[start:].strip():
        parts.append(text[start:])
    return parts


def parse_di(text: str) -> tuple[str, dict[str, str]] | list[str]:
    text = text.strip()
    m = re.match(r"!(DI\w+)\((.*)\)$", text, re.S)
    if not m:
        return []
    fields: dict[str, str] = {}
    for part in _split_top(m.group(2)):
        key, _, value = part.partition(":")
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key.strip()] = value
    return m.group(1), fields


def _define_args(line: str, open_paren: int) -> list[str]:
    """SSA names of the parameters in `define ... @f(<params>)`."""
    depth = 0
    for i in range(open_paren, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                params = _split_top(line[open_paren + 1:i])
                return [p.split()[-1] for p in params if p.split() and p.split()[-1].startswith("%")]
    return []


def parse_module(path: Path) -> Module:
    functions: dict[str, Function] = {}
    declarations: set[str] = set()
    types: dict[str, str] = {}
    metadata: dict[int, str] = {}
    module_asm: list[str] = []
    current: Function | None = None
    block = "entry"
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if current is not None:
                if line.startswith("}"):
                    current = None
                    continue
                if not line.strip() or line.lstrip().startswith(";"):
                    continue
                if not line.startswith(" "):
                    label = _LABEL.match(line)
                    if label:
                        block = label.group(1)
                    continue
                text = line.strip()
                dbg = _INST_DBG.search(text)
                result = _RESULT.match(line)
                inst = Instruction(text, result.group(1) if result else None,
                                   int(dbg.group(1)) if dbg else None, block)
                current.instructions.append(inst)
                if inst.result:
                    current.defs[inst.result] = inst
                continue
            if line.startswith("define"):
                m = _DEFINE.match(line)
                if not m:
                    continue
                name = _unquote(m.group(1))
                dbg = _FUNC_DBG.search(line)
                header = line.split("(", 1)[0]
                current = Function(name, int(dbg.group(1)) if dbg else None,
                                   " internal " in header or " private " in header)
                current.args = _define_args(line, m.end() - 1)
                functions[name] = current
                block = "entry"
            elif line.startswith("declare"):
                m = _DECLARE.match(line)
                if m:
                    declarations.add(_unquote(m.group(1)))
            elif line.startswith("module asm "):
                module_asm.append(line[len("module asm "):].strip().strip('"'))
            elif line.startswith("!"):
                m = _META.match(line.rstrip("\n"))
                if m:
                    metadata[int(m.group(1))] = m.group(2)
            elif line.startswith("%"):
                m = _TYPE.match(line.rstrip("\n"))
                if m:
                    types[m.group(1)] = m.group(2)
    return Module(path, functions, declarations, types, metadata, module_asm)


_BTF_SET = re.compile(r"__BTF_ID__set8__(\w+)")
_BTF_FUNC = re.compile(r"__BTF_ID__func__(\w+?)__\d+\b")


def btf_kfunc_sets(module: Module, prefix: str = "scx_kfunc_ids_") -> dict[str, list[str]]:
    """BTF_KFUNCS_START(set) ... BTF_ID_FLAGS(func, name) entries, read from the
    module-level asm that BTF_ID emits: {set name: [kfunc, ...]}."""
    sets: dict[str, list[str]] = {}
    current: str | None = None
    for line in module.module_asm:
        start = _BTF_SET.search(line)
        if start:
            current = start.group(1) if start.group(1).startswith(prefix) else None
            continue
        func = _BTF_FUNC.search(line)
        if func and current is not None:
            names = sets.setdefault(current, [])
            if func.group(1) not in names:
                names.append(func.group(1))
    return sets


_CALL = re.compile(r'\bcall\b[^@%]*?(?:(@[\w.$]+|@"[^"]*")|(%[\w.$]+)|(asm)\b)\s*[("]')


_ASM_CALL = re.compile(r'(?:tail |musttail |notail )?(?:call|callbr)\b[^"@%]*?\basm\b')


def call_target(inst: Instruction) -> tuple[str, str] | None:
    """('direct', name) | ('indirect', %value) | ('asm', text) for call/invoke instructions."""
    if inst.opcode not in ("call", "invoke", "callbr"):
        return None
    body = inst.text.split(" = ", 1)[1] if inst.result else inst.text
    if _ASM_CALL.match(body):
        return "asm", body
    m = _CALL.search(body)
    if not m:
        return None
    if m.group(1):
        return "direct", _unquote(m.group(1)[1:])
    if m.group(2):
        return "indirect", m.group(2)
    return "asm", body


def call_args(inst: Instruction) -> list[str]:
    """Argument operand texts of a call (best effort, top-level split)."""
    body = inst.text.split(" = ", 1)[1] if inst.result else inst.text
    m = _CALL.search(body)
    if not m:
        return []
    start = body.find("(", m.end() - 1)
    if m.group(3):            # asm "..." "constraints"(args)
        start = body.find('"(', m.end())
        start = start + 1 if start >= 0 else -1
    if start < 0:
        return []
    depth, i = 0, start
    while i < len(body):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return [a.strip() for a in _split_top(body[start + 1:i])]
