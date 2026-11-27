"""B6: classify IR instructions into the ordered events of the call-graph contract.

Events are attributed like field accesses: to the innermost frame that is not
inlined library code or a lock/assert wrapper, at that frame's source line.
Their order is source order (line, column, IR position), which is the program
order of straight-line code; it is not a control-flow graph.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .debuginfo import Frame, Source
from .fields import FieldResolver
from .ir import Function, Instruction, call_args

# -- calls that are events, not call edges ------------------------------------------
# name -> (kind, fixed lock tokens or None to resolve from the first pointer argument, op)
LOCK_CALLS: dict[str, tuple[str, tuple[str, ...] | None, str | None]] = {}
for _n in ("_raw_spin_lock", "_raw_spin_lock_irq", "_raw_spin_lock_irqsave", "_raw_spin_lock_nested",
           "_raw_spin_lock_bh", "_raw_spin_lock_irqsave_nested", "_raw_read_lock", "_raw_write_lock",
           "_raw_read_lock_irqsave", "_raw_write_lock_irqsave", "mutex_lock", "mutex_lock_nested",
           "mutex_lock_interruptible", "percpu_down_read", "percpu_down_write", "down_read", "down_write"):
    LOCK_CALLS[_n] = ("lock", None, None)
for _n in ("_raw_spin_trylock", "_raw_spin_trylock_bh", "mutex_trylock", "percpu_down_read_trylock"):
    LOCK_CALLS[_n] = ("lock", None, "trylock")
for _n in ("_raw_spin_unlock", "_raw_spin_unlock_irq", "_raw_spin_unlock_irqrestore", "_raw_spin_unlock_bh",
           "_raw_read_unlock", "_raw_write_unlock", "_raw_read_unlock_irqrestore", "_raw_write_unlock_irqrestore",
           "mutex_unlock", "percpu_up_read", "percpu_up_write", "up_read", "up_write"):
    LOCK_CALLS[_n] = ("unlock", None, None)
LOCK_CALLS.update({
    "raw_spin_rq_lock_nested": ("lock", ("rq",), None),
    "raw_spin_rq_trylock": ("lock", ("rq",), "trylock"),
    "raw_spin_rq_unlock": ("unlock", ("rq",), None),
    "_task_rq_lock": ("lock", ("pi_lock", "rq"), None),
    "task_rq_lock": ("lock", ("pi_lock", "rq"), None),
    "__task_rq_lock": ("lock", ("rq",), None),
    "task_rq_unlock": ("unlock", ("rq", "pi_lock"), None),
    "__task_rq_unlock": ("unlock", ("rq",), None),
    "double_rq_lock": ("lock", ("rq", "rq"), None),
    "double_rq_unlock": ("unlock", ("rq", "rq"), None),
})
ASSERT_CALL = "lock_is_held_type"
ERROR_CALLS = ("scx_exit", "scx_vexit", "__scx_exit")
SCX_EXIT_ERROR = 1024            # enum scx_exit_kind: SCX_EXIT_ERROR and above are errors

# Inline wrappers from kernel/sched/sched.h & co. that only lock/assert: collapsed into
# their caller, their inner lock/assert calls become events at the caller's line.
PRIMITIVE_FRAME = re.compile(
    r"(?:_|__)?(?:raw_spin_rq|rq|task_rq|this_rq|double_rq|double_raw|double_lock|_double_lock)_\w*lock\w*"
    r"|lockdep_assert_\w+|__rq_lockp|rq_lockp|rq_(?:un|re)?pin_lock|class_\w*lock\w*|sched_core_enabled")
RQ_FRAME = re.compile(r"rq|__rq_lockp")

ATOMIC_FRAME = re.compile(
    r"(?:raw_|arch_)?atomic(?:64|_long)?_\w+|(?:arch_)?(?:test_and_)?(?:set|clear|change)_bit(?:_lock|_unlock)?"
    r"|cpumask_(?:test_and_)?(?:set|clear)_cpu|(?:arch_)?(?:try_)?cmpxchg\w*|(?:arch_)?xchg\w*")
LIST_FRAME = re.compile(r"(?:__)?(?:list|hlist|llist)_\w+|INIT_LIST_HEAD|rb_\w+")


def atomic_op(name: str) -> str:
    for needle, op in (("try_cmpxchg", "cmpxchg"), ("cmpxchg", "cmpxchg"), ("xchg", "xchg"),
                       ("test_and_clear", "test_and_clear_bit"), ("test_and_set", "test_and_set_bit"),
                       ("set_cpu", "set_bit"), ("clear_cpu", "clear_bit"), ("set_bit", "set_bit"),
                       ("clear_bit", "clear_bit"), ("change_bit", "change_bit"),
                       ("set_release", "set_release"), ("read_acquire", "read_acquire"),
                       ("inc", "inc"), ("dec", "dec"), ("add", "add"), ("sub", "sub"), ("fetch_or", "or"),
                       ("fetch_and", "and"), ("_or", "or"), ("_and", "and"), ("andnot", "andnot"),
                       ("_set", "set"), ("_read", "read")):
        if needle in name:
            return op
    return "rmw"


def list_op(name: str) -> str:
    if "del" in name or "erase" in name:
        return "list_del" if not name.startswith("rb_") else "rb_erase"
    if name.startswith("rb_"):
        return "rb_insert"
    return "list_add"


def lock_token(resolver: FieldResolver, pointer: str) -> str | None:
    """rq / dsq / pi_lock / <global name> / <field> for a lock pointer."""
    if pointer.startswith("@"):
        return pointer[1:]
    place = resolver.place(pointer)
    if place is None:
        return None
    name = resolver.dwarf.name_of(place.root)
    path, _ = resolver.dwarf.path(place.root, place.offset, 4)
    if name == "scx_dispatch_q" and (not path or path[0] == "lock"):
        return "dsq"
    if name == "rq" and (not path or path[0] in ("__lock", "lock")):
        return "rq"
    if path and path[-1] == "pi_lock":
        return "pi_lock"
    return path[-1] if path else name


@dataclass
class Event:
    line: int
    column: int
    seq: int
    data: dict

    def key(self) -> tuple:
        return tuple(sorted(self.data.items()))


# -- source helpers -------------------------------------------------------------------
_IF = re.compile(r"\bif\s*\(")
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _balanced(text: str, start: int) -> int:
    """Index just after the parenthesis/brace group starting at text[start]."""
    pairs = {"(": ")", "{": "}"}
    closer, depth, i, quote = pairs[text[start]], 0, start, ""
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == text[start]:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def guard_at(source: Source, file: str, line: int) -> tuple[str, str] | None:
    """(cond, action) of an `if` at `line` whose branch leaves the normal path."""
    text = source.line(file, line)
    m = _IF.search(text)
    if not m:
        return None
    block = _strip_comments("\n".join(source.line(file, n) for n in range(line, line + 40)))
    m = _IF.search(block)
    start = block.index("(", m.start())
    end = _balanced(block, start)
    if end < 0:
        return None
    cond = " ".join(block[start + 1:end - 1].split())
    rest = block[end:].lstrip()
    close = -1
    if rest.startswith("{"):
        close = _balanced(rest, 0)
        body = rest[1:close - 1] if close > 0 else ""
    else:
        body = rest.split(";", 1)[0] + ";"
    has_else = re.match(r"else\b", rest[close:].lstrip() if rest.startswith("{") and close > 0
                        else rest.split(";", 1)[1].lstrip() if ";" in rest else "") is not None
    statements = _top_level_statements(body)
    if not statements:
        return None
    last = statements[-1]
    first_word = re.match(r"[A-Za-z_]\w*", last)
    leaves = first_word.group(0) if first_word else ""
    if leaves == "return":
        erroring = any(re.match(r"(?:scx_error|scx_exit|WARN\w*|BUG\w*)\s*\(", st) for st in statements)
        return cond, "error" if erroring else "return"
    if leaves in ("goto", "break", "continue"):
        return cond, "continue"
    if not has_else and len(statements) == 1 and re.match(r"^[\w\->.\[\]*]+\s*=[^=]", last):
        return cond, "fallback"
    return None


def _top_level_statements(body: str) -> list[str]:
    """Statements of a block, with nested blocks folded into the statement they belong to."""
    out, depth, current = [], 0, []
    for ch in body:
        if ch in "({":
            depth += 1
        elif ch in ")}":
            depth -= 1
            if ch == "}" and depth == 0:
                current.append(ch)
                out.append("".join(current).strip())
                current = []
                continue
        if ch == ";" and depth == 0:
            out.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if "".join(current).strip():
        out.append("".join(current).strip())
    return [st for st in out if st]


def call_expr(source: Source, file: str, line: int) -> str | None:
    """First argument of the lock/assert call on a source line (e.g. &dsq->lock)."""
    text = source.line(file, line)
    m = re.search(r"\bguard\s*\(\s*\w+\s*\)\s*\(", text) or re.search(r"\bscoped_guard\s*\(\s*\w+\s*,", text)
    if m:
        args = text[m.end():]
    else:
        m = re.search(r"\b\w*(?:lock|lockdep_assert)\w*\s*\(", text)
        if not m:
            return None
        args = text[m.end():]
    depth, out = 0, []
    for ch in args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        out.append(ch)
    expr = " ".join("".join(out).split())
    return expr or None


def error_msg(source: Source, file: str, line: int) -> str | None:
    block = " ".join(source.line(file, n) for n in range(line, line + 4))
    m = re.search(r"\bscx_(?:error|exit)\s*\(", block)
    if m:
        s = _STRING.search(block, m.end())
        if s:
            return s.group(1)
    return None


def warn_msg(source: Source, file: str, line: int) -> str | None:
    block = " ".join(source.line(file, n) for n in range(line, line + 4))
    m = re.search(r"\b(?:WARN_ON_ONCE|WARN_ON|WARN_ONCE|WARN|BUG_ON)\s*\(", block)
    if not m:
        return None
    end = _balanced(block, m.end() - 1)
    return " ".join(block[m.end():end - 1].split()) if end > 0 else None


class EventExtractor:
    """Turns the instructions of one function into events for their owner nodes."""

    def __init__(self, resolver: FieldResolver, source: Source):
        self.resolver = resolver
        self.source = source
        self.fn: Function | None = None
        self.uses: dict[str, list[Instruction]] = {}

    def start_function(self, fn: Function) -> None:
        self.fn = fn
        self.uses = {}
        for inst in fn.instructions:
            for name in re.findall(r"%[\w.$]+", inst.text.split(" = ", 1)[-1]):
                self.uses.setdefault(name, []).append(inst)

    def held_assert_kind(self, inst: Instruction) -> str:
        """lockdep_assert_held() warns when lock_is_held_type() == 0 (LOCK_STATE_NOT_HELD),
        lockdep_assert_not_held() when it is 1 (LOCK_STATE_HELD); eq/ne only reflects
        the branch layout."""
        for use in self.uses.get(inst.result or "", []):
            m = re.search(r"icmp (?:eq|ne) i32 %[\w.$]+, ([01])\b", use.text)
            if m:
                return "assert_not_held" if m.group(1) == "1" else "assert_held"
        return "assert_held"

    def call_events(self, inst: Instruction, target: str, frames: tuple[Frame, ...], k: int,
                    file: str, line: int) -> list[dict] | None:
        """Events for a call to a lock/assert/error primitive, or None for an ordinary call."""
        args = call_args(inst)
        pointer = args[0].split()[-1] if args else ""
        if target in LOCK_CALLS:
            kind, tokens, op = LOCK_CALLS[target]
            if tokens is None:
                token = lock_token(self.resolver, pointer) or "unknown"
                tokens = (token,)
            expr = call_expr(self.source, file, line)
            out = []
            for token in tokens:
                ev = {"kind": kind, "lock": token}
                if expr and len(tokens) == 1:
                    ev["expr"] = expr
                if op:
                    ev["op"] = op
                out.append(ev)
            return out
        if target == ASSERT_CALL:
            token = None
            if any(RQ_FRAME.search(f.sub.name) and PRIMITIVE_FRAME.fullmatch(f.sub.name) for f in frames[:k]):
                token = "rq"
            token = token or lock_token(self.resolver, pointer) or "unknown"
            ev = {"kind": self.held_assert_kind(inst), "lock": token}
            expr = call_expr(self.source, file, line)
            if expr:
                ev["expr"] = expr
            return [ev]
        if target in ERROR_CALLS:
            exit_kind = re.match(r"i32 (?:noundef )?(-?\d+)", args[1]) if len(args) > 1 else None
            if exit_kind and int(exit_kind.group(1)) < SCX_EXIT_ERROR:
                return []               # an exit that is not an error (e.g. unregistration)
            ev = {"kind": "error"}
            msg = error_msg(self.source, file, line)
            if msg:
                ev["msg"] = msg
            return [ev]
        return None

    def asm_events(self, inst: Instruction, file: str, line: int) -> list[dict]:
        body = inst.text
        if "@hardirqs_enabled" in body:
            text = self.source.line(file, line)
            if "lockdep_assert_irqs_disabled" in text:
                return [{"kind": "assert_held", "lock": "irqs_disabled", "expr": "lockdep_assert_irqs_disabled()"}]
            if "lockdep_assert_irqs_enabled" in text:
                return [{"kind": "assert_not_held", "lock": "irqs_disabled", "expr": "lockdep_assert_irqs_enabled()"}]
            return []
        if "ud2" in body and "__bug_table" in body:
            ev = {"kind": "warn"}
            msg = warn_msg(self.source, file, line)
            if msg:
                ev["msg"] = msg
            return [ev]
        return []

    def access_event(self, kind: str, field: str, volatile: bool, frames: tuple[Frame, ...], k: int,
                     pointer_expr: str | None = None) -> dict | None:
        """write / atomic event for a store or RMW on a tracked field (reads are not events,
        except atomic reads)."""
        collapsed = [f.sub.name for f in frames[:k]]
        atomic = next((n for n in reversed(collapsed) if ATOMIC_FRAME.fullmatch(n) and not n.startswith("__")), None)
        if atomic is not None or kind == "rmw":
            return {"kind": "atomic", "field": field, "op": atomic_op(atomic or "rmw")}
        if kind != "write":
            return None
        lst = next((n for n in reversed(collapsed) if LIST_FRAME.fullmatch(n)), None)
        bitop = next((n for n in reversed(collapsed) if n.startswith("__") and "_bit" in n), None)
        op = list_op(lst) if lst else ("set_bit" if bitop else ("write_once" if volatile else "set"))
        return {"kind": "write", "field": field, "op": op}

    @staticmethod
    def conditional_branch(inst: Instruction) -> bool:
        return inst.opcode in ("br", "switch") and (inst.opcode == "switch" or inst.text.startswith("br i1"))


def write_lines(source: Source, file: str, start: int, end: int | None, field: str) -> list[int]:
    """Source lines in [start, end] that write `field`'s last component: assignments
    (=, op=, ++/--) or list/rb/WRITE_ONCE/rcu_assign_pointer calls naming it. Used to
    place stores that the optimizer merged into a line-0 location."""
    leaf = re.escape(field.rsplit(".", 1)[-1])
    member = rf"(?:\.|->){leaf}\b"
    assign = re.compile(member + r"(?:\s*\[[^\]]*\])?\s*(?:[-+*/|&^]|<<|>>)?=(?!=)|" + member + r"\s*(?:\+\+|--)|(?:\+\+|--)\s*[\w>.-]*" + member)
    call = re.compile(r"\b(?:list_\w+|hlist_\w+|rb_\w+|RB_CLEAR_NODE|INIT_LIST_HEAD|WRITE_ONCE|rcu_assign_pointer)\s*\([^;]*" + member)
    lines = []
    for n in range(start, (end or start + 400) + 1):
        text = _strip_comments(source.line(file, n))
        if assign.search(text) or call.search(text):
            lines.append(n)
    return lines
