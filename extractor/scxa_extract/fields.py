"""B5: map memory accesses to struct.field names of the tracked scheduler structs.

A pointer is resolved to (root struct, byte offset) from the GEPs, byte-offset
GEPs, typed debug values and pointer-field loads that produce it. The field path
is then read from DWARF: descend into the members that contain the accessed
bytes, stopping at generic containers (list_head, rb_node, atomics, locks, ...),
so e.g. a store into p->scx.dsq_list.node.next is reported as
task_struct.scx.dsq_list.node.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .ir import Function, Instruction, Module, ref_id

# DWARF struct name -> canonical fieldref prefix (named by the outermost tracked struct)
TRACKED = {
    "task_struct": "task_struct",
    "sched_ext_entity": "task_struct.scx",
    "rq": "rq",
    "scx_rq": "rq.scx",
    "scx_dispatch_q": "scx_dispatch_q",
}

# Do not descend into these (typedef or struct names): the field is the container.
STOP_TYPES = {
    "list_head", "hlist_head", "hlist_node", "llist_node", "llist_head", "rb_node", "rb_root",
    "rb_root_cached", "cpumask", "cpumask_t", "cpumask_var_t", "atomic_t", "atomic64_t", "atomic_long_t",
    "raw_spinlock", "raw_spinlock_t", "spinlock", "spinlock_t", "refcount_struct", "refcount_t",
    "callback_head", "lockdep_map", "seqcount", "seqcount_t", "irq_work", "balance_callback",
    "kref", "wait_queue_head", "completion", "mutex", "rw_semaphore", "timer_list", "hrtimer",
}

_FIELD_OK = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_\[\]]*)+$")


# ------------------------------------------------------------------ IR layout
_INT = re.compile(r"^i(\d+)$")
_ARRAY = re.compile(r"^\[(\d+) x (.*)\]$")
_VECTOR = re.compile(r"^<(\d+) x (.*)>$")


class Layout:
    """x86-64 data layout of IR types (sizes, alignments, element offsets)."""

    def __init__(self, module: Module):
        self.types = module.types
        self._cache: dict[str, tuple[int, int, list[int]]] = {}

    def elements(self, struct: str) -> list[str]:
        body = self.types.get(struct, "").strip()
        if body.startswith("<{"):
            body = body[2:-2]
        elif body.startswith("{"):
            body = body[1:-1]
        else:
            return []
        from .ir import _split_top
        return [e.strip() for e in _split_top(body) if e.strip()]

    def packed(self, struct: str) -> bool:
        return self.types.get(struct, "").strip().startswith("<{")

    def size_align(self, ty: str) -> tuple[int, int]:
        ty = ty.strip()
        if ty == "ptr" or ty.startswith("ptr addrspace"):
            return 8, 8
        m = _INT.match(ty)
        if m:
            bits = int(m.group(1))
            size = max(1, (bits + 7) // 8)
            align = 1
            while align < size and align < 16:
                align *= 2
            return (size + align - 1) // align * align, align
        if ty in ("half", "bfloat"):
            return 2, 2
        if ty == "float":
            return 4, 4
        if ty == "double":
            return 8, 8
        if ty in ("x86_fp80", "fp128"):
            return 16, 16
        m = _ARRAY.match(ty)
        if m:
            size, align = self.size_align(m.group(2))
            return int(m.group(1)) * size, align
        m = _VECTOR.match(ty)
        if m:
            size = int(m.group(1)) * self.size_align(m.group(2))[0]
            align = 1
            while align < size and align < 16:
                align *= 2
            return (size + align - 1) // align * align, align
        if ty.startswith("%"):
            size, align, _ = self.struct_layout(ty)
            return size, align
        return 0, 1

    def struct_layout(self, struct: str) -> tuple[int, int, list[int]]:
        if struct in self._cache:
            return self._cache[struct]
        self._cache[struct] = (0, 1, [])          # recursion guard
        packed, offset, align, offsets = self.packed(struct), 0, 1, []
        for el in self.elements(struct):
            size, el_align = self.size_align(el)
            if packed:
                el_align = 1
            offset = (offset + el_align - 1) // el_align * el_align
            offsets.append(offset)
            offset += size
            align = max(align, el_align)
        size = (offset + align - 1) // align * align
        self._cache[struct] = (size, align, offsets)
        return self._cache[struct]

    def element_type(self, ty: str, index: int | None) -> str | None:
        ty = ty.strip()
        if ty.startswith("%"):
            els = self.elements(ty)
            return els[index] if index is not None and 0 <= index < len(els) else None
        m = _ARRAY.match(ty) or _VECTOR.match(ty)
        return m.group(2) if m else None


# ------------------------------------------------------------------ DWARF types
@dataclass(frozen=True)
class Member:
    name: str | None
    offset_bits: int       # from the start of the enclosing composite
    size_bits: int         # 0 for flexible arrays / unknown
    type_ref: int | None
    bitfield: bool

    @property
    def offset(self) -> int:
        return self.offset_bits // 8

    @property
    def end(self) -> int:
        """First byte after the member (bitfields: rounded out to whole bytes)."""
        return (self.offset_bits + self.size_bits + 7) // 8

    def contains(self, offset: int, size: int) -> bool:
        if self.size_bits == 0:
            return offset == self.offset and not self.bitfield
        return self.offset <= offset and offset + max(size, 1) <= self.end


class Dwarf:
    def __init__(self, module: Module):
        self.m = module
        self.by_name: dict[str, int] = {}
        for ref, text in module.metadata.items():
            if "DICompositeType(" in text and "elements:" in text and 'name: "' in text:
                node = module.node(ref)
                if node and node[0] == "DICompositeType":
                    self.by_name.setdefault(node[1].get("name", ""), ref)

    def strip(self, ref: int | None) -> tuple[int | None, set[str]]:
        """Follow typedef/const/volatile/member chains; returns (type ref, typedef names seen)."""
        names: set[str] = set()
        for _ in range(32):
            node = self.m.node(ref)
            if not node or node[0] != "DIDerivedType":
                return ref, names
            tag = node[1].get("tag", "")
            if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                       "DW_TAG_atomic_type", "DW_TAG_restrict_type"):
                if tag == "DW_TAG_typedef":
                    names.add(node[1].get("name", ""))
                ref = ref_id(node[1].get("baseType"))
            else:
                return ref, names
        return ref, names

    def size(self, ref: int | None) -> int:
        node = self.composite(self.strip(ref)[0])
        return int(node[1].get("size", "0") or 0) // 8 if node else 0

    def composite(self, ref: int | None) -> tuple[str, dict[str, str]] | None:
        node = self.m.node(ref)
        return node if node and node[0] == "DICompositeType" else None

    def members(self, ref: int) -> list[Member]:
        node = self.composite(ref)
        if not node:
            return []
        out = []
        for item in self.m.tuple_items(ref_id(node[1].get("elements"))):
            member = self.m.node(ref_id(item))
            if not member or member[0] != "DIDerivedType" or member[1].get("tag") != "DW_TAG_member":
                continue
            f = member[1]
            out.append(Member(f.get("name") or None, int(f.get("offset", "0") or 0),
                              int(f.get("size", "0") or 0), ref_id(f.get("baseType")),
                              "DIFlagBitField" in f.get("flags", "")))
        return out

    def embeddings(self, outer: int, depth: int = 0, base: int = 0) -> list[tuple[int, int]]:
        """(composite ref, byte offset) of every composite embedded (by value) in `outer`."""
        found: list[tuple[int, int]] = []
        if depth > 4:
            return found
        stripped, _ = self.strip(outer)
        for member in self.members(stripped) if self.composite(stripped) else []:
            child, _ = self.strip(member.type_ref)
            if self.composite(child) and not member.bitfield:
                found.append((child, base + member.offset))
                found.extend(self.embeddings(child, depth + 1, base + member.offset))
        return found

    def pointee(self, ref: int | None) -> int | None:
        """Composite a pointer type points to."""
        ref, _ = self.strip(ref)
        node = self.m.node(ref)
        if node and node[0] == "DIDerivedType" and node[1].get("tag") == "DW_TAG_pointer_type":
            target, _ = self.strip(ref_id(node[1].get("baseType")))
            return target if self.composite(target) else None
        return None

    def name_of(self, ref: int | None) -> str | None:
        node = self.composite(ref)
        return node[1].get("name") if node else None

    def path(self, root: int, offset: int, size: int) -> tuple[list[str], int | None]:
        """Member names leading to the bytes [offset, offset+size) of composite `root`,
        and the DWARF type at the end of the path."""
        names: list[str] = []
        current = root
        for _ in range(16):
            stripped, typedefs = self.strip(current)
            node = self.composite(stripped)
            if not node or (self.name_of(stripped) in STOP_TYPES) or (typedefs & STOP_TYPES):
                return names, current
            best = next((m for m in self.members(stripped) if m.contains(offset, size)), None)
            if best is None or best.bitfield:
                # bitfield storage, or an access spanning several members: stop here
                return names, current
            if best.name:
                names.append(best.name)
            offset -= best.offset
            current = best.type_ref
            stripped_child, child_typedefs = self.strip(current)
            if not self.composite(stripped_child):
                return names, current
            if best.name and (child_typedefs & STOP_TYPES or self.name_of(stripped_child) in STOP_TYPES):
                return names, current
            if offset == 0 and size and best.size_bits and size * 8 >= best.size_bits:
                return names, current    # the access covers the whole member
        return names, current


# ------------------------------------------------------------------ pointer resolution
@dataclass(frozen=True)
class Place:
    root: int          # DWARF composite ref the pointer points into
    offset: int        # byte offset from the start of root


_GEP = re.compile(r"getelementptr (?:inbounds |nuw |nusw |inrange\(\S+\) )*(.+?), ptr (%[\w.$]+|@[\w.$]+)((?:, [^,]+ [^,]+)*)")
_LOAD = re.compile(r"load (?:atomic )?(?:volatile )?(.+?), ptr (%[\w.$]+)")
_STORE = re.compile(r"store (?:atomic )?(volatile )?(.+?) (\S+), ptr (%[\w.$]+)")
_ASM_RMW = re.compile(r'asm (?:sideeffect )?"[^"]*\b(?:lock|bts[bwlq]?|btr[bwlq]?|btc[bwlq]?|xchg[bwlq]?|cmpxchg\w*|xadd[bwlq]?|inc[bwlq]|dec[bwlq]|or[bwlq]|and[bwlq])\b')
_ASM_MEM = re.compile(r"ptr elementtype\(([^)]*)\) (%[\w.$]+)")
_DBG_VALUE = re.compile(r"llvm\.dbg\.(?:value|declare)\(metadata ptr (%[\w.$]+), metadata !(\d+)")


def _strip_attachments(text: str) -> str:
    """Drop trailing metadata attachments (', !dbg !12, !tbaa !3') and alignment."""
    cut = text.find(", !")
    return text[:cut] if cut >= 0 else text


class FieldResolver:
    def __init__(self, module: Module):
        self.m = module
        self.layout = Layout(module)
        self.dwarf = Dwarf(module)
        self.tracked = {self.dwarf.by_name[n]: n for n in TRACKED if n in self.dwarf.by_name}
        self._fn: Function | None = None
        self._typed: dict[str, int] = {}
        self._memo: dict[str, Place | None] = {}
        self._embed_cache: dict[int, list[tuple[int, int]]] = {}

    def start_function(self, fn: Function) -> None:
        """Index the debug types of pointer values (arguments, locals) of one function."""
        self._fn, self._typed, self._memo = fn, {}, {}
        for inst in fn.instructions:
            if "llvm.dbg." not in inst.text:
                continue
            m = _DBG_VALUE.search(inst.text)
            if not m:
                continue
            var = self.m.node(int(m.group(2)))
            if var and var[0] == "DILocalVariable":
                target = self.dwarf.pointee(ref_id(var[1].get("type")))
                if target is not None:
                    self._typed.setdefault(m.group(1), target)

    def place(self, value: str, depth: int = 0) -> Place | None:
        if depth > 12 or self._fn is None or not value.startswith("%"):
            return None
        if value in self._memo:
            return self._memo[value]
        self._memo[value] = None
        result = self._place(value, depth)
        if result is None and value in self._typed:
            result = Place(self._typed[value], 0)
        self._memo[value] = result
        return result

    def _place(self, value: str, depth: int) -> Place | None:
        inst = self._fn.defs.get(value)
        if inst is None:
            return None
        body = _strip_attachments(inst.text.split(" = ", 1)[1])
        if "getelementptr" in body:
            m = _GEP.search(body)
            if not m:
                return None
            src, base = m.group(1).strip(), m.group(2)
            indices = [i.strip().split(" ", 1)[1] if " " in i.strip() else i.strip()
                       for i in m.group(3).split(",")[1:]]
            base_place = self.place(base, depth + 1)
            if src == "i8":
                if base_place is None or len(indices) != 1 or not re.fullmatch(r"-?\d+", indices[0]):
                    return None
                offset = base_place.offset + int(indices[0])
                if offset < 0 or offset >= self.dwarf.size(base_place.root):
                    return self.container_of(base_place.root, offset)
                return Place(base_place.root, offset)
            offset = self.ir_offset(src, indices)
            if offset is None:
                return None
            name = src[len("%struct."):] if src.startswith("%struct.") else None
            src_root = self.dwarf.by_name.get(name) if name else None
            if base_place is not None and (src_root is None or self.holds(base_place, src_root)):
                return Place(base_place.root, base_place.offset + offset)
            # The GEP reinterprets the pointer as `src` (e.g. clang folds
            # container_of(dsq, struct rq, scx.local_dsq)->scx.x into a GEP of
            # struct scx_rq on the dsq pointer): the GEP's own type wins.
            return Place(src_root, offset) if src_root is not None else None
        if body.startswith("load "):
            m = _LOAD.match(body)
            if not m or m.group(1).strip() != "ptr":
                return None
            loaded = self.place(m.group(2), depth + 1)
            if loaded is None:
                return None
            _, end_type = self.dwarf.path(loaded.root, loaded.offset, 8)
            target = self.dwarf.pointee(end_type)
            return Place(target, 0) if target is not None else None
        return None

    def holds(self, place: Place, struct: int) -> bool:
        """Whether a `struct` object starts at `place` (the root itself or an embedded one)."""
        if place.offset == 0 and place.root == struct:
            return True
        return (struct, place.offset) in self._embeddings(place.root)

    def container_of(self, inner: int, offset: int) -> Place | None:
        """container_of(): a negative offset from an embedded struct, e.g. the rq that
        embeds a local DSQ at rq.scx.local_dsq. Only tracked containers are tried, and
        only an unambiguous match is used."""
        matches = []
        for outer in self.tracked:
            for ref, at in self._embeddings(outer):
                if ref == inner and 0 <= at + offset < self.dwarf.size(outer):
                    matches.append(Place(outer, at + offset))
        return matches[0] if len(set(matches)) == 1 else None

    def _embeddings(self, outer: int) -> list[tuple[int, int]]:
        cached = self._embed_cache.get(outer)
        if cached is None:
            cached = self._embed_cache[outer] = self.dwarf.embeddings(outer)
        return cached

    def ir_offset(self, src: str, indices: list[str]) -> int | None:
        """Byte offset of a struct-typed GEP (first index scales the source type)."""
        if not indices or not re.fullmatch(r"-?\d+", indices[0]):
            return None
        size, _ = self.layout.size_align(src)
        offset, ty = int(indices[0]) * size, src
        for idx in indices[1:]:
            if ty.startswith("%"):
                if not re.fullmatch(r"\d+", idx):
                    return None
                k = int(idx)
                _, _, offsets = self.layout.struct_layout(ty)
                if k >= len(offsets):
                    return None
                offset += offsets[k]
                ty = self.layout.element_type(ty, k) or ""
            else:
                el = self.layout.element_type(ty, None)
                if el is None:
                    return None
                if re.fullmatch(r"-?\d+", idx):
                    offset += int(idx) * self.layout.size_align(el)[0]
                # a variable array index keeps the array's own offset: same field
                ty = el
        return offset

    def field(self, pointer: str, size: int) -> str | None:
        """fieldref of an access of `size` bytes through `pointer`, if it is in a tracked struct."""
        place = self.place(pointer)
        if place is None or place.root not in self.tracked:
            return None
        names, _ = self.dwarf.path(place.root, place.offset, size)
        if not names:
            return None
        ref = TRACKED[self.tracked[place.root]] + "." + ".".join(names)
        return ref if _FIELD_OK.match(ref) else None

    def access(self, inst: Instruction) -> tuple[str, str, bool] | None:
        """(read|write|rmw, fieldref, volatile) for a load/store or a memory-operand
        inline asm (x86 bit ops and lock-prefixed RMW) on a tracked field."""
        body = _strip_attachments(inst.text.split(" = ", 1)[1] if inst.result else inst.text)
        if body.startswith("load "):
            m = _LOAD.match(body)
            if m:
                ref = self.field(m.group(2), self.layout.size_align(m.group(1))[0])
                return ("read", ref, "volatile" in body.split(",", 1)[0]) if ref else None
        elif body.startswith("store "):
            m = _STORE.match(body)
            if m:
                ref = self.field(m.group(4), self.layout.size_align(m.group(2))[0])
                return ("write", ref, bool(m.group(1))) if ref else None
        elif " asm " in f" {body}" and _ASM_RMW.search(body):
            m = _ASM_MEM.search(body)
            if m:
                ref = self.field(m.group(2), self.layout.size_align(m.group(1))[0])
                return ("rmw", ref, True) if ref else None
        return None
