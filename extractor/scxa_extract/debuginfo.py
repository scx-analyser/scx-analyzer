"""Debug-info queries over a parsed module: source locations, inline frames, subprograms."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .ir import Module, ref_id


@dataclass(frozen=True)
class Subprogram:
    id: int
    name: str
    file: str          # path relative to the kernel root when it lies inside it
    line: int
    definition: bool


@dataclass(frozen=True)
class Frame:
    """One level of an inline chain: code of `sub` at `line`:`column` of its own body."""
    sub: Subprogram
    line: int
    column: int


class DebugInfo:
    def __init__(self, module: Module, kernel_root: Path | None):
        self.m = module
        self.kernel_root = kernel_root.resolve() if kernel_root else None
        self._subs: dict[int, Subprogram] = {}
        self._frames: dict[int, tuple[Frame, ...]] = {}

    # -- files --------------------------------------------------------------
    def file_path(self, ref: int | None) -> str:
        node = self.m.node(ref)
        if not node or node[0] != "DIFile":
            return "?"
        filename, directory = node[1].get("filename", "?"), node[1].get("directory", "")
        full = Path(os.path.normpath(os.path.join(directory, filename)))
        if self.kernel_root:
            try:
                return full.relative_to(self.kernel_root).as_posix()
            except ValueError:
                pass
        return filename

    # -- subprograms ----------------------------------------------------------
    def subprogram(self, ref: int | None) -> Subprogram | None:
        if ref is None:
            return None
        if ref in self._subs:
            return self._subs[ref]
        node = self.m.node(ref)
        if not node or node[0] != "DISubprogram":
            return None
        f = node[1]
        sub = Subprogram(ref, f.get("name", "?"), self.file_path(ref_id(f.get("file"))),
                         int(f.get("line", "0") or 0), "DISPFlagDefinition" in f.get("spFlags", ""))
        self._subs[ref] = sub
        return sub

    def scope_subprogram(self, ref: int | None) -> Subprogram | None:
        """Walk DILexicalBlock*/DILexicalBlockFile scopes up to their DISubprogram."""
        seen = 0
        while ref is not None and seen < 256:
            node = self.m.node(ref)
            if not node:
                return None
            if node[0] == "DISubprogram":
                return self.subprogram(ref)
            ref = ref_id(node[1].get("scope"))
            seen += 1
        return None

    # -- locations --------------------------------------------------------------
    def frames(self, loc: int | None) -> tuple[Frame, ...]:
        """Inline chain of a DILocation, innermost first. The last frame is the
        function that physically contains the instruction."""
        if loc is None:
            return ()
        if loc in self._frames:
            return self._frames[loc]
        chain: list[Frame] = []
        cur, guard = loc, 0
        while cur is not None and guard < 64:
            node = self.m.node(cur)
            if not node or node[0] != "DILocation":
                break
            f = node[1]
            sub = self.scope_subprogram(ref_id(f.get("scope")))
            if sub is None:
                break
            chain.append(Frame(sub, int(f.get("line", "0") or 0), int(f.get("column", "0") or 0)))
            cur = ref_id(f.get("inlinedAt"))
            guard += 1
        result = tuple(chain)
        self._frames[loc] = result
        return result


@lru_cache(maxsize=None)
def _source_lines(path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(path).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


class Source:
    """Read-only access to the kernel source tree (optional)."""

    def __init__(self, root: Path | None):
        self.root = root

    def lines(self, rel: str) -> tuple[str, ...]:
        if self.root is None or rel.startswith("/") or rel == "?":
            return ()
        return _source_lines(str(self.root / rel))

    def line(self, rel: str, number: int) -> str:
        lines = self.lines(rel)
        return lines[number - 1] if 0 < number <= len(lines) else ""

    def end_line(self, rel: str, start: int) -> int | None:
        """Line of the closing brace of the function whose definition starts at `start`."""
        lines = self.lines(rel)
        depth, opened = 0, False
        for i in range(max(start - 1, 0), min(len(lines), start + 5000)):
            text = _strip_code(lines[i])
            for ch in text:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        return i + 1
            if not opened and text.rstrip().endswith(";"):
                return None     # a prototype, not a definition
        return None


def _strip_code(text: str) -> str:
    """Drop string/char literals and // comments (enough for brace counting)."""
    out, i, quote = [], 0, ""
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif text.startswith("//", i):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)
