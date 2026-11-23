#!/usr/bin/env python3
"""Generate catalog/kfuncs.csv: the sched_ext kfunc inventory of the pinned kernel.

Scans every C file under <kernel>/kernel/sched/ for BTF kfunc sets
(BTF_KFUNCS_START(set) ... BTF_ID_FLAGS(func, name[, flags]) ... BTF_KFUNCS_END(set))
and for `__bpf_kfunc` function definitions, and writes one CSV row per
(kfunc, set) membership.

Usage:
    python3 catalog/scripts/inventory.py [--kernel-src PATH] [--output PATH]

The kernel source defaults to $KERNEL_SRC, then ~/linux. It should be checked
out at the tag in KERNEL_VERSION (the script warns if `git describe` disagrees).
Stdlib only.
"""

import argparse
import csv
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "catalog" / "kfuncs.csv"
SCAN_DIR = "kernel/sched"

COLUMNS = ["name", "kfunc_set", "flags", "config", "def_location", "set_entry_location"]

RE_START = re.compile(r"^\s*BTF_KFUNCS_START\((\w+)\)")
RE_END = re.compile(r"^\s*BTF_KFUNCS_END\((\w+)\)")
RE_ENTRY = re.compile(r"^\s*BTF_ID_FLAGS\(\s*func\s*,\s*(\w+)\s*(?:,\s*([^)]*?))?\s*\)")
RE_IF = re.compile(r"^\s*#\s*(ifdef|ifndef|if)\b\s*(.*)$")
RE_ELSE = re.compile(r"^\s*#\s*(else|elif)\b\s*(.*)$")
RE_ENDIF = re.compile(r"^\s*#\s*endif\b")
# `__bpf_kfunc <return type> name(` -- return type and name may span lines.
RE_DEF = re.compile(r"^__bpf_kfunc\b[^;{(]*?\b(\w+)\s*\(", re.MULTILINE)


def read_kernel_version():
    try:
        for line in (REPO_ROOT / "KERNEL_VERSION").read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    except OSError:
        pass
    return None


def git_describe(src):
    try:
        out = subprocess.run(
            ["git", "-C", str(src), "describe", "--tags", "--exact-match"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    return out.stdout.strip() or None


def normalize_flags(raw):
    if not raw:
        return ""
    flags = [f.strip() for f in raw.split("|") if f.strip()]
    return "|".join(flags)


RE_ATOM = re.compile(r"^!?(\w+|defined\s*\(\s*\w+\s*\))$")


def strip_comment(cond):
    return cond.split("/*")[0].split("//")[0].strip()


def is_atom(cond):
    """True for `X`, `!X`, `defined(X)`, `!defined(X)` and fully parenthesized `!(...)`."""
    if RE_ATOM.match(cond):
        return True
    return cond.startswith("!(") and cond.endswith(")") and balanced(cond[2:-1])


def balanced(s):
    depth = 0
    for ch in s:
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if depth < 0:
            return False
    return depth == 0


def negate(cond):
    if cond.startswith("!") and RE_ATOM.match(cond):
        return cond[1:]
    return f"!{cond}" if RE_ATOM.match(cond) else f"!({cond})"


def conjoin(terms):
    return " && ".join(t if is_atom(t) or len(terms) == 1 else f"({t})" for t in terms)


class CondTracker:
    """Tracks the preprocessor condition that is active at the current line.

    Each open #if level remembers the conditions of all its earlier branches
    and the condition of the current branch (None after #else). The active
    condition of a level is the negation of every earlier branch plus the
    current one, so `#if A / #elif B / #elif C` yields `!A && !B && C`.
    """

    def __init__(self):
        self.levels = []  # [(earlier branch conditions, current condition or None)]

    def feed(self, line):
        """Update the state for `line`; return True if it was a conditional directive."""
        m = RE_IF.match(line)
        if m:
            kind, cond = m.group(1), strip_comment(m.group(2))
            self.levels.append(([], negate(cond) if kind == "ifndef" else cond))
            return True
        m = RE_ELSE.match(line)
        if m:
            if self.levels:
                earlier, cur = self.levels.pop()
                if cur is not None:
                    earlier = earlier + [cur]
                new = strip_comment(m.group(2)) if m.group(1) == "elif" else None
                self.levels.append((earlier, new))
            return True
        if RE_ENDIF.match(line):
            if self.levels:
                self.levels.pop()
            return True
        return False

    def terms(self):
        out = []
        for earlier, cur in self.levels:
            out.extend(negate(c) for c in earlier)
            if cur is not None:
                out.append(cur)
        return out

    def condition(self):
        return conjoin(self.terms())


def scan_file(path, rel):
    """Return (entries, definitions) for one source file."""
    return scan_text(path.read_text(errors="replace"), rel)


def scan_text(text, rel):
    """Return (entries, definitions) for the contents of one source file."""
    lines = text.splitlines()

    entries = []
    cur_set = None
    conds = CondTracker()
    for lineno, line in enumerate(lines, 1):
        if conds.feed(line):
            continue
        m = RE_START.match(line)
        if m:
            cur_set = m.group(1)
            continue
        m = RE_END.match(line)
        if m:
            if m.group(1) != cur_set:
                sys.exit(f"{rel}:{lineno}: BTF_KFUNCS_END({m.group(1)}) does not match START({cur_set})")
            cur_set = None
            continue
        m = RE_ENTRY.match(line)
        if m and cur_set:
            entries.append({
                "name": m.group(1),
                "kfunc_set": cur_set,
                "flags": normalize_flags(m.group(2)),
                "config": conds.condition(),
                "set_entry_location": f"{rel}:{lineno}",
            })
    if cur_set:
        sys.exit(f"{rel}: unterminated BTF_KFUNCS_START({cur_set})")

    defs = {}
    for m in RE_DEF.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        defs.setdefault(m.group(1), f"{rel}:{lineno}")
    return entries, defs


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kernel-src", default=os.environ.get("KERNEL_SRC", "~/linux"),
                    help="kernel source tree (default: $KERNEL_SRC or ~/linux)")
    ap.add_argument("--output", default=str(DEFAULT_OUTPUT), help="CSV to write ('-' for stdout)")
    args = ap.parse_args()

    src = Path(args.kernel_src).expanduser().resolve()
    scan_root = src / SCAN_DIR
    if not scan_root.is_dir():
        sys.exit(f"error: {scan_root} not found; pass --kernel-src or set KERNEL_SRC")

    pinned, actual = read_kernel_version(), git_describe(src)
    if pinned and pinned != actual:
        where = f"is at {actual}" if actual else "is not at an exact tag (or not a git tree)"
        print(f"warning: KERNEL_VERSION is {pinned} but {src} {where}; "
              f"line numbers will not match {pinned}", file=sys.stderr)

    entries, defs = [], {}
    for path in sorted(scan_root.rglob("*.c")) + sorted(scan_root.rglob("*.h")):
        rel = path.relative_to(src).as_posix()
        e, d = scan_file(path, rel)
        entries.extend(e)
        for name, loc in d.items():
            defs.setdefault(name, loc)

    rows = []
    for e in entries:
        loc = defs.get(e["name"])
        if loc is None:
            print(f"warning: no __bpf_kfunc definition found for {e['name']}", file=sys.stderr)
        rows.append({**e, "def_location": loc or ""})
    rows.sort(key=lambda r: (r["name"], r["kfunc_set"]))

    out = sys.stdout if args.output == "-" else open(args.output, "w", newline="")
    try:
        w = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    finally:
        if out is not sys.stdout:
            out.close()

    per_set = {}
    for r in rows:
        per_set[r["kfunc_set"]] = per_set.get(r["kfunc_set"], 0) + 1
    unique = len({r["name"] for r in rows})
    print(f"{len(rows)} rows, {unique} unique kfuncs, {len(per_set)} sets"
          f" (kernel {actual or 'unknown'})", file=sys.stderr)
    for s in sorted(per_set):
        print(f"  {s}: {per_set[s]}", file=sys.stderr)
    unlisted = sorted(set(defs) - {r["name"] for r in rows})
    if unlisted:
        print(f"note: __bpf_kfunc defined but in no set: {', '.join(unlisted)}", file=sys.stderr)


if __name__ == "__main__":
    main()
