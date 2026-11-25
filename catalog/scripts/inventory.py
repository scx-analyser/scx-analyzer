#!/usr/bin/env python3
"""Generate catalog/kfuncs.csv: the sched_ext kfunc inventory of the pinned kernel.

Scans every C file under <kernel>/kernel/sched/ for BTF kfunc sets
(BTF_KFUNCS_START(set) ... BTF_ID_FLAGS(func, name[, flags]) ... BTF_KFUNCS_END(set))
and for `__bpf_kfunc` function definitions, and writes one CSV row per
(kfunc, set) membership.

Usage:
    python3 catalog/scripts/inventory.py [--kernel-src PATH] [--output PATH]
                                         [--allow-kernel-mismatch]

The kernel source defaults to $KERNEL_SRC, then ~/linux. The pin is the tag in
KERNEL_VERSION plus its full commit SHA in KERNEL_COMMIT. The tree's HEAD must
be that commit and `git status` must succeed and show no local changes in
kernel/sched/; otherwise the script fails before writing anything. A pinned run
reads the .c/.h files of the pinned commit from Git objects, so untracked or
ignored files on disk cannot change the output. --allow-kernel-mismatch turns
the checks into warnings for exploratory runs against another tree; such runs
scan every .c/.h on disk.
Stdlib only.
"""

import argparse
import csv
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[2]
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


RE_SHA = re.compile(r"^[0-9a-f]{40}$")


def read_pin_file(path):
    """First non-empty, non-comment line of a pin file, or None if absent."""
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    except OSError:
        pass
    return None


def read_pin(repo_root):
    """Return (tag, commit) from KERNEL_VERSION and KERNEL_COMMIT; exit if invalid."""
    tag = read_pin_file(Path(repo_root) / "KERNEL_VERSION")
    commit = read_pin_file(Path(repo_root) / "KERNEL_COMMIT")
    if not tag:
        sys.exit(f"error: {repo_root}/KERNEL_VERSION is missing or empty")
    if not commit or not RE_SHA.match(commit):
        sys.exit(f"error: {repo_root}/KERNEL_COMMIT must hold the full 40-hex commit SHA "
                 f"of {tag} (got {commit!r})")
    return tag, commit


def git(src, *args):
    """Stripped stdout of a git command in `src`, or None if it fails."""
    try:
        out = subprocess.run(["git", "-C", str(src), *args],
                             capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def kernel_problems(src, tag, commit):
    """List why the tree at `src` is not the pinned kernel (empty if it is)."""
    head = git(src, "rev-parse", "--verify", "HEAD^{commit}")
    if head is None:
        return [f"{src} is not a git tree, so its commit cannot be verified"]
    problems = []
    tag_commit = git(src, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}")
    if tag_commit is not None and tag_commit != commit:
        problems.append(f"tag {tag} is {tag_commit} in {src}, but KERNEL_COMMIT pins {commit}")
    if head != commit:
        problems.append(f"{src} HEAD is {head}, expected {commit} ({tag})")
    # None means git status failed; only an empty string means a clean tree.
    dirty = git(src, "status", "--porcelain", "--untracked-files=no", "--", SCAN_DIR)
    if dirty is None:
        problems.append(f"git status failed in {src}, so {SCAN_DIR}/ cannot be "
                        f"checked for local changes")
    elif dirty:
        problems.append(f"{src}/{SCAN_DIR} has local changes")
    return problems


def git_bytes(src, *args):
    """Raw stdout of a git command in `src`; exit if it fails."""
    try:
        out = subprocess.run(["git", "-C", str(src), *args], capture_output=True, check=False)
    except OSError as e:
        sys.exit(f"error: cannot run git: {e}")
    if out.returncode != 0:
        sys.exit(f"error: git {' '.join(args)} failed in {src}: "
                 f"{out.stderr.decode(errors='replace').strip()}")
    return out.stdout


def decode_source(data):
    """Bytes -> text, as Path.read_text(encoding='utf-8', errors='replace') reads them."""
    text = data.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def pinned_sources(src, commit):
    """(rel, text) for each .c then .h under SCAN_DIR in `commit`'s tree.

    Contents come from Git objects, not the disk, so untracked, ignored or
    assume-unchanged files cannot alter a pinned inventory.
    """
    blobs = {}
    for rec in git_bytes(src, "ls-tree", "-r", "-z", commit, "--", f"{SCAN_DIR}/").split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, kind, oid = meta.split()
        rel = path.decode("utf-8", errors="surrogateescape")
        if kind == b"blob" and mode != b"120000" and rel.endswith((".c", ".h")):
            blobs[rel] = oid.decode()
    order = (sorted((r for r in blobs if r.endswith(".c")), key=PurePosixPath)
             + sorted((r for r in blobs if r.endswith(".h")), key=PurePosixPath))
    for rel in order:
        yield rel, decode_source(git_bytes(src, "cat-file", "blob", blobs[rel]))


def disk_sources(src, scan_root):
    """(rel, text) for each .c then .h on disk under `scan_root` (exploratory runs)."""
    for path in sorted(scan_root.rglob("*.c")) + sorted(scan_root.rglob("*.h")):
        yield path.relative_to(src).as_posix(), path.read_text(encoding="utf-8", errors="replace")


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


def main(argv=None, repo_root=REPO_ROOT):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kernel-src", default=os.environ.get("KERNEL_SRC", "~/linux"),
                    help="kernel source tree (default: $KERNEL_SRC or ~/linux)")
    ap.add_argument("--output", default=str(Path(repo_root) / "catalog" / "kfuncs.csv"),
                    help="CSV to write ('-' for stdout)")
    ap.add_argument("--allow-kernel-mismatch", action="store_true",
                    help="only warn if the tree is not the commit in KERNEL_COMMIT "
                         "(exploratory runs; the output then does not describe the pin)")
    args = ap.parse_args(argv)

    src = Path(args.kernel_src).expanduser().resolve()
    scan_root = src / SCAN_DIR
    if not scan_root.is_dir():
        sys.exit(f"error: {scan_root} not found; pass --kernel-src or set KERNEL_SRC")

    tag, commit = read_pin(repo_root)
    problems = kernel_problems(src, tag, commit)
    if problems:
        level = "warning" if args.allow_kernel_mismatch else "error"
        for p in problems:
            print(f"{level}: {p}", file=sys.stderr)
        if not args.allow_kernel_mismatch:
            sys.exit(f"error: kernel tree does not match the pin ({tag} = {commit}); check out "
                     f"{tag} or pass --allow-kernel-mismatch for an exploratory run")
    actual = f"{tag} ({commit[:12]})" if not problems else "unpinned"

    sources = disk_sources(src, scan_root) if problems else pinned_sources(src, commit)
    entries, defs = [], {}
    for rel, text in sources:
        e, d = scan_text(text, rel)
        entries.extend(e)
        for name, loc in d.items():
            defs.setdefault(name, loc)

    missing = [e for e in entries if e["name"] not in defs]
    if missing:
        for e in missing:
            print(f"error: {e['set_entry_location']}: {e['name']} in {e['kfunc_set']} "
                  f"has no __bpf_kfunc definition under {SCAN_DIR}/", file=sys.stderr)
        sys.exit(f"error: {len(missing)} kfunc set entries without a definition; "
                 f"nothing written")

    rows = [{**e, "def_location": defs[e["name"]]} for e in entries]
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
          f" (kernel {actual})", file=sys.stderr)
    for s in sorted(per_set):
        print(f"  {s}: {per_set[s]}", file=sys.stderr)
    unlisted = sorted(set(defs) - {r["name"] for r in rows})
    if unlisted:
        print(f"note: __bpf_kfunc defined but in no set: {', '.join(unlisted)}", file=sys.stderr)


if __name__ == "__main__":
    main()
