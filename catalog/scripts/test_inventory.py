#!/usr/bin/env python3
"""Tests for inventory.py. Stdlib only:

    python3 -m unittest discover -s catalog/scripts -p 'test_*.py'
"""

import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory  # noqa: E402


def configs(src):
    """Map kfunc name -> config string for a snippet of C source."""
    entries, _ = inventory.scan_text(textwrap.dedent(src), "kernel/sched/t.c")
    return {e["name"]: e["config"] for e in entries}


class PreprocessorTest(unittest.TestCase):
    def test_unconditional(self):
        self.assertEqual(configs("""
            BTF_KFUNCS_START(s)
            BTF_ID_FLAGS(func, f)
            BTF_KFUNCS_END(s)
        """), {"f": ""})

    def test_ifdef_ifndef_else(self):
        self.assertEqual(configs("""
            BTF_KFUNCS_START(s)
            #ifdef CONFIG_A
            BTF_ID_FLAGS(func, a)
            #else
            BTF_ID_FLAGS(func, not_a)
            #endif
            #ifndef CONFIG_B
            BTF_ID_FLAGS(func, not_b)
            #else /* CONFIG_B */
            BTF_ID_FLAGS(func, b)
            #endif
            BTF_ID_FLAGS(func, after)
            BTF_KFUNCS_END(s)
        """), {"a": "CONFIG_A", "not_a": "!CONFIG_A",
               "not_b": "!CONFIG_B", "b": "CONFIG_B", "after": ""})

    def test_chained_elif(self):
        self.assertEqual(configs("""
            BTF_KFUNCS_START(s)
            #if A
            BTF_ID_FLAGS(func, fa)
            #elif B
            BTF_ID_FLAGS(func, fb)
            #elif C
            BTF_ID_FLAGS(func, fc)
            #else
            BTF_ID_FLAGS(func, fd)
            #endif
            BTF_KFUNCS_END(s)
        """), {"fa": "A", "fb": "!A && B", "fc": "!A && !B && C",
               "fd": "!A && !B && !C"})

    def test_elif_after_ifndef_and_compound(self):
        self.assertEqual(configs("""
            BTF_KFUNCS_START(s)
            #ifndef A
            BTF_ID_FLAGS(func, f1)
            #elif defined(B) || C
            BTF_ID_FLAGS(func, f2)
            #else
            BTF_ID_FLAGS(func, f3)
            #endif
            BTF_KFUNCS_END(s)
        """), {"f1": "!A", "f2": "A && (defined(B) || C)",
               "f3": "A && !(defined(B) || C)"})

    def test_nested(self):
        self.assertEqual(configs("""
            BTF_KFUNCS_START(s)
            #ifdef OUTER
            #if X
            BTF_ID_FLAGS(func, ox)
            #elif Y
            #ifdef INNER
            BTF_ID_FLAGS(func, oyi)
            #endif
            BTF_ID_FLAGS(func, oy)
            #endif
            BTF_ID_FLAGS(func, o)
            #else
            #if Z
            BTF_ID_FLAGS(func, nz)
            #endif
            #endif
            BTF_ID_FLAGS(func, top)
            BTF_KFUNCS_END(s)
        """), {"ox": "OUTER && X", "oyi": "OUTER && !X && Y && INNER",
               "oy": "OUTER && !X && Y", "o": "OUTER", "nz": "!OUTER && Z",
               "top": ""})

    def test_entries_flags_and_definitions(self):
        entries, defs = inventory.scan_text(textwrap.dedent("""\
            __bpf_kfunc void
            scx_bpf_foo(u64 x)
            {
            }
            BTF_KFUNCS_START(set_a)
            BTF_ID_FLAGS(func, scx_bpf_foo, KF_RCU | KF_TRUSTED_ARGS)
            BTF_KFUNCS_END(set_a)
        """), "kernel/sched/t.c")
        self.assertEqual(defs, {"scx_bpf_foo": "kernel/sched/t.c:1"})
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["kfunc_set"], "set_a")
        self.assertEqual(entries[0]["flags"], "KF_RCU|KF_TRUSTED_ARGS")
        self.assertEqual(entries[0]["set_entry_location"], "kernel/sched/t.c:6")


if __name__ == "__main__":
    unittest.main()
