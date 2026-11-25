#!/usr/bin/env python3
"""Tests for inventory.py. Stdlib only:

    python3 -m unittest discover -s catalog/scripts -p 'test_*.py'
"""

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
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


KERNEL_C = textwrap.dedent("""\
    __bpf_kfunc void scx_bpf_foo(void)
    {
    }
    BTF_KFUNCS_START(set_a)
    BTF_ID_FLAGS(func, scx_bpf_foo)
    BTF_KFUNCS_END(set_a)
""")


@unittest.skipUnless(shutil.which("git"), "git not installed")
class PinnedRunTest(unittest.TestCase):
    """Runs main() against a throwaway git "kernel" tree and pin files."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.kernel = self.tmp / "linux"
        (self.kernel / "kernel" / "sched").mkdir(parents=True)
        self.write_kernel(KERNEL_C)
        self.git("init", "-q")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "v0")
        self.git("tag", "v0.1")
        self.commit = self.git("rev-parse", "HEAD")
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.pin("v0.1", self.commit)
        self.out = self.tmp / "kfuncs.csv"

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
        return subprocess.run(["git", "-C", str(self.kernel), *args], env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def write_kernel(self, text):
        (self.kernel / "kernel" / "sched" / "ext.c").write_text(text)

    def pin(self, tag, commit):
        (self.repo / "KERNEL_VERSION").write_text(f"{tag}\n")
        (self.repo / "KERNEL_COMMIT").write_text(f"{commit}\n")

    def run_main(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                inventory.main(["--kernel-src", str(self.kernel), "--output", str(self.out),
                                *extra], repo_root=self.repo)
                code = 0
            except SystemExit as e:
                code = e.code
        return code, err.getvalue()

    def assertFails(self, *extra):
        code, err = self.run_main(*extra)
        self.assertNotIn(code, (0, None), err)
        self.assertFalse(self.out.exists(), "CSV written despite the failure")
        return code, err

    def test_matching_pin_writes_csv(self):
        code, err = self.run_main()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.out.read_text().splitlines()[1],
                         "scx_bpf_foo,set_a,,,kernel/sched/ext.c:1,kernel/sched/ext.c:5")

    def test_head_mismatch_fails(self):
        self.write_kernel(KERNEL_C + "\n")
        self.git("commit", "-q", "-am", "v1")
        _, err = self.assertFails()
        self.assertIn("HEAD is", err)

    def test_pin_disagrees_with_tag_fails(self):
        self.write_kernel(KERNEL_C + "\n")
        self.git("commit", "-q", "-am", "v1")
        self.pin("v0.1", self.git("rev-parse", "HEAD"))
        _, err = self.assertFails()
        self.assertIn("tag v0.1 is", err)

    def test_dirty_tree_fails(self):
        self.write_kernel(KERNEL_C + "/* local edit */\n")
        _, err = self.assertFails()
        self.assertIn("local changes", err)

    def test_invalid_commit_pin_fails(self):
        self.pin("v0.1", "v0.1")
        self.assertFails()

    def test_missing_definition_fails(self):
        self.write_kernel(KERNEL_C.replace(
            "BTF_ID_FLAGS(func, scx_bpf_foo)",
            "BTF_ID_FLAGS(func, scx_bpf_foo)\nBTF_ID_FLAGS(func, scx_bpf_ghost)"))
        self.git("commit", "-q", "-am", "ghost")
        self.pin("v0.1", self.git("rev-parse", "HEAD"))
        self.git("tag", "-f", "v0.1")
        _, err = self.assertFails()
        self.assertIn("kernel/sched/ext.c:6: scx_bpf_ghost in set_a has no __bpf_kfunc", err)
        self.assertNotIn("scx_bpf_foo", err)

    def write_extra(self, name):
        """An extra source file on disk that would add scx_bpf_extra if scanned."""
        (self.kernel / "kernel" / "sched" / name).write_text(textwrap.dedent("""\
            __bpf_kfunc void scx_bpf_extra(void)
            {
            }
            BTF_KFUNCS_START(set_x)
            BTF_ID_FLAGS(func, scx_bpf_extra)
            BTF_KFUNCS_END(set_x)
        """))

    def assertPinnedOutput(self):
        code, err = self.run_main()
        self.assertEqual(code, 0, err)
        csv = self.out.read_text()
        self.assertNotIn("scx_bpf_extra", csv)
        self.assertEqual(len(csv.splitlines()), 2, csv)
        self.assertIn("(kernel v0.1 (", err)

    def test_untracked_source_not_scanned(self):
        self.write_extra("untracked.c")
        self.write_extra("untracked.h")
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), "")
        self.assertPinnedOutput()

    def test_ignored_source_not_scanned(self):
        (self.kernel / ".git" / "info" / "exclude").write_text("ignored.*\n")
        self.write_extra("ignored.c")
        self.write_extra("ignored.h")
        self.git("check-ignore", "-q", "kernel/sched/ignored.c")
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        self.assertPinnedOutput()

    def test_assume_unchanged_edit_not_scanned(self):
        self.git("update-index", "--assume-unchanged", "kernel/sched/ext.c")
        self.write_extra("ext.c")
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertPinnedOutput()

    def test_untracked_source_scanned_with_override(self):
        self.write_extra("untracked.c")
        self.write_kernel(KERNEL_C + "/* edit */\n")
        code, err = self.run_main("--allow-kernel-mismatch")
        self.assertEqual(code, 0, err)
        self.assertIn("scx_bpf_extra", self.out.read_text())
        self.assertIn("kernel unpinned", err)

    def break_index(self):
        """Make git status fail (the index is unreadable) while HEAD still resolves."""
        self.write_kernel(KERNEL_C.replace("scx_bpf_foo", "scx_bpf_extra"))
        (self.kernel / ".git" / "index").write_bytes(b"not an index")
        with self.assertRaises(subprocess.CalledProcessError):
            self.git("status", "--porcelain")

    def test_failed_status_fails_and_keeps_output(self):
        self.out.write_text("previous output\n")
        self.break_index()
        code, err = self.run_main()
        self.assertNotIn(code, (0, None), err)
        self.assertIn("git status failed", err)
        self.assertEqual(self.out.read_text(), "previous output\n")

    def test_failed_status_only_warns_with_override(self):
        self.break_index()
        code, err = self.run_main("--allow-kernel-mismatch")
        self.assertEqual(code, 0, err)
        self.assertIn("warning: git status failed", err)
        self.assertIn("kernel unpinned", err)

    def test_override_only_warns(self):
        self.write_kernel(KERNEL_C + "\n")
        self.git("commit", "-q", "-am", "v1")
        code, err = self.run_main("--allow-kernel-mismatch")
        self.assertEqual(code, 0, err)
        self.assertIn("warning:", err)
        self.assertTrue(self.out.exists())


if __name__ == "__main__":
    unittest.main()
