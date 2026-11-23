import unittest
from pathlib import Path

from harness import TESTS, classify, parse_header

VERIFIER_OUT = """libbpf: prog 't_enqueue': BPF program load failed: Permission denied
libbpf: prog 't_enqueue': -- BEGIN PROG LOAD LOG --
0: R1=ctx() R10=fp0
calling kernel function scx_bpf_dsq_move_to_local is not allowed
processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0
-- END PROG LOAD LOG --
loader: load failed: Permission denied
"""
SCX_ERR = """[    3.1] sched_ext: BPF scheduler "i3_insert_bogus_dsq" enabled
[    3.2] sched_ext: BPF scheduler "i3_insert_bogus_dsq" disabled (runtime error)
[    3.2] sched_ext: i3_insert_bogus_dsq: non-existent DSQ 0xcafef00d for sh[123]
"""
LOCKDEP = """[    4.0] ======================================================
[    4.0] WARNING: possible circular locking dependency detected
[    4.0] ------------[ cut here ]------------
"""
WARN = """[    5.0] ------------[ cut here ]------------
[    5.0] WARNING: CPU: 1 PID: 42 at kernel/sched/ext.c:1234 scx_foo+0x10/0x20
"""
UNREG = '[    6.0] sched_ext: BPF scheduler "t" disabled (unregistered from user space)\n'


class Classify(unittest.TestCase):
    def test_verifier_reject(self):
        self.assertEqual(classify(2, VERIFIER_OUT, ""),
                         ("verifier_reject", "calling kernel function scx_bpf_dsq_move_to_local is not allowed"))

    def test_runtime_error_with_message(self):
        self.assertEqual(classify(0, "", SCX_ERR),
                         ("runtime_error", "runtime error: non-existent DSQ 0xcafef00d for sh[123]"))

    def test_lockdep_beats_warn(self):
        self.assertEqual(classify(0, "", LOCKDEP)[0], "lockdep")

    def test_warn(self):
        self.assertEqual(classify(0, "", WARN)[0], "warn")

    def test_clean_unregister_is_ok(self):
        self.assertEqual(classify(0, "SCXA_ATTACHED\n", UNREG), ("ok", ""))

    def test_attach_failure_without_dmesg(self):
        self.assertEqual(classify(3, "loader: attach t_ops failed: Invalid argument\n", ""),
                         ("runtime_error", "loader exit 3: loader: attach t_ops failed: Invalid argument"))


class Headers(unittest.TestCase):
    def test_every_test_declares_invariant_and_outcome(self):
        for t in TESTS.glob("*/*.bpf.c"):
            invariant, expect = parse_header(t)
            self.assertTrue(invariant.startswith("I"), t)
            self.assertEqual(t.name.split("_")[0], invariant, t)
            self.assertEqual(expect == "ok", t.parent.name == "pass", t)

    def test_missing_header_rejected(self):
        tmp = Path(__file__).with_name("_no_header.bpf.c")
        tmp.write_text("int x;\n")
        try:
            self.assertRaises(ValueError, parse_header, tmp)
        finally:
            tmp.unlink()


if __name__ == "__main__":
    unittest.main()
