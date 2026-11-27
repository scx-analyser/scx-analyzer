"""B6: ordered events (locks, lockdep asserts, warn/error, guards, writes, atomics)."""
import json
import os
import tempfile
import unittest
from pathlib import Path

import jsonschema

from extractor.scxa_extract import extract
from extractor.scxa_extract.debuginfo import Source
from extractor.scxa_extract.events import atomic_op, guard_at, write_lines
from extractor.scxa_extract.graph import Limits, Program
from extractor.scxa_extract.ir import parse_module

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "contracts/callgraph.schema.json").read_text(encoding="utf-8"))
BUILD = Path(os.environ.get("SCXA_IR_BUILD", REPO / "extractor/build"))

EXT_C = {
    10: "void kfunc_b(struct scx_dispatch_q *dsq, struct task_struct *p)",
    11: "{",
    12: "\tif (!p)",
    13: "\t\treturn;",
    14: "\traw_spin_lock(&dsq->lock);",
    15: "\tlockdep_assert_held(&dsq->lock);",
    16: "\tWARN_ON_ONCE(p->pid);",
    17: "\tp->pid = 3;",
    18: '\tscx_error(sch, "bad thing %d", 1);',
    19: "\traw_spin_unlock(&dsq->lock);",
    20: "\tlockdep_assert_not_held(&dsq->lock);",
    21: "\tscx_exit(sch, SCX_EXIT_UNREG, 0, \"bye\");",
    22: "}",
}

IR = r"""
%struct.scx_dispatch_q = type { i32 }
%struct.task_struct = type { i32 }

define dso_local void @kfunc_b(ptr %dsq, ptr %p) !dbg !10 {
entry:
  call void @llvm.dbg.value(metadata ptr %dsq, metadata !60, metadata !DIExpression()), !dbg !12
  call void @llvm.dbg.value(metadata ptr %p, metadata !62, metadata !DIExpression()), !dbg !12
  %c = icmp eq ptr %p, null, !dbg !12
  br i1 %c, label %out, label %body, !dbg !12

body:
  call void @_raw_spin_lock(ptr %dsq), !dbg !14
  %h = call i32 @lock_is_held_type(ptr %dsq, i32 -1), !dbg !15
  %n = icmp eq i32 %h, 0, !dbg !15
  call void asm sideeffect "1:\09 ud2 \0A.pushsection __bug_table,\22aw\22", "i"(i32 15), !dbg !15
  call void asm sideeffect "1:\09 ud2 \0A.pushsection __bug_table,\22aw\22", "i"(i32 16), !dbg !16
  %pid = getelementptr inbounds %struct.task_struct, ptr %p, i64 0, i32 0, !dbg !17
  store i32 3, ptr %pid, align 4, !dbg !17
  call void (ptr, i32, i64, ptr, ...) @scx_exit(ptr null, i32 noundef 1024, i64 0, ptr null), !dbg !18
  call void @_raw_spin_unlock(ptr %dsq), !dbg !19
  %h2 = call i32 @lock_is_held_type(ptr %dsq, i32 -1), !dbg !20
  %n2 = icmp eq i32 %h2, 1, !dbg !20
  call void (ptr, i32, i64, ptr, ...) @scx_exit(ptr null, i32 noundef 64, i64 0, ptr null), !dbg !21
  br label %out

out:
  ret void, !dbg !22
}

declare void @_raw_spin_lock(ptr)
declare void @_raw_spin_unlock(ptr)
declare i32 @lock_is_held_type(ptr, i32)
declare void @scx_exit(ptr, i32, i64, ptr, ...)
declare void @llvm.dbg.value(metadata, metadata, metadata)

!1 = !DIFile(filename: "kernel/sched/build_policy.c", directory: "@ROOT@")
!2 = !DIFile(filename: "kernel/sched/ext.c", directory: "@ROOT@")
!10 = distinct !DISubprogram(name: "kfunc_b", scope: !2, file: !2, line: 10, spFlags: DISPFlagDefinition)
!12 = !DILocation(line: 12, column: 6, scope: !10)
!14 = !DILocation(line: 14, column: 2, scope: !10)
!15 = !DILocation(line: 15, column: 2, scope: !10)
!16 = !DILocation(line: 16, column: 2, scope: !10)
!17 = !DILocation(line: 17, column: 9, scope: !10)
!18 = !DILocation(line: 18, column: 2, scope: !10)
!19 = !DILocation(line: 19, column: 2, scope: !10)
!20 = !DILocation(line: 20, column: 2, scope: !10)
!21 = !DILocation(line: 21, column: 2, scope: !10)
!22 = !DILocation(line: 22, column: 1, scope: !10)
!50 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "scx_dispatch_q", file: !2, line: 1, size: 32, elements: !51)
!51 = !{!52}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "lock", scope: !50, file: !2, line: 2, baseType: !53, size: 32)
!53 = !DIDerivedType(tag: DW_TAG_typedef, name: "raw_spinlock_t", file: !2, line: 3, baseType: !57)
!54 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "task_struct", file: !2, line: 5, size: 32, elements: !55)
!55 = !{!56}
!56 = !DIDerivedType(tag: DW_TAG_member, name: "pid", scope: !54, file: !2, line: 6, baseType: !57, size: 32)
!57 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!60 = !DILocalVariable(name: "dsq", arg: 1, scope: !10, file: !2, line: 10, type: !61)
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
!62 = !DILocalVariable(name: "p", arg: 2, scope: !10, file: !2, line: 10, type: !63)
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
"""


def kernel_tree(files: dict[str, dict[int, str]]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, lines in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines.get(n, "") for n in range(1, max(lines) + 1)) + "\n", encoding="utf-8")
    return root


class EventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = kernel_tree({"kernel/sched/ext.c": EXT_C})
        path = root / "b.ll"
        path.write_text(IR.replace("@ROOT@", str(root)), encoding="utf-8")
        program = Program([parse_module(path)], root)
        program.collect()
        cls.graph = program.to_json(["kfunc_b"], {"kfunc_b"}, "v7.1", None, Limits(expand=("*",)))
        cls.node = cls.graph["nodes"]["kfunc_b"]

    def test_schema_valid(self):
        jsonschema.validate(self.graph, SCHEMA)

    def test_events_in_source_order(self):
        self.assertEqual([
            {"kind": "guard", "cond": "!p", "action": "return", "line": 12},
            {"kind": "lock", "lock": "dsq", "expr": "&dsq->lock", "line": 14},
            {"kind": "assert_held", "lock": "dsq", "expr": "&dsq->lock", "line": 15},
            {"kind": "warn", "msg": "p->pid", "line": 16},
            {"kind": "write", "field": "task_struct.pid", "op": "set", "line": 17},
            {"kind": "error", "msg": "bad thing %d", "line": 18},
            {"kind": "unlock", "lock": "dsq", "expr": "&dsq->lock", "line": 19},
            {"kind": "assert_not_held", "lock": "dsq", "expr": "&dsq->lock", "line": 20},
        ], self.node["events"])

    def test_lock_assert_and_exit_helpers_are_not_call_edges(self):
        self.assertEqual([], self.node["callees"])
        for name in ("_raw_spin_lock", "lock_is_held_type", "scx_exit"):
            self.assertNotIn(name, self.graph["nodes"])

    def test_writes_have_matching_events(self):
        self.assertEqual(["task_struct.pid"], self.node["writes"])


class GuardSourceTests(unittest.TestCase):
    def guard(self, *lines):
        root = kernel_tree({"f.c": {i + 1: text for i, text in enumerate(lines)}})
        return guard_at(Source(root), "f.c", 1)

    def test_return_and_error(self):
        self.assertEqual(("unlikely(!sch)", "return"), self.guard("if (unlikely(!sch))", "\treturn false;"))
        self.assertEqual(("x", "error"), self.guard("if (x) {", '\tscx_error(sch, "no");', "\treturn;", "}"))

    def test_goto_break_continue(self):
        self.assertEqual(("a", "continue"), self.guard("if (a) {", "\tunlock(r);", "\tgoto out;", "}"))
        self.assertEqual(("b", "continue"), self.guard("if (b) break;"))

    def test_fallback_only_without_else(self):
        self.assertEqual(("!dsq", "fallback"), self.guard("if (!dsq)", "\tdsq = find_global_dsq(sch);"))
        self.assertIsNone(self.guard("if (slice)", "\tp->scx.slice = slice;", "else", "\tp->scx.slice = 1;"))

    def test_block_that_only_contains_an_exit_in_a_nested_if_is_not_a_guard(self):
        self.assertIsNone(self.guard("if (t) {", "\tif (c) {", "\t\tgoto out;", "\t}", "\tunlock(t);", "}"))

    def test_comments_and_multiline_conditions(self):
        self.assertEqual(("a && b", "return"), self.guard("if (a && /* x ) */", "    b)", "\treturn; // done"))

    def test_not_an_if(self):
        self.assertIsNone(self.guard("while (x)", "\treturn;"))


class HelperTests(unittest.TestCase):
    def test_atomic_ops(self):
        for name, op in (("atomic_long_set_release", "set_release"), ("atomic_long_try_cmpxchg", "cmpxchg"),
                         ("atomic_long_read_acquire", "read_acquire"), ("atomic_long_read", "read"),
                         ("cpumask_set_cpu", "set_bit"), ("cpumask_test_and_clear_cpu", "test_and_clear_bit"),
                         ("atomic_long_set", "set"), ("atomic_inc", "inc")):
            self.assertEqual(op, atomic_op(name), name)

    def test_write_lines_for_merged_stores(self):
        root = kernel_tree({"f.c": {1: "void f(void) {", 2: "\tif (s)", 3: "\t\tp->scx.slice = s;",
                                    4: "\telse", 5: "\t\tp->scx.slice = p->scx.slice ?: 1;",
                                    6: "\tif (p->scx.slice == 0)", 7: "\t\tlist_add(&p->scx.dsq_list.node, h);",
                                    8: "}"}})
        src = Source(root)
        self.assertEqual([3, 5], write_lines(src, "f.c", 1, 8, "task_struct.scx.slice"))
        self.assertEqual([7], write_lines(src, "f.c", 1, 8, "task_struct.scx.dsq_list.node"))


@unittest.skipUnless((BUILD / "kernel/sched/build_policy.ll").exists(),
                     "real IR not built (run extractor/build_kernel_ir.sh)")
class RealIREventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = extract.run(extract.build_parser().parse_args(["--build-dir", str(BUILD)]))

    def events(self, name):
        return self.graph["nodes"][name]["events"]

    def test_every_callee_and_write_has_an_event(self):
        for name, node in self.graph["nodes"].items():
            if "events" not in node:
                continue
            calls = {(e["target"], e.get("line")) for e in node["events"] if e["kind"] == "call"}
            self.assertEqual(len(node["callees"]), sum(e["kind"] == "call" for e in node["events"]), name)
            for callee in node["callees"]:
                self.assertIn((callee["target"], callee.get("line")), calls, name)
            touched = {e.get("field") for e in node["events"] if e["kind"] in ("write", "atomic")}
            self.assertLessEqual(set(node.get("writes", [])), touched, name)

    def test_consume_dispatch_q_locks_the_dsq(self):
        events = self.events("consume_dispatch_q")
        self.assertIn({"kind": "lock", "lock": "dsq", "expr": "&dsq->lock", "line": 2525}, events)
        self.assertIn({"kind": "unlock", "lock": "dsq", "expr": "&dsq->lock", "line": 2555}, events)

    def test_lockdep_asserts_rq_and_dsq(self):
        events = self.events("move_local_task_to_local_dsq")
        self.assertIn({"kind": "assert_held", "lock": "dsq", "expr": "&src_dsq->lock", "line": 2256}, events)
        self.assertIn({"kind": "assert_held", "lock": "rq", "expr": "dst_rq", "line": 2257}, events)
        self.assertNotIn(2257, [e.get("line") for e in events if e["kind"] == "warn"])   # folded into the assert
        self.assertIn({"kind": "assert_held", "lock": "irqs_disabled", "expr": "lockdep_assert_irqs_disabled()",
                       "line": 8102}, self.events("scx_dsq_insert_preamble"))

    def test_guards_including_inlined_conditions(self):
        events = self.events("scx_kick_cpu")
        self.assertIn({"kind": "guard", "cond": "!ops_cpu_valid(sch, cpu, NULL)", "action": "return", "line": 8886}, events)
        self.assertIn({"kind": "guard", "cond": "unlikely(dspc->cursor >= sch->dsp_max_batch)", "action": "error",
                       "line": 8138}, self.events("scx_dsq_insert_commit"))

    def test_errors_writes_and_atomics(self):
        self.assertIn({"kind": "error", "msg": "dispatch buffer overflow", "line": 8139}, self.events("scx_dsq_insert_commit"))
        self.assertIn({"kind": "write", "field": "task_struct.scx.ddsp_dsq_id", "op": "set", "line": 1793},
                      self.events("mark_direct_dispatch"))
        self.assertIn({"kind": "atomic", "field": "rq.scx.cpus_to_kick", "op": "set_bit", "line": 8921}, self.events("scx_kick_cpu"))
        self.assertIn({"kind": "atomic", "field": "task_struct.scx.ops_state", "op": "read", "line": 8145},
                      self.events("scx_dsq_insert_commit"))
        slices = [e for e in self.events("scx_bpf_dsq_insert___v2") if e.get("field") == "task_struct.scx.slice"]
        self.assertEqual([8208, 8210], [e["line"] for e in slices])     # merged line-0 store placed from source


if __name__ == "__main__":
    unittest.main()
