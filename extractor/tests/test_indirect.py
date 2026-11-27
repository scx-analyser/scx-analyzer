"""B7: indirect calls are kept and named by the slot they load their target from."""
import os
import tempfile
import unittest
from pathlib import Path

from extractor.scxa_extract import extract
from extractor.scxa_extract.graph import Limits, Program
from extractor.scxa_extract.ir import parse_module

REPO = Path(__file__).resolve().parents[2]
BUILD = Path(os.environ.get("SCXA_IR_BUILD", REPO / "extractor/build"))

IR = r"""
%struct.scx_sched = type { i64, %struct.sched_ext_ops }
%struct.sched_ext_ops = type { ptr, ptr }

define dso_local void @caller(ptr %sch, ptr %opaque) !dbg !10 {
entry:
  call void @llvm.dbg.value(metadata ptr %sch, metadata !60, metadata !DIExpression()), !dbg !11
  %slot = getelementptr inbounds %struct.scx_sched, ptr %sch, i64 0, i32 1, i32 1, !dbg !11
  %fn = load ptr, ptr %slot, align 8, !dbg !11
  call void %fn(i32 1), !dbg !11
  call void %opaque(), !dbg !12
  ret void, !dbg !12
}

declare void @llvm.dbg.value(metadata, metadata, metadata)

!2 = !DIFile(filename: "kernel/sched/ext.c", directory: "/k")
!10 = distinct !DISubprogram(name: "caller", scope: !2, file: !2, line: 10, spFlags: DISPFlagDefinition)
!11 = !DILocation(line: 11, column: 2, scope: !10)
!12 = !DILocation(line: 12, column: 2, scope: !10)
!50 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "scx_sched", file: !2, line: 1, size: 192, elements: !51)
!51 = !{!52, !53}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "flags", scope: !50, file: !2, line: 2, baseType: !59, size: 64)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "ops", scope: !50, file: !2, line: 3, baseType: !54, size: 128, offset: 64)
!54 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "sched_ext_ops", file: !2, line: 5, size: 128, elements: !55)
!55 = !{!56, !57}
!56 = !DIDerivedType(tag: DW_TAG_member, name: "select_cpu", scope: !54, file: !2, line: 6, baseType: !58, size: 64)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "dispatch", scope: !54, file: !2, line: 7, baseType: !58, size: 64, offset: 64)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!59 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
!60 = !DILocalVariable(name: "sch", arg: 1, scope: !10, file: !2, line: 10, type: !61)
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
"""


class IndirectTests(unittest.TestCase):
    def setUp(self):
        path = Path(tempfile.mkdtemp()) / "i.ll"
        path.write_text(IR, encoding="utf-8")
        program = Program([parse_module(path)], Path("/k"))
        program.collect()
        self.node = program.to_json(["caller"], {"caller"}, "v7.1", None, Limits(expand=("*",)))["nodes"]["caller"]

    def test_scx_ops_slot_is_named_ops_op(self):
        self.assertIn({"target": "ops.dispatch", "kind": "indirect", "line": 11}, self.node["callees"])
        self.assertIn({"kind": "call", "target": "ops.dispatch", "line": 11}, self.node["events"])

    def test_unknown_pointer_stays_an_explicit_indirect_edge(self):
        self.assertIn({"target": "<indirect>", "kind": "indirect", "line": 12}, self.node["callees"])


@unittest.skipUnless((BUILD / "kernel/sched/build_policy.ll").exists(),
                     "real IR not built (run extractor/build_kernel_ir.sh)")
class RealIRIndirectTests(unittest.TestCase):
    def test_scx_call_op_sites(self):
        graph = extract.run(extract.build_parser().parse_args(["--build-dir", str(BUILD)]))
        sites = {(name, c["target"], c.get("line")) for name, node in graph["nodes"].items()
                 for c in node["callees"] if c["kind"] == "indirect"}
        self.assertLessEqual({("call_task_dequeue", "ops.dequeue", 1453), ("do_enqueue_task", "ops.enqueue", 1948),
                              ("scx_dispatch_sched", "ops.dispatch", 2840), ("scx_dispatch_sched", "ops.dispatch", 2844)},
                             sites)

    def test_sched_class_methods_with_core_expanded(self):
        graph = extract.run(extract.build_parser().parse_args(
            ["--build-dir", str(BUILD), "--expand", "kernel/sched/core.c"]))
        targets = {c["target"] for node in graph["nodes"].values() for c in node["callees"] if c["kind"] == "indirect"}
        self.assertIn("sched_class.enqueue_task", targets)


if __name__ == "__main__":
    unittest.main()
