"""B3: IR parsing, inline-frame attribution and the direct call graph."""
import json
import os
import tempfile
import unittest
from pathlib import Path

import jsonschema

from extractor.scxa_extract import extract
from extractor.scxa_extract.graph import Limits, Program
from extractor.scxa_extract.ir import btf_kfunc_sets, call_args, call_target, parse_di, parse_module

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "contracts/callgraph.schema.json").read_text(encoding="utf-8"))
BUILD = Path(os.environ.get("SCXA_IR_BUILD", REPO / "extractor/build"))

# kfunc_a (out of line, ext.c) inlines helper (kernel/sched/sched.h) at line 12, whose
# code calls leaf.constprop.0 (out of line, renamed by the optimizer) at line 5; it calls
# core_fn (out of line, core.c) at 15, ext_fn (declared only) at 13 and an indirect
# pointer at 14. Field accesses: p->scx.slice = (write, 16), p->pid (read, 16), and
# an inlined library helper (include/linux/x.h) that stores p->scx.dsq_vtime through a
# byte offset at line 17 (attributed to kfunc_a).
SAMPLE = r"""
module asm ".local __BTF_ID__set8__scx_kfunc_ids_any;"
module asm "__BTF_ID__func__kfunc_a__101:"
module asm "__BTF_ID__set8__other_set:"
module asm "__BTF_ID__func__not_scx__102:"

%struct.task_struct = type { i32, %struct.sched_ext_entity }
%struct.sched_ext_entity = type { i64, i64 }

define dso_local void @kfunc_a(ptr noundef %p) !dbg !10 {
entry:
  call void @llvm.dbg.value(metadata ptr %p, metadata !60, metadata !DIExpression()), !dbg !23
  call void @leaf.constprop.0(ptr %p), !dbg !22
  call void @ext_fn(), !dbg !23
  %fp = load ptr, ptr %p, align 8, !dbg !24
  call void %fp(ptr noundef %p), !dbg !24
  call void @core_fn(), !dbg !25
  %slice = getelementptr inbounds %struct.task_struct, ptr %p, i64 0, i32 1, i32 0, !dbg !26
  store i64 1, ptr %slice, align 8, !dbg !26
  %pid = load i32, ptr %p, align 4, !dbg !26
  %vt = getelementptr inbounds i8, ptr %p, i64 16, !dbg !27
  store volatile i64 2, ptr %vt, align 8, !dbg !27
  ret void, !dbg !23
}

define internal fastcc void @leaf.constprop.0(ptr %x) !dbg !30 {
entry:
  ret void, !dbg !31
}

define internal void @core_fn() !dbg !40 {
entry:
  call void @leaf.constprop.0(ptr null), !dbg !41
  ret void, !dbg !41
}

declare void @ext_fn()
declare void @llvm.dbg.value(metadata, metadata, metadata)

!1 = !DIFile(filename: "kernel/sched/build_policy.c", directory: "/k")
!2 = !DIFile(filename: "kernel/sched/ext.c", directory: "/k")
!3 = !DIFile(filename: "kernel/sched/sched.h", directory: "/k")
!4 = !DIFile(filename: "kernel/sched/core.c", directory: "/k")
!5 = !DIFile(filename: "include/linux/x.h", directory: "/k")
!10 = distinct !DISubprogram(name: "kfunc_a", scope: !2, file: !2, line: 10, spFlags: DISPFlagDefinition)
!11 = distinct !DISubprogram(name: "helper", scope: !3, file: !3, line: 3, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition)
!12 = distinct !DILexicalBlock(scope: !11, file: !3, line: 4, column: 2)
!13 = distinct !DISubprogram(name: "set_vtime", scope: !5, file: !5, line: 1, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition)
!21 = !DILocation(line: 12, column: 3, scope: !10)
!22 = !DILocation(line: 5, column: 7, scope: !12, inlinedAt: !21)
!23 = !DILocation(line: 13, column: 3, scope: !10)
!24 = !DILocation(line: 14, column: 3, scope: !10)
!25 = !DILocation(line: 15, column: 3, scope: !10)
!26 = !DILocation(line: 16, column: 3, scope: !10)
!27 = !DILocation(line: 2, column: 2, scope: !13, inlinedAt: !28)
!28 = !DILocation(line: 17, column: 3, scope: !10)
!30 = distinct !DISubprogram(name: "leaf", scope: !2, file: !2, line: 40, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition)
!31 = !DILocation(line: 41, column: 1, scope: !30)
!40 = distinct !DISubprogram(name: "core_fn", scope: !4, file: !4, line: 7, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition)
!41 = !DILocation(line: 8, column: 1, scope: !40)
!50 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "task_struct", file: !2, line: 1, size: 192, elements: !51)
!51 = !{!52, !53}
!52 = !DIDerivedType(tag: DW_TAG_member, name: "pid", scope: !50, file: !2, line: 2, baseType: !57, size: 32)
!53 = !DIDerivedType(tag: DW_TAG_member, name: "scx", scope: !50, file: !2, line: 3, baseType: !54, size: 128, offset: 64)
!54 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "sched_ext_entity", file: !2, line: 5, size: 128, elements: !55)
!55 = !{!56, !58}
!56 = !DIDerivedType(tag: DW_TAG_member, name: "slice", scope: !54, file: !2, line: 6, baseType: !59, size: 64)
!58 = !DIDerivedType(tag: DW_TAG_member, name: "dsq_vtime", scope: !54, file: !2, line: 7, baseType: !59, size: 64, offset: 64)
!57 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!59 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!60 = !DILocalVariable(name: "p", arg: 1, scope: !10, file: !2, line: 10, type: !61)
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !50, size: 64)
"""


EXPAND_ALL = Limits(expand=("*",))


def sample_program(tmp: Path) -> Program:
    path = tmp / "sample.ll"
    path.write_text(SAMPLE, encoding="utf-8")
    program = Program([parse_module(path)], Path("/k"))
    program.collect()
    return program


class ParserTests(unittest.TestCase):
    def setUp(self):
        path = Path(tempfile.mkdtemp()) / "s.ll"
        path.write_text(SAMPLE, encoding="utf-8")
        self.module = parse_module(path)

    def test_functions_declarations_and_types(self):
        self.assertEqual({"kfunc_a", "leaf.constprop.0", "core_fn"}, set(self.module.functions))
        self.assertEqual({"ext_fn", "llvm.dbg.value"}, self.module.declarations)
        self.assertIn("%struct.task_struct", self.module.types)
        self.assertEqual(10, self.module.functions["kfunc_a"].dbg)
        self.assertEqual(["%p"], self.module.functions["kfunc_a"].args)

    def test_metadata_node_parsing(self):
        kind, fields = parse_di('!DISubprogram(name: "a, b", file: !2, line: 7, spFlags: DISPFlagA | DISPFlagB)')
        self.assertEqual("DISubprogram", kind)
        self.assertEqual("a, b", fields["name"])
        self.assertEqual("!2", fields["file"])
        self.assertEqual("DISPFlagA | DISPFlagB", fields["spFlags"])

    def test_call_targets_and_arguments(self):
        insts = self.module.functions["kfunc_a"].instructions
        self.assertEqual(("direct", "leaf.constprop.0"), call_target(insts[1]))
        self.assertEqual(("indirect", "%fp"), call_target(insts[4]))
        self.assertEqual(["ptr noundef %p"], call_args(insts[4]))

    def test_btf_kfunc_sets_only_scx_sets(self):
        self.assertEqual({"scx_kfunc_ids_any": ["kfunc_a"]}, btf_kfunc_sets(self.module))


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.program = sample_program(Path(tempfile.mkdtemp()))
        self.graph = self.program.to_json(["kfunc_a"], {"kfunc_a"}, "v7.1", "0" * 40, EXPAND_ALL)

    def test_schema_valid(self):
        jsonschema.validate(self.graph, SCHEMA)

    def test_inlined_helper_is_a_node_called_at_the_inline_site(self):
        callees = self.graph["nodes"]["kfunc_a"]["callees"]
        self.assertIn({"target": "helper", "kind": "direct", "line": 12}, callees)
        helper = self.graph["nodes"]["helper"]
        self.assertEqual(("internal", "kernel/sched/sched.h", 3, 1), (helper["kind"], helper["file"], helper["line"], helper["depth"]))

    def test_call_inside_inlined_code_belongs_to_the_inlined_function(self):
        self.assertEqual([{"target": "leaf", "kind": "direct", "line": 5}], self.graph["nodes"]["helper"]["callees"])
        self.assertEqual(2, self.graph["nodes"]["leaf"]["depth"])

    def test_optimizer_renamed_function_maps_to_its_source_name(self):
        self.assertNotIn("leaf.constprop.0", self.graph["nodes"])
        self.assertEqual("kernel/sched/ext.c", self.graph["nodes"]["leaf"]["file"])

    def test_declared_only_function_is_external_and_indirect_call_is_kept(self):
        self.assertEqual("external", self.graph["nodes"]["ext_fn"]["kind"])
        self.assertIn({"target": "<indirect>", "kind": "indirect", "line": 14}, self.graph["nodes"]["kfunc_a"]["callees"])

    def test_intrinsics_are_not_nodes(self):
        self.assertFalse(any(name.startswith("llvm.") for name in self.graph["nodes"]))

    def test_unknown_root_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "roots not found"):
            self.program.to_json(["nope"], set(), "v7.1", None)


class FieldTests(unittest.TestCase):
    """B5: reads/writes of tracked struct fields."""

    def setUp(self):
        program = sample_program(Path(tempfile.mkdtemp()))
        self.nodes = program.to_json(["kfunc_a"], {"kfunc_a"}, "v7.1", None, EXPAND_ALL)["nodes"]

    def test_struct_gep_store_is_a_write_named_by_the_outer_struct(self):
        self.assertIn("task_struct.scx.slice", self.nodes["kfunc_a"]["writes"])

    def test_load_through_a_typed_argument_is_a_read(self):
        self.assertEqual(["task_struct.pid"], self.nodes["kfunc_a"]["reads"])

    def test_inlined_library_helper_is_attributed_to_its_caller(self):
        self.assertIn("task_struct.scx.dsq_vtime", self.nodes["kfunc_a"]["writes"])   # byte-offset GEP
        self.assertNotIn("set_vtime", self.nodes)

    def test_functions_without_tracked_accesses_have_no_sets(self):
        self.assertNotIn("writes", self.nodes["leaf"])
        self.assertNotIn("reads", self.nodes["leaf"])


class LimitTests(unittest.TestCase):
    """B4: depth limit, stop-list and boundary files."""

    def setUp(self):
        self.program = sample_program(Path(tempfile.mkdtemp()))

    def graph(self, limits):
        return self.program.to_json(["kfunc_a"], {"kfunc_a"}, "v7.1", None, limits)["nodes"]

    def test_function_outside_expanded_files_is_a_boundary(self):
        nodes = self.graph(Limits())
        core = nodes["core_fn"]
        self.assertEqual(("boundary", [], 1, "kernel/sched/core.c"), (core["kind"], core["callees"], core["depth"], core["file"]))
        self.assertEqual("internal", nodes["helper"]["kind"])     # sched.h is expanded by default

    def test_expand_glob_follows_into_the_file(self):
        nodes = self.graph(Limits(expand=("kernel/sched/ext.c", "kernel/sched/core.c")))
        self.assertEqual("internal", nodes["core_fn"]["kind"])
        self.assertEqual("boundary", nodes["helper"]["kind"])     # sched.h no longer listed

    def test_depth_limit_records_but_does_not_expand(self):
        nodes = self.graph(Limits(max_depth=1, expand=("*",)))
        self.assertEqual("boundary", nodes["helper"]["kind"])
        self.assertNotIn("leaf", nodes)                             # only reachable through helper
        nodes = self.graph(Limits(max_depth=0, expand=("*",)))
        self.assertEqual("kfunc", nodes["kfunc_a"]["kind"])   # roots are always expanded
        self.assertEqual("boundary", nodes["helper"]["kind"])

    def test_stop_list_drops_the_call_and_the_node(self):
        nodes = self.graph(Limits(stop=("ext_\\w+",), expand=("*",)))
        self.assertNotIn("ext_fn", nodes)
        self.assertNotIn("ext_fn", {c["target"] for c in nodes["kfunc_a"]["callees"]})

    def test_default_stop_list_covers_lockdep_tracing_printk(self):
        limits = Limits()
        for name in ("lock_acquire", "lockdep_rcu_suspicious", "__SCT__tp_func_sched_ext_event",
                     "__do_trace_sched_ext_dump", "_printk_deferred", "__ubsan_handle_x", "class_rcu_constructor"):
            self.assertTrue(limits.stopped(name), name)
        for name in ("_raw_spin_lock", "scx_kick_cpu", "irq_work_queue", "lock_is_held_type", "lockdep_assert_rq_held"):
            self.assertFalse(limits.stopped(name), name)

    def test_negative_depth_rejected(self):
        with self.assertRaises(ValueError):
            Limits(max_depth=-1)


@unittest.skipUnless((BUILD / "kernel/sched/build_policy.ll").exists(),
                     "real IR not built (run extractor/build_kernel_ir.sh)")
class RealIRTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = extract.run(extract.build_parser().parse_args(["--build-dir", str(BUILD)]))

    def test_schema_valid(self):
        jsonschema.validate(self.graph, SCHEMA)

    def test_all_kfuncs_are_roots(self):
        self.assertEqual(59, len(self.graph["roots"]))
        self.assertTrue(all(self.graph["nodes"][r]["kind"] == "kfunc" for r in self.graph["roots"]))

    def test_core_c_is_a_boundary_by_default(self):
        node = self.graph["nodes"]["raw_spin_rq_lock_nested"]
        self.assertEqual(("boundary", "kernel/sched/core.c", []), (node["kind"], node["file"], node["callees"]))
        self.assertFalse(any(name.startswith(("lock_acquire", "__SCT__")) for name in self.graph["nodes"]))

    def test_known_v7_1_edges(self):
        def callees(name):
            return {(c["target"], c.get("line")) for c in self.graph["nodes"][name]["callees"]}
        self.assertIn(("scx_bpf_dsq_insert___v2", 8224), callees("scx_bpf_dsq_insert"))
        self.assertIn(("mark_direct_dispatch", 8134), callees("scx_dsq_insert_commit"))   # inlined in the IR
        self.assertIn(("scx_kick_cpu", 8952), callees("scx_bpf_kick_cpu"))
        self.assertIn(("consume_dispatch_q", 8538), callees("scx_bpf_dsq_move_to_local___v2"))

    def test_known_v7_1_field_accesses(self):
        def has(name, kind, field):
            return field in self.graph["nodes"][name].get(kind, [])
        self.assertTrue(has("scx_bpf_dsq_insert___v2", "writes", "task_struct.scx.slice"))
        self.assertTrue(has("mark_direct_dispatch", "writes", "task_struct.scx.ddsp_dsq_id"))
        self.assertTrue(has("mark_direct_dispatch", "reads", "task_struct.pid"))           # not a bitfield neighbour
        self.assertTrue(has("move_local_task_to_local_dsq", "writes", "task_struct.scx.dsq_list.node"))
        self.assertTrue(has("dsq_dec_nr", "writes", "rq.scx.nr_immed"))                     # container_of
        self.assertTrue(has("scx_kick_cpu", "writes", "rq.scx.cpus_to_kick"))               # set_bit asm
        self.assertTrue(has("scx_bpf_cpuperf_set", "writes", "rq.scx.cpuperf_target"))
        node = self.graph["nodes"]["mark_direct_dispatch"]
        self.assertEqual(("kernel/sched/ext.c", 1766, 1795), (node["file"], node["line"], node["end_line"]))


if __name__ == "__main__":
    unittest.main()
