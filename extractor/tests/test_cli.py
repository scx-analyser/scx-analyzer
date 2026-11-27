"""B8: scxa extract / scxa dot."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from extractor.scxa_extract.dot import subgraph, to_dot

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "contracts/fixtures/callgraph.example.json"
BUILD = Path(os.environ.get("SCXA_IR_BUILD", REPO / "extractor/build"))


def scxa(*args, cwd=None):
    return subprocess.run([sys.executable, str(REPO / "scxa"), *args], capture_output=True, text=True,
                          cwd=cwd or tempfile.gettempdir())


class DotTests(unittest.TestCase):
    def setUp(self):
        self.graph = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_subgraph_from_a_kfunc_with_depth(self):
        nodes = subgraph(self.graph, "scx_bpf_kick_cpu", 1)
        self.assertEqual({"scx_bpf_kick_cpu": 0, "scx_prog_sched": 1, "scx_kick_cpu": 1}, nodes)
        with self.assertRaisesRegex(ValueError, "not a node"):
            subgraph(self.graph, "nope", None)

    def test_dot_has_nodes_edges_and_styles(self):
        text = to_dot(self.graph, "scx_bpf_kick_cpu", 2)
        self.assertTrue(text.startswith("digraph scxa {") and text.rstrip().endswith("}"))
        self.assertIn('"scx_kick_cpu" -> "ops_cpu_valid" [label="8886"];', text)
        self.assertIn('style="filled,bold"', text)          # kfunc
        self.assertIn("4 atomic", text)                      # event summary of scx_kick_cpu
        self.assertNotIn('"scx_bpf_dsq_insert"', text)       # not reachable from the start node

    def test_cli_dot_and_check_routing(self):
        result = scxa("dot", "scx_bpf_dsq_insert", "--callgraph", str(FIXTURE), "--no-details")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('"scx_dsq_insert_commit" -> "mark_direct_dispatch" [label="8134"];', result.stdout)
        result = scxa("check", "--callgraph", str(FIXTURE))
        self.assertEqual(0, result.returncode, result.stderr)          # C1's runner still reachable

    def test_extract_without_ir_explains_how_to_build_it(self):
        result = scxa("extract", "--build-dir", tempfile.mkdtemp(), "--no-build")
        self.assertEqual(2, result.returncode)
        self.assertIn("build_kernel_ir.sh", result.stderr)


@unittest.skipUnless((BUILD / "kernel/sched/build_policy.ll").exists(),
                     "real IR not built (run extractor/build_kernel_ir.sh)")
class RealIRCliTests(unittest.TestCase):
    def test_extract_then_check(self):
        out = Path(tempfile.mkdtemp()) / "g.json"
        result = scxa("extract", "--build-dir", str(BUILD), "--roots", "scx_bpf_kick_cpu", "--depth", "2", "-o", str(out))
        self.assertEqual(0, result.returncode, result.stderr)
        graph = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(["scx_bpf_kick_cpu"], graph["roots"])
        self.assertLessEqual(max(n["depth"] for n in graph["nodes"].values()), 2)
        self.assertEqual(0, scxa("check", "--callgraph", str(out)).returncode)


if __name__ == "__main__":
    unittest.main()
