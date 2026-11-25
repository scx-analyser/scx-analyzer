"""Regression checks on catalog/invariants/I2.yaml (PR #55 review fixes).

Run: python -m unittest discover -s tools/tests
Set I2_YAML to check another copy of the catalog file.
"""
import os
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
I2 = Path(os.environ.get("I2_YAML", ROOT / "catalog/invariants/I2.yaml"))
HOLDING = "p->scx.holding_cpu == raw_smp_processor_id()"

# Edges accepted by the switch in scx_set_task_state() (ext.c:724-744).
TASK_STATE_EDGES = {
    ("SCX_TASK_NONE", "SCX_TASK_NONE"),
    ("SCX_TASK_INIT_BEGIN", "SCX_TASK_NONE"),
    ("SCX_TASK_INIT", "SCX_TASK_NONE"),
    ("SCX_TASK_READY", "SCX_TASK_NONE"),
    ("SCX_TASK_ENABLED", "SCX_TASK_NONE"),
    ("SCX_TASK_NONE", "SCX_TASK_INIT_BEGIN"),
    ("SCX_TASK_INIT_BEGIN", "SCX_TASK_INIT"),
    ("SCX_TASK_INIT", "SCX_TASK_READY"),
    ("SCX_TASK_ENABLED", "SCX_TASK_READY"),
    ("SCX_TASK_READY", "SCX_TASK_ENABLED"),
    ("SCX_TASK_NONE", "SCX_TASK_DEAD"),
    ("SCX_TASK_INIT_BEGIN", "SCX_TASK_DEAD"),
}


def rules():
    data = yaml.safe_load(I2.read_text(encoding="utf-8"))
    return {r["id"]: r for fam in data["invariants"] for r in fam.get("rules", [])}


def obligation(rule_id, ob_id):
    for ob in rules()[rule_id].get("obligations", []):
        if ob["id"] == ob_id:
            return ob
    raise AssertionError(f"{rule_id}/{ob_id} not found")


def site_functions(ob):
    return {s["function"] for s in ob["sites"]}


def exprs(ob):
    return [p["expr"] for p in (ob.get("requires") or {}).get("predicates", [])]


class I2RelinkPrecondition(unittest.TestCase):
    def test_link_once_covers_only_dispatch_enqueue(self):
        ob = obligation("I2.dsq_membership.single_dsq", "link_once")
        self.assertEqual(site_functions(ob), {"dispatch_enqueue"})

    def test_relink_local_has_no_null_dsq_precondition(self):
        ob = obligation("I2.dsq_membership.single_dsq", "relink_local")
        self.assertEqual(site_functions(ob), {"move_local_task_to_local_dsq"})
        for e in exprs(ob):
            self.assertNotIn("!p->scx.dsq", e)
        self.assertTrue(any("p->scx.dsq == src_dsq" in e for e in exprs(ob)))

    def test_no_other_obligation_requires_null_dsq_at_relink(self):
        for rid, rule in rules().items():
            for ob in rule.get("obligations", []):
                if "move_local_task_to_local_dsq" in site_functions(ob):
                    with self.subTest(obligation=f"{rid}/{ob['id']}"):
                        self.assertFalse(any("!p->scx.dsq" in e for e in exprs(ob)))


class I2ReadObligations(unittest.TestCase):
    def test_waiter_acquire_requires_no_value(self):
        ob = obligation("I2.ops_state.transitions", "waiter_acquire")
        self.assertEqual(exprs(ob), [])
        self.assertEqual(ob["access"].get("ordering"), "acquire")

    def test_revalidate_requires_only_the_lock(self):
        ob = obligation("I2.holding_cpu.handoff", "revalidate")
        self.assertEqual(exprs(ob), [])
        locks = ob["requires"]["locks"]
        self.assertEqual([(l["lock"], l["instance"]) for l in locks], [("rq", "src_rq")])

    def test_success_condition_on_dependent_writes(self):
        for ob_id in ("owned_continuation", "release_same_rq"):
            with self.subTest(obligation=ob_id):
                ob = obligation("I2.holding_cpu.handoff", ob_id)
                self.assertEqual(ob["access"]["op"], "write")
                self.assertTrue(any(HOLDING in e for e in exprs(ob)))


class I2TaskStateEdges(unittest.TestCase):
    def test_table_is_exactly_the_accepted_edges(self):
        table = rules()["I2.task_state.transitions"]["requires"].get("transitions")
        if table is None:
            self.skipTest("no lifecycle edge table in I2.yaml")
        edges = [(t["from"], t["to"]) for t in table]
        self.assertEqual(len(edges), len(set(edges)), "duplicate edges")
        self.assertEqual(set(edges), TASK_STATE_EDGES)
        self.assertIn(("SCX_TASK_NONE", "SCX_TASK_NONE"), edges)
        self.assertIn(("SCX_TASK_ENABLED", "SCX_TASK_NONE"), edges)


if __name__ == "__main__":
    unittest.main()
