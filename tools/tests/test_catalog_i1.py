"""Regression checks on catalog/invariants/I1.yaml obligation scoping.

Run: python -m unittest discover -s tools/tests
"""
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
I1 = ROOT / "catalog/invariants/I1.yaml"
SNAPSHOT = "qseq_at_dispatch"


def obligations():
    data = yaml.safe_load(I1.read_text(encoding="utf-8"))
    for family in data["invariants"]:
        for rule in family.get("rules", []):
            for ob in rule.get("obligations", []):
                yield rule["id"], ob


def snapshot_predicates(ob):
    preds = (ob.get("requires") or {}).get("predicates", [])
    return [p for p in preds
            if SNAPSHOT in p["expr"] or any(c["var"] == SNAPSHOT for c in p.get("captures", []))]


def site_functions(ob):
    return {s["function"] for s in ob["sites"]}


class I1DispatchSnapshotScope(unittest.TestCase):
    def test_snapshot_predicate_bound_only_to_finish_dispatch(self):
        found = [(rid, ob) for rid, ob in obligations() if snapshot_predicates(ob)]
        self.assertTrue(found, "no obligation uses the qseq_at_dispatch snapshot")
        for rid, ob in found:
            with self.subTest(obligation=f"{rid}/{ob['id']}"):
                self.assertEqual(site_functions(ob), {"finish_dispatch"})
                for p in snapshot_predicates(ob):
                    self.assertEqual(p["checked_by"], ["finish_dispatch"])
                    self.assertEqual(p["evaluated_at"]["function"], "finish_dispatch")

    def test_ops_dequeue_obligation_has_no_snapshot_predicate(self):
        found = [(rid, ob) for rid, ob in obligations() if "ops_dequeue" in site_functions(ob)]
        self.assertTrue(found, "no obligation covers the ops_dequeue site")
        for rid, ob in found:
            with self.subTest(obligation=f"{rid}/{ob['id']}"):
                self.assertEqual(snapshot_predicates(ob), [])


if __name__ == "__main__":
    unittest.main()
