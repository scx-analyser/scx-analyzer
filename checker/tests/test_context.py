"""C2 contract tests; these do not execute or establish kernel safety."""
import json
import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from checker.checkers import registered
from checker.context import (
    SOURCE_COMMIT, SOURCE_VERSION, KfuncGroup, LockFact, LockState, Permission,
    ProgramType, SourceReference, SourceVersionMismatch, Verification,
    get_context, permission_table, serialize_table,
)

ROOT = Path(__file__).resolve().parents[2]


def context(callback, **kwargs):
    return get_context(callback, source_version=SOURCE_VERSION, **kwargs)


class PermissionTests(unittest.TestCase):
    def test_dispatch_permits_dispatch(self):
        self.assertEqual(Permission.ALLOWED, context("dispatch").permission(KfuncGroup.DISPATCH))

    def test_enqueue_rejects_dispatch_only(self):
        entry = context("enqueue")
        self.assertEqual(Permission.DENIED, entry.permission(KfuncGroup.DISPATCH))
        self.assertEqual(Permission.DENIED, entry.permission_for_groups([KfuncGroup.DISPATCH], complete=True))

    def test_enqueue_permits_enqueue(self):
        self.assertEqual(Permission.ALLOWED, context("enqueue").permission(KfuncGroup.ENQUEUE))

    def test_cpu_release_rejects_enqueue_only(self):
        self.assertEqual(Permission.DENIED, context("cpu_release").permission(KfuncGroup.ENQUEUE))

    def test_all_six_source_mappings(self):
        expected = {
            "select_cpu": {KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE},
            "enqueue": {KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE},
            "dispatch": {KfuncGroup.ENQUEUE, KfuncGroup.DISPATCH},
            "cpu_release": {KfuncGroup.CPU_RELEASE},
            "init_task": {KfuncGroup.UNLOCKED},
            "dump": {KfuncGroup.UNLOCKED},
        }
        for callback, groups in expected.items():
            with self.subTest(callback=callback):
                entry = context(callback)
                self.assertEqual(groups | {KfuncGroup.ANY, KfuncGroup.IDLE}, set(entry.allowed_groups))
                self.assertEqual(Verification.SOURCE_VERIFIED, entry.verification)
                self.assertTrue(all(item.evidence for item in entry.permissions))

    def test_ops_prefix_is_accepted(self):
        self.assertEqual(context("dispatch"), context("ops.dispatch"))

    def test_unmodeled_callbacks_remain_unknown(self):
        for callback in (None, "dequeue", "future_callback", "", "selectcpu"):
            with self.subTest(callback=callback):
                entry = context(callback)
                self.assertEqual((), entry.allowed_groups)
                self.assertEqual(Verification.UNVERIFIED, entry.verification)
                self.assertTrue(all(item.decision == Permission.UNKNOWN for item in entry.permissions))
                self.assertEqual(LockState.UNKNOWN, entry.lock("rq").state)

    def test_unknown_group_is_unknown(self):
        self.assertEqual(Permission.UNKNOWN, context("dispatch").permission("FUTURE_GROUP"))

    def test_permission_results_cannot_be_used_as_booleans(self):
        results = [*Permission, *context("enqueue").permissions, *context("future_callback").permissions]
        for result in results:
            with self.subTest(kind=type(result).__name__, value=str(getattr(result, "decision", result))):
                with self.assertRaisesRegex(TypeError, "explicit"):
                    bool(result)

    def test_unknown_membership_prevents_a_denial(self):
        self.assertEqual(Permission.UNKNOWN, context("enqueue").permission_for_groups(
            [KfuncGroup.DISPATCH, "FUTURE_GROUP"], complete=True,
        ))

    def test_overlapping_groups_use_or_semantics(self):
        # v7.1 select_cpu helpers also belong to UNLOCKED, but enqueue need
        # only permit their SELECT_CPU membership to pass this group filter.
        entry = context("enqueue")
        self.assertEqual(Permission.DENIED, entry.permission(KfuncGroup.UNLOCKED))
        self.assertEqual(Permission.ALLOWED, entry.permission_for_groups(
            [KfuncGroup.UNLOCKED, KfuncGroup.SELECT_CPU],
        ))
        self.assertEqual(Permission.ALLOWED, context("init_task").permission_for_groups(
            [KfuncGroup.UNLOCKED, KfuncGroup.SELECT_CPU],
        ))

    def test_incomplete_and_empty_memberships_are_unknown(self):
        entry = context("enqueue")
        self.assertEqual(Permission.UNKNOWN, entry.permission_for_groups([]))
        self.assertEqual(Permission.UNKNOWN, entry.permission_for_groups([], complete=True))
        self.assertEqual(Permission.UNKNOWN, entry.permission_for_groups([KfuncGroup.DISPATCH]))
        with self.assertRaises(TypeError):
            entry.permission_for_groups("DISPATCH")
        with self.assertRaises(TypeError):
            entry.permission_for_groups([KfuncGroup.DISPATCH], complete="yes")

    def test_syscall_permissions_follow_registrations(self):
        entry = context(None, program_type=ProgramType.SYSCALL)
        self.assertEqual({KfuncGroup.UNLOCKED, KfuncGroup.SELECT_CPU, KfuncGroup.ANY, KfuncGroup.IDLE},
                         set(entry.allowed_groups))
        self.assertEqual(Permission.DENIED, entry.permission(KfuncGroup.DISPATCH))
        self.assertEqual(LockState.UNKNOWN, entry.lock("rq").state)

    def test_tracing_excludes_select_cpu_despite_idle_access(self):
        entry = context(None, program_type=ProgramType.TRACING)
        self.assertEqual({KfuncGroup.ANY, KfuncGroup.IDLE}, set(entry.allowed_groups))
        self.assertEqual(Permission.DENIED, entry.permission(KfuncGroup.SELECT_CPU))
        self.assertEqual(Permission.DENIED, entry.permission(KfuncGroup.UNLOCKED))

    def test_unknown_program_type_does_not_inherit_any_or_idle(self):
        entry = context(None, program_type="BPF_PROG_TYPE_XDP")
        self.assertEqual("BPF_PROG_TYPE_XDP", entry.program_type)
        self.assertTrue(all(item.decision == Permission.UNKNOWN for item in entry.permissions))

    def test_non_scx_struct_ops_rejects_even_any_and_idle(self):
        entry = context("dispatch", scx_attachment=False)
        self.assertTrue(all(item.decision == Permission.DENIED for item in entry.permissions))
        self.assertEqual(LockState.UNKNOWN, entry.lock("rq").state)

    def test_unresolved_attachment_does_not_use_the_early_filter_bypass(self):
        entry = context("dispatch", scx_attachment=None)
        self.assertTrue(all(item.decision == Permission.UNKNOWN for item in entry.permissions))
        self.assertEqual(LockState.UNKNOWN, entry.lock("rq").state)

    def test_inconsistent_or_malformed_query_is_explicit(self):
        with self.assertRaisesRegex(ValueError, "only to STRUCT_OPS"):
            context("enqueue", program_type=ProgramType.SYSCALL)
        for callback, kwargs in ((42, {}), (None, {"program_type": None}),
                                 ("enqueue", {"scx_attachment": "yes"})):
            with self.subTest(callback=callback, kwargs=kwargs):
                with self.assertRaises(TypeError):
                    context(callback, **kwargs)

    def test_source_version_mismatch_is_explicit(self):
        for version in (None, "TBD", "TBD (see KERNEL_VERSION)", "v7.0", "7.1", "v7.1-custom"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(SourceVersionMismatch, "source version mismatch"):
                    get_context("dispatch", source_version=version)
                with self.assertRaises(SourceVersionMismatch):
                    permission_table(source_version=version)

    def test_source_version_must_be_supplied(self):
        with self.assertRaises(TypeError):
            get_context("dispatch")


class LockAndEvidenceTests(unittest.TestCase):
    def test_rq_entry_preconditions_have_wrapper_and_call_site_evidence(self):
        symbols = {"enqueue": "do_enqueue_task", "dispatch": "scx_dispatch_sched", "cpu_release": "switch_class"}
        for callback, symbol in symbols.items():
            with self.subTest(callback=callback):
                fact = context(callback).lock("rq")
                self.assertEqual(LockState.KNOWN_HELD, fact.state)
                self.assertTrue({"update_locked_rq", "SCX_CALL_OP", symbol} <= {ref.symbol for ref in fact.evidence})
                self.assertTrue(all(ref.file == "kernel/sched/ext.c" for ref in fact.evidence))

    def test_unlocked_permission_does_not_mean_no_locks(self):
        entry = context("dump")
        self.assertEqual(Permission.ALLOWED, entry.permission(KfuncGroup.UNLOCKED))
        fact = entry.lock("scx_dump_lock")
        self.assertEqual(LockState.KNOWN_HELD, fact.state)
        self.assertTrue(any(ref.line <= 6337 <= ref.end_line for ref in fact.evidence))
        self.assertEqual(LockState.UNKNOWN, entry.lock("rq").state)

    def test_unproven_locks_remain_unknown(self):
        for callback in ("select_cpu", "init_task", "dump"):
            self.assertEqual(LockState.UNKNOWN, context(callback).lock("rq").state)
        for entry in permission_table(source_version=SOURCE_VERSION):
            for lock in ("pi_lock", "task_rq", "dsq", "arbitrary_lock"):
                with self.subTest(callback=entry.callback, lock=lock):
                    self.assertEqual(LockState.UNKNOWN, entry.lock(lock).state)

    def test_lock_results_cannot_be_used_as_booleans(self):
        results = [*LockState, context("select_cpu").lock("rq"), context("enqueue").lock("rq")]
        for result in results:
            with self.subTest(kind=type(result).__name__, value=str(getattr(result, "state", result))):
                with self.assertRaisesRegex(TypeError, "explicit"):
                    bool(result)

    def test_every_known_lock_state_requires_evidence(self):
        for state in (LockState.KNOWN_HELD, LockState.KNOWN_NOT_HELD):
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, "require source evidence"):
                LockFact("unproven", state)
        for entry in permission_table(source_version=SOURCE_VERSION):
            for fact in entry.entry_locks:
                if fact.state != LockState.UNKNOWN:
                    self.assertTrue(fact.evidence)

    def test_source_references_are_pinned_and_well_formed(self):
        for entry in permission_table(source_version=SOURCE_VERSION):
            self.assertEqual(SOURCE_COMMIT, entry.source_commit)
            self.assertTrue(entry.provisional)
            for permission in entry.permissions:
                self.assertTrue(any(ref.symbol == "scx_kf_allow_flags" for ref in permission.evidence))
                for ref in permission.evidence:
                    self.assertGreater(ref.line, 0)
                    self.assertGreaterEqual(ref.end_line, ref.line)
                    self.assertIn(f"/blob/{SOURCE_COMMIT}/", ref.url)
        ref = SourceReference("kernel/sched/ext.c", "scx_kf_allow_flags", 9829, 9829)
        self.assertTrue(ref.url.endswith("#L9829-L9829"))

    def test_context_is_immutable_and_export_is_detached(self):
        entry = context("enqueue")
        with self.assertRaises(FrozenInstanceError):
            entry.callback = "dispatch"
        exported = entry.to_dict()
        exported["permissions"][0]["decision"] = "changed"
        self.assertEqual(Permission.ALLOWED, entry.permission(KfuncGroup.ANY))
        self.assertEqual(entry, context("enqueue"))

    def test_model_does_not_register_a_semantic_checker(self):
        before = registered()
        permission_table(source_version=SOURCE_VERSION)
        self.assertEqual(before, registered())
        self.assertEqual({}, registered())


class InspectionTests(unittest.TestCase):
    def run_demo(self, *args):
        return subprocess.run([sys.executable, "-m", "checker.context", *args],
                              cwd=ROOT, capture_output=True, text=True)

    def test_serialization_is_deterministic_and_explicitly_provisional(self):
        first = serialize_table(source_version=SOURCE_VERSION)
        self.assertEqual(first, serialize_table(source_version=SOURCE_VERSION))
        self.assertTrue(first.endswith("\n"))
        entries = json.loads(first)
        self.assertEqual(sorted(entry["callback"] for entry in entries), [entry["callback"] for entry in entries])
        self.assertTrue(all(entry["source_version"] == "v7.1" and entry["provisional"] for entry in entries))

    def test_serialization_is_independent_of_hash_seed(self):
        code = "from checker.context import serialize_table; print(serialize_table(source_version='v7.1'), end='')"
        outputs = []
        for seed in ("1", "42"):
            completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True,
                                       text=True, env=dict(os.environ, PYTHONHASHSEED=seed))
            self.assertEqual(0, completed.returncode, completed.stderr)
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_table_demo(self):
        completed = self.run_demo("--source-version", "v7.1")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("PROVISIONAL Linux v7.1", completed.stdout)
        self.assertIn("DISPATCH,ENQUEUE", completed.stdout)
        self.assertIn("scx_dump_lock=known_held", completed.stdout)
        self.assertIn("KERNEL_VERSION remains TBD", completed.stdout)
        self.assertEqual("", completed.stderr)

    def test_json_demo(self):
        completed = self.run_demo("--source-version", "v7.1", "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(json.loads(serialize_table(source_version=SOURCE_VERSION)), json.loads(completed.stdout))

    def test_demo_requires_a_matching_explicit_reference_version(self):
        for args in ((), ("--source-version", "TBD")):
            with self.subTest(args=args):
                completed = self.run_demo(*args)
                self.assertEqual(2, completed.returncode)
                self.assertEqual("", completed.stdout)
                self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
