"""C2 contract tests; these do not execute or establish kernel safety."""
import json
import os
import re
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from checker.checkers import registered
from checker.context import (
    SOURCE_COMMIT, SOURCE_VERSION, KfuncGroup, LockFact, LockIdentity, LockMode, LockState, Permission,
    ProgramType, SourceReference, SourceVersionMismatch, Verification,
    audit_callback_coverage, callback_inventory, get_context, permission_table, serialize_table,
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
        for callback in (None, "future_callback", "", "selectcpu"):
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
        for callback in ("select_cpu", "dump"):
            self.assertEqual(LockState.UNKNOWN, context(callback).lock("rq").state)
        for entry in permission_table(source_version=SOURCE_VERSION):
            for lock in ("task_rq", "dsq", "arbitrary_lock"):
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


# Independent source extract, not a mock schema or a manually assumed callback count.
SOURCE_EXTRACT = json.loads((ROOT / "checker/tests/data/context-v7.1.json").read_text(encoding="utf-8"))
CONFIGS = ("CONFIG_EXT_GROUP_SCHED",)
UNLOCKED_CALLBACKS = {
    "init_task", "dump", "cgroup_init", "cgroup_exit", "cgroup_prep_move",
    "cgroup_cancel_move", "cgroup_set_weight", "cgroup_set_bandwidth", "cgroup_set_idle",
    "sub_attach", "sub_detach", "cpu_online", "cpu_offline", "init", "exit",
}
RQ_OBJECTS = {
    "enqueue": "task:p", "dequeue": "task:p", "runnable": "task:p", "running": "task:p",
    "stopping": "task:p", "quiescent": "task:p", "tick": "task:p", "set_weight": "task:p",
    "enable": "task:p", "disable": "task:p", "set_cpumask": "task:p", "exit_task": "task:p",
    "cgroup_move": "task:p", "yield": "task:from", "core_sched_before": "task:a",
    "dispatch": "cpu:cpu", "cpu_acquire": "cpu:cpu", "cpu_release": "cpu:cpu",
    "update_idle": "cpu:cpu", "dump_cpu": "cpu:cpu", "dump_task": "cpu:dumped",
}


def all_contexts():
    return permission_table(source_version=SOURCE_VERSION, enabled_configs=CONFIGS)


class CompleteCallbackCoverageTests(unittest.TestCase):
    def audit(self, header=None, table=None, **kwargs):
        return audit_callback_coverage(
            SOURCE_EXTRACT["header"] if header is None else header,
            SOURCE_EXTRACT["allow_table"] if table is None else table,
            source_version=kwargs.get("source_version", SOURCE_VERSION),
            source_commit=kwargs.get("source_commit", SOURCE_COMMIT),
        )

    def test_inventory_discovered_from_all_source_declarations(self):
        expected = tuple(sorted(re.findall(r"\(\*(\w+)\)", SOURCE_EXTRACT["header"])))
        self.assertEqual(expected, self.audit())
        self.assertEqual(expected, tuple(spec.name for spec in callback_inventory()))
        self.assertEqual(expected, tuple(entry.callback for entry in all_contexts()))
        self.assertEqual(SOURCE_VERSION, SOURCE_EXTRACT["source_version"])
        self.assertEqual(SOURCE_COMMIT, SOURCE_EXTRACT["source_commit"])

    def test_future_callback_cannot_silently_escape_model(self):
        header = SOURCE_EXTRACT["header"].replace("};", "void (*future_callback)(void);\n};")
        with self.assertRaisesRegex(ValueError, "unmodeled=.*future_callback"):
            self.audit(header=header)

    def test_removed_renamed_or_duplicate_callback_requires_review(self):
        for signature in ("", "void (*renamed)(void);", "void (*enqueue)(void);"):
            header = SOURCE_EXTRACT["header"].replace("void (*dequeue)(struct task_struct *p, u64 deq_flags);",
                                                      signature)
            with self.subTest(signature=signature), self.assertRaisesRegex(ValueError, "inventory mismatch"):
                self.audit(header=header)

    def test_callback_config_change_requires_review(self):
        header = SOURCE_EXTRACT["header"].replace("CONFIG_EXT_GROUP_SCHED", "CONFIG_FUTURE")
        with self.assertRaisesRegex(ValueError, "configuration mismatch"):
            self.audit(header=header)

    def test_allow_table_change_requires_review(self):
        table = SOURCE_EXTRACT["allow_table"].replace(
            "[SCX_OP_IDX(cpu_release)]\t= SCX_KF_ALLOW_CPU_RELEASE",
            "[SCX_OP_IDX(cpu_release)]\t= SCX_KF_ALLOW_ENQUEUE",
        )
        self.assertNotEqual(table, SOURCE_EXTRACT["allow_table"])
        with self.assertRaisesRegex(ValueError, "allow-table mismatch"):
            self.audit(table=table)

    def test_allow_table_configuration_changes_cannot_pass_with_identical_masks(self):
        original = SOURCE_EXTRACT["allow_table"]
        for table in (
            original.replace("CONFIG_EXT_GROUP_SCHED", "CONFIG_FUTURE"),
            original.replace("#ifdef CONFIG_EXT_GROUP_SCHED", ""),
            original.replace("#ifdef CONFIG_EXT_GROUP_SCHED", "#ifndef CONFIG_EXT_GROUP_SCHED"),
            original.replace("#ifdef CONFIG_EXT_GROUP_SCHED", "#ifdef CONFIG_EXT_GROUP_SCHED\n#else"),
        ):
            with self.subTest(table=table), self.assertRaisesRegex(ValueError, "configuration"):
                self.audit(table=table)

    def test_absent_or_unsupported_source_is_not_accepted(self):
        for header, table in (("", None), (None, ""), (None, SOURCE_EXTRACT["allow_table"].replace(
                "SCX_KF_ALLOW_CPU_RELEASE,", "SCX_KF_ALLOW_CPU_RELEASE | 1,"))):
            with self.subTest(header=header, table=table), self.assertRaises(ValueError):
                self.audit(header=header, table=table)

    def test_comments_do_not_add_fake_callback_declarations(self):
        header = SOURCE_EXTRACT["header"].replace(
            "struct sched_ext_ops {", "struct sched_ext_ops { /* void (*fake)(void); */",
        )
        self.assertEqual(self.audit(), self.audit(header=header))

    def test_all_callbacks_have_exact_declaration_and_all_call_site_references(self):
        for spec in callback_inventory():
            with self.subTest(callback=spec.name):
                self.assertEqual("kernel/sched/ext_internal.h", spec.declaration.file)
                self.assertEqual("sched_ext_ops." + spec.name, spec.declaration.symbol)
                self.assertTrue(spec.call_sites)
                for ref in (spec.declaration, *spec.call_sites):
                    self.assertEqual(SOURCE_VERSION, ref.source_version)
                    self.assertEqual(SOURCE_COMMIT, ref.source_commit)
                    self.assertGreater(ref.line, 0)
                    self.assertGreaterEqual(ref.end_line, ref.line)
        # Multiple invocations must not lose a distinct entry path.
        by_name = {s.name: s for s in callback_inventory()}
        for name in ("exit_task", "set_cpumask", "set_weight", "yield", "stopping", "init", "exit"):
            self.assertEqual(2, len(by_name[name].call_sites), name)

    def test_every_callback_permission_and_denial(self):
        explicit = {
            "select_cpu": {KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE},
            "enqueue": {KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE},
            "dispatch": {KfuncGroup.ENQUEUE, KfuncGroup.DISPATCH},
            "cpu_release": {KfuncGroup.CPU_RELEASE},
        }
        for entry in all_contexts():
            expected = explicit.get(entry.callback, {KfuncGroup.UNLOCKED}
                                    if entry.callback in UNLOCKED_CALLBACKS else set())
            expected = expected | {KfuncGroup.ANY, KfuncGroup.IDLE}
            with self.subTest(callback=entry.callback):
                self.assertEqual(Verification.SOURCE_VERIFIED, entry.verification)
                self.assertEqual(expected, set(entry.allowed_groups))
                for group in KfuncGroup:
                    decision = Permission.ALLOWED if group in expected else Permission.DENIED
                    self.assertEqual(decision, entry.permission(group), (entry.callback, group))

    def test_absent_allow_row_is_not_an_unrecognized_callback(self):
        for name in ("dequeue", "tick", "dump_cpu", "dump_task", "cgroup_move"):
            entry = context(name, enabled_configs=CONFIGS)
            with self.subTest(callback=name):
                self.assertEqual({KfuncGroup.ANY, KfuncGroup.IDLE}, set(entry.allowed_groups))
                self.assertEqual(Permission.DENIED, entry.permission(KfuncGroup.UNLOCKED))
                self.assertEqual(Permission.DENIED, entry.permission(KfuncGroup.DISPATCH))
        self.assertEqual(Permission.UNKNOWN, context("not_an_op").permission(KfuncGroup.ANY))

    def test_config_conditional_callbacks_require_explicit_enabled_config(self):
        for spec in callback_inventory():
            if not spec.required_configs:
                continue
            for configs in (None, (), ("CONFIG_EXT_SUB_SCHED",)):
                entry = context(spec.name, enabled_configs=configs)
                with self.subTest(callback=spec.name, configs=configs):
                    self.assertEqual(("CONFIG_EXT_GROUP_SCHED",), entry.required_configs)
                    self.assertTrue(all(p.decision == Permission.UNKNOWN for p in entry.permissions))
                    self.assertTrue(all(f.state == LockState.UNKNOWN for f in entry.entry_locks))
            entry = context(spec.name, enabled_configs=CONFIGS)
            self.assertEqual(Verification.SOURCE_VERIFIED, entry.verification)

    def test_unknown_attachments_and_non_scx_never_gain_expanded_callback_rights(self):
        for entry in all_contexts():
            for attachment, decision in ((None, Permission.UNKNOWN), (False, Permission.DENIED)):
                result = context(entry.callback, scx_attachment=attachment, enabled_configs=CONFIGS)
                with self.subTest(callback=entry.callback, attachment=attachment):
                    self.assertTrue(all(p.decision == decision for p in result.permissions))
                    self.assertTrue(all(f.state == LockState.UNKNOWN for f in result.entry_locks))

    def test_no_other_program_type_inherits_any_idle_or_entry_locks(self):
        for program in ("BPF_PROG_TYPE_LSM", "BPF_PROG_TYPE_KPROBE", "BPF_PROG_TYPE_EXT"):
            entry = context(None, program_type=program, enabled_configs=CONFIGS)
            self.assertTrue(all(p.decision == Permission.UNKNOWN for p in entry.permissions))
            self.assertTrue(all(f.state == LockState.UNKNOWN for f in entry.entry_locks))

    def test_all_registration_set_names_match_inspected_btf_sets(self):
        sets = SOURCE_EXTRACT["kfunc_sets"]
        self.assertEqual(set(sets), {p.registration_set for p in context("dispatch").permissions})
        for set_name, source in sets.items():
            self.assertIn("BTF_KFUNCS_START(" + set_name + ")", source["source"])
            self.assertIn("BTF_KFUNCS_END(" + set_name + ")", source["source"])

    def test_every_real_overlapping_membership_obeys_callback_and_program_gates(self):
        by_set = {p.registration_set: p.group for p in context("dispatch").permissions}
        memberships = {}
        for set_name, source in SOURCE_EXTRACT["kfunc_sets"].items():
            for name in re.findall(r"BTF_ID_FLAGS\(func,\s*(\w+)\s*[,)]", source["source"]):
                memberships.setdefault(name, set()).add(by_set[set_name])
        overlaps = {name: groups for name, groups in memberships.items() if len(groups) > 1}
        expected_names = {
            "__scx_bpf_select_cpu_and", "scx_bpf_select_cpu_and", "scx_bpf_select_cpu_dfl",
            "scx_bpf_dsq_move", "scx_bpf_dsq_move_vtime", "scx_bpf_dsq_move_set_slice",
            "scx_bpf_dsq_move_set_vtime",
        }
        self.assertEqual(expected_names, set(overlaps))
        for name, groups in overlaps.items():
            selects = KfuncGroup.SELECT_CPU in groups
            self.assertEqual({KfuncGroup.UNLOCKED, KfuncGroup.SELECT_CPU if selects else KfuncGroup.DISPATCH},
                             groups)
            for callback, expected in (("enqueue", Permission.ALLOWED if selects else Permission.DENIED),
                                       ("dispatch", Permission.DENIED if selects else Permission.ALLOWED),
                                       ("init_task", Permission.ALLOWED), ("dequeue", Permission.DENIED)):
                with self.subTest(kfunc=name, callback=callback):
                    self.assertEqual(expected, context(callback).permission_for_groups(groups, complete=True))
            for program, expected in ((ProgramType.SYSCALL, Permission.ALLOWED),
                                      (ProgramType.TRACING, Permission.DENIED),
                                      ("BPF_PROG_TYPE_XDP", Permission.UNKNOWN)):
                with self.subTest(kfunc=name, program=program):
                    self.assertEqual(expected, context(None, program_type=program).permission_for_groups(
                        groups, complete=True))

    def test_all_source_memberships_include_kfuncs_without_explicit_btf_flags(self):
        by_set = {p.registration_set: p.group for p in context("dispatch").permissions}
        memberships = {}
        for set_name, source in SOURCE_EXTRACT["kfunc_sets"].items():
            for name in re.findall(r"BTF_ID_FLAGS\(func,\s*(\w+)\s*[,)]", source["source"]):
                memberships.setdefault(name, set()).add(by_set[set_name])
        self.assertEqual(59, len(memberships))
        self.assertEqual(66, sum(len(groups) for groups in memberships.values()))
        for name in ("scx_bpf_nr_node_ids", "scx_bpf_nr_cpu_ids", "scx_bpf_now", "scx_bpf_events"):
            self.assertEqual({KfuncGroup.ANY}, memberships[name])
        flags = {name: set(re.findall(r"SCX_KF_ALLOW_(\w+)", mask)) for name, mask in
                 re.findall(r"\[SCX_OP_IDX\((\w+)\)\]\s*=\s*([^,]+),", SOURCE_EXTRACT["allow_table"])}
        entries = [(entry, flags.get(entry.callback, set()) | {"ANY", "IDLE"}) for entry in all_contexts()]
        entries.extend((context(None, program_type=program), allowed) for program, allowed in (
            (ProgramType.SYSCALL, {"ANY", "IDLE", "UNLOCKED", "SELECT_CPU"}),
            (ProgramType.TRACING, {"ANY", "IDLE"}),
        ))
        for entry, allowed in entries:
            for name, groups in memberships.items():
                expected = Permission.ALLOWED if groups & allowed else Permission.DENIED
                with self.subTest(callback=entry.callback, program=entry.program_type, kfunc=name):
                    self.assertEqual(expected, entry.permission_for_groups(groups, complete=True))

    def test_source_commit_mismatch_is_rejected_at_every_entry_point(self):
        for commit in (None, "", "TBD", "8cd9520", "0" * 40):
            with self.subTest(commit=commit):
                with self.assertRaisesRegex(SourceVersionMismatch, "source commit mismatch"):
                    context("enqueue", source_commit=commit)
                for api in (permission_table, serialize_table):
                    with self.assertRaises(SourceVersionMismatch):
                        api(source_version=SOURCE_VERSION, source_commit=commit)
                with self.assertRaises(SourceVersionMismatch):
                    self.audit(source_commit=commit)

    def test_inventory_audit_rejects_version_mismatch(self):
        with self.assertRaises(SourceVersionMismatch):
            self.audit(source_version="course-kernel-TBD")

    def test_bad_configs_fail_explicitly_in_all_queries(self):
        for configs in ("CONFIG_EXT_GROUP_SCHED", ["not-a-config"], [True], [None], [[]],
                        {"CONFIG_EXT_GROUP_SCHED": False}):
            for api in (lambda **kw: context("cgroup_move", **kw),
                        lambda **kw: permission_table(source_version=SOURCE_VERSION, **kw),
                        lambda **kw: serialize_table(source_version=SOURCE_VERSION, **kw)):
                with self.subTest(configs=configs), self.assertRaises((ValueError, TypeError)):
                    api(enabled_configs=configs)

    def test_config_iterator_is_shared_safely_and_serializes_deterministically(self):
        via_iterator = permission_table(source_version=SOURCE_VERSION, enabled_configs=iter(CONFIGS))
        self.assertEqual(all_contexts(), via_iterator)
        self.assertEqual(
            serialize_table(source_version=SOURCE_VERSION, enabled_configs=CONFIGS),
            serialize_table(source_version=SOURCE_VERSION, enabled_configs=(*CONFIGS, *CONFIGS)),
        )


class CompleteEntryLockTests(unittest.TestCase):
    def test_every_source_backed_rq_precondition_and_object(self):
        for entry in all_contexts():
            fact = entry.lock("rq")
            expected = LockState.KNOWN_HELD if entry.callback in RQ_OBJECTS else LockState.UNKNOWN
            with self.subTest(callback=entry.callback):
                self.assertEqual(expected, fact.state)
                if expected == LockState.KNOWN_HELD:
                    self.assertEqual(LockIdentity("rq", entry.callback + "." + RQ_OBJECTS[entry.callback]),
                                     fact.identity)
                    self.assertTrue(any(ref.symbol == "update_locked_rq" for ref in fact.evidence))
                    self.assertIn("precondition", fact.explanation)

    def test_subject_pi_lock_is_not_universally_held(self):
        for entry in all_contexts():
            fact = entry.lock("pi_lock")
            expected = (LockState.KNOWN_HELD if entry.callback in ("select_cpu", "exit_task", "cgroup_move")
                        else LockState.KNOWN_NOT_HELD if entry.callback == "init_task" else LockState.UNKNOWN)
            with self.subTest(callback=entry.callback):
                self.assertEqual(expected, fact.state)
                if expected != LockState.UNKNOWN:
                    self.assertEqual(entry.callback + ".task:p", fact.identity.object)
                    self.assertTrue(fact.evidence)

    def test_init_task_pi_absence_evidence_covers_all_four_callers_and_unlock(self):
        entry = context("init_task")
        expected = {"__scx_init_task", "scx_fork", "sched_cgroup_fork", "scx_task_iter_unlock",
                    "task_rq_unlock", "scx_root_enable_workfn", "scx_sub_enable_workfn", "scx_sub_disable"}
        for name in ("rq", "pi_lock"):
            fact = entry.lock(name)
            expected_state = LockState.KNOWN_NOT_HELD if name == "pi_lock" else LockState.UNKNOWN
            self.assertEqual(expected_state, fact.state)
            self.assertEqual(expected, {r.symbol for r in fact.evidence})

    def test_init_task_fork_pi_release_does_not_prove_common_rq_absence(self):
        entry = context("init_task")
        rq = entry.lock(LockIdentity("rq", "init_task.task:p"))
        self.assertEqual(LockState.UNKNOWN, rq.state)
        self.assertIn("only explicitly releases p's pi_lock", rq.explanation)
        self.assertEqual(LockState.KNOWN_NOT_HELD,
                         entry.lock(LockIdentity("pi_lock", "init_task.task:p")).state)

    def test_all_dump_callbacks_hold_same_global_lock(self):
        identities = set()
        for name in ("dump", "dump_cpu", "dump_task"):
            fact = context(name).lock("scx_dump_lock")
            self.assertEqual(LockState.KNOWN_HELD, fact.state)
            self.assertTrue(any(r.line <= 6337 <= r.end_line for r in fact.evidence))
            identities.add(fact.identity)
        self.assertEqual({LockIdentity("scx_dump_lock", "global:scx_dump_lock")}, identities)

    def test_unlocked_group_is_not_blanket_rq_absence(self):
        for name in sorted(UNLOCKED_CALLBACKS):
            entry = context(name, enabled_configs=CONFIGS)
            with self.subTest(callback=name):
                self.assertEqual(Permission.ALLOWED, entry.permission(KfuncGroup.UNLOCKED))
                self.assertEqual(LockState.UNKNOWN, entry.lock("rq").state)
        self.assertEqual(LockState.KNOWN_HELD, context("dump").lock("scx_dump_lock").state)

    def test_cgroup_setters_hold_rwsem_read_side(self):
        for name in ("cgroup_set_weight", "cgroup_set_idle", "cgroup_set_bandwidth"):
            fact = context(name, enabled_configs=CONFIGS).lock("scx_cgroup_ops_rwsem")
            self.assertEqual(LockState.KNOWN_HELD, fact.state)
            self.assertEqual("global:scx_cgroup_ops_rwsem", fact.identity.object)
            self.assertEqual(LockMode.READ, fact.mode)
            self.assertIn("read mode only", fact.explanation)

    def test_lock_modes_do_not_promote_shared_ownership_to_exclusive(self):
        for entry in all_contexts():
            for fact in entry.entry_locks:
                expected = (LockMode.READ if fact.name == "scx_cgroup_ops_rwsem" else LockMode.EXCLUSIVE
                            if fact.state == LockState.KNOWN_HELD else LockMode.UNKNOWN)
                self.assertEqual(expected, fact.mode, (entry.callback, fact.name))
        with self.assertRaises(TypeError):
            LockFact("rq", LockState.UNKNOWN, mode="exclusive")

    def test_enable_mutex_preconditions_and_explicit_release(self):
        for name, state in (("init", LockState.KNOWN_HELD), ("sub_attach", LockState.KNOWN_HELD),
                            ("sub_detach", LockState.KNOWN_NOT_HELD), ("exit", LockState.UNKNOWN)):
            self.assertEqual(state, context(name).lock("scx_enable_mutex").state, name)

    def test_distinct_rq_objects_and_unresolved_aliases_remain_unknown(self):
        entry = context("enqueue")
        known = entry.lock("rq")
        self.assertEqual(known, entry.lock(LockIdentity("rq", "enqueue.task:p")))
        for query in (LockIdentity("rq", "enqueue.task:other"), LockIdentity("rq", "enqueue.cpu:other"),
                      LockIdentity("rq", "dispatch.cpu:cpu"), LockIdentity("pi_lock", "enqueue.task:p"),
                      "task_rq", "p->pi_lock", "rq.lock", "dsq", "dsq->lock"):
            with self.subTest(query=query):
                self.assertEqual(LockState.UNKNOWN, entry.lock(query).state)
        for name, other in (("yield", "task:to"), ("core_sched_before", "task:b"),
                            ("dump_task", "task:p")):
            fact = context(name).lock(LockIdentity("rq", f"{name}.{other}"))
            self.assertEqual(LockState.UNKNOWN, fact.state)

    def test_no_known_fact_without_identity_and_complete_provenance(self):
        for entry in all_contexts():
            refs = [r for p in entry.permissions for r in p.evidence]
            for fact in entry.entry_locks:
                if fact.state != LockState.UNKNOWN:
                    self.assertIsNotNone(fact.identity)
                    self.assertEqual(fact.name, fact.identity.name)
                    self.assertTrue(fact.evidence)
                    refs.extend(fact.evidence)
            for ref in refs:
                self.assertEqual(SOURCE_VERSION, ref.source_version)
                self.assertEqual(SOURCE_COMMIT, ref.source_commit)
                self.assertTrue(ref.file.startswith("kernel/sched/"))
                self.assertTrue(ref.symbol)
                self.assertGreater(ref.line, 0)
                self.assertGreaterEqual(ref.end_line, ref.line)

    def test_invalid_lock_states_cannot_bypass_enum_boolean_safeguards(self):
        for state in ("known_held", "held", True, None):
            with self.subTest(state=state), self.assertRaises(TypeError):
                LockFact("rq", state)
        for args in (("", "task:p"), ("rq", ""), ("rq", None)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                LockIdentity(*args)
        with self.assertRaisesRegex(ValueError, "names must match"):
            LockFact("rq", LockState.UNKNOWN, identity=LockIdentity("pi_lock", "task:p"))

    def test_all_known_held_and_not_held_results_reject_truthiness(self):
        for entry in all_contexts():
            for fact in entry.entry_locks:
                with self.assertRaises(TypeError):
                    bool(fact)
                with self.assertRaises(TypeError):
                    bool(fact.state)
                with self.assertRaises(TypeError):
                    bool(fact.mode)


class ExpandedInspectionTests(unittest.TestCase):
    run_demo = InspectionTests.run_demo
    def test_config_enabled_demo_covers_every_source_callback(self):
        completed = self.run_demo("--source-version", SOURCE_VERSION,
                                  "--source-commit", SOURCE_COMMIT,
                                  "--enabled-config", CONFIGS[0])
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertNotIn("UNKNOWN (config)", completed.stdout)
        self.assertIn("global:scx_cgroup_ops_rwsem;mode=read", completed.stdout)
        for spec in callback_inventory():
            self.assertTrue(any(line.split() and line.split()[0] == spec.name
                                for line in completed.stdout.splitlines()), spec.name)

    def test_unknown_config_is_visible_in_default_demo_and_json(self):
        completed = self.run_demo("--source-version", SOURCE_VERSION)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("UNKNOWN (config)", completed.stdout)
        entries = json.loads(serialize_table(source_version=SOURCE_VERSION))
        for entry in entries:
            if entry["required_configs"]:
                self.assertEqual("unverified", entry["verification"])
                self.assertTrue(all(p["decision"] == "unknown" for p in entry["permissions"]))

    def test_cli_rejects_commit_mismatch_without_table_or_traceback(self):
        completed = self.run_demo("--source-version", SOURCE_VERSION, "--source-commit", "wrong")
        self.assertEqual(2, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertIn("source commit mismatch", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_config_enabled_json_is_deterministic(self):
        completed = self.run_demo("--source-version", SOURCE_VERSION, "--json",
                                  "--enabled-config", CONFIGS[0])
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(json.loads(serialize_table(source_version=SOURCE_VERSION, enabled_configs=CONFIGS)),
                         json.loads(completed.stdout))


if __name__ == "__main__":
    unittest.main()
