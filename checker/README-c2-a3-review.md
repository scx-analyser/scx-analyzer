# C2 / A3 discrepancy report for PR #49 re-review

Inspected on 2026-11-22. This is local review evidence; no review reply or other
GitHub state was posted. Epic A's catalog and shared schemas were not edited.

## Inspected revisions

| PR | Inspected head | Relationship / status observed |
|---|---|---|
| [#49](https://github.com/scx-analyser/scx-analyzer/pull/49) C2 | `6e5d2a4c30109db9b1f5a72884c1b3dedb16a68a` | Open; Adenis's changes-requested review identifies missing callback/lock coverage |
| [#48](https://github.com/scx-analyser/scx-analyzer/pull/48) C1 | `879fa8302ff9f5c35af10d0a8687e80acd074e21` | Approved, open/unmerged at inspection; #49 still targets its branch |
| [#50](https://github.com/scx-analyser/scx-analyzer/pull/50) A1 | `a17c4e5c53526be39fb0ef625d4ce8684f3bb382` | Proposed v7.1 inventory: 59 kfuncs, 66 memberships, seven sets |
| [#52](https://github.com/scx-analyser/scx-analyzer/pull/52) A2 | `847a014d9d253d5bb7e0a4c5fd6b1b7a8abf1af7` | Proposed family/rule catalog with contexts, scoped locks and source evidence |
| [#53](https://github.com/scx-analyser/scx-analyzer/pull/53) A3 | `698b3eb51c42fcde3ba7762df8c99563ee51c9a7` | Source-backed I1 proposal on #52, 14 rules covering 59 kfuncs |

The source reference for C2 and A3 matches: upstream v7.1,
`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`.
This is a provisional reference, not the established course kernel.
`KERNEL_VERSION` remains TBD. Current C2 branch shared contracts are the existing
contracts; the unmerged #52 schema is a proposed integration target.

## Aligned facts

- All 37 source-declared callback names, `ops.` spelling, the 19 nonzero
  allow-table rows, zero rows for other recognized callbacks, final ANY/IDLE
  exceptions and SCX/non-SCX attachment distinction agree.
- The seven BTF sets and program-type hooks agree: STRUCT_OPS all seven;
  SYSCALL UNLOCKED/SELECT_CPU/ANY/IDLE; TRACING ANY/IDLE. C2's ENQUEUE is
  `scx_kfunc_ids_enqueue_dispatch`, not a new enqueue-only set.
- All seven overlapping membership cases in #50/#53 agree: the four DSQ move
  helpers are DISPATCH + UNLOCKED, and the three select-CPU helpers are
  SELECT_CPU + UNLOCKED. C2 preserves OR semantics.
- The rq preconditions, subject select-CPU pi_lock, and dump guard agree.
  The exit_task pi_lock is also already documented by A3. C2 makes object
  identity/mode machine-readable, and records cgroup_move's subject pi_lock,
  setter rwsem **read mode**, and the common init/sub_attach mutex/sub_detach release.
- Permission, program type, BTF flags, access-site requirements and kernel-entry
  ownership must remain separate. Neither `KF_RCU` nor `KF_SLEEPABLE` proves a
  spinlock is held. Lockdep assertions state preconditions; they acquire no locks
  and are not production runtime enforcement.

## Comparison: precision, terminology, and open documentation questions

No contradictory callback/group permission mapping was found at the inspected
A3 head. UNKNOWN in C2 does **not** assert that A3's not-held claim is false.
The following categories keep evidence gaps separate from kernel-fact disputes.

| Category / A3 location | Result of comparison | Follow-up |
|---|---|---|
| Precision / [I1.yaml:166](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.yaml#L166), [244](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.yaml#L244) | A3 asserts rq absence for UNLOCKED callbacks. C2 retains rq UNKNOWN for all 15, including init_task: three init_task iterator paths explicitly drop rq, while the cited fork snippet explicitly drops pi_lock only. A common rq absence conclusion needs more evidence than an unacquired local lock or a new/unrunnable child. | Audit complete caller exclusion/preconditions before promoting UNKNOWN. C2 retains the independently verified init_task subject pi_lock absence. No kernel counterexample is claimed. |
| Precision / [I1.md:43](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.md#L43), [55](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.md#L55) | A3 gives additional arguments for select_cpu/dump rq absence. C2 does not encode universal absence over all ambient/object-specific wakeup and SysRq contexts. Its held pi_lock/dump-lock facts agree. | Preserve UNKNOWN until the relevant rq object and entry path are bound. The excluded proxy path/Kconfig evidence was inspected; this alone is not a claim about every ambient lock. |
| Identity/terminology / [I1.yaml:68-73](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.yaml#L68-L73), [I1.md:7-9](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.md#L7-L9) | A3 explicitly defines its rq as the callback's rq and uses notes to explain task/CPU identity. This agrees with C2's named entry locks. C2's structured invocation-local LockIdentity and LockMode are a richer representation, not evidence that A3 confuses all rqs. | Agree a machine-readable object/mode binding convention with A/B before shared-write analysis. Keep this integration requirement separate from factual disagreement. |
| Documentation ambiguity / [I1.md:58](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.md#L58) | The prose groups cgroup_cancel_move with setters under scx_cgroup_ops_rwsem read. Only the three setter functions explicitly acquire that read side in ext.c; cancellation sites at 4389/4430 do not. The machine-readable rules do not assert that rwsem for cancel_move. | Ask A to split/clarify the prose row or cite a complete outer-path guarantee. No C2 or catalog runtime counterexample was established. cgroup_mutex is a different lock. |
| Terminology/scope / [I1.md:59](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.md#L59), [63](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.md#L63) | A3's hotplug-lock shorthand or SYSCALL "none" can describe exclusion/no listed entry facts rather than ownership by the executing program. C2 leaves these locks UNKNOWN; that is not a contradiction until the shorthand's scope is fixed. | Clarify invoking execution, mode, object, and whether "none" means no guaranteed facts or a definite empty lockset. |
| Source adoption / [I1.md:4](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.md#L4), [I1.yaml:30-31](https://github.com/scx-analyser/scx-analyzer/blob/698b3eb51c42fcde3ba7762df8c99563ee51c9a7/catalog/invariants/I1.yaml#L30-L31) | The version/commit match C2. A3 refers to the proposed A1 pin, while this branch's KERNEL_VERSION/course-kernel decision remains TBD. This is an adoption boundary, not a disagreement about the inspected v7.1 source. | Keep current facts provisional until the exact course kernel and configuration are agreed. |
| Build availability / ext_internal.h:638-742 | The source itself conditionally declares eight cgroup callbacks. C2 requires explicit CONFIG_EXT_GROUP_SCHED attestation. A3 describes available source contexts without a structured build-availability field. | Treat this as a build/provenance integration requirement, not a different permission rule. |

## Confirmed C2 corrections from the final audit

- The coverage auditor previously accepted a changed CONFIG guard around
  otherwise identical allow-table masks. It now checks those guards against the
  declarations, and regression tests reject changed, missing and unsupported guards.
- The init_task common rq-not-held claim exceeded its cited evidence on the
  fork path. It is now UNKNOWN; the source-backed subject pi_lock absence remains.
- Membership coverage now includes the four ANY kfuncs whose BTF_ID_FLAGS
  invocations omit the optional flags argument. The independently checked fixture
  contains all 59 kfuncs / 66 memberships; this did not change group permissions.

## Source checks behind the narrower facts

All callback declarations and all 48 SCX_CALL_OP-family invocation sites in
ext.c/ext_idle.c were inventoried. The source coverage audit was run against the
complete pinned header and ext.c as well as the checked-in source extract.

The init_task pi_lock absence evidence follows core.c:4758-4785, ext.c:3762-3775,
6995-7000, 7291-7301 and 5807-5827, with scx_task_iter_unlock at ext.c:825-850
and task_rq_unlock at sched.h:1923-1937. It is specific to the invoking execution.
The three iterator paths release rq explicitly, but the cited fork snippet does
not establish a common rq absence precondition, so rq is UNKNOWN.

For unresolved outer facts, inspected paths include:
select_task_rq_scx ext.c:3311-3340; select_task_rq core.c:3571-3579;
try_to_wake_up core.c:4190-4290; wake_up_new_task core.c:4831-4843;
sched_exec core.c:5501-5517 (WF_EXEC exits before the SCX op at ext.c:3326-3327);
proxy_force_return core.c:6762-6797 and init/Kconfig:933-940 (incompatible with
SCHED_CLASS_EXT); scx_dump_state ext.c:6321-6454, its irq_work caller at 6481-6487
and SysRq handler at 7814-7820; hotplug callbacks ext.c:3392-3429 and
core.c:8621-8699. No inference that NULL means unlocked was used.

Cgroup source inspection also distinguishes the setter rwsem read guards
(ext.c:4436-4487), scx_cgroup_lock's write guard/cgroup_lock pair (4497-4510),
and cgroup lifecycle/migration outer contracts (core.c:9490-9567,
kernel/cgroup/cgroup.c:2645-2731, 2973-2980 and 5711-5746). These are not a
universal callback lockset; unencoded common ownership remains UNKNOWN.

## Latest C1 integration verification

An isolated copy of exact C1 commit
`879fa8302ff9f5c35af10d0a8687e80acd074e21` was overlaid with only these five C2
files. The 16 C1/source-contract files match that commit after normalizing Windows
line endings; the actual worktree's C1 files were not edited or merged.

On Windows Python 3.13.7, all **113 tests passed**: 71 C2 tests and 42 C1 tests.
This includes all six additional C1 regressions: single-file catalog diagnostics,
portable external callgraph paths, legacy-jsonschema installation hints, nested
JSON paths without schema dumps, schema-error formatting, and dependency bounds.
The copied contract validator checked three files with zero failures. Its CLI
emitted no findings and explicitly made no safety claim.

The current branch's existing C1 plus final C2 passed **107 tests** on Windows
Python 3.11.7. Its validator and normal checker/context commands also passed.
No Linux execution or kernel-safety validation is claimed by these host tests.

## Required follow-up across epics

1. Establish the exact **course kernel** version, commit, configuration and source
   integrity. Re-audit if it differs; no v7.1 facts may silently carry over.
2. Agree the precision/object-binding boundaries above with Epic A, and clarify
   the cgroup cancellation prose. A owns protected shared fields and required
   **specific** locks/modes. Its proposed task-field policies are not proven by
   this context table; no permission/identity disagreement should be inferred
   merely from UNKNOWN versus an unencoded guarantee.
3. Epic B should supply actual callback invocation identity, full source provenance,
   argument/object bindings, verified aliases, ordered events and explicit
   completeness/control-flow information. Existing shared contracts cannot express
   all of these, especially callgraph commit/config and object binding; any change
   requires cross-epic review.
4. Later C3 work may seed only matching, bound entry facts, then follow actual kfunc
   call paths to shared writes. It must invalidate facts across opaque calls and
   distinguish assertions from acquisitions. Async BPF callbacks do not inherit
   kernel-entry locks merely from their parent program's attach member.
5. After approved C1 merges, update #49's dependency/base through the normal reviewed
   Git workflow. No merge, rebase, retarget, commit or push was performed here.

C2 is supporting analysis infrastructure. These source/host unit checks neither
execute the course kernel nor prove the TA's state-modification invariants.
