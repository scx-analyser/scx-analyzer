"""Provisional Linux v7.1 entry facts for C3; no invariant verdicts.

This models final SCX callback filtering, intersected with kfunc registration
hooks. It neither selects the team's kernel nor reproduces the BPF verifier.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Iterable

SOURCE_VERSION = "v7.1"
SOURCE_COMMIT = "8cd9520d35a6c38db6567e97dd93b1f11f185dc6"


class SourceVersionMismatch(ValueError):
    """The caller's source does not match this provisional model."""


class KfuncGroup(StrEnum):
    ANY = "ANY"
    CPU_RELEASE = "CPU_RELEASE"
    DISPATCH = "DISPATCH"
    ENQUEUE = "ENQUEUE"
    IDLE = "IDLE"
    SELECT_CPU = "SELECT_CPU"
    UNLOCKED = "UNLOCKED"


class ProgramType(StrEnum):
    STRUCT_OPS = "BPF_PROG_TYPE_STRUCT_OPS"
    SYSCALL = "BPF_PROG_TYPE_SYSCALL"
    TRACING = "BPF_PROG_TYPE_TRACING"


class Permission(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"

    def __bool__(self) -> bool:
        raise TypeError("compare Permission values explicitly")


class LockState(StrEnum):
    KNOWN_HELD = "known_held"
    KNOWN_NOT_HELD = "known_not_held"
    UNKNOWN = "unknown"

    def __bool__(self) -> bool:
        raise TypeError("compare LockState values explicitly")


class Verification(StrEnum):
    SOURCE_VERIFIED = "source_verified"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class SourceReference:
    file: str
    symbol: str
    line: int
    end_line: int

    @property
    def url(self) -> str:
        return (f"https://github.com/torvalds/linux/blob/{SOURCE_COMMIT}/"
                f"{self.file}#L{self.line}-L{self.end_line}")


def _ext(symbol: str, line: int, end_line: int) -> SourceReference:
    return SourceReference("kernel/sched/ext.c", symbol, line, end_line)


@dataclass(frozen=True)
class GroupPermission:
    group: KfuncGroup
    registration_set: str
    decision: Permission
    evidence: tuple[SourceReference, ...]
    explanation: str

    def __bool__(self) -> bool:
        raise TypeError("compare GroupPermission.decision explicitly")


@dataclass(frozen=True)
class LockFact:
    name: str
    state: LockState
    evidence: tuple[SourceReference, ...] = ()
    explanation: str = "No entry-lock fact has been established for this lock."

    def __post_init__(self) -> None:
        if self.state != LockState.UNKNOWN and not self.evidence:
            raise ValueError("known lock states require source evidence")

    def __bool__(self) -> bool:
        raise TypeError("compare LockFact.state explicitly")


@dataclass(frozen=True)
class ExecutionContext:
    callback: str | None
    program_type: str
    scx_attachment: bool | None
    verification: Verification
    permissions: tuple[GroupPermission, ...]
    entry_locks: tuple[LockFact, ...]
    source_version: str = SOURCE_VERSION
    source_commit: str = SOURCE_COMMIT
    provisional: bool = True

    @property
    def allowed_groups(self) -> tuple[KfuncGroup, ...]:
        return tuple(item.group for item in self.permissions if item.decision == Permission.ALLOWED)

    def permission(self, group: KfuncGroup | str) -> Permission:
        """Unknown groups return UNKNOWN, never an implicit permission grant."""
        return next((item.decision for item in self.permissions if item.group == group),
                    Permission.UNKNOWN)

    def permission_for_groups(
        self, groups: Iterable[KfuncGroup | str], *, complete: bool = False,
    ) -> Permission:
        """Apply the filter's OR rule to all known memberships of a kfunc.

        A verified allowed membership suffices. DENIED additionally requires
        the caller to attest that the source/catalog membership set is complete.
        """
        if isinstance(groups, str):
            raise TypeError("pass a collection of groups, not a single string")
        if not isinstance(complete, bool):
            raise TypeError("complete must be a boolean")
        decisions = tuple(self.permission(group) for group in groups)
        if Permission.ALLOWED in decisions:
            return Permission.ALLOWED
        if not decisions or Permission.UNKNOWN in decisions or not complete:
            return Permission.UNKNOWN
        return Permission.DENIED

    def lock(self, name: str) -> LockFact:
        return next((fact for fact in self.entry_locks if fact.name == name),
                    LockFact(name, LockState.UNKNOWN))

    def to_dict(self) -> dict[str, Any]:
        """Return detached JSON-compatible data in a deterministic order."""
        return asdict(self)


# Each row is read directly from scx_kf_allow_flags[], not from old SCX_KF_*
# masks or illustrative fixtures. ANY and IDLE are separate filter exceptions.
_CALLBACKS = {
    "select_cpu": ((KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE), 9829),
    "enqueue": ((KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE), 9830),
    "dispatch": ((KfuncGroup.ENQUEUE, KfuncGroup.DISPATCH), 9831),
    "cpu_release": ((KfuncGroup.CPU_RELEASE,), 9832),
    "init_task": ((KfuncGroup.UNLOCKED,), 9833),
    "dump": ((KfuncGroup.UNLOCKED,), 9834),
}
_SETS = {
    KfuncGroup.ANY: "scx_kfunc_ids_any",
    KfuncGroup.CPU_RELEASE: "scx_kfunc_ids_cpu_release",
    KfuncGroup.DISPATCH: "scx_kfunc_ids_dispatch",
    KfuncGroup.ENQUEUE: "scx_kfunc_ids_enqueue_dispatch",
    KfuncGroup.IDLE: "scx_kfunc_ids_idle",
    KfuncGroup.SELECT_CPU: "scx_kfunc_ids_select_cpu",
    KfuncGroup.UNLOCKED: "scx_kfunc_ids_unlocked",
}
_FILTER = _ext("scx_kfunc_context_filter", 9860, 9917)
_REGISTRATION = _ext("scx_init", 9936, 9956)
_IDLE_REGISTRATION = SourceReference("kernel/sched/ext_idle.c", "scx_idle_init", 1511, 1520)
_RQ_ASSERTION = _ext("update_locked_rq", 458, 468)
_CALL_WRAPPER = _ext("SCX_CALL_OP", 474, 485)
_TASK_WRAPPER = _ext("SCX_CALL_OP_TASK", 518, 524)
_RQ_CALLS = {
    "enqueue": _ext("do_enqueue_task", 1944, 1948),
    "dispatch": _ext("scx_dispatch_sched", 2839, 2844),
    "cpu_release": _ext("switch_class", 3047, 3054),
}


def _locks(callback: str | None, verified: bool) -> tuple[LockFact, ...]:
    if not verified:
        return (LockFact("rq", LockState.UNKNOWN),)
    if callback in _RQ_CALLS:
        return (LockFact(
            "rq", LockState.KNOWN_HELD,
            (_RQ_ASSERTION, _CALL_WRAPPER, _RQ_CALLS[callback])
            + ((_TASK_WRAPPER,) if callback == "enqueue" else ()),
            "The callback's rq argument is checked by update_locked_rq() before entry; "
            "this is a source precondition for that rq, not a runtime observation.",
        ),)
    facts = (LockFact(
        "rq", LockState.UNKNOWN,
        explanation="Neither an UNLOCKED permission nor a NULL locked_rq argument "
                    "proves that any particular lock is absent.",
    ),)
    if callback == "dump":
        facts += (LockFact(
            "scx_dump_lock", LockState.KNOWN_HELD,
            (_ext("scx_dump_state", 6321, 6337), _ext("scx_dump_state", 6363, 6367)),
            "The function-scoped raw_spinlock_irqsave guard precedes ops.dump().",
        ),)
    return facts


def get_context(
    callback: str | None,
    *,
    source_version: str,
    program_type: ProgramType | str = ProgramType.STRUCT_OPS,
    scx_attachment: bool | None = True,
) -> ExecutionContext:
    """Query final permissions for an explicitly selected provisional source.

    STRUCT_OPS defaults to an identified SCX attachment. Pass False for a
    non-SCX attachment, or None if attachment identity is unresolved. A callback
    name is meaningful only for STRUCT_OPS; other programs must use None.
    Unmodeled callbacks/types remain UNKNOWN, including their lock state.
    """
    if source_version != SOURCE_VERSION:
        raise SourceVersionMismatch(
            f"source version mismatch: provisional model requires {SOURCE_VERSION!r}, "
            f"got {source_version!r}"
        )
    if callback is not None and not isinstance(callback, str):
        raise TypeError("callback must be a string or None")
    if not isinstance(program_type, str):
        raise TypeError("program_type must be a string or ProgramType")
    if scx_attachment is not None and not isinstance(scx_attachment, bool):
        raise TypeError("scx_attachment must be True, False, or None")
    if callback is not None:
        callback = callback.removeprefix("ops.")
    if program_type != ProgramType.STRUCT_OPS and callback is not None:
        raise ValueError("callback names apply only to STRUCT_OPS programs; use None")

    evidence = (_FILTER, _REGISTRATION, _IDLE_REGISTRATION)
    allowed: set[KfuncGroup] = set()
    verified = False
    explanation = "Callback, program type, or SCX attachment is not modeled; no permission is inferred."
    if program_type == ProgramType.STRUCT_OPS:
        if scx_attachment is False:
            verified = True
            explanation = "The final SCX filter rejects SCX kfuncs for non-SCX struct_ops."
        elif scx_attachment is True and callback in _CALLBACKS:
            groups, line = _CALLBACKS[callback]
            allowed.update((*groups, KfuncGroup.ANY, KfuncGroup.IDLE))
            evidence = (_ext("scx_kf_allow_flags", line, line), *evidence)
            verified = True
            explanation = "Final SCX per-op filtering and registration hooks determine this group permission."
    elif program_type in (ProgramType.SYSCALL, ProgramType.TRACING):
        allowed.update((KfuncGroup.ANY, KfuncGroup.IDLE))
        if program_type == ProgramType.SYSCALL:
            allowed.update((KfuncGroup.UNLOCKED, KfuncGroup.SELECT_CPU))
        verified = True
        explanation = "Filter exceptions are intersected with the inspected program-type registrations."

    permissions = tuple(GroupPermission(
        group, _SETS[group],
        (Permission.ALLOWED if group in allowed else Permission.DENIED) if verified else Permission.UNKNOWN,
        evidence, explanation,
    ) for group in sorted(KfuncGroup))
    is_scx_callback = verified and program_type == ProgramType.STRUCT_OPS and scx_attachment is True
    return ExecutionContext(
        callback, str(program_type), scx_attachment if program_type == ProgramType.STRUCT_OPS else None,
        Verification.SOURCE_VERIFIED if verified else Verification.UNVERIFIED,
        permissions, _locks(callback, is_scx_callback),
    )


def permission_table(*, source_version: str) -> tuple[ExecutionContext, ...]:
    return tuple(get_context(callback, source_version=source_version) for callback in sorted(_CALLBACKS))


def serialize_table(*, source_version: str) -> str:
    return json.dumps([context.to_dict() for context in permission_table(source_version=source_version)],
                      indent=2, sort_keys=True, allow_nan=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect provisional callback entry facts; no safety verdicts")
    parser.add_argument("--source-version", required=True, help="explicit reference version (only v7.1)")
    parser.add_argument("--json", action="store_true", help="include all permissions, lock facts, and evidence")
    args = parser.parse_args(argv)
    try:
        contexts = permission_table(source_version=args.source_version)
    except SourceVersionMismatch as exc:
        parser.error(str(exc))
    if args.json:
        print(serialize_table(source_version=args.source_version), end="")
        return 0
    print(f"PROVISIONAL Linux {SOURCE_VERSION} reference ({SOURCE_COMMIT})")
    print(f"{'CALLBACK':<14} {'CONTEXT GROUPS':<24} ENTRY LOCK FACTS")
    for context in contexts:
        groups = ",".join(group for group in context.allowed_groups
                          if group not in (KfuncGroup.ANY, KfuncGroup.IDLE))
        locks = ",".join(f"{fact.name}={fact.state}" for fact in context.entry_locks
                         if fact.state != LockState.UNKNOWN) or "unknown"
        print(f"{context.callback:<14} {groups:<24} {locks}")
    print("ANY and IDLE also permitted for these SCX callbacks; other lock states remain unknown.")
    print("Source-inspected entry facts only; KERNEL_VERSION remains TBD; no invariant verdicts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
