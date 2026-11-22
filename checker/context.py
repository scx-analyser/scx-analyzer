"""Provisional Linux v7.1 entry facts for C3; no invariant verdicts.

This models final SCX callback filtering, intersected with kfunc registration
hooks. It neither selects the team's kernel nor reproduces the BPF verifier.
"""
from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
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


class LockMode(StrEnum):
    EXCLUSIVE = "exclusive"
    READ = "read"
    UNKNOWN = "unknown"

    def __bool__(self) -> bool:
        raise TypeError("compare LockMode values explicitly")


@dataclass(frozen=True)
class SourceReference:
    file: str
    symbol: str
    line: int
    end_line: int
    source_version: str = SOURCE_VERSION
    source_commit: str = SOURCE_COMMIT

    @property
    def url(self) -> str:
        return (f"https://github.com/torvalds/linux/blob/{self.source_commit}/"
                f"{self.file}#L{self.line}-L{self.end_line}")


def _ext(symbol: str, line: int, end_line: int) -> SourceReference:
    return SourceReference("kernel/sched/ext.c", symbol, line, end_line)

def _idle(symbol: str, line: int, end_line: int) -> SourceReference:
    return SourceReference("kernel/sched/ext_idle.c", symbol, line, end_line)


def _core(symbol: str, line: int, end_line: int) -> SourceReference:
    return SourceReference("kernel/sched/core.c", symbol, line, end_line)


@dataclass(frozen=True)
class LockIdentity:
    """A symbolic object in ONE callback invocation; never a universal rq."""
    name: str
    object: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (self.name, self.object)):
            raise ValueError("lock identity requires a name and an explicit object")


@dataclass(frozen=True)
class CallbackSpec:
    name: str
    declaration: SourceReference
    required_configs: tuple[str, ...]
    call_sites: tuple[SourceReference, ...]


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

    identity: LockIdentity | None = None
    mode: LockMode = LockMode.UNKNOWN

    def __post_init__(self) -> None:
        if not isinstance(self.state, LockState):
            raise TypeError("state must be a LockState, compared explicitly")
        if not isinstance(self.mode, LockMode):
            raise TypeError("mode must be a LockMode")
        if self.identity is not None and not isinstance(self.identity, LockIdentity):
            raise TypeError("identity must be a LockIdentity")
        if self.identity is not None and self.identity.name != self.name:
            raise ValueError("lock fact and identity names must match")
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
    required_configs: tuple[str, ...] = ()
    enabled_configs: tuple[str, ...] | None = None

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

    def lock(self, name: str | LockIdentity) -> LockFact:
        """String lookup is callback-local; identity lookup requires exact equality.

        No task/CPU alias or cross-invocation binding is inferred. Consumers must
        retain and bind identity before using a fact for a particular access.
        """
        if isinstance(name, LockIdentity):
            return next((fact for fact in self.entry_locks if fact.identity == name),
                        LockFact(name.name, LockState.UNKNOWN, identity=name))
        if not isinstance(name, str):
            raise TypeError("lock query must be a name or LockIdentity")
        return next((fact for fact in self.entry_locks if fact.name == name),
                    LockFact(name, LockState.UNKNOWN))

    def to_dict(self) -> dict[str, Any]:
        """Return detached JSON-compatible data in a deterministic order."""
        return asdict(self)


# Discovered from ALL function-pointer members of sched_ext_ops at this commit,
# including callbacks omitted from the allow table and config-conditional members.
_DECLARATIONS = {
    "select_cpu": (318, 318, ()),
    "enqueue": (333, 333, ()),
    "dequeue": (349, 349, ()),
    "dispatch": (372, 372, ()),
    "tick": (382, 382, ()),
    "runnable": (409, 409, ()),
    "running": (426, 426, ()),
    "stopping": (446, 446, ()),
    "quiescent": (466, 466, ()),
    "yield": (481, 481, ()),
    "core_sched_before": (499, 499, ()),
    "set_weight": (508, 508, ()),
    "set_cpumask": (517, 518, ()),
    "update_idle": (540, 540, ()),
    "cpu_acquire": (550, 550, ()),
    "cpu_release": (562, 562, ()),
    "init_task": (577, 577, ()),
    "exit_task": (587, 587, ()),
    "enable": (596, 596, ()),
    "disable": (606, 606, ()),
    "dump": (614, 614, ()),
    "dump_cpu": (626, 626, ()),
    "dump_task": (636, 636, ()),
    "cgroup_init": (651, 652, ("CONFIG_EXT_GROUP_SCHED",)),
    "cgroup_exit": (661, 661, ("CONFIG_EXT_GROUP_SCHED",)),
    "cgroup_prep_move": (675, 676, ("CONFIG_EXT_GROUP_SCHED",)),
    "cgroup_move": (686, 687, ("CONFIG_EXT_GROUP_SCHED",)),
    "cgroup_cancel_move": (698, 699, ("CONFIG_EXT_GROUP_SCHED",)),
    "cgroup_set_weight": (708, 708, ("CONFIG_EXT_GROUP_SCHED",)),
    "cgroup_set_bandwidth": (728, 729, ("CONFIG_EXT_GROUP_SCHED",)),
    "cgroup_set_idle": (740, 740, ("CONFIG_EXT_GROUP_SCHED",)),
    "sub_attach": (750, 750, ()),
    "sub_detach": (756, 756, ()),
    "cpu_online": (769, 769, ()),
    "cpu_offline": (778, 778, ()),
    "init": (787, 787, ()),
    "exit": (797, 797, ()),
}
_CALL_SITES = {
    "dequeue": (
        _ext("call_task_dequeue", 1453, 1453),
    ),
    "enqueue": (
        _ext("do_enqueue_task", 1948, 1948),
    ),
    "runnable": (
        _ext("enqueue_task_scx", 2052, 2052),
    ),
    "stopping": (
        _ext("dequeue_task_scx", 2182, 2182),
        _ext("put_prev_task_scx", 3072, 3072),
    ),
    "quiescent": (
        _ext("dequeue_task_scx", 2186, 2186),
    ),
    "yield": (
        _ext("yield_task_scx", 2208, 2208),
        _ext("yield_to_task_scx", 2219, 2219),
    ),
    "dispatch": (
        _ext("scx_dispatch_sched", 2840, 2840),
        _ext("scx_dispatch_sched", 2844, 2844),
    ),
    "cpu_acquire": (
        _ext("balance_one", 2903, 2903),
    ),
    "running": (
        _ext("set_next_task_scx", 2982, 2982),
    ),
    "cpu_release": (
        _ext("switch_class", 3054, 3054),
    ),
    "core_sched_before": (
        _ext("scx_prio_less", 3302, 3305),
    ),
    "select_cpu": (
        _ext("select_task_rq_scx", 3339, 3339),
    ),
    "set_cpumask": (
        _ext("set_cpus_allowed_scx", 3389, 3389),
        _ext("switching_to_scx", 3930, 3930),
    ),
    "cpu_online": (
        _ext("handle_hotplug", 3411, 3411),
    ),
    "cpu_offline": (
        _ext("handle_hotplug", 3413, 3413),
    ),
    "tick": (
        _ext("task_tick_scx", 3531, 3531),
    ),
    "init_task": (
        _ext("__scx_init_task", 3572, 3572),
    ),
    "enable": (
        _ext("__scx_enable_task", 3637, 3637),
    ),
    "set_weight": (
        _ext("__scx_enable_task", 3640, 3640),
        _ext("reweight_task_scx", 3909, 3909),
    ),
    "disable": (
        _ext("scx_disable_task", 3659, 3659),
    ),
    "exit_task": (
        _ext("__scx_disable_and_exit_task", 3697, 3697),
        _ext("scx_sub_init_cancel_task", 3713, 3713),
    ),
    "cgroup_init": (
        _ext("scx_tg_online", 4323, 4324),
        _ext("scx_cgroup_init", 4739, 4740),
    ),
    "cgroup_exit": (
        _ext("scx_tg_offline", 4345, 4345),
        _ext("scx_cgroup_exit", 4708, 4708),
    ),
    "cgroup_prep_move": (
        _ext("scx_cgroup_can_attach", 4374, 4375),
    ),
    "cgroup_cancel_move": (
        _ext("scx_cgroup_can_attach", 4389, 4390),
        _ext("scx_cgroup_cancel_attach", 4430, 4431),
    ),
    "cgroup_move": (
        _ext("scx_cgroup_move_task", 4412, 4414),
    ),
    "cgroup_set_weight": (
        _ext("scx_group_set_weight", 4445, 4445),
    ),
    "cgroup_set_idle": (
        _ext("scx_group_set_idle", 4460, 4460),
    ),
    "cgroup_set_bandwidth": (
        _ext("scx_group_set_bandwidth", 4480, 4481),
    ),
    "sub_detach": (
        _ext("scx_sub_disable", 5894, 5895),
    ),
    "exit": (
        _ext("scx_sub_disable", 5899, 5899),
        _ext("scx_root_disable", 6016, 6016),
    ),
    "dump_task": (
        _ext("scx_dump_task", 6301, 6301),
    ),
    "dump": (
        _ext("scx_dump_state", 6365, 6365),
    ),
    "dump_cpu": (
        _ext("scx_dump_state", 6425, 6425),
    ),
    "init": (
        _ext("scx_root_enable_workfn", 6903, 6903),
        _ext("scx_sub_enable_workfn", 7211, 7211),
    ),
    "sub_attach": (
        _ext("scx_sub_enable_workfn", 7228, 7229),
    ),
    "update_idle": (
        _idle("__scx_update_idle", 792, 792),
    ),
}
# Only explicit allow-table rows; an inventory member absent here has zero flags.
_ALLOW_FLAGS = {
    "select_cpu": ((KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE), 9829),
    "enqueue": ((KfuncGroup.SELECT_CPU, KfuncGroup.ENQUEUE), 9830),
    "dispatch": ((KfuncGroup.ENQUEUE, KfuncGroup.DISPATCH), 9831),
    "cpu_release": ((KfuncGroup.CPU_RELEASE,), 9832),
    "init_task": ((KfuncGroup.UNLOCKED,), 9833),
    "dump": ((KfuncGroup.UNLOCKED,), 9834),
    "cgroup_init": ((KfuncGroup.UNLOCKED,), 9836),
    "cgroup_exit": ((KfuncGroup.UNLOCKED,), 9837),
    "cgroup_prep_move": ((KfuncGroup.UNLOCKED,), 9838),
    "cgroup_cancel_move": ((KfuncGroup.UNLOCKED,), 9839),
    "cgroup_set_weight": ((KfuncGroup.UNLOCKED,), 9840),
    "cgroup_set_bandwidth": ((KfuncGroup.UNLOCKED,), 9841),
    "cgroup_set_idle": ((KfuncGroup.UNLOCKED,), 9842),
    "sub_attach": ((KfuncGroup.UNLOCKED,), 9844),
    "sub_detach": ((KfuncGroup.UNLOCKED,), 9845),
    "cpu_online": ((KfuncGroup.UNLOCKED,), 9846),
    "cpu_offline": ((KfuncGroup.UNLOCKED,), 9847),
    "init": ((KfuncGroup.UNLOCKED,), 9848),
    "exit": ((KfuncGroup.UNLOCKED,), 9849),
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
_ALLOW_TABLE = _ext("scx_kf_allow_flags", 9823, 9850)
_REGISTRATION = _ext("scx_init", 9936, 9956)
_IDLE_REGISTRATION = _idle("scx_idle_init", 1511, 1520)
_RQ_ASSERTION = _ext("update_locked_rq", 458, 468)
_CALL_WRAPPER = _ext("SCX_CALL_OP", 474, 499)
_TASK_WRAPPER = _ext("SCX_CALL_OP_TASK", 502, 545)

# Each object expression binds to THIS invocation's formal callback argument.
# These are preconditions, not assertions that we observed a runtime acquisition.
_RQ_OBJECTS = {
    "enqueue": "task:p", "dequeue": "task:p", "runnable": "task:p",
    "running": "task:p", "stopping": "task:p", "quiescent": "task:p",
    "tick": "task:p", "set_weight": "task:p", "enable": "task:p",
    "disable": "task:p", "set_cpumask": "task:p", "exit_task": "task:p",
    "cgroup_move": "task:p", "yield": "task:from", "core_sched_before": "task:a",
    "dispatch": "cpu:cpu", "cpu_acquire": "cpu:cpu", "cpu_release": "cpu:cpu",
    "update_idle": "cpu:cpu", "dump_cpu": "cpu:cpu", "dump_task": "cpu:dumped",
}


def callback_inventory() -> tuple[CallbackSpec, ...]:
    """Complete source-declared inventory, including conditional members."""
    return tuple(CallbackSpec(
        name, SourceReference("kernel/sched/ext_internal.h", "sched_ext_ops." + name, line, end),
        configs, _CALL_SITES[name],
    ) for name, (line, end, configs) in sorted(_DECLARATIONS.items()))


def _check_source(source_version: str, source_commit: str) -> None:
    if source_version != SOURCE_VERSION:
        raise SourceVersionMismatch(
            f"source version mismatch: provisional model requires {SOURCE_VERSION!r}, got {source_version!r}"
        )
    if source_commit != SOURCE_COMMIT:
        raise SourceVersionMismatch(
            f"source commit mismatch: provisional model requires {SOURCE_COMMIT!r}, got {source_commit!r}"
        )


def audit_callback_coverage(
    header: str, ext_source: str, *, source_version: str, source_commit: str,
) -> tuple[str, ...]:
    """Compare real source declarations AND allow rows with the model.

    This detects added/removed/renamed callbacks and changed allow masks without
    assuming a callback count. It is an inventory audit, not source authentication:
    callers must independently establish the supplied tree's commit and integrity.
    """
    _check_source(source_version, source_commit)
    # Remove comments so documentation examples cannot masquerade as declarations.
    header = re.sub(r"/\*.*?\*/|//[^\n]*", "", header, flags=re.S)
    struct = re.search(r"\bstruct sched_ext_ops\s*\{(.*?)^\};", header, re.S | re.M)
    if struct is None:
        raise ValueError("sched_ext_ops declaration not found")
    names = re.findall(r"\(\*(\w+)\)\s*\(", struct.group(1))
    if len(names) != len(set(names)) or set(names) != set(_DECLARATIONS):
        missing = sorted(set(names) - set(_DECLARATIONS))
        stale = sorted(set(_DECLARATIONS) - set(names))
        raise ValueError(f"callback inventory mismatch: unmodeled={missing}, absent={stale}, duplicates="
                         f"{len(names) != len(set(names))}")
    conditions: list[str] = []
    for line in struct.group(1).splitlines():
        directive = line.strip()
        if directive.startswith("#ifdef "):
            conditions.append(directive.split()[1])
        elif directive.startswith("#endif"):
            if not conditions:
                raise ValueError("unbalanced callback configuration guards")
            conditions.pop()
        elif directive.startswith("#"):
            raise ValueError("unsupported callback configuration guard; source review required")
        for name in re.findall(r"\(\*(\w+)\)", line):
            if tuple(conditions) != _DECLARATIONS[name][2]:
                raise ValueError(f"callback configuration mismatch: {name}")
    if conditions:
        raise ValueError("unbalanced callback configuration guards")
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", ext_source, flags=re.S)
    table = re.search(r"scx_kf_allow_flags\[\]\s*=\s*\{(.*?)\};", source, re.S)
    if table is None:
        raise ValueError("scx_kf_allow_flags table not found")
    rows = re.findall(r"\[SCX_OP_IDX\((\w+)\)\]\s*=\s*([^,]+),", table.group(1))
    if any(re.fullmatch(r"\s*SCX_KF_ALLOW_\w+(?:\s*\|\s*SCX_KF_ALLOW_\w+)*\s*", flags) is None
           for _, flags in rows):
        raise ValueError("unsupported allow-table expression; source review required")
    expected = {name: {group.value for group in groups} for name, (groups, _) in _ALLOW_FLAGS.items()}
    actual = {name: set(re.findall(r"SCX_KF_ALLOW_(\w+)", flags)) for name, flags in rows}
    if len(rows) != len(actual) or actual != expected:
        raise ValueError("callback allow-table mismatch; source review required")
    # Matching masks are insufficient if their compilation conditions changed.
    conditions = []
    for line in table.group(1).splitlines():
        directive = line.strip()
        if directive.startswith("#ifdef "):
            conditions.append(directive.split()[1])
        elif directive.startswith("#endif"):
            if not conditions:
                raise ValueError("unbalanced allow-table configuration guards")
            conditions.pop()
        elif directive.startswith("#"):
            raise ValueError("unsupported allow-table configuration guard; source review required")
        for name in re.findall(r"\[SCX_OP_IDX\((\w+)\)\]", line):
            if tuple(conditions) != _DECLARATIONS[name][2]:
                raise ValueError(f"allow-table configuration mismatch: {name}")
    if conditions:
        raise ValueError("unbalanced allow-table configuration guards")
    return tuple(sorted(names))


def _configs(enabled_configs: Iterable[str] | None) -> tuple[str, ...] | None:
    if enabled_configs is None:
        return None
    if isinstance(enabled_configs, (str, Mapping)):
        raise TypeError("enabled_configs must be a collection of CONFIG_* names")
    configs = tuple(enabled_configs)
    if any(not isinstance(c, str) or not re.fullmatch(r"CONFIG_[A-Z0-9_]+", c) for c in configs):
        raise ValueError("enabled_configs must contain CONFIG_* names")
    return tuple(sorted(set(configs)))


def _locks(callback: str | None, verified: bool) -> tuple[LockFact, ...]:
    if not verified:
        return (LockFact("rq", LockState.UNKNOWN),)
    facts = []
    def add(name: str, state: LockState, obj: str, evidence: tuple[SourceReference, ...],
            explanation: str, mode: LockMode = LockMode.EXCLUSIVE) -> None:
        identity = obj if obj.startswith("global:") else f"{callback}.{obj}"
        facts.append(LockFact(name, state, evidence, explanation, LockIdentity(name, identity),
                              mode if state == LockState.KNOWN_HELD else LockMode.UNKNOWN))

    if callback in _RQ_OBJECTS:
        add("rq", LockState.KNOWN_HELD, _RQ_OBJECTS[callback],
            (_RQ_ASSERTION, _CALL_WRAPPER, _TASK_WRAPPER, *_CALL_SITES[callback]),
            "Source-declared entry precondition for this specific rq. The wrapper "
            "asserts ownership; it does not acquire a lock. Not a runtime observation.")
    else:
        add("rq", LockState.UNKNOWN, "rq:unspecified", _CALL_SITES[callback],
            "No specific rq entry state established. UNLOCKED permissions and a NULL "
            "locked_rq argument alone establish neither absence nor ownership.")

    if callback == "select_cpu":
        add("pi_lock", LockState.KNOWN_HELD, "task:p",
            (_TASK_WRAPPER, *_CALL_SITES[callback],
             _core("try_to_wake_up", 4190, 4191), _core("try_to_wake_up", 4288, 4290),
             _core("wake_up_new_task", 4831, 4843)),
            "Subject p's pi_lock is held by the wakeup callers. This is NOT an rq "
            "lock and does not establish ownership of another task's pi_lock.")
    elif callback == "exit_task":
        add("pi_lock", LockState.KNOWN_HELD, "task:p",
            (_ext("__scx_disable_and_exit_task", 3670, 3697),
             _ext("scx_sub_init_cancel_task", 3705, 3713)),
            "Both call sites explicitly require subject p's pi_lock as an entry precondition.")
    elif callback == "cgroup_move":
        add("pi_lock", LockState.KNOWN_HELD, "task:p",
            (*_CALL_SITES[callback], _core("sched_move_task", 9444, 9457),
             _core("_task_rq_lock", 737, 747),
             SourceReference("kernel/sched/sched.h", "task_rq_lock guard", 1939, 1943)),
            "sched_move_task's task_rq_lock guard holds subject p's pi_lock and rq.")

    if callback == "init_task":
        # ALL four callers inspected, not a conclusion drawn from the allow mask.
        evidence = (*_CALL_SITES[callback], _ext("scx_fork", 3762, 3775),
                    _core("sched_cgroup_fork", 4758, 4785),
                    _ext("scx_task_iter_unlock", 825, 850),
                    SourceReference("kernel/sched/sched.h", "task_rq_unlock", 1920, 1937),
                    _ext("scx_root_enable_workfn", 6995, 7000),
                    _ext("scx_sub_enable_workfn", 7291, 7301),
                    _ext("scx_sub_disable", 5807, 5827))
        facts.clear()
        add("rq", LockState.UNKNOWN, "task:p", evidence,
            "The three iterator paths release rq before init, but the cited fork path "
            "only explicitly releases p's pi_lock. A new task or no local rq acquisition "
            "does not establish absence of caller-held rq ownership on every path.")
        add("pi_lock", LockState.KNOWN_NOT_HELD, "task:p", evidence,
            "Subject p's pi_lock is released explicitly before entry: directly on the "
            "fork path and by task_rq_unlock on all three task-iteration paths. "
            "This is a source entry fact about the invoking execution, not a runtime "
            "observation or a statement about another execution's ownership.")

    if callback in ("dump", "dump_cpu", "dump_task"):
        add("scx_dump_lock", LockState.KNOWN_HELD, "global:scx_dump_lock",
            (_ext("scx_dump_state", 6321, 6337), *_CALL_SITES[callback],
             _ext("scx_dump_state", 6381, 6384), _ext("scx_dump_state", 6446, 6454)),
            "The function-scoped raw_spinlock_irqsave guard encloses all three dump callbacks.")
    if callback in ("cgroup_set_weight", "cgroup_set_idle", "cgroup_set_bandwidth"):
        starts = {"cgroup_set_weight": (4436, 4449), "cgroup_set_idle": (4452, 4465),
                  "cgroup_set_bandwidth": (4468, 4487)}
        start, end = starts[callback]
        add("scx_cgroup_ops_rwsem", LockState.KNOWN_HELD, "global:scx_cgroup_ops_rwsem",
            (_ext(_CALL_SITES[callback][0].symbol, start, end),),
            "percpu_down_read()/percpu_up_read() enclose the callback; read mode only.", LockMode.READ)
    if callback in ("init", "sub_attach"):
        refs = ((_ext("scx_root_enable_workfn", 6833, 6837),
                 _ext("scx_root_enable_workfn", 6902, 6909)) if callback == "init" else ())
        add("scx_enable_mutex", LockState.KNOWN_HELD, "global:scx_enable_mutex",
            (*refs, _ext("scx_sub_enable_workfn", 7163, 7173), *_CALL_SITES[callback]),
            "Root/sub enable workers acquire scx_enable_mutex before init/sub_attach.")
    elif callback == "sub_detach":
        add("scx_enable_mutex", LockState.KNOWN_NOT_HELD, "global:scx_enable_mutex",
            (_ext("scx_sub_disable", 5880, 5895),),
            "scx_sub_disable explicitly drops scx_enable_mutex before sub_detach.")
    return tuple(facts)


def get_context(
    callback: str | None,
    *,
    source_version: str,
    program_type: ProgramType | str = ProgramType.STRUCT_OPS,
    scx_attachment: bool | None = True,
    source_commit: str = SOURCE_COMMIT,
    enabled_configs: Iterable[str] | None = None,
) -> ExecutionContext:
    """Query final permissions for an explicitly selected provisional source.

    STRUCT_OPS defaults to an identified SCX attachment. Pass False for a
    non-SCX attachment, or None if attachment identity is unresolved. A callback
    name is meaningful only for STRUCT_OPS; other programs must use None.
    Unmodeled callbacks/types remain UNKNOWN, including their lock state.
    """
    _check_source(source_version, source_commit)
    configs = _configs(enabled_configs)
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

    spec = next((item for item in callback_inventory() if item.name == callback), None)
    evidence = (_ALLOW_TABLE, _FILTER, _REGISTRATION, _IDLE_REGISTRATION)
    allowed: set[KfuncGroup] = set()
    verified = False
    explanation = "Callback, program type, or SCX attachment is not modeled; no permission is inferred."
    if program_type == ProgramType.STRUCT_OPS:
        if scx_attachment is False:
            verified = True
            explanation = "The final SCX filter rejects SCX kfuncs for non-SCX struct_ops."
        elif scx_attachment is True and spec is not None:
            evidence = (spec.declaration, *evidence)
            if spec.required_configs and (configs is None or not set(spec.required_configs) <= set(configs)):
                explanation = "Callback requires " + ",".join(spec.required_configs) + "; build availability unresolved or disabled."
            else:
                groups, line = _ALLOW_FLAGS.get(callback, ((), None))
                allowed.update((*groups, KfuncGroup.ANY, KfuncGroup.IDLE))
                if line is not None:
                    evidence = (_ext("scx_kf_allow_flags", line, line), *evidence)
                verified = True
                explanation = ("Final filter plus registration hooks; "
                               + ("explicit allow-table row." if line is not None else
                                  "recognized callback absent from allow table: zero context flags."))

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
        required_configs=spec.required_configs if spec is not None else (), enabled_configs=configs,
    )


def permission_table(
    *, source_version: str, source_commit: str = SOURCE_COMMIT,
    enabled_configs: Iterable[str] | None = None,
) -> tuple[ExecutionContext, ...]:
    configs = _configs(enabled_configs)
    return tuple(get_context(spec.name, source_version=source_version, source_commit=source_commit,
                             enabled_configs=configs) for spec in callback_inventory())


def serialize_table(
    *, source_version: str, source_commit: str = SOURCE_COMMIT,
    enabled_configs: Iterable[str] | None = None,
) -> str:
    return json.dumps([context.to_dict() for context in permission_table(
        source_version=source_version, source_commit=source_commit, enabled_configs=enabled_configs,
    )], indent=2, sort_keys=True, allow_nan=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect provisional callback entry facts; no safety verdicts")
    parser.add_argument("--source-version", required=True, help="explicit reference version (only v7.1)")
    parser.add_argument("--source-commit", default=SOURCE_COMMIT, help="exact reference commit")
    parser.add_argument("--enabled-config", action="append", default=None,
                        help="attest an enabled CONFIG_* option; repeat as needed")
    parser.add_argument("--json", action="store_true", help="include all permissions, lock facts, and evidence")
    args = parser.parse_args(argv)
    kwargs = dict(source_version=args.source_version, source_commit=args.source_commit,
                  enabled_configs=args.enabled_config)
    try:
        contexts = permission_table(**kwargs)
    except (SourceVersionMismatch, TypeError, ValueError) as exc:
        parser.error(str(exc))
    if args.json:
        print(serialize_table(**kwargs), end="")
        return 0
    print(f"PROVISIONAL Linux {SOURCE_VERSION} reference ({SOURCE_COMMIT})")
    print(f"{'CALLBACK':<22} {'CONTEXT GROUPS':<24} ENTRY LOCK FACTS (invocation-local objects)")
    for context in contexts:
        groups = ",".join(group for group in context.allowed_groups
                          if group not in (KfuncGroup.ANY, KfuncGroup.IDLE))
        if context.verification == Verification.UNVERIFIED:
            groups = "UNKNOWN (config)"
        locks = ",".join(f"{fact.name}={fact.state}[{fact.identity.object}"
                         f"{';mode=read' if fact.mode == LockMode.READ else ''}]" for fact in context.entry_locks
                         if fact.state != LockState.UNKNOWN) or "unknown"
        print(f"{context.callback:<22} {groups or '-':<24} {locks}")
    print("ANY and IDLE also permitted for verified SCX callbacks; other lock states remain unknown.")
    print("Conditional callbacks need --enabled-config CONFIG_EXT_GROUP_SCHED; no config is inferred.")
    print("Source-inspected entry facts only; KERNEL_VERSION remains TBD; no invariant verdicts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
