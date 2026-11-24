"""Conservative ordered-event analysis. Results describe a model, not kernel safety."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from .checkers import Finding
from .context import (
    SOURCE_COMMIT, LockIdentity as ContextLockIdentity, LockMode, LockState,
    SourceReference, SourceVersionMismatch, Verification, get_context,
)
from .lock_policy import AccessKind, LockIdentity, ProtectionPolicy, require_name
from .runner import validate


@dataclass(frozen=True)
class LockOwnership:
    lock: LockIdentity
    state: LockState

    def __bool__(self) -> bool:
        raise TypeError("compare LockOwnership.state explicitly")


@dataclass(frozen=True)
class Lockset:
    entries: tuple[LockOwnership, ...] = ()

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        if not all(isinstance(item, LockOwnership) and isinstance(item.lock, LockIdentity)
                   and isinstance(item.state, LockState) for item in entries):
            raise TypeError("lockset entries require LockIdentity and LockState values")
        if len({item.lock for item in entries}) != len(entries):
            raise ValueError("duplicate lock identity in lockset")
        object.__setattr__(self, "entries", tuple(sorted(entries, key=lambda item: item.lock.name)))

    @classmethod
    def from_mapping(cls, states: Mapping[LockIdentity, LockState]) -> Lockset:
        return cls(tuple(LockOwnership(lock, state) for lock, state in states.items()))

    def state(self, lock: LockIdentity) -> LockState:
        if not isinstance(lock, LockIdentity):
            raise TypeError("lock queries require a LockIdentity")
        return next((item.state for item in self.entries if item.lock == lock), LockState.UNKNOWN)

    def with_state(self, lock: LockIdentity, state: LockState) -> Lockset:
        states = {item.lock: item.state for item in self.entries}
        states[lock] = state
        return Lockset.from_mapping(states)


class Assessment(StrEnum):
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    UNKNOWN = "unknown"

    def __bool__(self) -> bool:
        raise TypeError("compare Assessment values explicitly")


class PreconditionStatus(StrEnum):
    MET = "met"
    UNMET = "unmet"
    UNPROVEN = "unproven"

    def __bool__(self) -> bool:
        raise TypeError("compare PreconditionStatus values explicitly")


class ControlEffect(StrEnum):
    FALLTHROUGH = "fallthrough"
    EARLY_RETURN = "early_return"
    EXIT = "exit"

    def __bool__(self) -> bool:
        raise TypeError("compare ControlEffect values explicitly")


class GuardBranch(StrEnum):
    CONDITION_TRUE = "condition_true"
    CONDITION_FALSE = "condition_false"

    def __bool__(self) -> bool:
        raise TypeError("compare GuardBranch values explicitly")


@dataclass(frozen=True)
class ControlSemantics:
    """Reviewed control/lock effects of exactly one event, outside the schema.

    FALLTHROUGH preserves tracked locks on both diagnostic outcomes.
    EARLY_RETURN preserves locks on the continuation; its returning branch
    has unknown cleanup/effects. EXIT proves no local fallthrough, without
    claiming that the caller resumes or that exit cleanup preserves locks.
    References and attestations are supplied by the model author, not inferred.
    """
    function: str
    event_index: int
    event: tuple[tuple[str, str | int], ...]
    effect: ControlEffect
    reference: SourceReference
    branch_when: GuardBranch | None = None

    @classmethod
    def for_event(cls, function, event_index, event, effect, reference, *, branch_when=None):
        if not isinstance(event, Mapping):
            raise TypeError("control event must be a mapping")
        return cls(function, event_index, tuple(event.items()), effect, reference, branch_when)

    def __post_init__(self) -> None:
        require_name(self.function, "control function")
        if type(self.event_index) is not int or self.event_index < 0:
            raise ValueError("control event_index must be a nonnegative integer")
        pairs = tuple(self.event)
        if any(not isinstance(pair, tuple) or len(pair) != 2
               or not isinstance(pair[0], str) or type(pair[1]) not in (str, int) for pair in pairs):
            raise TypeError("control event must contain immutable scalar key/value pairs")
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError("duplicate control event key")
        object.__setattr__(self, "event", tuple(sorted(pairs)))
        event = dict(pairs)
        if event.get("kind") not in ("guard", "warn", "error"):
            raise ValueError("control semantics apply only to guard/warn/error events")
        if not isinstance(self.effect, ControlEffect):
            raise TypeError("control effect must be a ControlEffect")
        if self.branch_when is not None and not isinstance(self.branch_when, GuardBranch):
            raise TypeError("branch_when must be a GuardBranch")
        if self.effect == ControlEffect.EARLY_RETURN:
            if (event["kind"] != "guard" or event.get("action") != "return"
                    or not event.get("cond") or self.branch_when is None):
                raise ValueError("early return needs a guard, condition, return action and explicit branch polarity")
        elif event["kind"] == "guard" or self.branch_when is not None:
            raise ValueError("guards require early-return semantics; fallback/continue branches need a CFG")
        elif self.effect == ControlEffect.FALLTHROUGH and event.get("action") not in (None, "continue", "error"):
            raise ValueError("fallthrough cannot certify a return or unresolved fallback")
        elif self.effect == ControlEffect.EXIT and "cond" in event:
            raise ValueError("conditional exits need a modeled guard and continuation")
        ref = self.reference
        if not isinstance(ref, SourceReference) or ref.symbol != self.function:
            raise ValueError("control reference must identify its function")
        if type(ref.line) is not int or type(ref.end_line) is not int or not 1 <= ref.line <= ref.end_line:
            raise ValueError("control reference needs a valid source line range")
        require_name(ref.file, "control source file")
        require_name(ref.source_version, "control source version")
        require_name(ref.source_commit, "control source commit")


@dataclass(frozen=True)
class Provenance:
    """Caller attestations, absent from the shared callgraph schema.

    complete_events and linear_events attest to exhaustive successful primitive
    events, stable bindings, and linear control between reviewed control events.
    No branch or cleanup may be omitted, including branches inside predicates.
    They are modeling assumptions, never certificates of kernel behavior.
    """
    source_commit: str | None = None
    complete_events: bool = False
    linear_events: bool = False
    synthetic: bool = False
    enabled_configs: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        for name in ("complete_events", "linear_events", "synthetic"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a boolean attestation")
        if self.source_commit is not None:
            require_name(self.source_commit, "source commit")
        if self.enabled_configs is not None:
            if isinstance(self.enabled_configs, (str, Mapping)):
                raise TypeError("enabled_configs must contain enabled CONFIG_* names")
            configs = tuple(self.enabled_configs)
            if any(not isinstance(c, str) or not re.fullmatch(r"CONFIG_[A-Z0-9_]+", c) for c in configs):
                raise ValueError("enabled_configs must contain enabled CONFIG_* names")
            object.__setattr__(self, "enabled_configs", tuple(sorted(set(configs))))


@dataclass(frozen=True)
class AnalysisSite:
    root: str
    path: tuple[str, ...]
    function: str
    file: str | None
    line: int | None
    event_index: int | None


@dataclass(frozen=True)
class AnalysisCondition:
    code: str
    site: AnalysisSite
    detail: str


@dataclass(frozen=True)
class AccessAssessment:
    site: AnalysisSite
    field: str
    access: AccessKind | None
    required_lock: LockIdentity
    observed: LockState
    assessment: Assessment
    explanation: str
    conditions: tuple[AnalysisCondition, ...]

    def __bool__(self) -> bool:
        raise TypeError("compare AccessAssessment.assessment explicitly")


@dataclass(frozen=True)
class PreconditionAssessment:
    site: AnalysisSite
    lock: LockIdentity | None
    expected: LockState
    observed: LockState
    status: PreconditionStatus
    evidence: tuple[SourceReference, ...] = ()

    def __bool__(self) -> bool:
        raise TypeError("compare PreconditionAssessment.status explicitly")


@dataclass(frozen=True)
class RootExit:
    root: str
    locks: Lockset
    conditions: tuple[AnalysisCondition, ...]


@dataclass(frozen=True)
class FunctionSummary:
    """One invocation under its actual abstract entry state, never universal effects.

    Acquired/released describe successful body events, not exit guarantees.
    required_held/not_held retain assertion sites; they are not inferred entry locks.
    """
    site: AnalysisSite
    entry: Lockset
    exit: Lockset
    acquired: tuple[LockIdentity, ...]
    released: tuple[LockIdentity, ...]
    required_held: tuple[PreconditionAssessment, ...]
    required_not_held: tuple[PreconditionAssessment, ...]
    conditions: tuple[AnalysisCondition, ...]


@dataclass(frozen=True)
class AnalysisWork:
    limit: int
    consumed: int
    function_visits: int
    events: int
    metadata: int
    exhausted: bool


@dataclass(frozen=True)
class AnalysisResult:
    source_version: str
    provenance: Provenance
    illustrative: bool
    accesses: tuple[AccessAssessment, ...]
    preconditions: tuple[PreconditionAssessment, ...]
    conditions: tuple[AnalysisCondition, ...]
    exits: tuple[RootExit, ...]
    summaries: tuple[FunctionSummary, ...] = ()
    work: AnalysisWork | None = None
    control_semantics: tuple[ControlSemantics, ...] = ()

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True, allow_nan=False) + "\n"


@dataclass(frozen=True)
class _Flow:
    locks: Lockset
    conditions: tuple[AnalysisCondition, ...] = ()
    tainted: bool = False


@dataclass
class _Effects:
    acquired: set[LockIdentity] = field(default_factory=set)
    released: set[LockIdentity] = field(default_factory=set)
    early_return: bool = False


class _WorkBudgetExceeded(Exception):
    def __init__(self, site):
        self.site = site


class _Analyzer:
    def __init__(self, graph, policy, bindings, max_depth, max_work, control_semantics):
        self.graph, self.policy, self.bindings = graph, policy, bindings
        self.max_depth = max_depth
        self.control_semantics = {(item.function, item.event_index): item for item in control_semantics}
        self.accesses: list[AccessAssessment] = []
        self.preconditions: list[PreconditionAssessment] = []
        self.conditions: list[AnalysisCondition] = []
        self.summaries: list[FunctionSummary] = []
        self.max_work = max_work
        self.work_counts = {"function_visits": 0, "events": 0, "metadata": 0}
        self.work_used = 0
        self.exhausted = False
        self.policy_fields = {}
        self.policy_accesses = {}
        for rule in policy.rules:
            self.policy_fields.setdefault((rule.function, rule.field), []).append(rule)
            self.policy_accesses.setdefault((rule.function, rule.field, rule.access), []).append(rule)

    def field_rules(self, function, field):
        return self.policy_fields.get((function, field), ())

    def access_rules(self, function, field, access):
        return self.policy_accesses.get((function, field, access), ())

    def step(self, site, category):
        if self.work_used >= self.max_work:
            self.exhausted = True
            raise _WorkBudgetExceeded(site)
        self.work_used += 1
        self.work_counts[category] += 1

    def checked(self, values, site):
        for value in values:
            self.step(site, "metadata")
            yield value

    def work(self):
        return AnalysisWork(self.max_work, self.work_used, **self.work_counts, exhausted=self.exhausted)

    def site(self, path, event=None, index=None):
        node = self.graph["nodes"].get(path[-1], {})
        return AnalysisSite(path[0], path, path[-1], node.get("file"),
                            event.get("line") if event is not None else None, index)

    def uncertain(self, flow, code, site, detail):
        condition = AnalysisCondition(code, site, detail)
        self.conditions.append(condition)
        # Sticky uncertainty: without a CFG, later events cannot establish that
        # the apparent straight-line continuation is the path actually taken.
        return _Flow(Lockset(), (*flow.conditions, condition), True)

    def precondition(self, flow, site, lock, expected, evidence=()):
        observed = flow.locks.state(lock) if lock is not None else LockState.UNKNOWN
        status = (PreconditionStatus.MET if observed == expected else
                  PreconditionStatus.UNPROVEN if observed == LockState.UNKNOWN else PreconditionStatus.UNMET)
        self.preconditions.append(PreconditionAssessment(site, lock, expected, observed, status, evidence))
        if status != PreconditionStatus.MET:
            flow = self.uncertain(flow, f"{status.value}_precondition", site,
                                  f"Expected {expected.value} for {lock.name if lock else 'unresolved lock'}; "
                                  f"observed {observed.value}. Assertions do not acquire or release locks.")
        return flow

    def record_access(self, flow, site, rule, access):
        observed = flow.locks.state(rule.lock)
        assessment = {
            LockState.KNOWN_HELD: Assessment.PROTECTED,
            LockState.KNOWN_NOT_HELD: Assessment.UNPROTECTED,
            LockState.UNKNOWN: Assessment.UNKNOWN,
        }[observed]
        explanation = {
            Assessment.PROTECTED: "The specific required lock is held at this point in the supplied linear model.",
            Assessment.UNPROTECTED: "The specific required lock is absent in this model; this is not a kernel counterexample.",
            Assessment.UNKNOWN: "Ownership or event ordering cannot be established for this access.",
        }[assessment]
        if assessment == Assessment.PROTECTED:
            # Rules for this function/field/access kind are conjunctive. A
            # satisfied individual obligation must not certify a partial policy.
            missing = [(other.lock, flow.locks.state(other.lock))
                       for other in self.access_rules(site.function, rule.field, access)
                       if flow.locks.state(other.lock) != LockState.KNOWN_HELD]
            if missing:
                assessment = Assessment.UNKNOWN
                explanation = ("This lock is held, but protection requires every applicable policy lock; "
                               + ", ".join(f"{lock.name}={state.value}" for lock, state in missing) + ".")
        self.accesses.append(AccessAssessment(site, rule.field, access, rule.lock, observed,
                                              assessment, explanation, flow.conditions))

    def visit(self, path, flow):
        entry, effects = flow.locks, _Effects()
        first_access, first_precondition = len(self.accesses), len(self.preconditions)
        try:
            self.step(self.site(path), "function_visits")
            flow = self._visit(path, flow, effects)
        except _WorkBudgetExceeded as exc:
            flow = self.uncertain(flow, "work_budget", exc.site,
                                  f"Global work budget {self.max_work} exhausted; remaining effects/accesses are unknown.")
            self.pending_accesses(path, flow, exc.site.event_index, first_access)
        # A source 'lock' may have come from guard()/scoped_guard(), whose
        # cleanup release is absent from this schema. Acquiring a lock inside
        # the function is not a verified handoff to its caller. Tracking the
        # acquisitions (rather than entry/exit differences) also catches an
        # entry-held lock which the callee releases and reacquires.
        escaping = sorted((lock for lock in effects.acquired
                           if flow.locks.state(lock) == LockState.KNOWN_HELD), key=lambda lock: lock.name)
        if escaping:
            condition = AnalysisCondition(
                "unverified_lock_escape", self.site(path),
                "Acquired locks lack a verified release/exit handoff: "
                + ", ".join(lock.name for lock in escaping)
                + ". Scope cleanup may release them; no held exit fact is exported.",
            )
            self.conditions.append(condition)
            locks = flow.locks
            for lock in escaping:
                locks = locks.with_state(lock, LockState.UNKNOWN)
            # Known identities confine this uncertainty to the acquired locks.
            # It must not suppress a later explicit unlock of another lock.
            flow = _Flow(locks, (*flow.conditions, condition), flow.tainted)
        if effects.early_return:
            # The local continuation does not describe every returning path.
            # Cleanup and effects on a taken return branch are not in the CFG.
            flow = self.uncertain(flow, "early_return_join", self.site(path),
                                  "Reviewed early-return paths join at function exit with unknown cleanup/effects.")
        assertions = tuple(p for p in self.preconditions[first_precondition:] if p.site.path == path)
        self.summaries.append(FunctionSummary(
            self.site(path), entry, flow.locks,
            tuple(sorted(effects.acquired)), tuple(sorted(effects.released)),
            tuple(p for p in assertions if p.expected == LockState.KNOWN_HELD),
            tuple(p for p in assertions if p.expected == LockState.KNOWN_NOT_HELD), flow.conditions,
        ))
        return flow

    def pending_accesses(self, path, flow, first_event, first_access):
        """Report known local access candidates after a cut, without visiting callees.

        This reporting pass is linear in the current input body. A cut does not
        invent paths through skipped callees; work_budget findings cover that gap.
        """
        node = self.graph["nodes"].get(path[-1], {})
        if node.get("kind") in ("boundary", "external"):
            return
        recorded = {(a.site.event_index, a.field, a.access, a.required_lock)
                    for a in self.accesses[first_access:] if a.site.path == path}
        events = node.get("events", ())
        for index, event in enumerate(events):
            if index < (first_event or 0) or event["kind"] not in ("write", "atomic"):
                continue
            access, field = AccessKind(event["kind"]), event.get("field")
            for rule in self.access_rules(path[-1], field, access):
                if (index, field, access, rule.lock) not in recorded:
                    self.record_access(flow, self.site(path, event, index), rule, access)
        ordered = {e.get("field") for e in events if e["kind"] in ("write", "atomic")}
        for field in sorted(set(node.get("writes", ())) - ordered):
            for rule in self.field_rules(path[-1], field):
                if (None, field, None, rule.lock) not in recorded:
                    self.record_access(flow, self.site(path), rule, None)

    def _visit(self, path, flow, effects):
        name, site = path[-1], self.site(path)
        if name in path[:-1]:
            return self.uncertain(flow, "recursion", site, "Cycle: " + " -> ".join(path))
        if len(path) - 1 > self.max_depth:
            return self.uncertain(flow, "depth_limit", site, f"Maximum call depth {self.max_depth} exceeded.")
        node = self.graph["nodes"].get(name)
        if node is None:
            return self.uncertain(flow, "missing_callee", site, f"No definition for {name}.")
        if node["kind"] in ("boundary", "external"):
            return self.uncertain(flow, "opaque_callee", site, f"Effects of {node['kind']} function {name} are unknown.")

        events = node.get("events")
        edge_kinds, site_kinds, unlocated_kinds = {}, {}, {}
        if events is None:
            flow = self.uncertain(flow, "missing_events", site, "No ordered event body; absence does not imply purity.")
        else:
            call_sites, unlocated_calls, edge_lines, edge_sites = {}, {}, {}, set()
            sequenced_fields = set()
            for event in self.checked(events, site):
                if event["kind"] == "call":
                    target = event.get("target")
                    call_sites.setdefault(target, set()).add(event.get("line"))
                    if "line" not in event:
                        unlocated_calls[target] = unlocated_calls.get(target, 0) + 1
                elif event["kind"] in ("write", "atomic"):
                    sequenced_fields.add(event.get("field"))
            for edge in self.checked(node["callees"], site):
                target, kind, line = edge["target"], edge["kind"], edge.get("line")
                edge_kinds.setdefault(target, set()).add(kind)
                edge_sites.add((target, kind, line))
                if line is None:
                    unlocated_kinds.setdefault(target, set()).add(kind)
                else:
                    site_kinds.setdefault((target, line), set()).add(kind)
                    edge_lines.setdefault(target, set()).add(line)
            # A line-less event cannot stand in for several distinct source
            # call sites. Duplicate metadata for the same line is not another
            # site; unlocated adjacency alone does not establish multiplicity.
            for target in self.checked(sorted(edge_lines), site):
                missing_lines = edge_lines[target] - call_sites.get(target, set())
                if len(missing_lines) > unlocated_calls.get(target, 0):
                    flow = self.uncertain(flow, "incomplete_call_sites", site,
                                          f"Distinct call sites for {target} at {sorted(missing_lines)} "
                                          "cannot all be covered by the available ordered call events.")
            # Adjacency is used only for coverage and call-kind classification.
            # An unsequenced call could precede *any* event in this function.
            for target, kind, line in self.checked(sorted(edge_sites, key=lambda e: (e[0], e[1], e[2] is not None, e[2] or 0)), site):
                locations = call_sites.get(target, set())
                if not locations or (line is not None and None not in locations and line not in locations):
                    flow = self.uncertain(flow, "unsequenced_callee", site,
                                          f"Callee {target} has no matching ordered call event.")
        if events is None:
            sequenced_fields = set()
        for field in self.checked(sorted(set(node.get("writes", ())) - sequenced_fields), site):
            flow = self.uncertain(flow, "unordered_write", site,
                                  f"Write metadata for {field} has no ordered event; access kind/order are unknown.")
            for rule in self.field_rules(name, field):
                self.record_access(flow, site, rule, None)
        if events is None:
            return flow

        for index, event in enumerate(events):
            site, kind = self.site(path, event, index), event["kind"]
            self.step(site, "events")
            if kind in ("guard", "error", "warn"):
                semantics = self.control_semantics.get((name, index))
                if semantics is None:
                    flow = self.uncertain(flow, "unknown_control_flow", site,
                                          f"{kind} lacks reviewed control/lock effects; action text alone supplies no CFG.")
                elif semantics.effect == ControlEffect.EARLY_RETURN:
                    effects.early_return = True
                elif semantics.effect == ControlEffect.EXIT:
                    return self.uncertain(flow, "control_exit", site,
                                          "Reviewed exit has no local fallthrough; cleanup and caller continuation are unknown.")
                # A reviewed FALLTHROUGH is a lock-preserving diagnostic.
                # It never repairs previous uncertainty or acquires a lock.
                continue
            if "cond" in event or "action" in event:
                flow = self.uncertain(flow, "conditional_event", site, "Conditional event without a CFG.")
            if kind in ("lock", "unlock", "assert_held", "assert_not_held"):
                lock = self.bindings.get(name, {}).get(event.get("lock"))
                if lock is None:
                    flow = self.uncertain(flow, "unresolved_lock", site,
                                          f"No explicit object binding for lock token {event.get('lock')!r}.")
                if kind.startswith("assert_"):
                    expected = LockState.KNOWN_HELD if kind == "assert_held" else LockState.KNOWN_NOT_HELD
                    flow = self.precondition(flow, site, lock, expected)
                elif lock is not None:
                    if "op" in event:
                        flow = self.uncertain(flow, "unsupported_lock_operation", site,
                                              "Lock op qualifiers may denote trylocks or other unsupported semantics.")
                    elif not flow.tainted:
                        old = flow.locks.state(lock)
                        if ((kind == "lock" and old == LockState.KNOWN_HELD)
                                or (kind == "unlock" and old == LockState.KNOWN_NOT_HELD)):
                            flow = self.uncertain(flow, "invalid_lock_transition", site,
                                                  "Repeated acquisition/release is unsupported for this simple lock model.")
                        else:
                            state = LockState.KNOWN_HELD if kind == "lock" else LockState.KNOWN_NOT_HELD
                            (effects.acquired if kind == "lock" else effects.released).add(lock)
                            flow = _Flow(flow.locks.with_state(lock, state), flow.conditions, flow.tainted)
            elif kind in ("write", "atomic"):
                field = event.get("field")
                if field is None:
                    flow = self.uncertain(flow, "missing_access_field", site, "Access has no field identity.")
                    continue
                access = AccessKind(kind)
                rules = self.access_rules(name, field, access)
                for rule in rules:
                    self.record_access(flow, site, rule, access)
                if not rules:
                    self.conditions.append(AnalysisCondition(
                        "no_atomic_policy" if access == AccessKind.ATOMIC else "no_write_policy", site,
                        f"No explicit {access.value} policy for {field}; no field-to-lock requirement inferred.",
                    ))
            elif kind == "call":
                target = event.get("target")
                self.step(site, "metadata")
                kinds = (edge_kinds.get(target, set()) if "line" not in event else
                         unlocated_kinds.get(target, set()) | site_kinds.get((target, event["line"]), set()))
                if not target or kinds != {"direct"}:
                    flow = self.uncertain(flow, "unresolved_call", site,
                                          f"Call to {target!r} is missing, indirect, or lacks unambiguous direct-call metadata.")
                else:
                    flow = self.visit((*path, target), flow)
        return flow


def analyze(
    callgraph: dict[str, Any],
    policy: ProtectionPolicy,
    *,
    bindings: Mapping[str, Mapping[str, LockIdentity]] | None = None,
    entry_states: Mapping[str, Lockset] | None = None,
    callbacks: Mapping[str, str] | None = None,
    context_bindings: Mapping[str, Mapping[ContextLockIdentity, LockIdentity]] | None = None,
    provenance: Provenance | None = None,
    max_depth: int = 32,
    max_work: int = 10000,
    control_semantics: tuple[ControlSemantics, ...] = (),
) -> AnalysisResult:
    """Analyze each root independently; no registration, alias guessing, or kernel verdicts.

    C2 facts are source-backed entry *requirements*. They never seed ownership
    from assertions: explicitly supplied entry states must satisfy them.
    """
    validate("callgraph", callgraph)
    if not isinstance(policy, ProtectionPolicy):
        raise TypeError("policy must be a ProtectionPolicy")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 0 <= max_depth <= 128:
        raise ValueError("max_depth must be an integer between 0 and 128 (root depth is 0)")
    if not isinstance(max_work, int) or isinstance(max_work, bool) or not 1 <= max_work <= 1000000:
        raise ValueError("max_work must be an integer between 1 and 1000000")
    provenance = provenance if provenance is not None else Provenance()
    if not isinstance(provenance, Provenance):
        raise TypeError("provenance must be a Provenance")
    control_semantics = tuple(control_semantics)
    if (control_semantics and not provenance.synthetic
            and not re.fullmatch(r"[0-9a-f]{40}", provenance.source_commit or "")):
        raise SourceVersionMismatch("source control semantics require full commit provenance")
    seen_controls = set()
    for item in control_semantics:
        if not isinstance(item, ControlSemantics):
            raise TypeError("control_semantics must contain ControlSemantics objects")
        key = (item.function, item.event_index)
        if key in seen_controls:
            raise ValueError("duplicate control semantics for one event")
        seen_controls.add(key)
        ref = item.reference
        if ref.source_version != callgraph["kernel_version"] or ref.source_commit != provenance.source_commit:
            raise SourceVersionMismatch("control semantics require matching source version and commit provenance")
        node = callgraph["nodes"].get(item.function, {})
        events = node.get("events", ())
        if item.event_index >= len(events) or dict(item.event) != events[item.event_index]:
            raise ValueError("control semantics do not match the exact recorded event")
        event = events[item.event_index]
        if (node.get("file") != ref.file or "line" not in event
                or not ref.line <= event["line"] <= ref.end_line):
            raise ValueError("control reference does not match the event's source location")
    control_semantics = tuple(sorted(control_semantics, key=lambda item: (item.function, item.event_index)))
    bindings = {} if bindings is None else {function: dict(values) for function, values in bindings.items()}
    for function, values in bindings.items():
        require_name(function, "binding function")
        for token, lock in values.items():
            require_name(token, "lock token")
            if not isinstance(lock, LockIdentity):
                raise TypeError("lock bindings must resolve to LockIdentity objects")
    entry_states = dict(entry_states) if entry_states is not None else {}
    callbacks = dict(callbacks) if callbacks is not None else {}
    context_bindings = ({} if context_bindings is None else
                        {root: dict(values) for root, values in context_bindings.items()})
    roots = set(callgraph["roots"])
    if (entry_states.keys() | callbacks.keys() | context_bindings.keys()) - roots:
        raise ValueError("entry states and callback contexts must reference declared roots")
    if not all(isinstance(state, Lockset) for state in entry_states.values()):
        raise TypeError("entry states must be Lockset objects")
    for values in context_bindings.values():
        if not all(isinstance(identity, ContextLockIdentity) and isinstance(lock, LockIdentity)
                   for identity, lock in values.items()):
            raise TypeError("context_bindings must map C2 object identities to C3 lock identities")
    contexts = {}
    for root, callback in callbacks.items():
        require_name(callback, "callback")
        if provenance.source_commit != SOURCE_COMMIT:
            raise SourceVersionMismatch("C2 integration requires the exact matching source commit provenance")
        context = get_context(callback, source_version=callgraph["kernel_version"],
                              source_commit=provenance.source_commit,
                              enabled_configs=provenance.enabled_configs)
        contexts[root] = context

    engine = _Analyzer(callgraph, policy, bindings, max_depth, max_work, control_semantics)
    exits = []
    for root in sorted(roots):
        site = engine.site((root,))
        flow = _Flow(entry_states.get(root, Lockset()))
        if not provenance.complete_events or not provenance.linear_events:
            flow = engine.uncertain(flow, "untrusted_event_model", site,
                                    "Complete, unconditional linear event semantics have not been attested.")
        if callgraph.get("illustrative", False):
            flow = engine.uncertain(flow, "illustrative_input", site, "Illustrative input cannot establish definite access protection.")
        if root in contexts:
            context = contexts[root]
            if context.verification != Verification.SOURCE_VERIFIED:
                code = "unknown_callback_configuration" if context.required_configs else "unknown_callback"
                flow = engine.uncertain(flow, code, site, "C2 callback/build availability is not established.")
            for fact in context.entry_locks:
                if fact.state != LockState.UNKNOWN:
                    # Local event tokens cannot establish which task/CPU the
                    # callback's lock belongs to. Bind the actual C2 identity.
                    lock = context_bindings.get(root, {}).get(fact.identity)
                    if fact.state == LockState.KNOWN_HELD and fact.mode != LockMode.EXCLUSIVE:
                        flow = engine.uncertain(flow, "unsupported_entry_lock_mode", site,
                                                f"C2 requires {fact.mode.value} ownership of {fact.name}; "
                                                "C3 currently models exclusive locks only.")
                    flow = engine.precondition(flow, site, lock, fact.state, fact.evidence)
        flow = engine.visit((root,), flow)
        exits.append(RootExit(root, flow.locks, flow.conditions))
    return AnalysisResult(callgraph["kernel_version"], provenance, callgraph.get("illustrative", False),
                          tuple(engine.accesses), tuple(engine.preconditions), tuple(engine.conditions), tuple(exits),
                          tuple(engine.summaries), engine.work(), control_semantics)


def to_findings(result: AnalysisResult, *, invariant: str) -> list[Finding]:
    """Loss-aware, UNKNOWN-only adapter; no installed semantic checker or invented enforcement."""
    if not isinstance(invariant, str) or not re.fullmatch(r"I[0-9]+(?:\.[0-9]+)?", invariant):
        raise ValueError("an explicit catalog invariant ID is required")
    findings: list[Finding] = []
    for access in result.accesses:
        site = access.site
        detail = (f"{access.access or 'unordered access'} to {access.field}; requires {access.required_lock.name}; "
                  f"observed {access.observed.value}; model assessment {access.assessment.value}. "
                  + access.explanation)
        evidence: dict[str, Any] = {"function": site.function, "detail": detail}
        if site.file is not None:
            evidence["file"] = site.file
        if site.line is not None:
            evidence["line"] = site.line
        for condition in access.conditions:
            detail += f" [{condition.code}: {condition.detail}]"
        evidence["detail"] = detail
        findings.append({
            "kfunc": site.root, "invariant": invariant, "verdict": "unknown",
            "enforcement": ["unknown"], "static_or_runtime": "unknown", "path": list(site.path),
            "explanation": "Model-only access assessment; policy, provenance, reachability, and kernel safety are not verified.",
            "evidence": [evidence],
        })
    # A skipped subtree or unsupported obligation must not look like a fully
    # checked empty result. Access evidence already contains its own conditions;
    # emit only the remaining gaps, at their actual paths, without invented sites.
    covered = {condition for access in result.accesses for condition in access.conditions}
    for condition in result.conditions:
        if condition in covered:
            continue
        site = condition.site
        evidence = {"function": site.function, "detail": f"{condition.code}: {condition.detail}"}
        if site.file is not None:
            evidence["file"] = site.file
        if site.line is not None:
            evidence["line"] = site.line
        findings.append({
            "kfunc": site.root, "invariant": invariant, "verdict": "unknown", "enforcement": ["unknown"],
            "static_or_runtime": "unknown", "path": list(site.path),
            "explanation": "Unsupported or incomplete analysis; no protection or violation established.",
            "evidence": [evidence],
        })
    validate("findings", {"kernel_version": result.source_version, "findings": findings})
    return findings
