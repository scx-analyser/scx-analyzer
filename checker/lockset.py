"""Conservative ordered-event analysis. Results describe a model, not kernel safety."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from .checkers import Finding
from .context import (
    SOURCE_COMMIT, LockState, SourceReference, SourceVersionMismatch, Verification, get_context,
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


@dataclass(frozen=True)
class Provenance:
    """Caller attestations, absent from the shared callgraph schema.

    complete_events and linear_events attest to exhaustive, unconditional,
    successful primitive events, stable bindings, and no omitted branches.
    They are modeling assumptions, never certificates of kernel behavior.
    """
    source_commit: str | None = None
    complete_events: bool = False
    linear_events: bool = False
    synthetic: bool = False

    def __post_init__(self) -> None:
        for name in ("complete_events", "linear_events", "synthetic"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a boolean attestation")
        if self.source_commit is not None:
            require_name(self.source_commit, "source commit")


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
class AnalysisResult:
    source_version: str
    provenance: Provenance
    illustrative: bool
    accesses: tuple[AccessAssessment, ...]
    preconditions: tuple[PreconditionAssessment, ...]
    conditions: tuple[AnalysisCondition, ...]
    exits: tuple[RootExit, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True, allow_nan=False) + "\n"


@dataclass(frozen=True)
class _Flow:
    locks: Lockset
    conditions: tuple[AnalysisCondition, ...] = ()


class _Analyzer:
    def __init__(self, graph, policy, bindings, max_depth):
        self.graph, self.policy, self.bindings = graph, policy, bindings
        self.max_depth = max_depth
        self.accesses: list[AccessAssessment] = []
        self.preconditions: list[PreconditionAssessment] = []
        self.conditions: list[AnalysisCondition] = []

    def site(self, path, event=None, index=None):
        node = self.graph["nodes"].get(path[-1], {})
        return AnalysisSite(path[0], path, path[-1], node.get("file"),
                            event.get("line") if event is not None else None, index)

    def uncertain(self, flow, code, site, detail):
        condition = AnalysisCondition(code, site, detail)
        self.conditions.append(condition)
        # Sticky uncertainty: without a CFG, later events cannot establish that
        # the apparent straight-line continuation is the path actually taken.
        return _Flow(Lockset(), (*flow.conditions, condition))

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
                       for other in self.policy.for_access(site.function, rule.field, access)
                       if flow.locks.state(other.lock) != LockState.KNOWN_HELD]
            if missing:
                assessment = Assessment.UNKNOWN
                explanation = ("This lock is held, but protection requires every applicable policy lock; "
                               + ", ".join(f"{lock.name}={state.value}" for lock, state in missing) + ".")
        self.accesses.append(AccessAssessment(site, rule.field, access, rule.lock, observed,
                                              assessment, explanation, flow.conditions))

    @staticmethod
    def matches(edge, event):
        return (edge["target"] == event.get("target")
                and ("line" not in edge or "line" not in event or edge["line"] == event["line"]))

    def visit(self, path, flow):
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
        if events is None:
            flow = self.uncertain(flow, "missing_events", site, "No ordered event body; absence does not imply purity.")
        else:
            calls = [event for event in events if event["kind"] == "call"]
            # A line-less event cannot stand in for several distinct source
            # call sites. Duplicate metadata for the same line is not another
            # site; unlocated adjacency alone does not establish multiplicity.
            for target in sorted({edge["target"] for edge in node["callees"] if "line" in edge}):
                target_calls = [event for event in calls if event.get("target") == target]
                located = {event["line"] for event in target_calls if "line" in event}
                missing_lines = {edge["line"] for edge in node["callees"]
                                 if edge["target"] == target and "line" in edge} - located
                unlocated_count = sum("line" not in event for event in target_calls)
                if len(missing_lines) > unlocated_count:
                    flow = self.uncertain(flow, "incomplete_call_sites", site,
                                          f"Distinct call sites for {target} at {sorted(missing_lines)} "
                                          "cannot all be covered by the available ordered call events.")
            # Adjacency is used only for coverage and call-kind classification.
            # An unsequenced call could precede *any* event in this function.
            for edge in sorted(node["callees"], key=lambda edge: (edge["target"], edge["kind"], edge.get("line", -1))):
                if not any(self.matches(edge, event) for event in calls):
                    flow = self.uncertain(flow, "unsequenced_callee", site,
                                          f"Callee {edge['target']} has no matching ordered call event.")
        sequenced_fields = {event.get("field") for event in events or ()
                            if event["kind"] in ("write", "atomic")}
        for field in sorted(set(node.get("writes", ())) - sequenced_fields):
            flow = self.uncertain(flow, "unordered_write", site,
                                  f"Write metadata for {field} has no ordered event; access kind/order are unknown.")
            for rule in self.policy.for_field(name, field):
                self.record_access(flow, site, rule, None)
        if events is None:
            return flow

        for index, event in enumerate(events):
            site, kind = self.site(path, event, index), event["kind"]
            if kind in ("guard", "error", "warn"):
                flow = self.uncertain(flow, "unknown_control_flow", site,
                                      f"{kind} may change reachability or effects; the schema supplies no CFG.")
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
                    elif not flow.conditions:
                        old = flow.locks.state(lock)
                        if ((kind == "lock" and old == LockState.KNOWN_HELD)
                                or (kind == "unlock" and old == LockState.KNOWN_NOT_HELD)):
                            flow = self.uncertain(flow, "invalid_lock_transition", site,
                                                  "Repeated acquisition/release is unsupported for this simple lock model.")
                        else:
                            state = LockState.KNOWN_HELD if kind == "lock" else LockState.KNOWN_NOT_HELD
                            flow = _Flow(flow.locks.with_state(lock, state))
            elif kind in ("write", "atomic"):
                field = event.get("field")
                if field is None:
                    flow = self.uncertain(flow, "missing_access_field", site, "Access has no field identity.")
                    continue
                access = AccessKind(kind)
                rules = self.policy.for_access(name, field, access)
                for rule in rules:
                    self.record_access(flow, site, rule, access)
                if access == AccessKind.ATOMIC and not rules:
                    self.conditions.append(AnalysisCondition(
                        "no_atomic_policy", site, f"No explicit atomic-access policy for {field}; no lock requirement inferred.",
                    ))
            elif kind == "call":
                target = event.get("target")
                matches = [edge for edge in node["callees"] if self.matches(edge, event)]
                if not target or not matches or any(edge["kind"] != "direct" for edge in matches):
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
    provenance: Provenance | None = None,
    max_depth: int = 32,
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
    provenance = provenance if provenance is not None else Provenance()
    if not isinstance(provenance, Provenance):
        raise TypeError("provenance must be a Provenance")
    bindings = {} if bindings is None else {function: dict(values) for function, values in bindings.items()}
    for function, values in bindings.items():
        require_name(function, "binding function")
        for token, lock in values.items():
            require_name(token, "lock token")
            if not isinstance(lock, LockIdentity):
                raise TypeError("lock bindings must resolve to LockIdentity objects")
    entry_states = dict(entry_states) if entry_states is not None else {}
    callbacks = dict(callbacks) if callbacks is not None else {}
    roots = set(callgraph["roots"])
    if (entry_states.keys() | callbacks.keys()) - roots:
        raise ValueError("entry states and callback contexts must reference declared roots")
    if not all(isinstance(state, Lockset) for state in entry_states.values()):
        raise TypeError("entry states must be Lockset objects")
    contexts = {}
    for root, callback in callbacks.items():
        require_name(callback, "callback")
        context = get_context(callback, source_version=callgraph["kernel_version"])
        if provenance.source_commit != context.source_commit or provenance.source_commit != SOURCE_COMMIT:
            raise SourceVersionMismatch("C2 integration requires the exact matching source commit provenance")
        contexts[root] = context

    engine = _Analyzer(callgraph, policy, bindings, max_depth)
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
                flow = engine.uncertain(flow, "unknown_callback", site, "C2 has no verified model for this callback.")
            for fact in context.entry_locks:
                if fact.state != LockState.UNKNOWN:
                    lock = bindings.get(root, {}).get(fact.name)
                    flow = engine.precondition(flow, site, lock, fact.state, fact.evidence)
        flow = engine.visit((root,), flow)
        exits.append(RootExit(root, flow.locks, flow.conditions))
    return AnalysisResult(callgraph["kernel_version"], provenance, callgraph.get("illustrative", False),
                          tuple(engine.accesses), tuple(engine.preconditions), tuple(engine.conditions), tuple(exits))


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
    validate("findings", {"kernel_version": result.source_version, "findings": findings})
    return findings
