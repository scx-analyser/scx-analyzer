"""Conservative I3 guard coverage over ordered events; no production registration.

Positive results describe explicitly supplied models, never kernel-wide proofs.
The shared graph cannot encode CFG, aliases, completeness or a source commit.
Those facts must be supplied separately, bound to the exact graph fingerprint.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from heapq import heappop, heappush
from typing import Any

from .checkers import Finding
from .runner import validate


class _ExplicitEnum(StrEnum):
    def __bool__(self) -> bool:
        raise TypeError(f"compare {type(self).__name__} explicitly")


class Truth(_ExplicitEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Assessment(_ExplicitEnum):
    ESTABLISHED = "established"
    FALSE = "false"
    MISSING = "missing_check"
    UNKNOWN = "unknown"


class BranchWhen(_ExplicitEnum):
    CONDITION_TRUE = "condition_true"
    CONDITION_FALSE = "condition_false"


def _text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")


def _integer(value: int, label: str, minimum: int = 0) -> None:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")


def _tuple(value: Any, kind: type, label: str) -> tuple:
    if not isinstance(value, (tuple, list)) or not all(isinstance(v, kind) for v in value):
        raise TypeError(f"{label} must contain {kind.__name__} values")
    return tuple(value)


@dataclass(frozen=True, order=True)
class SourceReference:
    file: str
    symbol: str
    line: int
    end_line: int

    def __post_init__(self) -> None:
        _text(self.file, "source file")
        _text(self.symbol, "source symbol")
        _integer(self.line, "source line", 1)
        _integer(self.end_line, "source end line", self.line)


@dataclass(frozen=True)
class Source:
    version: str
    commit: str

    def __post_init__(self) -> None:
        _text(self.version, "source version")
        if not isinstance(self.commit, str) or not re.fullmatch(r"[0-9a-f]{40}", self.commit):
            raise ValueError("source commit must be a full lowercase SHA-1")


@dataclass(frozen=True, order=True)
class Predicate:
    """Opaque expression AND explicit object identities. No alias inference."""
    expression: str
    objects: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.expression, "predicate expression")
        objects = _tuple(self.objects, str, "predicate objects")
        if not objects:
            raise ValueError("predicate needs explicit object identities")
        for obj in objects:
            _text(obj, "object identity")
        object.__setattr__(self, "objects", objects)


@dataclass(frozen=True)
class GuardPolicy:
    """An explicit obligation, not a product of catalog objects x predicates.

    reference cites the obligation; access_line optionally narrows its site.
    Atomic operations require their own policy (access_kind='atomic').
    """
    rule_id: str
    root: str
    function: str
    field: str
    predicate: Predicate
    source: Source
    reference: SourceReference
    access_kind: str = "write"
    access_line: int | None = None
    access_object: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not re.fullmatch(r"I3\.[a-z][a-z0-9_.]*", self.rule_id):
            raise ValueError("guard policy needs an I3 rule id")
        for name in ("root", "function"):
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_]\w*", value):
                raise ValueError(f"policy {name} must name one function")
        if not isinstance(self.field, str) or not re.fullmatch(r"[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_\[\]]*)+", self.field):
            raise ValueError("policy field must be a shared-contract fieldref")
        if not isinstance(self.predicate, Predicate) or not isinstance(self.source, Source):
            raise TypeError("policy requires Predicate and Source values")
        if not isinstance(self.reference, SourceReference):
            raise TypeError("policy requires a source reference")
        if self.access_kind not in ("write", "atomic"):
            raise ValueError("policy access kind must be write or atomic")
        if self.access_line is not None:
            _integer(self.access_line, "policy access line", 1)
        if self.access_object is not None:
            _text(self.access_object, "policy access object")


@dataclass(frozen=True)
class FunctionModel:
    function: str
    reference: SourceReference
    complete_events: bool = False
    linear_except_guards: bool = False

    def __post_init__(self) -> None:
        _text(self.function, "function")
        if not isinstance(self.reference, SourceReference) or self.reference.symbol != self.function:
            raise ValueError("function model reference must identify its function")
        for key in ("complete_events", "linear_except_guards"):
            if type(getattr(self, key)) is not bool:
                raise TypeError(f"{key} must be a boolean attestation")


@dataclass(frozen=True)
class GuardSemantics:
    """Reviewed meaning of ONE guard event, including branch polarity.

    condition_true_means is the predicate value when event.cond is true.
    branch_when specifies which condition outcome takes event.action.
    exits_function attests an actual return, not an error helper's name.
    A terminating branch is joined back at function return, never discarded
    when propagating callee effects into its caller.
    """
    function: str
    event_index: int
    predicate: Predicate
    condition: str
    action: str
    condition_true_means: Truth
    branch_when: BranchWhen
    exits_function: bool
    reference: SourceReference

    def __post_init__(self) -> None:
        _text(self.function, "guard function")
        _integer(self.event_index, "guard event index")
        _text(self.condition, "guard condition")
        if self.action not in ("return", "error", "fallback", "continue"):
            raise ValueError("unsupported guard action")
        if not isinstance(self.predicate, Predicate):
            raise TypeError("guard requires a Predicate")
        if not isinstance(self.condition_true_means, Truth) or self.condition_true_means is Truth.UNKNOWN:
            raise ValueError("guard polarity must explicitly relate condition truth to predicate truth")
        if not isinstance(self.branch_when, BranchWhen) or type(self.exits_function) is not bool:
            raise TypeError("guard requires BranchWhen and explicit exit semantics")
        if not isinstance(self.reference, SourceReference) or self.reference.symbol != self.function:
            raise ValueError("guard source reference must identify its function")


@dataclass(frozen=True)
class ControlEdge:
    """Reviewed source-CFG edge between event IDs; target=None is function exit.

    outcome labels the SOURCE condition, not the required predicate. Event IDs
    and source line order are never used as a substitute for control flow.
    """
    origin: int
    target: int | None
    outcome: Truth = Truth.UNKNOWN

    def __post_init__(self) -> None:
        _integer(self.origin, "CFG origin")
        if self.target is not None:
            _integer(self.target, "CFG target")
        if not isinstance(self.outcome, Truth):
            raise TypeError("CFG outcome must be a Truth")


@dataclass(frozen=True)
class PredicatePreservation:
    """Reviewed preservation of ONE proof's predicate and access-object binding.

    This is never inferred from an argument spelling, a by-value prefix, an
    opaque callee or a write. The reference and reason must justify the effect.
    """
    event_index: int
    reference: SourceReference
    reason: str

    def __post_init__(self) -> None:
        _integer(self.event_index, "preservation event")
        if not isinstance(self.reference, SourceReference):
            raise TypeError("preservation needs a source reference")
        _text(self.reason, "preservation reason")


@dataclass(frozen=True)
class DominanceEvidence:
    """A narrow reviewed local source CFG, bound to one exact policy/access.

    C4 checks every entry-to-access path through this supplied DAG. Completeness,
    source fidelity and per-event preservation are reviewed inputs, not facts
    automatically extracted from C. This proves no caller/root-wide coverage.
    """
    policy: GuardPolicy
    graph_digest: str
    guard_index: int
    access_index: int
    edges: tuple[ControlEdge, ...]
    preserves: tuple[PredicatePreservation, ...]
    object_bindings: tuple[tuple[str, str], ...]
    reference: SourceReference
    stability_references: tuple[SourceReference, ...]
    rationale: str
    entry_index: int = 0
    configuration_independent: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.policy, GuardPolicy):
            raise TypeError("dominance evidence needs an exact GuardPolicy")
        if not isinstance(self.graph_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", self.graph_digest):
            raise ValueError("dominance evidence needs the exact graph fingerprint")
        for name in ("guard_index", "access_index", "entry_index"):
            _integer(getattr(self, name), name)
        if self.guard_index == self.access_index:
            raise ValueError("guard and access must be distinct events")
        if self.policy.access_line is None or self.policy.access_object is None:
            raise ValueError("dominance policy needs an exact access line and object identity")
        bindings = tuple(self.object_bindings)
        if any(not isinstance(b, tuple) or len(b) != 2 or not all(isinstance(v, str) and v.strip() for v in b)
               for b in bindings):
            raise TypeError("dominance bindings must map immutable identity/expression pairs in the site function")
        if len({identity for identity, _ in bindings}) != len(bindings):
            raise ValueError("duplicate dominance object binding")
        if {identity for identity, _ in bindings} != set(self.policy.predicate.objects) | {self.policy.access_object}:
            raise ValueError("dominance must bind every exact predicate and accessed-object identity")
        object.__setattr__(self, "object_bindings", tuple(sorted(bindings)))
        if not isinstance(self.reference, SourceReference) or self.reference.symbol != self.policy.function:
            raise ValueError("dominance reference must identify the access function")
        edges = _tuple(self.edges, ControlEdge, "CFG edges")
        if len(set(edges)) != len(edges):
            raise ValueError("duplicate CFG edge")
        object.__setattr__(self, "edges", tuple(sorted(
            edges, key=lambda e: (e.origin, e.target is None, e.target or 0, e.outcome.value))))
        preserves = _tuple(self.preserves, PredicatePreservation, "preservation evidence")
        if len({p.event_index for p in preserves}) != len(preserves):
            raise ValueError("duplicate preservation evidence")
        object.__setattr__(self, "preserves", tuple(sorted(preserves, key=lambda p: p.event_index)))
        refs = _tuple(self.stability_references, SourceReference, "stability references")
        if not refs:
            raise ValueError("dominance needs predicate/object stability evidence")
        object.__setattr__(self, "stability_references", tuple(sorted(set(refs))))
        _text(self.rationale, "dominance rationale")
        if type(self.configuration_independent) is not bool:
            raise TypeError("configuration_independent must be an explicit boolean")


@dataclass(frozen=True)
class EntryFact:
    predicate: Predicate
    value: Truth
    reference: SourceReference
    root: str

    def __post_init__(self) -> None:
        if not isinstance(self.predicate, Predicate) or not isinstance(self.value, Truth):
            raise TypeError("entry facts require Predicate and Truth values")
        if not isinstance(self.reference, SourceReference):
            raise TypeError("entry facts require explicit evidence")
        _text(self.root, "entry fact root")


@dataclass(frozen=True)
class Model:
    """Caller attestations, not automatically verified properties of extraction.

    bindings_verified covers stable object identities across every direct call,
    and the absence of unmodeled concurrent predicate changes. All assumptions
    are bound to an exact graph snapshot and one source version and commit.
    """
    source: Source
    graph_digest: str
    functions: tuple[FunctionModel, ...] = ()
    guards: tuple[GuardSemantics, ...] = ()
    bindings_verified: bool = False
    synthetic: bool = False
    config_digest: str | None = None
    dominance: tuple[DominanceEvidence, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.source, Source):
            raise TypeError("model requires a Source")
        if not isinstance(self.graph_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", self.graph_digest):
            raise ValueError("model requires the exact graph SHA-256 fingerprint")
        for name, kind in (("functions", FunctionModel), ("guards", GuardSemantics),
                           ("dominance", DominanceEvidence)):
            object.__setattr__(self, name, _tuple(getattr(self, name), kind, name))
        if len({f.function for f in self.functions}) != len(self.functions):
            raise ValueError("duplicate function model")
        if len({(g.function, g.event_index) for g in self.guards}) != len(self.guards):
            raise ValueError("duplicate guard annotation")
        if len({(d.policy, d.access_index) for d in self.dominance}) != len(self.dominance):
            raise ValueError("duplicate dominance evidence")
        object.__setattr__(self, "dominance", tuple(sorted(self.dominance, key=lambda d: (
            d.policy.root, d.policy.function, d.policy.rule_id, d.policy.field,
            d.policy.access_kind, d.access_index, d.policy.predicate, d.policy.access_object,
        ))))
        for name in ("bindings_verified", "synthetic"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a boolean attestation")
        if self.config_digest is not None and (
                not isinstance(self.config_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", self.config_digest)):
            raise ValueError("configuration digest must be a full lowercase SHA-256")


def graph_digest(callgraph: dict[str, Any]) -> str:
    """Fingerprint data, not evidence that its events match the source code."""
    encoded = json.dumps(callgraph, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Evidence:
    function: str
    detail: str
    path: tuple[str, ...]
    file: str | None = None
    line: int | None = None
    end_line: int | None = None


@dataclass(frozen=True)
class AccessAssessment:
    root: str
    path: tuple[str, ...]
    function: str
    file: str | None
    line: int | None
    event_index: int | None
    field: str
    rule_id: str
    policy_source: Source
    policy_reference: SourceReference
    predicate: Predicate
    observed: Truth
    assessment: Assessment
    explanation: str
    evidence: tuple[Evidence, ...]
    unresolved: tuple[str, ...]
    access_kind: str = "write"
    access_object: str | None = None
    proof_basis: str = "ordered_events"


@dataclass(frozen=True)
class AnalysisGap:
    root: str
    path: tuple[str, ...]
    function: str
    reason: str


@dataclass(frozen=True)
class AnalysisResult:
    accesses: tuple[AccessAssessment, ...]
    gaps: tuple[AnalysisGap, ...]
    work_used: int
    source: Source | None
    synthetic: bool
    graph_digest: str
    config_digest: str | None
    dominance_evidence: tuple[DominanceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_findings(self) -> list[Finding]:
        """Faithful C1 adapter: model assessments never become kernel verdicts."""
        findings: list[Finding] = []
        for access in self.accesses:
            evidence = [{k: v for k, v in asdict(e).items() if v is not None}
                        for e in access.evidence]
            evidence.append({"function": access.function, "detail": access.explanation,
                             "rule_id": access.rule_id, "field": access.field,
                             "predicate": asdict(access.predicate),
                             "source": asdict(access.policy_source),
                             "policy_reference": asdict(access.policy_reference),
                             "access_kind": access.access_kind, "access_object": access.access_object,
                             "event_index": access.event_index,
                             "proof_basis": access.proof_basis,
                             "graph_digest": self.graph_digest, "config_digest": self.config_digest,
                             "model_assessment": access.assessment.value,
                             "unresolved": list(access.unresolved)})
            if access.file is not None:
                evidence[-1]["file"] = access.file
            if access.line is not None:
                evidence[-1]["line"] = access.line
            if access.proof_basis == "reviewed_source_cfg":
                evidence[-1]["dominance_evidence"] = [asdict(d) for d in self.dominance_evidence
                    if d.policy.root == access.root and d.policy.function == access.function
                    and d.policy.rule_id == access.rule_id and d.policy.predicate == access.predicate
                    and d.policy.field == access.field and d.policy.access_kind == access.access_kind
                    and d.policy.access_object == access.access_object and d.access_index == access.event_index]
            findings.append({"kfunc": access.root, "invariant": "I3", "verdict": "unknown",
                             "enforcement": ["unknown"], "static_or_runtime": "unknown",
                             "path": list(access.path), "evidence": evidence,
                             "explanation": "Model-only guard coverage; no kernel safety verdict. "
                                            + access.explanation})
        for gap in self.gaps:
            findings.append({"kfunc": gap.root, "invariant": "I3", "verdict": "unknown",
                             "enforcement": ["unknown"], "static_or_runtime": "unknown", "path": list(gap.path),
                             "evidence": [{"function": gap.function, "detail": gap.reason,
                                           "source": asdict(self.source) if self.source is not None else None,
                                           "graph_digest": self.graph_digest,
                                           "config_digest": self.config_digest}],
                             "explanation": gap.reason})
        validate("findings", {"kernel_version": self.source.version if self.source else "unknown",
                              "findings": findings})
        return findings


@dataclass(frozen=True)
class _Fact:
    predicate: Predicate
    value: Truth = Truth.UNKNOWN
    evidence: tuple[Evidence, ...] = ()
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class _State:
    facts: tuple[_Fact, ...]
    issues: tuple[str, ...] = ()

    def fact(self, predicate: Predicate) -> _Fact:
        return next(f for f in self.facts if f.predicate == predicate)

    def put(self, fact: _Fact) -> _State:
        return replace(self, facts=tuple(fact if f.predicate == fact.predicate else f for f in self.facts))

    def forget(self, reason: str, *, taint: bool = False) -> _State:
        return _State(tuple(replace(f, value=Truth.UNKNOWN, reasons=(reason,)) for f in self.facts),
                      tuple(sorted(set(self.issues + ((reason,) if taint else ())))))


def _opposite(value: Truth) -> Truth:
    return Truth.FALSE if value is Truth.TRUE else Truth.TRUE


def _restrict(state: _State, predicate: Predicate, value: Truth, evidence: Evidence) -> _State | None:
    fact = state.fact(predicate)
    if not state.issues and fact.value is not Truth.UNKNOWN and fact.value is not value:
        return None  # Infeasible branch, not permission to overwrite a contradiction.
    return state.put(_Fact(predicate, value, fact.evidence + (evidence,)))


def _join(states: list[_State], charge: Callable[[], None]) -> _State:
    """Only unanimous, identical facts survive function exits."""
    facts = []
    # All states share the same ordered predicate vector. Align it directly
    # instead of repeatedly searching each state's vector (quadratic in facts).
    for incoming in zip(*(s.facts for s in states)):
        for _ in incoming:
            charge()
        first = incoming[0]
        same = all(f.value is first.value for f in incoming)
        evidence = tuple(dict.fromkeys(e for f in incoming for e in f.evidence))
        reasons = tuple(sorted({r for f in incoming for r in f.reasons}))
        facts.append(_Fact(first.predicate, first.value if same else Truth.UNKNOWN, evidence,
                           reasons if same else reasons + ("function exits disagree",)))
    return _State(tuple(facts), tuple(sorted({i for s in states for i in s.issues})))


class _BudgetExceeded(Exception):
    def __init__(self, state: _State):
        self.state = state


class _Analyzer:
    def __init__(self, graph: dict, policies: tuple[GuardPolicy, ...], model: Model | None,
                 entries: tuple[EntryFact, ...], max_depth: int, max_work: int):
        self.graph, self.policies, self.model = graph, policies, model
        self.max_depth, self.max_work, self.work = max_depth, max_work, 0
        self.models = {f.function: f for f in model.functions} if model is not None else {}
        self.guards = {(g.function, g.event_index): g for g in model.guards} if model is not None else {}
        self.dominance = {(d.policy, d.access_index): d for d in model.dominance} if model is not None else {}
        predicates = {p.predicate for p in policies} | {g.predicate for g in self.guards.values()}
        predicates.update(e.predicate for e in entries)
        baseline = _State(tuple(_Fact(p) for p in sorted(predicates)))
        self.initial: dict[str, _State] = {}
        for root in sorted(set(graph["roots"])):
            state = baseline  # Safe to share: every update returns a new frozen state.
            for entry in entries:
                if entry.root == root:
                    ref = entry.reference
                    state = state.put(_Fact(entry.predicate, entry.value,
                        (Evidence(ref.symbol, "explicit entry precondition (not a runtime observation)",
                                  (root,), ref.file, ref.line, ref.end_line),)))
            self.initial[root] = state
        self.accesses: list[AccessAssessment] = []
        self.gaps: list[AnalysisGap] = []
        self.assessed: set[GuardPolicy] = set()

    def spend(self, state: _State) -> None:
        if self.work >= self.max_work:
            raise _BudgetExceeded(state)
        self.work += 1

    def gap(self, root: str, path: tuple[str, ...], reason: str) -> None:
        value = AnalysisGap(root, path, path[-1], reason)
        if value not in self.gaps:
            self.gaps.append(value)

    def uncertain(self, root: str, path: tuple[str, ...], state: _State, reason: str) -> _State:
        self.gap(root, path, reason)
        return state.forget(reason, taint=True)

    def prove_dominance(self, proof: DominanceEvidence, state: _State) -> tuple[Truth, str]:
        """All-path validation through a reviewed DAG; never infer CFG from order.

        This proves only a local conditional property: if this exact source
        access is reached, its guard passed and its predicate/bindings persisted.
        It does not repair the invocation state or certify unvisited functions.
        """
        self.spend(state)
        policy = proof.policy
        fm = self.models.get(policy.function)
        if self.model is None or not self.model.bindings_verified or fm is None or not fm.complete_events:
            return Truth.UNKNOWN, "dominance lacks verified bindings or complete function events"
        if any(reason in state.issues for reason in ("recursive call cycle", "maximum call depth reached",
                                                     "unconfirmed direct call or indirect call")):
            return Truth.UNKNOWN, "dominance cannot discharge recursive/depth/indirect traversal gaps"
        if self.graph.get("illustrative", False) and not self.model.synthetic:
            return Truth.UNKNOWN, "illustrative graph cannot establish source dominance"
        if not self.model.synthetic and self.model.config_digest is None and not proof.configuration_independent:
            return Truth.UNKNOWN, "dominance lacks build provenance or reviewed configuration-independent scope"
        node = self.graph["nodes"][policy.function]
        events = node["events"]
        count = len(events)
        successors: list[list[ControlEdge]] = [[] for _ in events]
        incoming_count = [0] * count
        for edge in proof.edges:
            self.spend(state)
            successors[edge.origin].append(edge)
            if edge.target is not None:
                incoming_count[edge.target] += 1
        if incoming_count[proof.entry_index]:
            return Truth.UNKNOWN, "reviewed CFG entry has an incoming edge"
        for index, event in enumerate(events):
            self.spend(state)
            outgoing = successors[index]
            if event["kind"] == "guard":
                if len(outgoing) != 2 or {e.outcome for e in outgoing} != {Truth.TRUE, Truth.FALSE}:
                    return Truth.UNKNOWN, "reviewed CFG does not cover both guard outcomes"
            elif len(outgoing) != 1 or outgoing[0].outcome is not Truth.UNKNOWN:
                return Truth.UNKNOWN, "reviewed CFG lacks an explicit ordinary-event continuation/exit"
        # Reject cycles, including ones outside the candidate's apparent prefix.
        # They may invalidate a predicate before a later visit to the same write.
        ready = [i for i, degree in enumerate(incoming_count) if degree == 0]
        order = []
        while ready:
            self.spend(state)
            index = heappop(ready)
            order.append(index)
            for edge in successors[index]:
                self.spend(state)
                if edge.target is not None:
                    incoming_count[edge.target] -= 1
                    if incoming_count[edge.target] == 0:
                        heappush(ready, edge.target)
        if len(order) != count:
            return Truth.UNKNOWN, "cyclic dominance CFG needs an unsupported fixed point"
        # Check metadata independently of the supplied CFG. A reviewed diagram
        # cannot silently erase unsequenced calls/writes from the actual input.
        call_sites: dict[str, set[int | None]] = {}
        written = set()
        for event in events:
            self.spend(state)
            if event["kind"] == "call":
                call_sites.setdefault(event.get("target", ""), set()).add(event.get("line"))
            if event["kind"] in ("write", "atomic"):
                written.add(event.get("field"))
        for edge in node["callees"]:
            self.spend(state)
            locations = call_sites.get(edge["target"], set())
            if not locations or ("line" in edge and None not in locations and edge["line"] not in locations):
                return Truth.UNKNOWN, "dominance input contains an unsequenced callee"
        for field in node.get("writes", []):
            self.spend(state)
            if field not in written:
                return Truth.UNKNOWN, "dominance input contains an unsequenced write"
        preserved = {p.event_index for p in proof.preserves}
        guard = self.guards[(policy.function, proof.guard_index)]
        # UNKNOWN means the successful-check token is absent on at least one
        # reaching path, not that the actual predicate is false.
        reaching: dict[int, list[Truth]] = {proof.entry_index: [Truth.UNKNOWN]}
        for index in order:
            self.spend(state)
            if index not in reaching:
                continue
            values = reaching[index]
            for _ in values:
                self.spend(state)
            value = Truth.TRUE if all(v is Truth.TRUE for v in values) else Truth.UNKNOWN
            if index == proof.access_index:
                return value, ("all reviewed entry-to-access paths pass the guard with preserved predicate/object identities"
                               if value is Truth.TRUE else
                               "a reviewed path bypasses the successful guard or lacks predicate/object preservation")
            if index != proof.guard_index and index in preserved and events[index]["kind"] == "call":
                event = events[index]
                matches = []
                for edge in node["callees"]:
                    self.spend(state)
                    if (edge["target"] == event.get("target") and
                            ("line" not in edge or "line" not in event or edge["line"] == event["line"])):
                        matches.append(edge)
                if (len(matches) != 1 or matches[0]["kind"] != "direct"
                        or event.get("target") not in self.graph["nodes"]):
                    return Truth.UNKNOWN, "dominance preservation crosses an unconfirmed/indirect call"
            for edge in successors[index]:
                self.spend(state)
                if edge.target is None:
                    continue
                if index == proof.guard_index:
                    tested = (guard.condition_true_means if edge.outcome is Truth.TRUE else
                              _opposite(guard.condition_true_means))
                    outgoing = Truth.TRUE if tested is Truth.TRUE else Truth.UNKNOWN
                else:
                    outgoing = value if index in preserved else Truth.UNKNOWN
                reaching.setdefault(edge.target, []).append(outgoing)
        return Truth.UNKNOWN, "access is unreachable in the reviewed CFG; no observed access established"

    def assess(self, root: str, path: tuple[str, ...], policy: GuardPolicy, state: _State,
               index: int | None, event: dict) -> None:
        node = self.graph["nodes"].get(path[-1], {})
        fact = state.fact(policy.predicate)
        issues = tuple(sorted(set(state.issues + fact.reasons)))
        observed = Truth.UNKNOWN if state.issues else fact.value
        if issues:
            assessment = Assessment.UNKNOWN
        elif observed is Truth.TRUE:
            assessment = Assessment.ESTABLISHED
        elif observed is Truth.FALSE:
            assessment = Assessment.FALSE
        else:
            assessment = Assessment.MISSING
        explanations = {
            Assessment.ESTABLISHED: "Predicate established before access under the supplied model.",
            Assessment.FALSE: "Predicate false at access under the supplied model; not a kernel counterexample.",
            Assessment.MISSING: "Complete modeled path has no established check/precondition; actual predicate value unknown.",
            Assessment.UNKNOWN: "Insufficient evidence to establish predicate or check coverage.",
        }
        evidence, explanation, basis = fact.evidence, explanations[assessment], "ordered_events"
        proof = self.dominance.get((policy, index))
        if proof is not None:
            value, reason = self.prove_dominance(proof, state)
            basis = "reviewed_source_cfg"
            refs = (proof.reference, self.guards[(policy.function, proof.guard_index)].reference,
                    *proof.stability_references)
            evidence = tuple(Evidence(ref.symbol, "reviewed local dominance: " + proof.rationale,
                                      path, ref.file, ref.line, ref.end_line) for ref in dict.fromkeys(refs))
            observed = value
            if value is Truth.TRUE:
                assessment, issues = Assessment.ESTABLISHED, ()
                explanation = ("Local source-CFG dominance established at this possibly reached access; "
                               "caller/whole-root coverage is not certified. " + reason)
            else:
                assessment, issues = Assessment.UNKNOWN, (reason,)
                explanation = "Reviewed dominance evidence is insufficient: " + reason
                self.gap(root, path, reason)
        line = event.get("line", policy.access_line if index is None else None)
        self.accesses.append(AccessAssessment(root, path, path[-1], node.get("file"),
            line, index, policy.field, policy.rule_id, policy.source,
            policy.reference, policy.predicate,
            observed, assessment, explanation, evidence, issues,
            policy.access_kind, policy.access_object, basis))
        self.assessed.add(policy)

    def report_unassessed(self) -> None:
        """Coverage rows describe configured obligations, never invented paths."""
        for policy in self.policies:
            if policy in self.assessed:
                continue
            reason = (f"Configured obligation {policy.rule_id} for {policy.function}:{policy.access_line} "
                      "was not reached or assessed; no access path or successful coverage established.")
            path = (policy.root,)
            self.gap(policy.root, path, reason)
            node = self.graph["nodes"][policy.function]
            self.accesses.append(AccessAssessment(
                policy.root, path, policy.function, node.get("file"), policy.access_line, None,
                policy.field, policy.rule_id, policy.source, policy.reference, policy.predicate,
                Truth.UNKNOWN, Assessment.UNKNOWN, reason, (), (reason,), policy.access_kind,
                policy.access_object, "unassessed_obligation",
            ))

    def cut(self, root: str, path: tuple[str, ...], state: _State, reason: str) -> _State:
        self.gap(root, path, reason)
        state = state.forget(reason, taint=True)
        # One explicit unknown obligation per policy at a cut, without traversing
        # omitted events or pretending an actual access was observed there.
        for p in self.policies:
            if p.root == root and p.function == path[-1]:
                self.assess(root, path, p, state, None, {})
        return state

    def visit(self, root: str, path: tuple[str, ...], state: _State) -> _State:
        try:
            self.spend(state)
            if len(path) - 1 > self.max_depth:
                return self.cut(root, path, state, "maximum call depth reached")
            if path[-1] in path[:-1]:
                return self.cut(root, path, state, "recursive call cycle")
            node = self.graph["nodes"].get(path[-1])
            if node is None or node["kind"] in ("external", "boundary"):
                return self.cut(root, path, state, "missing or opaque function")
            if "events" not in node:
                return self.cut(root, path, state, "missing ordered events")
            return self.body(root, path, state, node)
        except _BudgetExceeded as exc:
            return self.cut(root, path, exc.state, "global work budget exhausted")

    def body(self, root: str, path: tuple[str, ...], state: _State, node: dict) -> _State:
        function = path[-1]
        fm = self.models.get(function)
        if fm is None or not fm.complete_events or not fm.linear_except_guards:
            state = self.uncertain(root, path, state, "unverified event completeness or control flow")
        if self.model is None or not self.model.bindings_verified:
            state = self.uncertain(root, path, state, "unverified object/argument bindings and predicate stability")
        if self.graph.get("illustrative", False) and (self.model is None or not self.model.synthetic):
            state = self.uncertain(root, path, state, "illustrative graph is not a verified kernel trace")
        if self.model is not None and not self.model.synthetic and self.model.config_digest is None:
            state = self.uncertain(root, path, state, "kernel configuration provenance missing")
        events = node["events"]
        called: dict[str, set[int | None]] = {}
        edges: dict[str, list[dict]] = {}
        written = set()
        access_sites = set()
        for event in events:
            self.spend(state)
            if event["kind"] == "call":
                called.setdefault(event.get("target", ""), set()).add(event.get("line"))
            if event["kind"] in ("write", "atomic"):
                written.add(event.get("field"))
                access_sites.add((event["kind"], event.get("field"), event.get("line")))
        for edge in sorted(node["callees"], key=lambda e: (e["target"], e["kind"], e.get("line", 0))):
            self.spend(state)
            edges.setdefault(edge["target"], []).append(edge)
            sites = called.get(edge["target"], set())
            if not sites or ("line" in edge and None not in sites and edge["line"] not in sites):
                state = state.forget("unsequenced callee metadata", taint=True)
                self.gap(root, path, "unsequenced callee metadata: " + edge["target"])
        for field in sorted(set(node.get("writes", []))):
            self.spend(state)
            if field not in written:
                state = state.forget("write metadata absent from ordered events", taint=True)
                self.gap(root, path, "unsequenced write metadata: " + field)
                for p in self.policies:
                    if p.root == root and p.function == function and p.field == field:
                        self.assess(root, path, p, state, None, {})
        for p in self.policies:
            if p.root == root and p.function == function and p.access_line is not None:
                self.spend(state)
                if ((p.access_kind, p.field, p.access_line) not in access_sites
                        and (p.access_kind, p.field, None) not in access_sites
                        and (p.access_kind, None, p.access_line) not in access_sites
                        and (p.access_kind, None, None) not in access_sites):
                    reason = "policy access site absent from ordered events"
                    state = state.forget(reason, taint=True)
                    self.gap(root, path, reason)
                    self.assess(root, path, p, state, None, {})
        exits: list[_State] = []
        for index, event in enumerate(events):
            self.spend(state)
            kind = event["kind"]
            if kind != "guard" and "cond" in event:
                state = self.uncertain(root, path, state, "conditional event lacks branch structure")
            if kind == "guard":
                guard = self.guards.get((function, index))
                if guard is None:
                    state = self.uncertain(root, path, state, "guard lacks verified polarity/branch semantics")
                    continue
                trace = Evidence(function, "reviewed guard: " + guard.condition, path,
                                 guard.reference.file, event.get("line", guard.reference.line),
                                 guard.reference.end_line)
                taken_value = guard.condition_true_means
                if guard.branch_when is BranchWhen.CONDITION_FALSE:
                    taken_value = _opposite(taken_value)
                taken = _restrict(state, guard.predicate, taken_value, trace)
                continuing = _restrict(state, guard.predicate, _opposite(taken_value), trace)
                if not guard.exits_function:
                    # No CFG for a nonterminating branch or its merge/effects.
                    state = self.uncertain(root, path, state, "nonterminating guard branch has unknown effects/merge")
                    continue
                if taken is not None:
                    exits.append(taken.forget("early-return branch may have predicate side effects"))
                if continuing is None:
                    break
                state = continuing
            elif kind == "call":
                target = event.get("target")
                matches = []
                for edge in edges.get(target, []):
                    self.spend(state)
                    if "line" not in edge or "line" not in event or edge["line"] == event["line"]:
                        matches.append(edge)
                if not target or len(matches) != 1 or matches[0]["kind"] != "direct":
                    state = state.forget("unconfirmed direct call or indirect call", taint=True)
                    self.gap(root, path, "unconfirmed direct call or indirect call: " + str(target))
                else:
                    state = self.visit(root, path + (target,), state)
            elif kind in ("write", "atomic"):
                if "field" not in event:
                    state = self.uncertain(root, path, state, "memory event lacks a field identity")
                    for p in self.policies:
                        if (p.root == root and p.function == function and p.access_kind == kind
                                and (p.access_line is None or "line" not in event or p.access_line == event["line"])):
                            self.assess(root, path, p, state, None, event)
                for p in self.policies:
                    if (p.root == root and p.function == function and p.field == event.get("field")
                            and p.access_kind == kind
                            and (p.access_line is None or "line" not in event or p.access_line == event["line"])):
                        access_state = state
                        if p.access_line is not None and "line" not in event:
                            access_state = state.forget("access source location unresolved", taint=True)
                        self.assess(root, path, p, access_state, index, event)
                # May change CPU/DSQ arguments, affinity, ownership, or dependent
                # state. No mutation/alias analysis exists to justify retention.
                state = state.forget("predicate stability invalidated by memory access")
            elif kind in ("error", "warn"):
                state = self.uncertain(root, path, state, "error/warn is not a proven terminator or pure operation")
            # lock/unlock/lockdep assertions establish no argument predicates.
        else:
            exits.append(state)
        return _join(exits, lambda: self.spend(exits[-1]))


def analyze(callgraph: dict[str, Any], policies: tuple[GuardPolicy, ...], *,
            model: Model | None = None, entry_facts: tuple[EntryFact, ...] = (),
            max_depth: int = 32, max_work: int = 10_000) -> AnalysisResult:
    """Analyze modeled direct-call paths; missing evidence stays UNKNOWN.

    No automatic catalog loading, C2 facts, C3 dependencies or registration.
    A version, commit or graph fingerprint mismatch is an explicit error.
    """
    validate("callgraph", callgraph)
    policies = _tuple(policies, GuardPolicy, "policies")
    entries = _tuple(entry_facts, EntryFact, "entry facts")
    _integer(max_depth, "maximum depth")
    if max_depth > 128:
        raise ValueError("maximum depth must be <= 128 (Python recursion safety)")
    _integer(max_work, "maximum work", 1)
    roots = set(callgraph["roots"])
    if roots - callgraph["nodes"].keys():
        raise ValueError("callgraph roots missing from nodes")
    if any(p.root not in roots for p in policies):
        raise ValueError("policy root is not a callgraph root")
    if any(p.function not in callgraph["nodes"] for p in policies):
        raise ValueError("policy function is not a callgraph node")
    if len({(p.rule_id, p.root, p.function, p.field, p.access_kind, p.access_line, p.access_object, p.predicate)
            for p in policies}) != len(policies):
        raise ValueError("duplicate guard policy")
    if any(e.root not in roots for e in entries):
        raise ValueError("entry fact root is not a callgraph root")
    if len({(e.root, e.predicate) for e in entries}) != len(entries):
        raise ValueError("duplicate/conflicting entry facts")
    if model is not None and not isinstance(model, Model):
        raise TypeError("model must be a Model")
    for p in policies:
        if p.source.version != callgraph["kernel_version"]:
            raise ValueError("kernel source version mismatch between policy and graph")
        if model is not None and p.source != model.source:
            raise ValueError("kernel source version/commit mismatch between policy and model")
        if model is not None and not model.synthetic and p.access_line is None:
            raise ValueError("non-synthetic policy requires an exact access line")
    if model is not None:
        if model.source.version != callgraph["kernel_version"]:
            raise ValueError("kernel source version mismatch between model and graph")
        if model.graph_digest != graph_digest(callgraph):
            raise ValueError("model graph fingerprint mismatch")
        for fm in model.functions:
            node = callgraph["nodes"].get(fm.function)
            if node is None or node.get("file") != fm.reference.file:
                raise ValueError("function model does not match graph source file")
            if any("line" in e and not fm.reference.line <= e["line"] <= fm.reference.end_line
                   for e in node.get("events", [])):
                raise ValueError("event outside function source range")
        for guard in model.guards:
            node = callgraph["nodes"].get(guard.function, {})
            events = node.get("events", [])
            if guard.event_index >= len(events):
                raise ValueError("guard annotation event missing")
            event = events[guard.event_index]
            if (event["kind"] != "guard" or event.get("cond") != guard.condition
                    or event.get("action") != guard.action or node.get("file") != guard.reference.file
                    or ("line" in event and not guard.reference.line <= event["line"] <= guard.reference.end_line)):
                raise ValueError("guard annotation does not match exact event/source")
        guards = {(g.function, g.event_index): g for g in model.guards}
        functions = {f.function: f for f in model.functions}
        for proof in model.dominance:
            p = proof.policy
            if proof.graph_digest != model.graph_digest:
                raise ValueError("dominance graph fingerprint mismatch")
            if p not in policies:
                raise ValueError("dominance evidence does not match a configured policy")
            node = callgraph["nodes"][p.function]
            events = node.get("events", [])
            if node["kind"] in ("boundary", "external") or proof.entry_index != 0:
                raise ValueError("dominance requires a defined function and its event-zero entry")
            if max(proof.guard_index, proof.access_index) >= len(events):
                raise ValueError("dominance event missing")
            guard = guards.get((p.function, proof.guard_index))
            if guard is None or guard.predicate != p.predicate:
                raise ValueError("dominance guard does not match the exact policy predicate/objects")
            access = events[proof.access_index]
            if (access["kind"] != p.access_kind or access.get("field") != p.field
                    or access.get("line") != p.access_line):
                raise ValueError("dominance access does not match the exact policy site/kind")
            fm = functions.get(p.function)
            if (node.get("file") != proof.reference.file
                    or (fm is not None and fm.reference != proof.reference)
                    or any("line" not in e or not proof.reference.line <= e["line"] <= proof.reference.end_line
                           for e in events)):
                raise ValueError("dominance function/event source range mismatch")
            for edge in proof.edges:
                if edge.origin >= len(events) or (edge.target is not None and edge.target >= len(events)):
                    raise ValueError("dominance CFG edge references a missing event")
            for preservation in proof.preserves:
                if preservation.event_index >= len(events):
                    raise ValueError("preservation event missing")
                ref = preservation.reference
                event = events[preservation.event_index]
                if (ref.symbol != p.function or ref.file != node.get("file")
                        or not ref.line <= event["line"] <= ref.end_line):
                    raise ValueError("preservation evidence source location mismatch")
    # Snapshot inputs; function invocations have copied immutable abstract states.
    graph = json.loads(json.dumps(callgraph, allow_nan=False))
    ordered = tuple(sorted(policies, key=lambda p: (p.root, p.function, p.field, p.rule_id,
                                                   p.access_kind, p.access_line or 0, p.predicate,
                                                   p.access_object or "")))
    engine = _Analyzer(graph, ordered, model, entries, max_depth, max_work)
    for root in sorted(roots):
        engine.visit(root, (root,), engine.initial[root])
    engine.report_unassessed()
    return AnalysisResult(tuple(engine.accesses), tuple(engine.gaps), engine.work,
                          model.source if model is not None else None,
                          model.synthetic if model is not None else False,
                          graph_digest(graph), model.config_digest if model is not None else None,
                          model.dominance if model is not None else ())
