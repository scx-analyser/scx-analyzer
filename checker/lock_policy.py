"""Explicit, function-scoped protection policies; no kernel policies installed."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


def require_name(value: str, label: str) -> None:
    if (not isinstance(value, str) or not value or value.strip() != value
            or any(char.isspace() or ord(char) < 32 for char in value)
            or any(char in value for char in "*?") or value.lower() == "unknown"):
        raise ValueError(f"{label} must be an explicit nonempty name without whitespace or wildcards")


@dataclass(frozen=True, order=True)
class LockIdentity:
    """Opaque identity of one lock object, supplied by the policy/bindings author."""
    name: str

    def __post_init__(self) -> None:
        require_name(self.name, "lock identity")


class AccessKind(StrEnum):
    WRITE = "write"
    ATOMIC = "atomic"


@dataclass(frozen=True)
class ProtectionRule:
    function: str
    field: str
    lock: LockIdentity
    access: AccessKind = AccessKind.WRITE

    def __post_init__(self) -> None:
        require_name(self.function, "policy function")
        if not isinstance(self.field, str) or not re.fullmatch(
            r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_\[\]]*)+", self.field,
        ):
            raise ValueError("policy field must be an explicit contract field reference")
        if not isinstance(self.lock, LockIdentity):
            raise TypeError("policy lock must be a LockIdentity")
        if not isinstance(self.access, AccessKind):
            raise TypeError("policy access must be an AccessKind")


@dataclass(frozen=True)
class ProtectionPolicy:
    rules: tuple[ProtectionRule, ...]

    def __post_init__(self) -> None:
        rules = tuple(self.rules)
        if not all(isinstance(rule, ProtectionRule) for rule in rules):
            raise TypeError("policy rules must be ProtectionRule objects")
        if len(set(rules)) != len(rules):
            raise ValueError("duplicate protection rule")
        object.__setattr__(self, "rules", tuple(sorted(
            rules, key=lambda rule: (rule.function, rule.field, rule.access, rule.lock.name),
        )))

    def for_field(self, function: str, field: str) -> tuple[ProtectionRule, ...]:
        return tuple(rule for rule in self.rules if rule.function == function and rule.field == field)

    def for_access(self, function: str, field: str, access: AccessKind) -> tuple[ProtectionRule, ...]:
        return tuple(rule for rule in self.for_field(function, field) if rule.access == access)
