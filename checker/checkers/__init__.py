"""Registry of semantic invariant checkers.

Future checkers for I1/I2/I3 are registered here. Keeping the registry
empty in C1 is intentional: a schema-valid empty finding list is not a proof.
"""
from typing import Any, Callable

Finding = dict[str, Any]
Checker = Callable[[dict[str, Any], dict[str, Any]], list[Finding]]
_REGISTRY: dict[str, Checker] = {}


def register(invariant_id: str, fn: Checker) -> None:
    """Register one checker. Refuse silent overwrites or duplicate claims."""
    if not isinstance(invariant_id, str) or not invariant_id or not callable(fn):
        raise ValueError("checker id must be a nonempty string and fn must be callable")
    if invariant_id in _REGISTRY:
        raise ValueError(f"duplicate checker for {invariant_id}")
    _REGISTRY[invariant_id] = fn


def registered() -> dict[str, Checker]:
    return dict(_REGISTRY)
