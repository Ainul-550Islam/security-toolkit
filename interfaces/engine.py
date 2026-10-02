"""Stable Python interface for security engines in any language.

An "engine" is a unit of security capability: a Python module, a Rust crate
reached over FFI or a subprocess, or a C++ library. The registry and the
health service care only about this contract, so a Rust engine and a Python
engine are interchangeable at the boundary.

Honesty requirement
-------------------
An engine that is not built, not installed or not loadable reports
``unavailable`` with a reason. It must never fabricate a success, and
:meth:`Engine.execute` on an unavailable engine must raise rather than return
a plausible-looking empty result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from core.constants import (
    EXECUTION_MODES,
    HEALTH_HEALTHY,
    HEALTH_STATES,
    HEALTH_UNAVAILABLE,
    LANGUAGES,
    MAX_NAME_LEN,
)
from core.errors import ValidationError


@dataclass(frozen=True, slots=True)
class EngineHealth:
    """Health verdict for one engine."""

    status: str = HEALTH_UNAVAILABLE
    detail: str = ""
    checked_at: str = ""

    def validate(self) -> EngineHealth:
        if self.status not in HEALTH_STATES:
            raise ValidationError(
                f"unknown health status: must be one of {', '.join(HEALTH_STATES)}"
            )
        return self

    @property
    def is_healthy(self) -> bool:
        return self.status == HEALTH_HEALTHY

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "detail": self.detail,
            "checked_at": self.checked_at,
        }


@dataclass(frozen=True, slots=True)
class EngineDescriptor:
    """Static, non-sensitive description of an engine.

    Contains no paths, no configuration and no credentials: it is safe to
    return from the capability and health endpoints.
    """

    name: str
    language: str
    version: str = "0.0.0"
    capabilities: tuple[str, ...] = ()
    execution_mode: str = "in_process"
    description: str = ""

    def validate(self) -> EngineDescriptor:
        if not self.name or len(self.name) > MAX_NAME_LEN:
            raise ValidationError("engine name must be 1..200 characters")
        if self.language not in LANGUAGES:
            raise ValidationError(
                f"unknown engine language: must be one of {', '.join(LANGUAGES)}"
            )
        if self.execution_mode not in EXECUTION_MODES:
            raise ValidationError(
                f"unknown execution mode: must be one of {', '.join(EXECUTION_MODES)}"
            )
        if len(self.capabilities) > 64:
            raise ValidationError("an engine may declare at most 64 capabilities")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "language": self.language,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "execution_mode": self.execution_mode,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class EngineStatus:
    """Descriptor plus current health and error state."""

    descriptor: EngineDescriptor
    health: EngineHealth
    error: str = ""

    @property
    def available(self) -> bool:
        return self.health.status != HEALTH_UNAVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.descriptor.to_dict(),
            "health": self.health.to_dict(),
            "error": self.error,
        }


@runtime_checkable
class Engine(Protocol):
    """Contract every engine implementation satisfies."""

    def describe(self) -> EngineDescriptor:
        """Static description. Must not perform I/O or raise."""
        ...

    def health(self) -> EngineHealth:
        """Current health. Must report failure, never raise."""
        ...

    def execute(self, operation: str, payload: dict[str, Any]) -> Any:
        """Run a declared capability.

        Raises :class:`core.errors.UnsupportedOperation` for an undeclared
        operation and :class:`core.errors.EngineUnavailable` when the engine
        is not loaded. Never returns a fabricated result.
        """
        ...


@dataclass(frozen=True, slots=True)
class UnavailableEngine:
    """Placeholder for an engine that is declared but not usable.

    This is the honest representation of "the Rust engine is not built": the
    capability is visible and explicitly unavailable, with a reason, instead
    of being silently absent or faked.
    """

    descriptor: EngineDescriptor
    reason: str = "engine not built or not installed"

    def describe(self) -> EngineDescriptor:
        return self.descriptor

    def health(self) -> EngineHealth:
        return EngineHealth(status=HEALTH_UNAVAILABLE, detail=self.reason)

    def execute(self, operation: str, payload: dict[str, Any]) -> Any:
        from core.errors import EngineUnavailable

        raise EngineUnavailable(
            f"engine {self.descriptor.name!r} is unavailable: {self.reason}",
            context={"engine": self.descriptor.name, "operation": operation},
        )


__all__ = [
    "Engine",
    "EngineDescriptor",
    "EngineHealth",
    "EngineStatus",
    "UnavailableEngine",
]
