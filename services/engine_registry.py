"""Registry of security engines across Python, Rust and C++.

Responsibilities
----------------
* Hold declared engines and their live status.
* Probe availability honestly: an engine that cannot be loaded is recorded as
  ``unavailable`` with a reason, never omitted and never faked.
* Route a capability request to an engine that actually declares it.

Non-responsibilities: building native code, loading shared libraries and
executing scans. Those belong to the engine implementations themselves.
"""

from __future__ import annotations

import threading
from typing import Any

from core.clock import Clock, SystemClock, utcnow_iso
from core.constants import (
    HEALTH_DEGRADED,
    HEALTH_HEALTHY,
    HEALTH_SEVERITY_ORDER,
    HEALTH_UNAVAILABLE,
    HEALTH_UNKNOWN,
    LANG_CPP,
    LANG_RUST,
    MODE_FFI,
)
from core.errors import EngineError, EngineUnavailable, UnsupportedOperation
from interfaces.engine import (
    Engine,
    EngineDescriptor,
    EngineHealth,
    EngineStatus,
    UnavailableEngine,
)

# Engines the project intends to ship. Declaring them here means the API can
# report "rust_core: unavailable (not built)" instead of pretending the
# capability does not exist.
DECLARED_NATIVE_ENGINES: tuple[EngineDescriptor, ...] = (
    EngineDescriptor(
        name="rust_core",
        language=LANG_RUST,
        version="0.1.0",
        capabilities=("hash_verify", "pattern_match"),
        execution_mode=MODE_FFI,
        description="Rust foundation crate (native/rust). Built separately.",
    ),
    EngineDescriptor(
        name="cpp_core",
        language=LANG_CPP,
        version="0.1.0",
        capabilities=("buffer_inspect",),
        execution_mode=MODE_FFI,
        description="C++ foundation library (native/cpp). Built separately.",
    ),
)


class EngineRegistry:
    """Thread-safe registry of engines.

    Registration is explicit; there is no auto-discovery by import scanning,
    because importing arbitrary modules to find engines is a code-execution
    surface.
    """

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock: Clock = clock or SystemClock()
        self._lock = threading.RLock()
        self._engines: dict[str, Engine] = {}

    # -- registration ---------------------------------------------------
    def register(self, eng: Engine, *, replace: bool = False) -> EngineDescriptor:
        """Register an engine. Duplicate names are rejected unless ``replace``."""
        descriptor = eng.describe().validate()
        with self._lock:
            if descriptor.name in self._engines and not replace:
                raise EngineError(
                    f"engine {descriptor.name!r} is already registered",
                    context={"engine": descriptor.name, "reason": "duplicate"},
                )
            self._engines[descriptor.name] = eng
        return descriptor

    def register_declared_native(self) -> list[EngineDescriptor]:
        """Register the declared native engines as unavailable placeholders.

        This is the honest default state: the Rust and C++ crates exist and
        build, but no FFI bridge is wired in PART 01, so they are surfaced as
        unavailable with that exact reason rather than reported as working.
        """
        registered: list[EngineDescriptor] = []
        for descriptor in DECLARED_NATIVE_ENGINES:
            placeholder = UnavailableEngine(
                descriptor=descriptor,
                reason="native binding not loaded (PART 01 ships the crate "
                       "and library only; no FFI bridge yet)",
            )
            registered.append(self.register(placeholder, replace=True))
        return registered

    def unregister(self, name: str) -> bool:
        with self._lock:
            return self._engines.pop(str(name), None) is not None

    # -- lookup ---------------------------------------------------------
    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._engines)

    def get(self, name: str) -> Engine:
        with self._lock:
            eng = self._engines.get(str(name))
        if eng is None:
            raise EngineUnavailable(
                f"engine {name!r} is not registered",
                context={"engine": str(name), "reason": "not_registered"},
            )
        return eng

    def status(self, name: str) -> EngineStatus:
        """Current status of one engine. Never raises for a failing engine."""
        eng = self.get(name)
        descriptor = eng.describe()
        try:
            health = eng.health().validate()
            error = ""
        except Exception as exc:
            # An engine whose own health check raises is not healthy; record
            # the type only so an exception message cannot leak internals.
            health = EngineHealth(
                status=HEALTH_UNAVAILABLE,
                detail="health check raised",
                checked_at=utcnow_iso(self._clock),
            )
            error = type(exc).__name__
        if not health.checked_at:
            health = EngineHealth(
                status=health.status,
                detail=health.detail,
                checked_at=utcnow_iso(self._clock),
            )
        return EngineStatus(descriptor=descriptor, health=health, error=error)

    def all_status(self) -> list[EngineStatus]:
        return [self.status(name) for name in self.names()]

    def available(self) -> list[str]:
        """Names of engines that are not unavailable."""
        return [s.descriptor.name for s in self.all_status() if s.available]

    def capabilities(self) -> dict[str, list[str]]:
        """Capability -> engines declaring it (available engines only)."""
        mapping: dict[str, list[str]] = {}
        for status in self.all_status():
            if not status.available:
                continue
            for capability in status.descriptor.capabilities:
                mapping.setdefault(capability, []).append(status.descriptor.name)
        return {k: sorted(v) for k, v in sorted(mapping.items())}

    def find_for_capability(self, capability: str) -> Engine:
        """Return a healthy engine declaring ``capability``.

        Prefers healthy over degraded; raises when none can serve it, rather
        than silently returning a degraded or unrelated engine.
        """
        candidates: list[tuple[int, str]] = []
        for status in self.all_status():
            if capability not in status.descriptor.capabilities:
                continue
            if not status.available:
                continue
            rank = HEALTH_SEVERITY_ORDER.get(status.health.status, 9)
            candidates.append((rank, status.descriptor.name))
        if not candidates:
            raise UnsupportedOperation(
                f"no available engine provides capability {capability!r}",
                context={"capability": str(capability), "reason": "no_engine"},
            )
        candidates.sort()
        return self.get(candidates[0][1])

    def execute(
        self, capability: str, operation: str, payload: dict[str, Any] | None = None
    ) -> Any:
        """Execute an operation on an engine providing ``capability``."""
        eng = self.find_for_capability(capability)
        return eng.execute(operation, dict(payload or {}))

    # -- aggregate ------------------------------------------------------
    def overall_status(self) -> str:
        """Aggregate engine health.

        An empty registry is ``unknown``, not ``healthy``: having checked
        nothing is not the same as everything being fine.
        """
        statuses = self.all_status()
        if not statuses:
            return HEALTH_UNKNOWN
        if all(s.health.status == HEALTH_HEALTHY for s in statuses):
            return HEALTH_HEALTHY
        if all(s.health.status == HEALTH_UNAVAILABLE for s in statuses):
            return HEALTH_UNAVAILABLE
        return HEALTH_DEGRADED

    def to_dict(self) -> dict[str, Any]:
        statuses = self.all_status()
        return {
            "overall": self.overall_status(),
            "engine_count": len(statuses),
            "available_count": sum(1 for s in statuses if s.available),
            "engines": [s.to_dict() for s in statuses],
            "capabilities": self.capabilities(),
        }


__all__ = ["EngineRegistry", "DECLARED_NATIVE_ENGINES"]
