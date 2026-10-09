"""Liveness, readiness and dependency health.

Distinction that matters in an orchestrator
-------------------------------------------
* LIVENESS answers "is this process functioning?" A failed liveness probe
  gets the container killed, so it must not depend on external systems: a
  database outage restarting every pod turns a dependency blip into an
  outage.
* READINESS answers "should traffic be routed here?" It DOES consider
  required dependencies, and it fails closed: an unknown or unchecked
  dependency is not ready.

Disclosure rule: health output contains no credentials, no connection
strings, no hostnames and no file paths. Dependencies are named
symbolically ("database", "engine:rust_core") and failures are described by
category, never by raw exception text.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from core.clock import Clock, SystemClock, utcnow_iso
from core.constants import (
    HEALTH_DEGRADED,
    HEALTH_HEALTHY,
    HEALTH_SEVERITY_ORDER,
    HEALTH_UNAVAILABLE,
    HEALTH_UNKNOWN,
)
from core.runtime import runtime_info
from core.version import API_VERSION, APP_NAME, VERSION
from services.engine_registry import EngineRegistry

_SAFE_DEPENDENCY_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,79}$")


@dataclass(frozen=True, slots=True)
class DependencyHealth:
    """Health of one dependency."""

    name: str
    status: str = HEALTH_UNKNOWN
    required: bool = True
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "required": self.required,
            "detail": self.detail,
        }


@dataclass
class DependencyCheck:
    """A named probe.

    ``probe`` returns True when the dependency is usable. Any exception is
    treated as a failure and its TYPE only is recorded.
    """

    name: str
    probe: Callable[[], bool]
    required: bool = True
    description: str = ""


class HealthService:
    """Aggregates process, dependency and engine health."""

    def __init__(
        self,
        *,
        registry: EngineRegistry | None = None,
        clock: Clock | None = None,
        environment: str = "",
    ) -> None:
        self._registry = registry
        self._clock: Clock = clock or SystemClock()
        self._environment = environment
        self._checks: list[DependencyCheck] = []

    def register_dependency(
        self,
        name: str,
        probe: Callable[[], bool],
        *,
        required: bool = True,
        description: str = "",
    ) -> None:
        """Add a dependency probe."""
        self._checks.append(
            DependencyCheck(
                name=str(name), probe=probe, required=bool(required),
                description=str(description),
            )
        )

    # -- probes ---------------------------------------------------------
    def liveness(self) -> dict[str, Any]:
        """Process-only liveness. Never consults dependencies."""
        return {
            "status": HEALTH_HEALTHY,
            "service": APP_NAME,
            "version": VERSION,
            "api_version": API_VERSION,
            "checked_at": utcnow_iso(self._clock),
        }

    def check_dependencies(self) -> list[DependencyHealth]:
        """Run every registered probe."""
        results: list[DependencyHealth] = []
        for check in self._checks:
            try:
                ok = bool(check.probe())
            except Exception as exc:
                results.append(
                    DependencyHealth(
                        name=check.name,
                        status=HEALTH_UNAVAILABLE,
                        required=check.required,
                        detail=f"probe raised {type(exc).__name__}",
                    )
                )
                continue
            results.append(
                DependencyHealth(
                    name=check.name,
                    status=HEALTH_HEALTHY if ok else HEALTH_UNAVAILABLE,
                    required=check.required,
                    detail="" if ok else "probe reported unavailable",
                )
            )
        return results

    def readiness(self) -> dict[str, Any]:
        """Readiness verdict including dependencies and engines.

        Fail-closed: any required dependency that is not explicitly healthy
        makes the service NOT ready. Optional dependency failures downgrade
        to ``degraded`` (still serving, reduced function).
        """
        dependencies = self.check_dependencies()
        worst = HEALTH_HEALTHY
        ready = True
        for dep in dependencies:
            rank = HEALTH_SEVERITY_ORDER.get(dep.status, 9)
            if dep.required:
                if dep.status != HEALTH_HEALTHY:
                    ready = False
                    worst = HEALTH_UNAVAILABLE
            elif rank > HEALTH_SEVERITY_ORDER.get(worst, 0):
                worst = HEALTH_DEGRADED

        engines: dict[str, Any] = {}
        if self._registry is not None:
            engine_overall = self._registry.overall_status()
            engines = {
                "overall": engine_overall,
                "available": self._registry.available(),
                "count": len(self._registry.names()),
            }
            # Native engines are optional in PART 01: their absence degrades
            # capability but does not make the service unready.
            if engine_overall in (HEALTH_UNAVAILABLE, HEALTH_DEGRADED) and ready:
                worst = HEALTH_DEGRADED

        return {
            "status": worst if ready else HEALTH_UNAVAILABLE,
            "ready": ready,
            "service": APP_NAME,
            "version": VERSION,
            "checked_at": utcnow_iso(self._clock),
            "dependencies": [d.to_dict() for d in dependencies],
            "engines": engines,
        }

    def full_report(self) -> dict[str, Any]:
        """Combined report for operators. Contains no sensitive values."""
        readiness = self.readiness()
        info = runtime_info()
        if self._environment:
            info["environment"] = self._environment
        return {
            "service": APP_NAME,
            "version": VERSION,
            "api_version": API_VERSION,
            "status": readiness["status"],
            "ready": readiness["ready"],
            "checked_at": readiness["checked_at"],
            "runtime": info,
            "dependencies": readiness["dependencies"],
            "engines": readiness["engines"],
        }


__all__ = ["HealthService", "DependencyHealth", "DependencyCheck"]
