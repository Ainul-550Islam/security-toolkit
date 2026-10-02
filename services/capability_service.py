"""Reports what this deployment can actually do.

Purpose: a single honest answer to "what is available here?" that the API,
the CLI and operators can trust. A capability appears as ``available`` only
when a real implementation is registered and healthy. Declared-but-unbuilt
native engines appear as ``declared`` with a reason, so the report never
overstates the system.
"""

from __future__ import annotations

from typing import Any

from config import feature_flags
from core.constants import LANG_CPP, LANG_PYTHON, LANG_RUST, LANG_TYPESCRIPT
from core.runtime import current_environment
from core.version import API_VERSION, APP_NAME, SCHEMA_VERSION, VERSION
from services.engine_registry import EngineRegistry

# What each language layer is responsible for. Mirrors
# docs/LANGUAGE_BOUNDARIES.md; kept here so the API can serve it.
LANGUAGE_ROLES: dict[str, str] = {
    LANG_PYTHON: "orchestration, policy, persistence, reporting and API surface",
    LANG_RUST: "memory-safe, CPU-bound primitives (hashing, pattern matching)",
    LANG_CPP: "low-level buffer inspection where an existing C/C++ library is required",
    LANG_TYPESCRIPT: "web user interface only; no security decisions client-side",
}


class CapabilityService:
    """Assembles the capability and metadata view."""

    def __init__(self, registry: EngineRegistry | None = None) -> None:
        self._registry = registry

    def engine_capabilities(self) -> dict[str, Any]:
        """Capabilities backed by a registered engine."""
        if self._registry is None:
            return {"available": {}, "declared": [], "engine_count": 0}
        available = self._registry.capabilities()
        declared: list[dict[str, Any]] = []
        for status in self._registry.all_status():
            if status.available:
                continue
            declared.append(
                {
                    "engine": status.descriptor.name,
                    "language": status.descriptor.language,
                    "capabilities": list(status.descriptor.capabilities),
                    "status": status.health.status,
                    "reason": status.health.detail or "unavailable",
                }
            )
        return {
            "available": available,
            "declared": declared,
            "engine_count": len(self._registry.names()),
        }

    def metadata(self) -> dict[str, Any]:
        """Non-sensitive service metadata for ``GET /api/v1/metadata``."""
        return {
            "service": APP_NAME,
            "version": VERSION,
            "api_version": API_VERSION,
            "schema_version": SCHEMA_VERSION,
            "environment": current_environment(),
            "language_roles": dict(LANGUAGE_ROLES),
            "features": feature_flags.all_flags(),
            "engines": self.engine_capabilities(),
        }

    def summary(self) -> dict[str, Any]:
        """Compact human-facing summary."""
        caps = self.engine_capabilities()
        return {
            "service": APP_NAME,
            "version": VERSION,
            "available_capabilities": sorted(caps["available"]),
            "unavailable_engines": [d["engine"] for d in caps["declared"]],
        }


__all__ = ["CapabilityService", "LANGUAGE_ROLES"]
