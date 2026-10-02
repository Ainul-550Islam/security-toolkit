"""Service metadata endpoints for ``/api/v1``.

Everything served here is deliberately non-sensitive: version, API version,
schema version, declared capabilities, feature-flag state and language
responsibilities. No hostnames, no paths, no configuration values, no
environment variables.
"""

from __future__ import annotations

from typing import Any

from config import feature_flags
from core.version import API_VERSION, APP_NAME, SCHEMA_VERSION, VERSION, version_info
from services.capability_service import CapabilityService

HTTP_OK = 200

# Keys that must never appear in a metadata response. Asserted by
# tests/test_security_baseline.py.
FORBIDDEN_KEYS: frozenset[str] = frozenset({
    "password", "secret", "token", "api_key", "private_key", "credential",
    "database_url", "dsn", "connection_string", "hostname", "path",
})


def metadata(service: CapabilityService) -> tuple[int, dict[str, Any]]:
    """Full service metadata."""
    return HTTP_OK, service.metadata()


def version_endpoint() -> tuple[int, dict[str, Any]]:
    """Version information only. Requires no service instance."""
    return HTTP_OK, version_info()


def capabilities(service: CapabilityService) -> tuple[int, dict[str, Any]]:
    """Engine capability view."""
    return HTTP_OK, service.engine_capabilities()


def features() -> tuple[int, dict[str, Any]]:
    """Resolved feature-flag state plus their documentation."""
    return HTTP_OK, {
        "service": APP_NAME,
        "api_version": API_VERSION,
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "flags": feature_flags.all_flags(),
        "declared": feature_flags.describe_flags(),
    }


ROUTES: dict[str, str] = {
    "/api/v1/metadata": "metadata",
    "/api/v1/version": "version_endpoint",
    "/api/v1/capabilities": "capabilities",
    "/api/v1/features": "features",
}

__all__ = ["metadata", "version_endpoint", "capabilities", "features",
           "ROUTES", "FORBIDDEN_KEYS", "HTTP_OK"]
