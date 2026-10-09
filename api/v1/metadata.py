"""Safe customer-facing metadata endpoints for ``/api/v1``.

The payloads describe the running software and capabilities that are actually
registered. They do not echo environment values, hostnames, paths, network
addresses, or secrets. The build identity is deliberately derived from the
versioned application and schema contract rather than an untrusted environment
variable.
"""

from __future__ import annotations

from typing import Any

from config import feature_flags
from core.version import API_VERSION, APP_NAME, SCHEMA_VERSION, VERSION, version_info
from services.capability_service import CapabilityService

HTTP_OK = 200

FORBIDDEN_KEYS: frozenset[str] = frozenset({
    "password", "secret", "token", "api_key", "private_key", "credential",
    "database_url", "dsn", "connection_string", "hostname", "path",
    "filesystem_path", "environment_variables", "host", "address",
})


def _validate_public_payload(value: Any) -> None:
    """Fail closed if a future metadata source adds a sensitive field name."""
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in FORBIDDEN_KEYS:
                raise RuntimeError("metadata contains a forbidden field")
            _validate_public_payload(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_public_payload(item)


def _build_identity() -> dict[str, str]:
    """Return stable build information without reading deployment secrets."""
    return {
        "application_version": VERSION,
        "api_contract": API_VERSION,
        "schema_contract": SCHEMA_VERSION,
    }


def metadata(service: CapabilityService) -> tuple[int, dict[str, Any]]:
    """Full, stable service metadata and capabilities."""
    body = dict(service.metadata())
    body["build_identity"] = _build_identity()
    body["supported_capabilities"] = service.engine_capabilities()
    _validate_public_payload(body)
    return HTTP_OK, body


def version_endpoint() -> tuple[int, dict[str, Any]]:
    """Version information only. Requires no service instance."""
    body = version_info()
    body["build_identity"] = _build_identity()
    _validate_public_payload(body)
    return HTTP_OK, body


def capabilities(service: CapabilityService) -> tuple[int, dict[str, Any]]:
    """Engine capability view backed only by registered engines."""
    body = service.engine_capabilities()
    _validate_public_payload(body)
    return HTTP_OK, body


def features() -> tuple[int, dict[str, Any]]:
    """Resolved feature-flag state plus non-sensitive flag documentation."""
    body = {
        "service": APP_NAME,
        "api_version": API_VERSION,
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "build_identity": _build_identity(),
        "flags": feature_flags.all_flags(),
        "declared": feature_flags.describe_flags(),
    }
    _validate_public_payload(body)
    return HTTP_OK, body


ROUTES: dict[str, str] = {
    "/api/v1/metadata": "metadata",
    "/api/v1/version": "version_endpoint",
    "/api/v1/capabilities": "capabilities",
    "/api/v1/features": "features",
}

__all__ = [
    "metadata",
    "version_endpoint",
    "capabilities",
    "features",
    "ROUTES",
    "FORBIDDEN_KEYS",
    "HTTP_OK",
]
