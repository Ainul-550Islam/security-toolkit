"""Shared safe primitives for optional cloud-provider SDK adapters.

Cloud SDKs stay optional so a base install never silently implies provider
connectivity. Adapter failures expose only stable codes, not provider messages,
URLs, request bodies, credential material, or SDK exception text.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any


_ERROR_CODES = frozenset({
    "not_configured",
    "invalid_credentials",
    "permission_denied",
    "scope_mismatch",
    "rate_limited",
    "timeout",
    "resource_limit_exceeded",
    "unavailable",
    "inventory_failed",
})


class CloudAdapterError(Exception):
    """Provider-independent failure with a bounded, safe machine code."""

    def __init__(self, code: str) -> None:
        safe_code = code if code in _ERROR_CODES else "inventory_failed"
        self.code = safe_code
        super().__init__(safe_code)

    def __str__(self) -> str:
        return self.code


def deadline_expired(deadline: float) -> bool:
    """Return whether a monotonic absolute deadline has elapsed."""
    return time.monotonic() >= deadline


def require_time(deadline: float) -> None:
    """Fail with a stable timeout code before starting another SDK call."""
    if deadline_expired(deadline):
        raise CloudAdapterError("timeout")


def mapping_value(value: Any) -> dict[str, Any]:
    """Convert a provider SDK model to a shallow mapping without repr fallback."""
    if isinstance(value, Mapping):
        return dict(value)
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        converted = as_dict()
        if isinstance(converted, Mapping):
            return dict(converted)
    if hasattr(value, "__dict__"):
        converted = vars(value)
        if isinstance(converted, Mapping):
            return dict(converted)
    return {}


def provider_error_code(exc: BaseException) -> str:
    """Classify known SDK errors without embedding their untrusted text."""
    name = type(exc).__name__.lower()
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(exc, "code", None)
    status_text = str(status or "").lower()
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            status_text = str(error.get("Code", "") or "").lower()

    if any(token in name for token in (
        "credentialunavailable", "credentialerror", "invalidcredential",
        "authenticationerror", "unauthorized", "invalidtoken",
    )) or any(token in status_text for token in (
        "invalidclienttokenid", "signaturedoesnotmatch", "unrecognizedclient",
        "invalid_client", "invalidcredential", "authenticationfailed",
        "credentialunavailable", "unauthorized",
    )):
        return "invalid_credentials"
    if any(token in name for token in (
        "accessdenied", "forbidden", "authorizationfailed", "permissiondenied",
    )) or any(
        token in status_text for token in (
            "accessdenied", "access_denied", "forbidden", "authorizationfailed",
            "permissiondenied", "insufficientpermission",
        )
    ) or status == 403:
        return "permission_denied"
    if any(token in name for token in (
        "throttl", "ratelimit", "resourceexhausted",
    )) or any(token in status_text for token in (
        "throttl", "toomanyrequests", "rateexceeded", "resourceexhausted",
    )) or status == 429:
        return "rate_limited"
    if any(token in name for token in (
        "timeout", "deadlineexceeded", "connectiontimeout",
    )) or "timeout" in status_text or status == 408:
        return "timeout"
    if any(token in name for token in (
        "serviceunavailable", "endpointconnection", "connectionerror",
        "transporterror", "temporarilyunavailable",
    )) or status in (500, 502, 503, 504):
        return "unavailable"
    return "inventory_failed"


def translate_provider_error(exc: BaseException) -> CloudAdapterError:
    """Raise only a code-level cloud error, hiding provider exception details."""
    if isinstance(exc, CloudAdapterError):
        return exc
    return CloudAdapterError(provider_error_code(exc))


__all__ = [
    "CloudAdapterError",
    "deadline_expired",
    "mapping_value",
    "provider_error_code",
    "require_time",
    "translate_provider_error",
]
