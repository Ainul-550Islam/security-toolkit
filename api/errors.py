"""Stable, redacted HTTP error contracts for the public API.

Legacy domain exceptions are mapped by their trusted class names so the new
transport layer does not import the old ``python/`` package at module import
time. Public messages are constants: provider errors, SQL details, exception
strings, filesystem paths, and stack traces are never copied into responses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class FieldViolation:
    """Safe field-level validation detail; values supplied by clients are omitted."""

    field: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"field": self.field, "code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True)
class ApiProblem:
    """Machine-readable public error with a stable status and code."""

    status: int
    code: str
    message: str
    fields: tuple[FieldViolation, ...] = ()
    retry_after: int = 0

    def __post_init__(self) -> None:
        if self.status < 400 or self.status > 599:
            raise ValueError("API problem status must be an error status")
        if not self.code or len(self.code) > 80:
            raise ValueError("API problem code must be a bounded identifier")
        if len(self.message) > 240:
            raise ValueError("API problem message is too long")
        if self.retry_after < 0:
            raise ValueError("retry_after cannot be negative")

    def body(self, request_id: str) -> dict[str, Any]:
        error: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "request_id": request_id,
        }
        if self.fields:
            error["fields"] = [item.to_dict() for item in self.fields]
        return {"error": error}


class ApiException(Exception):
    """Exception deliberately carrying only a reviewed public problem."""

    def __init__(self, problem: ApiProblem):
        super().__init__(problem.code)
        self.problem = problem


_ERROR_MAP: dict[str, tuple[int, str, str]] = {
    "AuthenticationError": (401, "authentication_failed", "Authentication required or invalid"),
    "AuthenticationAdapterError": (401, "authentication_failed", "Authentication required or invalid"),
    "AuthorizationError": (403, "forbidden", "Forbidden"),
    "RateLimitedError": (429, "rate_limited", "Too many requests"),
    "NotFoundError": (404, "not_found", "Resource not found"),
    "DuplicateError": (409, "conflict", "The requested change conflicts with existing data"),
    "LifecycleError": (409, "invalid_state_transition", "The requested state change is not allowed"),
    "ScopeViolationError": (403, "scope_denied", "The requested operation is outside the authorized scope"),
    "ValidationError": (400, "validation_failed", "Request validation failed"),
    "ConfigurationError": (503, "service_not_configured", "A required service is not configured"),
    "PersistenceError": (503, "storage_unavailable", "The service could not complete the request"),
    "UnsupportedOperation": (501, "capability_unavailable", "This capability is not available"),
    "EngineUnavailable": (503, "engine_unavailable", "A required engine is not available"),
}


def problem_from_exception(exc: BaseException) -> ApiProblem:
    """Translate a known domain exception without disclosing its text.

    Unknown exceptions always map to a generic 500. The caller may log the
    exception class name, but must not log ``str(exc)`` or a traceback here.
    """
    if isinstance(exc, ApiException):
        return exc.problem
    if type(exc).__name__ == "TicketingError":
        ticketing_code = str(getattr(exc, "code", ""))
        ticketing_errors = {
            "not_configured": (503, "ticketing_not_configured", "Ticketing is not configured"),
            "credentials_unavailable": (503, "ticketing_not_configured", "Ticketing is not configured"),
            "integration_disabled": (409, "integration_disabled", "The ticketing integration is disabled"),
            "provider_not_supported": (501, "capability_unavailable", "This ticketing provider is not supported"),
            "invalid_configuration": (409, "ticketing_configuration_invalid", "The ticketing configuration is invalid"),
            "invalid_credentials": (503, "ticketing_credentials_invalid", "Ticketing credentials are unavailable or invalid"),
            "auth_failed": (502, "ticketing_provider_error", "The ticketing provider could not authorize the request"),
            "permission_denied": (502, "ticketing_provider_error", "The ticketing provider rejected the request"),
            "provider_unavailable": (502, "ticketing_provider_unavailable", "The ticketing provider is unavailable"),
            "rate_limited": (503, "ticketing_rate_limited", "The ticketing provider is rate limiting requests"),
            "provider_rejected": (502, "ticketing_provider_error", "The ticketing provider rejected the request"),
            "response_invalid": (502, "ticketing_provider_error", "The ticketing provider returned an invalid response"),
            "duplicate_external_reference": (409, "ticketing_reference_conflict", "The external issue reference is ambiguous"),
            "issue_not_found": (404, "not_found", "Resource not found"),
            "transition_unavailable": (409, "ticketing_transition_unavailable", "The external issue cannot be closed"),
            "scope_mismatch": (404, "not_found", "Resource not found"),
        }
        status, code, message = ticketing_errors.get(
            ticketing_code,
            (502, "ticketing_provider_error", "The ticketing provider could not complete the request"),
        )
        return ApiProblem(status, code, message)
    mapped = _ERROR_MAP.get(type(exc).__name__)
    if mapped is None:
        return ApiProblem(500, "internal_error", "The service could not complete the request")
    status, code, message = mapped
    retry_after = 0
    if status == 429:
        try:
            retry_after = max(0, min(3600, int(getattr(exc, "retry_after", 0))))
        except (TypeError, ValueError, OverflowError):
            retry_after = 0
    return ApiProblem(status, code, message, retry_after=retry_after)


def validation_problem(
    *,
    field: str,
    code: str = "invalid",
    message: str = "Invalid value",
) -> ApiProblem:
    """Create a safe single-field input error without reflecting its value."""
    if not field or len(field) > 96 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.[]-" for ch in field):
        field = "request"
    if not code or len(code) > 64 or not code.replace("_", "").isalnum():
        code = "invalid"
    if not message or len(message) > 160:
        message = "Invalid value"
    return ApiProblem(
        400,
        "validation_failed",
        "Request validation failed",
        fields=(FieldViolation(field, code, message),),
    )


__all__ = [
    "ApiException",
    "ApiProblem",
    "FieldViolation",
    "problem_from_exception",
    "validation_problem",
]
