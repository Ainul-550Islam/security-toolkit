#!/usr/bin/env python3
# ============================================================================
#  errors.py — typed error taxonomy for the Phase-1 platform foundation.
#  ---------------------------------------------------------------------------
#  Foundation code raises specific exception types so callers can distinguish
#  validation errors from authorization/scope errors, persistence errors,
#  network errors, configuration errors and internal failures. Errors never
#  carry secret material; messages are safe for users and logs after
#  .user_message().
# ============================================================================

from __future__ import annotations


class SecurityToolkitError(Exception):
    """Base class for all platform errors."""

    exit_code = 1

    def __init__(self, message: str, *, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.detail = detail  # internal detail (logged, never shown by default)

    def user_message(self) -> str:
        return self.message


class ValidationError(SecurityToolkitError):
    """Invalid input (bad name, bad asset value, bad transition, bad ID)."""

    exit_code = 2


class ScopeViolationError(SecurityToolkitError):
    """A target/asset/request is out of the authorized scope."""

    exit_code = 3


class PersistenceError(SecurityToolkitError):
    """Database/storage failure (missing table, constraint, I/O)."""

    exit_code = 4


class ConfigurationError(SecurityToolkitError):
    """Missing/invalid configuration (bad config file, missing db path)."""

    exit_code = 5


class NotFoundError(SecurityToolkitError):
    """Requested record does not exist."""

    exit_code = 6


class DuplicateError(SecurityToolkitError):
    """Uniqueness violation surfaced as a domain-level duplicate."""

    exit_code = 7


class LifecycleError(ValidationError):
    """Invalid state transition on a Scan or Finding."""

    exit_code = 2


class NetworkError(SecurityToolkitError):
    """Network-level failure for scanner integrations."""

    exit_code = 8


class ScannerError(SecurityToolkitError):
    """A scanner subprocess/module failed in a controlled way."""

    exit_code = 9


class WorkerStopped(SecurityToolkitError):
    """Internal control signal: the operator cancelled the job while a
    stage subprocess was in flight — checked at safe checkpoints only."""

    exit_code = 9


class AuthenticationError(SecurityToolkitError):
    """Generic authentication failure — deliberately never reveals whether a
    user/credential exists, is valid-but-disabled, or merely wrong."""

    exit_code = 10
    http_status = 401


class AuthorizationError(SecurityToolkitError):
    """Generic access-denied result. Fail-closed: any unknown user, role,
    permission, or ownership relationship resolves to this error.
    The message NEVER includes object ids or the missing permission."""

    exit_code = 11
    http_status = 403


class RateLimitedError(SecurityToolkitError):
    """Too many attempts within the configured window (bounded throttling)."""

    exit_code = 12
    http_status = 429

    def __init__(self, message: str = "Too many attempts", *,
                 retry_after: int = 0, detail: str = ""):
        super().__init__(message, detail=detail)
        self.retry_after = int(retry_after)
