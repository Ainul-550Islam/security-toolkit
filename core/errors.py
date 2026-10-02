"""Canonical exception hierarchy for the foundation layer.

Relationship to ``python/errors.py``
------------------------------------
``python/errors.py`` is the existing, well-tested exception hierarchy used by
the phase 1-13 security modules. It is NOT replaced, re-implemented or
imported here. This module serves the new foundation packages (``config/``,
``core/``, ``interfaces/``, ``services/``, ``api/``) which must be importable
without pulling in the entire legacy ``python/`` package.

Design rules
------------
* Every error carries a stable, machine-readable ``code``.
* ``user_message()`` is safe to return to a caller: it never includes
  configuration values, secrets or filesystem contents.
* Exceptions carry non-sensitive ``context`` for structured logging only.
"""

from __future__ import annotations

from typing import Any


class FoundationError(Exception):
    """Base class for every foundation-layer error.

    ``code`` is a stable identifier suitable for metrics and client-side
    branching. ``context`` holds non-sensitive diagnostic key/values; callers
    MUST NOT place secrets in it.
    """

    code: str = "foundation_error"
    exit_code: int = 1

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = str(message)
        if code:
            self.code = str(code)
        self.context: dict[str, Any] = dict(context or {})

    def user_message(self) -> str:
        """Message safe to show to an operator or API client."""
        return self.message

    def to_dict(self) -> dict[str, Any]:
        """Serializable form for structured logging and API error bodies."""
        return {
            "code": self.code,
            "message": self.user_message(),
            "context": self.context,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


class ConfigurationError(FoundationError):
    """Invalid, missing or unsafe configuration. Always fail-closed."""

    code = "configuration_error"
    exit_code = 78  # EX_CONFIG


class ValidationError(FoundationError):
    """Input failed validation against a closed contract."""

    code = "validation_error"
    exit_code = 2


class SecurityViolation(FoundationError):
    """An operation was refused because it would breach a security boundary.

    Examples: path traversal, escaping the workspace root, a secret appearing
    where secrets are forbidden.
    """

    code = "security_violation"
    exit_code = 77  # EX_NOPERM


class UnsupportedOperation(FoundationError):
    """A capability was requested that this build genuinely does not provide.

    Raised instead of returning a fake success. If the Rust or C++ engine is
    not built, the honest answer is "unavailable", never a stubbed result.
    """

    code = "unsupported_operation"
    exit_code = 69  # EX_UNAVAILABLE


class EngineError(FoundationError):
    """A native or Python engine failed to execute or report health."""

    code = "engine_error"
    exit_code = 70


class EngineUnavailable(EngineError):
    """The engine is not installed, not built, or failed to load."""

    code = "engine_unavailable"
    exit_code = 69


class SecretError(FoundationError):
    """A secret could not be resolved from its provider.

    The message never contains the secret name's value, only its identifier.
    """

    code = "secret_error"
    exit_code = 78


class SchemaError(FoundationError):
    """A payload did not conform to its canonical JSON schema."""

    code = "schema_error"
    exit_code = 65  # EX_DATAERR


__all__ = [
    "FoundationError",
    "ConfigurationError",
    "ValidationError",
    "SecurityViolation",
    "UnsupportedOperation",
    "EngineError",
    "EngineUnavailable",
    "SecretError",
    "SchemaError",
]
