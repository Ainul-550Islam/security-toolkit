"""Typed success/failure result for cross-language boundaries.

Native engines (Rust, C++) cannot raise Python exceptions across an FFI
boundary. Rust models fallibility as ``Result<T, E>`` and C++ returns status
codes; this type is the Python mirror so a single shape carries outcomes
across all three languages without inventing per-call conventions.

Use exceptions for programmer errors and truly exceptional conditions; use
``Result`` when failure is an expected, enumerable outcome (an engine being
unavailable, a probe reporting degraded, a parse rejecting input).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, NoReturn, TypeVar

from core.errors import FoundationError

T = TypeVar("T")
U = TypeVar("U")


@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):
    """A successful outcome carrying a value."""

    value: T

    @property
    def is_ok(self) -> bool:
        return True

    @property
    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T:
        return self.value

    def unwrap_or(self, default: T) -> T:
        return self.value

    def map(self, fn: Callable[[T], U]) -> Result[U]:
        return Ok(fn(self.value))

    def to_dict(self) -> dict[str, Any]:
        return {"ok": True, "value": self.value}


@dataclass(frozen=True, slots=True)
class Err:
    """A failed outcome carrying a stable code and a safe message."""

    code: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def is_ok(self) -> bool:
        return False

    @property
    def is_err(self) -> bool:
        return True

    def unwrap(self) -> NoReturn:
        raise FoundationError(self.message, code=self.code, context=self.context)

    def unwrap_or(self, default: T) -> T:
        return default

    def map(self, fn: Callable[[Any], Any]) -> Err:
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
                "context": self.context,
            },
        }

    @classmethod
    def from_exception(cls, exc: BaseException) -> Err:
        """Build an Err from an exception without leaking internals.

        For a FoundationError the declared code and safe message are used.
        For anything else only the exception TYPE is reported: an arbitrary
        exception's text may embed a path, a query or a credential.
        """
        if isinstance(exc, FoundationError):
            return cls(exc.code, exc.user_message(), dict(exc.context))
        return cls("internal_error", f"unexpected {type(exc).__name__}")


Result = Ok[T] | Err


__all__ = ["Ok", "Err", "Result"]
