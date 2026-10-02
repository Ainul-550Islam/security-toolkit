"""Secure identifier generation and validation.

Rules
-----
* Random identifiers come from :mod:`secrets` (a CSPRNG), never
  :mod:`random`, which is a Mersenne Twister and is trivially predictable
  after observing a few outputs.
* Deterministic identifiers use UUIDv5 so the same logical input always maps
  to the same id. That is what makes re-processing idempotent instead of
  duplicating rows.
* Correlation ids are generated, never accepted verbatim from a remote
  caller: an attacker-chosen id could be used to forge or collide log
  entries. :func:`sanitize_correlation_id` bounds and filters inbound values.
"""

from __future__ import annotations

import re
import secrets
import uuid
from typing import Final

from core.errors import ValidationError

# UUIDv5 namespaces for the foundation layer. These are FIXED: changing one
# changes every derived identifier, so they must never be regenerated.
NS_FOUNDATION: Final[uuid.UUID] = uuid.UUID("6f4d0c2e-8a6a-5f3b-9d21-0b6c7a1e4f88")
NS_ENGINE: Final[uuid.UUID] = uuid.UUID("2c9a7b14-5e33-5a72-8f10-7d4e2b9c6a51")
NS_TRACE: Final[uuid.UUID] = uuid.UUID("b81e5f60-3d2a-5c48-91ab-4e7f0d5c3b29")

TOKEN_BYTES: Final[int] = 16          # 128 bits
MAX_CORRELATION_ID_LEN: Final[int] = 64

_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_CORRELATION_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9._:-]{1,64}\Z")


def new_id() -> str:
    """A random UUIDv4 string (CSPRNG-backed)."""
    return str(uuid.uuid4())


def new_token(n_bytes: int = TOKEN_BYTES) -> str:
    """A URL-safe random token.

    Used for correlation ids and non-secret handles. NOT a credential
    factory: real credentials belong to the secret provider.
    """
    if n_bytes < 16:
        raise ValidationError("token entropy must be at least 16 bytes")
    return secrets.token_urlsafe(int(n_bytes))


def new_correlation_id() -> str:
    """A fresh correlation id for tracing one request across components."""
    return f"cid-{secrets.token_hex(8)}"


def stable_id(namespace: uuid.UUID, name: str) -> str:
    """Deterministic UUIDv5 for ``name`` within ``namespace``.

    The same input always yields the same id, which is what makes retries and
    replays idempotent rather than duplicative.
    """
    if not isinstance(namespace, uuid.UUID):
        raise ValidationError("namespace must be a uuid.UUID")
    if not isinstance(name, str) or not name:
        raise ValidationError("stable_id requires a non-empty name")
    return str(uuid.uuid5(namespace, name))


def engine_id(language: str, name: str) -> str:
    """Deterministic identifier for a registered engine."""
    return stable_id(NS_ENGINE, f"{language}|{name}")


def is_uuid(value: str) -> bool:
    """True when ``value`` is a well-formed UUID string."""
    return isinstance(value, str) and bool(_UUID_RE.match(value))


def sanitize_correlation_id(value: str | None) -> str:
    """Return a safe correlation id derived from untrusted input.

    An inbound header is never trusted verbatim. If it is absent or does not
    match the strict allowlist (letters, digits, dot, underscore, colon,
    hyphen; bounded length) a NEW id is generated instead. This prevents log
    injection via newlines/control characters and forged correlation.
    """
    if not isinstance(value, str):
        return new_correlation_id()
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_CORRELATION_ID_LEN:
        return new_correlation_id()
    if not _CORRELATION_RE.match(candidate):
        return new_correlation_id()
    return candidate


def constant_time_equals(left: str, right: str) -> bool:
    """Timing-safe string comparison.

    Required whenever a secret, signature or token is compared: a normal
    ``==`` short-circuits on the first differing byte and leaks the position
    of the mismatch through timing.
    """
    return secrets.compare_digest(str(left), str(right))


__all__ = [
    "NS_FOUNDATION",
    "NS_ENGINE",
    "NS_TRACE",
    "new_id",
    "new_token",
    "new_correlation_id",
    "stable_id",
    "engine_id",
    "is_uuid",
    "sanitize_correlation_id",
    "constant_time_equals",
]
