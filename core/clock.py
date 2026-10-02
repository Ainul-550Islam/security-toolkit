"""UTC-aware time abstraction.

Why this exists
---------------
Security logic (token expiry, replay windows, credential rotation, retention)
must never depend on the host timezone or on naive datetimes. Two specific
bugs this module prevents:

* Naive datetimes. ``datetime.now()`` returns a timezone-naive value in local
  time. Comparing it against a UTC timestamp silently shifts every deadline by
  the host's UTC offset, which can extend an expired credential's life by
  hours.
* ``time.mktime()``. It interprets a struct_time as LOCAL time and is
  DST-ambiguous: during a DST fold, one wall-clock time maps to two instants
  and ``mktime`` picks one arbitrarily. It must never appear in expiration
  logic. Use :func:`to_epoch` instead.

Determinism
-----------
Every function takes time from an injectable :class:`Clock`. Tests use
:class:`FixedClock` or :class:`OffsetClock` to make time-dependent security
behaviour reproducible instead of sleeping.

Scope (PART 01)
---------------
This module establishes the reusable abstraction. It deliberately does NOT
rewrite the timestamp handling inside the existing phase 1-13 modules; those
keep their current, already-tested behaviour.
"""

from __future__ import annotations

import time as _time
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol, runtime_checkable

UTC: Final = UTC

# Canonical wire format: RFC 3339 / ISO 8601, UTC, second precision, 'Z'.
ISO_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%SZ"


class ClockError(ValueError):
    """Raised when a timestamp cannot be parsed or is not representable."""


@runtime_checkable
class Clock(Protocol):
    """Source of the current instant. Always timezone-aware UTC."""

    def now(self) -> datetime:
        """Return the current instant as a timezone-aware UTC datetime."""
        ...


class SystemClock:
    """Real wall-clock time, always UTC-aware."""

    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(UTC)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "SystemClock()"


class FixedClock:
    """A clock frozen at a fixed instant. For deterministic tests."""

    __slots__ = ("_instant",)

    def __init__(self, instant: datetime) -> None:
        self._instant = ensure_utc(instant)

    def now(self) -> datetime:
        return self._instant

    def set(self, instant: datetime) -> None:
        """Move the frozen instant (explicit, never implicit)."""
        self._instant = ensure_utc(instant)

    def advance(self, seconds: float) -> datetime:
        """Advance the frozen instant and return the new value."""
        self._instant = self._instant + timedelta(seconds=float(seconds))
        return self._instant

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"FixedClock({self._instant.isoformat()})"


class OffsetClock:
    """A clock that runs in real time but shifted by a fixed offset.

    Useful for exercising "what happens 40 days from now" without freezing
    time entirely.
    """

    __slots__ = ("_base", "_offset")

    def __init__(self, offset_seconds: float, base: Clock | None = None) -> None:
        self._offset = timedelta(seconds=float(offset_seconds))
        self._base: Clock = base or SystemClock()

    def now(self) -> datetime:
        return self._base.now() + self._offset


# Default process clock. Call sites should accept an injected Clock; this is
# the fallback for code that has no reason to care.
SYSTEM_CLOCK: Final[SystemClock] = SystemClock()


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime.

    A naive datetime is REJECTED rather than silently assumed to be UTC:
    guessing is exactly how expiry bugs are introduced.
    """
    if not isinstance(value, datetime):
        raise ClockError(f"expected datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ClockError(
            "naive datetime rejected: attach a timezone (security logic "
            "must never assume the host timezone)"
        )
    return value.astimezone(UTC)


def now(clock: Clock | None = None) -> datetime:
    """Current UTC instant from the given (or system) clock."""
    return ensure_utc((clock or SYSTEM_CLOCK).now())


def utcnow_iso(clock: Clock | None = None) -> str:
    """Current instant in the canonical wire format."""
    return to_iso(now(clock))


def to_iso(value: datetime) -> str:
    """Format a datetime in the canonical wire format (UTC, 'Z', seconds)."""
    return ensure_utc(value).strftime(ISO_FORMAT)


def parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 / RFC 3339 timestamp into an aware UTC datetime.

    Accepts a trailing ``Z`` and explicit offsets. A timestamp WITHOUT a
    timezone is rejected: the caller must state what it means.
    """
    if not isinstance(value, str):
        raise ClockError(f"expected str timestamp, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ClockError("empty timestamp")
    if len(text) > 64:
        raise ClockError("timestamp too long")
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ClockError(f"invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ClockError(
            f"timestamp without timezone rejected: {value!r} "
            "(say 'Z' or an explicit offset)"
        )
    return parsed.astimezone(UTC)


def to_epoch(value: datetime) -> float:
    """Seconds since the Unix epoch for an aware datetime.

    This is the correct replacement for ``time.mktime()``: it is unambiguous
    because the input carries its own offset.
    """
    return ensure_utc(value).timestamp()


def from_epoch(seconds: float) -> datetime:
    """Aware UTC datetime for a Unix timestamp."""
    try:
        return datetime.fromtimestamp(float(seconds), tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ClockError(f"epoch value out of range: {seconds!r}") from exc


def monotonic() -> float:
    """Monotonic seconds, for measuring DURATIONS only.

    Never persist this value or compare it against a wall-clock timestamp:
    its zero point is arbitrary and it does not survive a restart.
    """
    return _time.monotonic()


def is_expired(
    expires_at: datetime | str | None,
    *,
    clock: Clock | None = None,
    leeway_seconds: float = 0.0,
) -> bool:
    """Return True when ``expires_at`` is in the past.

    Fail-closed: a missing or unparseable expiry is treated as EXPIRED, so a
    malformed value can never grant access. ``leeway_seconds`` must be
    non-negative and shortens validity (never extends it), so clock skew can
    only make the check stricter.
    """
    if expires_at is None:
        return True
    if leeway_seconds < 0:
        raise ClockError("leeway_seconds must be non-negative")
    try:
        deadline = (
            parse_iso(expires_at) if isinstance(expires_at, str)
            else ensure_utc(expires_at)
        )
    except ClockError:
        return True
    return now(clock) >= (deadline - timedelta(seconds=float(leeway_seconds)))


def within_window(
    timestamp: datetime | str,
    *,
    window_seconds: float,
    clock: Clock | None = None,
) -> bool:
    """Return True when ``timestamp`` is within +/- window of now.

    This is the replay-protection primitive: a signed request is only
    acceptable if its timestamp is recent AND not implausibly in the future.
    Fail-closed on unparseable input.
    """
    if window_seconds <= 0:
        raise ClockError("window_seconds must be positive")
    try:
        moment = (
            parse_iso(timestamp) if isinstance(timestamp, str)
            else ensure_utc(timestamp)
        )
    except ClockError:
        return False
    delta = abs((now(clock) - moment).total_seconds())
    return delta <= float(window_seconds)
