"""Central bounded tenant-aware rate limiting.

The in-process implementation is intentionally explicit: ``health_status``
reports ``LOCAL_PROCESS`` and deployments needing cross-worker enforcement
must inject a shared backend. Key material is hashed before it enters the
bounded hit table, so tenant/principal identifiers are not retained there.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Mapping

_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_.:-]{1,63}$")
_DEFAULT_POLICIES: dict[str, tuple[int, float]] = {
    "api": (120, 60.0),
    "authentication": (10, 300.0),
    "scan_create": (10, 3600.0),
    "export": (20, 3600.0),
    "integration": (60, 60.0),
    "high_cost": (30, 60.0),
}


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Safe result of one rate-limit check."""

    allowed: bool
    operation: str
    limit: int
    remaining: int
    retry_after: int
    window_seconds: int
    backend: str = "LOCAL_PROCESS"

    def to_dict(self) -> dict[str, int | bool | str]:
        return {
            "allowed": self.allowed,
            "operation": self.operation,
            "limit": self.limit,
            "remaining": self.remaining,
            "retry_after": self.retry_after,
            "window_seconds": self.window_seconds,
            "backend": self.backend,
        }


class RateLimitService:
    """Thread-safe sliding-window limiter with operation and tenant scopes."""

    def __init__(
        self,
        *,
        limit: int = 120,
        window_seconds: float = 60.0,
        max_keys: int = 20_000,
        clock: Callable[[], float] = time.monotonic,
        policies: Mapping[str, tuple[int, float]] | None = None,
        backend_name: str = "LOCAL_PROCESS",
    ) -> None:
        if type(limit) is not int or limit < 1:
            raise ValueError("rate limit must be a positive integer")
        if not math.isfinite(float(window_seconds)) or window_seconds <= 0:
            raise ValueError("rate-limit window must be finite and positive")
        if type(max_keys) is not int or max_keys < 1 or max_keys > 1_000_000:
            raise ValueError("rate limiter key bound is invalid")
        safe_backend = str(backend_name or "")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,31}", safe_backend):
            raise ValueError("rate-limit backend name is invalid")
        configured = dict(_DEFAULT_POLICIES)
        configured["api"] = (limit, float(window_seconds))
        if policies is not None:
            if not isinstance(policies, Mapping) or set(policies) - set(_DEFAULT_POLICIES):
                raise ValueError("rate-limit policy name is unsupported")
            for name, pair in policies.items():
                if not isinstance(name, str) or name not in _DEFAULT_POLICIES:
                    raise ValueError("rate-limit policy name is unsupported")
                if (
                    not isinstance(pair, (tuple, list))
                    or len(pair) != 2
                    or type(pair[0]) is not int
                    or pair[0] < 1
                    or not math.isfinite(float(pair[1]))
                    or float(pair[1]) <= 0
                ):
                    raise ValueError("rate-limit policy bounds are invalid")
                configured[name] = (int(pair[0]), float(pair[1]))
        self._policies = configured
        self.limit = int(limit)
        self.window_seconds = float(window_seconds)
        self.max_keys = int(max_keys)
        self._clock = clock
        self.backend_name = safe_backend
        self._lock = threading.Lock()
        self._hits: dict[tuple[str, str], deque[float]] = {}
        self._last_sweep = 0.0

    @property
    def policies(self) -> dict[str, dict[str, int]]:
        """Return fixed policy limits without exposing keyed state."""
        return {
            name: {"limit": values[0], "window_seconds": max(1, math.ceil(values[1]))}
            for name, values in sorted(self._policies.items())
        }

    def check(
        self,
        operation: str,
        *,
        tenant_id: str = "",
        principal_id: str = "",
        identity: str = "",
    ) -> RateLimitDecision:
        """Consume one operation token under explicit tenant/actor identity."""
        name = str(operation or "")
        if name not in self._policies or not _OPERATION_RE.fullmatch(name):
            return RateLimitDecision(False, "unknown", 1, 0, 60, 60, self.backend_name)
        tenant = str(tenant_id or "")
        principal = str(principal_id or "")
        fallback = str(identity or "")
        if not tenant and name != "authentication":
            limit, window = self._policies[name]
            return RateLimitDecision(False, name, limit, 0, max(1, math.ceil(window)), max(1, math.ceil(window)), self.backend_name)
        if not principal and not fallback:
            limit, window = self._policies[name]
            return RateLimitDecision(False, name, limit, 0, max(1, math.ceil(window)), max(1, math.ceil(window)), self.backend_name)
        limit, window = self._policies[name]
        identity_value = "\x00".join((name, tenant, principal, fallback))
        key = hashlib.sha256(identity_value.encode("utf-8", "replace")).hexdigest()
        allowed, retry_after, remaining = self._consume(name, key, limit, window)
        return RateLimitDecision(
            allowed,
            name,
            limit,
            remaining,
            retry_after,
            max(1, math.ceil(window)),
            self.backend_name,
        )

    def allow(self, key: str) -> tuple[bool, int]:
        """Compatibility hook for API middleware's source/principal limiter."""
        raw_key = str(key or "")[:512]
        if not raw_key:
            raw_key = "unknown"
        digest = hashlib.sha256(raw_key.encode("utf-8", "replace")).hexdigest()
        allowed, retry_after, _remaining = self._consume(
            "api", digest, self.limit, self.window_seconds
        )
        return allowed, retry_after

    def _consume(
        self,
        operation: str,
        key: str,
        limit: int,
        window: float,
    ) -> tuple[bool, int, int]:
        try:
            now = float(self._clock())
        except Exception:
            now = float("nan")
        if not math.isfinite(now):
            return False, max(1, math.ceil(window)), 0
        cutoff = now - window
        scoped_key = (operation, key)
        with self._lock:
            if now - self._last_sweep >= min(window, 30.0):
                for expired_key in tuple(self._hits):
                    values = self._hits[expired_key]
                    if not values or values[-1] <= now - max(
                        self._policies.get(expired_key[0], (self.limit, self.window_seconds))[1]
                    ):
                        self._hits.pop(expired_key, None)
                self._last_sweep = now
            hits = self._hits.get(scoped_key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    return False, max(1, math.ceil(window)), 0
                hits = deque()
                self._hits[scoped_key] = hits
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= limit:
                retry = max(1, math.ceil(window - (now - hits[0])))
                return False, retry, 0
            hits.append(now)
            return True, 0, max(0, limit - len(hits))

    def health_check(self) -> bool:
        """The local limiter is usable while its fixed vocabulary is intact."""
        return bool(self._policies) and self.max_keys > 0

    def health_status(self) -> dict[str, str | bool]:
        return {
            "status": "healthy" if self.health_check() else "unavailable",
            "ready": self.health_check(),
            "backend": self.backend_name,
            "shared_across_processes": self.backend_name != "LOCAL_PROCESS",
        }


__all__ = ["RateLimitDecision", "RateLimitService"]
