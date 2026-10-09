"""Secret-safe structured operation observations over existing telemetry.

This adapter reuses the project's bounded metrics vocabulary and redaction
helpers. It never records arbitrary labels, request bodies, credential values,
or raw exception messages.
"""

from __future__ import annotations

import logging
import re
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from services.customer_resource_service import _domain_module

metrics = _domain_module("metrics")
redact = _domain_module("redact")

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,160}$")
_SAFE_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_.:-]{1,95}$")
_SAFE_ERROR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,79}$")
_RESULT_STATES = frozenset({
    "success", "error", "denied", "unavailable", "timeout", "partial", "skipped",
})


@dataclass(frozen=True, slots=True)
class OperationObservation:
    """Sanitized metadata emitted for one high-value operation."""

    request_id: str
    tenant_id: str
    operation: str
    actor_id: str
    started_at: str
    duration_seconds: float
    result: str
    error_class: str = ""

    def to_dict(self) -> dict[str, str | float]:
        result: dict[str, str | float] = {
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "operation": self.operation,
            "actor_id": self.actor_id,
            "started_at": self.started_at,
            "duration_seconds": round(max(0.0, self.duration_seconds), 6),
            "result": self.result,
        }
        if self.error_class:
            result["error_class"] = self.error_class
        return result


class OperationScope(AbstractContextManager["OperationScope"]):
    """Context manager that emits one completion observation on exit."""

    def __init__(
        self,
        service: "ObservabilityService",
        *,
        request_id: str,
        tenant_id: str,
        operation: str,
        actor_id: str,
        counter: str,
        duration_metric: str,
    ) -> None:
        self.service = service
        self.request_id = request_id
        self.tenant_id = tenant_id
        self.operation = operation
        self.actor_id = actor_id
        self.counter = counter
        self.duration_metric = duration_metric
        self.started_monotonic = time.monotonic()
        self.started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def __enter__(self) -> "OperationScope":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        duration = max(0.0, time.monotonic() - self.started_monotonic)
        if exc_type is None:
            result = "success"
            error_class = ""
        else:
            result = self.service.classify_failure(exc)
            error_class = type(exc).__name__
            if not _SAFE_ERROR_RE.fullmatch(error_class):
                error_class = "UnknownError"
        self.service.record(
            request_id=self.request_id,
            tenant_id=self.tenant_id,
            operation=self.operation,
            actor_id=self.actor_id,
            started_at=self.started_at,
            duration_seconds=duration,
            result=result,
            error_class=error_class,
            counter=self.counter,
            duration_metric=self.duration_metric,
        )
        return False


class ObservabilityService:
    """Emit bounded logs/counters/timings with request and tenant correlation."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("security_toolkit.operations")
        snapshot = metrics.snapshot()
        self._counter_names = frozenset(snapshot.get("counters", {}))
        self._duration_names = frozenset(snapshot.get("durations", {}))

    def operation(
        self,
        operation: str,
        *,
        request_id: str,
        tenant_id: str,
        actor_id: str,
        counter: str = "",
        duration_metric: str = "",
    ) -> OperationScope:
        """Start a trace-like scope; only safe identifiers are retained."""
        request = str(request_id or "")
        tenant = str(tenant_id or "")
        actor = str(actor_id or "")
        name = str(operation or "")
        if (
            not request
            or len(request) > 128
            or not _SAFE_ID_RE.fullmatch(request)
            or not tenant
            or not _SAFE_ID_RE.fullmatch(tenant)
            or not actor
            or not _SAFE_ID_RE.fullmatch(actor)
            or not _SAFE_OPERATION_RE.fullmatch(name)
        ):
            raise ValueError("operation correlation fields are invalid")
        if counter and counter not in self._counter_names:
            raise ValueError("operation counter is not in the fixed metrics vocabulary")
        if duration_metric and duration_metric not in self._duration_names:
            raise ValueError("duration metric is not in the fixed metrics vocabulary")
        return OperationScope(
            self,
            request_id=request,
            tenant_id=tenant,
            operation=name,
            actor_id=actor,
            counter=counter,
            duration_metric=duration_metric,
        )

    def record(
        self,
        *,
        request_id: str,
        tenant_id: str,
        operation: str,
        actor_id: str,
        started_at: str,
        duration_seconds: float,
        result: str,
        error_class: str = "",
        counter: str = "",
        duration_metric: str = "",
    ) -> OperationObservation:
        """Write a single minimized event and bounded metric updates."""
        if result not in _RESULT_STATES:
            raise ValueError("operation result state is unsupported")
        if counter and counter not in self._counter_names:
            raise ValueError("operation counter is not in the fixed metrics vocabulary")
        if duration_metric and duration_metric not in self._duration_names:
            raise ValueError("duration metric is not in the fixed metrics vocabulary")
        try:
            duration = float(duration_seconds)
        except (TypeError, ValueError, OverflowError):
            duration = 0.0
        if duration < 0 or duration != duration or duration == float("inf"):
            duration = 0.0
        safe_error = str(error_class or "")[:80]
        if safe_error and not _SAFE_ERROR_RE.fullmatch(safe_error):
            safe_error = "UnknownError"
        observation = OperationObservation(
            request_id=str(request_id)[:128],
            tenant_id=str(tenant_id)[:160],
            operation=str(operation)[:96],
            actor_id=str(actor_id)[:160],
            started_at=str(started_at)[:32],
            duration_seconds=duration,
            result=result,
            error_class=safe_error,
        )
        if counter:
            metrics.inc(counter)
        if duration_metric:
            metrics.add_duration(duration_metric, duration)
        safe_record = redact.redact(observation.to_dict())
        self.logger.info("security_operation", extra={"security_operation": safe_record})
        return observation

    @staticmethod
    def classify_failure(exc: BaseException | None) -> str:
        """Map exception classes to a bounded outcome category, not their text."""
        name = type(exc).__name__ if exc is not None else ""
        lowered = name.lower()
        if "timeout" in lowered:
            return "timeout"
        if "authorization" in lowered or "permission" in lowered:
            return "denied"
        if "configuration" in lowered or "unavailable" in lowered:
            return "unavailable"
        return "error"

    def health_status(self) -> dict[str, str | bool]:
        return {
            "status": "healthy" if self.logger is not None else "unavailable",
            "ready": self.logger is not None,
            "metrics_vocabulary_bounded": True,
            "secret_values_logged": False,
        }


__all__ = ["OperationObservation", "OperationScope", "ObservabilityService"]
