"""Telemetry event contract.

Mirrors ``schemas/event.schema.json``. Telemetry is observability data, NOT a
credential channel: :meth:`TelemetryEvent.validate` actively rejects metadata
keys that look like secrets so a well-meaning caller cannot turn the event bus
into a token leak.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from core.clock import utcnow_iso
from core.constants import (
    MAX_METADATA_KEYS,
    MAX_METADATA_VALUE_LEN,
    MAX_NAME_LEN,
    SEVERITIES,
)
from core.errors import ValidationError
from core.ids import new_correlation_id, new_id
from core.version import SCHEMA_VERSION

EVENT_KINDS: Final[tuple[str, ...]] = (
    "audit", "metric", "health", "diagnostic", "security",
)

_FORBIDDEN_METADATA_KEYS: Final[tuple[str, ...]] = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credential", "authorization", "cookie", "passphrase",
)


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """One canonical telemetry event."""

    event_type: str
    source: str
    event_id: str = field(default_factory=new_id)
    schema_version: str = SCHEMA_VERSION
    timestamp: str = field(default_factory=utcnow_iso)
    kind: str = "diagnostic"
    severity: str = "info"
    tenant_id: str = ""
    correlation_id: str = field(default_factory=new_correlation_id)
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> TelemetryEvent:
        """Validate against the closed vocabulary and bounds."""
        if not self.event_type or len(self.event_type) > MAX_NAME_LEN:
            raise ValidationError("event_type must be 1..200 characters")
        if not self.source or len(self.source) > MAX_NAME_LEN:
            raise ValidationError("source must be 1..200 characters")
        if self.kind not in EVENT_KINDS:
            raise ValidationError(
                f"unknown event kind: must be one of {', '.join(EVENT_KINDS)}"
            )
        if self.severity not in SEVERITIES:
            raise ValidationError(
                f"unknown severity: must be one of {', '.join(SEVERITIES)}"
            )
        if len(self.metadata) > MAX_METADATA_KEYS:
            raise ValidationError(f"metadata exceeds {MAX_METADATA_KEYS} keys")
        for key, value in self.metadata.items():
            lowered = str(key).lower()
            if any(bad in lowered for bad in _FORBIDDEN_METADATA_KEYS):
                raise ValidationError(
                    f"metadata key {key!r} looks like a credential; telemetry "
                    "must never carry secret material"
                )
            if isinstance(value, str) and len(value) > MAX_METADATA_VALUE_LEN:
                raise ValidationError(f"metadata value for {key!r} is too long")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "kind": self.kind,
            "severity": self.severity,
            "source": self.source,
            "tenant_id": self.tenant_id,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }


@runtime_checkable
class TelemetrySink(Protocol):
    """Destination for telemetry events."""

    def emit(self, event: TelemetryEvent) -> None:
        """Deliver one validated event. Must not raise on transport failure."""
        ...


class NullTelemetrySink:
    """Discards events. The honest default when no sink is configured."""

    __slots__ = ("count",)

    def __init__(self) -> None:
        self.count = 0

    def emit(self, event: TelemetryEvent) -> None:
        self.count += 1


__all__ = [
    "TelemetryEvent",
    "TelemetrySink",
    "NullTelemetrySink",
    "EVENT_KINDS",
]
