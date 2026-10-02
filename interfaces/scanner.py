"""Scanner contract: defensive assessment only.

Scope boundary (enforced by review and by :func:`assert_defensive`)
-------------------------------------------------------------------
A scanner INSPECTS and REPORTS. It may parse configuration, read files inside
the workspace, evaluate policy and compute findings. It must not exploit,
brute-force, pivot, or perform unauthenticated intrusive probing of third
parties. The foundation layer therefore declares a closed set of scanner
kinds, all of which are analysis-oriented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from core.constants import MAX_NAME_LEN, SEVERITIES
from core.errors import SecurityViolation, ValidationError

SCANNER_KINDS: Final[tuple[str, ...]] = (
    "static_analysis",   # source / IaC / config inspection
    "dependency",        # SBOM and known-vulnerability matching
    "secret_detection",  # credential material accidentally committed
    "configuration",     # hardening and baseline compliance
    "policy",            # organisational rule evaluation
)

# Terms that indicate offensive automation. Present so an attempt to register
# an exploit module fails loudly at the boundary instead of quietly shipping.
_OFFENSIVE_MARKERS: Final[tuple[str, ...]] = (
    "exploit", "payload_delivery", "reverse_shell", "bruteforce",
    "brute_force", "credential_stuffing", "ddos", "c2", "implant",
)


def assert_defensive(name: str, kind: str) -> None:
    """Reject scanner registrations that describe offensive automation."""
    lowered = f"{name} {kind}".lower()
    for marker in _OFFENSIVE_MARKERS:
        if marker in lowered:
            raise SecurityViolation(
                f"scanner {name!r} describes offensive automation "
                f"({marker!r}); this toolkit is defensive-only",
                context={"scanner": name, "reason": "offensive_scanner"},
            )


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """What to assess. A path target is validated by ``core.paths.safe_join``."""

    kind: str
    identifier: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> ScanTarget:
        if self.kind not in ("path", "repository", "manifest", "configuration"):
            raise ValidationError(
                "target kind must be path, repository, manifest or configuration"
            )
        if not self.identifier or len(self.identifier) > 2048:
            raise ValidationError("target identifier must be 1..2048 characters")
        return self


@dataclass(frozen=True, slots=True)
class Finding:
    """One assessment result."""

    rule_id: str
    title: str
    severity: str = "info"
    description: str = ""
    location: str = ""
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> Finding:
        if not self.rule_id or len(self.rule_id) > MAX_NAME_LEN:
            raise ValidationError("rule_id must be 1..200 characters")
        if not self.title or len(self.title) > MAX_NAME_LEN:
            raise ValidationError("title must be 1..200 characters")
        if self.severity not in SEVERITIES:
            raise ValidationError(
                f"unknown severity: must be one of {', '.join(SEVERITIES)}"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "location": self.location,
            "remediation": self.remediation,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Outcome of one scan.

    ``completed=False`` with a ``failure_reason`` is how a scanner reports a
    partial run. An incomplete scan must never be presented as a clean one:
    "no findings" and "could not look" are different answers.
    """

    scanner: str
    target: ScanTarget
    findings: tuple[Finding, ...] = ()
    completed: bool = False
    failure_reason: str = ""

    @property
    def clean(self) -> bool:
        """True only when the scan finished AND produced no findings."""
        return self.completed and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "target": {"kind": self.target.kind, "identifier": self.target.identifier},
            "completed": self.completed,
            "failure_reason": self.failure_reason,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


@runtime_checkable
class Scanner(Protocol):
    """Defensive assessment component."""

    @property
    def name(self) -> str: ...

    @property
    def kind(self) -> str: ...

    def supports(self, target: ScanTarget) -> bool:
        """True when this scanner can assess the target."""
        ...

    def scan(self, target: ScanTarget) -> ScanResult:
        """Assess the target. Reports failure via ``completed=False``."""
        ...


__all__ = [
    "Scanner", "ScanTarget", "ScanResult", "Finding",
    "SCANNER_KINDS", "assert_defensive",
]
