"""Safe, immutable identity and correlation context for one API request.

A context contains identifiers and authorization decisions only. It must never
contain a password, bearer token, session secret, provider credential, or raw
request body. The associated legacy authorization context is retained only as
an in-process object for adapter calls and is excluded from representations and
serialization.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$")
_SAFE_SOURCE_RE = re.compile(r"^[A-Fa-f0-9:.]{1,64}$")
_MAX_ROLES = 32
_MAX_PERMISSIONS = 512


@dataclass(frozen=True, slots=True)
class Principal:
    """Minimum safe identity information needed by endpoint handlers."""

    principal_id: str
    tenant_id: str
    subject_type: str
    roles: frozenset[str] = frozenset()
    permissions: frozenset[str] = frozenset()
    authentication_method: str = ""
    session_id: str = ""
    credential_id: str = ""

    def __post_init__(self) -> None:
        if not self.principal_id or len(self.principal_id) > 160:
            raise ValueError("principal_id must be a bounded non-empty identifier")
        if not self.tenant_id or len(self.tenant_id) > 160:
            raise ValueError("tenant_id must be a bounded non-empty identifier")
        if self.subject_type not in {"user", "api_credential", "service"}:
            raise ValueError("subject_type is not supported")
        if len(self.roles) > _MAX_ROLES or any(
            not isinstance(role, str) or not role or len(role) > 64
            for role in self.roles
        ):
            raise ValueError("roles must be bounded strings")
        if len(self.permissions) > _MAX_PERMISSIONS or any(
            not isinstance(permission, str) or not permission or len(permission) > 128
            for permission in self.permissions
        ):
            raise ValueError("permissions must be bounded strings")
        if len(self.authentication_method) > 64:
            raise ValueError("authentication_method is too long")
        if len(self.session_id) > 160 or len(self.credential_id) > 160:
            raise ValueError("principal reference is too long")

    def safe_dict(self) -> dict[str, Any]:
        """Return a token-free representation suitable for trusted handlers."""
        return {
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "subject_type": self.subject_type,
            "roles": sorted(self.roles),
            "permissions": sorted(self.permissions),
            "authentication_method": self.authentication_method,
            "session_id": self.session_id,
            "credential_id": self.credential_id,
        }


@dataclass(frozen=True, slots=True, repr=False)
class RequestContext:
    """Validated per-request context passed from middleware to handlers."""

    request_id: str
    principal: Principal | None = None
    tenant_id: str = ""
    roles: frozenset[str] = frozenset()
    permissions: frozenset[str] = frozenset()
    deadline_monotonic: float = 0.0
    source_ip: str = ""
    authorization_context: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _REQUEST_ID_RE.fullmatch(str(self.request_id)):
            raise ValueError("request_id has an invalid format")
        if not math.isfinite(float(self.deadline_monotonic)):
            raise ValueError("deadline_monotonic must be finite")
        if self.source_ip and not _SAFE_SOURCE_RE.fullmatch(self.source_ip):
            raise ValueError("source_ip must be a numeric address")
        if self.principal is None:
            if self.tenant_id or self.roles or self.permissions:
                raise ValueError("anonymous contexts cannot carry tenant permissions")
        else:
            if self.tenant_id != self.principal.tenant_id:
                raise ValueError("tenant_id must match the authenticated principal")
            if self.roles != self.principal.roles:
                raise ValueError("roles must match the authenticated principal")
            if self.permissions != self.principal.permissions:
                raise ValueError("permissions must match the authenticated principal")

    @property
    def is_authenticated(self) -> bool:
        return self.principal is not None

    def has_permission(self, permission: str) -> bool:
        return self.is_authenticated and permission in self.permissions

    def remaining_seconds(self, now_monotonic: float) -> float:
        """Return non-negative remaining handler budget."""
        return max(0.0, self.deadline_monotonic - float(now_monotonic))

    def safe_correlation_fields(self) -> dict[str, str]:
        """Identifiers safe for access logs; no body, token, or user-agent."""
        fields = {"request_id": self.request_id}
        if self.principal is not None:
            fields["principal_id"] = self.principal.principal_id
            fields["tenant_id"] = self.tenant_id
        return fields

    def __repr__(self) -> str:
        actor = self.principal.principal_id if self.principal else "anonymous"
        return (
            f"RequestContext(request_id={self.request_id!r}, "
            f"principal={actor!r}, tenant_id={self.tenant_id!r})"
        )


__all__ = ["Principal", "RequestContext"]
