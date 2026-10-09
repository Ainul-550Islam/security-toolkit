"""Central audit append/query facade over the immutable platform audit chain.

Audit hashes, persistence, sanitization, and supported action validation stay
owned by ``PlatformService`` and ``AuditEvent``. This service adds strict
append verification, event schema/correlation metadata, and tenant-filtered
bounded reads without creating another audit database.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Mapping

from services.customer_resource_service import _domain_module

models = _domain_module("models")

_ACTION_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,160}$")
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX_METADATA_BYTES = 16_384


class AuditServiceError(Exception):
    """Safe audit operation failure containing only a stable code."""

    def __init__(self, code: str) -> None:
        allowed = {
            "audit_input_invalid",
            "audit_action_unsupported",
            "audit_write_unavailable",
            "audit_read_unavailable",
            "audit_authorization_required",
            "audit_integrity_unavailable",
        }
        self.code = code if code in allowed else "audit_write_unavailable"
        super().__init__(self.code)


class AuditService:
    """Append and query validated audit events using the canonical hash chain."""

    def __init__(
        self,
        platform: Any,
        *,
        authorization: Any = None,
        authorize_read: Callable[[Any, str], Any] | None = None,
    ) -> None:
        self.platform = platform
        self.db = platform.db
        self.authorization = authorization
        self.authorize_read = authorize_read

    def record(
        self,
        action: str,
        *,
        actor: str,
        org_id: str = "",
        project_id: str = "",
        object_type: str = "",
        object_id: str = "",
        correlation_id: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one redacted event and verify it reached canonical storage."""
        safe_action = str(action or "")
        safe_actor = str(actor or "")
        tenant = str(org_id or "")
        project = str(project_id or "")
        kind = str(object_type or "")
        object_ref = str(object_id or "")
        correlation = str(correlation_id or "")
        if (
            not _ACTION_RE.fullmatch(safe_action)
            or not safe_actor
            or len(safe_actor) > 128
            or any(ord(char) < 32 for char in safe_actor)
            or len(tenant) > 160
            or len(project) > 160
            or len(kind) > 64
            or len(object_ref) > 160
            or any(ord(char) < 32 for char in kind + object_ref)
            or (tenant and not _IDENTIFIER_RE.fullmatch(tenant))
            or (project and not _IDENTIFIER_RE.fullmatch(project))
            or (object_ref and not _IDENTIFIER_RE.fullmatch(object_ref))
            or (correlation and not _CORRELATION_RE.fullmatch(correlation))
        ):
            raise AuditServiceError("audit_input_invalid")
        if safe_action not in models.AuditEvent.ACTIONS:
            raise AuditServiceError("audit_action_unsupported")
        if metadata is not None and not isinstance(metadata, Mapping):
            raise AuditServiceError("audit_input_invalid")
        payload = dict(metadata or {})
        payload["schema_version"] = 1
        if correlation:
            payload["correlation_id"] = correlation
        try:
            encoded = json.dumps(
                payload,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8", "strict")
        except (TypeError, ValueError, OverflowError, UnicodeError):
            raise AuditServiceError("audit_input_invalid") from None
        if len(encoded) > _MAX_METADATA_BYTES:
            raise AuditServiceError("audit_input_invalid")
        try:
            event = self.platform.audit(
                safe_action,
                actor=safe_actor,
                org_id=tenant,
                project_id=project,
                object_type=kind,
                object_id=object_ref,
                metadata=payload,
            )
            rows = self.db.query(
                "SELECT id, ts, action, actor, object_type, object_id, org_id, "
                "project_id, metadata, prev_hash, event_hash FROM audit_events "
                "WHERE id=? AND org_id=? LIMIT 1",
                (str(getattr(event, "id", "")), tenant),
                limit=1,
            )
        except Exception:
            raise AuditServiceError("audit_write_unavailable") from None
        if not rows or str(rows[0].get("action", "")) != safe_action:
            raise AuditServiceError("audit_write_unavailable")
        saved = dict(rows[0])
        raw_metadata = saved.get("metadata", "{}")
        if isinstance(raw_metadata, str):
            try:
                raw_metadata = json.loads(raw_metadata)
            except (TypeError, ValueError, json.JSONDecodeError):
                raise AuditServiceError("audit_write_unavailable") from None
        if not isinstance(raw_metadata, dict):
            raise AuditServiceError("audit_write_unavailable")
        saved["metadata"] = raw_metadata
        saved["schema_version"] = int(raw_metadata.get("schema_version", 1))
        saved["correlation_id"] = str(raw_metadata.get("correlation_id", ""))
        if not saved.get("event_hash"):
            raise AuditServiceError("audit_write_unavailable")
        return saved

    def list_tenant_events(
        self,
        org_id: str,
        *,
        principal_context: Any = None,
        action: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List tenant events with tenant predicates and bounded pagination."""
        tenant = str(org_id or "")
        if not tenant or len(tenant) > 160:
            raise AuditServiceError("audit_input_invalid")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise AuditServiceError("audit_input_invalid")
        if type(offset) is not int or not 0 <= offset <= 100_000:
            raise AuditServiceError("audit_input_invalid")
        if action and action not in models.AuditEvent.ACTIONS:
            raise AuditServiceError("audit_action_unsupported")
        try:
            if self.authorize_read is not None:
                allowed = self.authorize_read(principal_context, tenant)
                if allowed is False:
                    raise AuditServiceError("audit_authorization_required")
            elif self.authorization is not None:
                if principal_context is None:
                    raise AuditServiceError("audit_authorization_required")
                self.authorization.require_audit(principal_context, tenant)
            else:
                raise AuditServiceError("audit_authorization_required")
            where = "org_id=?"
            args: tuple[Any, ...] = (tenant,)
            if action:
                where += " AND action=?"
                args += (action,)
            count_rows = self.db.query(
                "SELECT COUNT(*) AS total FROM audit_events WHERE " + where,
                args,
                limit=1,
            )
            rows = self.db.query(
                "SELECT id, ts, action, actor, object_type, object_id, org_id, "
                "project_id, metadata, event_hash FROM audit_events WHERE " +
                where + " ORDER BY rowid DESC LIMIT ? OFFSET ?",
                args + (limit, offset),
                limit=limit,
            )
        except AuditServiceError:
            raise
        except Exception:
            raise AuditServiceError("audit_read_unavailable") from None
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                metadata = row.get("metadata", "{}")
                if isinstance(metadata, str):
                    metadata = json.loads(metadata)
                if not isinstance(metadata, dict):
                    metadata = {}
                items.append({
                    "id": str(row.get("id", "")),
                    "ts": str(row.get("ts", "")),
                    "action": str(row.get("action", "")),
                    "actor": str(row.get("actor", "")),
                    "object_type": str(row.get("object_type", "")),
                    "object_id": str(row.get("object_id", "")),
                    "org_id": str(row.get("org_id", "")),
                    "project_id": str(row.get("project_id", "")),
                    "metadata": metadata,
                    "schema_version": int(metadata.get("schema_version", 1)),
                    "correlation_id": str(metadata.get("correlation_id", "")),
                    "integrity_reference": str(row.get("event_hash", "")),
                })
            except (TypeError, ValueError, OverflowError):
                raise AuditServiceError("audit_read_unavailable") from None
        total = int(count_rows[0].get("total", 0)) if count_rows else 0
        return {"items": items, "total": total, "count": len(items), "limit": limit, "offset": offset}

    def verify_chain(self) -> dict[str, Any]:
        """Return the canonical chain verifier's safe aggregate result."""
        try:
            result = self.platform.audit_verify()
        except Exception:
            raise AuditServiceError("audit_integrity_unavailable") from None
        if not isinstance(result, dict):
            raise AuditServiceError("audit_integrity_unavailable")
        return {
            "ok": bool(result.get("ok")),
            "verified": max(0, int(result.get("verified", 0))),
            "legacy": max(0, int(result.get("legacy", 0))),
            "total": max(0, int(result.get("total", 0))),
            "issue_count": len(result.get("issues", [])) if isinstance(result.get("issues", []), list) else 0,
        }


__all__ = ["AuditService", "AuditServiceError"]
