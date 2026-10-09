"""Tenant-isolated audit log reads with bounded pagination."""

from __future__ import annotations

import json
from typing import Any

import models
import redact
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_MAX_METADATA_BYTES = 4096


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _integer_query(request: HttpRequest, key: str, default: int, maximum: int) -> int:
    values = request.query.get(key, [])
    if not values:
        return default
    if len(values) != 1 or not values[0].isdigit():
        raise ApiException(validation_problem(
            field=key, code="invalid", message=f"{key} must be an integer"
        ))
    value = int(values[0])
    if not 0 <= value <= maximum or (key == "limit" and value == 0):
        raise ApiException(validation_problem(
            field=key, code="out_of_range", message=f"{key} is outside the allowed range"
        ))
    return value


def _metadata(value: Any) -> dict[str, Any]:
    safe = redact.redact(value if isinstance(value, dict) else {})
    try:
        encoded = json.dumps(safe, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError, OverflowError):
        return {"truncated": True}
    if len(encoded.encode("utf-8")) > _MAX_METADATA_BYTES:
        return {"truncated": True}
    return safe


def _view(event: Any) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "ts": str(event.ts),
        "action": str(event.action),
        "actor": str(redact.redact_text(event.actor))[:128],
        "object_type": str(event.object_type)[:64],
        "object_id": str(event.object_id)[:160],
        "org_id": str(event.org_id),
        "project_id": str(event.project_id),
        "metadata": _metadata(event.metadata),
    }


def register(router: ApiRouter) -> None:
    services = router.services

    def list_tenant_audit(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        allowed = {"limit", "offset", "action"}
        if set(request.query) - allowed:
            raise ApiException(validation_problem(
                field="query", code="unknown_parameter", message="Unexpected query parameter"
            ))
        if any(len(values) > 1 for values in request.query.values()):
            raise ApiException(validation_problem(
                field="query", code="duplicate_parameter", message="Specify each parameter at most once"
            ))
        tenant_id = params["tenant_id"]
        context = _context(request)
        services.authorization.require_audit(context, tenant_id)
        limit = _integer_query(request, "limit", 100, 500)
        offset = _integer_query(request, "offset", 0, 10_000)
        action_values = request.query.get("action", [])
        action = action_values[0] if action_values else ""
        if action and action not in models.AuditEvent.ACTIONS:
            raise ApiException(validation_problem(
                field="action", code="invalid", message="Audit action is not supported"
            ))
        if action:
            rows = services.platform.db.query(
                "SELECT * FROM audit_events WHERE org_id=? AND action=? "
                "ORDER BY rowid DESC LIMIT ? OFFSET ?",
                (tenant_id, action, limit, offset),
            )
        else:
            rows = services.platform.db.query(
                "SELECT * FROM audit_events WHERE org_id=? "
                "ORDER BY rowid DESC LIMIT ? OFFSET ?",
                (tenant_id, limit, offset),
            )
        events = []
        for row in rows:
            metadata = row.get("metadata", "{}")
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}
            event = models.AuditEvent.from_dict({
                **row,
                "metadata": metadata if isinstance(metadata, dict) else {},
            })
            events.append(_view(event))
        return HttpResponse(200, {
            "data": events,
            "count": len(events),
            "limit": limit,
            "offset": offset,
        })

    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/audit-events",
        methods=frozenset({"GET"}),
        handler=list_tenant_audit,
        operation_id="listTenantAuditEvents",
        summary="Read audit events limited to the authenticated tenant",
        tags=("audit",),
        permission="audit.read",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "Tenant audit records"},
    ))


__all__ = ["register"]
