"""Project-scoped remediation workflow APIs over the canonical remedy engine."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import models
import redact
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_DUE_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_MAX_WINDOW = 500


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _body(request: HttpRequest, allowed: frozenset[str], *, allow_empty: bool = False) -> dict[str, Any]:
    if request.body is None and allow_empty:
        return {}
    if not isinstance(request.body, dict):
        raise ApiException(validation_problem(
            field="request", code="invalid_type", message="A JSON object is required"
        ))
    if set(request.body) - allowed:
        raise ApiException(validation_problem(
            field="request", code="unknown_field", message="Unexpected field"
        ))
    return request.body


def _query(request: HttpRequest, allowed: frozenset[str]) -> None:
    if set(request.query) - allowed:
        raise ApiException(validation_problem(
            field="query", code="unknown_parameter", message="Unexpected query parameter"
        ))
    if any(len(values) > 1 for values in request.query.values()):
        raise ApiException(validation_problem(
            field="query", code="duplicate_parameter", message="Specify each parameter at most once"
        ))


def _integer(request: HttpRequest, name: str, default: int, minimum: int, maximum: int) -> int:
    values = request.query.get(name, [])
    if not values:
        return default
    if len(values) != 1 or not values[0].isdigit():
        raise ApiException(validation_problem(
            field=name, code="invalid", message=f"{name} must be an integer"
        ))
    value = int(values[0])
    if not minimum <= value <= maximum:
        raise ApiException(validation_problem(
            field=name, code="out_of_range", message=f"{name} is outside the allowed range"
        ))
    return value


def _service(services: Any) -> Any:
    extra = services.extra if isinstance(services.extra, dict) else {}
    service = extra.get("remediation_service")
    if service is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The remediation service is not configured"))
    return service


def _ticket_view(ticket: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "id", "org_id", "project_id", "finding_id", "remediation_group_id",
        "title", "owner_type", "owner_id", "owner_name", "status", "priority",
        "due_at", "created_at", "updated_at", "resolved_at",
        "verification_status", "verification_scan_id", "verification_attempts",
    )
    result = {key: ticket.get(key) for key in allowed if key in ticket}
    for key in ("title", "owner_name"):
        if key in result:
            result[key] = str(redact.redact_text(result[key]))[:240]
    history = ticket.get("history")
    if isinstance(history, list):
        safe_history = []
        for item in history[:100]:
            if not isinstance(item, dict):
                continue
            safe_history.append({
                "id": str(item.get("id", "")),
                "actor": str(redact.redact_text(item.get("actor", "")))[:128],
                "action": str(item.get("action", ""))[:64],
                "ts": str(item.get("ts", "")),
                "detail": redact.redact(item.get("detail", {})) if isinstance(item.get("detail"), dict) else {},
            })
        result["history"] = safe_history
    sla = ticket.get("sla")
    if isinstance(sla, dict):
        result["sla"] = {str(key)[:8]: value for key, value in sla.items()}
    return result


def register(router: ApiRouter) -> None:
    services = router.services

    def list_tickets(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset({"limit", "offset", "status"}))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        status = request.query.get("status", [""])[0]
        if status and status not in models.REMEDIATION_STATUSES:
            raise ApiException(validation_problem(
                field="status", code="invalid", message="Remediation status is not supported"
            ))
        limit = _integer(request, "limit", 50, 1, 100)
        offset = _integer(request, "offset", 0, 0, _MAX_WINDOW - 1)
        if offset + limit > _MAX_WINDOW:
            raise ApiException(validation_problem(
                field="pagination", code="out_of_range", message="The remediation result window is limited"
            ))
        tickets = _service(services).list_tickets(
            project_id, status=status, limit=_MAX_WINDOW, org_id=context.org_id
        )
        page = tickets[offset:offset + limit]
        return HttpResponse(200, {
            "data": [_ticket_view(ticket) for ticket in page],
            "count": len(page),
            "total": len(tickets),
            "limit": limit,
            "offset": offset,
            "truncated": len(tickets) == _MAX_WINDOW,
        })

    def ensure_finding_ticket(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _body(request, frozenset(), allow_empty=True)
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        finding = services.authorization.require_finding(context, params["finding_id"])
        if finding.project_id != project_id:
            raise ApiException(ApiProblem(404, "not_found", "Resource not found"))
        ticket = _service(services).ensure(
            finding.id, actor=context.label(), org_id=context.org_id
        )
        return HttpResponse(201, {"data": _ticket_view(ticket)})

    def get_ticket(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        services.authorization.require_remediation(context, params["ticket_id"])
        ticket = _service(services).view(
            params["ticket_id"], history_limit=100, org_id=context.org_id
        )
        return HttpResponse(200, {"data": _ticket_view(ticket)})

    def change_status(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"status", "reason"}))
        status = body.get("status")
        reason = body.get("reason", "")
        if not isinstance(status, str) or status not in models.REMEDIATION_STATUSES:
            raise ApiException(validation_problem(
                field="status", code="invalid", message="Remediation status is not supported"
            ))
        if not isinstance(reason, str) or len(reason) > 200:
            raise ApiException(validation_problem(
                field="reason", code="invalid", message="Reason exceeds the allowed length"
            ))
        context = _context(request)
        services.authorization.require_remediation(context, params["ticket_id"])
        ticket = _service(services).status(
            params["ticket_id"], status, actor=context.label(), reason=reason,
            org_id=context.org_id,
        )
        return HttpResponse(200, {"data": _ticket_view(ticket)})

    def assign_ticket(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"owner_id"}))
        owner_id = body.get("owner_id")
        if not isinstance(owner_id, str) or not 1 <= len(owner_id) <= 128:
            raise ApiException(validation_problem(
                field="owner_id", code="required", message="A tenant-local user ID is required"
            ))
        context = _context(request)
        services.authorization.require_remediation(context, params["ticket_id"])
        ticket = _service(services).assign(
            params["ticket_id"], "user", owner_id, actor=context.label(),
            org_id=context.org_id,
        )
        return HttpResponse(200, {"data": _ticket_view(ticket)})

    def set_due_date(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"due_at"}))
        due_at = body.get("due_at")
        if not isinstance(due_at, str) or not _DUE_AT_RE.fullmatch(due_at):
            raise ApiException(validation_problem(
                field="due_at", code="invalid", message="Use a UTC timestamp in YYYY-MM-DDTHH:MM:SSZ format"
            ))
        try:
            datetime.strptime(due_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ApiException(validation_problem(
                field="due_at", code="invalid", message="Due date is not a valid UTC calendar timestamp"
            )) from None
        context = _context(request)
        services.authorization.require_remediation(context, params["ticket_id"])
        ticket = _service(services).set_due(
            params["ticket_id"], due_at, actor=context.label(),
            org_id=context.org_id,
        )
        return HttpResponse(200, {"data": _ticket_view(ticket)})

    def add_comment(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"comment"}))
        comment = body.get("comment")
        if not isinstance(comment, str) or not 1 <= len(comment.strip()) <= 2000:
            raise ApiException(validation_problem(
                field="comment", code="invalid", message="Comment must contain 1 to 2000 characters"
            ))
        context = _context(request)
        services.authorization.require_remediation(context, params["ticket_id"])
        ticket = _service(services).add_comment(
            params["ticket_id"], comment, actor=context.label(),
            org_id=context.org_id,
        )
        return HttpResponse(201, {"data": _ticket_view(ticket)})

    def request_verification(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _body(request, frozenset(), allow_empty=True)
        context = _context(request)
        services.authorization.require_remediation(context, params["ticket_id"])
        ticket = _service(services).request_verification(
            params["ticket_id"], actor=context.label(), org_id=context.org_id
        )
        return HttpResponse(202, {"data": _ticket_view(ticket)})

    common_project = {
        "tags": ("remediation",),
        "scope_kind": "project",
        "scope_parameter": "project_id",
        "response_schema": {"type": "object"},
    }
    common_ticket = {
        "tags": ("remediation",),
        "response_schema": {"type": "object"},
    }
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/remediations",
        methods=frozenset({"GET"}),
        handler=list_tickets,
        operation_id="listProjectRemediations",
        summary="List bounded project remediation tickets and status history references",
        permission="remediation.read",
        responses={"200": "Project remediation ticket page"},
        **common_project,
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/findings/{finding_id}/remediation",
        methods=frozenset({"POST"}),
        handler=ensure_finding_ticket,
        operation_id="ensureFindingRemediation",
        summary="Create or retrieve the existing idempotent remediation ticket for a finding",
        permission="remediation.update",
        request_schema={"type": "object", "additionalProperties": False},
        responses={"201": "Remediation ticket", "404": "Finding not found"},
        **common_project,
    ))
    router.register(RouteSpec(
        path="/api/v1/remediations/{ticket_id}",
        methods=frozenset({"GET"}),
        handler=get_ticket,
        operation_id="getRemediationTicket",
        summary="Read a tenant-authorized remediation ticket and bounded history",
        permission="remediation.read",
        responses={"200": "Remediation ticket"},
        **common_ticket,
    ))
    router.register(RouteSpec(
        path="/api/v1/remediations/{ticket_id}/status",
        methods=frozenset({"PATCH"}),
        handler=change_status,
        operation_id="changeRemediationStatus",
        summary="Apply a legal remediation state transition through the existing engine",
        permission="remediation.update",
        request_schema={
            "type": "object", "required": ["status"],
            "additionalProperties": False,
            "properties": {
                "status": {"type": "string", "enum": list(models.REMEDIATION_STATUSES)},
                "reason": {"type": "string", "maxLength": 200},
            },
        },
        responses={"200": "Updated remediation ticket", "409": "Invalid state transition"},
        **common_ticket,
    ))
    router.register(RouteSpec(
        path="/api/v1/remediations/{ticket_id}/assignment",
        methods=frozenset({"POST"}),
        handler=assign_ticket,
        operation_id="assignRemediationTicket",
        summary="Assign a ticket to an existing user in its organization",
        permission="remediation.assign",
        request_schema={
            "type": "object", "required": ["owner_id"],
            "additionalProperties": False,
            "properties": {"owner_id": {"type": "string", "minLength": 1, "maxLength": 128}},
        },
        responses={"200": "Assigned ticket", "400": "Owner is invalid or outside the tenant"},
        **common_ticket,
    ))
    router.register(RouteSpec(
        path="/api/v1/remediations/{ticket_id}/due-date",
        methods=frozenset({"PATCH"}),
        handler=set_due_date,
        operation_id="setRemediationDueDate",
        summary="Set a UTC remediation deadline and record the change in history",
        permission="remediation.update",
        request_schema={
            "type": "object", "required": ["due_at"],
            "additionalProperties": False,
            "properties": {"due_at": {"type": "string", "format": "date-time", "maxLength": 20}},
        },
        responses={"200": "Updated due date"},
        **common_ticket,
    ))
    router.register(RouteSpec(
        path="/api/v1/remediations/{ticket_id}/comments",
        methods=frozenset({"POST"}),
        handler=add_comment,
        operation_id="addRemediationComment",
        summary="Append a redacted customer comment to the ticket audit history",
        permission="remediation.update",
        request_schema={
            "type": "object", "required": ["comment"],
            "additionalProperties": False,
            "properties": {"comment": {"type": "string", "minLength": 1, "maxLength": 2000}},
        },
        responses={"201": "Comment added"},
        **common_ticket,
    ))
    router.register(RouteSpec(
        path="/api/v1/remediations/{ticket_id}/verification",
        methods=frozenset({"POST"}),
        handler=request_verification,
        operation_id="requestRemediationVerification",
        summary="Queue a real evidence-based verification scan through the existing job service",
        permission="remediation.verify",
        request_schema={"type": "object", "additionalProperties": False},
        responses={"202": "Verification scan queued", "409": "Ticket is not ready for verification"},
        **common_ticket,
    ))


__all__ = ["register"]
