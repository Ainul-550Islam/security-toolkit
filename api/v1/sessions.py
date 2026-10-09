"""Authenticated self-service session listing and revocation APIs."""

from __future__ import annotations

from typing import Any

import redact
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


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
    service = extra.get("customer_resources")
    if service is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The session resource service is not configured"))
    return service


def _session_view(row: dict[str, Any], current_session_id: str) -> dict[str, Any]:
    user_agent = str(redact.redact_text(row.get("user_agent", "")))[:256]
    return {
        "id": str(row.get("id", "")),
        "current": str(row.get("id", "")) == current_session_id,
        "ip": str(redact.redact_text(row.get("ip", "")))[:64],
        "device_metadata": {
            "user_agent": user_agent,
            "auth_method": str(row.get("auth_method", ""))[:32],
            "mfa_status": str(row.get("mfa_status", "none"))[:16],
            "provider_id": str(redact.redact_text(row.get("provider_id", "")))[:96],
        },
        "created_at": str(row.get("created_at", "")),
        "last_seen_at": str(row.get("last_seen_at", "")),
        "expires_at": str(row.get("expires_at", "")),
        "absolute_expires_at": str(row.get("absolute_expires_at", "")),
        "revoked_at": str(row.get("revoked_at", "")),
        "revoke_reason": str(row.get("revoke_reason", ""))[:64],
        "status": "revoked" if row.get("revoked_at") else "active",
    }


def register(router: ApiRouter) -> None:
    services = router.services

    def list_current_user_sessions(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset({"limit", "offset", "status"}))
        context = _context(request)
        if context.credential_id or not context.user_id:
            raise ApiException(ApiProblem(409, "sessions_not_applicable", "This principal has no user session"))
        status = request.query.get("status", ["active"])[0]
        if status not in {"active", "revoked", "all"}:
            raise ApiException(validation_problem(
                field="status", code="invalid", message="Session status is not supported"
            ))
        limit = _integer(request, "limit", 50, 1, 200)
        offset = _integer(request, "offset", 0, 0, 10_000)
        result = _service(services).sessions_list(
            context.org_id,
            context.user_id,
            limit=limit,
            offset=offset,
            status=status,
        )
        return HttpResponse(200, {
            "data": [_session_view(row, context.session_id) for row in result["sessions"]],
            "count": result["count"],
            "total": result["total"],
            "limit": result["limit"],
            "offset": result["offset"],
        })

    def get_current_session(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        if context.credential_id or not context.session_id or not context.user_id:
            principal_type = "api_credential" if context.credential_id else "user"
            return HttpResponse(200, {
                "data": {"state": "NOT_APPLICABLE", "principal_type": principal_type, "session": None}
            })
        current = _service(services).session_get(
            context.org_id, context.user_id, context.session_id
        )
        return HttpResponse(200, {"data": {"session": _session_view(current, context.session_id)}})

    def revoke_current_session(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        if not context.session_id or not context.user_id:
            raise ApiException(ApiProblem(409, "sessions_not_applicable", "This principal has no revocable user session"))
        services.authorization.require_own_session(context, context.session_id)
        services.identity.session_revoke_id(
            context.session_id, reason="customer_logout", actor=context.label()
        )
        return HttpResponse(204, b"")

    def revoke_all_current_user_sessions(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        if context.credential_id or not context.user_id:
            raise ApiException(ApiProblem(409, "sessions_not_applicable", "This principal has no user sessions"))
        count = services.identity.sessions_revoke_all(
            context.user_id, reason="customer_forced_logout", actor=context.label()
        )
        return HttpResponse(200, {"data": {"revoked_count": int(count)}})

    router.register(RouteSpec(
        path="/api/v1/sessions",
        methods=frozenset({"GET"}),
        handler=list_current_user_sessions,
        operation_id="listCurrentUserSessions",
        summary="List only the authenticated user's bounded session/device metadata",
        tags=("sessions",),
        permission="identity.sessions.read",
        response_schema={"type": "object"},
        responses={"200": "Current user's session page"},
    ))
    router.register(RouteSpec(
        path="/api/v1/sessions/current",
        methods=frozenset({"GET"}),
        handler=get_current_session,
        operation_id="getCurrentSession",
        summary="Read current session metadata without returning token material",
        tags=("sessions",),
        permission="identity.sessions.read",
        response_schema={"type": "object"},
        responses={"200": "Current session state"},
    ))
    router.register(RouteSpec(
        path="/api/v1/sessions/current/revoke",
        methods=frozenset({"POST"}),
        handler=revoke_current_session,
        operation_id="revokeCurrentSession",
        summary="Revoke the caller's own authenticated session",
        tags=("sessions",),
        permission="identity.read",
        response_schema={"type": "object"},
        responses={"204": "Current session revoked"},
    ))
    router.register(RouteSpec(
        path="/api/v1/sessions/revoke-all",
        methods=frozenset({"POST"}),
        handler=revoke_all_current_user_sessions,
        operation_id="revokeAllCurrentUserSessions",
        summary="Force logout by revoking every session belonging to the caller",
        tags=("sessions",),
        permission="identity.sessions.revoke",
        response_schema={"type": "object"},
        responses={"200": "Revocation count"},
    ))


__all__ = ["register"]
