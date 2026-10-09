"""Organization-scoped user administration through IdentityService."""

from __future__ import annotations

from typing import Any

import errors as domain_errors
import rbac
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_ALLOWED_STATUSES = frozenset({"active", "disabled", "deactivated", "suspended"})


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _body(request: HttpRequest, allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(request.body, dict):
        raise ApiException(validation_problem(
            field="request", code="invalid_type", message="A JSON object is required"
        ))
    if set(request.body) - allowed:
        raise ApiException(validation_problem(
            field="request", code="unknown_field", message="Unexpected field"
        ))
    return request.body


def _limit(request: HttpRequest, *, default: int = 100, maximum: int = 500) -> int:
    values = request.query.get("limit", [])
    if not values:
        return default
    if len(values) != 1 or not values[0].isdigit():
        raise ApiException(validation_problem(
            field="limit", code="invalid", message="Limit must be an integer"
        ))
    value = int(values[0])
    if not 1 <= value <= maximum:
        raise ApiException(validation_problem(
            field="limit", code="out_of_range", message="Limit is outside the allowed range"
        ))
    return value


def _user_view(services: Any, user: Any) -> dict[str, Any]:
    result = user.to_dict()
    result["roles"] = list(services.identity.user_roles(user.id))
    return result


def _session_view(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(session.get("id", "")),
        "user_id": str(session.get("user_id", "")),
        "username": str(session.get("username", ""))[:32],
        "auth_method": str(session.get("auth_method", ""))[:32],
        "mfa_status": str(session.get("mfa_status", "none"))[:16],
        "created_at": str(session.get("created_at", "")),
        "last_seen_at": str(session.get("last_seen_at", "")),
        "expires_at": str(session.get("expires_at", "")),
        "revoked_at": str(session.get("revoked_at", "")),
    }


def _page_value(request: HttpRequest, key: str, default: int, maximum: int) -> int:
    values = request.query.get(key, [])
    if not values:
        return default
    if len(values) != 1 or not values[0].isdigit():
        raise ApiException(validation_problem(
            field=key, code="invalid", message=f"{key} must be an integer"
        ))
    value = int(values[0])
    lower = 1 if key == "limit" else 0
    if not lower <= value <= maximum:
        raise ApiException(validation_problem(
            field=key, code="out_of_range", message=f"{key} is outside the allowed range"
        ))
    return value


def register(router: ApiRouter) -> None:
    services = router.services

    def list_users(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        users = services.identity.user_list(tenant_id, limit=_limit(request))
        return HttpResponse(200, {
            "data": [_user_view(services, user) for user in users],
            "count": len(users),
        })

    def create_user(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({
            "username", "email", "display_name", "password", "roles"
        }))
        for field_name in ("username", "email", "password"):
            if not isinstance(body.get(field_name), str) or not body[field_name]:
                raise ApiException(validation_problem(
                    field=field_name, code="required", message="A valid value is required"
                ))
        display_name = body.get("display_name", "")
        if not isinstance(display_name, str) or len(display_name) > 128:
            raise ApiException(validation_problem(
                field="display_name", code="invalid", message="Display name exceeds the allowed length"
            ))
        roles = body.get("roles", ["viewer"])
        if not isinstance(roles, list) or not 1 <= len(roles) <= 5:
            raise ApiException(validation_problem(
                field="roles", code="invalid", message="One to five roles are required"
            ))
        if any(not isinstance(role, str) for role in roles):
            raise ApiException(validation_problem(
                field="roles", code="invalid", message="Roles must be strings"
            ))
        try:
            normalized_roles = tuple(rbac.validate_role(role) for role in roles)
        except domain_errors.ValidationError:
            raise ApiException(validation_problem(
                field="roles", code="invalid", message="One or more roles are invalid"
            )) from None
        if len(set(normalized_roles)) != len(normalized_roles):
            raise ApiException(validation_problem(
                field="roles", code="duplicate", message="Roles must be unique"
            ))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        user = services.identity.user_create(
            tenant_id,
            body["username"],
            body["email"],
            body["password"],
            normalized_roles,
            display_name=display_name,
            as_roles=context.roles,
            as_permissions=context.permissions,
            actor=context.label(),
        )
        return HttpResponse(201, {"data": _user_view(services, user)})

    def get_user(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        user = services.authorization.require_user(context, params["user_id"])
        return HttpResponse(200, {"data": _user_view(services, user)})

    def update_user(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"roles", "status"}))
        if len(body) != 1:
            raise ApiException(validation_problem(
                field="request", code="invalid", message="Update exactly one of roles or status"
            ))
        context = _context(request)
        user = services.authorization.require_user(context, params["user_id"])
        actor = context.label()
        if "roles" in body:
            roles = body["roles"]
            if not isinstance(roles, list) or not 1 <= len(roles) <= 5:
                raise ApiException(validation_problem(
                    field="roles", code="invalid", message="One to five roles are required"
                ))
            if any(not isinstance(role, str) for role in roles):
                raise ApiException(validation_problem(
                    field="roles", code="invalid", message="Roles must be strings"
                ))
            try:
                normalized_roles = tuple(rbac.validate_role(role) for role in roles)
            except domain_errors.ValidationError:
                raise ApiException(validation_problem(
                    field="roles", code="invalid", message="One or more roles are invalid"
                )) from None
            if len(set(normalized_roles)) != len(normalized_roles):
                raise ApiException(validation_problem(
                    field="roles", code="duplicate", message="Roles must be unique"
                ))
            if user.id == context.user_id:
                raise ApiException(ApiProblem(
                    409, "self_role_change_denied", "You cannot change your own roles"
                ))
            services.authorization.require(context, "role.assign")
            services.identity.user_set_roles(
                user.id,
                normalized_roles,
                as_roles=context.roles,
                as_permissions=context.permissions,
                actor=actor,
            )
            updated = services.identity.user_get(user.id)
        else:
            status = body["status"]
            if not isinstance(status, str) or status not in _ALLOWED_STATUSES:
                raise ApiException(validation_problem(
                    field="status", code="invalid", message="Status is not allowed"
                ))
            if status != user.status and user.id == context.user_id and status != "active":
                raise ApiException(ApiProblem(
                    409, "self_status_change_denied", "You cannot disable your own account"
                ))
            if status != "active":
                services.authorization.require(context, "user.disable")
            services.identity.user_set_status(user.id, status, actor=actor)
            updated = services.identity.user_get(user.id)
        return HttpResponse(200, {"data": _user_view(services, updated)})

    def list_sessions(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        allowed = {"limit", "offset", "status"}
        if set(request.query) - allowed:
            raise ApiException(validation_problem(
                field="query", code="unknown_parameter", message="Unexpected query parameter"
            ))
        if any(len(values) > 1 for values in request.query.values()):
            raise ApiException(validation_problem(
                field="query", code="duplicate_parameter", message="Specify each parameter at most once"
            ))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        status = request.query.get("status", ["active"])[0]
        if status not in {"active", "revoked", "all"}:
            raise ApiException(validation_problem(
                field="status", code="invalid", message="Session status is not supported"
            ))
        result = services.identity.sessions_list_org(
            tenant_id,
            limit=_page_value(request, "limit", 100, 500),
            offset=_page_value(request, "offset", 0, 100_000),
            status="" if status == "all" else status,
        )
        return HttpResponse(200, {
            "data": [_session_view(session) for session in result["sessions"]],
            "count": result["count"],
            "total": result["total"],
            "limit": result["limit"],
            "offset": result["offset"],
        })

    def revoke_session(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        rows = services.platform.db.query(
            "SELECT s.id, u.org_id FROM sessions s JOIN users u "
            "ON u.id=s.user_id WHERE s.id=? LIMIT 1",
            (params["session_id"],),
        )
        if not rows or rows[0]["org_id"] != tenant_id:
            raise ApiException(ApiProblem(403, "forbidden", "Forbidden"))
        services.identity.session_revoke_id(
            params["session_id"], reason="api_revoked", actor=context.label()
        )
        return HttpResponse(204, b"")

    route_prefix = "/api/v1/tenants/{tenant_id}/users"
    common = {
        "tags": ("users",),
        "scope_kind": "organization",
        "scope_parameter": "tenant_id",
        "response_schema": {"type": "object"},
    }
    router.register(RouteSpec(
        path=route_prefix,
        methods=frozenset({"GET"}),
        handler=list_users,
        operation_id="listTenantUsers",
        summary="List users in the authenticated tenant",
        permission="user.read",
        request_schema=None,
        responses={"200": "Tenant users"},
        **common,
    ))
    router.register(RouteSpec(
        path=route_prefix,
        methods=frozenset({"POST"}),
        handler=create_user,
        operation_id="createTenantUser",
        summary="Create a tenant user through IdentityService",
        permission="user.create",
        request_schema={
            "type": "object",
            "required": ["username", "email", "password"],
            "additionalProperties": False,
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 32},
                "email": {"type": "string", "maxLength": 254},
                "password": {"type": "string", "minLength": 12},
                "display_name": {"type": "string", "maxLength": 128},
                "roles": {
                    "type": "array", "minItems": 1, "maxItems": 5,
                    "items": {"type": "string", "enum": sorted(rbac.ROLES)},
                },
            },
        },
        responses={"201": "User created"},
        **common,
    ))
    router.register(RouteSpec(
        path=route_prefix + "/{user_id}",
        methods=frozenset({"GET"}),
        handler=get_user,
        operation_id="getTenantUser",
        summary="Read one tenant user without exposing password or lock metadata",
        permission="user.read",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "User metadata", "403": "User is outside the authenticated tenant"},
    ))
    router.register(RouteSpec(
        path=route_prefix + "/{user_id}",
        methods=frozenset({"PATCH"}),
        handler=update_user,
        operation_id="updateTenantUser",
        summary="Update one tenant user's role assignment or lifecycle status",
        permission="user.update",
        scope_kind="organization",
        scope_parameter="tenant_id",
        request_schema={
            "type": "object",
            "minProperties": 1,
            "maxProperties": 1,
            "additionalProperties": False,
            "properties": {
                "roles": {
                    "type": "array", "minItems": 1, "maxItems": 5,
                    "items": {"type": "string", "enum": sorted(rbac.ROLES)},
                },
                "status": {"type": "string", "enum": sorted(_ALLOWED_STATUSES)},
            },
        },
        response_schema={"type": "object"},
        responses={"200": "User updated"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/sessions",
        methods=frozenset({"GET"}),
        handler=list_sessions,
        operation_id="listTenantSessions",
        summary="List minimized session metadata within one tenant",
        tags=("users", "sessions"),
        permission="identity.sessions.read",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "Tenant session metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/sessions/{session_id}/revoke",
        methods=frozenset({"POST"}),
        handler=revoke_session,
        operation_id="revokeTenantSession",
        summary="Revoke one verified session through IdentityService",
        tags=("users", "sessions"),
        permission="identity.sessions.revoke",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"204": "Session revoked"},
    ))


__all__ = ["register"]
