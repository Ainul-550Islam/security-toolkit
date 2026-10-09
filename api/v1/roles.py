"""Tenant RBAC inspection and audited role-assignment APIs."""

from __future__ import annotations

from typing import Any

import rbac
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_MAX_ROLES_PER_USER = 5


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


def _role_view(name: str) -> dict[str, Any]:
    normalized = rbac.validate_role(name)
    return {
        "name": normalized,
        "permissions": sorted(rbac.ROLE_PERMISSIONS[normalized]),
    }


def _normalize_roles(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_ROLES_PER_USER:
        raise ApiException(validation_problem(
            field="roles", code="invalid", message="One to five roles are required"
        ))
    if any(not isinstance(role, str) for role in value):
        raise ApiException(validation_problem(
            field="roles", code="invalid", message="Roles must be strings"
        ))
    try:
        roles = tuple(rbac.validate_role(role) for role in value)
    except Exception:
        raise ApiException(validation_problem(
            field="roles", code="invalid", message="One or more roles are not supported"
        )) from None
    if len(set(roles)) != len(roles):
        raise ApiException(validation_problem(
            field="roles", code="duplicate", message="Roles must be unique"
        ))
    return roles


def register(router: ApiRouter) -> None:
    services = router.services

    def list_roles(_request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        roles = [_role_view(name) for name in rbac.ROLE_ORDER]
        return HttpResponse(200, {"data": roles, "count": len(roles)})

    def get_role(_request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        name = params["role_name"]
        if name not in rbac.ROLES:
            raise ApiException(ApiProblem(404, "not_found", "Resource not found"))
        return HttpResponse(200, {"data": _role_view(name)})

    def get_user_roles(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        user = services.authorization.require_user(context, params["user_id"])
        assigned = services.identity.user_roles(user.id)
        return HttpResponse(200, {
            "data": {
                "user_id": user.id,
                "org_id": user.org_id,
                "roles": [_role_view(role) for role in assigned],
            }
        })

    def set_user_roles(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"roles"}))
        roles = _normalize_roles(body.get("roles"))
        context = _context(request)
        user = services.authorization.require_user(context, params["user_id"])
        if user.id == context.user_id:
            raise ApiException(ApiProblem(
                409, "self_role_change_denied", "You cannot change your own roles"
            ))
        services.authorization.require(context, "role.assign")
        assigned = services.identity.user_set_roles(
            user.id,
            roles,
            as_roles=context.roles,
            as_permissions=context.permissions,
            actor=context.label(),
        )
        return HttpResponse(200, {
            "data": {"user_id": user.id, "org_id": user.org_id,
                     "roles": [_role_view(role) for role in assigned]}
        })

    def remove_user_role(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        role_name = params["role_name"]
        if role_name not in rbac.ROLES:
            raise ApiException(ApiProblem(404, "not_found", "Resource not found"))
        context = _context(request)
        user = services.authorization.require_user(context, params["user_id"])
        if user.id == context.user_id:
            raise ApiException(ApiProblem(
                409, "self_role_change_denied", "You cannot change your own roles"
            ))
        services.authorization.require(context, "role.assign")
        current = tuple(services.identity.user_roles(user.id))
        if role_name not in current:
            remaining = current
        else:
            remaining = tuple(role for role in current if role != role_name)
        if not remaining:
            raise ApiException(ApiProblem(
                409, "last_role_required", "A user must retain at least one role"
            ))
        assigned = services.identity.user_set_roles(
            user.id,
            remaining,
            as_roles=context.roles,
            as_permissions=context.permissions,
            actor=context.label(),
        )
        return HttpResponse(200, {
            "data": {"user_id": user.id, "org_id": user.org_id,
                     "roles": [_role_view(role) for role in assigned]}
        })

    router.register(RouteSpec(
        path="/api/v1/roles",
        methods=frozenset({"GET"}),
        handler=list_roles,
        operation_id="listRoles",
        summary="List the platform's supported RBAC roles and explicit permissions",
        tags=("roles",),
        permission="role.read",
        response_schema={"type": "object"},
        responses={"200": "Supported roles"},
    ))
    router.register(RouteSpec(
        path="/api/v1/roles/{role_name}",
        methods=frozenset({"GET"}),
        handler=get_role,
        operation_id="getRole",
        summary="Inspect one supported role and its effective permissions",
        tags=("roles",),
        permission="role.read",
        response_schema={"type": "object"},
        responses={"200": "Role detail", "404": "Role not found"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/users/{user_id}/roles",
        methods=frozenset({"GET"}),
        handler=get_user_roles,
        operation_id="getTenantUserRoles",
        summary="Read a user's assigned roles within the authenticated tenant",
        tags=("roles", "users"),
        permission="role.read",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "Tenant-local user roles"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/users/{user_id}/roles",
        methods=frozenset({"PUT"}),
        handler=set_user_roles,
        operation_id="setTenantUserRoles",
        summary="Assign roles under the existing role-escalation guard and audit trail",
        tags=("roles", "users"),
        permission="role.assign",
        scope_kind="organization",
        scope_parameter="tenant_id",
        request_schema={
            "type": "object",
            "required": ["roles"],
            "additionalProperties": False,
            "properties": {
                "roles": {
                    "type": "array", "minItems": 1, "maxItems": _MAX_ROLES_PER_USER,
                    "uniqueItems": True, "items": {"type": "string", "enum": list(rbac.ROLE_ORDER)},
                },
            },
        },
        response_schema={"type": "object"},
        responses={"200": "Updated roles", "403": "Role assignment exceeds caller authority", "409": "Self role changes are denied"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/users/{user_id}/roles/{role_name}",
        methods=frozenset({"DELETE"}),
        handler=remove_user_role,
        operation_id="removeTenantUserRole",
        summary="Remove one role without permitting a user to become roleless",
        tags=("roles", "users"),
        permission="role.assign",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "Updated roles", "403": "Role assignment exceeds caller authority", "409": "A user must retain at least one role"},
    ))


__all__ = ["register"]
