"""Tenant-safe organization profile, preferences, and MFA posture APIs."""

from __future__ import annotations

from typing import Any

from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


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


def _customer_resources(services: Any) -> Any:
    extra = services.extra if isinstance(services.extra, dict) else {}
    service = extra.get("customer_resources")
    if service is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The organization resource service is not configured"))
    return service


def _mfa_service(services: Any) -> Any:
    extra = services.extra if isinstance(services.extra, dict) else {}
    service = extra.get("mfa_service")
    if service is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The organization security-posture service is not configured"))
    return service


def _organization_view(organization: Any, preferences: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(organization.id),
        "name": str(organization.name),
        "status": str(organization.status),
        "created_at": str(organization.created_at),
        "updated_at": str(organization.updated_at),
        "preferences": preferences,
    }


def register(router: ApiRouter) -> None:
    services = router.services

    def get_organization(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        org_id = params["organization_id"]
        services.authorization.require_org(context, org_id)
        organization = services.platform.org_get(org_id)
        preferences = _customer_resources(services).organization_preferences_get(org_id)
        return HttpResponse(200, {"data": _organization_view(organization, preferences)})

    def update_organization(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"name"}))
        name = body.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 128:
            raise ApiException(validation_problem(
                field="name", code="invalid", message="A valid organization name is required"
            ))
        context = _context(request)
        org_id = params["organization_id"]
        services.authorization.require_org(context, org_id)
        organization = _customer_resources(services).organization_update(
            org_id, {"name": name.strip()}, actor=context.label()
        )
        preferences = _customer_resources(services).organization_preferences_get(org_id)
        return HttpResponse(200, {"data": _organization_view(organization, preferences)})

    def get_preferences(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        org_id = params["organization_id"]
        services.authorization.require_org(context, org_id)
        return HttpResponse(200, {
            "data": _customer_resources(services).organization_preferences_get(org_id)
        })

    def update_preferences(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"timezone", "locale"}))
        if not body:
            raise ApiException(validation_problem(
                field="request", code="empty", message="At least one preference is required"
            ))
        context = _context(request)
        org_id = params["organization_id"]
        services.authorization.require_org(context, org_id)
        preferences = _customer_resources(services).organization_preferences_update(
            org_id, body, actor=context.label()
        )
        return HttpResponse(200, {"data": preferences})

    def get_security_posture(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        org_id = params["organization_id"]
        services.authorization.require_org(context, org_id)
        policy = _mfa_service(services).policy_get(org_id)
        return HttpResponse(200, {
            "data": {
                "org_id": org_id,
                "mfa_policy": policy,
                "state": "CONFIGURED" if int(policy.get("version", 0)) > 0 else "DEFAULT",
            }
        })

    def update_security_posture(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"policy", "version"}))
        policy = body.get("policy")
        if not isinstance(policy, dict):
            raise ApiException(validation_problem(
                field="policy", code="required", message="A valid MFA policy object is required"
            ))
        version = body.get("version", 0)
        if type(version) is not int or version < 0:
            raise ApiException(validation_problem(
                field="version", code="invalid", message="Version must be a non-negative integer"
            ))
        context = _context(request)
        org_id = params["organization_id"]
        services.authorization.require_org(context, org_id)
        result = _mfa_service(services).policy_set(
            org_id,
            policy,
            version=version,
            actor=context.label(),
        )
        return HttpResponse(200, {"data": {"org_id": org_id, "mfa_policy": result, "state": "CONFIGURED"}})

    router.register(RouteSpec(
        path="/api/v1/organizations/{organization_id}",
        methods=frozenset({"GET"}),
        handler=get_organization,
        operation_id="getOrganization",
        summary="Read tenant-owned organization profile, preferences, and lifecycle metadata",
        tags=("organizations",),
        permission="organization.read",
        scope_kind="organization",
        scope_parameter="organization_id",
        response_schema={"type": "object"},
        responses={"200": "Organization profile and lifecycle metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/organizations/{organization_id}",
        methods=frozenset({"PATCH"}),
        handler=update_organization,
        operation_id="updateOrganization",
        summary="Update an authorized organization profile",
        tags=("organizations",),
        permission="organization.update",
        scope_kind="organization",
        scope_parameter="organization_id",
        request_schema={
            "type": "object",
            "required": ["name"],
            "additionalProperties": False,
            "properties": {"name": {"type": "string", "minLength": 1, "maxLength": 128}},
        },
        response_schema={"type": "object"},
        responses={"200": "Updated organization profile", "409": "Organization name conflicts"},
    ))
    router.register(RouteSpec(
        path="/api/v1/organizations/{organization_id}/preferences",
        methods=frozenset({"GET"}),
        handler=get_preferences,
        operation_id="getOrganizationPreferences",
        summary="Read persisted timezone and locale preferences with explicit defaults",
        tags=("organizations", "preferences"),
        permission="organization.read",
        scope_kind="organization",
        scope_parameter="organization_id",
        response_schema={"type": "object"},
        responses={"200": "Organization preferences"},
    ))
    router.register(RouteSpec(
        path="/api/v1/organizations/{organization_id}/preferences",
        methods=frozenset({"PATCH"}),
        handler=update_preferences,
        operation_id="updateOrganizationPreferences",
        summary="Persist validated organization timezone and locale preferences",
        tags=("organizations", "preferences"),
        permission="organization.update",
        scope_kind="organization",
        scope_parameter="organization_id",
        request_schema={
            "type": "object",
            "minProperties": 1,
            "additionalProperties": False,
            "properties": {
                "timezone": {"type": "string", "maxLength": 64},
                "locale": {"type": "string", "maxLength": 35},
            },
        },
        response_schema={"type": "object"},
        responses={"200": "Updated organization preferences"},
    ))
    router.register(RouteSpec(
        path="/api/v1/organizations/{organization_id}/security-posture",
        methods=frozenset({"GET"}),
        handler=get_security_posture,
        operation_id="getOrganizationSecurityPosture",
        summary="Read the existing organization MFA policy and configuration state",
        tags=("organizations", "security"),
        permission="identity.policy.read",
        scope_kind="organization",
        scope_parameter="organization_id",
        response_schema={"type": "object"},
        responses={"200": "Organization MFA posture"},
    ))
    router.register(RouteSpec(
        path="/api/v1/organizations/{organization_id}/security-posture",
        methods=frozenset({"PATCH"}),
        handler=update_security_posture,
        operation_id="updateOrganizationSecurityPosture",
        summary="Update the existing MFA policy with optimistic version checking",
        tags=("organizations", "security"),
        permission="identity.policy.update",
        scope_kind="organization",
        scope_parameter="organization_id",
        request_schema={
            "type": "object",
            "required": ["policy"],
            "additionalProperties": False,
            "properties": {
                "version": {"type": "integer", "minimum": 0},
                "policy": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "mode": {"type": "string", "enum": ["optional", "roles", "required"]},
                        "roles": {"type": "array", "maxItems": 10, "items": {"type": "string"}},
                        "step_up_ttl": {"type": "integer", "minimum": 60, "maximum": 3600},
                        "require_recent": {"type": "integer", "minimum": 60, "maximum": 86400},
                    },
                },
            },
        },
        response_schema={"type": "object"},
        responses={"200": "Updated MFA posture", "409": "Policy version conflicts"},
    ))


__all__ = ["register"]
