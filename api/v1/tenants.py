"""Tenant-scoped organization and project read APIs."""

from __future__ import annotations

from typing import Any

from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _object_body(request: HttpRequest, allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(request.body, dict):
        raise ApiException(validation_problem(
            field="request", code="invalid_type", message="A JSON object is required"
        ))
    unknown = set(request.body) - allowed
    if unknown:
        raise ApiException(validation_problem(
            field="request", code="unknown_field", message="Unexpected field"
        ))
    return request.body


def _project_view(project: Any) -> dict[str, Any]:
    return {
        "id": project.id,
        "org_id": project.org_id,
        "name": project.name,
        "description": project.description,
        "status": project.status,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
    }


def register(router: ApiRouter) -> None:
    """Register the implemented tenant read surface and existing project operations."""
    services = router.services

    def list_current_tenant(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        tenant_id = request.context.tenant_id
        services.authorization.require_org(context, tenant_id)
        organization = services.platform.org_get(tenant_id)
        return HttpResponse(200, {"data": organization.to_dict()})

    def get_tenant(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        tenant_id = params["tenant_id"]
        services.authorization.require_org(_context(request), tenant_id)
        organization = services.platform.org_get(tenant_id)
        return HttpResponse(200, {"data": organization.to_dict()})

    def list_projects(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        tenant_id = params["tenant_id"]
        services.authorization.require_org(_context(request), tenant_id)
        projects = services.platform.project_list(tenant_id)
        return HttpResponse(200, {
            "data": [_project_view(project) for project in projects],
            "count": len(projects),
        })

    def create_project(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _object_body(request, frozenset({"name", "description"}))
        name = body.get("name")
        description = body.get("description", "")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 128:
            raise ApiException(validation_problem(
                field="name", code="invalid", message="A project name is required"
            ))
        if not isinstance(description, str) or len(description) > 2000:
            raise ApiException(validation_problem(
                field="description", code="invalid", message="Description exceeds the allowed length"
            ))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        project = services.platform.project_create(
            tenant_id,
            name.strip(),
            description=description,
            actor=context.label(),
        )
        return HttpResponse(201, {"data": _project_view(project)})

    router.register(RouteSpec(
        path="/api/v1/tenants",
        methods=frozenset({"GET"}),
        handler=list_current_tenant,
        operation_id="getCurrentTenant",
        summary="Read the authenticated principal's tenant",
        tags=("tenants",),
        permission="organization.read",
        response_schema={"type": "object"},
        responses={"200": "Tenant metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}",
        methods=frozenset({"GET"}),
        handler=get_tenant,
        operation_id="getTenant",
        summary="Read a tenant within the authenticated tenant boundary",
        tags=("tenants",),
        permission="organization.read",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "Tenant metadata", "403": "Tenant is outside the caller's scope"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/projects",
        methods=frozenset({"GET"}),
        handler=list_projects,
        operation_id="listTenantProjects",
        summary="List projects in one authorized tenant",
        tags=("tenants", "projects"),
        permission="project.read",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "Tenant projects"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/projects",
        methods=frozenset({"POST"}),
        handler=create_project,
        operation_id="createTenantProject",
        summary="Create a project in the authenticated tenant",
        tags=("tenants", "projects"),
        permission="project.create",
        scope_kind="organization",
        scope_parameter="tenant_id",
        request_schema={
            "type": "object",
            "required": ["name"],
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "description": {"type": "string", "maxLength": 2000},
            },
        },
        response_schema={"type": "object"},
        responses={"201": "Project created"},
    ))


__all__ = ["register"]
