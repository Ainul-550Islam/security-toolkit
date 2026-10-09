"""Tenant-safe project lifecycle and authorized-scope APIs."""

from __future__ import annotations

from typing import Any

from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


_PAGE_LIMIT = 100
_MAX_OFFSET = 900


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


def _page(request: HttpRequest, key: str, default: int, maximum: int) -> int:
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


def _project_view(project: Any) -> dict[str, Any]:
    return {
        "id": str(project.id),
        "org_id": str(project.org_id),
        "name": str(project.name),
        "description": str(project.description)[:2000],
        "status": str(project.status),
        "created_at": str(project.created_at),
        "updated_at": str(project.updated_at),
    }


def _resources(services: Any) -> Any:
    extra = services.extra if isinstance(services.extra, dict) else {}
    service = extra.get("customer_resources")
    if service is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The project resource service is not configured"))
    return service


def _name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 128:
        raise ApiException(validation_problem(
            field=field, code="invalid", message="Value must contain 1 to 128 characters"
        ))
    return value.strip()


def register(router: ApiRouter) -> None:
    services = router.services

    def list_projects(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset({"limit", "offset"}))
        context = _context(request)
        services.authorization.require_org(context, context.org_id)
        limit = _page(request, "limit", 50, _PAGE_LIMIT)
        offset = _page(request, "offset", 0, _MAX_OFFSET)
        projects = services.authorization.visible_projects(context)
        projects = sorted(
            projects,
            key=lambda project: (str(project.created_at), str(project.id)),
            reverse=True,
        )
        page = projects[offset:offset + limit]
        return HttpResponse(200, {
            "data": [_project_view(project) for project in page],
            "count": len(page),
            "total": len(projects),
            "limit": limit,
            "offset": offset,
        })

    def create_project(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"name", "description"}))
        name = _name(body.get("name"), "name")
        description = body.get("description", "")
        if not isinstance(description, str) or len(description) > 2000:
            raise ApiException(validation_problem(
                field="description", code="invalid", message="Description exceeds the allowed length"
            ))
        context = _context(request)
        services.authorization.require_org(context, context.org_id)
        project = services.platform.project_create(
            context.org_id,
            name,
            description=description,
            actor=context.label(),
        )
        return HttpResponse(201, {"data": _project_view(project)})

    def get_project(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        project = services.authorization.require_project(context, params["project_id"])
        return HttpResponse(200, {"data": _project_view(project)})

    def update_project(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"name", "description", "status"}))
        if not body:
            raise ApiException(validation_problem(
                field="request", code="empty", message="At least one project field is required"
            ))
        changes: dict[str, Any] = {}
        if "name" in body:
            changes["name"] = _name(body["name"], "name")
        if "description" in body:
            if not isinstance(body["description"], str) or len(body["description"]) > 2000:
                raise ApiException(validation_problem(
                    field="description", code="invalid", message="Description exceeds the allowed length"
                ))
            changes["description"] = body["description"]
        if "status" in body:
            status = body["status"]
            if not isinstance(status, str) or status not in {"active", "paused"}:
                raise ApiException(validation_problem(
                    field="status", code="invalid", message="Use active or paused; archive through the archive operation"
                ))
            changes["status"] = status
        context = _context(request)
        services.authorization.require_project(context, params["project_id"])
        updated = _resources(services).project_update(
            context.org_id,
            params["project_id"],
            changes,
            actor=context.label(),
        )
        return HttpResponse(200, {"data": _project_view(updated)})

    def archive_project(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        services.authorization.require_project(context, params["project_id"])
        updated = _resources(services).project_archive(
            context.org_id, params["project_id"], actor=context.label()
        )
        return HttpResponse(200, {"data": _project_view(updated)})

    def restore_project(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        services.authorization.require_project(context, params["project_id"])
        updated = _resources(services).project_restore(
            context.org_id, params["project_id"], actor=context.label()
        )
        return HttpResponse(200, {"data": _project_view(updated)})

    def get_scope(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        project = services.authorization.require_project(context, params["project_id"])
        scope = services.platform.scope_get(project.id)
        return HttpResponse(200, {
            "data": {
                "project_id": project.id,
                "org_id": project.org_id,
                "allow": scope.to_dict()["allow"],
                "deny": scope.to_dict()["deny"],
            }
        })

    def update_scope(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"allow", "deny"}))
        if set(body) != {"allow", "deny"}:
            raise ApiException(validation_problem(
                field="request", code="required", message="Both allow and deny lists are required"
            ))
        for field in ("allow", "deny"):
            values = body[field]
            if not isinstance(values, list) or len(values) > 500:
                raise ApiException(validation_problem(
                    field=field, code="invalid", message="Scope entries must be a bounded list"
                ))
            if any(not isinstance(value, str) or not 1 <= len(value) <= 512 for value in values):
                raise ApiException(validation_problem(
                    field=field, code="invalid", message="Each scope entry must be a bounded string"
                ))
        context = _context(request)
        project = services.authorization.require_project(context, params["project_id"])
        scope = services.platform.scope_set(
            project.id, body["allow"], body["deny"], actor=context.label()
        )
        return HttpResponse(200, {"data": {"project_id": project.id, **scope}})

    router.register(RouteSpec(
        path="/api/v1/projects",
        methods=frozenset({"GET"}),
        handler=list_projects,
        operation_id="listProjects",
        summary="List only projects visible to the authenticated tenant principal",
        tags=("projects",),
        permission="project.read",
        response_schema={"type": "object"},
        responses={"200": "Bounded visible project page"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects",
        methods=frozenset({"POST"}),
        handler=create_project,
        operation_id="createProject",
        summary="Create a project in the authenticated tenant",
        tags=("projects",),
        permission="project.create",
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
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}",
        methods=frozenset({"GET"}),
        handler=get_project,
        operation_id="getProject",
        summary="Read a project after project and tenant authorization",
        tags=("projects",),
        permission="project.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Project metadata", "403": "Project is outside the caller's scope"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}",
        methods=frozenset({"PATCH"}),
        handler=update_project,
        operation_id="updateProject",
        summary="Update an authorized project profile or active/paused state",
        tags=("projects",),
        permission="project.update",
        scope_kind="project",
        scope_parameter="project_id",
        request_schema={
            "type": "object",
            "minProperties": 1,
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "description": {"type": "string", "maxLength": 2000},
                "status": {"type": "string", "enum": ["active", "paused"]},
            },
        },
        response_schema={"type": "object"},
        responses={"200": "Updated project", "409": "Project name conflicts"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/archive",
        methods=frozenset({"POST"}),
        handler=archive_project,
        operation_id="archiveProject",
        summary="Archive, without deleting, an authorized project",
        tags=("projects",),
        permission="project.delete",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Archived project"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/restore",
        methods=frozenset({"POST"}),
        handler=restore_project,
        operation_id="restoreProject",
        summary="Restore an archived project to active status",
        tags=("projects",),
        permission="project.update",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Restored project"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/scope",
        methods=frozenset({"GET"}),
        handler=get_scope,
        operation_id="getProjectScope",
        summary="Read the explicit allow/deny scope for one project",
        tags=("projects", "scope"),
        permission="scope.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Project scope rules"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/scope",
        methods=frozenset({"PUT"}),
        handler=update_scope,
        operation_id="updateProjectScope",
        summary="Replace the bounded project allow/deny scope with an audited change",
        tags=("projects", "scope"),
        permission="scope.update",
        scope_kind="project",
        scope_parameter="project_id",
        request_schema={
            "type": "object",
            "required": ["allow", "deny"],
            "additionalProperties": False,
            "properties": {
                "allow": {"type": "array", "maxItems": 500, "items": {"type": "string", "maxLength": 512}},
                "deny": {"type": "array", "maxItems": 500, "items": {"type": "string", "maxLength": 512}},
            },
        },
        response_schema={"type": "object"},
        responses={"200": "Updated project scope"},
    ))


__all__ = ["register"]
