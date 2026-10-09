"""Project-scoped dashboard and analytics read APIs."""

from __future__ import annotations

from typing import Any

from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def register(router: ApiRouter) -> None:
    services = router.services

    def bundle(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.analytics is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The analytics service is not configured"))
        allowed = {"cutoff", "start", "end"}
        if set(request.query) - allowed:
            raise ApiException(validation_problem(
                field="query", code="unknown_parameter", message="Unexpected query parameter"
            ))
        if any(len(values) > 1 for values in request.query.values()):
            raise ApiException(validation_problem(
                field="query", code="duplicate_parameter", message="Specify each parameter at most once"
            ))
        project_id = params["project_id"]
        services.authorization.require_project(_context(request), project_id)
        cutoff = request.query.get("cutoff", [""])[0]
        start = request.query.get("start", [""])[0]
        end = request.query.get("end", [""])[0]
        result = services.analytics.bundle(
            project_id,
            cutoff=cutoff,
            start=start,
            end=end,
        )
        return HttpResponse(200, {"data": result})

    for path, operation_id, summary in (
        ("/api/v1/projects/{project_id}/analytics", "getProjectAnalytics", "Read bounded project analytics"),
        ("/api/v1/projects/{project_id}/dashboard", "getProjectDashboard", "Read the existing analytics bundle for the dashboard"),
    ):
        router.register(RouteSpec(
            path=path,
            methods=frozenset({"GET"}),
            handler=bundle,
            operation_id=operation_id,
            summary=summary,
            tags=("analytics", "dashboard"),
            permission="analytics.read",
            scope_kind="project",
            scope_parameter="project_id",
            response_schema={"type": "object"},
            responses={"200": "Project analytics"},
        ))


__all__ = ["register"]
