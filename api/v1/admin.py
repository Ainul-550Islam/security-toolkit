"""Out-of-band platform-operator endpoints, isolated from tenant RBAC."""

from __future__ import annotations

import hmac
import os
import re
from typing import Any

from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


_ADMIN_TOKEN_ENV = "SECURITY_TOOLKIT_PLATFORM_ADMIN_TOKEN"
_ADMIN_TOKEN_HEADER = "x-platform-admin-token"
_ADMIN_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
def _authorize_operator(request: HttpRequest) -> None:
    configured = str(os.environ.get(_ADMIN_TOKEN_ENV, "") or "")
    presented = request.header(_ADMIN_TOKEN_HEADER, "")
    if not _ADMIN_TOKEN_RE.fullmatch(configured):
        raise ApiException(ApiProblem(
            503,
            "platform_admin_unavailable",
            "Platform operator access is not configured",
        ))
    if (
        not _ADMIN_TOKEN_RE.fullmatch(presented)
        or not hmac.compare_digest(presented, configured)
    ):
        raise ApiException(ApiProblem(
            401,
            "authentication_failed",
            "Platform operator authentication required or invalid",
        ))


def _empty_body(request: HttpRequest) -> None:
    if not isinstance(request.body, dict):
        raise ApiException(validation_problem(
            field="request", code="invalid_type", message="A JSON object is required"
        ))
    if request.body:
        raise ApiException(validation_problem(
            field="request", code="unknown_field", message="Unexpected field"
        ))


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
    minimum = 1 if key == "limit" else 0
    if not minimum <= value <= maximum:
        raise ApiException(validation_problem(
            field=key, code="out_of_range", message=f"{key} is outside the allowed range"
        ))
    return value


def _safe_label(value: Any, *, maximum: int = 96) -> str:
    candidate = str(value or "")[:maximum]
    return candidate if _SAFE_LABEL_RE.fullmatch(candidate) else ""


def _job_projection(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _safe_label(row.get("id")),
        "tenant_id": _safe_label(row.get("org_id")),
        "project_id": _safe_label(row.get("project_id")),
        "scan_id": _safe_label(row.get("scan_id")),
        "job_type": _safe_label(row.get("job_type")),
        "profile": _safe_label(row.get("profile")),
        "status": _safe_label(row.get("status")),
        "attempt": max(0, int(row.get("attempt", 0) or 0)),
        "max_attempts": max(0, int(row.get("max_attempts", 0) or 0)),
        "created_at": str(row.get("created_at", "") or "")[:40],
        "queued_at": str(row.get("queued_at", "") or "")[:40],
        "started_at": str(row.get("started_at", "") or "")[:40],
        "finished_at": str(row.get("finished_at", "") or "")[:40],
        "error_code": _safe_label(row.get("error_code"), maximum=64),
    }


def _job_model_projection(job: Any) -> dict[str, Any]:
    return _job_projection({
        "id": getattr(job, "id", ""),
        "org_id": getattr(job, "org_id", ""),
        "project_id": getattr(job, "project_id", ""),
        "scan_id": getattr(job, "scan_id", ""),
        "job_type": getattr(job, "job_type", ""),
        "profile": getattr(job, "profile", ""),
        "status": getattr(job, "status", ""),
        "attempt": getattr(job, "attempt", 0),
        "max_attempts": getattr(job, "max_attempts", 0),
        "created_at": getattr(job, "created_at", ""),
        "queued_at": getattr(job, "queued_at", ""),
        "started_at": getattr(job, "started_at", ""),
        "finished_at": getattr(job, "finished_at", ""),
        "error_code": getattr(job, "error_code", ""),
    })


def register(router: ApiRouter) -> None:
    services = router.services

    def operator_health(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        _authorize_operator(request)
        return HttpResponse(200, {"data": services.health.full_report()})

    def operator_features(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        _authorize_operator(request)
        return HttpResponse(200, {"data": services.capabilities.metadata()})

    def list_platform_jobs(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        _authorize_operator(request)
        _query(request, frozenset({"status", "limit", "offset"}))
        status = request.query.get("status", [""])[0]
        if status:
            from models import JOB_STATUSES

            if status not in JOB_STATUSES:
                raise ApiException(validation_problem(
                    field="status", code="invalid", message="status is not supported"
                ))
        limit = _page(request, "limit", 100, 500)
        offset = _page(request, "offset", 0, 100_000)
        where = " WHERE status=?" if status else ""
        parameters: tuple[Any, ...] = (status,) if status else ()
        count_rows = services.platform.db.query(
            "SELECT COUNT(*) AS count FROM jobs" + where,
            parameters,
            limit=1,
        )
        rows = services.platform.db.query(
            "SELECT id, org_id, project_id, scan_id, job_type, profile, status, "
            "attempt, max_attempts, created_at, queued_at, started_at, "
            "finished_at, error_code FROM jobs" + where
            + " ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
            parameters + (limit, offset),
        )
        total = int(count_rows[0].get("count", 0)) if count_rows else 0
        return HttpResponse(200, {
            "data": [_job_projection(row) for row in rows],
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
        })

    def integration_diagnostics(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        _authorize_operator(request)
        if services.integrations is None:
            raise ApiException(ApiProblem(
                503,
                "service_not_configured",
                "The integration service is not configured",
            ))
        rows = services.platform.db.query(
            "SELECT status, health_state, COUNT(*) AS count "
            "FROM external_integrations WHERE connector_kind != '' "
            "GROUP BY status, health_state",
            limit=100,
        )
        summary = {
            "total": 0,
            "enabled": 0,
            "disabled": 0,
            "health_states": {
                "unchecked": 0,
                "healthy": 0,
                "degraded": 0,
                "misconfigured": 0,
                "disabled": 0,
                "rate_limited": 0,
                "unreachable": 0,
                "unsupported": 0,
                "unknown": 0,
            },
        }
        known_statuses = {"enabled", "disabled"}
        for row in rows:
            count = max(0, int(row.get("count", 0) or 0))
            summary["total"] += count
            status = str(row.get("status", "") or "")
            if status in known_statuses:
                summary[status] += count
            health_state = str(row.get("health_state", "") or "")
            if not health_state:
                target_state = "unchecked"
            elif health_state in summary["health_states"]:
                target_state = health_state
            else:
                target_state = "unknown"
            summary["health_states"][target_state] += count
        return HttpResponse(200, {"data": summary})

    def retry_platform_job(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _authorize_operator(request)
        _empty_body(request)
        if services.jobs is None:
            raise ApiException(ApiProblem(
                503,
                "service_not_configured",
                "The job service is not configured",
            ))
        job = services.jobs.retry_manual(
            params["job_id"], actor="platform_admin_key"
        )
        return HttpResponse(202, {"data": _job_model_projection(job)})

    def sweep_stale_jobs(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        _authorize_operator(request)
        _empty_body(request)
        if services.jobs is None:
            raise ApiException(ApiProblem(
                503,
                "service_not_configured",
                "The job service is not configured",
            ))
        reclaimed = int(services.jobs.sweep_stale(actor="platform_admin_key"))
        services.platform.audit(
            "platform.maintenance.jobs_swept",
            object_type="job_queue",
            object_id="global",
            actor="platform_admin_key",
            metadata={"reclaimed": max(0, reclaimed)},
        )
        return HttpResponse(200, {"data": {"reclaimed": max(0, reclaimed)}})

    shared = {
        "auth_required": False,
        "security_scheme": "platformAdminKey",
        "tags": ("platform-admin",),
    }
    routes = (
        RouteSpec(
            path="/api/v1/admin/health",
            methods=frozenset({"GET"}),
            handler=operator_health,
            operation_id="getPlatformAdminHealth",
            summary="Read operator-only health diagnostics",
            response_schema={"type": "object"},
            responses={"200": "Safe platform health report", "503": "Operator key is not configured"},
            **shared,
        ),
        RouteSpec(
            path="/api/v1/admin/features",
            methods=frozenset({"GET"}),
            handler=operator_features,
            operation_id="getPlatformAdminFeatures",
            summary="Read resolved platform capabilities and feature availability",
            response_schema={"type": "object"},
            responses={"200": "Platform capability summary", "503": "Operator key is not configured"},
            **shared,
        ),
        RouteSpec(
            path="/api/v1/admin/jobs",
            methods=frozenset({"GET"}),
            handler=list_platform_jobs,
            operation_id="listPlatformAdminJobs",
            summary="List bounded cross-tenant job metadata without payloads or raw errors",
            response_schema={"type": "object"},
            responses={"200": "Safe platform job metadata", "503": "Operator key is not configured"},
            **shared,
        ),
        RouteSpec(
            path="/api/v1/admin/integration-diagnostics",
            methods=frozenset({"GET"}),
            handler=integration_diagnostics,
            operation_id="getPlatformIntegrationDiagnostics",
            summary="Read aggregate integration health counts without tenant details or credentials",
            response_schema={"type": "object"},
            responses={"200": "Aggregate integration diagnostics", "503": "Service unavailable"},
            **shared,
        ),
        RouteSpec(
            path="/api/v1/admin/jobs/{job_id}/retry",
            methods=frozenset({"POST"}),
            handler=retry_platform_job,
            operation_id="retryPlatformAdminJob",
            summary="Retry a failed platform job through the existing job service",
            request_schema={"type": "object", "additionalProperties": False},
            response_schema={"type": "object"},
            responses={"202": "Retry queued", "503": "Operator key or job service unavailable"},
            **shared,
        ),
        RouteSpec(
            path="/api/v1/admin/maintenance/jobs/sweep-stale",
            methods=frozenset({"POST"}),
            handler=sweep_stale_jobs,
            operation_id="sweepStalePlatformJobs",
            summary="Run the existing bounded stale-job recovery operation",
            request_schema={"type": "object", "additionalProperties": False},
            response_schema={"type": "object"},
            responses={"200": "Stale jobs processed", "503": "Operator key or job service unavailable"},
            **shared,
        ),
    )
    for route in routes:
        router.register(route)


__all__ = ["register"]
