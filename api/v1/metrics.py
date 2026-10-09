"""Tenant-safe aggregate operational metrics derived from persisted records."""

from __future__ import annotations

from typing import Any

from api.errors import ApiException, ApiProblem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


_ACTIVE_SCAN_STATUSES = ("pending", "queued", "running", "paused", "cancelling")
_ACTIVE_JOB_STATUSES = ("created", "queued", "running", "paused", "retry_wait", "cancelling")
_OPEN_FINDING_STATUSES = ("open", "acknowledged", "reopened")


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _count(services: Any, sql: str, parameters: tuple[Any, ...]) -> int:
    row = services.platform.db.query_one(sql, parameters)
    value = row.get("count", 0)
    return int(value) if isinstance(value, (int, float)) and value >= 0 else 0


def register(router: ApiRouter) -> None:
    services = router.services

    def tenant_metrics(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)

        tenant_parameter = (tenant_id,)
        active_scan_parameters = (tenant_id,) + _ACTIVE_SCAN_STATUSES
        active_job_parameters = (tenant_id,) + _ACTIVE_JOB_STATUSES
        open_finding_parameters = (tenant_id,) + _OPEN_FINDING_STATUSES
        metrics = {
            "projects": _count(
                services,
                "SELECT COUNT(*) AS count FROM projects WHERE org_id=?",
                tenant_parameter,
            ),
            "assets": _count(
                services,
                "SELECT COUNT(*) AS count FROM assets a "
                "JOIN projects p ON p.id=a.project_id WHERE p.org_id=?",
                tenant_parameter,
            ),
            "findings": _count(
                services,
                "SELECT COUNT(*) AS count FROM findings f "
                "JOIN projects p ON p.id=f.project_id WHERE p.org_id=?",
                tenant_parameter,
            ),
            "open_findings": _count(
                services,
                "SELECT COUNT(*) AS count FROM findings f "
                "JOIN projects p ON p.id=f.project_id WHERE p.org_id=? "
                "AND f.lifecycle IN (?,?,?)",
                open_finding_parameters,
            ),
            "scans": _count(
                services,
                "SELECT COUNT(*) AS count FROM scans s "
                "JOIN projects p ON p.id=s.project_id WHERE p.org_id=?",
                tenant_parameter,
            ),
            "active_scans": _count(
                services,
                "SELECT COUNT(*) AS count FROM scans s "
                "JOIN projects p ON p.id=s.project_id WHERE p.org_id=? "
                "AND s.status IN (?,?,?,?,?)",
                active_scan_parameters,
            ),
            "jobs": _count(
                services,
                "SELECT COUNT(*) AS count FROM jobs WHERE org_id=?",
                tenant_parameter,
            ),
            "active_jobs": _count(
                services,
                "SELECT COUNT(*) AS count FROM jobs WHERE org_id=? "
                "AND status IN (?,?,?,?,?,?)",
                active_job_parameters,
            ),
            "integrations": _count(
                services,
                "SELECT COUNT(*) AS count FROM external_integrations WHERE org_id=? "
                "AND connector_kind != ''",
                tenant_parameter,
            ),
            "enabled_integrations": _count(
                services,
                "SELECT COUNT(*) AS count FROM external_integrations WHERE org_id=? "
                "AND connector_kind != '' AND status='enabled'",
                tenant_parameter,
            ),
            "cloud_accounts": _count(
                services,
                "SELECT COUNT(*) AS count FROM cloud_accounts WHERE org_id=?",
                tenant_parameter,
            ),
            "enabled_cloud_accounts": _count(
                services,
                "SELECT COUNT(*) AS count FROM cloud_accounts WHERE org_id=? "
                "AND enabled=1",
                tenant_parameter,
            ),
            "audit_events": _count(
                services,
                "SELECT COUNT(*) AS count FROM audit_events WHERE org_id=?",
                tenant_parameter,
            ),
        }
        return HttpResponse(200, {
            "data": {
                "tenant_id": tenant_id,
                "scope": "tenant_aggregate",
                "source": "persisted_tenant_records",
                "metrics": metrics,
            }
        })

    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/metrics",
        methods=frozenset({"GET"}),
        handler=tenant_metrics,
        operation_id="getTenantMetrics",
        summary="Read aggregate operational metrics for one tenant",
        tags=("metrics", "monitoring"),
        permission="analytics.read",
        scope_kind="organization",
        scope_parameter="tenant_id",
        response_schema={"type": "object"},
        responses={"200": "Tenant-scoped aggregate counts"},
    ))


__all__ = ["register"]
