"""Bounded asset discovery history and inventory APIs over real stored data.

Discovery jobs are existing scan/job records. Creation is delegated to the
canonical project scan API; this module never invents results or starts a
second scanner/work queue.
"""

from __future__ import annotations

import math
import re
from typing import Any

import models
import redact
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_DISCOVERY_PROFILES = frozenset({"recon", "crawler", "port-scan", "cloud-inventory"})
_MAX_WINDOW = 500


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


def _asset_view(asset: Any) -> dict[str, Any]:
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    raw_source = metadata.get("source", metadata.get("discovery_source", ""))
    raw_owner = metadata.get("owner", metadata.get("owner_id", metadata.get("owner_user_id", "")))
    source = str(redact.redact_text(raw_source))[:128] if isinstance(raw_source, (str, int)) else ""
    owner = str(redact.redact_text(raw_owner))[:128] if isinstance(raw_owner, (str, int)) else ""
    return {
        "id": str(asset.id),
        "project_id": str(asset.project_id),
        "asset_type": str(asset.asset_type),
        "value": str(redact.redact_text(asset.value))[:2048],
        "display": str(redact.redact_text(asset.display))[:2048],
        "status": str(asset.status),
        "owner": owner,
        "ownership_status": "KNOWN" if owner else "UNSPECIFIED",
        "source": source,
        "source_attribution_status": "KNOWN" if source else "UNSPECIFIED",
        "first_seen": str(asset.first_seen),
        "last_seen": str(asset.last_seen),
    }


def _safe_profile(value: Any) -> str:
    profile = str(value or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile):
        return "unknown"
    return profile


def _job_view(job: Any) -> dict[str, Any]:
    error_code = str(getattr(job, "error_code", ""))
    if not error_code.replace("_", "").isalnum() or len(error_code) > 64:
        error_code = ""
    return {
        "id": str(job.id),
        "scan_id": str(job.scan_id),
        "profile": _safe_profile(job.profile),
        "status": str(job.status),
        "priority": str(job.priority),
        "attempt": int(job.attempt),
        "max_attempts": int(job.max_attempts),
        "created_at": str(job.created_at),
        "queued_at": str(job.queued_at),
        "started_at": str(job.started_at),
        "finished_at": str(job.finished_at),
        "error_code": error_code,
        "result_reference_available": bool(str(job.result_reference or "")),
    }


def _scan_view(scan: Any, jobs: list[Any]) -> dict[str, Any]:
    try:
        progress = float(scan.progress)
    except (TypeError, ValueError, OverflowError):
        progress = 0.0
    if not math.isfinite(progress):
        progress = 0.0
    progress = min(1.0, max(0.0, progress))
    summary = scan.summary if isinstance(scan.summary, dict) else {}
    safe_summary: dict[str, Any] = {}
    for key in ("assets", "findings"):
        value = summary.get(key)
        if type(value) is int and 0 <= value <= 1_000_000:
            safe_summary[key] = value
    risk_score = summary.get("risk_score")
    if type(risk_score) in (int, float) and math.isfinite(float(risk_score)):
        safe_summary["risk_score"] = risk_score
    risk_level = str(summary.get("risk_level", "")).casefold()
    if risk_level in {"info", "low", "medium", "high", "critical", "unknown"}:
        safe_summary["risk_level"] = risk_level
    return {
        "id": str(scan.id),
        "project_id": str(scan.project_id),
        "profile": _safe_profile(scan.profile),
        "scope_reference_available": bool(str(scan.scope_ref or "")),
        "status": str(scan.status),
        "created_at": str(scan.created_at),
        "started_at": str(scan.started_at),
        "finished_at": str(scan.finished_at),
        "progress": progress,
        "summary": safe_summary,
        "jobs": [_job_view(job) for job in sorted(
            jobs, key=lambda item: (item.created_at, item.id), reverse=True
        )],
    }


def _jobs_by_scan(services: Any, context: Any, project_id: str) -> tuple[dict[str, list[Any]], str]:
    if services.jobs is None:
        return {}, "NOT_CONFIGURED"
    jobs = services.jobs.job_list(
        project_id=project_id, org_id=context.org_id, limit=1000
    )
    result: dict[str, list[Any]] = {}
    for job in jobs:
        if job.org_id == context.org_id and job.project_id == project_id:
            result.setdefault(job.scan_id, []).append(job)
    return result, "AVAILABLE"


def _profiles(services: Any) -> list[dict[str, str]]:
    if services.jobs is None:
        return []
    result = []
    for name in sorted(_DISCOVERY_PROFILES):
        try:
            profile = services.jobs.registry.get(name)
        except Exception:
            continue
        result.append({"name": name, "description": str(profile.description)[:300]})
    return result


def register(router: ApiRouter) -> None:
    services = router.services

    def discovery_summary(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset())
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        extra = services.extra if isinstance(services.extra, dict) else {}
        asset_service = extra.get("asset_service")
        assets = (
            asset_service.list_assets(context.org_id, project_id, limit=500)
            if asset_service is not None
            else services.platform.asset_list(project_id, limit=500)
        )
        scans = services.platform.scan_list(project_id, limit=501)
        discovery_scans = [scan for scan in scans if scan.profile in _DISCOVERY_PROFILES]
        by_scan, job_state = _jobs_by_scan(services, context, project_id)
        capped = len(scans) > 500 or len(assets) == 500
        return HttpResponse(200, {
            "data": {
                "project_id": project_id,
                "state": "AVAILABLE" if services.jobs is not None else "NOT_CONFIGURED",
                "assets": [_asset_view(asset) for asset in assets],
                "discovery_jobs": [_scan_view(scan, by_scan.get(scan.id, [])) for scan in discovery_scans[:500]],
                "supported_profiles": _profiles(services),
                "job_state": job_state,
                "job_submission": {
                    "state": "SUPPORTED_VIA_SCAN_API" if services.jobs is not None else "NOT_CONFIGURED",
                    "route": f"/api/v1/projects/{project_id}/scans",
                },
                "truncated": capped,
            },
            "count": len(assets),
        })

    def list_discovery_assets(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset({"limit", "offset"}))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        limit = _integer(request, "limit", 50, 1, 100)
        offset = _integer(request, "offset", 0, 0, _MAX_WINDOW - 1)
        if offset + limit > _MAX_WINDOW:
            raise ApiException(validation_problem(
                field="pagination", code="out_of_range", message="The asset result window is limited"
            ))
        extra = services.extra if isinstance(services.extra, dict) else {}
        asset_service = extra.get("asset_service")
        assets = (
            asset_service.list_assets(
                context.org_id, project_id, limit=_MAX_WINDOW
            )
            if asset_service is not None
            else services.platform.asset_list(project_id, limit=_MAX_WINDOW)
        )
        page = assets[offset:offset + limit]
        return HttpResponse(200, {
            "data": [_asset_view(asset) for asset in page],
            "count": len(page),
            "limit": limit,
            "offset": offset,
            "truncated": len(assets) == _MAX_WINDOW,
        })

    def list_discovery_jobs(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset({"limit", "offset", "status", "profile"}))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        limit = _integer(request, "limit", 50, 1, 100)
        offset = _integer(request, "offset", 0, 0, _MAX_WINDOW - 1)
        if offset + limit > _MAX_WINDOW:
            raise ApiException(validation_problem(
                field="pagination", code="out_of_range", message="The discovery history window is limited"
            ))
        status = request.query.get("status", [""])[0]
        if status and status not in models.SCAN_STATUSES:
            raise ApiException(validation_problem(
                field="status", code="invalid", message="Scan status is not supported"
            ))
        profile = request.query.get("profile", [""])[0]
        if profile and profile not in _DISCOVERY_PROFILES:
            raise ApiException(validation_problem(
                field="profile", code="invalid", message="Discovery profile is not supported"
            ))
        scans = services.platform.scan_list(project_id, limit=_MAX_WINDOW + 1)
        scans = [scan for scan in scans if scan.profile in _DISCOVERY_PROFILES]
        if status:
            scans = [scan for scan in scans if scan.status == status]
        if profile:
            scans = [scan for scan in scans if scan.profile == profile]
        truncated = len(scans) > _MAX_WINDOW
        scans = scans[:_MAX_WINDOW]
        by_scan, job_state = _jobs_by_scan(services, context, project_id)
        page = scans[offset:offset + limit]
        return HttpResponse(200, {
            "data": [_scan_view(scan, by_scan.get(scan.id, [])) for scan in page],
            "count": len(page),
            "total": len(scans),
            "limit": limit,
            "offset": offset,
            "truncated": truncated,
            "job_state": job_state,
        })

    def get_discovery_job(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        scan = services.authorization.require_scan(context, params["scan_id"])
        if scan.project_id != project_id:
            raise ApiException(ApiProblem(404, "not_found", "Resource not found"))
        if scan.profile not in _DISCOVERY_PROFILES:
            raise ApiException(ApiProblem(404, "not_found", "Resource not found"))
        by_scan, job_state = _jobs_by_scan(services, context, project_id)
        return HttpResponse(200, {
            "data": {
                "discovery_job": _scan_view(scan, by_scan.get(scan.id, [])),
                "job_state": job_state,
            }
        })

    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/assets/discovery",
        methods=frozenset({"GET"}),
        handler=discovery_summary,
        operation_id="getAssetDiscoverySummary",
        summary="Read actual project assets and discovery scan history from persisted records",
        tags=("assets", "discovery"),
        permission="asset.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Bounded discovery summary"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/assets/discovery/assets",
        methods=frozenset({"GET"}),
        handler=list_discovery_assets,
        operation_id="listDiscoveredAssets",
        summary="List bounded project-owned assets with recorded ownership/source attribution",
        tags=("assets", "discovery"),
        permission="asset.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Discovered asset page"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/assets/discovery/jobs",
        methods=frozenset({"GET"}),
        handler=list_discovery_jobs,
        operation_id="listAssetDiscoveryJobs",
        summary="List persisted discovery scan/job history using supported scanner profiles",
        tags=("assets", "discovery", "scans"),
        permission="scan.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Bounded discovery job page"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/assets/discovery/jobs/{scan_id}",
        methods=frozenset({"GET"}),
        handler=get_discovery_job,
        operation_id="getAssetDiscoveryJob",
        summary="Read a tenant-authorized discovery scan and its real job state",
        tags=("assets", "discovery", "scans"),
        permission="scan.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Discovery job details", "404": "Discovery job not found"},
    ))


__all__ = ["register"]
