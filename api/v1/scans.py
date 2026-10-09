"""Asynchronous project-scoped scan APIs backed by the existing job engine."""

from __future__ import annotations

import math
import re
from typing import Any

import models
from api.errors import ApiException, ApiProblem, validation_problem
from api.idempotency import IdempotencyStore
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_INTERNAL_PROFILES = frozenset({"federation-bulk", "integration-delivery", "report-generation"})
_MATERIAL_REQUIRED_PROFILES = frozenset({"container-scan", "kubernetes-scan", "iac-scan"})
_ERROR_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}$")


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


def _query_values(request: HttpRequest, allowed: frozenset[str]) -> None:
    if set(request.query) - allowed:
        raise ApiException(validation_problem(
            field="query", code="unknown_parameter", message="Unexpected query parameter"
        ))
    if any(len(values) > 1 for values in request.query.values()):
        raise ApiException(validation_problem(
            field="query", code="duplicate_parameter", message="Specify each parameter at most once"
        ))


def _limit(request: HttpRequest, *, default: int = 50, maximum: int = 200) -> int:
    values = request.query.get("limit", [])
    if not values:
        return default
    if len(values) != 1 or not values[0].isdigit():
        raise ApiException(validation_problem(
            field="limit", code="invalid", message="Limit must be an integer"
        ))
    limit = int(values[0])
    if not 1 <= limit <= maximum:
        raise ApiException(validation_problem(
            field="limit", code="out_of_range", message="Limit is outside the allowed range"
        ))
    return limit


def _job_view(job: Any) -> dict[str, Any]:
    error_code = str(getattr(job, "error_code", ""))
    if not _ERROR_CODE_RE.fullmatch(error_code):
        error_code = ""
    return {
        "id": job.id,
        "scan_id": job.scan_id,
        "profile": job.profile,
        "status": job.status,
        "priority": job.priority,
        "attempt": job.attempt,
        "max_attempts": job.max_attempts,
        "timeout_seconds": job.timeout_seconds,
        "created_at": job.created_at,
        "queued_at": job.queued_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error_code": error_code,
        "result_reference": str(job.result_reference)[:128],
    }


def _scan_view(platform: Any, scan: Any, jobs: list[Any]) -> dict[str, Any]:
    stages = platform.scan_stage_list(scan.id)
    safe_stages = []
    for stage in stages:
        code = str(stage.error_code or "")
        safe_stages.append({
            "stage": stage.stage,
            "status": stage.status,
            "attempt": stage.attempt,
            "created_at": stage.created_at,
            "started_at": stage.started_at,
            "finished_at": stage.finished_at,
            "error_code": code if _ERROR_CODE_RE.fullmatch(code) else "",
        })
    summary = scan.summary if isinstance(scan.summary, dict) else {}
    safe_summary = {}
    for key in ("profile", "stages", "completed_stages", "assets", "findings", "risk_score", "risk_level"):
        value = summary.get(key)
        if isinstance(value, (str, int, float, bool)) and not isinstance(value, (dict, list)):
            if isinstance(value, float) and not (-1_000_000 <= value <= 1_000_000):
                continue
            safe_summary[key] = value if not isinstance(value, str) else value[:128]
    scan_error = scan.error if isinstance(scan.error, dict) else {}
    error_code = str(scan_error.get("code", ""))
    latest_jobs = sorted(jobs, key=lambda item: (item.created_at, item.id), reverse=True)
    try:
        progress = float(scan.progress)
    except (TypeError, ValueError, OverflowError):
        progress = 0.0
    if not math.isfinite(progress):
        progress = 0.0
    progress = min(1.0, max(0.0, progress))
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "profile": scan.profile,
        "scope_ref": scan.scope_ref,
        "status": scan.status,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "progress": progress,
        "stages": safe_stages,
        "summary": safe_summary,
        "error_code": error_code if _ERROR_CODE_RE.fullmatch(error_code) else "",
        "jobs": [_job_view(job) for job in latest_jobs],
    }


def _get_jobs(services: Any, org_id: str, project_id: str, scan_id: str) -> list[Any]:
    if services.jobs is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The job service is not configured"))
    rows = services.jobs.job_list(project_id=project_id, org_id=org_id, limit=1000)
    return [job for job in rows if job.scan_id == scan_id and job.org_id == org_id and job.project_id == project_id]


def _job_for_action(services: Any, org_id: str, project_id: str, scan_id: str) -> Any:
    jobs = _get_jobs(services, org_id, project_id, scan_id)
    if not jobs:
        raise ApiException(ApiProblem(404, "not_found", "Resource not found"))
    jobs.sort(key=lambda item: (item.created_at, item.id), reverse=True)
    return jobs[0]


def register(router: ApiRouter) -> None:
    services = router.services

    def list_profiles(request: HttpRequest, _params: dict[str, str]) -> HttpResponse:
        if services.jobs is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The job service is not configured"))
        profiles = []
        for profile in services.jobs.registry.list_profiles():
            name = profile.get("name", "")
            profiles.append({
                "name": name,
                "description": str(profile.get("description", ""))[:300],
                "stages": list(profile.get("stages", [])),
                "active_required": bool(profile.get("active_required", False)),
                "timeout": int(profile.get("timeout", 0)),
                "in_process": bool(profile.get("in_process", False)),
                "permissions_required": list(profile.get("permissions_required", [])),
                "api_supported": name not in _INTERNAL_PROFILES | _MATERIAL_REQUIRED_PROFILES,
            })
        return HttpResponse(200, {"data": profiles, "count": len(profiles)})

    def list_scans(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query_values(request, frozenset({"limit", "status", "profile"}))
        project_id = params["project_id"]
        context = _context(request)
        services.authorization.require_project(context, project_id)
        statuses = request.query.get("status", [])
        profiles = request.query.get("profile", [])
        status = statuses[0] if statuses else ""
        profile = profiles[0] if profiles else ""
        if status and status not in models.SCAN_STATUSES:
            raise ApiException(validation_problem(
                field="status", code="invalid", message="Scan status is not supported"
            ))
        if profile and services.jobs is not None:
            if profile not in services.jobs.registry.PROFILES:
                raise ApiException(validation_problem(
                    field="profile", code="invalid", message="Scan profile is not supported"
                ))
        extra = services.extra if isinstance(services.extra, dict) else {}
        scan_service = extra.get("scan_service")
        if scan_service is not None:
            scans = scan_service.list_scans(
                context.org_id,
                project_id,
                status=status,
                profile=profile,
                limit=_limit(request),
            )
        else:
            scans = services.platform.scan_list(project_id, limit=_limit(request))
            if status:
                scans = [scan for scan in scans if scan.status == status]
            if profile:
                scans = [scan for scan in scans if scan.profile == profile]
        jobs = []
        if services.jobs is not None:
            jobs = services.jobs.job_list(project_id=project_id, org_id=context.org_id, limit=1000)
        by_scan: dict[str, list[Any]] = {}
        for job in jobs:
            if job.org_id == context.org_id and job.project_id == project_id:
                by_scan.setdefault(job.scan_id, []).append(job)
        return HttpResponse(200, {
            "data": [_scan_view(services.platform, scan, by_scan.get(scan.id, [])) for scan in scans],
            "count": len(scans),
        })

    def create_scan(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({
            "profile", "target", "payload", "active_enabled", "max_attempts", "timeout_seconds"
        }))
        profile_name = body.get("profile")
        if not isinstance(profile_name, str) or not 1 <= len(profile_name) <= 64:
            raise ApiException(validation_problem(
                field="profile", code="required", message="A supported scan profile is required"
            ))
        if services.jobs is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The job service is not configured"))
        try:
            profile = services.jobs.registry.get(profile_name)
        except Exception:
            raise ApiException(validation_problem(
                field="profile", code="invalid", message="Scan profile is not supported"
            )) from None
        if profile_name in _INTERNAL_PROFILES:
            raise ApiException(ApiProblem(
                501, "capability_unavailable", "This profile is available only through its dedicated service"
            ))
        if profile_name in _MATERIAL_REQUIRED_PROFILES:
            raise ApiException(ApiProblem(
                501, "capability_unavailable", "This profile requires a staged input API that is not configured"
            ))
        payload = body.get("payload", {})
        if not isinstance(payload, dict):
            raise ApiException(validation_problem(
                field="payload", code="invalid_type", message="Payload must be a JSON object"
            ))
        payload = dict(payload)
        if "target" in body:
            if "target" in payload:
                raise ApiException(validation_problem(
                    field="target", code="duplicate", message="Target must be supplied once"
                ))
            payload["target"] = body["target"]
        try:
            services.jobs.validate_payload(payload)
        except Exception:
            raise ApiException(validation_problem(
                field="payload", code="invalid", message="Payload is invalid for the job engine"
            )) from None
        active_enabled = body.get("active_enabled", False)
        if not isinstance(active_enabled, bool):
            raise ApiException(validation_problem(
                field="active_enabled", code="invalid_type", message="active_enabled must be a boolean"
            ))
        if profile.active_required and not active_enabled:
            raise ApiException(validation_problem(
                field="active_enabled", code="required", message="Active profiles require explicit authorization"
            ))
        if active_enabled and not profile.active_required:
            raise ApiException(validation_problem(
                field="active_enabled", code="not_allowed", message="This profile does not use active scanning"
            ))
        max_attempts = body.get("max_attempts", 3)
        if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
            raise ApiException(validation_problem(
                field="max_attempts", code="out_of_range", message="max_attempts must be between 1 and 5"
            ))
        timeout_seconds = body.get("timeout_seconds", int(profile.timeout))
        timeout_limit = min(3600, int(profile.timeout))
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= timeout_limit:
            raise ApiException(validation_problem(
                field="timeout_seconds", code="out_of_range", message="timeout_seconds must be within the profile's configured time limit"
            ))
        if profile.in_process:
            required_entity_fields = {
                "cloud-scan": "account_id",
                "cloud-inventory": "account_id",
            }
            required_field = required_entity_fields.get(profile_name, "")
            if required_field and not payload.get(required_field):
                raise ApiException(validation_problem(
                    field="payload", code="required", message="A registered in-process entity reference is required"
                ))
            if profile_name == "posture-snapshot" and payload.get("target"):
                raise ApiException(validation_problem(
                    field="target", code="not_allowed", message="This profile operates on the authorized project"
                ))
        else:
            target = str(payload.get("target") or payload.get("bucket") or payload.get("service") or "")
            if not target:
                raise ApiException(validation_problem(
                    field="target", code="required", message="A scan target is required"
                ))

        context = _context(request)
        if context.credential_id:
            if not context.user_id:
                raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user"))
            try:
                issuing_user = services.identity.user_get(context.user_id)
            except Exception:
                raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user")) from None
            if issuing_user.org_id != context.org_id or issuing_user.status != "active":
                raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user"))
        project_id = params["project_id"]
        project = services.authorization.require_project(context, project_id)
        services.authorization.require(context, "scan.start")
        for permission in profile.permissions_required:
            services.authorization.require(context, permission)
        if profile.active_required:
            services.authorization.require(context, "scan.start")
        extra = services.extra if isinstance(services.extra, dict) else {}
        scan_service = extra.get("scan_service")
        if scan_service is None and not profile.in_process:
            target = str(payload.get("target") or payload.get("bucket") or payload.get("service") or "")
            scope_result = services.platform.scope_check(project_id, target)
            if not scope_result.get("in_scope"):
                raise ApiException(ApiProblem(
                    403, "scope_denied", "The scan target is outside the project's authorized scope"
                ))

        raw_key = request.header("idempotency-key")
        idempotency = extra.get("idempotency_store")
        if idempotency is None:
            idempotency = IdempotencyStore(services.platform.db)
        if scan_service is not None:
            claim = scan_service.claim_create(
                context.org_id, project_id, raw_key, body
            )
        else:
            claim = idempotency.claim(
                context.org_id,
                "scan.create:" + project_id,
                raw_key,
                {"project_id": project_id, "body": body},
            )
        if claim.is_replay:
            return HttpResponse(
                claim.status_code,
                claim.response,
                headers=[("Idempotency-Replayed", "true")],
            )

        scan = None
        try:
            if scan_service is not None:
                scan, job = scan_service.queue_scan(
                    context.org_id,
                    project_id,
                    profile_name,
                    payload,
                    actor=context.label(),
                    actor_id=context.user_id,
                    active_enabled=active_enabled,
                    max_attempts=max_attempts,
                    timeout_seconds=timeout_seconds,
                )
            else:
                scan = services.platform.scan_create(
                    project_id,
                    profile_name,
                    scope_ref=str(project.scope_policy.get("name", ""))[:128],
                    initiator={"actor": context.label()[:128]},
                    actor=context.label(),
                )
                services.platform.scan_transition(scan.id, "queued")
                job = services.jobs.create_job(
                    scan.id,
                    profile_name,
                    payload,
                    active_enabled=active_enabled,
                    max_attempts=max_attempts,
                    timeout_seconds=timeout_seconds,
                    actor_id=context.user_id,
                    actor=context.label(),
                )
            response_body = {
                "data": {
                    "scan": _scan_view(services.platform, services.platform.scan_get(scan.id), [job]),
                    "job": _job_view(job),
                }
            }
            if scan_service is not None:
                scan_service.complete_create(claim, status_code=202, response=response_body)
            else:
                idempotency.complete(claim, status_code=202, response=response_body)
        except Exception:
            try:
                if scan_service is not None:
                    scan_service.fail_create(claim)
                else:
                    idempotency.fail(claim)
            except Exception:
                pass
            if scan is not None:
                try:
                    current = services.platform.scan_get(scan.id)
                    if current.status in {"pending", "queued"}:
                        services.platform.scan_set_error(
                            scan.id, "job_create_failed", "The scan job could not be queued"
                        )
                        services.platform.scan_transition(scan.id, "failed")
                except Exception:
                    pass
            raise
        return HttpResponse(202, response_body, headers=[("Location", "/api/v1/scans/" + scan.id)])

    def get_scan(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        scan = services.authorization.require_scan(context, params["scan_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        scan_service = extra.get("scan_service")
        if scan_service is not None:
            scan = scan_service.get_scan(context.org_id, scan.id)
        jobs = _get_jobs(services, context.org_id, scan.project_id, scan.id)
        return HttpResponse(200, {"data": _scan_view(services.platform, scan, jobs)})

    def cancel_scan(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        scan = services.authorization.require_scan(context, params["scan_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        scan_service = extra.get("scan_service")
        if scan_service is not None:
            updated_scan, cancelled = scan_service.cancel_scan(
                context.org_id, scan.id, actor=context.label()
            )
        else:
            job = _job_for_action(services, context.org_id, scan.project_id, scan.id)
            cancelled = services.jobs.cancel(job.id, actor=context.label())
            if cancelled.status == "cancelling" and not cancelled.worker_id and not cancelled.started_at:
                cancelled = services.jobs.cancel_finalize(job.id, actor=context.label())
                current = services.platform.scan_get(scan.id)
                if current.status not in {"cancelled", "completed", "failed"}:
                    services.platform.scan_transition(scan.id, "cancelled")
            else:
                current = services.platform.scan_get(scan.id)
                if current.status in {"pending", "queued", "running", "paused"}:
                    services.platform.scan_transition(scan.id, "cancelling")
            updated_scan = services.platform.scan_get(scan.id)
        return HttpResponse(202, {
            "data": {
                "scan": _scan_view(services.platform, updated_scan, [cancelled]),
                "job": _job_view(cancelled),
            }
        })

    def pause_scan(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        scan = services.authorization.require_scan(context, params["scan_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        scan_service = extra.get("scan_service")
        if scan_service is not None:
            updated_scan, paused = scan_service.pause_scan(
                context.org_id, scan.id, actor=context.label()
            )
        else:
            job = _job_for_action(services, context.org_id, scan.project_id, scan.id)
            paused = services.jobs.pause(job.id, actor=context.label())
            current = services.platform.scan_get(scan.id)
            if current.status in {"pending", "queued"} and not paused.started_at:
                services.platform.scan_transition(scan.id, "paused")
            updated_scan = services.platform.scan_get(scan.id)
        return HttpResponse(202, {
            "data": {
                "scan": _scan_view(services.platform, updated_scan, [paused]),
                "job": _job_view(paused),
            }
        })

    def resume_scan(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        scan = services.authorization.require_scan(context, params["scan_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        scan_service = extra.get("scan_service")
        if scan_service is not None:
            updated_scan, resumed = scan_service.resume_scan(
                context.org_id, scan.id, actor=context.label()
            )
        else:
            job = _job_for_action(services, context.org_id, scan.project_id, scan.id)
            resumed = services.jobs.resume(job.id, actor=context.label())
            updated_scan = services.platform.scan_get(scan.id)
        return HttpResponse(202, {
            "data": {
                "scan": _scan_view(services.platform, updated_scan, [resumed]),
                "job": _job_view(resumed),
            }
        })

    router.register(RouteSpec(
        path="/api/v1/scan-profiles",
        methods=frozenset({"GET"}),
        handler=list_profiles,
        operation_id="listScanProfiles",
        summary="List static scanner profiles and API input availability",
        tags=("scans",),
        permission="scan.read",
        response_schema={"type": "object"},
        responses={"200": "Scanner profile capabilities"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/scans",
        methods=frozenset({"GET"}),
        handler=list_scans,
        operation_id="listProjectScans",
        summary="List scans and safe job status for one project",
        tags=("scans",),
        permission="scan.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Project scans"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/scans",
        methods=frozenset({"POST"}),
        handler=create_scan,
        operation_id="createProjectScan",
        summary="Queue a scoped scan through the existing job engine",
        tags=("scans",),
        permission="scan.create",
        scope_kind="project",
        scope_parameter="project_id",
        request_schema={
            "type": "object",
            "required": ["profile"],
            "additionalProperties": False,
            "properties": {
                "profile": {"type": "string", "maxLength": 64},
                "target": {"type": "string", "maxLength": 512},
                "payload": {"type": "object", "additionalProperties": True},
                "active_enabled": {"type": "boolean"},
                "max_attempts": {"type": "integer", "minimum": 1, "maximum": 5},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
            },
        },
        response_schema={"type": "object"},
        responses={"202": "Scan queued", "403": "Permission or scope denied", "409": "Idempotency conflict"},
    ))
    router.register(RouteSpec(
        path="/api/v1/scans/{scan_id}",
        methods=frozenset({"GET"}),
        handler=get_scan,
        operation_id="getScan",
        summary="Read safe scan, stage and job status after ownership checks",
        tags=("scans",),
        permission="scan.read",
        response_schema={"type": "object"},
        responses={"200": "Scan status"},
    ))
    router.register(RouteSpec(
        path="/api/v1/scans/{scan_id}/cancel",
        methods=frozenset({"POST"}),
        handler=cancel_scan,
        operation_id="cancelScan",
        summary="Request cancellation through the existing job lifecycle",
        tags=("scans",),
        permission="scan.cancel",
        response_schema={"type": "object"},
        responses={"202": "Cancellation requested"},
    ))
    router.register(RouteSpec(
        path="/api/v1/scans/{scan_id}/pause",
        methods=frozenset({"POST"}),
        handler=pause_scan,
        operation_id="pauseScan",
        summary="Pause the existing scan job at its next worker checkpoint",
        tags=("scans",),
        permission="scan.pause",
        response_schema={"type": "object"},
        responses={"202": "Pause requested"},
    ))
    router.register(RouteSpec(
        path="/api/v1/scans/{scan_id}/resume",
        methods=frozenset({"POST"}),
        handler=resume_scan,
        operation_id="resumeScan",
        summary="Resume a paused job through the existing queue",
        tags=("scans",),
        permission="scan.start",
        response_schema={"type": "object"},
        responses={"202": "Job resumed"},
    ))


__all__ = ["register"]
