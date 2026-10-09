"""Asynchronous reports and tenant-safe report retrieval/export."""

from __future__ import annotations

import re
from typing import Any

import models
from api.errors import ApiException, ApiProblem, validation_problem
from api.idempotency import IdempotencyStore
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_.~-]{1,128}$")
_EXPORT_TYPES = {
    "json": "application/json; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
}


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


def _report_view(run: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "id", "org_id", "project_id", "report_type", "title", "status",
        "schema_version", "risk_version", "data_cutoff", "report_hash",
        "generated_at", "generated_by", "truncated", "truncation_reason",
        "original_count", "included_count", "byte_size", "immutable",
        "created_at",
    )
    return {key: run.get(key) for key in fields if key in run}


def _validate_credential_actor(services: Any, context: Any) -> None:
    if not context.credential_id:
        return
    if not context.user_id:
        raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user"))
    try:
        user = services.identity.user_get(context.user_id)
    except Exception:
        raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user")) from None
    if user.org_id != context.org_id or user.status != "active":
        raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user"))


def register(router: ApiRouter) -> None:
    services = router.services

    def list_reports(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.reports is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The report service is not configured"))
        allowed = {"limit", "offset", "report_type"}
        if set(request.query) - allowed:
            raise ApiException(validation_problem(
                field="query", code="unknown_parameter", message="Unexpected query parameter"
            ))
        if any(len(values) > 1 for values in request.query.values()):
            raise ApiException(validation_problem(
                field="query", code="duplicate_parameter", message="Specify each parameter at most once"
            ))
        project_id = params["project_id"]
        context = _context(request)
        services.authorization.require_project(context, project_id)
        limit_text = request.query.get("limit", ["50"])[0]
        offset_text = request.query.get("offset", ["0"])[0]
        if not limit_text.isdigit() or not offset_text.isdigit():
            raise ApiException(validation_problem(
                field="pagination", code="invalid", message="Pagination values must be integers"
            ))
        limit, offset = int(limit_text), int(offset_text)
        if not 1 <= limit <= 500 or not 0 <= offset <= 100_000:
            raise ApiException(validation_problem(
                field="pagination", code="out_of_range", message="Pagination is outside the allowed range"
            ))
        report_type = request.query.get("report_type", [""])[0]
        if report_type and report_type not in models.REPORT_TYPES:
            raise ApiException(validation_problem(
                field="report_type", code="invalid", message="Report type is not supported"
            ))
        extra = services.extra if isinstance(services.extra, dict) else {}
        report_service = extra.get("report_service")
        if report_service is not None:
            result = report_service.list_reports(
                context.org_id,
                project_id,
                limit=limit,
                offset=offset,
                report_type=report_type,
            )
        else:
            result = services.reports.list_runs(
                project_id, limit=limit, offset=offset, report_type=report_type
            )
        return HttpResponse(200, {
            "data": [_report_view(run) for run in result["reports"]],
            "count": result["count"],
            "total": result["total"],
            "limit": result["limit"],
            "offset": result["offset"],
        })

    def generate_report(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.reports is None or services.jobs is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The report job service is not configured"))
        body = _body(request, frozenset({"report_type", "title", "store_payload"}))
        report_type = body.get("report_type")
        if not isinstance(report_type, str) or report_type not in models.REPORT_TYPES:
            raise ApiException(validation_problem(
                field="report_type", code="invalid", message="Report type is not supported"
            ))
        title = body.get("title", "")
        if not isinstance(title, str) or len(title) > 200:
            raise ApiException(validation_problem(
                field="title", code="invalid", message="Title exceeds the allowed length"
            ))
        store_payload = body.get("store_payload", False)
        if not isinstance(store_payload, bool):
            raise ApiException(validation_problem(
                field="store_payload", code="invalid_type", message="store_payload must be a boolean"
            ))
        context = _context(request)
        _validate_credential_actor(services, context)
        project_id = params["project_id"]
        project = services.authorization.require_project(context, project_id)
        if report_type == "compliance_evidence":
            services.authorization.require(context, "compliance_evidence.read")
        try:
            profile = services.jobs.registry.get("report-generation")
        except Exception:
            raise ApiException(ApiProblem(503, "service_not_configured", "Asynchronous report generation is not configured")) from None
        for permission in profile.permissions_required:
            services.authorization.require(context, permission)
        payload: dict[str, Any] = {
            "target": "project:" + project_id,
            "report_type": report_type,
            "store_payload": store_payload,
        }
        if title:
            payload["title"] = title
        try:
            services.jobs.validate_payload(payload)
        except Exception:
            raise ApiException(validation_problem(
                field="title", code="invalid", message="Report options are invalid for the job engine"
            )) from None
        extra = services.extra if isinstance(services.extra, dict) else {}
        report_service = extra.get("report_service")
        if report_service is not None:
            submission = report_service.generate_async(
                context.org_id,
                project_id,
                report_type,
                title=title,
                store_payload=store_payload,
                actor=context.label(),
                actor_id=context.user_id,
                idempotency_key=request.header("idempotency-key"),
                request_body=body,
            )
            if submission.get("replayed"):
                return HttpResponse(
                    int(submission.get("status_code", 202)),
                    submission.get("response", {}),
                    headers=[("Idempotency-Replayed", "true")],
                )
            scan_id = str(submission.get("scan_id", ""))
            headers = []
            if _REPORT_ID_RE.fullmatch(scan_id):
                headers.append(("Location", "/api/v1/scans/" + scan_id))
            return HttpResponse(
                int(submission.get("status_code", 202)),
                submission.get("response", {}),
                headers=headers,
            )
        idempotency = extra.get("idempotency_store")
        if idempotency is None:
            idempotency = IdempotencyStore(services.platform.db)
        claim = idempotency.claim(
            context.org_id,
            "report.generate:" + project_id,
            request.header("idempotency-key"),
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
            scan = services.platform.scan_create(
                project_id,
                "report-generation",
                scope_ref=str(project.scope_policy.get("name", ""))[:128],
                initiator={"actor": context.label()[:128]},
                actor=context.label(),
            )
            services.platform.scan_transition(scan.id, "queued")
            job = services.jobs.create_job(
                scan.id,
                "report-generation",
                payload,
                job_type="report",
                timeout_seconds=min(900, int(profile.timeout)),
                actor_id=context.user_id,
                actor=context.label(),
            )
            response_body = {
                "data": {
                    "report_type": report_type,
                    "status": "queued",
                    "scan_id": scan.id,
                    "job_id": job.id,
                    "job_status": job.status,
                }
            }
            idempotency.complete(claim, status_code=202, response=response_body)
        except Exception:
            try:
                idempotency.fail(claim)
            except Exception:
                pass
            if scan is not None:
                try:
                    current = services.platform.scan_get(scan.id)
                    if current.status in {"pending", "queued"}:
                        services.platform.scan_set_error(
                            scan.id, "report_job_create_failed", "The report job could not be queued"
                        )
                        services.platform.scan_transition(scan.id, "failed")
                except Exception:
                    pass
            raise
        return HttpResponse(
            202,
            response_body,
            headers=[("Location", "/api/v1/scans/" + scan.id)],
        )

    def get_report(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.reports is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The report service is not configured"))
        report_id = params["report_id"]
        context = _context(request)
        services.authorization.require_report(context, report_id)
        extra = services.extra if isinstance(services.extra, dict) else {}
        report_service = extra.get("report_service")
        if report_service is not None:
            run = report_service.get_report(context.org_id, report_id)
        else:
            run = services.reports.get_run(report_id)
        return HttpResponse(200, {"data": _report_view(run)})

    def export_report(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.reports is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The report service is not configured"))
        if set(request.query) - {"format"}:
            raise ApiException(validation_problem(
                field="query", code="unknown_parameter", message="Unexpected query parameter"
            ))
        formats = request.query.get("format", [])
        if len(formats) > 1:
            raise ApiException(validation_problem(
                field="format", code="duplicate_parameter", message="Specify one format"
            ))
        fmt = formats[0].lower() if formats else "json"
        if fmt not in _EXPORT_TYPES:
            raise ApiException(validation_problem(
                field="format", code="invalid", message="Export format is not supported"
            ))
        report_id = params["report_id"]
        context = _context(request)
        services.authorization.require_report(context, report_id)
        extra = services.extra if isinstance(services.extra, dict) else {}
        report_service = extra.get("report_service")
        if report_service is not None:
            raw = report_service.export_report(
                context.org_id, report_id, fmt, actor=context.label()
            )
        else:
            raw = services.reports.export(report_id, fmt, actor=context.label())
        safe_id = report_id if _REPORT_ID_RE.fullmatch(report_id) else "report"
        extension = "html" if fmt == "html" else fmt
        return HttpResponse(
            200,
            raw,
            headers=[
                ("Content-Type", _EXPORT_TYPES[fmt]),
                ("Content-Disposition", f'attachment; filename="report-{safe_id[:64]}.{extension}"'),
            ],
        )

    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/reports",
        methods=frozenset({"GET"}),
        handler=list_reports,
        operation_id="listProjectReports",
        summary="List report metadata in one authorized project",
        tags=("reports",),
        permission="report.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Project reports"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/reports",
        methods=frozenset({"POST"}),
        handler=generate_report,
        operation_id="generateProjectReport",
        summary="Queue a report through the existing worker and ReportService",
        tags=("reports",),
        permission="report.generate",
        scope_kind="project",
        scope_parameter="project_id",
        request_schema={
            "type": "object",
            "required": ["report_type"],
            "additionalProperties": False,
            "properties": {
                "report_type": {"type": "string", "enum": list(models.REPORT_TYPES)},
                "title": {"type": "string", "maxLength": 200},
                "store_payload": {"type": "boolean"},
            },
        },
        response_schema={"type": "object"},
        responses={"202": "Report job queued", "409": "Idempotency conflict"},
    ))
    router.register(RouteSpec(
        path="/api/v1/reports/{report_id}",
        methods=frozenset({"GET"}),
        handler=get_report,
        operation_id="getReport",
        summary="Read report metadata after report/project ownership checks",
        tags=("reports",),
        permission="report.read",
        response_schema={"type": "object"},
        responses={"200": "Report metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/reports/{report_id}/export",
        methods=frozenset({"GET"}),
        handler=export_report,
        operation_id="exportReport",
        summary="Export a report through ReportService without filesystem paths",
        tags=("reports",),
        permission="report.export",
        response_schema={"type": "string", "format": "binary"},
        responses={"200": "Report file"},
    ))


__all__ = ["register"]
