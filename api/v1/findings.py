"""Project-scoped findings and minimized evidence APIs."""

from __future__ import annotations

from typing import Any

import models
import redact
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


def _limit(request: HttpRequest, *, default: int = 100, maximum: int = 500) -> int:
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


def _finding_view(finding: Any) -> dict[str, Any]:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "project_id": finding.project_id,
        "asset_id": finding.asset_id,
        "title": str(redact.redact_text(finding.title))[:300],
        "description": str(redact.redact_text(finding.description))[:4000],
        "severity": finding.severity,
        "confidence": finding.confidence,
        "category": finding.category,
        "source": str(redact.redact_text(finding.source))[:128],
        "rule_id": str(redact.redact_text(finding.rule_id))[:128],
        "template_id": str(redact.redact_text(finding.template_id))[:128],
        "cwe": str(finding.cwe)[:32],
        "cve": str(finding.cve)[:32],
        "cvss": redact.redact(finding.cvss if isinstance(finding.cvss, dict) else {}),
        "remediation": str(redact.redact_text(finding.remediation))[:4000],
        "lifecycle": finding.lifecycle,
        "fingerprint": finding.fingerprint,
        "first_detected": finding.first_detected,
        "last_detected": finding.last_detected,
        "resolved_at": finding.resolved_at,
    }


def _evidence_view(row: dict[str, Any]) -> dict[str, Any]:
    view = {
        "id": str(row.get("id", "")),
        "finding_id": str(row.get("finding_id", "")),
        "evidence_type": str(row.get("evidence_type", "")),
        "url": str(redact.redact_text(row.get("url", "")))[:2048],
        "method": str(row.get("method", ""))[:16],
        "status_code": str(row.get("status_code", ""))[:16],
        "detection_reason": str(redact.redact_text(row.get("detection_reason", "")))[:500],
        "scanner": str(redact.redact_text(row.get("scanner", "")))[:128],
        "rule_id": str(redact.redact_text(row.get("rule_id", "")))[:128],
        "captured_at": str(row.get("captured_at", "")),
    }
    for field in ("integrity_reference", "download"):
        item = row.get(field)
        if isinstance(item, dict):
            view[field] = dict(item)
    return view


def register(router: ApiRouter) -> None:
    services = router.services

    def list_findings(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        unknown = set(request.query) - {"limit", "severity", "lifecycle"}
        if unknown:
            raise ApiException(validation_problem(
                field="query", code="unknown_parameter", message="Unexpected query parameter"
            ))
        project_id = params["project_id"]
        context = _context(request)
        services.authorization.require_project(context, project_id)
        severities = request.query.get("severity", [])
        statuses = request.query.get("lifecycle", [])
        if len(severities) > 1 or len(statuses) > 1:
            raise ApiException(validation_problem(
                field="query", code="duplicate_parameter", message="Specify each filter at most once"
            ))
        severity = severities[0] if severities else ""
        lifecycle = statuses[0] if statuses else ""
        if severity and severity not in models.SEVERITIES:
            raise ApiException(validation_problem(
                field="severity", code="invalid", message="Severity is not supported"
            ))
        if lifecycle and lifecycle not in models.FINDING_STATUSES:
            raise ApiException(validation_problem(
                field="lifecycle", code="invalid", message="Finding lifecycle is not supported"
            ))
        extra = services.extra if isinstance(services.extra, dict) else {}
        finding_service = extra.get("finding_service")
        if finding_service is not None:
            findings = finding_service.list_findings(
                context.org_id,
                project_id,
                severity=severity,
                lifecycle=lifecycle,
                limit=_limit(request),
            )
        else:
            findings = services.platform.finding_list(
                project_id,
                severity=severity or None,
                lifecycle=lifecycle or None,
                limit=_limit(request),
            )
        return HttpResponse(200, {
            "data": [_finding_view(finding) for finding in findings],
            "count": len(findings),
        })

    def get_finding(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        finding = services.authorization.require_finding(context, params["finding_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        finding_service = extra.get("finding_service")
        if finding_service is not None:
            finding = finding_service.get_finding(context.org_id, params["finding_id"])
        return HttpResponse(200, {"data": _finding_view(finding)})

    def update_finding(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"lifecycle"}))
        if set(body) != {"lifecycle"} or not isinstance(body["lifecycle"], str):
            raise ApiException(validation_problem(
                field="lifecycle", code="required", message="A finding lifecycle is required"
            ))
        new_status = body["lifecycle"]
        if new_status not in models.FINDING_STATUSES:
            raise ApiException(validation_problem(
                field="lifecycle", code="invalid", message="Finding lifecycle is not supported"
            ))
        context = _context(request)
        finding = services.authorization.require_finding(context, params["finding_id"])
        if new_status == "accepted_risk":
            services.authorization.require(context, "finding.accept_risk")
        elif new_status in {"resolved", "remediated", "false_positive"}:
            services.authorization.require(context, "finding.resolve")
        extra = services.extra if isinstance(services.extra, dict) else {}
        finding_service = extra.get("finding_service")
        if finding_service is not None:
            updated = finding_service.set_status(
                context.org_id, finding.id, new_status, actor=context.label()
            )
        else:
            updated = services.platform.finding_set_status(
                finding.id, new_status, actor=context.label()
            )
        return HttpResponse(200, {"data": _finding_view(updated)})

    def list_finding_evidence(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        unknown = set(request.query) - {"limit"}
        if unknown:
            raise ApiException(validation_problem(
                field="query", code="unknown_parameter", message="Unexpected query parameter"
            ))
        context = _context(request)
        finding = services.authorization.require_finding(context, params["finding_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        evidence_service = extra.get("evidence_service")
        limit = _limit(request, default=50, maximum=100)
        if evidence_service is not None:
            result = evidence_service.list_finding_evidence(
                context.org_id, finding.id, limit=limit
            )
            records = result.get("data", [])
        else:
            finding_service = extra.get("finding_service")
            if finding_service is not None:
                records = finding_service.evidence_list(
                    context.org_id,
                    finding.id,
                    limit=limit,
                )
            else:
                records = services.platform.evidence_list(
                    finding.id, limit=limit
                )
        safe_records = [_evidence_view(row) for row in records]
        return HttpResponse(200, {"data": safe_records, "count": len(safe_records)})

    def get_evidence(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        services.authorization.require_evidence(context, params["evidence_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        evidence_service = extra.get("evidence_service")
        if evidence_service is not None:
            row = evidence_service.get_evidence(context.org_id, params["evidence_id"])
        else:
            rows = services.platform.db.query(
                "SELECT id, finding_id, evidence_type, url, method, status_code, "
                "request_snippet, response_snippet, detection_reason, scanner, "
                "rule_id, captured_at FROM evidence WHERE id=? LIMIT 1",
                (params["evidence_id"],),
            )
            if not rows:
                raise ApiException(ApiProblem(404, "not_found", "Resource not found"))
            row = rows[0]
        return HttpResponse(200, {"data": _evidence_view(row)})

    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/findings",
        methods=frozenset({"GET"}),
        handler=list_findings,
        operation_id="listProjectFindings",
        summary="List findings with bounded severity and lifecycle filters",
        tags=("findings",),
        permission="finding.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Project findings"},
    ))
    router.register(RouteSpec(
        path="/api/v1/findings/{finding_id}",
        methods=frozenset({"GET"}),
        handler=get_finding,
        operation_id="getFinding",
        summary="Read a minimized finding projection after ownership checks",
        tags=("findings",),
        permission="finding.read",
        response_schema={"type": "object"},
        responses={"200": "Finding metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/findings/{finding_id}",
        methods=frozenset({"PATCH"}),
        handler=update_finding,
        operation_id="updateFindingLifecycle",
        summary="Transition finding lifecycle using PlatformService",
        tags=("findings",),
        permission="finding.update",
        request_schema={
            "type": "object",
            "required": ["lifecycle"],
            "additionalProperties": False,
            "properties": {"lifecycle": {"type": "string", "enum": list(models.FINDING_STATUSES)}},
        },
        response_schema={"type": "object"},
        responses={"200": "Finding updated"},
    ))
    router.register(RouteSpec(
        path="/api/v1/findings/{finding_id}/evidence",
        methods=frozenset({"GET"}),
        handler=list_finding_evidence,
        operation_id="listFindingEvidence",
        summary="List safe evidence metadata without request or response snippets",
        tags=("findings", "evidence"),
        permission="finding.read",
        response_schema={"type": "object"},
        responses={"200": "Evidence metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/evidence/{evidence_id}",
        methods=frozenset({"GET"}),
        handler=get_evidence,
        operation_id="getEvidence",
        summary="Read one minimized evidence record after finding ownership checks",
        tags=("evidence",),
        permission="finding.read",
        response_schema={"type": "object"},
        responses={"200": "Evidence metadata"},
    ))


__all__ = ["register"]
