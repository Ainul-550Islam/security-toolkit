"""Tenant-scoped evidence metadata and authorized retrieval APIs.

Binary evidence storage/download is not implemented by the current platform.
This module therefore exposes bounded metadata and persisted report references,
and returns an explicit unavailable state for download instead of fabricating
an artifact or reading an arbitrary filesystem path.
"""

from __future__ import annotations

from typing import Any

import redact
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_MAX_EVIDENCE_WINDOW = 500


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _query(request: HttpRequest) -> None:
    if set(request.query) - {"limit", "offset"}:
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


def _text(value: Any, maximum: int) -> str:
    return str(redact.redact_text(value if value is not None else ""))[:maximum]


def _record_view(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get("id", "")),
        "finding_id": str(row.get("finding_id", "")),
        "evidence_type": _text(row.get("evidence_type", ""), 64),
        "url": _text(row.get("url", ""), 2048),
        "method": _text(row.get("method", ""), 16),
        "status_code": _text(row.get("status_code", ""), 16),
        "detection_reason": _text(row.get("detection_reason", ""), 500),
        "scanner": _text(row.get("scanner", ""), 128),
        "rule_id": _text(row.get("rule_id", ""), 128),
        "captured_at": str(row.get("captured_at", "")),
        "integrity_reference": {
            "record_id": str(row.get("id", "")),
            "captured_at": str(row.get("captured_at", "")),
            "hash_status": "NOT_AVAILABLE",
        },
        "download": {
            "status": "NOT_AVAILABLE",
            "reason": "binary_evidence_store_not_configured",
        },
    }


def _report_evidence_view(item: dict[str, Any], report_id: str, report_hash: str) -> dict[str, Any]:
    return {
        "evidence_id": str(item.get("id", "")),
        "finding_id": str(item.get("finding_id", "")),
        "evidence_type": _text(item.get("type", item.get("evidence_type", "")), 64),
        "url": _text(item.get("url", ""), 2048),
        "method": _text(item.get("method", ""), 16),
        "status_code": _text(item.get("status_code", ""), 16),
        "detection_reason": _text(item.get("detection_reason", ""), 500),
        "scanner": _text(item.get("scanner", ""), 128),
        "rule_id": _text(item.get("rule_id", ""), 128),
        "captured_at": str(item.get("captured_at", item.get("evidence_ts", ""))),
        "integrity_reference": {
            "report_id": report_id,
            "report_hash": report_hash,
            "status": "REPORT_HASH_ONLY" if report_hash else "NOT_AVAILABLE",
        },
        "download": {
            "status": "NOT_AVAILABLE",
            "reason": "binary_evidence_store_not_configured",
        },
    }


def _resources(services: Any) -> Any:
    extra = services.extra if isinstance(services.extra, dict) else {}
    service = extra.get("customer_resources")
    if service is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The evidence query service is not configured"))
    return service


def register(router: ApiRouter) -> None:
    services = router.services

    def scan_evidence(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request)
        context = _context(request)
        scan = services.authorization.require_scan(context, params["scan_id"])
        limit = _integer(request, "limit", 50, 1, 100)
        offset = _integer(request, "offset", 0, 0, _MAX_EVIDENCE_WINDOW - 1)
        if offset + limit > _MAX_EVIDENCE_WINDOW:
            raise ApiException(validation_problem(
                field="pagination", code="out_of_range", message="The evidence result window is limited"
            ))
        extra = services.extra if isinstance(services.extra, dict) else {}
        evidence_service = extra.get("evidence_service")
        if evidence_service is not None:
            result = evidence_service.list_scan_evidence(
                context.org_id, scan.id, limit=limit, offset=offset
            )
            return HttpResponse(200, result)
        ids = _resources(services).finding_ids_for_scan(
            context.org_id, scan.project_id, scan.id, limit=500
        )
        target_count = offset + limit + 1
        records: list[dict[str, Any]] = []
        truncated = len(ids) == 500
        for finding_id in ids:
            remaining = target_count - len(records)
            if remaining <= 0:
                truncated = True
                break
            rows = services.platform.evidence_list(
                finding_id, limit=min(101, remaining)
            )
            if len(rows) >= remaining:
                truncated = True
            records.extend(rows)
            if len(records) >= target_count:
                records = records[:target_count]
                break
        page = records[offset:offset + limit]
        return HttpResponse(200, {
            "data": [_record_view(row) for row in page],
            "count": len(page),
            "limit": limit,
            "offset": offset,
            "truncated": truncated,
            "download_state": "NOT_AVAILABLE",
        })

    def report_evidence(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request)
        if services.reports is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The report service is not configured"))
        context = _context(request)
        report_id = params["report_id"]
        owner = services.authorization.require_report(context, report_id)
        limit = _integer(request, "limit", 50, 1, 100)
        offset = _integer(request, "offset", 0, 0, _MAX_EVIDENCE_WINDOW - 1)
        if offset + limit > _MAX_EVIDENCE_WINDOW:
            raise ApiException(validation_problem(
                field="pagination", code="out_of_range", message="The evidence result window is limited"
            ))
        extra = services.extra if isinstance(services.extra, dict) else {}
        evidence_service = extra.get("evidence_service")
        if evidence_service is not None:
            return HttpResponse(200, evidence_service.list_report_evidence(
                context.org_id, report_id, limit=limit, offset=offset
            ))
        report = services.reports.get_run(report_id, with_payload=True)
        payload = report.get("payload")
        if not isinstance(payload, dict):
            return HttpResponse(200, {
                "data": [],
                "count": 0,
                "limit": limit,
                "offset": offset,
                "state": "NOT_AVAILABLE",
                "reason": "report_payload_not_persisted",
                "report_id": report_id,
                "project_id": str(owner["project_id"]),
                "report_hash": str(report.get("report_hash", "")),
                "download_state": "NOT_AVAILABLE",
            })
        report_hash = str(report.get("report_hash", ""))[:128]
        items: list[dict[str, Any]] = []
        for item in payload.get("evidence", []) if isinstance(payload.get("evidence"), list) else []:
            if isinstance(item, dict):
                items.append(item)
        findings = payload.get("findings", [])
        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                evidence_items = finding.get("evidence", [])
                if not isinstance(evidence_items, list):
                    continue
                for item in evidence_items:
                    if isinstance(item, dict):
                        safe_item = dict(item)
                        safe_item.setdefault("finding_id", finding.get("id", ""))
                        items.append(safe_item)
                        if len(items) >= _MAX_EVIDENCE_WINDOW:
                            break
                if len(items) >= _MAX_EVIDENCE_WINDOW:
                    break
        page = items[offset:offset + limit]
        return HttpResponse(200, {
            "data": [_report_evidence_view(item, report_id, report_hash) for item in page],
            "count": len(page),
            "limit": limit,
            "offset": offset,
            "state": "AVAILABLE",
            "truncated": len(items) >= _MAX_EVIDENCE_WINDOW,
            "report_id": report_id,
            "project_id": str(owner["project_id"]),
            "report_hash": report_hash,
            "download_state": "NOT_AVAILABLE",
        })

    def evidence_download(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        services.authorization.require_evidence(context, params["evidence_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        evidence_service = extra.get("evidence_service")
        if evidence_service is not None:
            evidence_service.download_status(context.org_id, params["evidence_id"])
        raise ApiException(ApiProblem(
            503,
            "evidence_download_unavailable",
            "Binary evidence downloads are not configured",
        ))

    router.register(RouteSpec(
        path="/api/v1/scans/{scan_id}/evidence",
        methods=frozenset({"GET"}),
        handler=scan_evidence,
        operation_id="listScanEvidence",
        summary="List bounded evidence metadata for a tenant-authorized scan",
        tags=("evidence", "scans"),
        permission="finding.read",
        response_schema={"type": "object"},
        responses={"200": "Scan evidence metadata", "403": "Scan is outside the caller's scope"},
    ))
    router.register(RouteSpec(
        path="/api/v1/reports/{report_id}/evidence",
        methods=frozenset({"GET"}),
        handler=report_evidence,
        operation_id="listReportEvidence",
        summary="Read evidence references from an authorized persisted report snapshot",
        tags=("evidence", "reports"),
        permission="report.read",
        response_schema={"type": "object"},
        responses={"200": "Report evidence or explicit unavailable state"},
    ))
    router.register(RouteSpec(
        path="/api/v1/evidence/{evidence_id}/download",
        methods=frozenset({"GET"}),
        handler=evidence_download,
        operation_id="downloadEvidence",
        summary="Authorize evidence ownership before reporting unavailable binary storage",
        tags=("evidence",),
        permission="finding.read",
        response_schema={"type": "string", "format": "binary"},
        responses={"503": "Binary evidence downloads are unavailable"},
    ))


__all__ = ["register"]
