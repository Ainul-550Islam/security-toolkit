"""Bounded tenant-scoped search across existing project security records."""

from __future__ import annotations

from typing import Any

import models
import redact
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_SEARCH_TYPES = ("assets", "findings", "scans", "reports", "evidence", "integrations")
_TYPE_PERMISSION = {
    "assets": "asset.read",
    "findings": "finding.read",
    "scans": "scan.read",
    "reports": "report.read",
    "evidence": "finding.read",
    "integrations": "integration.read",
}
_SOURCE_LIMIT = 500
_MAX_WINDOW = 500


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _query(request: HttpRequest) -> None:
    allowed = {"q", "type", "status", "severity", "asset_type", "report_type", "limit", "offset"}
    if set(request.query) - allowed:
        raise ApiException(validation_problem(
            field="query", code="unknown_parameter", message="Unexpected query parameter"
        ))
    if any(len(values) > 1 for values in request.query.values()):
        raise ApiException(validation_problem(
            field="query", code="duplicate_parameter", message="Specify each parameter at most once"
        ))


def _value(request: HttpRequest, name: str, default: str = "", maximum: int = 256) -> str:
    value = request.query.get(name, [default])[0]
    if len(value) > maximum:
        raise ApiException(validation_problem(
            field=name, code="invalid", message=f"{name} exceeds the allowed length"
        ))
    return value


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


def _types(value: str) -> tuple[str, ...]:
    if not value or value == "all":
        return _SEARCH_TYPES
    requested = tuple(part.strip().lower() for part in value.split(","))
    if not requested or len(requested) > len(_SEARCH_TYPES) or any(not part for part in requested):
        raise ApiException(validation_problem(
            field="type", code="invalid", message="Search type must be a supported type or comma-separated list"
        ))
    if len(set(requested)) != len(requested) or any(part not in _SEARCH_TYPES for part in requested):
        raise ApiException(validation_problem(
            field="type", code="invalid", message="One or more search types are not supported"
        ))
    return requested


def _safe_text(value: Any, maximum: int) -> str:
    return str(redact.redact_text(value if value is not None else ""))[:maximum]


def _result(
    kind: str,
    identifier: Any,
    title: Any,
    summary: Any,
    updated_at: Any,
    *,
    status: Any = "",
    severity: Any = "",
    asset_type: Any = "",
    report_type: Any = "",
    source_id: Any = "",
) -> dict[str, Any]:
    return {
        "type": kind,
        "id": _safe_text(identifier, 128),
        "title": _safe_text(title, 240),
        "summary": _safe_text(summary, 500),
        "status": _safe_text(status, 64),
        "severity": _safe_text(severity, 32),
        "asset_type": _safe_text(asset_type, 64),
        "report_type": _safe_text(report_type, 64),
        "updated_at": str(updated_at or "")[:64],
        "source_id": _safe_text(source_id, 128),
    }


def _contains(result: dict[str, Any], needle: str) -> bool:
    if not needle:
        return True
    haystack = " ".join(str(result.get(key, "")) for key in (
        "type", "id", "title", "summary", "status", "severity", "asset_type", "report_type"
    )).casefold()
    return needle.casefold() in haystack


def register(router: ApiRouter) -> None:
    services = router.services

    def search_project(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request)
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        needle = _value(request, "q", maximum=256)
        type_filter = _value(request, "type", maximum=128)
        requested_types = _types(type_filter)
        explicit_type_filter = bool(type_filter and type_filter != "all")
        status_filter = _value(request, "status", maximum=64)
        severity_filter = _value(request, "severity", maximum=32)
        asset_type_filter = _value(request, "asset_type", maximum=64)
        report_type_filter = _value(request, "report_type", maximum=64)
        if severity_filter and severity_filter not in models.SEVERITIES:
            raise ApiException(validation_problem(
                field="severity", code="invalid", message="Severity is not supported"
            ))
        if asset_type_filter and asset_type_filter not in models.ASSET_TYPES:
            raise ApiException(validation_problem(
                field="asset_type", code="invalid", message="Asset type is not supported"
            ))
        if report_type_filter and report_type_filter not in models.REPORT_TYPES:
            raise ApiException(validation_problem(
                field="report_type", code="invalid", message="Report type is not supported"
            ))
        limit = _integer(request, "limit", 50, 1, 100)
        offset = _integer(request, "offset", 0, 0, _MAX_WINDOW - 1)
        if offset + limit > _MAX_WINDOW:
            raise ApiException(validation_problem(
                field="pagination", code="out_of_range", message="The search result window is limited"
            ))

        allowed_types: list[str] = []
        excluded_types: list[str] = []
        for kind in requested_types:
            permission = _TYPE_PERMISSION[kind]
            if explicit_type_filter:
                services.authorization.require(context, permission)
                allowed_types.append(kind)
            elif permission in context.permissions:
                allowed_types.append(kind)
            else:
                excluded_types.append(kind)

        extra = services.extra if isinstance(services.extra, dict) else {}
        search_service = extra.get("search_service")
        if search_service is not None:
            data = search_service.search(
                context.org_id,
                project_id,
                query=needle,
                types=allowed_types,
                status=status_filter,
                severity=severity_filter,
                asset_type=asset_type_filter,
                report_type=report_type_filter,
                limit=limit,
                offset=offset,
                excluded_types=excluded_types,
            )
            return HttpResponse(200, data)

        results: list[dict[str, Any]] = []
        source_states: dict[str, str] = {}
        truncated_sources: list[str] = []
        finding_rows: list[Any] | None = None

        def get_findings() -> list[Any]:
            nonlocal finding_rows
            if finding_rows is None:
                finding_rows = services.platform.finding_list(
                    project_id,
                    severity=severity_filter or None,
                    limit=_SOURCE_LIMIT,
                )
                if len(finding_rows) == _SOURCE_LIMIT:
                    truncated_sources.append("findings")
            return finding_rows

        if "assets" in allowed_types:
            assets = services.platform.asset_list(
                project_id,
                asset_type=asset_type_filter or None,
                limit=_SOURCE_LIMIT,
            )
            source_states["assets"] = "AVAILABLE"
            if len(assets) == _SOURCE_LIMIT:
                truncated_sources.append("assets")
            for asset in assets:
                results.append(_result(
                    "asset", asset.id, asset.display or asset.value,
                    f"{asset.asset_type} · {asset.status}", asset.last_seen,
                    status=asset.status, asset_type=asset.asset_type,
                ))

        if "findings" in allowed_types:
            findings = get_findings()
            source_states["findings"] = "AVAILABLE"
            for finding in findings:
                if status_filter and finding.lifecycle.casefold() != status_filter.casefold():
                    continue
                results.append(_result(
                    "finding", finding.id, finding.title,
                    f"{finding.severity} · {finding.category} · {finding.lifecycle}",
                    finding.last_detected, status=finding.lifecycle,
                    severity=finding.severity, asset_type="", source_id=finding.asset_id,
                ))

        if "scans" in allowed_types:
            scans = services.platform.scan_list(project_id, limit=_SOURCE_LIMIT)
            source_states["scans"] = "AVAILABLE"
            if len(scans) == _SOURCE_LIMIT:
                truncated_sources.append("scans")
            for scan in scans:
                if status_filter and scan.status.casefold() != status_filter.casefold():
                    continue
                results.append(_result(
                    "scan", scan.id, scan.profile,
                    f"{scan.status} · {scan.progress:.0%}", scan.created_at,
                    status=scan.status,
                ))

        if "reports" in allowed_types:
            if services.reports is None:
                source_states["reports"] = "NOT_CONFIGURED"
            else:
                report_data = services.reports.list_runs(
                    project_id, limit=_SOURCE_LIMIT, offset=0,
                    report_type=report_type_filter,
                )
                reports = report_data.get("reports", [])
                source_states["reports"] = "AVAILABLE"
                if int(report_data.get("total", len(reports))) > _SOURCE_LIMIT:
                    truncated_sources.append("reports")
                for report in reports:
                    if status_filter and str(report.get("status", "")).casefold() != status_filter.casefold():
                        continue
                    results.append(_result(
                        "report", report.get("id"), report.get("title"),
                        f"{report.get('report_type', '')} · {report.get('status', '')}",
                        report.get("created_at"), status=report.get("status"),
                        report_type=report.get("report_type"),
                    ))

        if "evidence" in allowed_types:
            findings = get_findings()
            source_states["evidence"] = "AVAILABLE"
            evidence_count = 0
            for finding in findings:
                remaining = _SOURCE_LIMIT - evidence_count
                if remaining <= 0:
                    truncated_sources.append("evidence")
                    break
                evidence = services.platform.evidence_list(
                    finding.id, limit=min(10, remaining)
                )
                if len(evidence) == min(10, remaining):
                    truncated_sources.append("evidence")
                for item in evidence:
                    evidence_count += 1
                    if status_filter and status_filter.casefold() not in {"captured", "available"}:
                        continue
                    results.append(_result(
                        "evidence", item.get("id"), item.get("evidence_type"),
                        f"{item.get('detection_reason', '')} · {item.get('url', '')}",
                        item.get("captured_at"), status="captured",
                        source_id=finding.id,
                    ))
                    if evidence_count >= _SOURCE_LIMIT:
                        truncated_sources.append("evidence")
                        break
                if evidence_count >= _SOURCE_LIMIT:
                    break

        if "integrations" in allowed_types:
            if services.integrations is None:
                source_states["integrations"] = "NOT_CONFIGURED"
            else:
                integration_data = services.integrations.connections.list(
                    context.org_id,
                    project_id=project_id,
                    limit=_SOURCE_LIMIT,
                    offset=0,
                )
                items = integration_data.get("items", [])
                source_states["integrations"] = "AVAILABLE"
                if int(integration_data.get("total", len(items))) > _SOURCE_LIMIT:
                    truncated_sources.append("integrations")
                for item in items:
                    if status_filter and str(item.get("status", "")).casefold() != status_filter.casefold():
                        continue
                    results.append(_result(
                        "integration", item.get("id"), item.get("name"),
                        f"{item.get('provider', '')} · {item.get('health_state', '')}",
                        item.get("updated_at", item.get("created_at")),
                        status=item.get("status"),
                    ))

        if status_filter:
            results = [result for result in results if result.get("status", "").casefold() == status_filter.casefold()]
        if severity_filter:
            results = [result for result in results if result.get("severity", "").casefold() == severity_filter.casefold()]
        if asset_type_filter:
            results = [result for result in results if result.get("asset_type", "").casefold() == asset_type_filter.casefold()]
        if report_type_filter:
            results = [result for result in results if result.get("report_type", "").casefold() == report_type_filter.casefold()]
        results = [result for result in results if _contains(result, needle)]
        results.sort(
            key=lambda item: (str(item.get("updated_at", "")), item["type"], item["id"]),
            reverse=True,
        )
        page = results[offset:offset + limit]
        return HttpResponse(200, {
            "data": page,
            "count": len(page),
            "total": len(results),
            "limit": limit,
            "offset": offset,
            "total_is_lower_bound": bool(truncated_sources),
            "truncated_sources": sorted(set(truncated_sources)),
            "source_states": source_states,
            "excluded_types": excluded_types,
        })

    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/search",
        methods=frozenset({"GET"}),
        handler=search_project,
        operation_id="searchProjectSecurityRecords",
        summary="Search bounded assets, findings, scans, reports, evidence, and integrations for one project",
        tags=("search",),
        permission="project.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Bounded project search page"},
    ))


__all__ = ["register"]
