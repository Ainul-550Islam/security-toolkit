"""Customer risk read APIs backed only by persisted platform findings/assets."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import redact
from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec

_CATEGORY_SAMPLE_MAX = 500


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


def _string(request: HttpRequest, name: str, maximum: int = 40) -> str:
    value = request.query.get(name, [""])[0]
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


def _trends(services: Any, project_id: str, start: str, end: str) -> dict[str, Any]:
    lifecycle = services.analytics.finding_trend(
        project_id, start=start, end=end
    )
    risk_events = services.analytics.risk_delta(
        project_id, start=start, end=end
    )
    return {
        "finding_lifecycle": lifecycle,
        "persisted_risk_events": {
            **risk_events,
            "definition": "Counts persisted risk.increased and risk.decreased security events; this is not a recalculated score time series.",
        },
    }


def _top_categories(services: Any, project_id: str, risk_summary: dict[str, Any], limit: int) -> dict[str, Any]:
    """Aggregate the bounded persisted score columns, not transient models."""
    allowed_statuses = sorted({
        str(status) for status in risk_summary.get("scope_statuses", [])
        if isinstance(status, str) and status
    })
    cutoff = str(risk_summary.get("data_cutoff", ""))
    where = ["project_id=?"]
    parameters: list[Any] = [project_id]
    if allowed_statuses:
        where.append("lifecycle IN (" + ",".join("?" for _ in allowed_statuses) + ")")
        parameters.extend(allowed_statuses)
    if cutoff:
        where.append("first_detected<=?")
        parameters.append(cutoff)
    rows = services.platform.db.query(
        "SELECT category, severity, risk_score FROM findings WHERE "
        + " AND ".join(where)
        + " ORDER BY last_detected DESC, id LIMIT ?",
        tuple(parameters + [_CATEGORY_SAMPLE_MAX]),
        limit=_CATEGORY_SAMPLE_MAX,
    )
    aggregates: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "risk_total": 0.0, "by_severity": defaultdict(int)}
    )
    for finding in rows:
        category = str(redact.redact_text(finding.get("category") or "other"))[:128] or "other"
        entry = aggregates[category]
        try:
            persisted_risk = float(finding.get("risk_score") or 0)
        except (TypeError, ValueError, OverflowError):
            persisted_risk = 0.0
        entry["count"] += 1
        entry["risk_total"] += persisted_risk
        severity = str(finding.get("severity") or "unknown")[:32]
        entry["by_severity"][severity] += 1
    result = []
    for category, values in aggregates.items():
        result.append({
            "category": category,
            "count": int(values["count"]),
            "persisted_risk_total": round(float(values["risk_total"]), 1),
            "persisted_risk_average": round(
                float(values["risk_total"]) / max(1, int(values["count"])), 1
            ),
            "by_severity": dict(sorted(values["by_severity"].items())),
        })
    result.sort(key=lambda item: (-item["persisted_risk_total"], item["category"].casefold()))
    return {
        "data": result[:limit],
        "source": "persisted_findings",
        "sample_size": len(rows),
        "truncated": len(rows) == _CATEGORY_SAMPLE_MAX,
    }


def register(router: ApiRouter) -> None:
    services = router.services

    def get_risk(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset({"cutoff", "start", "end", "category_limit"}))
        if services.analytics is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The risk analytics service is not configured"))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        cutoff = _string(request, "cutoff")
        start = _string(request, "start")
        end = _string(request, "end")
        category_limit = _integer(request, "category_limit", 10, 1, 20)
        extra = services.extra if isinstance(services.extra, dict) else {}
        risk_service = extra.get("risk_service")
        if risk_service is not None:
            data = risk_service.project_summary(
                context.org_id,
                project_id,
                cutoff=cutoff,
                start=start,
                end=end,
                category_limit=category_limit,
            )
            return HttpResponse(200, {"data": data})
        summary = services.analytics.risk_summary(project_id, cutoff=cutoff)
        risk_assets = services.analytics.risk_by_asset(
            project_id, cutoff=summary["data_cutoff"], limit=10
        )
        buckets = services.analytics.risk_buckets(
            project_id, cutoff=summary["data_cutoff"], bucket_width=10
        )
        category_data = _top_categories(
            services, project_id, summary, category_limit
        )
        trend_data = _trends(services, project_id, start, end)
        return HttpResponse(200, {
            "data": {
                "project_id": project_id,
                "data_cutoff": summary["data_cutoff"],
                "risk_calculation_version": summary["risk_calculation_version"],
                "aggregate": summary,
                "severity_distribution": summary["by_severity"],
                "risk_level_distribution": summary["by_risk_level"],
                "risk_score_histogram": buckets,
                "top_assets": risk_assets,
                "top_categories": category_data,
                "score_components": {
                    "persisted_risk_total": {
                        "value": summary["total_risk"],
                        "source": "sum of persisted finding risk_score values for the reported active statuses",
                    },
                    "persisted_risk_average": {
                        "value": summary["avg_risk"],
                        "source": "average of persisted finding risk_score values for the reported active statuses",
                    },
                    "maximum_persisted_risk": {
                        "value": summary["max_risk"],
                        "source": "maximum persisted finding risk_score value",
                    },
                    "by_priority": summary["by_priority"],
                    "by_exposure": summary["by_exposure"],
                    "by_criticality": summary["by_criticality"],
                    "by_confidence": summary["by_confidence"],
                    "recalculated": False,
                },
                "trends": trend_data,
            }
        })

    def get_risk_trends(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        _query(request, frozenset({"start", "end"}))
        if services.analytics is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The risk analytics service is not configured"))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        extra = services.extra if isinstance(services.extra, dict) else {}
        risk_service = extra.get("risk_service")
        if risk_service is not None:
            trends = risk_service.project_trends(
                context.org_id,
                project_id,
                start=_string(request, "start"),
                end=_string(request, "end"),
            )
        else:
            trends = _trends(
                services,
                project_id,
                _string(request, "start"),
                _string(request, "end"),
            )
        return HttpResponse(200, {"data": {"project_id": project_id, **trends}})

    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/risk",
        methods=frozenset({"GET"}),
        handler=get_risk,
        operation_id="getProjectRisk",
        summary="Read persisted finding risk, distributions, explainable components, and bounded trends",
        tags=("risk", "analytics"),
        permission="analytics.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Persisted project risk summary"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/risk/trends",
        methods=frozenset({"GET"}),
        handler=get_risk_trends,
        operation_id="getProjectRiskTrends",
        summary="Read persisted finding lifecycle and risk-event trends in a bounded date range",
        tags=("risk", "analytics"),
        permission="analytics.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Persisted risk trends"},
    ))


__all__ = ["register"]
