"""Project-scoped asset APIs over PlatformService."""

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


def _asset_view(asset: Any) -> dict[str, Any]:
    return {
        "id": asset.id,
        "project_id": asset.project_id,
        "asset_type": asset.asset_type,
        "value": str(redact.redact_text(asset.value))[:2048],
        "display": str(redact.redact_text(asset.display))[:2048],
        "metadata": redact.redact(asset.metadata if isinstance(asset.metadata, dict) else {}),
        "status": asset.status,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
    }


def register(router: ApiRouter) -> None:
    services = router.services

    def list_assets(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        project_id = params["project_id"]
        context = _context(request)
        services.authorization.require_project(context, project_id)
        type_values = request.query.get("asset_type", [])
        if len(type_values) > 1:
            raise ApiException(validation_problem(
                field="asset_type", code="invalid", message="Specify one asset type"
            ))
        asset_type = type_values[0] if type_values else ""
        if asset_type and asset_type not in models.ASSET_TYPES:
            raise ApiException(validation_problem(
                field="asset_type", code="invalid", message="Asset type is not supported"
            ))
        extra = services.extra if isinstance(services.extra, dict) else {}
        asset_service = extra.get("asset_service")
        if asset_service is not None:
            assets = asset_service.list_assets(
                context.org_id,
                project_id,
                asset_type=asset_type,
                limit=_limit(request),
            )
        else:
            assets = services.platform.asset_list(
                project_id,
                asset_type=asset_type or None,
                limit=_limit(request),
            )
        return HttpResponse(200, {"data": [_asset_view(asset) for asset in assets], "count": len(assets)})

    def create_asset(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request, frozenset({"asset_type", "value", "display"}))
        asset_type = body.get("asset_type")
        value = body.get("value")
        display = body.get("display", "")
        if not isinstance(asset_type, str) or asset_type not in models.ASSET_TYPES:
            raise ApiException(validation_problem(
                field="asset_type", code="invalid", message="Asset type is not supported"
            ))
        if not isinstance(value, str) or not 1 <= len(value) <= 2048:
            raise ApiException(validation_problem(
                field="value", code="invalid", message="Asset value is required and bounded"
            ))
        if not isinstance(display, str) or len(display) > 2048:
            raise ApiException(validation_problem(
                field="display", code="invalid", message="Display value exceeds the allowed length"
            ))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        extra = services.extra if isinstance(services.extra, dict) else {}
        asset_service = extra.get("asset_service")
        if asset_service is not None:
            asset = asset_service.add_asset(
                context.org_id,
                project_id,
                asset_type,
                value,
                display=display,
                actor=context.label(),
            )
        else:
            asset = services.platform.asset_add(
                project_id,
                asset_type,
                value,
                display=display,
                actor=context.label(),
            )
        return HttpResponse(201, {"data": _asset_view(asset)})

    def get_asset(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        asset = services.authorization.require_asset(context, params["asset_id"])
        extra = services.extra if isinstance(services.extra, dict) else {}
        asset_service = extra.get("asset_service")
        if asset_service is not None:
            asset = asset_service.get_asset(context.org_id, params["asset_id"])
        return HttpResponse(200, {"data": _asset_view(asset)})

    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/assets",
        methods=frozenset({"GET"}),
        handler=list_assets,
        operation_id="listProjectAssets",
        summary="List assets within one authorized project",
        tags=("assets",),
        permission="asset.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Project assets"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/assets",
        methods=frozenset({"POST"}),
        handler=create_asset,
        operation_id="createProjectAsset",
        summary="Add a normalized asset through PlatformService",
        tags=("assets",),
        permission="asset.create",
        scope_kind="project",
        scope_parameter="project_id",
        request_schema={
            "type": "object",
            "required": ["asset_type", "value"],
            "additionalProperties": False,
            "properties": {
                "asset_type": {"type": "string", "enum": list(models.ASSET_TYPES)},
                "value": {"type": "string", "minLength": 1, "maxLength": 2048},
                "display": {"type": "string", "maxLength": 2048},
            },
        },
        response_schema={"type": "object"},
        responses={"201": "Asset created"},
    ))
    router.register(RouteSpec(
        path="/api/v1/assets/{asset_id}",
        methods=frozenset({"GET"}),
        handler=get_asset,
        operation_id="getAsset",
        summary="Read one asset after project ownership authorization",
        tags=("assets",),
        permission="asset.read",
        response_schema={"type": "object"},
        responses={"200": "Asset metadata", "403": "Asset is outside the caller's project scope"},
    ))


__all__ = ["register"]
