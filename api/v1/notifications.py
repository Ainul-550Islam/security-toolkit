"""Customer notification preferences and provider-capability APIs.

The existing ``api.v1.integrations`` module remains the canonical owner of
notification history, delivery status, detail, and retry routes. This module
adds resource-style preference/channel endpoints without registering duplicate
paths or creating another notification engine.
"""

from __future__ import annotations

from typing import Any

from api.errors import ApiException, ApiProblem, validation_problem
from api.middleware import HttpRequest, HttpResponse
from api.router import ApiRouter, RouteSpec


_SETTING_FIELDS = frozenset({
    "email_enabled", "email_to", "webhook_enabled", "webhook_url",
    "webhook_secret", "keep_secret",
})


def _context(request: HttpRequest) -> Any:
    if request.context is None:
        raise ApiException(ApiProblem(401, "authentication_failed", "Authentication required or invalid"))
    return request.context.authorization_context


def _body(request: HttpRequest) -> dict[str, Any]:
    if not isinstance(request.body, dict):
        raise ApiException(validation_problem(
            field="request", code="invalid_type", message="A JSON object is required"
        ))
    if set(request.body) - _SETTING_FIELDS:
        raise ApiException(validation_problem(
            field="request", code="unknown_field", message="Unexpected field"
        ))
    if not request.body:
        raise ApiException(validation_problem(
            field="request", code="empty", message="At least one setting is required"
        ))
    for field in ("email_enabled", "webhook_enabled", "keep_secret"):
        if field in request.body and type(request.body[field]) is not bool:
            raise ApiException(validation_problem(
                field=field, code="invalid_type", message="Value must be a boolean"
            ))
    for field, maximum in (("email_to", 200), ("webhook_url", 512), ("webhook_secret", 4096)):
        if field not in request.body:
            continue
        value = request.body[field]
        if not isinstance(value, str):
            raise ApiException(validation_problem(
                field=field, code="invalid", message="Value is invalid or too large"
            ))
        try:
            size = len(value.encode("utf-8", "strict"))
        except UnicodeEncodeError:
            size = maximum + 1
        if size > maximum:
            raise ApiException(validation_problem(
                field=field, code="invalid", message="Value is invalid or too large"
            ))
    if "webhook_secret" in request.body:
        secret = request.body["webhook_secret"]
        if not secret or len(secret) < 8:
            raise ApiException(validation_problem(
                field="webhook_secret", code="invalid", message="Provide a non-empty secret of at least eight characters"
            ))
    return request.body


def _active_credential_issuer(services: Any, context: Any) -> None:
    if not getattr(context, "credential_id", ""):
        return
    user_id = str(getattr(context, "user_id", "") or "")
    if not user_id:
        raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user"))
    try:
        user = services.identity.user_get(user_id)
    except Exception:
        raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user")) from None
    if user.org_id != context.org_id or user.status != "active":
        raise ApiException(ApiProblem(403, "forbidden", "The API credential has no active issuing user"))


def _service(services: Any) -> Any:
    if services.notifications is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The notification service is not configured"))
    return services.notifications


def register(router: ApiRouter) -> None:
    services = router.services

    def get_preferences(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        settings = _service(services).settings_view(project_id, org_id=context.org_id)
        return HttpResponse(200, {"data": settings})

    def update_preferences(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        body = _body(request)
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        _active_credential_issuer(services, context)
        settings = _service(services).update_settings(
            context.org_id, project_id, body, actor=context.label()
        )
        return HttpResponse(200, {"data": settings, "project_id": project_id})

    def get_channels(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        service = _service(services)
        return HttpResponse(200, {
            "data": {
                "channels": service.available_channels(),
                "preferences": service.settings_view(project_id, org_id=context.org_id),
            }
        })

    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications/preferences",
        methods=frozenset({"GET"}),
        handler=get_preferences,
        operation_id="getNotificationPreferences",
        summary="Read safe project notification preferences without secret material",
        tags=("notifications",),
        permission="notification.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Safe notification preferences"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications/preferences",
        methods=frozenset({"PATCH"}),
        handler=update_preferences,
        operation_id="updateNotificationPreferences",
        summary="Update write-only notification destinations through the existing notification engine",
        tags=("notifications",),
        permission="notification.configure",
        scope_kind="project",
        scope_parameter="project_id",
        request_schema={
            "type": "object",
            "minProperties": 1,
            "additionalProperties": False,
            "properties": {
                "email_enabled": {"type": "boolean"},
                "email_to": {"type": "string", "maxLength": 200},
                "webhook_enabled": {"type": "boolean"},
                "webhook_url": {"type": "string", "maxLength": 512},
                "webhook_secret": {"type": "string", "minLength": 8, "maxLength": 4096, "writeOnly": True},
                "keep_secret": {"type": "boolean"},
            },
        },
        response_schema={"type": "object"},
        responses={"200": "Updated secret-free notification preferences"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications/channels",
        methods=frozenset({"GET"}),
        handler=get_channels,
        operation_id="getNotificationChannels",
        summary="Read configured/unavailable notification channels and safe project preferences",
        tags=("notifications",),
        permission="notification.read",
        scope_kind="project",
        scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Provider channel availability"},
    ))


__all__ = ["register"]
