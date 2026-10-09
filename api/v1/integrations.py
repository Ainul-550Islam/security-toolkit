"""Tenant-safe integration, notification, and cloud-account read/config APIs."""

from __future__ import annotations

from typing import Any

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


def _actor(context: Any) -> str:
    user_id = str(getattr(context, "user_id", "") or "")
    if user_id:
        return "user:" + user_id[:128]
    credential_id = str(getattr(context, "credential_id", "") or "")
    if credential_id:
        return "credential:" + credential_id[:128]
    return "unknown"


def _require_active_credential_issuer(services: Any, context: Any) -> None:
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


def _connection_view(view: dict[str, Any]) -> dict[str, Any]:
    result = dict(view)
    credential_ref = str(result.pop("credential_ref", "") or "")
    result["credential_reference_configured"] = bool(credential_ref)
    return result


def _connection_for_context(services: Any, context: Any, integration_id: str) -> dict[str, Any]:
    if services.integrations is None:
        raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
    view = services.integrations.get_connection(context.org_id, integration_id)
    project_id = str(view.get("project_id") or "")
    if project_id:
        services.authorization.require_project(context, project_id)
    else:
        services.authorization.require_org(context, context.org_id)
    return view


def _query(request: HttpRequest, allowed: frozenset[str]) -> None:
    if set(request.query) - allowed:
        raise ApiException(validation_problem(
            field="query", code="unknown_parameter", message="Unexpected query parameter"
        ))
    if any(len(values) > 1 for values in request.query.values()):
        raise ApiException(validation_problem(
            field="query", code="duplicate_parameter", message="Specify each parameter at most once"
        ))


def _page(request: HttpRequest, key: str, default: int, maximum: int) -> int:
    values = request.query.get(key, [])
    if not values:
        return default
    if len(values) != 1 or not values[0].isdigit():
        raise ApiException(validation_problem(
            field=key, code="invalid", message=f"{key} must be an integer"
        ))
    value = int(values[0])
    minimum = 1 if key == "limit" else 0
    if not minimum <= value <= maximum:
        raise ApiException(validation_problem(
            field=key, code="out_of_range", message=f"{key} is outside the allowed range"
        ))
    return value


def _cloud_account_view(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        raw = value.to_dict()
    else:
        raw = dict(value)
    credential_ref = str(raw.pop("credential_ref", "") or "")
    credential_hint = str(raw.pop("credential_hint", "") or "")
    raw.pop("credential_enc", None)
    raw["credential_configured"] = bool(credential_ref or credential_hint)
    return raw


def register(router: ApiRouter) -> None:
    services = router.services

    def integration_catalog(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        context = _context(request)
        services.authorization.require_org(context, params["tenant_id"])
        return HttpResponse(200, {"data": services.integrations.provider_capabilities()})

    def list_integrations(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        _query(request, frozenset({"project_id", "status", "connector_kind", "health_state", "limit", "offset"}))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        project_id = request.query.get("project_id", [""])[0]
        if project_id:
            services.authorization.require_project(context, project_id)
        result = services.integrations.list_connections(
            tenant_id,
            project_id=project_id,
            status=request.query.get("status", [""])[0],
            connector_kind=request.query.get("connector_kind", [""])[0],
            health_state=request.query.get("health_state", [""])[0],
            limit=_page(request, "limit", 100, 500),
            offset=_page(request, "offset", 0, 100_000),
        )
        return HttpResponse(200, {
            "data": [_connection_view(item) for item in result["items"]],
            "count": result["count"],
            "total": result["total"],
        })

    def create_integration(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        allowed = frozenset({
            "project_id", "name", "connector_kind", "auth_mode", "endpoint_url",
            "provider", "credential_ref", "config", "max_attempts",
        })
        body = _body(request, allowed)
        for field in ("name", "connector_kind", "auth_mode"):
            if not isinstance(body.get(field), str) or not body[field]:
                raise ApiException(validation_problem(
                    field=field, code="required", message="A valid value is required"
                ))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        project_id = body.get("project_id", "")
        if not isinstance(project_id, str):
            raise ApiException(validation_problem(
                field="project_id", code="invalid_type", message="project_id must be a string"
            ))
        if project_id:
            services.authorization.require_project(context, project_id)
        for field_name in ("endpoint_url", "provider", "credential_ref"):
            if field_name in body and not isinstance(body[field_name], str):
                raise ApiException(validation_problem(
                    field=field_name, code="invalid_type", message="Value must be a string"
                ))
        config = body.get("config", {})
        if not isinstance(config, dict):
            raise ApiException(validation_problem(
                field="config", code="invalid_type", message="config must be a JSON object"
            ))
        attempts = body.get("max_attempts", 3)
        if type(attempts) is not int or not 1 <= attempts <= 10:
            raise ApiException(validation_problem(
                field="max_attempts", code="out_of_range", message="max_attempts must be between 1 and 10"
            ))
        _require_active_credential_issuer(services, context)
        result = services.integrations.create_connection(
            tenant_id,
            project_id=project_id,
            name=body["name"],
            connector_kind=body["connector_kind"],
            auth_mode=body["auth_mode"],
            endpoint_url=body.get("endpoint_url", ""),
            provider=body.get("provider", ""),
            credential_ref=body.get("credential_ref", ""),
            config=config,
            max_attempts=attempts,
            actor=_actor(context),
        )
        return HttpResponse(201, {"data": _connection_view(result)})

    def get_integration(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        context = _context(request)
        result = _connection_for_context(services, context, params["integration_id"])
        return HttpResponse(200, {"data": _connection_view(result)})

    def update_integration(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        allowed = frozenset({"name", "endpoint_url", "provider", "auth_mode", "credential_ref", "config"})
        body = _body(request, allowed)
        if not body:
            raise ApiException(validation_problem(
                field="request", code="empty", message="At least one configuration field is required"
            ))
        context = _context(request)
        _require_active_credential_issuer(services, context)
        current = _connection_for_context(services, context, params["integration_id"])
        for field_name in ("name", "endpoint_url", "provider", "auth_mode", "credential_ref"):
            if field_name in body and not isinstance(body[field_name], str):
                raise ApiException(validation_problem(
                    field=field_name, code="invalid_type", message="Value must be a string"
                ))
        if "config" in body and not isinstance(body["config"], dict):
            raise ApiException(validation_problem(
                field="config", code="invalid_type", message="config must be a JSON object"
            ))
        result = services.integrations.update_configuration(
            context.org_id,
            params["integration_id"],
            name=body.get("name"),
            endpoint_url=body.get("endpoint_url"),
            provider=body.get("provider"),
            auth_mode=body.get("auth_mode"),
            credential_ref=body.get("credential_ref"),
            config=body.get("config"),
            actor=_actor(context),
        )
        if str(current.get("project_id") or "") != str(result.get("project_id") or ""):
            raise ApiException(ApiProblem(409, "scope_changed", "The integration scope changed unexpectedly"))
        return HttpResponse(200, {"data": _connection_view(result)})

    def enable_integration(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        _body(request, frozenset())
        context = _context(request)
        _require_active_credential_issuer(services, context)
        current = _connection_for_context(services, context, params["integration_id"])
        validation = services.integrations.validate(context.org_id, params["integration_id"])
        if current.get("status") == "enabled":
            raise ApiException(ApiProblem(409, "invalid_state_transition", "The integration is already enabled"))
        if validation.get("configuration_status") != "valid":
            raise ApiException(ApiProblem(409, "integration_misconfigured", "The integration configuration must be valid before activation"))
        actor = _actor(context)
        result = services.integrations.enable(
            context.org_id,
            params["integration_id"],
            approved_by=actor,
            actor=actor,
        )
        if str(current.get("project_id") or "") != str(result.get("project_id") or ""):
            raise ApiException(ApiProblem(409, "scope_changed", "The integration scope changed unexpectedly"))
        return HttpResponse(200, {"data": _connection_view(result)})

    def disable_integration(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        _body(request, frozenset())
        context = _context(request)
        _require_active_credential_issuer(services, context)
        _connection_for_context(services, context, params["integration_id"])
        result = services.integrations.disable(
            context.org_id, params["integration_id"], actor=_actor(context)
        )
        return HttpResponse(200, {"data": _connection_view(result)})

    def test_integration(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        _body(request, frozenset())
        context = _context(request)
        _require_active_credential_issuer(services, context)
        _connection_for_context(services, context, params["integration_id"])
        result = services.integrations.test_connection(
            context.org_id, params["integration_id"], actor=_actor(context)
        )
        return HttpResponse(200, {"data": result})

    def integration_health(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        context = _context(request)
        _require_active_credential_issuer(services, context)
        result = _connection_for_context(services, context, params["integration_id"])
        health = services.integrations.health(
            context.org_id,
            integration_id=params["integration_id"],
            actor=_actor(context),
        )
        return HttpResponse(200, {"data": {"integration": _connection_view(result), **health}})

    def integration_deliveries(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        _query(request, frozenset({"status", "limit", "offset"}))
        context = _context(request)
        _connection_for_context(services, context, params["integration_id"])
        result = services.integrations.delivery_state(
            context.org_id,
            integration_id=params["integration_id"],
            status=request.query.get("status", [""])[0],
            limit=_page(request, "limit", 50, 500),
            offset=_page(request, "offset", 0, 100_000),
        )
        return HttpResponse(200, result)

    def list_integration_health(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.integrations is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The integration service is not configured"))
        _query(request, frozenset({"limit"}))
        context = _context(request)
        _require_active_credential_issuer(services, context)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        limit = _page(request, "limit", 100, 500)
        result = services.integrations.health(tenant_id, limit=limit, actor=_actor(context))
        return HttpResponse(200, {"data": result})

    def notification_settings(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.notifications is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The notification service is not configured"))
        project_id = params["project_id"]
        context = _context(request)
        services.authorization.require_project(context, project_id)
        return HttpResponse(200, {
            "data": services.notifications.settings_view(
                project_id,
                org_id=context.org_id,
            )
        })

    def update_notification_settings(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.notifications is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The notification service is not configured"))
        allowed = frozenset({
            "email_enabled", "email_to", "webhook_enabled", "webhook_url",
            "webhook_secret", "keep_secret",
        })
        body = _body(request, allowed)
        if not body:
            raise ApiException(validation_problem(
                field="request", code="empty", message="At least one setting is required"
            ))
        for field in ("email_enabled", "webhook_enabled", "keep_secret"):
            if field in body and type(body[field]) is not bool:
                raise ApiException(validation_problem(
                    field=field, code="invalid_type", message="Value must be a boolean"
                ))
        for field, maximum in (("email_to", 200), ("webhook_url", 512), ("webhook_secret", 4096)):
            if field not in body:
                continue
            if not isinstance(body[field], str):
                raise ApiException(validation_problem(
                    field=field, code="invalid", message="Value is invalid or too large"
                ))
            try:
                size = len(body[field].encode("utf-8", "strict"))
            except UnicodeEncodeError:
                size = maximum + 1
            if size > maximum:
                raise ApiException(validation_problem(
                    field=field, code="invalid", message="Value is invalid or too large"
                ))
        if "webhook_secret" in body and not body["webhook_secret"]:
            raise ApiException(validation_problem(
                field="webhook_secret", code="required", message="Provide a non-empty write-only secret"
            ))
        context = _context(request)
        project_id = params["project_id"]
        project = services.authorization.require_project(context, project_id)
        _require_active_credential_issuer(services, context)
        result = services.notifications.update_settings(
            context.org_id,
            project_id,
            body,
            actor=_actor(context),
        )
        return HttpResponse(200, {"data": result, "project_id": project.id})

    def upsert_finding_ticket(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.ticketing is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The ticketing service is not configured"))
        body = _body(request, frozenset({"integration_id"}))
        integration_id = body.get("integration_id")
        if not isinstance(integration_id, str) or not 1 <= len(integration_id) <= 128:
            raise ApiException(validation_problem(
                field="integration_id", code="required", message="A valid ticketing integration is required"
            ))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        _require_active_credential_issuer(services, context)
        result = services.ticketing.upsert_finding(
            context.org_id,
            project_id,
            integration_id,
            params["finding_id"],
        )
        return HttpResponse(200, {"data": result})

    def close_finding_ticket(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.ticketing is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The ticketing service is not configured"))
        body = _body(request, frozenset({"integration_id"}))
        integration_id = body.get("integration_id")
        if not isinstance(integration_id, str) or not 1 <= len(integration_id) <= 128:
            raise ApiException(validation_problem(
                field="integration_id", code="required", message="A valid ticketing integration is required"
            ))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        _require_active_credential_issuer(services, context)
        result = services.ticketing.close_finding(
            context.org_id,
            project_id,
            integration_id,
            params["finding_id"],
        )
        return HttpResponse(200, {"data": result})

    def link_finding_ticket(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.ticketing is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The ticketing service is not configured"))
        body = _body(request, frozenset({"integration_id", "related_finding_id"}))
        integration_id = body.get("integration_id")
        related_finding_id = body.get("related_finding_id")
        if not isinstance(integration_id, str) or not 1 <= len(integration_id) <= 128:
            raise ApiException(validation_problem(
                field="integration_id", code="required", message="A valid ticketing integration is required"
            ))
        if not isinstance(related_finding_id, str) or not 1 <= len(related_finding_id) <= 128:
            raise ApiException(validation_problem(
                field="related_finding_id", code="required", message="A valid related finding is required"
            ))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        _require_active_credential_issuer(services, context)
        result = services.ticketing.link_findings(
            context.org_id,
            project_id,
            integration_id,
            params["finding_id"],
            related_finding_id,
        )
        return HttpResponse(200, {"data": result})

    def list_notifications(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.notifications is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The notification service is not configured"))
        _query(request, frozenset({"status", "limit"}))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        status_values = request.query.get("status", [])
        if len(status_values) > 1 or (status_values and len(status_values[0]) > 32):
            raise ApiException(validation_problem(
                field="status", code="invalid", message="Status filter is invalid"
            ))
        result = services.notifications.list_notifications(
            context.org_id,
            project_id,
            status=status_values[0] if status_values else "",
            limit=_page(request, "limit", 100, 500),
        )
        return HttpResponse(200, {
            "data": result,
            "counts": services.notifications.notification_counts(context.org_id, project_id),
        })

    def get_notification(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.notifications is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The notification service is not configured"))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        result = services.notifications.notification_view(
            context.org_id,
            project_id,
            params["notification_id"],
        )
        return HttpResponse(200, {"data": result})

    def retry_notification(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.notifications is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The notification service is not configured"))
        context = _context(request)
        project_id = params["project_id"]
        services.authorization.require_project(context, project_id)
        _require_active_credential_issuer(services, context)
        result = services.notifications.retry(
            context.org_id,
            params["notification_id"],
            project_id=project_id,
            actor=_actor(context),
        )
        return HttpResponse(200, {"data": result})

    def create_cloud_account(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.clouds is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The cloud security service is not configured"))
        allowed = frozenset({
            "provider", "account_identifier", "display_name", "region_scope",
            "credential_ref", "credential_secret",
        })
        body = _body(request, allowed)
        for field in ("provider", "account_identifier"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                raise ApiException(validation_problem(
                    field=field, code="required", message="A valid value is required"
                ))
        for field in ("display_name", "credential_ref", "credential_secret"):
            if field in body and not isinstance(body[field], str):
                raise ApiException(validation_problem(
                    field=field, code="invalid_type", message="Value must be a string"
                ))
        regions = body.get("region_scope", [])
        if (
            not isinstance(regions, list)
            or len(regions) > 64
            or any(not isinstance(region, str) or len(region) > 64 for region in regions)
        ):
            raise ApiException(validation_problem(
                field="region_scope", code="invalid", message="region_scope must contain at most 64 bounded strings"
            ))
        credential_secret = body.get("credential_secret", "")
        if len(credential_secret.encode("utf-8")) > 16_384:
            raise ApiException(validation_problem(
                field="credential_secret", code="too_large", message="Credential value is too large"
            ))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        _require_active_credential_issuer(services, context)
        if credential_secret:
            services.authorization.require(context, "cloud.account.manage_credentials")
        result = services.clouds.account_create(
            tenant_id,
            provider=body["provider"],
            account_identifier=body["account_identifier"],
            display_name=body.get("display_name", ""),
            region_scope=regions,
            credential_ref=body.get("credential_ref", ""),
            credential_secret=credential_secret or None,
            created_by=_actor(context),
        )
        return HttpResponse(201, {"data": _cloud_account_view(result)})

    def update_cloud_account(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.clouds is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The cloud security service is not configured"))
        allowed = frozenset({"display_name", "enabled", "region_scope", "credential_secret"})
        body = _body(request, allowed)
        if not body:
            raise ApiException(validation_problem(
                field="request", code="empty", message="At least one update field is required"
            ))
        if "display_name" in body and not isinstance(body["display_name"], str):
            raise ApiException(validation_problem(
                field="display_name", code="invalid_type", message="display_name must be a string"
            ))
        if "enabled" in body and type(body["enabled"]) is not bool:
            raise ApiException(validation_problem(
                field="enabled", code="invalid_type", message="enabled must be a boolean"
            ))
        regions = body.get("region_scope")
        if regions is not None and (
            not isinstance(regions, list)
            or len(regions) > 64
            or any(not isinstance(region, str) or len(region) > 64 for region in regions)
        ):
            raise ApiException(validation_problem(
                field="region_scope", code="invalid", message="region_scope must contain at most 64 bounded strings"
            ))
        credential_secret = body.get("credential_secret", "")
        if not isinstance(credential_secret, str):
            raise ApiException(validation_problem(
                field="credential_secret", code="invalid_type", message="credential_secret must be a string"
            ))
        if "credential_secret" in body and not credential_secret:
            raise ApiException(validation_problem(
                field="credential_secret", code="required", message="Provide a non-empty credential value"
            ))
        if len(credential_secret.encode("utf-8")) > 16_384:
            raise ApiException(validation_problem(
                field="credential_secret", code="too_large", message="Credential value is too large"
            ))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        _require_active_credential_issuer(services, context)
        current = services.clouds.account_get(tenant_id, params["account_id"])
        if credential_secret:
            services.authorization.require(context, "cloud.account.manage_credentials")
        result = services.clouds.account_update(
            tenant_id,
            params["account_id"],
            display_name=body.get("display_name"),
            enabled=body.get("enabled"),
            region_scope=regions,
            credential_secret=credential_secret or None,
            actor=_actor(context),
        )
        if result.org_id != current.org_id or result.id != current.id:
            raise ApiException(ApiProblem(409, "scope_changed", "The cloud account scope changed unexpectedly"))
        return HttpResponse(200, {"data": _cloud_account_view(result)})

    def list_cloud_accounts(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.clouds is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The cloud security service is not configured"))
        _query(request, frozenset({"limit"}))
        context = _context(request)
        tenant_id = params["tenant_id"]
        services.authorization.require_org(context, tenant_id)
        result = services.clouds.account_list(tenant_id, limit=_page(request, "limit", 100, 500))
        return HttpResponse(200, {"data": [_cloud_account_view(item) for item in result], "count": len(result)})

    def get_cloud_account(request: HttpRequest, params: dict[str, str]) -> HttpResponse:
        if services.clouds is None:
            raise ApiException(ApiProblem(503, "service_not_configured", "The cloud security service is not configured"))
        context = _context(request)
        services.authorization.require_org(context, params["tenant_id"])
        account = services.clouds.account_get(params["tenant_id"], params["account_id"])
        return HttpResponse(200, {"data": _cloud_account_view(account)})

    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/integration-catalog",
        methods=frozenset({"GET"}), handler=integration_catalog,
        operation_id="getIntegrationCatalog",
        summary="Read the canonical connector and capability catalog",
        tags=("integrations",), permission="integration.read",
        scope_kind="organization", scope_parameter="tenant_id",
        response_schema={"type": "object"}, responses={"200": "Connector catalog"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/integrations",
        methods=frozenset({"GET"}), handler=list_integrations,
        operation_id="listTenantIntegrations",
        summary="List integrations within one tenant with bounded filters",
        tags=("integrations",), permission="integration.read",
        scope_kind="organization", scope_parameter="tenant_id",
        response_schema={"type": "object"}, responses={"200": "Tenant integrations"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/integrations",
        methods=frozenset({"POST"}), handler=create_integration,
        operation_id="createTenantIntegration",
        summary="Create a disabled integration using secret references only",
        tags=("integrations",), permission="integration.create",
        scope_kind="organization", scope_parameter="tenant_id",
        request_schema={
            "type": "object", "required": ["name", "connector_kind", "auth_mode"],
            "additionalProperties": False,
            "properties": {
                "project_id": {"type": "string"},
                "name": {"type": "string", "minLength": 3, "maxLength": 96},
                "connector_kind": {"type": "string"},
                "auth_mode": {"type": "string"},
                "endpoint_url": {"type": "string", "maxLength": 2048},
                "provider": {"type": "string", "maxLength": 128},
                "credential_ref": {"type": "string", "maxLength": 512},
                "config": {"type": "object"},
                "max_attempts": {"type": "integer", "minimum": 1, "maximum": 10},
            },
        },
        response_schema={"type": "object"}, responses={"201": "Disabled integration created"},
    ))
    router.register(RouteSpec(
        path="/api/v1/integrations/{integration_id}",
        methods=frozenset({"GET"}), handler=get_integration,
        operation_id="getIntegration",
        summary="Read one tenant integration after project/tenant ownership checks",
        tags=("integrations",), permission="integration.read",
        response_schema={"type": "object"}, responses={"200": "Integration metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/integrations/{integration_id}",
        methods=frozenset({"PATCH"}), handler=update_integration,
        operation_id="updateIntegration",
        summary="Update integration configuration without accepting raw credential material",
        tags=("integrations",), permission="integration.configure",
        request_schema={"type": "object", "additionalProperties": False, "properties": {
            "name": {"type": "string", "maxLength": 96},
            "endpoint_url": {"type": "string", "maxLength": 2048},
            "provider": {"type": "string", "maxLength": 128},
            "auth_mode": {"type": "string"},
            "credential_ref": {"type": "string", "maxLength": 512},
            "config": {"type": "object"},
        }},
        response_schema={"type": "object"}, responses={"200": "Integration updated"},
    ))
    for suffix, method, operation_id, handler, permission, summary in (
        ("enable", "POST", "enableIntegration", enable_integration, "integration.enable", "Validate and activate an integration with separation of duties"),
        ("disable", "POST", "disableIntegration", disable_integration, "integration.disable", "Disable an integration and stop outbound activity"),
        ("test", "POST", "testIntegration", test_integration, "integration.test", "Run the existing honest integration connectivity check"),
    ):
        router.register(RouteSpec(
            path=f"/api/v1/integrations/{{integration_id}}/{suffix}",
            methods=frozenset({method}), handler=handler,
            operation_id=operation_id, summary=summary,
            tags=("integrations",), permission=permission,
            request_schema={"type": "object", "additionalProperties": False},
            response_schema={"type": "object"}, responses={"200": "Integration operation result"},
        ))
    router.register(RouteSpec(
        path="/api/v1/integrations/{integration_id}/health",
        methods=frozenset({"GET"}), handler=integration_health,
        operation_id="getIntegrationHealth",
        summary="Read existing integration health without inventing a successful check",
        tags=("integrations",), permission="integration.health",
        response_schema={"type": "object"}, responses={"200": "Integration health"},
    ))
    router.register(RouteSpec(
        path="/api/v1/integrations/{integration_id}/deliveries",
        methods=frozenset({"GET"}), handler=integration_deliveries,
        operation_id="listIntegrationDeliveries",
        summary="List bounded, minimized integration delivery receipts",
        tags=("integrations",), permission="integration.audit",
        response_schema={"type": "object"}, responses={"200": "Integration deliveries"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/integration-health",
        methods=frozenset({"GET"}), handler=list_integration_health,
        operation_id="listTenantIntegrationHealth",
        summary="Read bounded health states for tenant integrations",
        tags=("integrations",), permission="integration.health",
        scope_kind="organization", scope_parameter="tenant_id",
        response_schema={"type": "object"}, responses={"200": "Tenant integration health"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications/settings",
        methods=frozenset({"GET"}), handler=notification_settings,
        operation_id="getNotificationSettings",
        summary="Read safe notification settings without returning secrets",
        tags=("integrations", "notifications"), permission="notification.read",
        scope_kind="project", scope_parameter="project_id",
        response_schema={"type": "object"}, responses={"200": "Notification settings"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications/settings",
        methods=frozenset({"PATCH"}), handler=update_notification_settings,
        operation_id="updateNotificationSettings",
        summary="Update notification destinations with write-only webhook secrets",
        tags=("integrations", "notifications"), permission="notification.configure",
        scope_kind="project", scope_parameter="project_id",
        request_schema={
            "type": "object", "additionalProperties": False,
            "minProperties": 1,
            "properties": {
                "email_enabled": {"type": "boolean"},
                "email_to": {"type": "string", "maxLength": 200},
                "webhook_enabled": {"type": "boolean"},
                "webhook_url": {"type": "string", "maxLength": 512},
                "webhook_secret": {"type": "string", "minLength": 8, "maxLength": 4096, "writeOnly": True},
                "keep_secret": {"type": "boolean"},
            },
        },
        response_schema={"type": "object"}, responses={"200": "Safe notification settings"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/findings/{finding_id}/ticket",
        methods=frozenset({"POST"}), handler=upsert_finding_ticket,
        operation_id="upsertFindingTicket",
        summary="Create or update the idempotent external ticket for one finding",
        tags=("integrations", "ticketing"), permission="integration.send",
        scope_kind="project", scope_parameter="project_id",
        request_schema={
            "type": "object", "required": ["integration_id"],
            "additionalProperties": False,
            "properties": {"integration_id": {"type": "string", "minLength": 1, "maxLength": 128}},
        },
        response_schema={"type": "object"},
        responses={"200": "External issue reference", "404": "Finding or integration not found", "503": "Ticketing credentials unavailable"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/findings/{finding_id}/ticket/close",
        methods=frozenset({"POST"}), handler=close_finding_ticket,
        operation_id="closeFindingTicket",
        summary="Close the external issue linked to one local finding",
        tags=("integrations", "ticketing"), permission="integration.send",
        scope_kind="project", scope_parameter="project_id",
        request_schema={
            "type": "object", "required": ["integration_id"],
            "additionalProperties": False,
            "properties": {"integration_id": {"type": "string", "minLength": 1, "maxLength": 128}},
        },
        response_schema={"type": "object"},
        responses={"200": "Closed external issue reference", "404": "Finding or issue not found"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/findings/{finding_id}/ticket/link",
        methods=frozenset({"POST"}), handler=link_finding_ticket,
        operation_id="linkFindingTickets",
        summary="Link the external issues for two tenant-local findings",
        tags=("integrations", "ticketing"), permission="integration.send",
        scope_kind="project", scope_parameter="project_id",
        request_schema={
            "type": "object", "required": ["integration_id", "related_finding_id"],
            "additionalProperties": False,
            "properties": {
                "integration_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "related_finding_id": {"type": "string", "minLength": 1, "maxLength": 128},
            },
        },
        response_schema={"type": "object"},
        responses={"200": "Linked external issue reference", "404": "Finding or issue not found"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications",
        methods=frozenset({"GET"}), handler=list_notifications,
        operation_id="listProjectNotifications",
        summary="List delivery states and aggregate counts for one project",
        tags=("notifications",), permission="notification.read",
        scope_kind="project", scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Tenant-scoped notification delivery records"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications/delivery/{notification_id}",
        methods=frozenset({"GET"}), handler=get_notification,
        operation_id="getProjectNotification",
        summary="Read one redacted notification and bounded delivery attempts",
        tags=("notifications",), permission="notification.read",
        scope_kind="project", scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Notification state", "404": "Notification not found"},
    ))
    router.register(RouteSpec(
        path="/api/v1/projects/{project_id}/notifications/delivery/{notification_id}/retry",
        methods=frozenset({"POST"}), handler=retry_notification,
        operation_id="retryProjectNotification",
        summary="Request a rate-limited retry for a project notification",
        tags=("notifications",), permission="notification.retry",
        scope_kind="project", scope_parameter="project_id",
        response_schema={"type": "object"},
        responses={"200": "Retry result", "404": "Notification not found", "409": "Notification cannot be retried", "429": "Retry rate limit reached"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/cloud-accounts",
        methods=frozenset({"GET"}), handler=list_cloud_accounts,
        operation_id="listTenantCloudAccounts",
        summary="List registered cloud accounts without credential references or material",
        tags=("integrations", "cloud"), permission="cloud.read",
        scope_kind="organization", scope_parameter="tenant_id",
        response_schema={"type": "object"}, responses={"200": "Cloud account metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/cloud-accounts",
        methods=frozenset({"POST"}), handler=create_cloud_account,
        operation_id="createTenantCloudAccount",
        summary="Register a tenant cloud account and accept credentials write-only",
        tags=("integrations", "cloud"), permission="cloud.account.create",
        scope_kind="organization", scope_parameter="tenant_id",
        request_schema={
            "type": "object",
            "required": ["provider", "account_identifier"],
            "additionalProperties": False,
            "properties": {
                "provider": {"type": "string", "minLength": 2, "maxLength": 24},
                "account_identifier": {"type": "string", "minLength": 1, "maxLength": 256},
                "display_name": {"type": "string", "maxLength": 128},
                "region_scope": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 64}},
                "credential_ref": {"type": "string", "maxLength": 128},
                "credential_secret": {"type": "string", "maxLength": 16384, "writeOnly": True},
            },
        },
        response_schema={"type": "object"}, responses={"201": "Cloud account registered"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/cloud-accounts/{account_id}",
        methods=frozenset({"GET"}), handler=get_cloud_account,
        operation_id="getTenantCloudAccount",
        summary="Read one tenant cloud account after organization ownership checks",
        tags=("integrations", "cloud"), permission="cloud.read",
        scope_kind="organization", scope_parameter="tenant_id",
        response_schema={"type": "object"}, responses={"200": "Cloud account metadata"},
    ))
    router.register(RouteSpec(
        path="/api/v1/tenants/{tenant_id}/cloud-accounts/{account_id}",
        methods=frozenset({"PATCH"}), handler=update_cloud_account,
        operation_id="updateTenantCloudAccount",
        summary="Update cloud account metadata and rotate credentials write-only",
        tags=("integrations", "cloud"), permission="cloud.account.update",
        scope_kind="organization", scope_parameter="tenant_id",
        request_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "display_name": {"type": "string", "maxLength": 128},
                "enabled": {"type": "boolean"},
                "region_scope": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 64}},
                "credential_secret": {"type": "string", "maxLength": 16384, "writeOnly": True},
            },
        },
        response_schema={"type": "object"}, responses={"200": "Cloud account updated"},
    ))


__all__ = ["register"]
