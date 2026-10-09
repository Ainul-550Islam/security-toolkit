"""Central integration lifecycle facade over the provider-neutral engine.

Connector capabilities, validation, secret-reference encryption/governance,
health semantics, delivery state, and network operations remain in the
existing EnterpriseIntegrationService. This service enforces tenant scope and
exposes lifecycle operations without accepting raw provider secrets.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .customer_resource_service import _domain_module

errors = _domain_module("errors")
models = _domain_module("models")

_MAX_LIMIT = 500


class IntegrationService:
    """Tenant-safe lifecycle and capability facade for existing integrations."""

    def __init__(self, platform: Any, engine: Any) -> None:
        self.platform = platform
        self.db = platform.db
        self.engine = engine
        self.connections = engine.connections
        self.outbound = engine.outbound
        self.inbound = engine.inbound
        self.delivery_runner = engine.delivery_runner

    def __getattr__(self, name: str) -> Any:
        """Preserve established provider-neutral engine access for adapters."""
        return getattr(self.engine, name)

    def _org(self, org_id: str) -> None:
        if not isinstance(org_id, str) or not org_id:
            raise errors.ValidationError("tenant scope is required")
        self.platform.org_require(org_id)

    def _project(self, org_id: str, project_id: str) -> None:
        if not project_id:
            return
        try:
            project = self.platform.project_get(project_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("project not found") from None
        if project.org_id != org_id:
            raise errors.NotFoundError("project not found")

    def _connection(self, org_id: str, integration_id: str) -> dict[str, Any]:
        self._org(org_id)
        try:
            row = self.connections._connection(org_id, integration_id)
        except errors.NotFoundError:
            raise errors.NotFoundError("integration not found") from None
        self._project(org_id, str(row.get("project_id") or ""))
        return row

    def provider_capabilities(self) -> dict[str, Any]:
        """Return canonical connector/auth/capability metadata, no secrets."""
        return self.connections.catalog()

    def list_connections(
        self,
        org_id: str,
        *,
        project_id: str = "",
        status: str = "",
        connector_kind: str = "",
        health_state: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._org(org_id)
        self._project(org_id, project_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("integration page limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset <= 100_000:
            raise errors.ValidationError("integration page offset is outside the allowed range")
        return self.connections.list(
            org_id,
            project_id=project_id,
            status=status,
            connector_kind=connector_kind,
            health_state=health_state,
            limit=limit,
            offset=offset,
        )

    def create_connection(
        self,
        org_id: str,
        *,
        project_id: str = "",
        name: str,
        connector_kind: str,
        auth_mode: str,
        endpoint_url: str = "",
        provider: str = "",
        credential_ref: str = "",
        config: Mapping[str, Any] | None = None,
        max_attempts: int = 3,
        actor: str = "api",
    ) -> dict[str, Any]:
        self._org(org_id)
        self._project(org_id, project_id)
        if config is not None and not isinstance(config, Mapping):
            raise errors.ValidationError("integration config must be an object")
        return self.connections.create(
            org_id,
            project_id=project_id,
            name=name,
            connector_kind=connector_kind,
            auth_mode=auth_mode,
            endpoint_url=endpoint_url,
            provider=provider,
            credential_ref=credential_ref,
            config=dict(config or {}),
            max_attempts=max_attempts,
            actor=actor,
        )

    def get_connection(self, org_id: str, integration_id: str) -> dict[str, Any]:
        row = self._connection(org_id, integration_id)
        return self.connections._public(row)

    def validate(self, org_id: str, integration_id: str) -> dict[str, Any]:
        self._connection(org_id, integration_id)
        return self.connections.validate(org_id, integration_id)

    def update_configuration(
        self,
        org_id: str,
        integration_id: str,
        *,
        endpoint_url: str | None = None,
        name: str | None = None,
        provider: str | None = None,
        auth_mode: str | None = None,
        credential_ref: str | None = None,
        config: Mapping[str, Any] | None = None,
        actor: str = "api",
    ) -> dict[str, Any]:
        current = self._connection(org_id, integration_id)
        if config is not None and not isinstance(config, Mapping):
            raise errors.ValidationError("integration config must be an object")
        if credential_ref is not None:
            reference = str(credential_ref or "").strip()
            if len(reference) > 160:
                raise errors.ValidationError("credential reference is outside the allowed bound")
            if reference and reference != str(current.get("credential_ref") or ""):
                candidate = dict(current)
                candidate["credential_ref"] = reference
                if not self.connections._credential_ok(candidate):
                    raise errors.ValidationError("new credential reference is not active")
        return self.connections.update(
            org_id,
            integration_id,
            endpoint_url=endpoint_url,
            name=name,
            provider=provider,
            auth_mode=auth_mode,
            credential_ref=credential_ref,
            config=dict(config) if config is not None else None,
            actor=actor,
        )

    def rotate_credential_reference(
        self,
        org_id: str,
        integration_id: str,
        new_credential_ref: str,
        *,
        actor: str = "api",
    ) -> dict[str, Any]:
        """Rotate by reference to an already-active governed credential.

        Raw credential material is intentionally not accepted. The existing
        secret governance registry verifies the reference before it is stored.
        """
        row = self._connection(org_id, integration_id)
        reference = str(new_credential_ref or "").strip()
        if not reference or len(reference) > 160:
            raise errors.ValidationError("active credential reference is required")
        if reference == str(row.get("credential_ref") or ""):
            raise errors.ValidationError("new credential reference must differ from the current reference")
        candidate = dict(row)
        candidate["credential_ref"] = reference
        if not self.connections._credential_ok(candidate):
            raise errors.ValidationError("new credential reference is not active")
        return self.connections.update(
            org_id, integration_id, credential_ref=reference, actor=actor
        )

    def enable(
        self,
        org_id: str,
        integration_id: str,
        *,
        approved_by: str,
        actor: str = "api",
    ) -> dict[str, Any]:
        self._connection(org_id, integration_id)
        if not approved_by:
            raise errors.ValidationError("integration approver identity is required")
        validation = self.connections.validate(org_id, integration_id)
        if validation.get("configuration_status") != "valid":
            raise errors.ValidationError("integration configuration must be valid before activation")
        return self.connections.enable(
            org_id, integration_id, approved_by=approved_by, actor=actor
        )

    def disable(self, org_id: str, integration_id: str, *, actor: str = "api") -> dict[str, Any]:
        self._connection(org_id, integration_id)
        return self.connections.disable(org_id, integration_id, actor=actor)

    def test_connection(self, org_id: str, integration_id: str, *, actor: str = "api") -> dict[str, Any]:
        """Run the canonical bounded provider test after tenant validation."""
        self._connection(org_id, integration_id)
        return self.connections.test(org_id, integration_id, actor=actor)

    def health(
        self,
        org_id: str,
        *,
        integration_id: str = "",
        limit: int = 100,
        actor: str = "api",
    ) -> dict[str, Any]:
        self._org(org_id)
        if integration_id:
            self._connection(org_id, integration_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("integration health limit is outside the allowed range")
        return self.connections.health(
            org_id, integration_id=integration_id, limit=limit, actor=actor
        )

    def delivery_state(
        self,
        org_id: str,
        *,
        integration_id: str = "",
        status: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._org(org_id)
        if integration_id:
            self._connection(org_id, integration_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise errors.ValidationError("integration delivery limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset <= 100_000:
            raise errors.ValidationError("integration delivery offset is outside the allowed range")
        return self.connections.deliveries_list(
            org_id,
            integration_id=integration_id,
            status=status,
            limit=limit,
            offset=offset,
        )

    def send_event(
        self,
        org_id: str,
        integration_id: str,
        *,
        event_type: str,
        payload: Mapping[str, Any],
        idempotency_key: str = "",
        actor: str = "api",
    ) -> dict[str, Any]:
        self._connection(org_id, integration_id)
        if not isinstance(payload, Mapping):
            raise errors.ValidationError("integration event payload must be an object")
        return self.outbound.send(
            org_id,
            integration_id,
            event_type=event_type,
            payload=dict(payload),
            external_event_id=idempotency_key,
            actor=actor,
        )

    def process_due(self, org_id: str, *, limit: int = 50) -> dict[str, Any]:
        self._org(org_id)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise errors.ValidationError("integration delivery batch limit is outside the allowed range")
        return self.delivery_runner.process_due(org_id, limit=limit)


__all__ = ["IntegrationService"]
