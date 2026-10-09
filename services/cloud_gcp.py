"""GCP project inventory adapter backed by Cloud Asset Inventory SDK.

The adapter performs project-scoped resource and IAM-policy queries with
bounded pagination and request timeouts. It never scans an organization or
returns fabricated inventory. Install the optional ``cloud-gcp`` extra and
provide encrypted service-account credentials or an explicit workload/default
identity reference to enable live queries.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from services.cloud_common import (
    CloudAdapterError,
    mapping_value,
    require_time,
    translate_provider_error,
)

_PROJECT_RE = re.compile(r"^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$")
_SECRET_KEYS = frozenset({
    "type", "project_id", "private_key_id", "private_key", "client_email",
    "client_id", "auth_uri", "token_uri", "auth_provider_x509_cert_url",
    "client_x509_cert_url", "universe_domain",
})
_MAX_RESOURCES = 50_000
_MAX_SECONDS = 120
_MAX_PAGES = 500
_PAGE_SIZE = 500
_READ_MASK = "name,asset_type,project,location,display_name,description,labels,additional_attributes"
_READ_ONLY_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"


def _project_reference(context: Mapping[str, Any]) -> str:
    reference = str(context.get("ref", "") or "")
    if context.get("credential_secret"):
        return "encrypted_secret"
    if reference in {"workload_identity", "default"}:
        return reference
    if reference.startswith("env:"):
        return reference
    raise CloudAdapterError("not_configured")


def _credentials(context: Mapping[str, Any]) -> Any:
    secret = context.get("credential_secret")
    try:
        import google.auth
        from google.oauth2 import credentials as user_credentials
        from google.oauth2 import service_account
    except ImportError:
        raise CloudAdapterError("not_configured") from None
    if secret:
        if not isinstance(secret, str) or len(secret.encode("utf-8")) > 16_384:
            raise CloudAdapterError("invalid_credentials")
        try:
            material = json.loads(secret)
        except (TypeError, ValueError):
            raise CloudAdapterError("invalid_credentials") from None
        if (
            not isinstance(material, dict)
            or set(material) - _SECRET_KEYS
            or material.get("type") != "service_account"
            or not isinstance(material.get("private_key"), str)
            or not material.get("private_key")
            or not isinstance(material.get("client_email"), str)
            or not material.get("client_email")
            or not isinstance(material.get("project_id"), str)
            or not material.get("project_id")
        ):
            raise CloudAdapterError("invalid_credentials")
        try:
            return service_account.Credentials.from_service_account_info(
                material,
                scopes=[_READ_ONLY_SCOPE],
            )
        except Exception as exc:
            raise translate_provider_error(exc) from None

    reference = _project_reference(context)
    if reference.startswith("env:"):
        variable = reference[4:]
        if variable == "GOOGLE_OAUTH_ACCESS_TOKEN":
            token = str(os.environ.get(variable, "") or "")
            if not token:
                raise CloudAdapterError("invalid_credentials")
            try:
                return user_credentials.Credentials(token=token)
            except Exception as exc:
                raise translate_provider_error(exc) from None
        if variable != "GOOGLE_APPLICATION_CREDENTIALS":
            raise CloudAdapterError("not_configured")
        if not os.environ.get(variable):
            raise CloudAdapterError("invalid_credentials")
    try:
        result = google.auth.default(scopes=[_READ_ONLY_SCOPE])
        return result[0]
    except Exception as exc:
        raise translate_provider_error(exc) from None


def _plain_attributes(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    try:
        from google.protobuf.json_format import MessageToDict
        converted = MessageToDict(value, preserving_proto_field_name=True)
    except ImportError:
        converted = mapping_value(value)
    except Exception:
        raise CloudAdapterError("inventory_failed") from None
    if isinstance(converted, dict):
        return converted
    if isinstance(converted, Mapping):
        return dict(converted)
    raise CloudAdapterError("inventory_failed")


def _read(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _project_in_scope(item: Any, project_id: str) -> bool:
    project = str(_read(item, "project", "") or "")
    if not project:
        return True
    normalized = project.split("/")[-1]
    if normalized == project_id:
        return True
    if project_id.isdigit():
        return False
    # Asset Inventory commonly reports the canonical numeric project number
    # even when the request used the project ID. The request itself is scoped
    # to exactly projects/{project_id}, so a numeric alias is valid here.
    return normalized.isdigit()


def _asset_type(raw_type: str) -> str:
    normalized = raw_type.lower()
    if normalized in {"storage.googleapis.com/bucket", "storage.googleapis.com/bucketaccesscontrol"}:
        return "storage_bucket"
    if normalized in {"compute.googleapis.com/instance", "compute.googleapis.com/instancegroup"}:
        return "compute_instance"
    if normalized in {"compute.googleapis.com/firewall", "compute.googleapis.com/networkfirewallpolicy"}:
        return "security_group"
    if normalized in {"sqladmin.googleapis.com/instance"}:
        return "database"
    return "gcp_resource"


def _normalize_resource(item: Any, project_id: str) -> dict[str, Any]:
    if not _project_in_scope(item, project_id):
        raise CloudAdapterError("scope_mismatch")
    resource_id = str(_read(item, "name", "") or "")
    asset_type = str(_read(item, "asset_type", "") or "")
    if not resource_id or not asset_type:
        raise CloudAdapterError("inventory_failed")
    raw_attributes = _plain_attributes(_read(item, "additional_attributes", {}))
    attrs: dict[str, Any] = {"asset_type": asset_type}
    if isinstance(raw_attributes, dict):
        for key in ("public_access_prevention", "uniform_bucket_level_access", "encryption", "network_interfaces", "ip_addresses", "allowed", "source_ranges", "ports", "firewall_rules"):
            if key in raw_attributes:
                value = raw_attributes[key]
                if isinstance(value, (str, int, float, bool, list, dict)):
                    attrs[key] = value
    name = str(_read(item, "display_name", "") or resource_id.rsplit("/", 1)[-1])
    region = str(_read(item, "location", "") or "global")
    return {
        "provider": "gcp",
        "account": project_id,
        "region": region[:64],
        "resource_type": _asset_type(asset_type),
        "resource_id": resource_id[:512],
        "name": name[:256],
        "attributes": attrs,
    }


def _normalize_policy(item: Any, project_id: str) -> dict[str, Any] | None:
    if not _project_in_scope(item, project_id):
        raise CloudAdapterError("scope_mismatch")
    resource_id = str(_read(item, "resource", "") or "")
    policy = _read(item, "policy", {})
    if not resource_id:
        return None
    bindings = _read(policy, "bindings", []) or []
    statements: list[dict[str, Any]] = []
    public_read = False
    public_write = False
    for binding in bindings:
        role = str(_read(binding, "role", "") or "")
        members = _read(binding, "members", []) or []
        if isinstance(members, str):
            members = [members]
        if not isinstance(members, (list, tuple)):
            continue
        principals = [str(member)[:256] for member in members[:512]]
        statements.append({
            "effect": "Allow",
            "action": [role[:256]] if role else [],
            "resource": [resource_id[:512]],
            "principal": principals,
        })
        if "allUsers" in principals or "allAuthenticatedUsers" in principals:
            if "objectViewer" in role or "viewer" in role.lower():
                public_read = True
            if any(token in role.lower() for token in ("admin", "creator", "writer")):
                public_write = True
    return {
        "provider": "gcp",
        "account": project_id,
        "region": "global",
        "resource_type": "iam_policy",
        "resource_id": f"{resource_id}:iam-policy"[:512],
        "name": resource_id.rsplit("/", 1)[-1][:256],
        "attributes": {
            "statements": statements[:2048],
            "public_read": public_read,
            "public_write": public_write,
            "public_acl": public_read or public_write,
        },
    }


class GcpInventoryAdapter:
    """Bounded Cloud Asset Inventory resource and IAM policy reader."""

    def __init__(
        self,
        *,
        asset_client_factory: Callable[[Mapping[str, Any]], Any] | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_seconds: int = _MAX_SECONDS,
        max_resources: int = _MAX_RESOURCES,
    ) -> None:
        self._asset_client_factory = asset_client_factory
        self._clock = clock
        self._max_seconds = max(1, min(int(max_seconds), _MAX_SECONDS))
        self._max_resources = max(1, min(int(max_resources), _MAX_RESOURCES))

    def _client(self, context: Mapping[str, Any]) -> Any:
        _project_reference(context)
        if self._asset_client_factory is not None:
            try:
                return self._asset_client_factory(context)
            except Exception as exc:
                raise translate_provider_error(exc) from None
        try:
            from google.cloud import asset_v1
            from google.api_core.client_options import ClientOptions
        except ImportError:
            raise CloudAdapterError("not_configured") from None
        credential = _credentials(context)
        try:
            return asset_v1.AssetServiceClient(
                credentials=credential,
                client_options=ClientOptions(api_endpoint="cloudasset.googleapis.com"),
            )
        except Exception as exc:
            raise translate_provider_error(exc) from None

    def _request(self, client: Any, method_name: str, request: dict[str, Any], deadline: float) -> Any:
        require_time(deadline)
        method = getattr(client, method_name, None)
        if not callable(method):
            raise CloudAdapterError("not_configured")
        kwargs: dict[str, Any] = {"request": request, "timeout": 15}
        try:
            from google.api_core.retry import Retry
            kwargs["retry"] = Retry(
                initial=1.0,
                maximum=5.0,
                multiplier=2.0,
                deadline=30.0,
            )
        except ImportError:
            retry_policy = None
        else:
            retry_policy = kwargs["retry"]
        if retry_policy is None:
            kwargs.pop("retry", None)
        try:
            return method(**kwargs)
        except Exception as exc:
            raise translate_provider_error(exc) from None

    def inventory(self, account: Any, credentials: Mapping[str, Any]) -> list[dict[str, Any]]:
        project_id = str(getattr(account, "account_identifier", "") or "")
        if not _PROJECT_RE.fullmatch(project_id):
            raise CloudAdapterError("scope_mismatch")
        if not isinstance(credentials, Mapping):
            raise CloudAdapterError("invalid_credentials")
        client = self._client(credentials)
        deadline = self._clock() + self._max_seconds
        scope = f"projects/{project_id}"
        request = {
            "scope": scope,
            "read_mask": _READ_MASK,
            "page_size": _PAGE_SIZE,
        }
        resources: list[dict[str, Any]] = []
        try:
            iterator = self._request(client, "search_all_resources", request, deadline)
            for count, item in enumerate(iterator, start=1):
                require_time(deadline)
                if count > _MAX_PAGES * _PAGE_SIZE or len(resources) >= self._max_resources:
                    raise CloudAdapterError("resource_limit_exceeded")
                resources.append(_normalize_resource(item, project_id))

            policy_request = {"scope": scope, "page_size": _PAGE_SIZE}
            policies = self._request(client, "search_all_iam_policies", policy_request, deadline)
            for count, item in enumerate(policies, start=1):
                require_time(deadline)
                if count > _MAX_PAGES * _PAGE_SIZE or len(resources) >= self._max_resources:
                    raise CloudAdapterError("resource_limit_exceeded")
                normalized = _normalize_policy(item, project_id)
                if normalized is not None:
                    resources.append(normalized)
        except CloudAdapterError:
            raise
        except Exception as exc:
            raise translate_provider_error(exc) from None
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    raise translate_provider_error(exc) from None
        return resources


__all__ = ["GcpInventoryAdapter"]
