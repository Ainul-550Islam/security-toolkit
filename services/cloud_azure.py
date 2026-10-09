"""Azure subscription inventory adapter backed by Azure SDK clients.

The adapter uses Resource Manager's subscription-scoped resource listing,
checks every returned resource ID against that subscription, and exposes only
bounded security-relevant metadata present in provider responses. The Azure SDK
is optional; unavailable SDKs and provider failures are returned as explicit
safe codes, never as empty inventories.
"""

from __future__ import annotations

import json
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

_SUBSCRIPTION_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_REGION_RE = re.compile(r"^[a-z0-9-]{2,64}$")
_SECRET_KEYS = frozenset({"tenant_id", "client_id", "client_secret"})
_MAX_RESOURCES = 50_000
_MAX_SECONDS = 120
_MAX_PAGES = 500
_MGMT_PORTS = (22, 3389, 23, 5900)


def _get(obj: Any, *keys: str, default: Any = None) -> Any:
    mapping = mapping_value(obj)
    for key in keys:
        if key in mapping:
            return mapping[key]
        camel = key.split("_")
        pascal = "".join(part[:1].upper() + part[1:] for part in camel)
        if pascal in mapping:
            return mapping[pascal]
        if hasattr(obj, key):
            return getattr(obj, key)
    return default


def _credential_material(context: Mapping[str, Any]) -> dict[str, str]:
    secret = context.get("credential_secret")
    if secret:
        if not isinstance(secret, str) or len(secret.encode("utf-8")) > 16_384:
            raise CloudAdapterError("invalid_credentials")
        try:
            values = json.loads(secret)
        except (TypeError, ValueError):
            raise CloudAdapterError("invalid_credentials") from None
        if not isinstance(values, dict) or set(values) != _SECRET_KEYS:
            raise CloudAdapterError("invalid_credentials")
        if any(not isinstance(values[key], str) or not values[key] for key in _SECRET_KEYS):
            raise CloudAdapterError("invalid_credentials")
        return dict(values)
    reference = str(context.get("ref", "") or "")
    if reference in {"workload_identity", "default"} or reference.startswith("env:"):
        return {}
    raise CloudAdapterError("not_configured")


def _public_address(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text in {"*", "internet", "0.0.0.0/0", "::/0", "any"}


def _mapped_resource(resource: Any, subscription_id: str, selected_regions: set[str]) -> dict[str, Any]:
    model = mapping_value(resource)
    resource_id = str(model.get("id", _get(resource, "id", default="")) or "")
    prefix = f"/subscriptions/{subscription_id}/"
    if not resource_id.lower().startswith(prefix.lower()):
        raise CloudAdapterError("scope_mismatch")
    name = str(model.get("name", _get(resource, "name", default="")) or "")
    kind = str(model.get("type", _get(resource, "type", default="")) or "").lower()
    region = str(model.get("location", _get(resource, "location", default="")) or "global").lower()
    if selected_regions and region not in selected_regions and region != "global":
        return {}
    properties = mapping_value(model.get("properties", _get(resource, "properties", default={})))
    attrs: dict[str, Any] = {"resource_type": kind, "resource_id": resource_id}
    normalized_type = "azure_resource"

    if kind == "microsoft.compute/virtualmachines":
        normalized_type = "compute_instance"
        power_state = str(properties.get("provisioningState", ""))
        if power_state:
            attrs["state"] = power_state[:64]
        os_profile = mapping_value(properties.get("osProfile", {}))
        if os_profile.get("computerName"):
            attrs["hostname"] = str(os_profile["computerName"])[:256]
    elif kind == "microsoft.network/networksecuritygroups":
        normalized_type = "security_group"
        cidrs: list[str] = []
        open_ports: list[dict[str, Any]] = []
        allow_all_ingress = False
        rules = properties.get("securityRules", [])
        if isinstance(rules, list):
            for rule in rules[:2048]:
                data = mapping_value(rule)
                if str(data.get("direction", "")).lower() != "inbound":
                    continue
                if str(data.get("access", "")).lower() != "allow":
                    continue
                address_sources = data.get("sourceAddressPrefixes") or [data.get("sourceAddressPrefix", "")]
                port_values = data.get("destinationPortRanges") or [data.get("destinationPortRange", "")]
                sources = [str(item) for item in address_sources if item]
                ports = [str(item) for item in port_values if item]
                for source in sources:
                    if source not in cidrs:
                        cidrs.append(source)
                    if not _public_address(source):
                        continue
                    for port_text in ports:
                        if port_text == "*":
                            allow_all_ingress = True
                            open_ports.extend({"cidr": source, "port": port} for port in _MGMT_PORTS)
                            continue
                        if "-" in port_text:
                            parts = port_text.split("-", 1)
                            try:
                                start, end = int(parts[0]), int(parts[1])
                            except ValueError:
                                continue
                            open_ports.extend({"cidr": source, "port": port} for port in _MGMT_PORTS if start <= port <= end)
                        else:
                            try:
                                port = int(port_text)
                            except ValueError:
                                continue
                            if port in _MGMT_PORTS:
                                open_ports.append({"cidr": source, "port": port})
        attrs["cidrs"] = cidrs[:2048]
        attrs["open_ports"] = open_ports[:4096]
        attrs["allow_all_ingress"] = allow_all_ingress
    elif kind == "microsoft.storage/storageaccounts":
        normalized_type = "storage_bucket"
        allow_public = properties.get("allowBlobPublicAccess")
        public_network = str(properties.get("publicNetworkAccess", "")).lower()
        network_rules = mapping_value(properties.get("networkAcls", {}))
        default_action = str(network_rules.get("defaultAction", "")).lower()
        if isinstance(allow_public, bool):
            attrs["public_access_allowed"] = allow_public
        if public_network:
            attrs["public_network_access"] = public_network
        if allow_public is True and public_network != "disabled" and default_action != "deny":
            attrs["public_endpoint"] = True
        encryption = mapping_value(properties.get("encryption", {}))
        services = mapping_value(encryption.get("services", {}))
        blob_encryption = mapping_value(services.get("blob", {}))
        if isinstance(blob_encryption.get("enabled"), bool):
            attrs["encryption_enabled"] = blob_encryption["enabled"]
        https_only = properties.get("supportsHttpsTrafficOnly")
        if isinstance(https_only, bool):
            attrs["https_only"] = https_only
    elif kind in {"microsoft.sql/servers", "microsoft.sql/servers/databases"}:
        normalized_type = "database"
        public_network = str(properties.get("publicNetworkAccess", "")).lower()
        if public_network:
            is_public = public_network == "enabled"
            attrs["publicly_accessible"] = is_public
            attrs["public_endpoint"] = is_public
        minimum_tls = properties.get("minimalTlsVersion")
        if minimum_tls:
            attrs["minimum_tls_version"] = str(minimum_tls)[:64]
        encryption = properties.get("encryptionProtectorAutoRotation", None)
        if isinstance(encryption, bool):
            attrs["encryption_enabled"] = encryption

    return {
        "provider": "azure",
        "account": subscription_id,
        "region": region,
        "resource_type": normalized_type,
        "resource_id": resource_id[:512],
        "name": name[:256],
        "attributes": attrs,
    }


class AzureInventoryAdapter:
    """Read-only subscription inventory with bounded pagination and scope checks."""

    def __init__(
        self,
        *,
        resource_client_factory: Callable[[str, Mapping[str, str]], Any] | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_seconds: int = _MAX_SECONDS,
        max_resources: int = _MAX_RESOURCES,
    ) -> None:
        self._resource_client_factory = resource_client_factory
        self._clock = clock
        self._max_seconds = max(1, min(int(max_seconds), _MAX_SECONDS))
        self._max_resources = max(1, min(int(max_resources), _MAX_RESOURCES))

    def _client(self, subscription_id: str, context: Mapping[str, Any]) -> Any:
        material = _credential_material(context)
        if self._resource_client_factory is not None:
            try:
                return self._resource_client_factory(subscription_id, material)
            except Exception as exc:
                raise translate_provider_error(exc) from None
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient
        except ImportError:
            raise CloudAdapterError("not_configured") from None
        try:
            if material:
                credential = ClientSecretCredential(
                    tenant_id=material["tenant_id"],
                    client_id=material["client_id"],
                    client_secret=material["client_secret"],
                )
            else:
                credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
            client = ResourceManagementClient(
                credential,
                subscription_id,
                retry_total=3,
                retry_backoff_factor=0.5,
                connection_timeout=5,
                read_timeout=10,
                logging_enable=False,
            )
            return client
        except Exception as exc:
            raise translate_provider_error(exc) from None

    def inventory(self, account: Any, credentials: Mapping[str, Any]) -> list[dict[str, Any]]:
        subscription_id = str(getattr(account, "account_identifier", "") or "")
        if not _SUBSCRIPTION_RE.fullmatch(subscription_id):
            raise CloudAdapterError("scope_mismatch")
        if not isinstance(credentials, Mapping):
            raise CloudAdapterError("invalid_credentials")
        client = self._client(subscription_id, credentials)
        regions_raw = getattr(account, "region_scope", None) or []
        if not isinstance(regions_raw, list) or len(regions_raw) > 64:
            raise CloudAdapterError("scope_mismatch")
        selected_regions: set[str] = set()
        for region in regions_raw:
            if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
                raise CloudAdapterError("scope_mismatch")
            selected_regions.add(region.lower())
        deadline = self._clock() + self._max_seconds
        resources: list[dict[str, Any]] = []
        try:
            iterator = client.resources.list()
            for count, resource in enumerate(iterator, start=1):
                require_time(deadline)
                if count > _MAX_PAGES * 1000 or count > self._max_resources:
                    raise CloudAdapterError("resource_limit_exceeded")
                normalized = _mapped_resource(resource, subscription_id, selected_regions)
                if normalized:
                    resources.append(normalized)
                if len(resources) > self._max_resources:
                    raise CloudAdapterError("resource_limit_exceeded")
        except CloudAdapterError:
            raise
        except Exception as exc:
            raise translate_provider_error(exc) from None
        finally:
            close_method = getattr(client, "close", None)
            if callable(close_method):
                try:
                    close_method()
                except Exception as exc:
                    raise translate_provider_error(exc) from None
        return resources


__all__ = ["AzureInventoryAdapter"]
