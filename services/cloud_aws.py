"""AWS inventory adapter backed by the optional, pinned Boto3 SDK.

The adapter is read-only and verifies the live STS identity before collecting
resources. The base application does not install Boto3 or infer cloud access;
install the ``cloud-aws`` extra and supply a tenant-scoped account credential
reference or write-only encrypted credential material to enable this path.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from services.cloud_common import (
    CloudAdapterError,
    require_time,
    translate_provider_error,
)

_AWS_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]+$")
_SECRET_KEYS = frozenset({
    "access_key_id",
    "secret_access_key",
    "session_token",
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
})
_MGMT_PORTS = (22, 3389, 23, 5900)
_MAX_REGIONS = 32
_MAX_PAGES = 100
_MAX_RESOURCES = 50_000
_MAX_SECONDS = 120
_CONNECT_TIMEOUT = 3
_READ_TIMEOUT = 10


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _secret_kwargs(credentials: Mapping[str, Any]) -> dict[str, str]:
    secret = credentials.get("credential_secret")
    if not secret:
        return {}
    if not isinstance(secret, str) or len(secret.encode("utf-8")) > 16_384:
        raise CloudAdapterError("invalid_credentials")
    try:
        parsed = json.loads(secret)
    except (TypeError, ValueError):
        raise CloudAdapterError("invalid_credentials") from None
    if not isinstance(parsed, dict) or set(parsed) - _SECRET_KEYS:
        raise CloudAdapterError("invalid_credentials")
    access_key = parsed.get("aws_access_key_id", parsed.get("access_key_id"))
    secret_key = parsed.get("aws_secret_access_key", parsed.get("secret_access_key"))
    session_token = parsed.get("aws_session_token", parsed.get("session_token"))
    if not isinstance(access_key, str) or not access_key.strip():
        raise CloudAdapterError("invalid_credentials")
    if not isinstance(secret_key, str) or not secret_key.strip():
        raise CloudAdapterError("invalid_credentials")
    result = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
    }
    if session_token:
        if not isinstance(session_token, str):
            raise CloudAdapterError("invalid_credentials")
        result["aws_session_token"] = session_token
    return result


def _credential_reference(credentials: Mapping[str, Any]) -> str:
    ref = str(credentials.get("ref", "") or "")
    if credentials.get("credential_secret"):
        return "encrypted_secret"
    if ref in {"workload_identity", "default"}:
        return ref
    if ref.startswith("env:"):
        return ref
    raise CloudAdapterError("not_configured")


def _aws_error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return ""
    error = response.get("Error")
    if not isinstance(error, Mapping):
        return ""
    return str(error.get("Code", ""))


def _page_iterator(
    call: Callable[..., Mapping[str, Any]],
    *,
    items_key: str,
    token_name: str,
    params: dict[str, Any],
    deadline: float,
    page_size_name: str,
    page_size: int,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = ""
    for page_number in range(_MAX_PAGES):
        require_time(deadline)
        request = dict(params)
        request[page_size_name] = page_size
        if token:
            request[token_name] = token
        try:
            response = call(**request)
        except Exception as exc:
            raise translate_provider_error(exc) from None
        if not isinstance(response, Mapping):
            raise CloudAdapterError("inventory_failed")
        raw_items = response.get(items_key, [])
        if not isinstance(raw_items, list):
            raise CloudAdapterError("inventory_failed")
        for item in raw_items:
            items.append(dict(item) if isinstance(item, Mapping) else {})
            if len(items) > _MAX_RESOURCES:
                raise CloudAdapterError("resource_limit_exceeded")
        next_token = response.get("NextToken", "")
        if not next_token:
            return items
        if not isinstance(next_token, str) or next_token == token:
            raise CloudAdapterError("inventory_failed")
        token = next_token
    raise CloudAdapterError("resource_limit_exceeded")


def _regions(client: Any, requested: list[str], deadline: float) -> list[str]:
    if requested:
        regions = list(requested)
    else:
        require_time(deadline)
        try:
            response = client.describe_regions(AllRegions=False)
        except Exception as exc:
            raise translate_provider_error(exc) from None
        records = response.get("Regions", []) if isinstance(response, Mapping) else []
        regions = [str(item.get("RegionName", "")) for item in records if isinstance(item, Mapping)]
    unique: list[str] = []
    for region in regions:
        if not isinstance(region, str) or not _AWS_REGION_RE.fullmatch(region):
            raise CloudAdapterError("scope_mismatch")
        if region not in unique:
            unique.append(region)
    if not unique or len(unique) > _MAX_REGIONS:
        raise CloudAdapterError("resource_limit_exceeded")
    return unique


def _resource(
    *,
    resource_type: str,
    resource_id: str,
    name: str,
    region: str,
    account_id: str,
    attributes: dict[str, Any],
) -> dict[str, Any]:
    return {
        "provider": "aws",
        "account": account_id,
        "region": region,
        "resource_type": resource_type,
        "resource_id": resource_id[:512],
        "name": name[:256],
        "attributes": attributes,
    }


class AwsInventoryAdapter:
    """Bounded, read-only AWS inventory via STS, EC2, RDS, and S3."""

    def __init__(
        self,
        *,
        session_factory: Callable[..., Any] | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_seconds: int = _MAX_SECONDS,
        max_resources: int = _MAX_RESOURCES,
    ) -> None:
        self._session_factory = session_factory
        self._clock = clock
        self._max_seconds = max(1, min(int(max_seconds), _MAX_SECONDS))
        self._max_resources = max(1, min(int(max_resources), _MAX_RESOURCES))

    def _new_session(self, credential_context: Mapping[str, Any]) -> tuple[Any, Any]:
        _credential_reference(credential_context)
        kwargs = _secret_kwargs(credential_context)
        if self._session_factory is not None:
            try:
                return self._session_factory(**kwargs), None
            except Exception as exc:
                raise translate_provider_error(exc) from None
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise CloudAdapterError("not_configured") from None
        config = Config(
            connect_timeout=_CONNECT_TIMEOUT,
            read_timeout=_READ_TIMEOUT,
            retries={"max_attempts": 3, "mode": "standard"},
            user_agent_extra="security-toolkit-cloud-inventory/1",
        )
        try:
            session = boto3.Session(**kwargs)
        except Exception as exc:
            raise translate_provider_error(exc) from None
        return session, config

    def _client(self, session: Any, service: str, region: str, config: Any) -> Any:
        try:
            kwargs: dict[str, Any] = {"region_name": region}
            if config is not None:
                kwargs["config"] = config
            return session.client(service, **kwargs)
        except Exception as exc:
            raise translate_provider_error(exc) from None

    def _collect_instances(
        self,
        ec2: Any,
        *,
        region: str,
        account_id: str,
        deadline: float,
        result: list[dict[str, Any]],
    ) -> None:
        rows = _page_iterator(
            ec2.describe_instances,
            items_key="Reservations",
            token_name="NextToken",
            params={},
            deadline=deadline,
            page_size_name="MaxResults",
            page_size=1000,
        )
        for reservation in rows:
            instances = reservation.get("Instances", [])
            if not isinstance(instances, list):
                raise CloudAdapterError("inventory_failed")
            for instance in instances:
                if not isinstance(instance, Mapping):
                    continue
                instance_id = str(instance.get("InstanceId", ""))
                if not instance_id:
                    raise CloudAdapterError("inventory_failed")
                public_v4 = False
                public_v6 = False
                for interface in instance.get("NetworkInterfaces", []) or []:
                    if not isinstance(interface, Mapping):
                        continue
                    for address in interface.get("PrivateIpAddresses", []) or []:
                        if isinstance(address, Mapping) and address.get("Association", {}).get("PublicIp"):
                            public_v4 = True
                    if interface.get("Association", {}).get("PublicIp"):
                        public_v4 = True
                    if interface.get("Ipv6Addresses"):
                        public_v6 = True
                if instance.get("PublicIpAddress"):
                    public_v4 = True
                if instance.get("PublicIpv6Address"):
                    public_v6 = True
                tags = {
                    str(tag.get("Key", "")): str(tag.get("Value", ""))
                    for tag in instance.get("Tags", []) or []
                    if isinstance(tag, Mapping) and tag.get("Key")
                }
                state = instance.get("State", {})
                attributes = {
                    "state": str(state.get("Name", "")) if isinstance(state, Mapping) else "",
                    "instance_type": str(instance.get("InstanceType", "")),
                    "public_ip": public_v4,
                    "public_ipv6": public_v6,
                    "internal_only": not (public_v4 or public_v6),
                    "subnet_id": str(instance.get("SubnetId", "")),
                    "vpc_id": str(instance.get("VpcId", "")),
                    "tags": tags,
                }
                result.append(_resource(
                    resource_type="compute_instance",
                    resource_id=instance_id,
                    name=tags.get("Name", instance_id),
                    region=region,
                    account_id=account_id,
                    attributes=attributes,
                ))
                if len(result) > self._max_resources:
                    raise CloudAdapterError("resource_limit_exceeded")

    def _collect_security_groups(
        self,
        ec2: Any,
        *,
        region: str,
        account_id: str,
        deadline: float,
        result: list[dict[str, Any]],
    ) -> None:
        groups = _page_iterator(
            ec2.describe_security_groups,
            items_key="SecurityGroups",
            token_name="NextToken",
            params={},
            deadline=deadline,
            page_size_name="MaxResults",
            page_size=1000,
        )
        for group in groups:
            group_id = str(group.get("GroupId", ""))
            if not group_id:
                raise CloudAdapterError("inventory_failed")
            cidrs: list[str] = []
            open_ports: list[dict[str, Any]] = []
            allow_all = False
            permissions = group.get("IpPermissions", [])
            if not isinstance(permissions, list):
                raise CloudAdapterError("inventory_failed")
            for permission in permissions:
                if not isinstance(permission, Mapping):
                    continue
                protocol = str(permission.get("IpProtocol", ""))
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                if protocol == "-1":
                    from_port, to_port = 0, 65535
                sources: list[str] = []
                for key in ("IpRanges", "Ipv6Ranges"):
                    for entry in permission.get(key, []) or []:
                        if isinstance(entry, Mapping):
                            cidr = str(entry.get("CidrIp", entry.get("CidrIpv6", "")))
                            if cidr:
                                sources.append(cidr)
                for cidr in sources:
                    if cidr not in cidrs:
                        cidrs.append(cidr)
                    if cidr in {"0.0.0.0/0", "::/0"}:
                        allow_all = allow_all or protocol == "-1"
                    for port in _MGMT_PORTS:
                        if isinstance(from_port, int) and isinstance(to_port, int) and from_port <= port <= to_port:
                            open_ports.append({"cidr": cidr, "port": port})
            attributes = {
                "cidrs": cidrs[:2048],
                "open_ports": open_ports[:4096],
                "allow_all_ingress": allow_all,
                "vpc_id": str(group.get("VpcId", "")),
            }
            result.append(_resource(
                resource_type="security_group",
                resource_id=group_id,
                name=str(group.get("GroupName", group_id)),
                region=region,
                account_id=account_id,
                attributes=attributes,
            ))
            if len(result) > self._max_resources:
                raise CloudAdapterError("resource_limit_exceeded")

    def _collect_databases(
        self,
        rds: Any,
        *,
        region: str,
        account_id: str,
        deadline: float,
        result: list[dict[str, Any]],
    ) -> None:
        rows = _page_iterator(
            rds.describe_db_instances,
            items_key="DBInstances",
            token_name="Marker",
            params={},
            deadline=deadline,
            page_size_name="MaxRecords",
            page_size=100,
        )
        for database in rows:
            db_id = str(database.get("DBInstanceIdentifier", ""))
            if not db_id:
                raise CloudAdapterError("inventory_failed")
            public = database.get("PubliclyAccessible") is True
            endpoint = database.get("Endpoint", {})
            attributes = {
                "publicly_accessible": public,
                "public_endpoint": bool(public and isinstance(endpoint, Mapping) and endpoint.get("Address")),
                "internal_only": not public,
                "encryption_enabled": database.get("StorageEncrypted") is True,
                "engine": str(database.get("Engine", "")),
                "status": str(database.get("DBInstanceStatus", "")),
                "multi_az": database.get("MultiAZ") is True,
            }
            result.append(_resource(
                resource_type="database",
                resource_id=db_id,
                name=db_id,
                region=region,
                account_id=account_id,
                attributes=attributes,
            ))
            if len(result) > self._max_resources:
                raise CloudAdapterError("resource_limit_exceeded")

    def _collect_buckets(
        self,
        session: Any,
        *,
        account_id: str,
        config: Any,
        deadline: float,
        result: list[dict[str, Any]],
    ) -> None:
        s3 = self._client(session, "s3", "us-east-1", config)
        require_time(deadline)
        try:
            paginator = s3.get_paginator("list_buckets")
            pages = paginator.paginate(PaginationConfig={"PageSize": 1000})
            for page_number, page in enumerate(pages):
                require_time(deadline)
                if page_number >= _MAX_PAGES:
                    raise CloudAdapterError("resource_limit_exceeded")
                buckets = page.get("Buckets", []) if isinstance(page, Mapping) else []
                for bucket in buckets:
                    require_time(deadline)
                    if not isinstance(bucket, Mapping):
                        continue
                    name = str(bucket.get("Name", ""))
                    if not name:
                        raise CloudAdapterError("inventory_failed")
                    public_acl = False
                    public_policy = False
                    encryption = False
                    try:
                        require_time(deadline)
                        acl = s3.get_bucket_acl(Bucket=name)
                        for grant in acl.get("Grants", []) if isinstance(acl, Mapping) else []:
                            grantee = grant.get("Grantee", {}) if isinstance(grant, Mapping) else {}
                            uri = str(grantee.get("URI", "")) if isinstance(grantee, Mapping) else ""
                            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                                permission = str(grant.get("Permission", ""))
                                if permission in {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}:
                                    public_acl = True
                        require_time(deadline)
                        policy_status = s3.get_bucket_policy_status(Bucket=name)
                        status = policy_status.get("PolicyStatus", {}) if isinstance(policy_status, Mapping) else {}
                        public_policy = bool(isinstance(status, Mapping) and status.get("IsPublic") is True)
                    except Exception as exc:
                        if _aws_error_code(exc) == "NoSuchBucketPolicy":
                            public_policy = False
                        else:
                            raise translate_provider_error(exc) from None
                    block_acl = False
                    block_policy = False
                    try:
                        require_time(deadline)
                        block = s3.get_public_access_block(Bucket=name)
                        config_block = block.get("PublicAccessBlockConfiguration", {}) if isinstance(block, Mapping) else {}
                        if isinstance(config_block, Mapping):
                            block_acl = bool(
                                config_block.get("BlockPublicAcls") is True
                                or config_block.get("IgnorePublicAcls") is True
                            )
                            block_policy = bool(
                                config_block.get("BlockPublicPolicy") is True
                                or config_block.get("RestrictPublicBuckets") is True
                            )
                    except Exception as exc:
                        if _aws_error_code(exc) not in {
                            "NoSuchPublicAccessBlockConfiguration",
                            "NoSuchPublicAccessBlock",
                        }:
                            raise translate_provider_error(exc) from None
                    try:
                        require_time(deadline)
                        encryption_response = s3.get_bucket_encryption(Bucket=name)
                        rule = encryption_response.get("ServerSideEncryptionConfiguration", {}) if isinstance(encryption_response, Mapping) else {}
                        encryption = bool(isinstance(rule, Mapping) and rule.get("Rules"))
                    except Exception as exc:
                        if _aws_error_code(exc) not in {
                            "ServerSideEncryptionConfigurationNotFoundError",
                            "NoSuchBucketEncryption",
                        }:
                            raise translate_provider_error(exc) from None
                    is_public_acl = public_acl and not block_acl
                    is_public_policy = public_policy and not block_policy
                    is_public = is_public_acl or is_public_policy
                    region = "us-east-1"
                    try:
                        require_time(deadline)
                        location = s3.get_bucket_location(Bucket=name)
                        constraint = location.get("LocationConstraint") if isinstance(location, Mapping) else None
                        if constraint:
                            region = "eu-west-1" if constraint == "EU" else str(constraint)
                    except Exception as exc:
                        raise translate_provider_error(exc) from None
                    attributes = {
                        "public_acl": is_public_acl,
                        "public_read": is_public_policy,
                        "public_endpoint": is_public,
                        "internal_only": not is_public,
                        "encryption_enabled": encryption,
                        "created_at": str(bucket.get("CreationDate", ""))[:64],
                    }
                    result.append(_resource(
                        resource_type="storage_bucket",
                        resource_id=name,
                        name=name,
                        region=region,
                        account_id=account_id,
                        attributes=attributes,
                    ))
                    if len(result) > self._max_resources:
                        raise CloudAdapterError("resource_limit_exceeded")
        except CloudAdapterError:
            raise
        except Exception as exc:
            raise translate_provider_error(exc) from None

    def inventory(self, account: Any, credentials: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Collect only resources confirmed by AWS APIs for the requested account."""
        account_id = str(getattr(account, "account_identifier", "") or "")
        if not _AWS_ACCOUNT_ID_RE.fullmatch(account_id):
            raise CloudAdapterError("scope_mismatch")
        if not isinstance(credentials, Mapping):
            raise CloudAdapterError("invalid_credentials")
        reference = _credential_reference(credentials)
        session, config = self._new_session(credentials)
        deadline = self._clock() + self._max_seconds
        sts = self._client(session, "sts", "us-east-1", config)
        require_time(deadline)
        try:
            identity = sts.get_caller_identity()
        except Exception as exc:
            raise translate_provider_error(exc) from None
        live_account = str(identity.get("Account", "")) if isinstance(identity, Mapping) else ""
        if live_account != account_id:
            raise CloudAdapterError("scope_mismatch")

        regions_requested = getattr(account, "region_scope", None) or []
        if not isinstance(regions_requested, list):
            raise CloudAdapterError("scope_mismatch")
        ec2_global = self._client(session, "ec2", "us-east-1", config)
        regions = _regions(ec2_global, regions_requested, deadline)
        result: list[dict[str, Any]] = []
        for region in regions:
            require_time(deadline)
            ec2 = self._client(session, "ec2", region, config)
            self._collect_instances(
                ec2, region=region, account_id=account_id,
                deadline=deadline, result=result,
            )
            self._collect_security_groups(
                ec2, region=region, account_id=account_id,
                deadline=deadline, result=result,
            )
            rds = self._client(session, "rds", region, config)
            self._collect_databases(
                rds, region=region, account_id=account_id,
                deadline=deadline, result=result,
            )
        self._collect_buckets(
            session, account_id=account_id, config=config,
            deadline=deadline, result=result,
        )
        if len(result) > self._max_resources:
            raise CloudAdapterError("resource_limit_exceeded")
        if reference not in {"workload_identity", "default", "encrypted_secret"} and not reference.startswith("env:"):
            raise CloudAdapterError("not_configured")
        return result


__all__ = ["AwsInventoryAdapter"]
