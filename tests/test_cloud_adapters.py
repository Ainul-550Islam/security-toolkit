"""Read-only cloud adapter tests use explicit SDK-client doubles only.

The test doubles never leave the process or produce production scan data. They
exercise normalization, pagination, scope checks, bounded failures, and safe
error mapping without requiring provider credentials or network access.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "python"))

from services.cloud_aws import AwsInventoryAdapter
from services.cloud_azure import AzureInventoryAdapter
from services.cloud_common import CloudAdapterError, provider_error_code
from services.cloud_gcp import GcpInventoryAdapter


class _AwsPaginator:
    def paginate(self, **_kwargs):
        return [{"Buckets": [{"Name": "sample-bucket", "CreationDate": "2026-01-01"}]}]


class _AwsClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.instance_calls = 0

    def get_caller_identity(self):
        return {"Account": "123456789012"}

    def describe_regions(self, **_kwargs):
        return {"Regions": [{"RegionName": "us-east-1"}]}

    def describe_instances(self, **kwargs):
        self.instance_calls += 1
        if self.instance_calls == 1:
            return {
                "Reservations": [{"Instances": [{
                    "InstanceId": "i-1",
                    "InstanceType": "t3.small",
                    "State": {"Name": "running"},
                    "PublicIpAddress": "203.0.113.10",
                    "Tags": [{"Key": "Name", "Value": "api"}],
                }]}],
                "NextToken": "page-two",
            }
        self.assert_next_token = kwargs.get("NextToken")
        return {"Reservations": [{"Instances": [{
            "InstanceId": "i-2",
            "InstanceType": "t3.micro",
            "State": {"Name": "stopped"},
            "Tags": [{"Key": "Name", "Value": "worker"}],
        }]}]}

    def describe_security_groups(self, **_kwargs):
        return {"SecurityGroups": [{
            "GroupId": "sg-1",
            "GroupName": "public-ssh",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
        }]}

    def describe_db_instances(self, **_kwargs):
        return {"DBInstances": []}

    def get_paginator(self, _name):
        return _AwsPaginator()

    def get_bucket_acl(self, **_kwargs):
        return {"Grants": [{
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "READ",
        }]}

    def get_bucket_policy_status(self, **_kwargs):
        return {"PolicyStatus": {"IsPublic": False}}

    def get_public_access_block(self, **_kwargs):
        return {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }}

    def get_bucket_encryption(self, **_kwargs):
        return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}

    def get_bucket_location(self, **_kwargs):
        return {"LocationConstraint": "us-east-1"}


class _AwsSession:
    def __init__(self) -> None:
        self.clients: dict[tuple[str, str], _AwsClient] = {}

    def client(self, service: str, region_name: str = "", **_kwargs):
        key = (service, region_name)
        self.clients.setdefault(key, _AwsClient(service))
        return self.clients[key]


class CloudAdapterTests(unittest.TestCase):
    def test_aws_inventory_is_paginated_normalized_and_account_bound(self) -> None:
        session = _AwsSession()
        adapter = AwsInventoryAdapter(session_factory=lambda **_kwargs: session)
        account = SimpleNamespace(
            account_identifier="123456789012",
            region_scope=["us-east-1"],
        )
        resources = adapter.inventory(account, {"ref": "workload_identity"})
        self.assertEqual(len(resources), 4)
        instances = [item for item in resources if item["resource_type"] == "compute_instance"]
        self.assertEqual({item["resource_id"] for item in instances}, {"i-1", "i-2"})
        self.assertTrue(instances[0]["attributes"]["public_ip"] or instances[1]["attributes"]["public_ip"])
        group = next(item for item in resources if item["resource_type"] == "security_group")
        self.assertIn({"cidr": "0.0.0.0/0", "port": 22}, group["attributes"]["open_ports"])
        bucket = next(item for item in resources if item["resource_type"] == "storage_bucket")
        self.assertTrue(bucket["attributes"]["public_acl"])
        self.assertTrue(bucket["attributes"]["encryption_enabled"])
        self.assertEqual(session.clients[("ec2", "us-east-1")].instance_calls, 2)
        self.assertEqual(session.clients[("ec2", "us-east-1")].assert_next_token, "page-two")

    def test_aws_wrong_sts_identity_fails_closed(self) -> None:
        class WrongIdentity(_AwsSession):
            def client(self, service: str, region_name: str = "", **kwargs):
                current = super().client(service, region_name, **kwargs)
                if service == "sts":
                    current.get_caller_identity = lambda: {"Account": "999999999999"}
                return current

        adapter = AwsInventoryAdapter(session_factory=lambda **_kwargs: WrongIdentity())
        with self.assertRaises(CloudAdapterError) as raised:
            adapter.inventory(
                SimpleNamespace(account_identifier="123456789012", region_scope=["us-east-1"]),
                {"ref": "workload_identity"},
            )
        self.assertEqual(raised.exception.code, "scope_mismatch")

    def test_aws_resource_ceiling_is_explicit(self) -> None:
        adapter = AwsInventoryAdapter(
            session_factory=lambda **_kwargs: _AwsSession(),
            max_resources=1,
        )
        with self.assertRaises(CloudAdapterError) as raised:
            adapter.inventory(
                SimpleNamespace(account_identifier="123456789012", region_scope=["us-east-1"]),
                {"ref": "workload_identity"},
            )
        self.assertEqual(raised.exception.code, "resource_limit_exceeded")

    def test_azure_resource_scope_and_metadata_mapping(self) -> None:
        class ResourceOperations:
            def __init__(self, resources):
                self._resources = resources

            def list(self):
                return self._resources

        class ResourceClient:
            closed = False

            def __init__(self, resources):
                self.resources = ResourceOperations(resources)

            def close(self):
                self.closed = True

        subscription = "12345678-1234-1234-1234-123456789abc"
        source = ResourceClient([
            {
                "id": f"/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store1",
                "name": "store1",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "eastus",
                "properties": {
                    "allowBlobPublicAccess": True,
                    "publicNetworkAccess": "Enabled",
                    "networkAcls": {"defaultAction": "Allow"},
                    "encryption": {"services": {"blob": {"enabled": True}}},
                },
            },
        ])
        adapter = AzureInventoryAdapter(resource_client_factory=lambda _sub, _creds: source)
        resources = adapter.inventory(
            SimpleNamespace(account_identifier=subscription, region_scope=["eastus"]),
            {"ref": "workload_identity"},
        )
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["resource_type"], "storage_bucket")
        self.assertTrue(resources[0]["attributes"]["public_access_allowed"])
        self.assertTrue(resources[0]["attributes"]["public_endpoint"])
        self.assertTrue(resources[0]["attributes"]["encryption_enabled"])
        self.assertTrue(source.closed)

    def test_azure_cross_subscription_response_fails_closed(self) -> None:
        subscription = "12345678-1234-1234-1234-123456789abc"
        client = SimpleNamespace(
            resources=SimpleNamespace(list=lambda: [{
                "id": "/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/outside",
                "name": "outside",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "eastus",
                "properties": {},
            }]),
            close=lambda: None,
        )
        adapter = AzureInventoryAdapter(resource_client_factory=lambda _sub, _creds: client)
        with self.assertRaises(CloudAdapterError) as raised:
            adapter.inventory(
                SimpleNamespace(account_identifier=subscription, region_scope=[]),
                {"ref": "workload_identity"},
            )
        self.assertEqual(raised.exception.code, "scope_mismatch")

    def test_gcp_project_assets_and_public_iam_are_normalized(self) -> None:
        class AssetClient:
            closed = False

            def search_all_resources(self, *, request, timeout, **_kwargs):
                self.resource_request = request
                self.timeout = timeout
                return [{
                    "name": "//storage.googleapis.com/projects/my-project/buckets/public-store",
                    "asset_type": "storage.googleapis.com/Bucket",
                    "project": "projects/my-project",
                    "location": "US",
                    "display_name": "public-store",
                    "additional_attributes": {"uniform_bucket_level_access": {"enabled": True}},
                }]

            def search_all_iam_policies(self, *, request, timeout, **_kwargs):
                self.iam_request = request
                return [{
                    "resource": "//storage.googleapis.com/projects/my-project/buckets/public-store",
                    "project": "projects/my-project",
                    "policy": {"bindings": [{
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"],
                    }]},
                }]

            def close(self):
                self.closed = True

        client = AssetClient()
        adapter = GcpInventoryAdapter(asset_client_factory=lambda _context: client)
        resources = adapter.inventory(
            SimpleNamespace(account_identifier="my-project", region_scope=[]),
            {"ref": "workload_identity"},
        )
        self.assertEqual(len(resources), 2)
        self.assertEqual(client.resource_request["scope"], "projects/my-project")
        self.assertEqual(client.iam_request["scope"], "projects/my-project")
        self.assertEqual(resources[0]["resource_type"], "storage_bucket")
        policy = resources[1]
        self.assertEqual(policy["resource_type"], "iam_policy")
        self.assertTrue(policy["attributes"]["public_read"])
        self.assertTrue(client.closed)

    def test_gcp_cross_project_result_is_rejected(self) -> None:
        class AssetClient:
            def search_all_resources(self, **_kwargs):
                return [{
                    "name": "//compute.googleapis.com/projects/other-project/zones/us-central1-a/instances/vm",
                    "asset_type": "compute.googleapis.com/Instance",
                    "project": "projects/other-project",
                }]

            def close(self):
                return None

        adapter = GcpInventoryAdapter(asset_client_factory=lambda _context: AssetClient())
        with self.assertRaises(CloudAdapterError) as raised:
            adapter.inventory(
                SimpleNamespace(account_identifier="my-project", region_scope=[]),
                {"ref": "workload_identity"},
            )
        self.assertEqual(raised.exception.code, "scope_mismatch")

    def test_provider_error_translation_never_includes_raw_exception_text(self) -> None:
        class AccessDenied(Exception):
            def __str__(self):
                return "AccessDenied secret=provider-key filesystem=/private/path"

        exc = AccessDenied()
        self.assertEqual(provider_error_code(exc), "permission_denied")
        safe = CloudAdapterError(provider_error_code(exc))
        self.assertEqual(str(safe), "permission_denied")
        self.assertNotIn("provider-key", str(safe))
        self.assertNotIn("/private/path", str(safe))


if __name__ == "__main__":
    unittest.main()
