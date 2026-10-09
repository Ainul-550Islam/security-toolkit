"""Foundation services and safe cross-domain primitives.

These services coordinate foundation components only. They do NOT duplicate
the domain services in ``python/`` (scanning, findings, cases, integrations,
federation); those remain authoritative for their domains. Database, migration,
crypto, and key-management classes provide shared infrastructure contracts.
"""

from services.cloud_aws import AwsInventoryAdapter
from services.cloud_azure import AzureInventoryAdapter
from services.cloud_common import CloudAdapterError
from services.cloud_gcp import GcpInventoryAdapter
from services.crypto import CryptoService
from services.database import DatabaseService
from services.key_management import KeyManagementService
from services.migrations import MigrationRunner

__all__ = [
    "AwsInventoryAdapter",
    "AzureInventoryAdapter",
    "CloudAdapterError",
    "CryptoService",
    "DatabaseService",
    "GcpInventoryAdapter",
    "KeyManagementService",
    "MigrationRunner",
]
